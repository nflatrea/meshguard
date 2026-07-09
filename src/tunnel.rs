//! The WireGuard engine. It drives boringtun's [`Tunn`] state machine with three
//! concurrent loops, over any [`Transport`] and [`PacketIo`]:
//!
//!   1. **encapsulate**: read a cleartext packet -> encrypt -> send a datagram.
//!   2. **decapsulate**: receive a datagram -> decrypt -> write cleartext
//!      (and emit handshake replies back onto the transport).
//!   3. **timers**: every ~250ms drive keepalives, rekeys, and handshake retries.
//!
//! boringtun's crypto calls are synchronous and fast; we hold the mutex only
//! across the call and copy the output out before doing any `.await`, so the lock
//! is never held across a suspension point.

use crate::identity::{wg_public_from_node_key, Identity};
use crate::io::{PacketIo, Transport};
use boringtun::noise::{Tunn, TunnResult};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Build a boringtun tunnel from our identity and the peer's NodeId bytes.
///
pub fn build_tunn(
    local: &Identity,
    peer_node_key: &[u8; 32],
    keepalive: Option<u16>,
) -> anyhow::Result<Tunn> {
    let peer_wg_public = wg_public_from_node_key(peer_node_key)?;
    let index: u32 = rand::random();
    Ok(Tunn::new(
        local.wg_secret(),
        peer_wg_public,
        None,      // optional pre-shared key
        keepalive, // persistent keepalive seconds
        index,     // local sender index
        None,      // optional rate limiter
    ))
}

/// Run the tunnel until a fatal transport/io error.
///
/// `initiate` should be true on the dialing (client) side so it kicks the
/// handshake immediately; the accepting side passes false and responds.
pub async fn run(
    tunn: Arc<Mutex<Tunn>>,
    transport: Arc<dyn Transport>,
    io: Arc<dyn PacketIo>,
    initiate: bool,
) -> anyhow::Result<()> {
    if initiate {
        let mut buf = [0u8; 256];
        let first = {
            let mut t = tunn.lock().unwrap();
            match t.format_handshake_initiation(&mut buf, false) {
                TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                _ => None,
            }
        };
        if let Some(d) = first {
            transport.send(&d).await?;
        }
    }

    let encap = encapsulate_loop(tunn.clone(), transport.clone(), io.clone());
    let decap = decapsulate_loop(tunn.clone(), transport.clone(), io.clone());
    let timer = timer_loop(tunn.clone(), transport.clone());

    tokio::try_join!(encap, decap, timer)?;
    Ok(())
}

async fn encapsulate_loop(
    tunn: Arc<Mutex<Tunn>>,
    transport: Arc<dyn Transport>,
    io: Arc<dyn PacketIo>,
) -> anyhow::Result<()> {
    loop {
        let pkt = io.read_packet().await?;
        let out = {
            let mut buf = vec![0u8; pkt.len() + 64];
            let mut t = tunn.lock().unwrap();
            match t.encapsulate(&pkt, &mut buf) {
                TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                _ => None,
            }
        };
        if let Some(d) = out {
            transport.send(&d).await?;
        }
    }
}

async fn decapsulate_loop(
    tunn: Arc<Mutex<Tunn>>,
    transport: Arc<dyn Transport>,
    io: Arc<dyn PacketIo>,
) -> anyhow::Result<()> {
    loop {
        let dgram = transport.recv().await?;
        let mut to_send: Vec<Vec<u8>> = Vec::new();
        let mut to_write: Option<Vec<u8>> = None;
        {
            let mut buf = vec![0u8; 1600];
            let mut t = tunn.lock().unwrap();
            match t.decapsulate(None, &dgram, &mut buf) {
                TunnResult::WriteToNetwork(p) => {
                    to_send.push(p.to_vec());
                    // Drain any queued packets with empty inputs, per boringtun's idiom.
                    let mut flush = vec![0u8; 1600];
                    loop {
                        match t.decapsulate(None, &[], &mut flush) {
                            TunnResult::WriteToNetwork(p2) => to_send.push(p2.to_vec()),
                            _ => break,
                        }
                    }
                }
                TunnResult::WriteToTunnelV4(p, _) => to_write = Some(p.to_vec()),
                TunnResult::WriteToTunnelV6(p, _) => to_write = Some(p.to_vec()),
                _ => {}
            }
        }
        for d in to_send {
            transport.send(&d).await?;
        }
        if let Some(p) = to_write {
            io.write_packet(&p).await?;
        }
    }
}

async fn timer_loop(
    tunn: Arc<Mutex<Tunn>>,
    transport: Arc<dyn Transport>,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    loop {
        interval.tick().await;
        let out = {
            let mut buf = vec![0u8; 1600];
            let mut t = tunn.lock().unwrap();
            match t.update_timers(&mut buf) {
                TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                _ => None,
            }
        };
        if let Some(d) = out {
            transport.send(&d).await?;
        }
    }
}
