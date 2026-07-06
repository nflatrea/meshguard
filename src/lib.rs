//! meshguard
//!
//! The crate is layered so the WireGuard core is testable with no network and no
//! root: see [`selftest`], which runs a full handshake + data exchange in-process.

pub mod config;
pub mod identity;
pub mod io;
pub mod transport;
pub mod tunnel;

#[cfg(feature = "tun")]
pub mod tun;

use crate::identity::Identity;
use crate::io::{ChannelIo, Transport};
use crate::transport::inmem::InMemTransport;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Run a full WireGuard handshake and round-trip a packet between two freshly
/// generated identities over an in-memory transport. No sockets, no root.
///
/// Returns the number of plaintext bytes successfully delivered end-to-end.
pub async fn selftest() -> anyhow::Result<usize> {
    let alice = Identity::generate();
    let bob = Identity::generate();

    let (t_alice, t_bob) = InMemTransport::pair(1400);
    let (io_alice, app_alice) = ChannelIo::pair();
    let (io_bob, mut app_bob) = ChannelIo::pair();

    // Each side derives the peer's WG key purely from the peer's NodeId.
    let tunn_alice = Arc::new(Mutex::new(tunnel::build_tunn(
        &alice,
        &bob.node_key(),
        Some(5),
    )?));
    let tunn_bob = Arc::new(Mutex::new(tunnel::build_tunn(
        &bob,
        &alice.node_key(),
        Some(5),
    )?));

    // Alice initiates the handshake; Bob responds.
    let a = tokio::spawn(tunnel::run(
        tunn_alice,
        Arc::new(t_alice) as Arc<dyn Transport>,
        Arc::new(io_alice),
        true,
    ));
    let b = tokio::spawn(tunnel::run(
        tunn_bob,
        Arc::new(t_bob) as Arc<dyn Transport>,
        Arc::new(io_bob),
        false,
    ));

    // Inject a plausible IPv4 packet at Alice's app side.
    let packet = sample_ipv4_packet(alice.overlay_ip(), bob.overlay_ip(), b"meshguard-hello");
    app_alice.to_tunnel.send(packet.clone()).await?;

    // Expect it to arrive, decrypted, at Bob's app side.
    let received = tokio::time::timeout(Duration::from_secs(10), app_bob.from_tunnel.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for packet to traverse the tunnel"))?
        .ok_or_else(|| anyhow::anyhow!("tunnel closed before delivering packet"))?;

    a.abort();
    b.abort();

    if received != packet {
        anyhow::bail!(
            "packet corrupted in transit: sent {} bytes, got {} bytes",
            packet.len(),
            received.len()
        );
    }
    Ok(received.len())
}

/// Build a minimal, well-formed IPv4 packet (header + payload) for tests/demos.
pub fn sample_ipv4_packet(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut p = Vec::with_capacity(total_len);
    p.push(0x45); // version 4, IHL 5
    p.push(0x00); // DSCP/ECN
    p.extend_from_slice(&(total_len as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]); // identification
    p.extend_from_slice(&[0x40, 0x00]); // flags (DF), fragment offset
    p.push(0x40); // TTL 64
    p.push(0x11); // protocol UDP (17)
    p.extend_from_slice(&[0x00, 0x00]); // header checksum (left zero; not validated here)
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}
