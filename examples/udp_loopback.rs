//! Runs the meshguard WireGuard engine between two identities over real UDP
//! sockets on loopback, the same engine the iroh path uses but with UDP
//! transport instead. 
//!
//! Run with:  cargo run --example udp_loopback

use meshguard::identity::Identity;
use meshguard::io::{ChannelIo, Transport};
use meshguard::transport::udp::UdpTransport;
use meshguard::tunnel::{build_tunn, run};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let alice = Identity::generate();
    let bob = Identity::generate();

    let a_addr = "127.0.0.1:55551".parse()?;
    let b_addr = "127.0.0.1:55552".parse()?;

    let t_alice = UdpTransport::connect(a_addr, b_addr).await?;
    let t_bob = UdpTransport::connect(b_addr, a_addr).await?;

    let (io_alice, app_alice) = ChannelIo::pair();
    let (io_bob, mut app_bob) = ChannelIo::pair();

    let tunn_alice = Arc::new(Mutex::new(build_tunn(&alice, &bob.node_key(), Some(5))?));
    let tunn_bob = Arc::new(Mutex::new(build_tunn(&bob, &alice.node_key(), Some(5))?));

    let a = tokio::spawn(run(
        tunn_alice,
        Arc::new(t_alice) as Arc<dyn Transport>,
        Arc::new(io_alice),
        true,
    ));
    let b = tokio::spawn(run(
        tunn_bob,
        Arc::new(t_bob) as Arc<dyn Transport>,
        Arc::new(io_bob),
        false,
    ));

    let packet =
        meshguard::sample_ipv4_packet(alice.overlay_ip(), bob.overlay_ip(), b"hello-over-udp");
    println!("Alice ({}) -> Bob ({})", alice.overlay_ip(), bob.overlay_ip());
    app_alice.to_tunnel.send(packet.clone()).await?;

    let got = tokio::time::timeout(Duration::from_secs(10), app_bob.from_tunnel.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timed out"))?
        .ok_or_else(|| anyhow::anyhow!("closed"))?;

    a.abort();
    b.abort();

    assert_eq!(got, packet, "packet corrupted");
    println!(
        "OK: {} bytes decrypted at Bob, identical to what Alice sent (over real UDP).",
        got.len()
    );
    Ok(())
}
