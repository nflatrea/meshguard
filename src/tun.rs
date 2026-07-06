//! Real TUN interface, bridged to the engine via [`ChannelIo`].
//!
//! Two pump tasks move packets between the kernel interface and the channels the
//! tunnel engine reads/writes. Creating the interface needs root / CAP_NET_ADMIN
//! at runtime. Compiled only with `--features tun` (Linux/macOS).

use crate::io::ChannelIo;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Create and bring up a TUN interface, returning the engine-side [`ChannelIo`].
///
/// The interface is assigned `addr/8` (the whole `10.0.0.0/8` overlay) with the
/// given `mtu`, so every peer's derived overlay IP is on-link and reachable with
/// no manual routes. Background tasks keep pumping until the process exits.
pub async fn setup(name: &str, addr: Ipv4Addr, mtu: u16) -> anyhow::Result<ChannelIo> {
    let mut config = tun::Configuration::default();
    config
        .name(name)
        .address(addr)
        // /8 covers the entire 10.0.0.0/8 overlay, so every peer's overlay IP is
        // on-link — no per-peer `ip route` needed to reach them through the tunnel.
        .netmask(Ipv4Addr::new(255, 0, 0, 0))
        .mtu(mtu as i32)
        .up();
    #[cfg(target_os = "linux")]
    config.platform(|p| {
        // No 4-byte packet-information prefix: the engine reads/writes raw IP packets.
        p.packet_information(false);
    });

    let dev = tun::create_as_async(&config)?;
    let (mut reader, mut writer) = tokio::io::split(dev);

    let (io, mut app) = ChannelIo::pair();

    // Kernel -> engine: read IP packets off the interface, hand them to the tunnel.
    let to_tunnel = app.to_tunnel.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; (mtu as usize) + 4];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_tunnel.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Engine -> kernel: write decrypted packets back onto the interface.
    tokio::spawn(async move {
        while let Some(pkt) = app.from_tunnel.recv().await {
            if writer.write_all(&pkt).await.is_err() {
                break;
            }
        }
    });

    Ok(io)
}
