//! A plain UDP [`Transport`] to a fixed peer address.
//!
//! This is the "no-iroh" transport: it behaves like ordinary WireGuard-over-UDP.
//! Useful for a local two-process demo and as the reference the iroh transport
//! mirrors. It does not do NAT traversal or NodeId dialing — that's iroh's job.

use crate::io::Transport;
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub struct UdpTransport {
    sock: UdpSocket,
}

impl UdpTransport {
    /// Bind locally and connect to a fixed peer.
    pub async fn connect(bind: SocketAddr, peer: SocketAddr) -> anyhow::Result<Self> {
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(peer).await?;
        Ok(Self { sock })
    }
}

#[async_trait]
impl Transport for UdpTransport {
    async fn send(&self, datagram: &[u8]) -> anyhow::Result<()> {
        let _ = self.sock.send(datagram).await;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<Vec<u8>> {
        let mut buf = vec![0u8; 1600];
        let n = self.sock.recv(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }

    fn max_datagram_size(&self) -> usize {
        1400
    }
}
