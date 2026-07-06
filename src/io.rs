//! The two seams the tunnel engine plugs into.
//!
//! * [`Transport`] is an unreliable datagram link to exactly one peer. WireGuard
//!   packets go in and out of it. The real implementation is iroh (dial by
//!   NodeId); an in-memory pair and a UDP socket are provided for tests/demos.
//! * [`PacketIo`] is the plaintext side: where cleartext IP packets come from and
//!   go to. The real implementation is a TUN device; a channel-backed one is used
//!   for the self-test and to pump a TUN.

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};

/// An unreliable, unordered datagram link to a single peer.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send one datagram. May silently drop if larger than [`Transport::max_datagram_size`].
    async fn send(&self, datagram: &[u8]) -> anyhow::Result<()>;
    /// Receive the next datagram.
    async fn recv(&self) -> anyhow::Result<Vec<u8>>;
    /// Largest datagram that fits in one packet on the current path.
    fn max_datagram_size(&self) -> usize;
}

/// The plaintext packet source/sink (a TUN device, or a test channel).
#[async_trait]
pub trait PacketIo: Send + Sync {
    /// Read one outbound cleartext IP packet (from the OS) to be encrypted.
    async fn read_packet(&self) -> anyhow::Result<Vec<u8>>;
    /// Deliver one decrypted cleartext IP packet (to the OS).
    async fn write_packet(&self, packet: &[u8]) -> anyhow::Result<()>;
}

/// A channel-backed [`PacketIo`], used by the self-test and to bridge a TUN device.
///
/// From the tunnel's point of view: `read_packet` drains `outbound_rx` (packets the
/// app wants to send), `write_packet` pushes into `inbound_tx` (packets to hand back
/// to the app).
pub struct ChannelIo {
    outbound_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
}

/// The counterpart handle the "app" (or TUN pump) holds.
pub struct AppHandle {
    /// Push a cleartext packet toward the tunnel (it will be encrypted & sent).
    pub to_tunnel: mpsc::Sender<Vec<u8>>,
    /// Receive cleartext packets the tunnel decrypted for us.
    pub from_tunnel: mpsc::Receiver<Vec<u8>>,
}

impl ChannelIo {
    pub fn pair() -> (ChannelIo, AppHandle) {
        let (to_tunnel, outbound_rx) = mpsc::channel(1024);
        let (inbound_tx, from_tunnel) = mpsc::channel(1024);
        (
            ChannelIo {
                outbound_rx: Mutex::new(outbound_rx),
                inbound_tx,
            },
            AppHandle {
                to_tunnel,
                from_tunnel,
            },
        )
    }
}

#[async_trait]
impl PacketIo for ChannelIo {
    async fn read_packet(&self) -> anyhow::Result<Vec<u8>> {
        self.outbound_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("packet source closed"))
    }

    async fn write_packet(&self, packet: &[u8]) -> anyhow::Result<()> {
        self.inbound_tx.send(packet.to_vec()).await.ok();
        Ok(())
    }
}
