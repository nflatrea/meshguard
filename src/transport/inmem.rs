//! An in-memory [`Transport`] pair: two ends wired directly to each other.
//! Used by the self-test to run a full WireGuard handshake + data exchange with
//! no sockets, no root, and no network.

use crate::io::Transport;
use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};

pub struct InMemTransport {
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    mtu: usize,
}

impl InMemTransport {
    /// Create two ends of a link.
    pub fn pair(mtu: usize) -> (InMemTransport, InMemTransport) {
        let (a_tx, a_rx) = mpsc::channel(1024);
        let (b_tx, b_rx) = mpsc::channel(1024);
        (
            InMemTransport {
                tx: a_tx,
                rx: Mutex::new(b_rx),
                mtu,
            },
            InMemTransport {
                tx: b_tx,
                rx: Mutex::new(a_rx),
                mtu,
            },
        )
    }
}

#[async_trait]
impl Transport for InMemTransport {
    async fn send(&self, datagram: &[u8]) -> anyhow::Result<()> {
        // Drop on overflow, like real lossy datagram link.
        let _ = self.tx.try_send(datagram.to_vec());
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<Vec<u8>> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("transport closed"))
    }

    fn max_datagram_size(&self) -> usize {
        self.mtu
    }
}
