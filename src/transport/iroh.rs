//! The iroh [`Transport`]: this is what makes meshguard route by NodeId.
//!
//! A WireGuard packet becomes one iroh *unreliable QUIC datagram* — never a
//! stream — so we don't stack QUIC's retransmission on top of WireGuard's own
//! loss handling. iroh resolves the NodeId (via the mainline DHT and/or the n0
//! DNS/pkarr service), hole-punches a direct path when it can, and relays
//! otherwise.
//!
//! NOTE: This module targets iroh >= 0.35 and is compiled only with
//! `--features iroh`. iroh's API evolves; if it drifts, pin the version in
//! Cargo.toml to the one documented in docs/BUILD.md.

use crate::identity::Identity;
use crate::io::Transport;
use async_trait::async_trait;
use bytes::Bytes;
use iroh::{Endpoint, NodeId, SecretKey};

/// ALPN identifying the meshguard protocol during the iroh/QUIC handshake.
pub const ALPN: &[u8] = b"meshguard/wg/0";

/// Build an iroh endpoint from our identity.
///
/// Discovery uses n0's hosted DNS/pkarr resolver (`discovery_n0`): it publishes
/// and resolves NodeIds with no extra infrastructure, which is all that's needed
/// to dial by NodeId. It is stateless name resolution, not a control server — the
/// tunnel itself is still peer-to-peer.
///
/// For fully serverless discovery over the BitTorrent mainline DHT, enable iroh's
/// `discovery-pkarr-dht` feature and add a DHT service, e.g.:
/// ```ignore
/// use iroh::discovery::pkarr::dht::DhtDiscovery;
/// let dht = DhtDiscovery::builder().secret_key(secret.clone()).build()?;
/// let ep = Endpoint::builder()
///     .secret_key(secret)
///     .alpns(vec![ALPN.to_vec()])
///     .discovery_n0()
///     .discovery(Box::new(dht))   // iroh 0.35: pass a Box<dyn Discovery>
///     .bind().await?;
/// ```
pub async fn make_endpoint(id: &Identity) -> anyhow::Result<Endpoint> {
    let secret = SecretKey::from_bytes(&id.seed());
    let ep = Endpoint::builder()
        .secret_key(secret)
        .alpns(vec![ALPN.to_vec()])
        .discovery_n0()
        .bind()
        .await?;
    Ok(ep)
}

/// Parse a NodeId string ("23ryys7p...") into an iroh NodeId.
pub fn parse_node_id(s: &str) -> anyhow::Result<NodeId> {
    Ok(s.trim().parse()?)
}

/// A [`Transport`] backed by an established iroh connection.
pub struct IrohTransport {
    conn: iroh::endpoint::Connection,
}

impl IrohTransport {
    /// Dial a peer by NodeId and wrap the resulting connection.
    pub async fn dial(ep: &Endpoint, node: NodeId) -> anyhow::Result<Self> {
        let conn = ep.connect(node, ALPN).await?;
        Ok(Self { conn })
    }

    /// Wrap an already-accepted connection (server side).
    pub fn from_connection(conn: iroh::endpoint::Connection) -> Self {
        Self { conn }
    }

    /// The verified NodeId of the remote end (its TLS/QUIC identity).
    pub fn remote_node_id(&self) -> anyhow::Result<NodeId> {
        Ok(self.conn.remote_node_id()?)
    }
}

#[async_trait]
impl Transport for IrohTransport {
    async fn send(&self, datagram: &[u8]) -> anyhow::Result<()> {
        // Unreliable datagram. If it exceeds the current path limit, drop it —
        // WireGuard will retransmit and adapt its MTU.
        let _ = self.conn.send_datagram(Bytes::copy_from_slice(datagram));
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<Vec<u8>> {
        let dgram = self.conn.read_datagram().await?;
        Ok(dgram.to_vec())
    }

    fn max_datagram_size(&self) -> usize {
        self.conn.max_datagram_size().unwrap_or(1200)
    }
}
