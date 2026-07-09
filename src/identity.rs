//! A single ed25519 seed is the whole identity of a meshguard node.
//!
//! From that one 32-byte seed we derive:
//!   * the iroh identity (ed25519) -> public half is the NodeId you dial,
//!   * the WireGuard static keypair (x25519)
//!     ed25519 -> curve25519 conversion (the same one libsodium exposes as
//!     `crypto_sign_ed25519_sk_to_curve25519`),
//!   * a deterministic overlay IP for the tunnel interface.
//!

use boringtun::x25519::{PublicKey, StaticSecret};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha512};
use std::net::Ipv4Addr;

/// The node's secret identity: just an ed25519 seed.
#[derive(Clone)]
pub struct Identity {
    seed: [u8; 32],
}

impl Identity {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self { seed }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// ed25519 public key = the raw bytes of the iroh NodeId.
    pub fn node_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed).verifying_key().to_bytes()
    }

    /// The NodeId as the same z-base-32 string iroh prints.
    pub fn node_id_string(&self) -> String {
        encode_node_key(&self.node_key())
    }

    /// This node's WireGuard static secret, derived from the ed25519 seed.
    pub fn wg_secret(&self) -> StaticSecret {
        let hash = Sha512::digest(self.seed);
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&hash[..32]);
        // x25519_dalek clamps the scalar on use.
        StaticSecret::from(sk)
    }

    /// This node's WireGuard public key.
    pub fn wg_public(&self) -> PublicKey {
        PublicKey::from(&self.wg_secret())
    }

    /// Deterministic overlay IPv4 address for the tunnel interface.
    pub fn overlay_ip(&self) -> Ipv4Addr {
        overlay_ip_from_node_key(&self.node_key())
    }
}

/// Convert a peer's NodeId (ed25519 public key) into its WireGuard public key.
///
/// ed25519 public keys are points in Edwards form; WireGuard uses the same curve
/// in Montgomery (x25519) form. The birational map gives the WG key for free.
pub fn wg_public_from_node_key(node_key: &[u8; 32]) -> anyhow::Result<PublicKey> {
    let edwards = CompressedEdwardsY(*node_key)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("NodeId is not a valid ed25519 point"))?;
    Ok(PublicKey::from(edwards.to_montgomery().to_bytes()))
}

/// Deterministic overlay IPv4 from a node key: 10.x.y.z, never .0 in the last octet.
pub fn overlay_ip_from_node_key(node_key: &[u8; 32]) -> Ipv4Addr {
    let h = Sha512::digest(node_key);
    let last = if h[2] == 0 { 1 } else { h[2] };
    Ipv4Addr::new(10, h[0], h[1], last)
}

/// iroh prints a NodeId as RFC4648 base32 (no padding), lowercased.
pub fn encode_node_key(node_key: &[u8; 32]) -> String {
    data_encoding::BASE32_NOPAD.encode(node_key).to_lowercase()
}

pub fn parse_node_key(s: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = data_encoding::BASE32_NOPAD
        .decode(s.trim().to_uppercase().as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid NodeId: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("NodeId must decode to 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_roundtrips() {
        let id = Identity::generate();
        let s = id.node_id_string();
        let key = parse_node_key(&s).unwrap();
        assert_eq!(key, id.node_key());
    }

    #[test]
    fn peer_wg_key_derives_from_node_id() {
        // A peer computes our WG public key purely from our NodeId, and it must
        // match the WG public key we derive from our own secret.
        let id = Identity::generate();
        let derived = wg_public_from_node_key(&id.node_key()).unwrap();
        assert_eq!(derived.as_bytes(), id.wg_public().as_bytes());
    }
}
