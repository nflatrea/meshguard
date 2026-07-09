//! Transport implementations. The engine only ever sees the [`crate::io::Transport`] trait.

pub mod inmem;
pub mod udp;

#[cfg(feature = "iroh")]
pub mod iroh;
