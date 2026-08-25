//! Canonical, transport-neutral client protocol for the STEIN CORE daemon.
//!
//! The types in this crate are wire DTOs, not domain entities. The local IPC
//! adapter authenticates the peer and supplies its actor identity before any
//! [`ClientRequest`] reaches an application handler.

mod ids;
mod message;
mod metadata;
mod timestamp;
mod version;
mod views;
mod wire;

pub use ids::*;
pub use message::*;
pub use metadata::*;
pub use timestamp::*;
pub use version::*;
pub use views::*;
pub use wire::*;
