//! A generic "register and discover" service over a QUIC control connection.
//!
//! A client logs in with `Tunnel::Registry`, registers a `(key, value)` where
//! `value` is an opaque blob, and can list the other registered entries. The
//! server keeps an in-memory roster and never interprets keys or values; an
//! embedder can gate registrations with `ServerConfig::registry_validator`.
//! This module is independent of any particular use (omnip layers a peer mesh
//! on top, but the primitive stands alone).

pub(crate) mod protocol;
pub(crate) mod relay;
pub(crate) mod service;
mod session;

pub use protocol::{RegistryEntry, RegistryMessage};
pub use relay::{IncomingRelay, RelayStream};
pub use session::{RegistrySession, RelayHandle};
