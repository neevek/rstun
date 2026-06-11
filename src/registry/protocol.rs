//! Generic registry wire protocol.
//!
//! A client registers a `(key, value)` and can list the other registered
//! entries. `value` is an opaque byte blob — rstun attaches no meaning to it;
//! embedders put whatever they need there (a serialized identity, an address,
//! etc.). All registry traffic rides the single `TunnelMessage::Registry`
//! envelope.

use crate::tunnel_message::TunnelMessage;
use anyhow::{Result, bail};
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RegistryMessage {
    /// Client -> server: register/refresh this client under `key`.
    Register { key: String, value: Vec<u8> },
    /// Server -> client: registration accepted.
    Registered,
    /// Client -> server: request the current roster.
    List,
    /// Server -> client: roster snapshot (excludes the requester).
    Listing(Vec<RegistryEntry>),
    /// Client -> server: ask for this connection's server-observed public address
    /// (STUN-like; generic, no meaning attached). Used by embedders that need
    /// their reflexive address before NAT traversal.
    WhatsMyAddr,
    /// Server -> client: the address the server sees for this connection.
    MyAddr(std::net::SocketAddr),
}

/// One entry in a registry listing. `value` is opaque to rstun.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    pub key: String,
    pub value: Vec<u8>,
}

impl Display for RegistryMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryMessage::Register { key, value } => {
                write!(f, "register:{key}({} bytes)", value.len())
            }
            RegistryMessage::Registered => f.write_str("registered"),
            RegistryMessage::List => f.write_str("list"),
            RegistryMessage::Listing(entries) => write!(f, "listing:{}", entries.len()),
            RegistryMessage::WhatsMyAddr => f.write_str("whats_my_addr"),
            RegistryMessage::MyAddr(addr) => write!(f, "my_addr:{addr}"),
        }
    }
}

/// Send a registry message wrapped in the `TunnelMessage::Registry` envelope.
pub(crate) async fn send_msg(send: &mut SendStream, msg: RegistryMessage) -> Result<()> {
    TunnelMessage::send(send, &TunnelMessage::Registry(msg)).await
}

/// Receive a registry message. A `RespFailure` from the peer is surfaced as an
/// error; any non-registry message is unexpected on this control stream.
pub(crate) async fn recv_msg(recv: &mut RecvStream) -> Result<RegistryMessage> {
    match TunnelMessage::recv(recv).await? {
        TunnelMessage::Registry(m) => Ok(m),
        TunnelMessage::RespFailure(msg) => bail!("{msg}"),
        other => bail!("expected a registry message, got {other}"),
    }
}
