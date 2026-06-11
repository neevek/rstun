//! Server-side registry: a live roster of registered clients and the
//! per-connection loop that registers one client (optionally validated by an
//! embedder-supplied hook) and answers roster queries. Reuses the existing QUIC
//! connection/stream plumbing; the server just hands the reused login stream
//! here. rstun attaches no meaning to keys or values.

use crate::RegistryValidator;
use crate::registry::protocol::{RegistryEntry, RegistryMessage, send_msg};
use crate::registry::relay::{self, RelayIncoming, RelayOpen, RelayStream};
use crate::tunnel_message::TunnelMessage;
use anyhow::{Context, Result};
use dashmap::DashMap;
use log::{debug, info, warn};
use quinn::{Connection, RecvStream, SendStream};
use rs_utilities::log_and_bail;
use std::sync::Arc;
use std::time::Duration;

/// Upper bound on a registration key (bytes).
const MAX_KEY_LEN: usize = 256;
/// Upper bound on a registration value blob (bytes).
const MAX_VALUE_LEN: usize = 16 * 1024;
/// How long a client has to send its registration after login.
const REGISTRATION_TIMEOUT_MS: u64 = 10_000;

/// A client currently registered in the roster.
#[derive(Debug, Clone)]
pub(crate) struct RegisteredClient {
    conn: Connection,
    value: Vec<u8>,
}

/// Shared, lock-free roster keyed by registration key.
pub(crate) type Registry = Arc<DashMap<String, RegisteredClient>>;

/// Create an empty registry.
pub(crate) fn new_registry() -> Registry {
    Arc::new(DashMap::new())
}

/// Drive a registry client's control stream: register it (optionally validated),
/// then answer roster queries until the connection closes. The login bidi
/// stream is reused here (no heartbeat task).
pub(crate) async fn serve(
    registry: Registry,
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    validator: Option<RegistryValidator>,
) -> Result<()> {
    let remote_addr = conn.remote_address();

    // First message must be a Register. Bound the wait so a client that logs in
    // but never registers can't park resources forever.
    let first = tokio::time::timeout(
        Duration::from_millis(REGISTRATION_TIMEOUT_MS),
        TunnelMessage::recv(&mut recv),
    )
    .await
    .with_context(|| format!("registration not received in time from {remote_addr}"))??;

    let (key, value) = match first {
        TunnelMessage::Registry(RegistryMessage::Register { key, value }) => (key, value),
        // Anonymous reflexive-address query: an embedder may open a throwaway
        // connection (e.g. from a NAT-traversal punch socket) just to learn its
        // server-observed address, without registering. Reply, then let the
        // client close the connection (bounded) so the reply flushes first.
        TunnelMessage::Registry(RegistryMessage::WhatsMyAddr) => {
            send_msg(&mut send, RegistryMessage::MyAddr(conn.remote_address())).await?;
            send.finish().ok();
            let _ = tokio::time::timeout(
                Duration::from_millis(REGISTRATION_TIMEOUT_MS),
                conn.closed(),
            )
            .await;
            return Ok(());
        }
        other => {
            TunnelMessage::send_failure(&mut send, format!("expected Register, got {other}"))
                .await
                .ok();
            log_and_bail!("registry: unexpected first message from {remote_addr}");
        }
    };

    if let Err(e) = validate(&key, &value, validator.as_ref()) {
        TunnelMessage::send_failure(&mut send, format!("registration rejected: {e}"))
            .await
            .ok();
        log_and_bail!("registry: registration rejected from {remote_addr}: {e}");
    }

    registry.insert(
        key.clone(),
        RegisteredClient {
            conn: conn.clone(),
            value,
        },
    );
    send_msg(&mut send, RegistryMessage::Registered).await?;
    info!("[registry] client registered, key={key}, remote_addr={remote_addr}");

    // Serve roster queries and relay-open requests until the connection closes.
    // Control messages ride `recv`; relay opens arrive as new bidi streams.
    let result = loop {
        tokio::select! {
            _ = conn.closed() => break Ok(()),
            msg = TunnelMessage::recv(&mut recv) => {
                match msg {
                    Ok(TunnelMessage::Registry(RegistryMessage::List)) => {
                        let entries = snapshot(&registry, &key);
                        if let Err(e) = send_msg(&mut send, RegistryMessage::Listing(entries)).await {
                            break Err(e);
                        }
                    }
                    Ok(TunnelMessage::Registry(RegistryMessage::WhatsMyAddr)) => {
                        // STUN-like reply with this connection's observed address.
                        if let Err(e) =
                            send_msg(&mut send, RegistryMessage::MyAddr(conn.remote_address())).await
                        {
                            break Err(e);
                        }
                    }
                    Ok(other) => {
                        warn!("[registry] unexpected message from key={key}: {other}");
                    }
                    Err(e) => break Err(e),
                }
            }
            accepted = conn.accept_bi() => {
                match accepted {
                    Ok((rsend, rrecv)) => {
                        // A relay-open from this client; forward it without blocking the loop.
                        let registry = registry.clone();
                        let from_key = key.clone();
                        tokio::spawn(async move {
                            if let Err(e) = forward_relay(registry, from_key, rsend, rrecv).await {
                                debug!("[registry] relay open dropped: {e}");
                            }
                        });
                    }
                    Err(_) => break Ok(()), // connection closed
                }
            }
        }
    };

    // Only remove the entry if it still points at this connection (a newer
    // registration for the same key may have replaced it).
    registry.remove_if(&key, |_, entry| entry.conn.stable_id() == conn.stable_id());
    info!("[registry] client unregistered, key={key}, remote_addr={remote_addr}");
    result
}

/// Forward a relay-open from `from_key` to its target: read the `RelayOpen`
/// header, find the target's connection, open a stream to it, tag it with the
/// authenticated `from_key`, and pipe bytes both ways. Dropping the streams on
/// any error resets them.
async fn forward_relay(
    registry: Registry,
    from_key: String,
    opener_send: SendStream,
    mut opener_recv: RecvStream,
) -> Result<()> {
    let open: RelayOpen = relay::read_frame(&mut opener_recv).await?;

    // Look up the target (clone its connection so we don't hold the DashMap ref
    // across the await).
    let target_conn = match registry.get(&open.to_key) {
        Some(entry) if entry.conn.close_reason().is_none() => entry.conn.clone(),
        _ => {
            anyhow::bail!("relay target not found/closed: {}", open.to_key);
        }
    };

    let (mut target_send, target_recv) = target_conn
        .open_bi()
        .await
        .context("failed to open stream to relay target")?;
    relay::write_frame(
        &mut target_send,
        &RelayIncoming {
            from_key,
            header: open.header,
        },
    )
    .await?;

    let mut a = RelayStream::new(opener_send, opener_recv);
    let mut b = RelayStream::new(target_send, target_recv);
    tokio::io::copy_bidirectional(&mut a, &mut b).await.ok();
    Ok(())
}

/// Drop entries whose QUIC connection has closed. Each client's own task removes
/// its entry on a clean exit; this is the safety net for connections that died
/// without the task observing `closed()` promptly.
pub(crate) fn prune(registry: &Registry) {
    registry.retain(|_, entry| entry.conn.close_reason().is_none());
}

/// Apply size bounds and the optional embedder validator to a registration.
fn validate(key: &str, value: &[u8], validator: Option<&RegistryValidator>) -> Result<()> {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        log_and_bail!("key length out of range (1..={MAX_KEY_LEN})");
    }
    if value.len() > MAX_VALUE_LEN {
        log_and_bail!("value too large (max {MAX_VALUE_LEN} bytes)");
    }
    if let Some(validator) = validator {
        validator(key, value)?;
    }
    Ok(())
}

/// Snapshot the roster for a requester, excluding the requester and pruning
/// entries whose connection has closed.
fn snapshot(registry: &Registry, requester_key: &str) -> Vec<RegistryEntry> {
    registry
        .iter()
        .filter(|e| e.key() != requester_key && e.value().conn.close_reason().is_none())
        .map(|e| RegistryEntry {
            key: e.key().clone(),
            value: e.value().value.clone(),
        })
        .collect()
}
