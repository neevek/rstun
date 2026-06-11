//! Client-side registry session.

use crate::registry::protocol::{RegistryEntry, RegistryMessage, recv_msg, send_msg};
use crate::registry::relay::{self, IncomingRelay, RelayIncoming, RelayOpen, RelayStream};
use anyhow::{Context, Result, bail};
use log::debug;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

/// Channel depth for inbound relay streams awaiting the embedder.
const INCOMING_RELAY_CAP: usize = 128;

/// A live registry control session.
///
/// The login bidi stream carries control requests (`register`/`list`), accessed
/// `&mut self` (borrow-checked, no lock). Relay streams ride additional bidi
/// streams on the same `quinn::Connection`, which is `Clone` (Arc) — so opening
/// and accepting relays never contend on the control path.
pub struct RegistrySession {
    _endpoint: Endpoint,
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    incoming: Option<mpsc::Receiver<IncomingRelay>>,
}

/// Cheaply-cloneable handle to open relay streams without holding the session
/// lock (the embedder typically keeps the session behind a `Mutex`).
#[derive(Clone)]
pub struct RelayHandle {
    conn: Connection,
}

impl RelayHandle {
    /// Open a relayed stream to `to_key`, sending the opaque `header` first.
    pub async fn open_relay(&self, to_key: &str, header: Vec<u8>) -> Result<RelayStream> {
        let (mut send, recv) = self
            .conn
            .open_bi()
            .await
            .context("failed to open relay stream")?;
        relay::write_frame(
            &mut send,
            &RelayOpen {
                to_key: to_key.to_string(),
                header,
            },
        )
        .await?;
        Ok(RelayStream::new(send, recv))
    }
}

impl RegistrySession {
    /// Build a session and spawn the background task that accepts inbound relay
    /// streams (server-opened) and surfaces them via `take_incoming`.
    pub(crate) fn new(
        endpoint: Endpoint,
        conn: Connection,
        send: SendStream,
        recv: RecvStream,
    ) -> Self {
        let (tx, rx) = mpsc::channel(INCOMING_RELAY_CAP);
        let accept_conn = conn.clone();
        tokio::spawn(async move {
            // Loop ends when accept_bi errors (connection closed).
            while let Ok((s, mut r)) = accept_conn.accept_bi().await {
                // Read the RelayIncoming header, then hand the pipe over. A
                // malformed header just drops that stream and keeps looping.
                if let Ok(inc) = relay::read_frame::<_, RelayIncoming>(&mut r).await {
                    let item = IncomingRelay {
                        from_key: inc.from_key,
                        header: inc.header,
                        stream: RelayStream::new(s, r),
                    };
                    // try_send (not send().await) so a slow/absent consumer
                    // can't stall the accept loop: drop the relay on a full
                    // backlog, stop entirely when the receiver is gone.
                    match tx.try_send(item) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            debug!("[registry] inbound relay dropped: backlog full");
                        }
                        Err(TrySendError::Closed(_)) => break,
                    }
                }
            }
        });

        Self {
            _endpoint: endpoint,
            conn,
            send,
            recv,
            incoming: Some(rx),
        }
    }

    /// A lock-free handle for opening relay streams.
    pub fn relay_handle(&self) -> RelayHandle {
        RelayHandle {
            conn: self.conn.clone(),
        }
    }

    /// Take the receiver of inbound relay streams (once; subsequent calls return
    /// `None`). The caller MUST drain it promptly: inbound relays beyond the
    /// channel capacity are dropped rather than stalling the accept loop.
    pub fn take_incoming(&mut self) -> Option<mpsc::Receiver<IncomingRelay>> {
        self.incoming.take()
    }

    /// Register (or refresh) this client under `key` with an opaque `value`.
    pub async fn register(&mut self, key: String, value: Vec<u8>) -> Result<()> {
        send_msg(&mut self.send, RegistryMessage::Register { key, value }).await?;
        match recv_msg(&mut self.recv)
            .await
            .context("registration failed")?
        {
            RegistryMessage::Registered => Ok(()),
            other => bail!("unexpected registration response: {other}"),
        }
    }

    /// Fetch the current roster (excludes this client).
    pub async fn list(&mut self) -> Result<Vec<RegistryEntry>> {
        send_msg(&mut self.send, RegistryMessage::List).await?;
        match recv_msg(&mut self.recv).await.context("list failed")? {
            RegistryMessage::Listing(entries) => Ok(entries),
            other => bail!("unexpected list response: {other}"),
        }
    }

    /// Ask the server for this connection's server-observed public address
    /// (STUN-like). Note this reflects the *registry* connection's socket; an
    /// embedder punching from a different socket should discover that socket's
    /// own mapping instead.
    pub async fn whats_my_addr(&mut self) -> Result<std::net::SocketAddr> {
        send_msg(&mut self.send, RegistryMessage::WhatsMyAddr).await?;
        match recv_msg(&mut self.recv)
            .await
            .context("whats_my_addr failed")?
        {
            RegistryMessage::MyAddr(addr) => Ok(addr),
            other => bail!("unexpected whats_my_addr response: {other}"),
        }
    }

    /// True once the underlying QUIC connection has closed.
    pub fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }
}
