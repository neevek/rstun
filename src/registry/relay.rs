//! Relayed streams between two registered clients.
//!
//! A client opens a new bidi QUIC stream to the server and writes a `RelayOpen`
//! header naming the target key plus an opaque `header` blob. The server opens a
//! matching bidi stream to the target, writes a `RelayIncoming` header tagging
//! the (server-authenticated) originator key, and then pipes raw bytes between
//! the two with `tokio::io::copy_bidirectional`. rstun never interprets the
//! `header` or the payload.

use anyhow::{Context, Result, bail};
use quinn::{RecvStream, SendStream};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Upper bound on a relay open/incoming header (the small framed prefix only;
/// the post-header byte pipe is unbounded). Distinct from the registry value
/// cap and the tunnel-message cap.
pub(crate) const MAX_RELAY_HEADER: usize = 4096;

/// First frame a client writes on a freshly opened relay stream (client→server).
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RelayOpen {
    pub to_key: String,
    pub header: Vec<u8>,
}

/// First frame the server writes on the relayed stream it opens toward the
/// target (server→target). `from_key` is the originator's authenticated key.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RelayIncoming {
    pub from_key: String,
    pub header: Vec<u8>,
}

/// Write a 4-byte big-endian length prefix + bincode, bounded by MAX_RELAY_HEADER.
pub(crate) async fn write_frame<W, T>(w: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard())
        .context("encode relay frame")?;
    if bytes.len() > MAX_RELAY_HEADER {
        bail!(
            "relay header too large: {} > {MAX_RELAY_HEADER}",
            bytes.len()
        );
    }
    w.write_u32(bytes.len() as u32).await?;
    w.write_all(&bytes).await?;
    Ok(())
}

/// Read a frame written by `write_frame`.
pub(crate) async fn read_frame<R, T>(r: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    use tokio::io::AsyncReadExt;
    let len = r.read_u32().await? as usize;
    if len > MAX_RELAY_HEADER {
        bail!("relay header too large: {len} > {MAX_RELAY_HEADER}");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.context("read relay frame")?;
    let (value, _) = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .context("decode relay frame")?;
    Ok(value)
}

/// An opaque, full-duplex byte pipe between two registered clients. After the
/// header is consumed, this is just the underlying QUIC bidi stream.
pub struct RelayStream {
    send: SendStream,
    recv: RecvStream,
}

impl RelayStream {
    pub(crate) fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for RelayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Fully-qualified to select quinn's tokio AsyncRead impl over the
        // inherent (Quinn-error) poll_read on RecvStream.
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for RelayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// An incoming relayed stream surfaced to the embedder on the target side.
pub struct IncomingRelay {
    /// Server-authenticated registry key of the client that opened the relay.
    pub from_key: String,
    /// The opaque header bytes the opener supplied.
    pub header: Vec<u8>,
    /// The full-duplex byte pipe to the opener (via the server).
    pub stream: RelayStream,
}
