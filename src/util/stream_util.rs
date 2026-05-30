use crate::BUFFER_POOL;
use crate::tcp::AsyncStream;
use anyhow::Result;
use log::debug;
use quinn::{RecvStream, SendStream};
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::oneshot;
use tokio::time::error::Elapsed;

#[derive(Debug, PartialEq, Eq)]
pub enum TransferError {
    InternalError,
    InvalidIPAddress,
    InvalidIPFamily,
    InvalidDomain,
    TimeoutError,
}

impl Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalError => write!(f, "InternalError"),
            Self::InvalidIPAddress => write!(f, "InvalidIPAddress"),
            Self::InvalidIPFamily => write!(f, "InvalidIPFamily"),
            Self::InvalidDomain => write!(f, "InvalidDomain"),
            Self::TimeoutError => write!(f, "TimeoutError"),
        }
    }
}

pub struct StreamUtil {}

impl StreamUtil {
    pub fn start_flowing<S: AsyncStream>(
        tag: &'static str,
        stream: S,
        quic_stream: (SendStream, RecvStream),
        stream_timeout_ms: u64,
    ) {
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                log::warn!("[{tag}] peer address unavailable, err={e}");
                return;
            }
        };

        let (mut stream_read, mut stream_write) = tokio::io::split(stream);
        let (mut quic_send, mut quic_recv) = quic_stream;
        let index = quic_send.id().index();

        debug!("[{tag}] stream open id={index}, peer={peer_addr}");

        let (quic_to_stream_tx, quic_to_stream_rx) = oneshot::channel::<()>();
        let (stream_to_quic_tx, stream_to_quic_rx) = oneshot::channel::<()>();
        const BUFFER_SIZE: usize = 8192;

        tokio::spawn(async move {
            let mut transfer_bytes = 0u64;
            let mut buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);
            loop {
                let result = Self::quic_to_stream(
                    &mut quic_recv,
                    &mut stream_write,
                    &mut buffer,
                    &mut transfer_bytes,
                    stream_timeout_ms,
                )
                .await;

                match result {
                    Err(TransferError::TimeoutError) => {
                        let _ = quic_to_stream_tx.send(());
                        stream_to_quic_rx.await.ok();
                        // either the sender is dropped or the task times out
                        break;
                    }
                    Ok(0) | Err(_) => {
                        let _ = quic_to_stream_tx.send(());
                        break;
                    }
                    _ => {
                        // ok, continue
                    }
                }
            }

            debug!(
                "[{tag}] stream close id={index}, peer={peer_addr}, dir=q2s, bytes={transfer_bytes}"
            );
        });

        tokio::spawn(async move {
            let mut transfer_bytes = 0u64;
            let mut buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);
            loop {
                let result = Self::stream_to_quic(
                    &mut stream_read,
                    &mut quic_send,
                    &mut buffer,
                    &mut transfer_bytes,
                    stream_timeout_ms,
                )
                .await;

                match result {
                    Err(TransferError::TimeoutError) => {
                        let _ = stream_to_quic_tx.send(());
                        quic_to_stream_rx.await.ok();
                        // either the sender is dropped or the task times out
                        break;
                    }
                    Ok(0) | Err(_) => {
                        let _ = stream_to_quic_tx.send(());
                        break;
                    }
                    _ => {
                        // ok, continue
                    }
                }
            }

            debug!(
                "[{tag}] stream close id={index}, peer={peer_addr}, dir=s2q, bytes={transfer_bytes}"
            );
            Ok::<(), anyhow::Error>(())
        });
    }

    async fn stream_to_quic<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream_read: &mut ReadHalf<S>,
        quic_send: &mut SendStream,
        buffer: &mut [u8],
        transfer_bytes: &mut u64,
        stream_timeout_ms: u64,
    ) -> Result<usize, TransferError> {
        let len_read = tokio::time::timeout(
            Duration::from_millis(stream_timeout_ms),
            stream_read.read(buffer),
        )
        .await
        .map_err(|_: Elapsed| TransferError::TimeoutError)?
        .map_err(|_| TransferError::InternalError)?;
        if len_read > 0 {
            *transfer_bytes += len_read as u64;
            quic_send
                .write_all(&buffer[..len_read])
                .await
                .map_err(|_| TransferError::InternalError)?;
            Ok(len_read)
        } else {
            quic_send
                .finish()
                .map_err(|_| TransferError::InternalError)?;
            Ok(0)
        }
    }

    async fn quic_to_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        quic_recv: &mut RecvStream,
        stream_write: &mut WriteHalf<S>,
        buffer: &mut [u8],
        transfer_bytes: &mut u64,
        stream_timeout_ms: u64,
    ) -> Result<usize, TransferError> {
        let result = tokio::time::timeout(
            Duration::from_millis(stream_timeout_ms),
            quic_recv.read(buffer),
        )
        .await
        .map_err(|_: Elapsed| TransferError::TimeoutError)?
        .map_err(|_| TransferError::InternalError)?;
        if let Some(len_read) = result {
            *transfer_bytes += len_read as u64;
            stream_write
                .write_all(&buffer[..len_read])
                .await
                .map_err(|_| TransferError::InternalError)?;
            Ok(len_read)
        } else {
            stream_write
                .shutdown()
                .await
                .map_err(|_| TransferError::InternalError)?;
            Ok(0)
        }
    }

    /// Serializes a tunnel target into its wire bytes. Returns `None` when there
    /// is nothing to write (a `None` target with `mark_none == false`). Kept pure
    /// so it is unit-testable.
    ///
    /// Wire format:
    ///   family 4: [4][4-byte ipv4][2-byte port]
    ///   family 6: [6][16-byte ipv6][2-byte port]
    ///   family 3: [3][1-byte host len][host utf8][2-byte port]  (domain)
    ///   none + mark_none: [0]
    pub fn encode_tunnel_target(
        target: &Option<crate::TunnelTarget>,
        mark_none: bool,
    ) -> Result<Option<Vec<u8>>> {
        let buf = match target {
            Some(crate::TunnelTarget::Addr(SocketAddr::V4(v4))) => {
                let mut buf = Vec::with_capacity(1 + 4 + 2);
                buf.push(4);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
                buf
            }
            Some(crate::TunnelTarget::Addr(SocketAddr::V6(v6))) => {
                let mut buf = Vec::with_capacity(1 + 16 + 2);
                buf.push(6);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
                buf
            }
            Some(crate::TunnelTarget::Domain(host, port)) => {
                let host_bytes = host.as_bytes();
                if host_bytes.is_empty() || host_bytes.len() > u8::MAX as usize {
                    anyhow::bail!("invalid tunnel domain length: {}", host_bytes.len());
                }
                let mut buf = Vec::with_capacity(1 + 1 + host_bytes.len() + 2);
                buf.push(3);
                buf.push(host_bytes.len() as u8);
                buf.extend_from_slice(host_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
                buf
            }
            None => {
                if mark_none {
                    vec![0]
                } else {
                    return Ok(None);
                }
            }
        };
        Ok(Some(buf))
    }

    pub async fn write_tunnel_target(
        quic_send: &mut SendStream,
        target: &Option<crate::TunnelTarget>,
        mark_none: bool,
    ) -> Result<()> {
        if let Some(buf) = Self::encode_tunnel_target(target, mark_none)? {
            quic_send.write_all(&buf).await?;
        }
        Ok(())
    }

    pub async fn read_tunnel_target<R: AsyncRead + Unpin>(
        quic_recv: &mut R,
        stream_timeout_ms: u64,
    ) -> Result<crate::TunnelTarget, TransferError> {
        let timeout = Duration::from_millis(stream_timeout_ms);
        let family = Self::read_target_family(quic_recv, timeout).await?;
        Self::read_tunnel_target_body(quic_recv, family, timeout).await
    }

    /// Like `read_tunnel_target`, but a leading family byte of `0` (the
    /// `mark_none` sentinel produced by `encode_tunnel_target`) decodes to
    /// `None`. Used by the UDP relay, where a flow may target the server's
    /// configured default upstream instead of an explicit destination.
    pub async fn read_optional_tunnel_target<R: AsyncRead + Unpin>(
        quic_recv: &mut R,
        stream_timeout_ms: u64,
    ) -> Result<Option<crate::TunnelTarget>, TransferError> {
        let timeout = Duration::from_millis(stream_timeout_ms);
        let family = Self::read_target_family(quic_recv, timeout).await?;
        if family == 0 {
            return Ok(None);
        }
        Self::read_tunnel_target_body(quic_recv, family, timeout)
            .await
            .map(Some)
    }

    async fn read_target_family<R: AsyncRead + Unpin>(
        quic_recv: &mut R,
        timeout: Duration,
    ) -> Result<u8, TransferError> {
        let mut family = [0u8; 1];
        tokio::time::timeout(timeout, quic_recv.read_exact(&mut family))
            .await
            .map_err(|_: Elapsed| TransferError::TimeoutError)?
            .map_err(|_| TransferError::InternalError)?;
        Ok(family[0])
    }

    async fn read_tunnel_target_body<R: AsyncRead + Unpin>(
        quic_recv: &mut R,
        family: u8,
        timeout: Duration,
    ) -> Result<crate::TunnelTarget, TransferError> {
        match family {
            4 => {
                let mut buf = [0u8; 4 + 2];
                tokio::time::timeout(timeout, quic_recv.read_exact(&mut buf))
                    .await
                    .map_err(|_: Elapsed| TransferError::TimeoutError)?
                    .map_err(|_| TransferError::InternalError)?;
                let ip = Ipv4Addr::from(
                    <[u8; 4]>::try_from(&buf[0..4]).map_err(|_| TransferError::InvalidIPAddress)?,
                );
                let port = u16::from_be_bytes(buf[4..6].try_into().unwrap());
                Ok(crate::TunnelTarget::Addr(SocketAddr::new(ip.into(), port)))
            }
            6 => {
                let mut buf = [0u8; 16 + 2];
                tokio::time::timeout(timeout, quic_recv.read_exact(&mut buf))
                    .await
                    .map_err(|_: Elapsed| TransferError::TimeoutError)?
                    .map_err(|_| TransferError::InternalError)?;
                let ip = Ipv6Addr::from(
                    <[u8; 16]>::try_from(&buf[0..16])
                        .map_err(|_| TransferError::InvalidIPAddress)?,
                );
                let port = u16::from_be_bytes(buf[16..18].try_into().unwrap());
                Ok(crate::TunnelTarget::Addr(SocketAddr::new(ip.into(), port)))
            }
            3 => {
                let mut len = [0u8; 1];
                tokio::time::timeout(timeout, quic_recv.read_exact(&mut len))
                    .await
                    .map_err(|_: Elapsed| TransferError::TimeoutError)?
                    .map_err(|_| TransferError::InternalError)?;
                let host_len = len[0] as usize;
                if host_len == 0 {
                    return Err(TransferError::InvalidDomain);
                }
                let mut buf = vec![0u8; host_len + 2];
                tokio::time::timeout(timeout, quic_recv.read_exact(&mut buf))
                    .await
                    .map_err(|_: Elapsed| TransferError::TimeoutError)?
                    .map_err(|_| TransferError::InternalError)?;
                let host = std::str::from_utf8(&buf[..host_len])
                    .map_err(|_| TransferError::InvalidDomain)?
                    .to_string();
                let port = u16::from_be_bytes(buf[host_len..host_len + 2].try_into().unwrap());
                Ok(crate::TunnelTarget::Domain(host, port))
            }
            _ => {
                log::warn!("invalid tunnel target address family, family={family}");
                Err(TransferError::InvalidIPFamily)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TunnelTarget;

    async fn round_trip(target: TunnelTarget) -> TunnelTarget {
        let bytes = StreamUtil::encode_tunnel_target(&Some(target), true)
            .unwrap()
            .unwrap();
        StreamUtil::read_tunnel_target(&mut bytes.as_slice(), 1000)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn tunnel_target_round_trips_all_families() {
        let v4 = TunnelTarget::Addr("198.18.0.7:443".parse().unwrap());
        assert_eq!(round_trip(v4.clone()).await, v4);

        let v6 = TunnelTarget::Addr("[fd00:1234::1]:8443".parse().unwrap());
        assert_eq!(round_trip(v6.clone()).await, v6);

        let domain = TunnelTarget::Domain("example.com".to_string(), 443);
        assert_eq!(round_trip(domain.clone()).await, domain);
    }

    #[tokio::test]
    async fn read_optional_tunnel_target_decodes_none_and_targets() {
        // `mark_none` sentinel byte [0] decodes to None (the fixed-upstream case
        // used by the UDP relay).
        let none_bytes = StreamUtil::encode_tunnel_target(&None, true)
            .unwrap()
            .unwrap();
        assert_eq!(none_bytes, vec![0]);
        assert_eq!(
            StreamUtil::read_optional_tunnel_target(&mut none_bytes.as_slice(), 1000).await,
            Ok(None)
        );

        // A real Domain target round-trips through the optional reader.
        let domain = TunnelTarget::Domain("example.com".to_string(), 443);
        let domain_bytes = StreamUtil::encode_tunnel_target(&Some(domain.clone()), true)
            .unwrap()
            .unwrap();
        assert_eq!(
            StreamUtil::read_optional_tunnel_target(&mut domain_bytes.as_slice(), 1000).await,
            Ok(Some(domain))
        );

        // An Addr target round-trips too.
        let addr = TunnelTarget::Addr("198.18.0.7:443".parse().unwrap());
        let addr_bytes = StreamUtil::encode_tunnel_target(&Some(addr.clone()), true)
            .unwrap()
            .unwrap();
        assert_eq!(
            StreamUtil::read_optional_tunnel_target(&mut addr_bytes.as_slice(), 1000).await,
            Ok(Some(addr))
        );
    }

    #[test]
    fn encode_none_respects_mark_none() {
        assert_eq!(
            StreamUtil::encode_tunnel_target(&None, true).unwrap(),
            Some(vec![0])
        );
        assert_eq!(
            StreamUtil::encode_tunnel_target(&None, false).unwrap(),
            None
        );
    }

    #[test]
    fn encode_rejects_empty_and_oversized_domain() {
        let empty = TunnelTarget::Domain(String::new(), 443);
        assert!(StreamUtil::encode_tunnel_target(&Some(empty), true).is_err());
        let oversized = TunnelTarget::Domain("a".repeat(256), 443);
        assert!(StreamUtil::encode_tunnel_target(&Some(oversized), true).is_err());
    }

    #[tokio::test]
    async fn read_rejects_unknown_family_and_zero_len_domain() {
        // Unknown family byte.
        let mut bad = [9u8, 1, 2, 3].as_slice();
        assert_eq!(
            StreamUtil::read_tunnel_target(&mut bad, 1000).await,
            Err(TransferError::InvalidIPFamily)
        );
        // Domain family with zero length.
        let mut zero = [3u8, 0].as_slice();
        assert_eq!(
            StreamUtil::read_tunnel_target(&mut zero, 1000).await,
            Err(TransferError::InvalidDomain)
        );
        // Domain family with non-UTF8 host bytes.
        let mut bad_utf8 = [3u8, 2, 0xff, 0xfe, 0, 80].as_slice();
        assert_eq!(
            StreamUtil::read_tunnel_target(&mut bad_utf8, 1000).await,
            Err(TransferError::InvalidDomain)
        );
    }
}
