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
    TimeoutError,
}

impl Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalError => write!(f, "InternalError"),
            Self::InvalidIPAddress => write!(f, "InvalidIPAddress"),
            Self::InvalidIPFamily => write!(f, "InvalidIPFamily"),
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
                log::error!("failed to obtain peer address:{e}");
                return;
            }
        };

        let (mut stream_read, mut stream_write) = tokio::io::split(stream);
        let (mut quic_send, mut quic_recv) = quic_stream;
        let index = quic_send.id().index();

        debug!("[{tag}] START {index:<3} →  {peer_addr:<20}");

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

            debug!("[{tag}] END  {index:<5}→  {peer_addr}, {transfer_bytes} bytes");
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

            debug!("[{tag}] END  {index:<4}←  {peer_addr}, {transfer_bytes} bytes");
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

    pub async fn write_socket_addr(
        quic_send: &mut SendStream,
        addr: &Option<SocketAddr>,
        mark_none: bool,
    ) -> Result<()> {
        match addr {
            Some(SocketAddr::V4(v4)) => {
                let mut buf = [0u8; 1 + 4 + 2];
                buf[0] = 4;
                buf[1..5].copy_from_slice(&v4.ip().octets());
                buf[5..7].copy_from_slice(&v4.port().to_be_bytes());
                quic_send.write_all(&buf[..7]).await?;
            }
            Some(SocketAddr::V6(v6)) => {
                let mut buf = [0u8; 1 + 16 + 2];
                buf[0] = 6;
                buf[1..17].copy_from_slice(&v6.ip().octets());
                buf[17..19].copy_from_slice(&v6.port().to_be_bytes());
                quic_send.write_all(&buf[..19]).await?;
            }
            None => {
                if mark_none {
                    quic_send.write_u8(0).await?;
                }
            }
        };
        Ok(())
    }

    pub async fn read_socket_addr(
        quic_recv: &mut RecvStream,
        stream_timeout_ms: u64,
    ) -> Result<SocketAddr, TransferError> {
        let mut buf = [0u8; 19];
        tokio::time::timeout(
            Duration::from_millis(stream_timeout_ms),
            quic_recv.read_exact(&mut buf[..7]),
        )
        .await
        .map_err(|_: Elapsed| TransferError::TimeoutError)?
        .map_err(|_| TransferError::InternalError)?;

        match buf[0] {
            4 => {
                let ip = Ipv4Addr::from(
                    <[u8; 4]>::try_from(&buf[1..5]).map_err(|_| TransferError::InvalidIPAddress)?,
                );
                let port = u16::from_be_bytes(buf[5..7].try_into().unwrap());
                Ok(SocketAddr::new(ip.into(), port))
            }
            6 => {
                tokio::time::timeout(
                    Duration::from_millis(stream_timeout_ms),
                    quic_recv.read_exact(&mut buf[7..]),
                )
                .await
                .map_err(|_: Elapsed| TransferError::TimeoutError)?
                .map_err(|_| TransferError::InternalError)?;

                let ip = Ipv6Addr::from(
                    <[u8; 16]>::try_from(&buf[1..17])
                        .map_err(|_| TransferError::InvalidIPAddress)?,
                );
                let port = u16::from_be_bytes(buf[17..19].try_into().unwrap());
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => {
                log::error!("invalid address family");
                Err(TransferError::InvalidIPFamily)
            }
        }
    }
}
