use crate::tcp::AsyncStream;
use crate::BUFFER_POOL;
use anyhow::Result;
use log::debug;
use quinn::{RecvStream, SendStream};
use rs_utilities::log_and_bail;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::error::Elapsed;

#[derive(Debug, PartialEq, Eq)]
enum TransferError {
    InternalError,
    TimeoutError,
}

pub struct StreamUtil {}

impl StreamUtil {
    pub fn start_flowing<S: AsyncStream>(
        tag: &'static str,
        stream: S,
        quic_stream: (SendStream, RecvStream),
        dst_addr: Option<SocketAddr>,
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

        let loop_count = Arc::new(AtomicI32::new(0));
        let loop_count_clone = loop_count.clone();
        const BUFFER_SIZE: usize = 8192;

        tokio::spawn(async move {
            let mut transfer_bytes = 0u64;
            let mut buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);
            loop {
                let c_start = loop_count.load(Ordering::Relaxed);
                let result = Self::quic_to_stream(
                    &mut quic_recv,
                    &mut stream_write,
                    &mut buffer,
                    &mut transfer_bytes,
                    stream_timeout_ms,
                )
                .await;
                let c_end = loop_count.fetch_add(1, Ordering::Relaxed);

                match result {
                    Err(TransferError::TimeoutError) => {
                        if c_start == c_end {
                            log::warn!("quic to tcp timeout");
                            break;
                        }
                    }
                    Ok(0) | Err(_) => {
                        break;
                    }
                    _ => {
                        // ok
                    }
                }
            }

            debug!("[{tag}] END  {index:<5}→  {peer_addr}, {transfer_bytes} bytes");
        });

        tokio::spawn(async move {
            if let Some(dst_addr) = dst_addr {
                Self::write_socket_addr(&mut quic_send, &dst_addr).await?;
            }

            let mut transfer_bytes = 0u64;
            let mut buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);
            loop {
                let c_start = loop_count_clone.load(Ordering::Relaxed);
                let result = Self::stream_to_quic(
                    &mut stream_read,
                    &mut quic_send,
                    &mut buffer,
                    &mut transfer_bytes,
                    stream_timeout_ms,
                )
                .await;
                let c_end = loop_count_clone.fetch_add(1, Ordering::Relaxed);

                match result {
                    Err(TransferError::TimeoutError) => {
                        if c_start == c_end {
                            log::warn!("tcp to quic timeout");
                            break;
                        }
                    }
                    Ok(0) | Err(_) => {
                        break;
                    }
                    _ => {
                        // ok
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

    // pub async fn process<S: AsyncStream>(
    //     tag: &'static str,
    //     stream: S,
    //     quic_stream: (SendStream, RecvStream),
    //     stream_timeout_ms: u64,
    // ) {
    //     let (r, w) = split(stream.take().unwrap());
    //     tokio::spawn(async move {
    //         let a = r;
    //     });
    //
    //     tokio::spawn(async move {
    //         let a = w;
    //     });
    //
    //     match conn.open_bi().await {
    //         Ok((mut quic_send, quic_recv)) => {
    //             Self::write_socket_addr(&mut quic_send, &dst_addr).await;
    //             let stream = stream.take().unwrap();
    //         }
    //         Err(e) => {
    //             log::error!("failed to open_bi, will retry: {e}");
    //         }
    //     }
    // }

    async fn write_socket_addr(quic_send: &mut SendStream, addr: &SocketAddr) -> Result<()> {
        match addr {
            SocketAddr::V4(v4) => {
                let ip = v4.ip().octets();
                let port = v4.port().to_be_bytes();
                quic_send.write_all(&[4]).await?;
                quic_send.write_all(&ip).await?;
                quic_send.write_all(&port).await?;
            }
            SocketAddr::V6(v6) => {
                let ip = v6.ip().octets();
                let port = v6.port().to_be_bytes();
                quic_send.write_all(&[6]).await?;
                quic_send.write_all(&ip).await?;
                quic_send.write_all(&port).await?;
            }
        }
        Ok(())
    }

    async fn read_socket_addr(quic_recv: &mut RecvStream) -> Result<SocketAddr> {
        let tag = quic_recv.read_u8().await?;

        match tag {
            4 => {
                let mut buf = [0u8; 6];
                quic_recv.read_exact(&mut buf).await?;
                let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&buf[0..4])?);
                let port = u16::from_be_bytes(buf[4..6].try_into().unwrap());
                Ok(SocketAddr::new(ip.into(), port))
            }
            6 => {
                let mut buf = [0u8; 18];
                quic_recv.read_exact(&mut buf).await?;
                let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[0..16])?);
                let port = u16::from_be_bytes(buf[16..18].try_into().unwrap());
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => {
                log_and_bail!("invalid address family tag: {tag}");
            }
        }
    }
}
