use crate::tcp::AsyncStream;
use crate::BUFFER_POOL;
use anyhow::Result;
use log::debug;
use quinn::{RecvStream, SendStream};
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
}
