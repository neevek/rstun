use std::time::Duration;

use crate::BUFFER_POOL;
use anyhow::Result;
use log::debug;
use quinn::{RecvStream, SendStream};
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::error::Elapsed;

pub struct Tunnel {}

#[derive(Debug, PartialEq, Eq)]
pub enum TransferError {
    Timeout,
    InternalError,
}

impl Tunnel {
    pub fn new() -> Self {
        Tunnel {}
    }

    pub fn start(
        &self,
        tunnel_out: bool,
        tcp_stream: TcpStream,
        quic_stream: (SendStream, RecvStream),
    ) {
        tokio::spawn(async move {
            Self::run(tunnel_out, tcp_stream, quic_stream).await.ok();
        });
    }

    async fn run(
        tunnel_out: bool,
        mut tcp_stream: TcpStream,
        quic_stream: (SendStream, RecvStream),
    ) -> Result<(), TransferError> {
        let (mut tcp_read, mut tcp_write) = tcp_stream.split();
        let (mut quic_send, mut quic_recv) = quic_stream;

        let tag = if tunnel_out { "OUT" } else { "IN" };
        let index = quic_send.id().index();
        let in_addr = tcp_read
            .peer_addr()
            .map_err(|_| TransferError::InternalError)?;

        debug!("[{tag}] tunnel start   : {index:<3} ↔ {in_addr:<20}");

        const BUFFER_SIZE: usize = 8192;
        let mut inbound_buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);
        let mut outbound_buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);

        let mut tx_bytes = 0u64;
        let mut rx_bytes = 0u64;
        let mut tcp_stream_eos = false;
        let mut quic_stream_eos = false;
        let mut loop_count = 0;

        loop {
            loop_count += 1;
            let result = if !tcp_stream_eos && !quic_stream_eos {
                tokio::select! {
                    result = Self::transfer_data_with_timeout(
                        &mut tcp_read,
                        &mut quic_send,
                        &mut inbound_buffer,
                        &mut tx_bytes,
                        &mut tcp_stream_eos) => result,
                    result = Self::transfer_data_with_timeout(
                        &mut quic_recv,
                        &mut tcp_write,
                        &mut outbound_buffer,
                        &mut rx_bytes,
                        &mut quic_stream_eos) => result,
                }
            } else if !quic_stream_eos {
                Self::transfer_data_with_timeout(
                    &mut quic_recv,
                    &mut tcp_write,
                    &mut outbound_buffer,
                    &mut rx_bytes,
                    &mut quic_stream_eos,
                )
                .await
            } else {
                Self::transfer_data_with_timeout(
                    &mut tcp_read,
                    &mut quic_send,
                    &mut inbound_buffer,
                    &mut tx_bytes,
                    &mut tcp_stream_eos,
                )
                .await
            };

            match result {
                Ok(0) => {
                    if tcp_stream_eos && quic_stream_eos {
                        break;
                    }
                }
                Err(TransferError::Timeout) => {
                    debug!("[{tag}] tunnel timeout: {index:<3} ↔ {in_addr:<20} | ⟳ {loop_count:<8}| ↑ {tx_bytes:<10} ↓ {rx_bytes:<10}");
                    break;
                }
                Err(_) => break,
                Ok(_) => {}
            }
        }

        debug!("[{tag}] tunnel end    : {index:<3} ↔ {in_addr:<20} | ⟳ {loop_count:<8}| ↑ {tx_bytes:<10} ↓ {rx_bytes:<10}");

        Ok(())
    }

    async fn transfer_data_with_timeout<R, W>(
        reader: &mut R,
        writer: &mut W,
        buffer: &mut [u8],
        out_bytes: &mut u64,
        eos_flag: &mut bool,
    ) -> Result<usize, TransferError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        match tokio::time::timeout(Duration::from_secs(15), reader.read(buffer))
            .await
            .map_err(|_: Elapsed| TransferError::Timeout)?
        {
            Ok(0) => {
                if !*eos_flag {
                    *eos_flag = true;
                    writer
                        .shutdown()
                        .await
                        .map_err(|_| TransferError::InternalError)?;
                }
                Ok(0)
            }
            Ok(n) => {
                *out_bytes += n as u64;
                writer
                    .write_all(&buffer[..n])
                    .await
                    .map_err(|_| TransferError::InternalError)?;
                Ok(n)
            }
            Err(_) => Err(TransferError::InternalError), // Connection mostly reset by peer
        }
    }
}

impl Default for Tunnel {
    fn default() -> Self {
        Self::new()
    }
}
