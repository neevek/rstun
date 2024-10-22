use super::tcp_server::TcpMessage;
use crate::{TcpServer, BUFFER_POOL};
use anyhow::Result;
use log::{debug, error, info};
use quinn::{Connection, RecvStream, SendStream};
use std::borrow::BorrowMut;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;

#[derive(Debug, PartialEq, Eq)]
pub enum TransferError {
    InternalError,
}

pub struct TcpTunnel;

impl TcpTunnel {
    pub async fn start(
        tunnel_out: bool,
        conn: &Connection,
        tcp_server: &mut TcpServer,
        pending_stream: &mut Option<TcpStream>,
    ) {
        tcp_server.set_active(true);
        let mut tcp_receiver = tcp_server.take_tcp_receiver().unwrap();
        loop {
            let tcp_stream = match pending_stream.take() {
                Some(tcp_stream) => tcp_stream,
                None => match tcp_receiver.borrow_mut().recv().await {
                    Some(TcpMessage::Request(tcp_stream)) => tcp_stream,
                    _ => break,
                },
            };

            match conn.open_bi().await {
                Ok(quic_stream) => TcpTunnel::run(tunnel_out, tcp_stream, quic_stream),
                Err(e) => {
                    error!("failed to open_bi, will retry: {e}");
                    // self.post_tunnel_log(
                    //     format!("connection failed, will reconnect: {e}").as_str(),
                    // );
                    *pending_stream = Some(tcp_stream);
                    break;
                }
            }
        }
        // the tcp server will be reused when tunnel reconnects
        tcp_server.set_active(false);
    }

    fn run(tunnel_out: bool, tcp_stream: TcpStream, quic_stream: (SendStream, RecvStream)) {
        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
        let (mut quic_send, mut quic_recv) = quic_stream;

        let tag = if tunnel_out { "OUT" } else { "IN" };
        let index = quic_send.id().index();
        let in_addr = match tcp_read.peer_addr() {
            Ok(in_addr) => in_addr,
            Err(e) => {
                log::error!("failed to get peer_addr: {e:?}");
                return;
            }
        };

        debug!("[{tag}] START {index:<3} →  {in_addr:<20}");

        const BUFFER_SIZE: usize = 8192;

        tokio::spawn(async move {
            let mut transfer_bytes = 0u64;
            let mut loop_count = 0u32;
            let mut buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);
            loop {
                loop_count += 1;
                let result = Self::quic_to_tcp(
                    &mut quic_recv,
                    &mut tcp_write,
                    &mut buffer,
                    &mut transfer_bytes,
                )
                .await;
                if let Ok(0) | Err(_) = result {
                    break;
                }
            }

            debug!("[{tag}] END   {index:<3} →  {in_addr:<20} | ⟳ {loop_count:<8} | {transfer_bytes:<10}");
        });

        tokio::spawn(async move {
            let mut transfer_bytes = 0u64;
            let mut loop_count = 0u32;
            let mut buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);
            loop {
                loop_count += 1;
                let result = Self::tcp_to_quic(
                    &mut tcp_read,
                    &mut quic_send,
                    &mut buffer,
                    &mut transfer_bytes,
                )
                .await;
                if let Ok(0) | Err(_) = result {
                    break;
                }
            }

            debug!("[{tag}] END  {index:<3} ←  {in_addr:<20} | ⟳ {loop_count:<8} | {transfer_bytes:<10}");
        });
    }

    async fn tcp_to_quic(
        tcp_read: &mut OwnedReadHalf,
        quic_send: &mut SendStream,
        buffer: &mut [u8],
        transfer_bytes: &mut u64,
    ) -> Result<usize, TransferError> {
        let len_read = tcp_read
            .read(buffer)
            .await
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

    async fn quic_to_tcp(
        quic_recv: &mut RecvStream,
        tcp_write: &mut OwnedWriteHalf,
        buffer: &mut [u8],
        transfer_bytes: &mut u64,
    ) -> Result<usize, TransferError> {
        let result = quic_recv
            .read(buffer)
            .await
            .map_err(|_| TransferError::InternalError)?;
        if let Some(len_read) = result {
            *transfer_bytes += len_read as u64;
            tcp_write
                .write_all(&buffer[..len_read])
                .await
                .map_err(|_| TransferError::InternalError)?;
            Ok(len_read)
        } else {
            tcp_write
                .shutdown()
                .await
                .map_err(|_| TransferError::InternalError)?;
            Ok(0)
        }
    }

    pub async fn process(conn: quinn::Connection, upstream_addr: SocketAddr) {
        let remote_addr = &conn.remote_address();
        info!("start tcp streaming, {remote_addr} ↔ {upstream_addr}");

        loop {
            match conn.accept_bi().await {
                Err(quinn::ConnectionError::TimedOut { .. }) => {
                    info!("connection timeout: {remote_addr}");
                    break;
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!("connection closed: {remote_addr}");
                    break;
                }
                Err(e) => {
                    error!("failed to open accpet_bi: {remote_addr}, err: {e}");
                    break;
                }
                Ok(quic_stream) => tokio::spawn(async move {
                    match TcpStream::connect(&upstream_addr).await {
                        Ok(tcp_stream) => Self::run(true, tcp_stream, quic_stream),
                        Err(e) => error!("failed to connect to {upstream_addr}, err: {e}"),
                    }
                }),
            };
        }
    }
}
