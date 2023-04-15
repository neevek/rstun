use crate::ReadResult;
use crate::BUFFER_POOL;
use anyhow::Result;
use log::info;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub struct Tunnel {}

impl Tunnel {
    pub fn new() -> Self {
        Tunnel {}
    }

    pub async fn start(
        &self,
        tcp_stream: (OwnedReadHalf, OwnedWriteHalf),
        quic_stream: (SendStream, RecvStream),
    ) {
        let (mut tcp_read, mut tcp_write) = tcp_stream;
        let (mut quic_send, mut quic_recv) = quic_stream;

        info!(
            "built tunnel for local conn, {} <=> {}",
            quic_send.id().index(),
            tcp_read.peer_addr().unwrap(),
        );

        tokio::spawn(async move {
            loop {
                let result = Self::tcp_to_quic(&mut tcp_read, &mut quic_send).await;
                if let Ok(ReadResult::EOF) | Err(_) = result {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            loop {
                let result = Self::quic_to_tcp(&mut tcp_write, &mut quic_recv).await;
                if let Ok(ReadResult::EOF) | Err(_) = result {
                    break;
                }
            }
        });
    }

    async fn tcp_to_quic(
        tcp_read: &mut OwnedReadHalf,
        quic_send: &mut SendStream, //local_read: &mut OwnedReadHalf,
    ) -> Result<ReadResult> {
        let mut buffer = BUFFER_POOL.alloc_and_fill(8192);
        let len_read = tcp_read.read(&mut buffer[..]).await?;
        if len_read > 0 {
            quic_send.write_all(&buffer[..len_read]).await?;
            Ok(ReadResult::Succeeded)
        } else {
            quic_send.finish().await?;
            Ok(ReadResult::EOF)
        }
    }

    async fn quic_to_tcp(
        tcp_write: &mut OwnedWriteHalf,
        quic_recv: &mut RecvStream,
    ) -> Result<ReadResult> {
        let mut buffer = BUFFER_POOL.alloc_and_fill(8192);
        let result = quic_recv.read(&mut buffer[..]).await?;
        if let Some(len_read) = result {
            tcp_write.write_all(&buffer[..len_read]).await?;
            Ok(ReadResult::Succeeded)
        } else {
            Ok(ReadResult::EOF)
        }
    }
}
