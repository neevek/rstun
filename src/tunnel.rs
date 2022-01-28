use crate::BufferPool;
use crate::ReadResult;
use anyhow::Result;
use log::info;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub struct Tunnel {
    buffer_pool: BufferPool,
}

impl Tunnel {
    pub fn new(buffer_pool: BufferPool) -> Self {
        Tunnel { buffer_pool }
    }

    pub async fn start(
        &self,
        tcp_stream: (OwnedReadHalf, OwnedWriteHalf),
        quic_stream: (SendStream, RecvStream),
    ) -> Result<()> {
        let (mut tcp_read, mut tcp_write) = tcp_stream;
        let (mut quic_send, mut quic_recv) = quic_stream;

        info!(
            "built tunnel for local conn, {} <=> {}",
            quic_send.id().index(),
            tcp_read.peer_addr().unwrap(),
        );

        let bp = self.buffer_pool.clone();
        tokio::spawn(async move {
            loop {
                let result = Self::tcp_to_quic(&mut tcp_read, &mut quic_send, &bp).await;
                if let Ok(ReadResult::EOF) | Err(_) = result {
                    break;
                }
            }
        });

        let bp = self.buffer_pool.clone();
        tokio::spawn(async move {
            loop {
                let result = Self::quic_to_tcp(&mut tcp_write, &mut quic_recv, &bp).await;
                if let Ok(ReadResult::EOF) | Err(_) = result {
                    break;
                }
            }
        });
        Ok(())
    }

    async fn tcp_to_quic(
        tcp_read: &mut OwnedReadHalf,
        quic_send: &mut SendStream, //local_read: &mut OwnedReadHalf,
        buffer_pool: &BufferPool,
    ) -> Result<ReadResult> {
        let mut buffer = buffer_pool.alloc(8192);

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
        buffer_pool: &BufferPool,
    ) -> Result<ReadResult> {
        let mut buffer = buffer_pool.alloc(8192);
        let result = quic_recv.read(&mut buffer[..]).await?;
        if let Some(len_read) = result {
            tcp_write.write_all(&buffer[..len_read]).await?;
            Ok(ReadResult::Succeeded)
        } else {
            Ok(ReadResult::EOF)
        }
    }
}
