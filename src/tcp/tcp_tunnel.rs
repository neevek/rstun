use crate::tcp::TcpMessage;
use crate::util::stream_util::StreamUtil;
use crate::TcpServer;
use log::{debug, error, info};
use std::borrow::BorrowMut;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

pub struct TcpTunnel;

impl TcpTunnel {
    pub async fn start_serving(
        tunnel_out: bool,
        conn: &quinn::Connection,
        tcp_server: &mut TcpServer,
        pending_stream: &mut Option<TcpStream>,
        tcp_timeout_ms: u64,
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
                Ok(quic_stream) => StreamUtil::start_flowing(
                    if tunnel_out { "OUT" } else { "IN" },
                    tcp_stream,
                    quic_stream,
                    tcp_timeout_ms,
                ),
                Err(e) => {
                    error!("failed to open_bi, will retry: {e}");
                    *pending_stream = Some(tcp_stream);
                    break;
                }
            }
        }
        tcp_server.put_tcp_receiver(tcp_receiver);
        // the tcp server will be reused when tunnel reconnects
        tcp_server.set_active(false);
    }

    pub async fn start_accepting(
        conn: &quinn::Connection,
        upstream_addr: SocketAddr,
        tcp_timeout_ms: u64,
    ) {
        let remote_addr = &conn.remote_address();
        info!("start tcp streaming, {remote_addr} ↔  {upstream_addr}");

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
                    match tokio::time::timeout(
                        Duration::from_secs(5),
                        TcpStream::connect(&upstream_addr),
                    )
                    .await
                    {
                        Ok(Ok(tcp_stream)) => StreamUtil::start_flowing(
                            "OUT",
                            tcp_stream,
                            quic_stream,
                            tcp_timeout_ms,
                        ),
                        Ok(Err(e)) => error!("failed to connect to {upstream_addr}, err: {e}"),
                        Err(_) => error!("timeout connecting to {upstream_addr}"),
                    }
                }),
            };
        }
    }
}
