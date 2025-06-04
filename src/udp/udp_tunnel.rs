use crate::{
    tcp::tcp_server::{TcpMessage, TcpSender},
    tunnel_message::{TunnelMessage, UdpLocalAddr},
    udp::{udp_packet::UdpPacket, udp_server::UdpMessage},
    BUFFER_POOL, UDP_PACKET_SIZE,
};

use super::udp_server::UdpServer;
use anyhow::{bail, Context, Result};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use quinn::{Connection, RecvStream, SendStream};
use rs_utilities::log_and_bail;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::net::UdpSocket;

type TSafe<T> = Arc<tokio::sync::Mutex<T>>;

pub struct UdpTunnel;

impl UdpTunnel {
    pub async fn start(
        conn: &quinn::Connection,
        mut udp_server: UdpServer,
        tcp_sender: Option<TcpSender>,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        let stream_map = Arc::new(DashMap::new());
        udp_server.set_active(true);
        let mut udp_receiver = udp_server.take_receiver().unwrap();

        debug!("start transfering udp packets from: {}", udp_server.addr());
        while let Some(UdpMessage::Packet(packet)) = udp_receiver.recv().await {
            let quic_send = match UdpTunnel::open_stream(
                conn.clone(),
                udp_server.clone(),
                packet.addr,
                stream_map.clone(),
                udp_timeout_ms,
            )
            .await
            {
                Ok(quic_send) => quic_send,
                Err(e) => {
                    error!("{e}");
                    if conn.close_reason().is_some() {
                        if let Some(tcp_sender) = tcp_sender {
                            tcp_sender.send(TcpMessage::Quit).await.ok();
                        }
                        debug!("connection is closed, will quit");
                        break;
                    }
                    continue;
                }
            };

            // send the packet using an async task
            tokio::spawn(async move {
                let mut quic_send = quic_send.lock().await;
                let payload_len = packet.payload.len();
                TunnelMessage::send_raw(&mut quic_send, &packet.payload)
                    .await
                    .inspect_err(|e| {
                        warn!(
                            "failed to send datagram({payload_len}) through the tunnel, err: {e}"
                        );
                    })
                    .ok();
            });
        }

        // put the receiver back
        udp_server.set_active(false);
        udp_server.put_receiver(udp_receiver);
        info!("local udp server paused");
        Ok(())
    }

    async fn open_stream(
        conn: Connection,
        udp_server: UdpServer,
        peer_addr: SocketAddr,
        stream_map: Arc<DashMap<SocketAddr, TSafe<SendStream>>>,
        udp_timeout_ms: u64,
    ) -> Result<TSafe<SendStream>> {
        if let Some(s) = stream_map.get(&peer_addr) {
            return Ok((*s).clone());
        }

        let (mut quic_send, mut quic_recv) =
            conn.open_bi().await.context("open_bi failed for udp out")?;

        TunnelMessage::send(
            &mut quic_send,
            &TunnelMessage::ReqUdpStart(UdpLocalAddr(peer_addr)),
        )
        .await?;

        debug!(
            "new udp session: {peer_addr}, streams: {}",
            stream_map.len()
        );

        let quic_send = Arc::new(tokio::sync::Mutex::new(quic_send));
        stream_map.insert(peer_addr, quic_send.clone());
        let udp_sender = udp_server.clone_udp_sender();

        let stream_map = stream_map.clone();
        tokio::spawn(async move {
            debug!(
                "start udp stream: {peer_addr}, streams: {}",
                stream_map.len()
            );
            loop {
                let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
                match tokio::time::timeout(
                    Duration::from_millis(udp_timeout_ms),
                    TunnelMessage::recv_raw(&mut quic_recv, &mut buf),
                )
                .await
                {
                    Ok(Ok(len)) => {
                        unsafe {
                            buf.set_len(len as usize);
                        }
                        let packet = UdpPacket {
                            payload: buf,
                            addr: peer_addr,
                        };
                        udp_sender.send(UdpMessage::Packet(packet)).await.ok();
                    }
                    e => {
                        match e {
                            Ok(Err(e)) => {
                                warn!("failed to read for udp, err: {e}");
                            }
                            Err(_) => {
                                // timedout
                                // debug!("timeout on reading udp packet");
                            }
                            _ => unreachable!(""),
                        }
                        break;
                    }
                }
            }

            stream_map.remove(&peer_addr);
            debug!(
                "drop udp session: {peer_addr}, streams: {}",
                stream_map.len()
            );
        });

        Ok(quic_send)
    }

    pub async fn process(conn: &quinn::Connection, upstream_addr: SocketAddr, udp_timeout_ms: u64) {
        let remote_addr = &conn.remote_address();
        info!("start udp streaming, {remote_addr} ↔  {upstream_addr}");

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
                    error!("failed to accpet_bi: {remote_addr}, err: {e}");
                    break;
                }
                Ok((quic_send, quic_recv)) => tokio::spawn(async move {
                    Self::process_internal(quic_send, quic_recv, upstream_addr, udp_timeout_ms)
                        .await
                }),
            };
        }

        info!("connection for udp out is dropped");
    }

    async fn process_internal(
        mut quic_send: SendStream,
        mut quic_recv: RecvStream,
        upstream_addr: SocketAddr,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        let peer_addr = match TunnelMessage::recv(&mut quic_recv).await {
            Ok(TunnelMessage::ReqUdpStart(peer_addr)) => peer_addr.0,
            _ => {
                log_and_bail!("unexpected first udp message");
            }
        };
        debug!("new udp session: {peer_addr}");

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let udp_socket = match UdpSocket::bind(local_addr).await {
            Ok(udp_socket) => Arc::new(udp_socket),
            Err(e) => {
                log_and_bail!("failed to bind to localhost, err: {e:?}");
            }
        };

        if let Err(e) = udp_socket.connect(upstream_addr).await {
            log_and_bail!("failed to connect to upstream: {upstream_addr}, err: {e:?}");
        };

        let udp_socket_clone = udp_socket.clone();
        tokio::spawn(async move {
            debug!("start udp stream: {peer_addr} ←  {upstream_addr}");
            let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
            loop {
                match tokio::time::timeout(
                    Duration::from_millis(udp_timeout_ms),
                    udp_socket_clone.recv(&mut buf),
                )
                .await
                {
                    Ok(Ok(len)) => {
                        TunnelMessage::send_raw(&mut quic_send, &buf[..len])
                            .await
                            .ok();
                    }
                    e => {
                        match e {
                            Ok(Err(e)) => {
                                warn!("failed to receive datagrams from upstream: {upstream_addr}, err: {e:?}");
                            }
                            Err(_) => {
                                debug!(
                                    "timeout on receiving datagrams from upstream: {upstream_addr}"
                                );
                            }
                            _ => unreachable!(""),
                        }
                        break;
                    }
                }
            }
            debug!("drop udp stream: {peer_addr} ←  {upstream_addr}");
        });

        debug!("start sending datagrams to upstream, {peer_addr} →  {upstream_addr}");
        let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
        loop {
            match tokio::time::timeout(
                Duration::from_millis(udp_timeout_ms),
                TunnelMessage::recv_raw(&mut quic_recv, &mut buf),
            )
            .await
            {
                Ok(Ok(len)) => {
                    udp_socket
                        .send(&buf[..len as usize])
                        .await
                        .context("failed to send datagram through udp_socket")?;
                }
                e => {
                    match e {
                        Ok(Err(e)) => {
                            warn!("failed to read from udp packet from tunnel, err: {e:?}");
                        }
                        Err(_) => {
                            debug!("timeout on reading udp packet from tunnel");
                        }
                        _ => unreachable!(""),
                    }
                    break;
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    }
}
