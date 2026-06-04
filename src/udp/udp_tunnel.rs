use crate::BUFFER_POOL;
use crate::TunnelTarget;
use crate::UDP_PACKET_SIZE;
use crate::socket_addr_with_unspecified_ip_port;
use crate::tunnel_message::TunnelMessage;
use crate::udp::{UdpMessage, UdpPacket, UdpReceiver, UdpSender};
use crate::util::stream_util::StreamUtil;
use crate::{
    ChannelUdpConnectCtx, ChannelUdpConnection, ChannelUdpConnector, format_optional_socket_addr,
};
use anyhow::{Context, Result, anyhow, bail};
use dashmap::{DashMap, mapref::entry::Entry};
use log::{debug, warn};
use quinn::{Connection, RecvStream, SendStream};
use rs_utilities::log_and_bail;
use std::fmt;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::{net::UdpSocket, sync::Mutex};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct UdpStreamKey {
    local_addr: SocketAddr,
    peer_addr: Option<TunnelTarget>,
}

impl fmt::Display for UdpStreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.peer_addr {
            Some(peer_addr) => write!(f, "{} -> {peer_addr}", self.local_addr),
            None => write!(f, "{}", self.local_addr),
        }
    }
}

/// Whether the synthetic channel local address should be IPv6. A `Domain`
/// target has no known family at this hop, so fall back to the default upstream.
fn target_family_is_ipv6(
    target: &Option<TunnelTarget>,
    default_upstream: Option<SocketAddr>,
) -> bool {
    match target {
        Some(TunnelTarget::Addr(addr)) => addr.is_ipv6(),
        Some(TunnelTarget::Domain(..)) | None => default_upstream.is_some_and(|a| a.is_ipv6()),
    }
}

type ChannelReplyMap = DashMap<SocketAddr, Sender<UdpPacket>>;

fn format_udp_socket_label(udp_socket: &UdpSocket) -> String {
    let local_addr = match udp_socket.local_addr() {
        Ok(addr) => addr.to_string(),
        Err(err) => format!("local_addr_unavailable ({err})"),
    };
    let peer_addr = match udp_socket.peer_addr() {
        Ok(addr) => addr.to_string(),
        Err(err) => format!("peer_addr_unavailable ({err})"),
    };
    format!("{local_addr} -> {peer_addr}")
}

pub struct UdpTunnel;

impl UdpTunnel {
    pub async fn start_dynamic_accepting(
        conn: &quinn::Connection,
        default_upstream: Option<SocketAddr>,
        udp_timeout_ms: u64,
        udp_connector: Option<ChannelUdpConnector>,
    ) -> Result<()> {
        if let Some(connector) = udp_connector {
            Self::start_accepting_with_connector(
                conn,
                default_upstream,
                udp_timeout_ms,
                Some(connector),
            )
            .await
        } else {
            Self::start_accepting(conn, default_upstream, udp_timeout_ms).await
        }
    }

    pub async fn start_serving(
        conn: &quinn::Connection,
        udp_sender: &Sender<UdpMessage>,
        udp_receiver: &mut Receiver<UdpMessage>,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        debug!(
            "[udp] serving loop started, remote_addr={}",
            conn.remote_address()
        );
        let stream_map = Arc::new(DashMap::new());
        while let Some(UdpMessage::Packet(packet)) = udp_receiver.recv().await {
            let stream_key = UdpStreamKey {
                local_addr: packet.local_addr,
                peer_addr: packet.peer_addr.clone(),
            };
            let packet_sender = match UdpTunnel::open_stream(
                conn.clone(),
                udp_sender.clone(),
                stream_key.clone(),
                stream_map.clone(),
                udp_timeout_ms,
            )
            .await
            {
                Ok(packet_sender) => packet_sender,
                Err(e) => {
                    debug!("[udp] open stream failed, err={e}");
                    if conn.close_reason().is_some() {
                        debug!("[udp] connection closed, stopping serving loop");
                        break;
                    }
                    continue;
                }
            };

            if let Err(e) = packet_sender.try_send(packet) {
                match e {
                    mpsc::error::TrySendError::Full(_) => {
                        debug!("[udp] writer queue full, drop datagram, key={stream_key}");
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        warn!("[udp] enqueue failed, writer closed, key={stream_key}");
                        if conn.close_reason().is_some() {
                            debug!("[udp] connection closed, stopping serving loop");
                            break;
                        }
                    }
                }
            }
        }

        debug!(
            "[udp] serving loop stopped, remote_addr={}",
            conn.remote_address()
        );

        Ok(())
    }

    async fn open_stream(
        conn: Connection,
        udp_sender: Sender<UdpMessage>,
        stream_key: UdpStreamKey,
        stream_map: Arc<DashMap<UdpStreamKey, Sender<UdpPacket>>>,
        udp_timeout_ms: u64,
    ) -> Result<Sender<UdpPacket>> {
        if let Some(s) = stream_map.get(&stream_key) {
            return Ok(s.value().clone());
        }

        let (mut quic_send, mut quic_recv) =
            conn.open_bi().await.context("open_bi failed for udp out")?;

        // The flow's target is constant for the stream's lifetime, so it is sent
        // once at stream open (mirroring the TCP path) instead of per datagram.
        // Send it before publishing the stream so a failed open never leaves a
        // half-initialized map entry.
        StreamUtil::write_tunnel_target(&mut quic_send, &stream_key.peer_addr, true)
            .await
            .map_err(|e| anyhow!("send udp tunnel target failed: {e}"))?;

        let (packet_sender, mut packet_receiver) = mpsc::channel::<UdpPacket>(512);
        stream_map.insert(stream_key.clone(), packet_sender.clone());

        let stream_map_for_writer = stream_map.clone();
        let writer_stream_key = stream_key.clone();
        tokio::spawn(async move {
            debug!(
                "[udp] stream writer open key={writer_stream_key}, streams={}",
                stream_map_for_writer.len(),
            );
            while let Some(packet) = packet_receiver.recv().await {
                let payload_len = packet.payload.len();
                if let Err(e) = TunnelMessage::send_raw(&mut quic_send, &packet.payload).await {
                    warn!("[udp] send datagram failed, len={payload_len}, err={e}");
                    break;
                }
            }

            stream_map_for_writer.remove(&writer_stream_key);
            debug!(
                "[udp] stream writer close key={writer_stream_key}, streams={}",
                stream_map_for_writer.len(),
            );
        });

        let stream_map_for_reader = stream_map.clone();
        tokio::spawn(async move {
            debug!(
                "[udp] stream reader open key={stream_key}, streams={}",
                stream_map_for_reader.len(),
            );
            loop {
                let mut payload = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
                match tokio::time::timeout(
                    Duration::from_millis(udp_timeout_ms),
                    TunnelMessage::recv_raw(&mut quic_recv, &mut payload),
                )
                .await
                {
                    Ok(Ok(packet_len)) => {
                        payload.set_filled_len(packet_len as usize);
                        let packet = UdpPacket {
                            payload,
                            local_addr: stream_key.local_addr,
                            peer_addr: stream_key.peer_addr.clone(),
                        };
                        let _ = udp_sender.send(UdpMessage::Packet(packet)).await;
                    }
                    Ok(Err(_)) => {
                        // warn!("failed to read for udp, err: {e}");
                        break;
                    }
                    Err(_) => {
                        // Timeout occurred
                        break;
                    }
                }
            }

            stream_map_for_reader.remove(&stream_key);
            debug!(
                "[udp] stream reader close key={stream_key}, streams={}",
                stream_map_for_reader.len(),
            );
        });

        Ok(packet_sender)
    }

    pub async fn start_accepting(
        conn: &quinn::Connection,
        upstream_addr: Option<SocketAddr>,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        Self::start_accepting_with_connector(conn, upstream_addr, udp_timeout_ms, None).await
    }

    pub async fn start_accepting_with_connector(
        conn: &quinn::Connection,
        default_upstream: Option<SocketAddr>,
        udp_timeout_ms: u64,
        udp_connector: Option<ChannelUdpConnector>,
    ) -> Result<()> {
        let remote_addr = &conn.remote_address();
        let upstream_addr_label = format_optional_socket_addr(default_upstream);
        debug!(
            "[udp] accept loop started, remote_addr={remote_addr}, upstream={upstream_addr_label}"
        );

        if let Some(connector) = udp_connector {
            let ctx = ChannelUdpConnectCtx {
                default_upstream,
                timeout_ms: udp_timeout_ms,
            };
            match connector(ctx).await {
                Ok(ChannelUdpConnection {
                    sender: udp_sender,
                    receiver: udp_receiver,
                    stop,
                }) => {
                    let result = Self::start_accepting_channel(
                        conn,
                        udp_sender,
                        udp_receiver,
                        default_upstream,
                        udp_timeout_ms,
                    )
                    .await;
                    if let Some(stop) = stop {
                        stop();
                    }
                    result?;
                }
                Err(err) => {
                    warn!("[udp-ch] connector failed, err={err}");
                }
            }
        } else {
            loop {
                match conn.accept_bi().await {
                    Err(quinn::ConnectionError::TimedOut) => {
                        debug!("[udp] accept loop idle timeout, remote_addr={remote_addr}");
                        break;
                    }
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        debug!("[udp] accept loop peer closed, remote_addr={remote_addr}");
                        break;
                    }
                    Err(e) => {
                        warn!("[udp] accept failed, remote_addr={remote_addr}, err={e}");
                        break;
                    }
                    Ok((quic_send, quic_recv)) => {
                        tokio::spawn(async move {
                            if let Err(err) = Self::process(
                                quic_send,
                                quic_recv,
                                default_upstream,
                                udp_timeout_ms,
                            )
                            .await
                            {
                                warn!("[udp] stream processing failed, err={err}");
                            }
                        });
                    }
                };
            }
        }

        debug!("[udp] accept loop stopped, remote_addr={remote_addr}");

        Ok(())
    }

    async fn start_accepting_channel(
        conn: &quinn::Connection,
        udp_sender: UdpSender,
        udp_receiver: UdpReceiver,
        default_upstream: Option<SocketAddr>,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        let remote_addr = &conn.remote_address();
        debug!("[udp-ch] accept loop started, remote_addr={remote_addr}");

        let next_local_port = Arc::new(AtomicU16::new(10000));
        let reply_map = Arc::new(ChannelReplyMap::new());
        Self::spawn_channel_reply_router(reply_map.clone(), udp_receiver);

        loop {
            match conn.accept_bi().await {
                Err(quinn::ConnectionError::TimedOut) => {
                    debug!("[udp-ch] accept loop idle timeout, remote_addr={remote_addr}");
                    break;
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!("[udp-ch] accept loop peer closed, remote_addr={remote_addr}");
                    break;
                }
                Err(e) => {
                    warn!("[udp-ch] accept failed, remote_addr={remote_addr}, err={e}");
                    break;
                }
                Ok((quic_send, quic_recv)) => Self::spawn_channel_bridge_stream(
                    quic_send,
                    quic_recv,
                    udp_sender.clone(),
                    reply_map.clone(),
                    next_local_port.clone(),
                    default_upstream,
                    udp_timeout_ms,
                ),
            }
        }

        debug!("[udp-ch] accept loop stopped, remote_addr={remote_addr}");

        Ok(())
    }

    async fn process(
        quic_send: SendStream,
        mut quic_recv: RecvStream,
        upstream_addr: Option<SocketAddr>,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        let quic_send = Arc::new(Mutex::new(quic_send));

        // The flow's target is sent once at stream open. Resolve a Domain target
        // here at the tunnel egress; a fixed `upstream_addr` always wins.
        let target = StreamUtil::read_optional_tunnel_target(&mut quic_recv, udp_timeout_ms)
            .await
            .map_err(|e| anyhow!("read udp tunnel target failed: {e}"))?;
        let resolved = match upstream_addr {
            Some(addr) => addr,
            None => match target {
                Some(target) => Self::resolve_udp_target(&target, udp_timeout_ms).await?,
                None => bail!("no valid upstream_addr to connect"),
            },
        };

        let udp_socket = match Self::create_peer_socket_and_exchange_data(
            resolved,
            quic_send.clone(),
            udp_timeout_ms,
        )
        .await?
        {
            Some(socket) => socket,
            None => bail!("failed to create upstream udp socket for {resolved}"),
        };

        let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
        loop {
            match tokio::time::timeout(
                Duration::from_millis(udp_timeout_ms),
                TunnelMessage::recv_raw(&mut quic_recv, &mut buf),
            )
            .await
            {
                Ok(Ok(packet_len)) => {
                    udp_socket
                        .0
                        .send(&buf[..packet_len as usize])
                        .await
                        .context("failed to send datagram through udp_socket")?;
                }
                Ok(Err(e)) => {
                    warn!("[udp] read from tunnel failed, err={e}");
                    break;
                }
                Err(_) => {
                    // timeout on receiving datagrams from the tunnel
                    break;
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    }

    /// Resolves a UDP flow target to a concrete upstream address. `Addr` is
    /// returned as-is; `Domain` resolves at the egress via the system resolver
    /// (mirroring how the TCP path connects by hostname).
    async fn resolve_udp_target(target: &TunnelTarget, udp_timeout_ms: u64) -> Result<SocketAddr> {
        match target {
            TunnelTarget::Addr(addr) => Ok(*addr),
            TunnelTarget::Domain(host, port) => {
                let addrs: Vec<SocketAddr> = tokio::time::timeout(
                    Duration::from_millis(udp_timeout_ms),
                    tokio::net::lookup_host((host.as_str(), *port)),
                )
                .await
                .map_err(|_| anyhow!("udp resolve timeout for {host}:{port}"))?
                .with_context(|| format!("udp resolve failed for {host}:{port}"))?
                .collect();
                // Prefer IPv4: a UDP `connect` does not verify reachability, so a
                // resolver-first IPv6 on a host with broken IPv6 would silently
                // blackhole the flow (TCP egress sidesteps this by trying every
                // address). Fall back to the first result for IPv6-only names.
                let resolved = addrs
                    .iter()
                    .find(|a| a.is_ipv4())
                    .or_else(|| addrs.first())
                    .copied()
                    .with_context(|| format!("udp resolve empty for {host}:{port}"))?;
                debug!("[udp] resolve host={host}:{port} -> ip={resolved}");
                Ok(resolved)
            }
        }
    }

    async fn process_channel(
        quic_send: SendStream,
        quic_recv: RecvStream,
        udp_sender: UdpSender,
        reply_map: Arc<ChannelReplyMap>,
        next_local_port: Arc<AtomicU16>,
        default_upstream: Option<SocketAddr>,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        Self::process_channel_io(
            quic_send,
            quic_recv,
            udp_sender,
            reply_map,
            next_local_port,
            default_upstream,
            udp_timeout_ms,
        )
        .await
    }

    async fn process_channel_io<W, R>(
        quic_send: W,
        quic_recv: R,
        udp_sender: UdpSender,
        reply_map: Arc<ChannelReplyMap>,
        next_local_port: Arc<AtomicU16>,
        default_upstream: Option<SocketAddr>,
        udp_timeout_ms: u64,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin + Send + 'static,
        R: AsyncRead + Unpin,
    {
        let (reply_tx, mut reply_rx) = mpsc::channel::<UdpPacket>(512);
        let writer = tokio::spawn(async move {
            let mut quic_send = quic_send;
            while let Some(packet) = reply_rx.recv().await {
                TunnelMessage::send_raw_to(&mut quic_send, &packet.payload).await?;
            }
            Ok::<(), anyhow::Error>(())
        });

        let mut quic_recv = quic_recv;

        // The flow's target is sent once at stream open; stamp it on every
        // forwarded datagram so the chained next hop knows the destination.
        let target = StreamUtil::read_optional_tunnel_target(&mut quic_recv, udp_timeout_ms)
            .await
            .map_err(|e| anyhow!("read udp tunnel target failed: {e}"))?;
        let ipv6 = target_family_is_ipv6(&target, default_upstream);

        let mut local_addr = None;
        loop {
            let mut payload = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
            match tokio::time::timeout(
                Duration::from_millis(udp_timeout_ms),
                TunnelMessage::recv_raw_from(&mut quic_recv, &mut payload),
            )
            .await
            {
                Ok(Ok(packet_len)) => {
                    let local_addr = Self::channel_local_addr(
                        &mut local_addr,
                        &next_local_port,
                        &reply_map,
                        &reply_tx,
                        ipv6,
                    )?;
                    payload.set_filled_len(packet_len as usize);
                    udp_sender
                        .send(UdpMessage::Packet(UdpPacket {
                            payload,
                            local_addr,
                            peer_addr: target.clone(),
                        }))
                        .await
                        .ok();
                }
                Ok(Err(e)) => {
                    warn!("[udp-ch] read from tunnel failed, err={e}");
                    break;
                }
                Err(_) => {
                    break;
                }
            }
        }

        if let Some(local_addr) = local_addr {
            reply_map.remove(&local_addr);
        }

        drop(reply_tx);
        writer.await.map_err(anyhow::Error::from)??;

        Ok(())
    }

    fn spawn_channel_bridge_stream(
        quic_send: SendStream,
        quic_recv: RecvStream,
        udp_sender: UdpSender,
        reply_map: Arc<ChannelReplyMap>,
        next_local_port: Arc<AtomicU16>,
        default_upstream: Option<SocketAddr>,
        udp_timeout_ms: u64,
    ) {
        tokio::spawn(async move {
            let result = Self::process_channel(
                quic_send,
                quic_recv,
                udp_sender,
                reply_map,
                next_local_port,
                default_upstream,
                udp_timeout_ms,
            )
            .await;
            if let Err(err) = result {
                warn!("[udp-ch] bridge stream failed, err={err}");
            }
        });
    }

    fn spawn_channel_reply_router(reply_map: Arc<ChannelReplyMap>, mut udp_receiver: UdpReceiver) {
        tokio::spawn(async move {
            while let Some(msg) = udp_receiver.recv().await {
                match msg {
                    UdpMessage::Packet(packet) => {
                        if let Some(reply_tx) = reply_map
                            .get(&packet.local_addr)
                            .map(|entry| entry.value().clone())
                        {
                            let _ = reply_tx.send(packet).await;
                        } else {
                            // debug!(
                            //     "debugdrop udp reply with no matching local addr {}, len:{}",
                            //     packet.local_addr,
                            //     packet.payload.len()
                            // );
                        }
                    }
                    UdpMessage::Quit => break,
                }
            }
        });
    }

    fn channel_local_addr(
        local_addr: &mut Option<SocketAddr>,
        next_local_port: &AtomicU16,
        reply_map: &ChannelReplyMap,
        reply_tx: &Sender<UdpPacket>,
        ipv6: bool,
    ) -> Result<SocketAddr> {
        if let Some(local_addr) = *local_addr {
            return Ok(local_addr);
        }

        let allocated_local_addr =
            Self::reserve_channel_local_addr(next_local_port, ipv6, reply_map, reply_tx)?;
        *local_addr = Some(allocated_local_addr);
        Ok(allocated_local_addr)
    }

    async fn create_peer_socket_and_exchange_data(
        addr: SocketAddr,
        quic_send: Arc<Mutex<SendStream>>,
        udp_timeout_ms: u64,
    ) -> Result<Option<(Arc<UdpSocket>, oneshot::Sender<()>)>> {
        let local_addr = socket_addr_with_unspecified_ip_port(addr.is_ipv6());
        match UdpSocket::bind(local_addr).await {
            Ok(udp_socket) => {
                if let Err(e) = udp_socket.connect(addr).await {
                    log_and_bail!("failed to connect to upstream: {addr}, err: {e}");
                };

                let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
                let udp_socket = Arc::new(udp_socket);

                Self::udp_to_quic(
                    udp_socket.clone(),
                    quic_send.clone(),
                    udp_timeout_ms,
                    shutdown_rx,
                );

                Ok(Some((udp_socket, shutdown_tx)))
            }
            Err(e) => {
                log_and_bail!("failed to bind to localhost, err: {e}");
            }
        }
    }

    fn udp_to_quic(
        udp_socket: Arc<UdpSocket>,
        quic_send: Arc<Mutex<SendStream>>,
        udp_timeout_ms: u64,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        tokio::spawn(async move {
            let socket_label = format_udp_socket_label(&udp_socket);
            debug!("[udp] upstream socket open, {socket_label}");
            let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
            loop {
                tokio::select! {
                    biased;

                    _ = &mut shutdown_rx => {
                        break;
                    }

                    result = tokio::time::timeout(
                        Duration::from_millis(udp_timeout_ms),
                        udp_socket.recv(&mut buf)
                    ) => {
                        match result {
                            Ok(Ok(len)) => {
                                let mut quic_send = quic_send.lock().await;
                                TunnelMessage::send_raw(&mut quic_send, &buf[..len])
                                    .await
                                    .ok();
                            }
                            Ok(Err(e)) => {
                                warn!("[udp] upstream recv failed, err={e}");
                                break;
                            }
                            Err(_) => {
                                // timeout on receiving datagrams from upstream
                                break;
                            }
                        }
                    }
                }
            }
            // debug!("dropped udp stream, {socket_label}");
        });
    }

    fn reserve_channel_local_addr(
        next_local_port: &AtomicU16,
        ipv6: bool,
        reply_map: &ChannelReplyMap,
        reply_tx: &Sender<UdpPacket>,
    ) -> Result<SocketAddr> {
        for _ in 0..u16::MAX {
            let port = next_local_port.fetch_add(1, Ordering::Relaxed);
            if port == 0 {
                continue;
            }

            let local_addr = Self::channel_local_addr_for_port(port, ipv6);

            match reply_map.entry(local_addr) {
                Entry::Occupied(_) => continue,
                Entry::Vacant(entry) => {
                    entry.insert(reply_tx.clone());
                    return Ok(local_addr);
                }
            }
        }

        bail!("no free synthetic udp channel local_addr available")
    }

    fn channel_local_addr_for_port(port: u16, ipv6: bool) -> SocketAddr {
        let mut local_addr = socket_addr_with_unspecified_ip_port(ipv6);
        local_addr.set_port(port);
        local_addr
    }
}

#[cfg(test)]
mod tests {
    use super::UdpTunnel;
    use crate::BUFFER_POOL;
    use crate::TunnelTarget;
    use crate::tunnel_message::TunnelMessage;
    use crate::udp::{UdpMessage, UdpPacket};
    use crate::util::stream_util::StreamUtil;
    use dashmap::DashMap;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{Arc, atomic::AtomicU16};
    use tokio::io::{AsyncWriteExt, duplex, split};
    use tokio::sync::mpsc;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn resolve_udp_target_returns_addr_unchanged() {
        let addr: SocketAddr = "203.0.113.5:443".parse().unwrap();
        let resolved = UdpTunnel::resolve_udp_target(&TunnelTarget::Addr(addr), 1000)
            .await
            .expect("resolve addr");
        assert_eq!(resolved, addr);
    }

    #[tokio::test]
    async fn resolve_udp_target_prefers_ipv4_for_domain() {
        // `localhost` resolves (via /etc/hosts, offline) to both 127.0.0.1 and
        // ::1. The egress resolver must prefer the IPv4 address, since a UDP
        // `connect` cannot probe IPv6 reachability.
        let resolved = UdpTunnel::resolve_udp_target(
            &TunnelTarget::Domain("localhost".to_string(), 5353),
            1000,
        )
        .await
        .expect("resolve localhost");
        assert!(resolved.is_ipv4(), "expected IPv4, got {resolved}");
        assert_eq!(resolved, "127.0.0.1:5353".parse().unwrap());
    }

    #[tokio::test]
    async fn resolve_udp_target_accepts_numeric_domain_host() {
        // A numeric host string resolves to itself without a DNS round-trip.
        let resolved = UdpTunnel::resolve_udp_target(
            &TunnelTarget::Domain("198.51.100.9".to_string(), 9000),
            1000,
        )
        .await
        .expect("resolve numeric host");
        assert_eq!(resolved, "198.51.100.9:9000".parse().unwrap());
    }

    #[test]
    fn reserve_channel_local_addr_matches_upstream_address_family() {
        let next_local_port = AtomicU16::new(10_000);
        let reply_map = DashMap::new();
        let (reply_tx, _reply_rx) = mpsc::channel(1);

        let ipv4_addr =
            UdpTunnel::reserve_channel_local_addr(&next_local_port, false, &reply_map, &reply_tx)
                .expect("allocate ipv4 addr");
        assert_eq!(
            ipv4_addr,
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 10_000)
        );

        let ipv6_addr =
            UdpTunnel::reserve_channel_local_addr(&next_local_port, true, &reply_map, &reply_tx)
                .expect("allocate ipv6 addr");
        assert_eq!(
            ipv6_addr,
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 10_001)
        );

        let default_addr =
            UdpTunnel::reserve_channel_local_addr(&next_local_port, false, &reply_map, &reply_tx)
                .expect("allocate default addr");
        assert_eq!(
            default_addr,
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 10_002)
        );
    }

    #[test]
    fn reserve_channel_local_addr_skips_zero_and_active_keys() {
        let next_local_port = AtomicU16::new(10_000);
        let reply_map = DashMap::new();
        let (reply_tx, _reply_rx) = mpsc::channel(1);

        let in_use_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 10_000);
        reply_map.insert(in_use_addr, reply_tx.clone());

        let addr =
            UdpTunnel::reserve_channel_local_addr(&next_local_port, false, &reply_map, &reply_tx)
                .expect("allocate addr after skipping active key");
        assert_eq!(addr, SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 10_001));

        let wrap_port = AtomicU16::new(u16::MAX);
        let wrap_addr =
            UdpTunnel::reserve_channel_local_addr(&wrap_port, false, &reply_map, &reply_tx)
                .expect("allocate addr after wrap");
        assert_eq!(
            wrap_addr,
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), u16::MAX)
        );

        let after_wrap_addr =
            UdpTunnel::reserve_channel_local_addr(&wrap_port, false, &reply_map, &reply_tx)
                .expect("allocate addr after skipping zero");
        assert_eq!(
            after_wrap_addr,
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 1)
        );
    }

    #[tokio::test]
    async fn process_channel_io_preserves_framing_while_writing_replies() {
        let reply_map = Arc::new(DashMap::new());
        let next_local_port = Arc::new(AtomicU16::new(10_000));
        let (udp_sender, mut udp_receiver) = mpsc::channel::<UdpMessage>(8);
        let (process_stream, mut peer_stream) = duplex(4096);
        let (quic_recv, quic_send) = split(process_stream);
        let dst_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 5353);

        let process_task = tokio::spawn(UdpTunnel::process_channel_io(
            quic_send,
            quic_recv,
            udp_sender,
            reply_map.clone(),
            next_local_port,
            None,
            1_000,
        ));

        // New framing: the flow target is written once at stream open, then
        // datagrams are sent raw with no per-packet metadata.
        let target_bytes =
            StreamUtil::encode_tunnel_target(&Some(TunnelTarget::Addr(dst_addr)), true)
                .expect("encode tunnel target")
                .expect("target bytes");
        peer_stream
            .write_all(&target_bytes)
            .await
            .expect("send tunnel target");
        TunnelMessage::send_raw_to(&mut peer_stream, b"first")
            .await
            .expect("send first payload");

        let first_packet = timeout(Duration::from_secs(1), udp_receiver.recv())
            .await
            .expect("first packet timeout")
            .expect("first packet missing");
        let UdpMessage::Packet(first_packet) = first_packet else {
            panic!("unexpected quit");
        };
        assert_eq!(&first_packet.payload[..], b"first");

        let local_addr = first_packet.local_addr;
        let reply_tx = reply_map
            .get(&local_addr)
            .map(|entry| entry.value().clone())
            .expect("reply tx missing");
        reply_tx
            .send(UdpPacket {
                payload: BUFFER_POOL.alloc_from_slice(b"reply"),
                local_addr,
                peer_addr: Some(TunnelTarget::Addr(dst_addr)),
            })
            .await
            .expect("send reply");

        // No second metadata frame — the target was already sent once at open.
        TunnelMessage::send_raw_to(&mut peer_stream, b"second")
            .await
            .expect("send second payload");

        let mut reply_buf = [0u8; 32];
        let reply_len = TunnelMessage::recv_raw_from(&mut peer_stream, &mut reply_buf)
            .await
            .expect("read reply");
        assert_eq!(&reply_buf[..reply_len as usize], b"reply");

        let second_packet = timeout(Duration::from_secs(1), udp_receiver.recv())
            .await
            .expect("second packet timeout")
            .expect("second packet missing");
        let UdpMessage::Packet(second_packet) = second_packet else {
            panic!("unexpected quit");
        };
        assert_eq!(&second_packet.payload[..], b"second");
        assert_eq!(second_packet.local_addr, local_addr);

        drop(reply_tx);
        drop(peer_stream);

        timeout(Duration::from_secs(1), process_task)
            .await
            .expect("process task timeout")
            .expect("process task join failed")
            .expect("process task failed");
        assert!(reply_map.get(&local_addr).is_none());
    }
}
