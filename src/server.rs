use crate::tcp::tcp_server::{TcpMessage, TcpSender};
use crate::udp::udp_packet::UdpPacket;
use crate::udp::udp_server::{UdpMessage, UdpServer};
use crate::{
    pem_util, ControlStream, ServerConfig, TcpServer, Tunnel, TunnelInInfo, TunnelMessage,
    TunnelOutInfo, TunnelType, Upstream, UpstreamType, SUPPORTED_CIPHER_SUITES,
};
use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use log::{debug, error, info, warn};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{congestion, Endpoint, TransportConfig};
use quinn_proto::{IdleTimeout, VarInt};
use rs_utilities::log_and_bail;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::Duration;

#[derive(Debug)]
pub struct Server {
    config: ServerConfig,
    tcp_server_ports: Mutex<Vec<u16>>,
    udp_server_ports: Mutex<Vec<u16>>,
    endpoint: Option<Endpoint>,
}

impl Server {
    pub fn new(config: ServerConfig) -> Arc<Self> {
        Arc::new(Server {
            config,
            tcp_server_ports: Mutex::new(Vec::new()),
            udp_server_ports: Mutex::new(Vec::new()),
            endpoint: None,
        })
    }

    pub fn bind(self: &mut Arc<Self>) -> Result<SocketAddr> {
        let config = &self.config;
        let addr: SocketAddr = config
            .addr
            .parse()
            .context(format!("invalid address: {}", config.addr))?;

        let quinn_server_cfg = Self::load_quinn_server_config(&self.config)?;
        let endpoint = quinn::Endpoint::server(quinn_server_cfg, addr).map_err(|e| {
            error!("failed to bind tunnel server on address: {addr}, err: {e}");
            e
        })?;

        info!(
            "tunnel server is bound on address: {}, idle_timeout: {}",
            endpoint.local_addr()?,
            config.max_idle_timeout_ms
        );

        let ep = endpoint.clone();
        let config = self.config.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600 * 24)).await;
                match Self::load_quinn_server_config(&config) {
                    Ok(quinn_server_cfg) => {
                        info!("updated quinn server config!");
                        ep.set_server_config(Some(quinn_server_cfg));
                    }
                    Err(e) => {
                        error!("failed to load quinn server config:{e}");
                    }
                }
            }
        });

        Arc::get_mut(self).unwrap().endpoint = Some(endpoint);

        Ok(addr)
    }

    fn load_quinn_server_config(config: &ServerConfig) -> Result<quinn::ServerConfig> {
        let (certs, key) =
            Self::read_certs_and_key(config.cert_path.as_str(), config.key_path.as_str())
                .context("failed to read certificate or key")?;

        let default_provider = rustls::crypto::ring::default_provider();
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: SUPPORTED_CIPHER_SUITES.into(),
            ..default_provider
        };

        let tls_server_cfg = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        let mut transport_cfg = TransportConfig::default();
        transport_cfg.stream_receive_window(quinn::VarInt::from_u32(1024 * 1024));
        transport_cfg.receive_window(quinn::VarInt::from_u32(1024 * 1024 * 2));
        transport_cfg.send_window(1024 * 1024 * 2);
        transport_cfg.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
        if config.max_idle_timeout_ms > 0 {
            let timeout = IdleTimeout::from(VarInt::from_u32(config.max_idle_timeout_ms as u32));
            transport_cfg.max_idle_timeout(Some(timeout));
            transport_cfg.keep_alive_interval(Some(Duration::from_millis(
                config.max_idle_timeout_ms * 2 / 3,
            )));
        }
        transport_cfg.max_concurrent_bidi_streams(VarInt::from_u32(1024));

        let quic_server_cfg = Arc::new(QuicServerConfig::try_from(tls_server_cfg)?);
        let mut quinn_server_cfg = quinn::ServerConfig::with_crypto(quic_server_cfg);
        quinn_server_cfg.transport = Arc::new(transport_cfg);
        Ok(quinn_server_cfg)
    }

    pub async fn serve(self: &Arc<Self>) -> Result<()> {
        let endpoint = self.endpoint.as_ref().context("failed")?;
        while let Some(client_conn) = endpoint.accept().await {
            let mut this = self.clone();
            tokio::spawn(async move {
                let client_conn = client_conn.await?;
                let tun_type = this.authenticate_connection(client_conn).await?;

                match tun_type {
                    TunnelType::Out(info) => {
                        if let Some(addr) = info.udp_upstream_addr {
                            let conn = info.conn.clone();
                            if info.tcp_upstream_addr.is_some() {
                                tokio::spawn(async move {
                                    Self::process_udp_out(conn, addr).await;
                                });
                            } else {
                                Self::process_udp_out(conn, addr).await;
                            }
                        }

                        if let Some(addr) = info.tcp_upstream_addr {
                            Self::process_tcp_out(info.conn.clone(), addr)
                                .await
                                .map_err(|e| error!("process_tcp_out failed: {e}"))
                                .ok();
                        }
                    }

                    TunnelType::In(info) => {
                        let mut udp_server_addr = None;
                        let mut tcp_server_addr = None;

                        if let Some(udp_server) = info.udp_server {
                            let addr = udp_server.addr();
                            this.udp_server_ports.lock().await.push(addr.port());
                            udp_server_addr = Some(addr);

                            let conn = info.conn.clone();
                            match &info.tcp_server {
                                Some(tcp_server) => {
                                    let that = this.clone();
                                    let tcp_sender = tcp_server.clone_tcp_sender();
                                    tokio::spawn(async move {
                                        that.process_udp_in(conn, udp_server, Some(tcp_sender))
                                            .await
                                            .ok();
                                    });
                                }
                                None => {
                                    this.process_udp_in(conn, udp_server, None).await.ok();
                                }
                            }
                        }

                        if let Some(tcp_server) = info.tcp_server {
                            let addr = tcp_server.addr();
                            this.tcp_server_ports.lock().await.push(addr.port());
                            tcp_server_addr = Some(addr);

                            this.process_tcp_in(info.conn.clone(), tcp_server, info.ctrl_stream)
                                .await
                                .map_err(|e| error!("process_in_connection failed: {e}"))
                                .ok();
                        }

                        if let Some(addr) = udp_server_addr {
                            let mut v = this.udp_server_ports.lock().await;
                            if let Some(index) = v.iter().position(|x| *x == addr.port()) {
                                v.remove(index);
                            }
                        }

                        if let Some(addr) = tcp_server_addr {
                            let mut v = this.tcp_server_ports.lock().await;
                            if let Some(index) = v.iter().position(|x| *x == addr.port()) {
                                v.remove(index);
                            }
                        }
                    }
                }

                Ok::<(), anyhow::Error>(())
            });
        }

        info!("quit!");

        Ok(())
    }

    async fn authenticate_connection(
        self: &mut Arc<Self>,
        conn: quinn::Connection,
    ) -> Result<TunnelType> {
        let remote_addr = &conn.remote_address();

        info!("received connection, authenticating... addr:{remote_addr}");
        let (mut quic_send, mut quic_recv) = conn
            .accept_bi()
            .await
            .context(format!("login request not received in time: {remote_addr}"))?;

        info!("received bi_stream request: {remote_addr}");
        let tunnel_type;
        match TunnelMessage::recv(&mut quic_recv).await? {
            TunnelMessage::ReqOutLogin(login_info) => {
                info!("received OutLogin request: {remote_addr}");

                Self::check_password(self.config.password.as_str(), login_info.password.as_str())?;

                let tcp_upstream_addr = self.obtain_upstream_addr(
                    false,
                    UpstreamType::Tcp,
                    &login_info.tcp_upstream,
                    &self.config.tcp_upstreams,
                )?;
                let udp_upstream_addr = self.obtain_upstream_addr(
                    false,
                    UpstreamType::Udp,
                    &login_info.udp_upstream,
                    &self.config.udp_upstreams,
                )?;

                if tcp_upstream_addr.is_none() && udp_upstream_addr.is_none() {
                    TunnelMessage::send(
                        &mut quic_send,
                        &TunnelMessage::RespFailure(
                            "both tcp and udp upstream address are none".to_string(),
                        ),
                    )
                    .await?;
                    log_and_bail!("both tcp and udp upstream address are none");
                }

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;
                tunnel_type = TunnelType::Out(TunnelOutInfo {
                    conn,
                    tcp_upstream_addr,
                    udp_upstream_addr,
                });
                info!("sent response for OutLogin request: {remote_addr}");
            }

            TunnelMessage::ReqInLogin(login_info) => {
                info!("received InLogin request: {remote_addr}");

                Self::check_password(self.config.password.as_str(), login_info.password.as_str())?;

                let tcp_upstream_addr = self.obtain_upstream_addr(
                    true,
                    UpstreamType::Tcp,
                    &login_info.tcp_upstream,
                    &self.config.tcp_upstreams,
                )?;
                let udp_upstream_addr = self.obtain_upstream_addr(
                    true,
                    UpstreamType::Udp,
                    &login_info.udp_upstream,
                    &self.config.udp_upstreams,
                )?;

                if tcp_upstream_addr.is_none() && udp_upstream_addr.is_none() {
                    TunnelMessage::send(
                        &mut quic_send,
                        &TunnelMessage::RespFailure(
                            "both tcp and udp upstream address are none".to_string(),
                        ),
                    )
                    .await?;
                    log_and_bail!("both tcp and udp upstream address are none");
                }

                let tcp_server = match tcp_upstream_addr {
                    Some(tcp_upstream_addr) => {
                        let guarded_tcp_server_ports = self.tcp_server_ports.lock().await;
                        if guarded_tcp_server_ports.contains(&tcp_upstream_addr.port()) {
                            TunnelMessage::send(
                                &mut quic_send,
                                &TunnelMessage::RespFailure(
                                    "remote tcp port is in use".to_string(),
                                ),
                            )
                            .await?;
                            log_and_bail!("tcp port is in use: {}", tcp_upstream_addr.port());
                        }

                        match TcpServer::bind_and_start(tcp_upstream_addr).await {
                            Ok(tcp_server) => Some(tcp_server),
                            Err(e) => {
                                TunnelMessage::send(
                                    &mut quic_send,
                                    &TunnelMessage::RespFailure(
                                        "tcp server failed to bind".to_string(),
                                    ),
                                )
                                .await?;
                                log_and_bail!("remote tcp server failed to bind: {e}");
                            }
                        }
                    }
                    _ => None,
                };

                let udp_server = match udp_upstream_addr {
                    Some(udp_upstream_addr) => {
                        let guarded_udp_server_ports = self.udp_server_ports.lock().await;
                        if guarded_udp_server_ports.contains(&udp_upstream_addr.port()) {
                            TunnelMessage::send(
                                &mut quic_send,
                                &TunnelMessage::RespFailure(
                                    "remote udp port is in use".to_string(),
                                ),
                            )
                            .await?;
                            if let Some(mut tcp_server) = tcp_server {
                                tcp_server.shutdown().await.ok();
                            }
                            log_and_bail!("udp port is in use: {}", udp_upstream_addr.port());
                        }

                        match UdpServer::bind_and_start(udp_upstream_addr).await {
                            Ok(udp_server) => Some(udp_server),
                            Err(e) => {
                                TunnelMessage::send(
                                    &mut quic_send,
                                    &TunnelMessage::RespFailure(
                                        "udp server failed to bind".to_string(),
                                    ),
                                )
                                .await?;
                                if let Some(mut tcp_server) = tcp_server {
                                    tcp_server.shutdown().await.ok();
                                }
                                log_and_bail!("remote udp server failed to bind: {e}");
                            }
                        }
                    }
                    _ => None,
                };

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;

                tunnel_type = TunnelType::In(TunnelInInfo {
                    conn,
                    tcp_server,
                    udp_server,
                    ctrl_stream: ControlStream {
                        quic_send,
                        quic_recv,
                    },
                });

                info!("sent response for InLogin request: {remote_addr}");
            }

            _ => {
                log_and_bail!("received unepxected message");
            }
        }

        info!("connection authenticated! addr: {remote_addr}");

        Ok(tunnel_type)
    }

    fn obtain_upstream_addr(
        &self,
        is_tunnel_in: bool,
        upstream_type: UpstreamType,
        upstream: &Upstream,
        configured_upstreams: &[SocketAddr],
    ) -> Result<Option<SocketAddr>> {
        Ok(match upstream {
            Upstream::PeerDefault => {
                if is_tunnel_in {
                    log_and_bail!("explicit port is required to start TunnelIn mode tunneling");
                }

                if configured_upstreams.is_empty() {
                    log_and_bail!(
                        r#"explicit {upstream_type} upstream address must be specified when logging in
                             because there's no default upstream specified for the server"#
                    );
                }
                if configured_upstreams.len() > 1 {
                    log_and_bail!(
                        r#"explicit {upstream_type} upstream address must be specified because there are
                            more than one upstreams specified for the server"#
                    );
                }

                Some(*configured_upstreams.first().unwrap())
            }

            Upstream::ClientSpecified(addr) => {
                if is_tunnel_in && !addr.ip().is_unspecified() && !addr.ip().is_loopback() {
                    log_and_bail!(
                        r#"only loopback or unspecified IP is allowed for TunnelIn mode
                         tunelling: {addr:?}, or simply specify a port without the IP part"#
                    );
                }

                Some(*addr)
            }

            Upstream::NotSpecified => None,
        })
    }

    async fn process_udp_out(client_conn: quinn::Connection, upstream_addr: SocketAddr) {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let remote_addr = &client_conn.remote_address();
        info!("start udp streaming in TunnelOut mode, {remote_addr} ↔ {upstream_addr}");

        let mtu = client_conn.max_datagram_size().unwrap_or(1500);
        loop {
            match client_conn.read_datagram().await {
                Ok(datagram) => {
                    let packet = match UdpPacket::try_from(datagram) {
                        Ok(packet) => packet,
                        Err(e) => {
                            warn!("invalid packet, err: {e:?}");
                            continue;
                        }
                    };

                    let sock = match UdpSocket::bind(local_addr).await {
                        Ok(sock) => sock,
                        Err(e) => {
                            warn!("failed to bind to localhost, err: {e:?}");
                            continue;
                        }
                    };

                    if let Err(e) = sock.connect(upstream_addr).await {
                        warn!("failed to connect to upstream: {upstream_addr}, err: {e:?}");
                        continue;
                    };

                    let conn = client_conn.clone();
                    tokio::spawn(async move {
                        let len = packet.payload.len();
                        let addr = &packet.addr;
                        debug!("send datagram({len}), {addr} → {upstream_addr}");
                        sock.send(&packet.payload).await.ok();

                        let mut buf = BytesMut::zeroed(mtu);
                        match tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
                            .await
                        {
                            Ok(Ok(len)) => {
                                let buf = buf.split_to(len);
                                let addr = &packet.addr;
                                debug!("read datagram({len}), {addr} ← {upstream_addr}");
                                conn.send_datagram(UdpPacket::new(buf.into(), packet.addr).into())
                                    .unwrap();
                            }
                            Ok(Err(e)) => {
                                warn!("failed to read udp socket, err: {e:?}");
                            }
                            Err(_) => {
                                debug!("timeout on reading udp packet");
                            }
                        }
                    });
                }

                Err(e) => {
                    error!("failed to read_datagram, err: {e:?}");
                    break;
                }
            }
        }
    }

    async fn process_tcp_out(conn: quinn::Connection, upstream_addr: SocketAddr) -> Result<()> {
        let remote_addr = &conn.remote_address();
        info!("start tcp streaming in TunnelOut mode, {remote_addr} ↔ {upstream_addr}");

        loop {
            match conn.accept_bi().await {
                Err(quinn::ConnectionError::TimedOut { .. }) => {
                    info!("connection timeout: {remote_addr}");
                    return Ok(());
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!("connection closed: {remote_addr}");
                    return Ok(());
                }
                Err(e) => {
                    log_and_bail!("failed to open accpet_bi: {remote_addr}, err: {e}");
                }
                Ok(quic_stream) => tokio::spawn(async move {
                    match TcpStream::connect(&upstream_addr).await {
                        Ok(tcp_stream) => Tunnel::new().start(true, tcp_stream, quic_stream),
                        Err(e) => error!("failed to connect to {upstream_addr}, err: {e}"),
                    }
                }),
            };
        }
    }

    async fn process_udp_in(
        self: &Arc<Self>,
        conn: quinn::Connection,
        mut udp_server: UdpServer,
        tcp_sender: Option<TcpSender>,
    ) -> Result<()> {
        info!(
            "start udp streaming in TunnelIn mode, {} ↔ {}",
            udp_server.addr(),
            conn.remote_address(),
        );

        let mut udp_server_clone = udp_server.clone();
        let udp_sender = udp_server.clone_udp_sender();
        let conn_clone = conn.clone();
        let addr = udp_server.addr();

        tokio::spawn(async move {
            udp_server.set_active(true);
            let mut udp_receiver = udp_server.take_receiver().unwrap();
            while let Some(UdpMessage::Packet(packet)) = udp_receiver.recv().await {
                let len = packet.payload.len();
                let addr = &packet.addr;
                debug!("send datagram({len}) from {addr}",);
                if let Err(e) = conn.send_datagram(packet.into()) {
                    warn!("sending packet failed: {e:?}");
                }
            }

            // on receiving UdpMessage::Quit, quit and put the receiver back
            udp_server.set_active(false);
            udp_server.put_receiver(udp_receiver);
            info!("udp server quit");
        });

        loop {
            match conn_clone.read_datagram().await {
                Ok(datagram) => {
                    if let Ok(packet) = UdpPacket::try_from(datagram) {
                        let len = packet.payload.len();
                        let addr = &packet.addr;
                        debug!("send datagram({len}) to {addr}",);
                        udp_sender.send(UdpMessage::Packet(packet)).await.ok();
                    }
                }
                Err(e) => {
                    if conn_clone.close_reason().is_some() {
                        udp_server_clone.pause().await;
                        if let Some(tcp_sender) = tcp_sender {
                            tcp_sender.send(TcpMessage::Quit).await.ok();
                        }
                        debug!("connection is closed, will quit");
                        break;
                    }
                    warn!("read_datagram failed: {e}");
                }
            }
        }

        info!("udp server quit: {addr}");

        Ok(())
    }

    async fn process_tcp_in(
        self: &Arc<Self>,
        conn: quinn::Connection,
        mut tcp_server: TcpServer,
        mut ctrl_stream: ControlStream,
    ) -> Result<()> {
        info!(
            "start tcp streaming in TunnelIn mode, {} ↔ {}",
            tcp_server.addr(),
            conn.remote_address(),
        );

        let tcp_sender = tcp_server.clone_tcp_sender();
        tokio::spawn(async move {
            TunnelMessage::recv(&mut ctrl_stream.quic_recv).await.ok();
            // send Quit to the previous session to signify exit, so the current
            // session can start immediately, see below
            tcp_sender.send(TcpMessage::Quit).await.ok();
            Ok::<(), anyhow::Error>(())
        });

        tcp_server.set_active(true);
        while let Some(TcpMessage::Request(tcp_stream)) = tcp_server.recv().await {
            match conn.open_bi().await {
                Ok(quic_stream) => Tunnel::new().start(false, tcp_stream, quic_stream),
                _ => {
                    log_and_bail!("failed to open bi_streams to client, quit");
                }
            }
        }

        let addr = tcp_server.addr();
        tcp_server.shutdown().await.ok();

        info!("tcp server quit: {addr}");

        Ok(())
    }

    fn read_certs_and_key(
        cert_path: &str,
        key_path: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let (certs, key) = if cert_path.is_empty() {
            info!("will use auto-generated self-signed certificate.");
            warn!("============================= WARNING ==============================");
            warn!("No valid certificate path is provided, a self-signed certificate");
            warn!("for the domain \"localhost\" is generated.");
            warn!("============== Be cautious, this is for TEST only!!! ===============");
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
            let cert = CertificateDer::from(cert.cert);
            (vec![cert], PrivateKeyDer::Pkcs8(key))
        } else {
            let certs = pem_util::load_certificates_from_pem(cert_path)
                .context(format!("failed to read cert file: {cert_path}"))?;
            let key = pem_util::load_private_key_from_pem(key_path)
                .context(format!("failed to read key file: {key_path}"))?;
            (certs, key)
        };

        Ok((certs, key))
    }

    fn check_password(password1: &str, password2: &str) -> Result<()> {
        if password1 != password2 {
            log_and_bail!("passwords don't match!");
        }
        Ok(())
    }
}
