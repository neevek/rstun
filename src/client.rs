use crate::{
    pem_util, socket_addr_with_unspecified_ip_port,
    tcp::tcp_server::{TcpMessage, TcpSender},
    tunnel_info_bridge::{TunnelInfo, TunnelInfoBridge, TunnelInfoType, TunnelTraffic},
    udp::{
        udp_packet::UdpPacket,
        udp_server::{UdpMessage, UdpServer},
    },
    ClientConfig, ControlStream, SelectedCipherSuite, TcpServer, Tunnel, TunnelMessage,
    TUNNEL_MODE_OUT,
};
use anyhow::{bail, Context, Result};
use backon::ExponentialBuilder;
use backon::Retryable;
use bytes::BytesMut;
use log::{debug, error, info, warn};
use quinn::{
    congestion, crypto::rustls::QuicClientConfig, Connection, RecvStream, SendStream,
    TransportConfig,
};
use quinn_proto::{IdleTimeout, VarInt};
use rs_utilities::{
    dns::{self, DNSQueryOrdering, DNSResolverConfig, DNSResolverLookupIpStrategy},
    log_and_bail, unwrap_or_return,
};
use rustls::{
    client::danger::ServerCertVerified,
    crypto::{ring::cipher_suite, CryptoProvider},
    RootCertStore, SupportedCipherSuite,
};
use rustls_platform_verifier::{self, Verifier};
use serde::Serialize;
use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex, Once},
    time::Duration,
};
#[cfg(not(target_os = "windows"))]
use tokio::signal::unix::{signal, SignalKind};
use tokio::{net::TcpStream, net::UdpSocket, sync::mpsc::Sender, task::JoinHandle};
use x509_parser::prelude::{FromDer, X509Certificate};

const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S.%3f";
const DEFAULT_SERVER_PORT: u16 = 3515;
const POST_TRAFFIC_DATA_INTERVAL_SECS: u64 = 10;
static INIT: Once = Once::new();

#[derive(Clone, Serialize)]
pub enum ClientState {
    Idle = 0,
    Preparing,
    Connecting,
    Connected,
    LoggingIn,
    Tunneling,
    Terminated,
}

impl Display for ClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientState::Idle => write!(f, "Idle"),
            ClientState::Preparing => write!(f, "Preparing"),
            ClientState::Connecting => write!(f, "Connecting"),
            ClientState::Connected => write!(f, "Connected"),
            ClientState::LoggingIn => write!(f, "LoggingIn"),
            ClientState::Tunneling => write!(f, "Tunneling"),
            ClientState::Terminated => write!(f, "Terminated"),
        }
    }
}

struct ThreadSafeState {
    remote_conn: Option<Connection>,
    ctrl_stream: Option<ControlStream>,
    tcp_server: Option<TcpServer>,
    udp_server: Option<UdpServer>,
    client_state: ClientState,
    channel_message_sender: Option<Sender<TcpMessage>>,
    total_traffic_data: TunnelTraffic,
    tunnel_info_bridge: TunnelInfoBridge,
    on_info_report_enabled: bool,
    is_terminated: bool,
}

impl ThreadSafeState {
    fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            ctrl_stream: None,
            tcp_server: None,
            udp_server: None,
            remote_conn: None,
            client_state: ClientState::Idle,
            channel_message_sender: None,
            total_traffic_data: TunnelTraffic::default(),
            tunnel_info_bridge: TunnelInfoBridge::new(),
            on_info_report_enabled: false,
            is_terminated: false,
        }))
    }
}

macro_rules! inner_state {
    ($self:ident, $field:ident) => {
        (*$self.inner_state.lock().unwrap()).$field
    };
}

pub struct Client {
    pub config: ClientConfig,
    inner_state: Arc<Mutex<ThreadSafeState>>,
}

impl Client {
    pub fn new(config: ClientConfig) -> Arc<Self> {
        INIT.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .unwrap();
        });

        Arc::new(Client {
            config,
            inner_state: ThreadSafeState::new(),
        })
    }

    pub fn start_tunneling(self: &Arc<Self>) {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(self.config.threads)
            .build()
            .unwrap()
            .block_on(async { self.connect_and_serve().await });
    }

    pub async fn start_tcp_server(self: &Arc<Self>) -> Result<Option<SocketAddr>> {
        if self.config.mode != TUNNEL_MODE_OUT {
            bail!("call start_tcp_server() for TunnelOut mode only");
        }
        let addr = unwrap_or_return!(self.config.local_tcp_server_addr, Ok(None));

        self.post_tunnel_log("preparing tcp server...");

        // create a local tcp server for 'OUT' tunnel
        // let tcp_server = TcpServer::bind_and_start(addr).await?;

        let bind_tcp_server = || async { TcpServer::bind_and_start(addr).await };
        let tcp_server = bind_tcp_server
            .retry(ExponentialBuilder::default().with_max_times(10))
            .sleep(tokio::time::sleep)
            .notify(|err: &anyhow::Error, dur: Duration| {
                warn!("will retry after {:?}, err:{:?}", dur, err);
            })
            .await?;

        let addr = tcp_server.addr();

        info!("[TunnelOut] tcp server bound to: {addr}");

        self.post_tunnel_log(format!("[TunnelOut] tcp server bound to: {addr}").as_str());

        inner_state!(self, channel_message_sender) = Some(tcp_server.clone_tcp_sender());
        inner_state!(self, tcp_server) = Some(tcp_server);
        Ok(Some(addr))
    }

    pub async fn start_udp_server(self: &Arc<Self>) -> Result<Option<SocketAddr>> {
        if self.config.mode != TUNNEL_MODE_OUT {
            bail!("call start_udp_server() for TunnelOut mode only");
        }
        let addr = unwrap_or_return!(self.config.local_udp_server_addr, Ok(None));

        self.post_tunnel_log("preparing udp server...");

        // create a local udp server for 'OUT' tunnel
        let bind_udp_server = || async { UdpServer::bind_and_start(addr).await };
        let udp_server = bind_udp_server
            .retry(ExponentialBuilder::default().with_max_times(10))
            .sleep(tokio::time::sleep)
            .notify(|err: &anyhow::Error, dur: Duration| {
                warn!("will retry after {:?}, err:{:?}", dur, err);
            })
            .await?;
        let addr = udp_server.addr();

        info!("[TunnelOut] udp server bound to: {addr}");

        self.post_tunnel_log(format!("[TunnelOut] udp server bound to: {addr}").as_str());

        inner_state!(self, udp_server) = Some(udp_server);
        Ok(Some(addr))
    }

    pub fn get_config(self: &Arc<Self>) -> ClientConfig {
        self.config.clone()
    }

    pub fn stop(self: &Arc<Self>) -> Result<()> {
        Ok(())
    }

    pub fn connect_and_serve_async(self: &Arc<Self>) -> JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move { this.connect_and_serve().await })
    }

    async fn connect_and_serve(self: &Arc<Self>) {
        info!(
            "connecting, idle_timeout:{}, retry_timeout:{}, threads:{}",
            self.config.max_idle_timeout_ms, self.config.wait_before_retry_ms, self.config.threads
        );

        let mut connect_retry_count = 0;
        let connect_max_retry = self.config.connect_max_retry;
        let wait_before_retry_ms = self.config.wait_before_retry_ms;

        let mut pending_conn = None;
        loop {
            match self.connect().await {
                Ok(_) => {
                    connect_retry_count = 0;

                    if self.config.mode == TUNNEL_MODE_OUT {
                        self.serve_outgoing(&mut pending_conn).await.ok();
                    } else {
                        self.serve_incoming().await.ok();
                    }
                }

                Err(e) => {
                    error!("connect failed, err: {e}");
                    if connect_max_retry > 0 {
                        connect_retry_count += 1;
                        if connect_retry_count >= connect_max_retry {
                            info!("quit after having retried for {connect_retry_count} times");
                            break;
                        }
                    }

                    debug!("will wait for {wait_before_retry_ms}ms before retrying...");
                    tokio::time::sleep(Duration::from_millis(wait_before_retry_ms)).await;
                }
            }

            if !self.should_retry() {
                info!("client quit!");
                break;
            }

            info!("connection dropped, will reconnect.");
        }

        self.post_tunnel_log("quit");
        self.set_and_post_tunnel_state(ClientState::Terminated);
    }

    async fn connect(self: &Arc<Self>) -> Result<()> {
        self.set_and_post_tunnel_state(ClientState::Connecting);

        let mut transport_cfg = TransportConfig::default();
        transport_cfg.stream_receive_window(quinn::VarInt::from_u32(1024 * 1024));
        transport_cfg.receive_window(quinn::VarInt::from_u32(1024 * 1024 * 2));
        transport_cfg.send_window(1024 * 1024 * 2);
        transport_cfg.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
        transport_cfg.max_concurrent_bidi_streams(VarInt::from_u32(1024));

        if self.config.max_idle_timeout_ms > 0 {
            let timeout =
                IdleTimeout::from(VarInt::from_u32(self.config.max_idle_timeout_ms as u32));
            transport_cfg.max_idle_timeout(Some(timeout));
            transport_cfg.keep_alive_interval(Some(Duration::from_millis(
                self.config.max_idle_timeout_ms * 2 / 3,
            )));
        }

        let (tls_client_cfg, domain) = self.parse_client_config_and_domain()?;
        let quic_client_cfg = Arc::new(QuicClientConfig::try_from(tls_client_cfg)?);
        let mut quinn_client_cfg = quinn::ClientConfig::new(quic_client_cfg);
        quinn_client_cfg.transport_config(Arc::new(transport_cfg));

        let remote_addr = Self::parse_server_addr(&self.config.server_addr).await?;
        let local_addr: SocketAddr = socket_addr_with_unspecified_ip_port(remote_addr.is_ipv6());

        let mut endpoint = quinn::Endpoint::client(local_addr)?;
        endpoint.set_default_client_config(quinn_client_cfg);

        self.post_tunnel_log(
            format!(
                "connecting to {remote_addr}, local_addr: {}",
                endpoint.local_addr().unwrap()
            )
            .as_str(),
        );

        let connection = endpoint.connect(remote_addr, domain.as_str())?.await?;

        self.set_and_post_tunnel_state(ClientState::Connected);
        self.post_tunnel_log(format!("connected to server: {remote_addr:?}").as_str());

        let (mut quic_send, mut quic_recv) = connection
            .open_bi()
            .await
            .map_err(|e| error!("open bidirectional connection failed: {e}"))
            .unwrap();

        self.set_and_post_tunnel_state(ClientState::LoggingIn);
        self.post_tunnel_log("logging in...");

        Self::login(&self.config, &mut quic_send, &mut quic_recv).await?;

        self.set_and_post_tunnel_state(ClientState::Tunneling);
        self.post_tunnel_log("logged in!");

        inner_state!(self, remote_conn) = Some(connection);
        inner_state!(self, ctrl_stream) = Some(ControlStream {
            quic_send,
            quic_recv,
        });

        Ok(())
    }

    async fn serve_udp_out(
        self: &Arc<Self>,
        tcp_sender: Option<TcpSender>,
        use_async: bool,
    ) -> Result<()> {
        if inner_state!(self, udp_server).is_none() {
            return Ok(());
        }

        let mut udp_server = inner_state!(self, udp_server).clone().unwrap();
        let mut udp_server_clone = udp_server.clone();
        let udp_sender = udp_server.clone_udp_sender();
        let conn = inner_state!(self, remote_conn).clone().unwrap();
        let conn_clone = conn.clone();

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

            // on receiving UdpMessage::Quit, put the receiver back
            udp_server.set_active(false);
            udp_server.put_receiver(udp_receiver);
            info!("local udp server quit");
        });

        let task = || async move {
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
        };

        if use_async {
            tokio::spawn(task());
        } else {
            task().await;
        }
        Ok(())
    }

    async fn serve_tcp_out(self: &Arc<Self>, pending_conn: &mut Option<TcpStream>) -> Result<()> {
        if inner_state!(self, tcp_server).is_none() {
            return Ok(());
        }

        let mut tcp_server = inner_state!(self, tcp_server).take().unwrap();
        tcp_server.set_active(true);

        let remote_conn = inner_state!(self, remote_conn).clone().unwrap();
        loop {
            let tcp_stream = match pending_conn.take() {
                Some(tcp_stream) => tcp_stream,
                None => match tcp_server.recv().await {
                    Some(TcpMessage::Request(tcp_stream)) => tcp_stream,
                    _ => break,
                },
            };

            match remote_conn.open_bi().await {
                Ok(quic_stream) => Tunnel::new().start(true, tcp_stream, quic_stream),
                Err(e) => {
                    error!("failed to open_bi on remote connection, will retry: {e}");
                    self.post_tunnel_log(
                        format!("connection failed, will reconnect: {e}").as_str(),
                    );
                    *pending_conn = Some(tcp_stream);
                    break;
                }
            }
        }

        // the tcp server will be reused when tunnel reconnects
        tcp_server.set_active(false);
        inner_state!(self, tcp_server) = Some(tcp_server);

        Ok(())
    }

    async fn serve_outgoing(self: &Arc<Self>, pending_conn: &mut Option<TcpStream>) -> Result<()> {
        self.post_tunnel_log("start serving in [TunnelOut] mode...");
        self.report_traffic_data_in_background().await;
        self.set_and_post_tunnel_state(ClientState::Preparing);

        if self.config.local_udp_server_addr.is_some() && inner_state!(self, udp_server).is_none() {
            self.start_udp_server().await?;
        }

        if self.config.local_tcp_server_addr.is_some() && inner_state!(self, tcp_server).is_none() {
            self.start_tcp_server().await?;
        }

        let tcp_sender = inner_state!(self, tcp_server)
            .as_ref()
            .map(|tcp_server| tcp_server.clone_tcp_sender());

        let udp_only = self.config.local_tcp_server_addr.is_none();
        self.serve_udp_out(tcp_sender, !udp_only).await.ok();
        self.serve_tcp_out(pending_conn).await.ok();

        let remote_conn = inner_state!(self, remote_conn).clone().unwrap();
        let stats = remote_conn.stats();
        let data = &mut inner_state!(self, total_traffic_data);
        data.rx_bytes += stats.udp_rx.bytes;
        data.tx_bytes += stats.udp_tx.bytes;
        data.rx_dgrams += stats.udp_rx.datagrams;
        data.tx_dgrams += stats.udp_tx.datagrams;
        Ok(())
    }

    async fn serve_udp_in(
        self: &Arc<Self>,
        use_async: bool,
        udp_server_addr: SocketAddr,
    ) -> Result<()> {
        let remote_conn = inner_state!(self, remote_conn).clone().unwrap();

        let task = || async move {
            let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let mtu = remote_conn.max_datagram_size().unwrap_or(1500);
            loop {
                match remote_conn.read_datagram().await {
                    Ok(datagram) => {
                        if let Ok(packet) = UdpPacket::try_from(datagram) {
                            let len = packet.payload.len();
                            debug!("send datagram({len}) to {udp_server_addr}",);
                            let sock = match UdpSocket::bind(local_addr).await {
                                Ok(sock) => sock,
                                Err(e) => {
                                    warn!("failed to bind to localhost, err: {e:?}");
                                    continue;
                                }
                            };

                            if let Err(e) = sock.connect(udp_server_addr).await {
                                warn!("failed to connect to upstream: {}, err: {e:?}", packet.addr);
                                continue;
                            };

                            let conn = remote_conn.clone();
                            tokio::spawn(async move {
                                sock.send(&packet.payload).await.ok();

                                let mut buf = BytesMut::zeroed(mtu);
                                match tokio::time::timeout(
                                    Duration::from_secs(3),
                                    sock.recv(&mut buf),
                                )
                                .await
                                {
                                    Ok(Ok(len)) => {
                                        let buf = buf.split_to(len);
                                        debug!("read datagram({len}) from {udp_server_addr}",);
                                        conn.send_datagram(
                                            UdpPacket::new(buf.into(), packet.addr).into(),
                                        )
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
                    }
                    Err(e) => {
                        if remote_conn.close_reason().is_some() {
                            debug!("connection is closed, will quit");
                            break;
                        }
                        warn!("read_datagram failed: {e}");
                    }
                }
            }
        };

        if use_async {
            tokio::spawn(task());
        } else {
            task().await;
        }

        Ok(())
    }

    async fn serve_tcp_in(self: &Arc<Self>) -> Result<()> {
        let remote_conn = inner_state!(self, remote_conn).clone().unwrap();
        while let Ok(quic_stream) = remote_conn.accept_bi().await {
            match TcpStream::connect(self.config.local_tcp_server_addr.unwrap()).await {
                Ok(tcp_stream) => Tunnel::new().start(false, tcp_stream, quic_stream),
                Err(e) => {
                    error!(
                        "failed to connect to tcp server: {e}, {}",
                        self.config.local_tcp_server_addr.unwrap(),
                    );
                }
            }
        }
        Ok(())
    }

    async fn serve_incoming(self: &Arc<Self>) -> Result<()> {
        self.post_tunnel_log("start serving in [TunnelIn] mode...");

        self.observe_terminate_signals().await.map_err(|e| {
            self.post_tunnel_log("failed to observe signals");
            e
        })?;

        let udp_only = self.config.local_tcp_server_addr.is_none();
        if let Some(udp_server_addr) = self.config.local_udp_server_addr {
            self.serve_udp_in(!udp_only, udp_server_addr).await.ok();
        }
        self.serve_tcp_in().await.ok();

        Ok(())
    }

    async fn report_traffic_data_in_background(self: &Arc<Self>) {
        let remote_conn = inner_state!(self, remote_conn).clone().unwrap();

        let this = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(POST_TRAFFIC_DATA_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                let stats = remote_conn.stats();
                let data = {
                    // have to be very careful to avoid deadlock, don't hold the lock for too long
                    let total_traffic_data = &inner_state!(this, total_traffic_data);
                    TunnelTraffic {
                        rx_bytes: stats.udp_rx.bytes + total_traffic_data.rx_bytes,
                        tx_bytes: stats.udp_tx.bytes + total_traffic_data.tx_bytes,
                        rx_dgrams: stats.udp_rx.datagrams + total_traffic_data.rx_dgrams,
                        tx_dgrams: stats.udp_tx.datagrams + total_traffic_data.tx_dgrams,
                    }
                };
                this.post_tunnel_info(TunnelInfo::new(
                    TunnelInfoType::TunnelTraffic,
                    Box::new(data),
                ));
            }
        });
    }

    async fn observe_terminate_signals(self: &Arc<Self>) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            let this = self.clone();
            let mut quic_send = inner_state!(self, ctrl_stream).take().unwrap().quic_send;
            tokio::spawn(async move {
                let mut ctrlc = signal(SignalKind::interrupt()).unwrap();
                let mut terminate = signal(SignalKind::terminate()).unwrap();
                tokio::select! {
                    _ = ctrlc.recv() => debug!("received SIGINT"),
                    _ = terminate.recv() => debug!("received SIGTERM"),
                }
                inner_state!(this, is_terminated) = true;

                TunnelMessage::send(&mut quic_send, &TunnelMessage::ReqTerminate)
                    .await
                    .ok();

                tokio::time::sleep(Duration::from_millis(1000)).await;
                std::process::exit(0);
            });
        }

        Ok(())
    }

    fn get_crypto_provider(self: &Arc<Self>, cipher: &SupportedCipherSuite) -> Arc<CryptoProvider> {
        let default_provider = rustls::crypto::ring::default_provider();
        let mut cipher_suites = vec![*cipher];
        // Quinn assumes that the cipher suites contain this one
        cipher_suites.push(cipher_suite::TLS13_AES_128_GCM_SHA256);
        Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites,
            ..default_provider
        })
    }

    fn create_client_config_builder(
        self: &Arc<Self>,
        cipher: &SupportedCipherSuite,
    ) -> std::result::Result<
        rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
        rustls::Error,
    > {
        let cfg_builder =
            rustls::ClientConfig::builder_with_provider(self.get_crypto_provider(cipher))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap();
        Ok(cfg_builder)
    }

    fn parse_client_config_and_domain(self: &Arc<Self>) -> Result<(rustls::ClientConfig, String)> {
        self.post_tunnel_log(format!("will use cipher: {}", self.config.cipher).as_str());
        let cipher = *SelectedCipherSuite::from_str(&self.config.cipher).map_err(|_| {
            rustls::Error::General(format!("invalid cipher: {}", self.config.cipher))
        })?;

        if self.config.cert_path.is_empty() {
            if !Self::is_ip_addr(&self.config.server_addr) {
                let domain = match self.config.server_addr.rfind(':') {
                    Some(colon_index) => self.config.server_addr[0..colon_index].to_string(),
                    None => self.config.server_addr.to_string(),
                };

                let client_config = self
                    .create_client_config_builder(&cipher)?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(Verifier::new()))
                    .with_no_client_auth();

                return Ok((client_config, domain));
            }

            let client_config = self
                .create_client_config_builder(&cipher)?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier::new(
                    self.get_crypto_provider(&cipher),
                )))
                .with_no_client_auth();

            warn!("No certificate is provided for verification, domain \"localhost\" is assumed");
            return Ok((client_config, "localhost".to_string()));
        }

        let certs = pem_util::load_certificates_from_pem(self.config.cert_path.as_str())
            .context("failed to read from cert file")?;
        let cert = certs
            .first()
            .context("certificate is not in PEM format")?
            .clone();

        let mut roots = RootCertStore::empty();
        roots.add(cert).context(format!(
            "failed to add certificate: {}",
            self.config.cert_path
        ))?;

        let (_rem, cert) = X509Certificate::from_der(certs.first().unwrap().as_ref()).context(
            format!("not a valid X509Certificate: {}", self.config.cert_path),
        )?;

        let common_name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .context(format!(
                "failed to read CN (Common Name) from specified certificate: {}",
                self.config.cert_path
            ))?;

        Ok((
            self.create_client_config_builder(&cipher)?
                .with_root_certificates(roots)
                .with_no_client_auth(),
            common_name.to_string(),
        ))
    }

    fn should_retry(&self) -> bool {
        !inner_state!(self, is_terminated)
    }

    pub fn get_state(self: &Arc<Self>) -> ClientState {
        inner_state!(self, client_state).clone()
    }

    async fn login(
        config: &ClientConfig,
        quic_send: &mut SendStream,
        quic_recv: &mut RecvStream,
    ) -> Result<()> {
        debug!("sending login request...");
        TunnelMessage::send(quic_send, config.login_msg.as_ref().unwrap()).await?;
        debug!("sent login request!");

        let resp = TunnelMessage::recv(quic_recv).await?;
        if let TunnelMessage::RespFailure(msg) = resp {
            log_and_bail!("failed to login: {msg}");
        }
        if !resp.is_resp_success() {
            log_and_bail!("failed to login");
        }
        TunnelMessage::handle_message(&resp)?;
        debug!("finished login request!");
        Ok(())
    }

    fn is_ip_addr(addr: &str) -> bool {
        addr.parse::<SocketAddr>().is_ok()
    }

    async fn parse_server_addr(addr: &str) -> Result<SocketAddr> {
        let sock_addr: Result<SocketAddr> = addr.parse().context("error will be ignored");

        if sock_addr.is_ok() {
            return sock_addr;
        }

        let mut domain = addr;
        let mut port = DEFAULT_SERVER_PORT;
        let pos = addr.rfind(':');
        if let Some(pos) = pos {
            port = addr[(pos + 1)..]
                .parse()
                .with_context(|| format!("invalid address: {}", addr))?;
            domain = &addr[..pos];
        }

        if let Ok(ip) = Self::lookup_server_ip(domain, "dns.alidns.com", vec![]).await {
            return Ok(SocketAddr::new(ip, port));
        }

        if let Ok(ip) = Self::lookup_server_ip(domain, "dot.pub", vec![]).await {
            return Ok(SocketAddr::new(ip, port));
        }

        if let Ok(ip) = Self::lookup_server_ip(
            domain,
            "",
            vec![
                "1.12.12.12".to_string(),
                "120.53.53.53".to_string(),
                "223.5.5.5".to_string(),
                "223.6.6.6".to_string(),
            ],
        )
        .await
        {
            return Ok(SocketAddr::new(ip, port));
        }

        if let Ok(ip) = Self::lookup_server_ip(domain, "", vec![]).await {
            return Ok(SocketAddr::new(ip, port));
        }

        bail!("failed to resolve domain: {domain}");
    }

    async fn lookup_server_ip(
        domain: &str,
        dot_server: &str,
        name_servers: Vec<String>,
    ) -> Result<IpAddr> {
        let dns_config = DNSResolverConfig {
            strategy: DNSResolverLookupIpStrategy::Ipv6thenIpv4,
            num_conccurent_reqs: 3,
            ordering: DNSQueryOrdering::QueryStatistics,
        };

        let resolver = if !dot_server.is_empty() {
            dns::resolver2(dot_server, vec![], dns_config)
        } else if !name_servers.is_empty() {
            dns::resolver2("", name_servers, dns_config)
        } else {
            dns::resolver2("", vec![], dns_config)
        };

        let ip = resolver.await.lookup_first(domain).await?;
        info!("resolved {domain} to {ip}");
        Ok(ip)
    }

    fn post_tunnel_log(self: &Arc<Self>, log: &str) {
        info!("{}", log);
        self.post_tunnel_info(TunnelInfo::new(
            TunnelInfoType::TunnelLog,
            Box::new(format!(
                "{} {log}",
                chrono::Local::now().format(TIME_FORMAT)
            )),
        ));
    }

    fn set_and_post_tunnel_state(self: &Arc<Self>, state: ClientState) {
        info!("client state: {state}");
        inner_state!(self, client_state) = state.clone();
        self.post_tunnel_info(TunnelInfo::new(
            TunnelInfoType::TunnelState,
            Box::new(state),
        ));
    }

    fn post_tunnel_info<T>(self: &Arc<Self>, server_info: TunnelInfo<T>)
    where
        T: ?Sized + Serialize,
    {
        if inner_state!(self, on_info_report_enabled) {
            inner_state!(self, tunnel_info_bridge).post_tunnel_info(server_info);
        }
    }

    pub fn set_on_info_listener(
        self: &Arc<Self>,
        callback: impl FnMut(&str) + 'static + Send + Sync,
    ) {
        inner_state!(self, tunnel_info_bridge).set_listener(callback);
    }

    pub fn has_on_info_listener(self: &Arc<Self>) -> bool {
        inner_state!(self, tunnel_info_bridge).has_listener()
    }

    pub fn set_enable_on_info_report(self: &Arc<Self>, enable: bool) {
        info!("set_enable_on_info_report, enable:{enable}");
        inner_state!(self, on_info_report_enabled) = enable;
    }
}

#[derive(Debug)]
struct InsecureCertVerifier(Arc<rustls::crypto::CryptoProvider>);

impl InsecureCertVerifier {
    pub fn new(crypto: Arc<CryptoProvider>) -> Self {
        Self(crypto)
    }
}

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::prelude::v1::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::prelude::v1::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }

    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::prelude::v1::Result<ServerCertVerified, rustls::Error> {
        warn!("======================================= WARNING ======================================");
        warn!("Connecting to a server without verifying its certificate is DANGEROUS!!!");
        warn!("Provide the self-signed certificate for verification or connect with a domain name");
        warn!("======================= Be cautious, this is for TEST only!!! ========================");
        Ok(ServerCertVerified::assertion())
    }
}
