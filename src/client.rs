use crate::{
    pem_util, socket_addr_with_unspecified_ip_port,
    tcp::{tcp_tunnel::TcpTunnel, AsyncStream, StreamReceiver, StreamRequest},
    tunnel_info_bridge::{TunnelInfo, TunnelInfoBridge, TunnelInfoType, TunnelTraffic},
    tunnel_message::TunnelMessage,
    udp::{udp_server::UdpServer, udp_tunnel::UdpTunnel, UdpReceiver, UdpSender},
    ClientConfig, LoginInfo, SelectedCipherSuite, TcpServer, Tunnel, TunnelConfig, TunnelMode,
    UpstreamType,
};
use anyhow::{bail, Context, Result};
use backon::ExponentialBuilder;
use backon::Retryable;
use log::{error, info, warn};
use quinn::{congestion, crypto::rustls::QuicClientConfig, Connection, Endpoint, TransportConfig};
use quinn_proto::{IdleTimeout, VarInt};
use rs_utilities::dns::{self, DNSQueryOrdering, DNSResolverConfig, DNSResolverLookupIpStrategy};
use rs_utilities::log_and_bail;
use rustls::{
    client::danger::ServerCertVerified,
    crypto::{ring::cipher_suite, CryptoProvider},
    RootCertStore, SupportedCipherSuite,
};
use rustls_platform_verifier::{self, BuilderVerifierExt};
use serde::Serialize;
use std::collections::HashMap;
use std::{
    fmt::Display,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex, Once},
    time::Duration,
};
use tokio::net::TcpStream;

const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S.%3f";
const DEFAULT_SERVER_PORT: u16 = 3515;
const POST_TRAFFIC_DATA_INTERVAL_SECS: u64 = 30;
static INIT: Once = Once::new();

#[derive(Clone, Serialize, PartialEq)]
pub enum ClientState {
    Idle = 0,
    Connecting,
    Connected,
    LoggingIn,
    Tunneling,
    Stopping,
    Terminated,
}

impl Display for ClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientState::Idle => write!(f, "Idle"),
            ClientState::Connecting => write!(f, "Connecting"),
            ClientState::Connected => write!(f, "Connected"),
            ClientState::LoggingIn => write!(f, "LoggingIn"),
            ClientState::Tunneling => write!(f, "Tunneling"),
            ClientState::Stopping => write!(f, "Stopping"),
            ClientState::Terminated => write!(f, "Terminated"),
        }
    }
}

struct State {
    tcp_servers: HashMap<SocketAddr, TcpServer>,
    udp_servers: HashMap<SocketAddr, UdpServer>,
    connections: HashMap<SocketAddr, Connection>,
    client_state: ClientState,
    total_traffic_data: TunnelTraffic,
    tunnel_info_bridge: TunnelInfoBridge,
    on_info_report_enabled: bool,
}

impl State {
    fn new() -> Self {
        Self {
            tcp_servers: HashMap::new(),
            udp_servers: HashMap::new(),
            connections: HashMap::new(),
            client_state: ClientState::Idle,
            total_traffic_data: TunnelTraffic::default(),
            tunnel_info_bridge: TunnelInfoBridge::new(),
            on_info_report_enabled: false,
        }
    }

    fn post_tunnel_info<T>(&self, server_info: TunnelInfo<T>)
    where
        T: ?Sized + Serialize,
    {
        if self.on_info_report_enabled {
            self.tunnel_info_bridge.post_tunnel_info(server_info);
        }
    }
}

struct LoginConfig {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    quinn_client_cfg: quinn::ClientConfig,
    domain: String,
}

#[derive(Clone)]
pub struct Client {
    config: ClientConfig,
    inner_state: Arc<Mutex<State>>,
}

macro_rules! inner_state {
    ($self:ident, $field:ident) => {
        (*$self.inner_state.lock().unwrap()).$field
    };
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        INIT.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .unwrap();
        });

        Client {
            config,
            inner_state: Arc::new(Mutex::new(State::new())),
        }
    }

    pub fn start_tunneling(&mut self) {
        let (tx, rx) = std::sync::mpsc::channel();
        ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
            .expect("Error setting Ctrl-C handler");

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(self.config.workers)
            .build()
            .unwrap()
            .block_on(async {
                self.connect_and_serve_async();
                rx.recv().expect("Could not receive from channel.");
                self.stop_async().await;
            });
    }

    pub fn connect_and_serve_async(&mut self) {
        for (index, tunnel_config) in self.config.tunnels.iter().cloned().enumerate() {
            let mut this = self.clone();
            tokio::spawn(async move {
                this.connect_and_serve::<TcpStream>(
                    index,
                    Tunnel::NetworkBased(tunnel_config),
                    None,
                    None,
                )
                .await;
            });
        }

        self.report_traffic_data_in_background();
    }

    pub fn connect_and_serve_tcp_async<S: AsyncStream>(
        &mut self,
        stream_receiver: StreamReceiver<S>,
    ) {
        let mut this = self.clone();
        tokio::spawn(async move {
            this.connect_and_serve::<S>(
                0,
                Tunnel::ChannelBased(UpstreamType::Tcp),
                Some(stream_receiver),
                None,
            )
            .await;
        });
    }

    pub fn connect_and_serve_udp_async(&mut self, ch: (UdpSender, UdpReceiver)) {
        let mut this = self.clone();
        tokio::spawn(async move {
            this.connect_and_serve::<TcpStream>(
                0,
                Tunnel::ChannelBased(UpstreamType::Udp),
                None,
                Some(ch),
            )
            .await;
        });
    }

    pub async fn start_tcp_server(&self, addr: SocketAddr) -> Result<TcpServer> {
        let bind_tcp_server = || async { TcpServer::bind_and_start(addr).await };
        let tcp_server = bind_tcp_server
            .retry(
                ExponentialBuilder::default()
                    .with_max_delay(Duration::from_secs(10))
                    .with_max_times(10),
            )
            .sleep(tokio::time::sleep)
            .notify(|err: &anyhow::Error, dur: Duration| {
                warn!("will start tcp server ({addr}) after {dur:?}, err: {err:?}");
            })
            .await?;

        inner_state!(self, tcp_servers).insert(addr, tcp_server.clone());

        Ok(tcp_server)
    }

    pub async fn start_udp_server(&self, addr: SocketAddr) -> Result<UdpServer> {
        // create a local udp server for 'OUT' tunnel
        let bind_udp_server = || async { UdpServer::bind_and_start(addr).await };
        let udp_server = bind_udp_server
            .retry(
                ExponentialBuilder::default()
                    .with_max_delay(Duration::from_secs(10))
                    .with_max_times(10),
            )
            .sleep(tokio::time::sleep)
            .notify(|err: &anyhow::Error, dur: Duration| {
                warn!("will start udp server ({addr}) after {dur:?}, err: {err:?}");
            })
            .await?;

        inner_state!(self, udp_servers).insert(addr, udp_server.clone());
        Ok(udp_server)
    }

    pub fn get_config(&self) -> ClientConfig {
        self.config.clone()
    }

    #[allow(clippy::unnecessary_to_owned)]
    pub fn stop(&self) {
        self.set_and_post_tunnel_state(ClientState::Stopping);

        if let Ok(mut state) = self.inner_state.lock() {
            for mut s in state.tcp_servers.values().cloned() {
                tokio::spawn(async move {
                    s.shutdown().await.ok();
                });
            }
            for mut s in state.udp_servers.values().cloned() {
                tokio::spawn(async move {
                    s.shutdown().await.ok();
                });
            }

            for c in state.connections.values().cloned() {
                tokio::spawn(async move {
                    c.close(VarInt::from_u32(1), b"");
                });
            }

            state.tcp_servers.clear();
            state.udp_servers.clear();
            state.connections.clear();
        }

        std::thread::sleep(Duration::from_secs(3));
    }

    #[allow(clippy::unnecessary_to_owned)]
    pub async fn stop_async(&self) {
        self.set_and_post_tunnel_state(ClientState::Stopping);

        let mut tasks = tokio::task::JoinSet::new();
        if let Ok(mut state) = self.inner_state.lock() {
            for mut s in state.tcp_servers.values().cloned() {
                tasks.spawn(async move {
                    s.shutdown().await.ok();
                });
            }
            for mut s in state.udp_servers.values().cloned() {
                tasks.spawn(async move {
                    s.shutdown().await.ok();
                });
            }

            for c in state.connections.values().cloned() {
                tasks.spawn(async move {
                    c.close(VarInt::from_u32(1), b"");
                });
            }

            state.tcp_servers.clear();
            state.udp_servers.clear();
            state.connections.clear();
        }

        while tasks.join_next().await.is_some() {}
    }

    async fn connect_and_serve<S: AsyncStream>(
        &mut self,
        index: usize,
        tunnel: Tunnel,
        mut stream_receiver: Option<StreamReceiver<S>>,
        mut ch: Option<(UdpSender, UdpReceiver)>,
    ) {
        let login_info = LoginInfo {
            password: self.config.password.clone(),
            tunnel: tunnel.clone(),
        };

        let mut pending_network_based_stream = None;
        let mut pending_channel_based_stream = None;
        loop {
            let connect = || async {
                let login_cfg = self.prepare_login_config().await?;
                let mut endpoint = quinn::Endpoint::client(login_cfg.local_addr)?;
                endpoint.set_default_client_config(login_cfg.quinn_client_cfg);

                let conn = self
                    .login(
                        index,
                        &endpoint,
                        &login_info,
                        &login_cfg.remote_addr,
                        login_cfg.domain.as_str(),
                    )
                    .await?;

                Ok(conn)
            };
            let result = connect
                .retry(
                    ExponentialBuilder::default()
                        .with_max_delay(Duration::from_secs(10))
                        .with_max_times(usize::MAX),
                )
                .when(|_| !self.should_quit())
                .sleep(tokio::time::sleep)
                .notify(|err: &anyhow::Error, dur: Duration| {
                    warn!("will retry after {dur:?}, err: {err:?}");
                })
                .await;

            if self.should_quit() {
                break;
            }

            match result {
                Ok(conn) => match &tunnel {
                    Tunnel::NetworkBased(tunnel_config) => {
                        self.handle_network_based_tunnel(
                            index,
                            conn,
                            tunnel_config,
                            &mut pending_network_based_stream,
                        )
                        .await;
                    }
                    Tunnel::ChannelBased(upstream_type) => match upstream_type {
                        UpstreamType::Tcp => {
                            self.post_tunnel_log(
                                format!(
                                    "{index}:STREAM_OUT start serving via {}",
                                    conn.remote_address()
                                )
                                .as_str(),
                            );
                            self.set_and_post_tunnel_state(ClientState::Tunneling);

                            let stream_receiver = stream_receiver.as_mut().unwrap();
                            TcpTunnel::start_serving(
                                true,
                                &conn,
                                stream_receiver,
                                &mut pending_channel_based_stream,
                                self.config.tcp_timeout_ms,
                            )
                            .await;
                        }

                        UpstreamType::Udp => {
                            self.post_tunnel_log(
                                format!(
                                    "{index}:UDP_OUT start serving via {}",
                                    conn.remote_address()
                                )
                                .as_str(),
                            );
                            self.set_and_post_tunnel_state(ClientState::Tunneling);

                            let ch = ch.as_mut().unwrap();
                            UdpTunnel::start_serving(
                                &conn,
                                &ch.0,
                                &mut ch.1,
                                self.config.udp_timeout_ms,
                            )
                            .await;
                        }
                    },
                },

                Err(e) => {
                    error!("{e}");
                    info!(
                        "[{login_info}] quit after having retried for {} times",
                        usize::MAX
                    );
                    break;
                }
            };

            if self.should_quit() {
                break;
            }
        }
        self.post_tunnel_log(format!("[{login_info}] quit").as_str());
    }

    async fn handle_network_based_tunnel(
        &mut self,
        index: usize,
        conn: Connection,
        tunnel_config: &TunnelConfig,
        pending_request: &mut Option<StreamRequest<TcpStream>>,
    ) {
        let upstream_type = &tunnel_config.upstream.upstream_type;
        let local_server_addr = tunnel_config.local_server_addr.unwrap();

        inner_state!(self, connections).insert(local_server_addr, conn.clone());

        if tunnel_config.mode == TunnelMode::Out {
            match upstream_type {
                UpstreamType::Tcp => {
                    self.serve_outbound_tcp(
                        index,
                        conn.clone(),
                        local_server_addr,
                        pending_request,
                    )
                    .await
                    .ok();
                }
                UpstreamType::Udp => {
                    self.serve_outbound_udp(index, conn.clone(), local_server_addr)
                        .await
                        .ok();
                }
            }
        } else {
            match upstream_type {
                UpstreamType::Tcp => {
                    self.serve_inbound_tcp(index, conn.clone(), local_server_addr)
                        .await
                        .ok();
                }
                UpstreamType::Udp => {
                    self.serve_inbound_udp(index, conn.clone(), local_server_addr)
                        .await
                        .ok();
                }
            }
        }

        inner_state!(self, connections).remove(&local_server_addr);

        let stats = conn.stats();
        let data = &mut inner_state!(self, total_traffic_data);
        data.rx_bytes += stats.udp_rx.bytes;
        data.tx_bytes += stats.udp_tx.bytes;
        data.rx_dgrams += stats.udp_rx.datagrams;
        data.tx_dgrams += stats.udp_tx.datagrams;
    }

    async fn prepare_login_config(&self) -> Result<LoginConfig> {
        let mut transport_cfg = TransportConfig::default();
        transport_cfg.stream_receive_window(quinn::VarInt::from_u32(1024 * 1024));
        transport_cfg.receive_window(quinn::VarInt::from_u32(1024 * 1024 * 2));
        transport_cfg.send_window(1024 * 1024 * 2);
        transport_cfg.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
        transport_cfg.max_concurrent_bidi_streams(VarInt::from_u32(1024));

        if self.config.quic_timeout_ms > 0 {
            let timeout = IdleTimeout::from(VarInt::from_u32(self.config.quic_timeout_ms as u32));
            transport_cfg.max_idle_timeout(Some(timeout));
            transport_cfg.keep_alive_interval(Some(Duration::from_millis(
                self.config.quic_timeout_ms * 2 / 3,
            )));
        }

        let (tls_client_cfg, domain) = self.parse_client_config_and_domain()?;
        let quic_client_cfg = Arc::new(QuicClientConfig::try_from(tls_client_cfg)?);
        let mut client_cfg = quinn::ClientConfig::new(quic_client_cfg);
        client_cfg.transport_config(Arc::new(transport_cfg));

        let remote_addr = self.parse_server_addr().await?;
        let local_addr = socket_addr_with_unspecified_ip_port(remote_addr.is_ipv6());
        Ok(LoginConfig {
            local_addr,
            remote_addr,
            quinn_client_cfg: client_cfg,
            domain,
        })
    }

    async fn login(
        &self,
        index: usize,
        endpoint: &Endpoint,
        login_info: &LoginInfo,
        remote_addr: &SocketAddr,
        domain: &str,
    ) -> Result<Connection> {
        self.set_and_post_tunnel_state(ClientState::Connecting);
        self.post_tunnel_log(
            format!(
                "{index}:{} connecting, idle_timeout:{}, retry_timeout:{}, cipher:{}, threads:{}",
                login_info.format_with_remote_addr(remote_addr),
                self.config.quic_timeout_ms,
                self.config.wait_before_retry_ms,
                self.config.cipher,
                self.config.workers,
            )
            .as_str(),
        );

        let conn = endpoint.connect(*remote_addr, domain)?.await?;
        let (mut quic_send, mut quic_recv) = conn
            .open_bi()
            .await
            .context("open bidirectional connection failed")?;

        self.set_and_post_tunnel_state(ClientState::Connected);

        self.post_tunnel_log(
            format!(
                "{index}:{} logging in...",
                login_info.format_with_remote_addr(remote_addr)
            )
            .as_str(),
        );

        let login_msg = TunnelMessage::ReqLogin(login_info.clone());
        TunnelMessage::send(&mut quic_send, &login_msg).await?;

        let resp = TunnelMessage::recv(&mut quic_recv).await?;
        if let TunnelMessage::RespFailure(msg) = resp {
            bail!(
                "{index}:{} failed to login: {msg}",
                login_info.format_with_remote_addr(remote_addr)
            );
        }
        if !resp.is_resp_success() {
            bail!(
                "{index}:{} unexpected response, failed to login",
                login_info.format_with_remote_addr(remote_addr)
            );
        }
        TunnelMessage::handle_message(&resp)?;
        self.post_tunnel_log(
            format!(
                "{index}:{} login succeeded!",
                login_info.format_with_remote_addr(remote_addr)
            )
            .as_str(),
        );
        Ok(conn)
    }

    async fn serve_outbound_tcp(
        &mut self,
        index: usize,
        conn: Connection,
        local_server_addr: SocketAddr,
        pending_request: &mut Option<StreamRequest<TcpStream>>,
    ) -> Result<()> {
        let tcp_server = {
            inner_state!(self, tcp_servers)
                .get(&local_server_addr)
                .cloned()
        };

        let mut tcp_server = match tcp_server {
            Some(server) => server.clone(),
            None => self.start_tcp_server(local_server_addr).await?,
        };

        self.post_tunnel_log(
            format!(
                "{index}:TCP_OUT start serving from {} via {}",
                tcp_server.addr(),
                conn.remote_address()
            )
            .as_str(),
        );
        self.set_and_post_tunnel_state(ClientState::Tunneling);

        let mut tcp_receiver = tcp_server.take_receiver();

        TcpTunnel::start_serving(
            true,
            &conn,
            &mut tcp_receiver,
            pending_request,
            self.config.tcp_timeout_ms,
        )
        .await;

        tcp_server.put_receiver(tcp_receiver);

        Ok(())
    }

    async fn serve_outbound_udp(
        &mut self,
        index: usize,
        conn: Connection,
        local_server_addr: SocketAddr,
    ) -> Result<()> {
        let udp_server = {
            inner_state!(self, udp_servers)
                .get(&local_server_addr)
                .cloned()
        };

        let mut udp_server = match udp_server {
            Some(server) => server.clone(),
            None => self.start_udp_server(local_server_addr).await?,
        };

        self.post_tunnel_log(
            format!(
                "{index}:UDP_OUT start serving from {} via {}",
                udp_server.addr(),
                conn.remote_address()
            )
            .as_str(),
        );

        self.set_and_post_tunnel_state(ClientState::Tunneling);

        let mut udp_receiver = udp_server.take_receiver();
        let udp_sender = udp_server.clone_sender();

        UdpTunnel::start_serving(
            &conn,
            &udp_sender,
            &mut udp_receiver,
            self.config.udp_timeout_ms,
        )
        .await;

        udp_server.put_receiver(udp_receiver);

        Ok(())
    }

    async fn serve_inbound_tcp(
        &mut self,
        index: usize,
        conn: Connection,
        local_server_addr: SocketAddr,
    ) -> Result<()> {
        self.post_tunnel_log(
            format!(
                "{index}:TCP_IN start serving via: {}",
                conn.remote_address()
            )
            .as_str(),
        );

        self.set_and_post_tunnel_state(ClientState::Tunneling);
        TcpTunnel::start_accepting(&conn, Some(local_server_addr), self.config.tcp_timeout_ms)
            .await;

        Ok(())
    }

    async fn serve_inbound_udp(
        &mut self,
        index: usize,
        conn: Connection,
        local_server_addr: SocketAddr,
    ) -> Result<()> {
        self.post_tunnel_log(
            format!(
                "{index}:UDP_IN start serving via: {}",
                conn.remote_address()
            )
            .as_str(),
        );

        self.set_and_post_tunnel_state(ClientState::Tunneling);
        UdpTunnel::start_accepting(&conn, Some(local_server_addr), self.config.udp_timeout_ms)
            .await;

        Ok(())
    }

    fn should_quit(&self) -> bool {
        let state = self.get_state();
        state == ClientState::Stopping || state == ClientState::Terminated
    }

    fn report_traffic_data_in_background(&self) {
        let state = self.inner_state.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(POST_TRAFFIC_DATA_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                let mut rx_bytes = 0;
                let mut tx_bytes = 0;
                let mut rx_dgrams = 0;
                let mut tx_dgrams = 0;

                {
                    let connections = &state.lock().unwrap().connections;
                    for conn in connections.values() {
                        let stats = conn.stats();
                        rx_bytes += stats.udp_rx.bytes;
                        tx_bytes += stats.udp_tx.bytes;
                        rx_dgrams += stats.udp_rx.datagrams;
                        tx_dgrams += stats.udp_tx.datagrams;
                    }
                }

                {
                    let total_traffic_data = &&state.lock().unwrap().total_traffic_data;
                    rx_bytes += total_traffic_data.rx_bytes;
                    tx_bytes += total_traffic_data.tx_bytes;
                    rx_dgrams += total_traffic_data.rx_dgrams;
                    tx_dgrams += total_traffic_data.tx_dgrams;
                }

                let state = state.lock().unwrap();
                let client_state = state.client_state.clone();
                let data = TunnelTraffic {
                    rx_bytes,
                    tx_bytes,
                    rx_dgrams,
                    tx_dgrams,
                };

                info!("traffic log, rx_bytes:{rx_bytes}, tx_bytes:{tx_bytes}, rx_dgrams:{rx_dgrams}, tx_dgrams:{tx_dgrams}");
                state.post_tunnel_info(TunnelInfo::new(
                    TunnelInfoType::TunnelTraffic,
                    Box::new(data),
                ));

                if client_state == ClientState::Stopping || client_state == ClientState::Terminated
                {
                    break;
                }
            }
        });
    }

    fn get_crypto_provider(&self, cipher: &SupportedCipherSuite) -> Arc<CryptoProvider> {
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
        &self,
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

    fn parse_client_config_and_domain(&self) -> Result<(rustls::ClientConfig, String)> {
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
                    .with_platform_verifier()?
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

            static ONCE: Once = Once::new();
            ONCE.call_once(|| {
                warn!(
                    "No certificate is provided for verification, domain \"localhost\" is assumed"
                );
            });
            return Ok((client_config, "localhost".to_string()));
        }

        // when client config provides a certificate
        let certs = pem_util::load_certificates_from_pem(self.config.cert_path.as_str())
            .context("failed to read from cert file")?;
        if certs.is_empty() {
            log_and_bail!(
                "No certificates found in provided file: {}",
                self.config.cert_path
            );
        }
        let mut roots = RootCertStore::empty();
        // save all certificates in the certificate chain to the trust list
        for cert in &certs {
            roots.add(cert.clone()).context(format!(
                "failed to add certificate from file: {}",
                self.config.cert_path
            ))?;
        }

        // for self-signed certificates, generating IP-based TLS certificates is not difficult
        let domain_or_ip = match self.config.server_addr.rfind(':') {
            Some(colon_index) => self.config.server_addr[0..colon_index].to_string(),
            None => self.config.server_addr.to_string(),
        };

        Ok((
            self.create_client_config_builder(&cipher)?
                .with_root_certificates(roots)
                .with_no_client_auth(),
            domain_or_ip,
        ))
    }

    pub fn get_state(&self) -> ClientState {
        inner_state!(self, client_state).clone()
    }

    fn is_ip_addr(addr: &str) -> bool {
        addr.parse::<SocketAddr>().is_ok()
    }

    async fn parse_server_addr(&self) -> Result<SocketAddr> {
        let addr = self.config.server_addr.as_str();
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

        for dot in &self.config.dot_servers {
            if let Ok(ip) = Self::lookup_server_ip(domain, dot, vec![]).await {
                return Ok(SocketAddr::new(ip, port));
            }
        }

        if let Ok(ip) = Self::lookup_server_ip(domain, "", self.config.dns_servers.clone()).await {
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

    fn post_tunnel_log(&self, msg: &str) {
        info!("{msg}");
        let state = self.inner_state.lock().unwrap();
        state.post_tunnel_info(TunnelInfo::new(
            TunnelInfoType::TunnelLog,
            Box::new(format!(
                "{} {msg}",
                chrono::Local::now().format(TIME_FORMAT)
            )),
        ));
    }

    fn set_and_post_tunnel_state(&self, client_state: ClientState) {
        let mut state = self.inner_state.lock().unwrap();
        state.client_state = client_state.clone();
        state.post_tunnel_info(TunnelInfo::new(
            TunnelInfoType::TunnelState,
            Box::new(client_state),
        ));
    }

    pub fn set_on_info_listener(&self, callback: impl FnMut(&str) + 'static + Send + Sync) {
        inner_state!(self, tunnel_info_bridge).set_listener(callback);
    }

    pub fn has_on_info_listener(&self) -> bool {
        inner_state!(self, tunnel_info_bridge).has_listener()
    }

    pub fn set_enable_on_info_report(&self, enable: bool) {
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
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            warn!("======================================= WARNING ======================================");
            warn!("Connecting to a server without verifying its certificate is DANGEROUS!!!");
            warn!("Provide the self-signed certificate for verification or connect with a domain name");
            warn!("======================= Be cautious, this is for TEST only!!! ========================");
        });
        Ok(ServerCertVerified::assertion())
    }
}
