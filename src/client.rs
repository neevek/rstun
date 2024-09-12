use crate::{
    pem_util, socket_addr_with_unspecified_ip_port,
    tcp::{tcp_server::TcpMessage, tcp_tunnel::TcpTunnel},
    tunnel_info_bridge::{TunnelInfo, TunnelInfoBridge, TunnelInfoType, TunnelTraffic},
    udp::{udp_server::UdpServer, udp_tunnel::UdpTunnel},
    ClientConfig, LoginInfo, SelectedCipherSuite, TcpServer, TunnelMessage, TUNNEL_MODE_IN,
    TUNNEL_MODE_OUT,
};
use anyhow::{bail, Context, Result};
use backon::ExponentialBuilder;
use backon::Retryable;
use log::{error, info, warn};
use quinn::{congestion, crypto::rustls::QuicClientConfig, Connection, Endpoint, TransportConfig};
use quinn_proto::{IdleTimeout, VarInt};
use rs_utilities::{
    dns::{self, DNSQueryOrdering, DNSResolverConfig, DNSResolverLookupIpStrategy},
    unwrap_or_return,
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
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex, Once},
    time::Duration,
};
use tokio::{net::TcpStream, sync::mpsc::Sender, task::JoinHandle};
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

struct State {
    tcp_conn: Option<Connection>,
    udp_conn: Option<Connection>,
    tcp_server: Option<TcpServer>,
    udp_server: Option<UdpServer>,
    client_state: ClientState,
    channel_message_sender: Option<Sender<TcpMessage>>,
    total_traffic_data: TunnelTraffic,
    tunnel_info_bridge: TunnelInfoBridge,
    on_info_report_enabled: bool,
}

impl State {
    fn new() -> Self {
        Self {
            tcp_server: None,
            udp_server: None,
            tcp_conn: None,
            udp_conn: None,
            client_state: ClientState::Idle,
            channel_message_sender: None,
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
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(self.config.threads)
            .build()
            .unwrap()
            .block_on(async { self.connect_and_serve().await });
    }

    pub async fn start_tcp_server(&mut self) -> Result<Option<SocketAddr>> {
        if self.config.mode != TUNNEL_MODE_OUT {
            bail!("call start_tcp_server() for TunnelOut mode only");
        }
        let addr = unwrap_or_return!(self.config.local_tcp_server_addr, Ok(None));

        self.post_tunnel_log("preparing tcp server...");

        let bind_tcp_server = || async { TcpServer::bind_and_start(addr).await };
        let tcp_server = bind_tcp_server
            .retry(
                ExponentialBuilder::default()
                    .with_max_delay(Duration::from_secs(10))
                    .with_max_times(10),
            )
            .sleep(tokio::time::sleep)
            .notify(|err: &anyhow::Error, dur: Duration| {
                warn!("will retry after {dur:?}, err: {err:?}");
            })
            .await?;

        let addr = tcp_server.addr();
        self.post_tunnel_log(format!("[TunnelOut] tcp server bound to: {addr}").as_str());

        let mut state = self.inner_state.lock().unwrap();
        state.channel_message_sender = Some(tcp_server.clone_tcp_sender());
        state.tcp_server = Some(tcp_server);
        Ok(Some(addr))
    }

    pub async fn start_udp_server(&mut self) -> Result<Option<SocketAddr>> {
        if self.config.mode != TUNNEL_MODE_OUT {
            bail!("call start_udp_server() for TunnelOut mode only");
        }
        let addr = unwrap_or_return!(self.config.local_udp_server_addr, Ok(None));
        self.post_tunnel_log("preparing udp server...");

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
                warn!("will retry after {dur:?}, err: {err:?}");
            })
            .await?;
        let addr = udp_server.addr();

        self.post_tunnel_log(format!("[TunnelOut] udp server bound to: {addr}").as_str());

        inner_state!(self, udp_server) = Some(udp_server);
        Ok(Some(addr))
    }

    pub fn get_config(&self) -> ClientConfig {
        self.config.clone()
    }

    pub fn stop(&self) -> Result<()> {
        Ok(())
    }

    pub fn connect_and_serve_async(mut self) -> JoinHandle<()> {
        tokio::spawn(async move { self.connect_and_serve().await })
    }

    async fn connect_and_serve(&mut self) {
        info!(
            "connecting, idle_timeout:{}, retry_timeout:{}, threads:{}",
            self.config.max_idle_timeout_ms, self.config.wait_before_retry_ms, self.config.threads
        );

        let mut pending_conn = None;
        loop {
            let connect = || async { self.connect().await };
            let result = connect
                .retry(
                    ExponentialBuilder::default()
                        .with_max_delay(Duration::from_secs(10))
                        .with_max_times(usize::MAX),
                )
                .sleep(tokio::time::sleep)
                .notify(|err: &anyhow::Error, dur: Duration| {
                    warn!("will retry after {dur:?}, err: {err:?}");
                })
                .await;
            match result {
                Ok(_) => {
                    if self.config.mode == TUNNEL_MODE_OUT {
                        self.serve_outgoing(&mut pending_conn).await.ok();
                    } else {
                        self.serve_incoming().await.ok();
                    }
                }

                Err(e) => {
                    error!("{e}");
                    info!("quit after having retried for {} times", usize::MAX);
                    break;
                }
            };
        }
        self.post_tunnel_log("quit");
        self.set_and_post_tunnel_state(ClientState::Terminated);
    }

    async fn connect(&self) -> Result<()> {
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

        let is_tunnel_in = self.config.mode == TUNNEL_MODE_IN;
        if let Some(tcp_upstream) = &self.config.tcp_upstream {
            let login_info = LoginInfo {
                password: self.config.password.clone(),
                upstream: tcp_upstream.clone(),
            };
            let login_msg = if is_tunnel_in {
                TunnelMessage::ReqTcpInLogin(login_info)
            } else {
                TunnelMessage::ReqTcpOutLogin(login_info)
            };

            let conn = self
                .login(&endpoint, &remote_addr, domain.as_str(), login_msg)
                .await?;
            inner_state!(self, tcp_conn) = Some(conn);
        }

        if let Some(udp_upstream) = &self.config.udp_upstream {
            let login_info = LoginInfo {
                password: self.config.password.clone(),
                upstream: udp_upstream.clone(),
            };
            let login_msg = if is_tunnel_in {
                TunnelMessage::ReqUdpInLogin(login_info)
            } else {
                TunnelMessage::ReqUdpOutLogin(login_info)
            };

            let conn = self
                .login(&endpoint, &remote_addr, domain.as_str(), login_msg)
                .await?;
            inner_state!(self, udp_conn) = Some(conn);
        }

        self.set_and_post_tunnel_state(ClientState::Tunneling);

        Ok(())
    }

    async fn login(
        &self,
        endpoint: &Endpoint,
        remote_addr: &SocketAddr,
        domain: &str,
        login_msg: TunnelMessage,
    ) -> Result<Connection> {
        self.set_and_post_tunnel_state(ClientState::Connecting);
        self.post_tunnel_log(
            format!(
                "[{login_msg}] connecting to {remote_addr}, local_addr: {}",
                endpoint.local_addr().unwrap()
            )
            .as_str(),
        );

        let conn = endpoint.connect(*remote_addr, domain)?.await?;
        let (mut quic_send, mut quic_recv) = conn
            .open_bi()
            .await
            .context("open bidirectional connection failed")?;

        self.set_and_post_tunnel_state(ClientState::Connected);
        self.post_tunnel_log(format!("[{login_msg}] connected: {remote_addr:?}",).as_str());
        self.post_tunnel_log(format!("[{login_msg}] logging in...").as_str());

        TunnelMessage::send(&mut quic_send, &login_msg).await?;

        let resp = TunnelMessage::recv(&mut quic_recv).await?;
        if let TunnelMessage::RespFailure(msg) = resp {
            bail!("[{login_msg}] failed to login: {msg}");
        }
        if !resp.is_resp_success() {
            bail!("[{login_msg}] unexpected response, failed to login");
        }
        TunnelMessage::handle_message(&resp)?;
        self.post_tunnel_log(format!("[{login_msg}] logged in").as_str());
        Ok(conn)
    }

    async fn serve_outgoing(&mut self, pending_tcp_stream: &mut Option<TcpStream>) -> Result<()> {
        self.set_and_post_tunnel_state(ClientState::Preparing);

        if self.config.local_tcp_server_addr.is_some() && inner_state!(self, tcp_server).is_none() {
            self.start_tcp_server().await?;
            let conn = inner_state!(self, tcp_conn).clone().unwrap();
            self.report_traffic_data_in_background(conn).await;
        }

        if self.config.local_udp_server_addr.is_some() && inner_state!(self, udp_server).is_none() {
            self.start_udp_server().await?;
            let conn = inner_state!(self, udp_conn).clone().unwrap();
            self.report_traffic_data_in_background(conn.clone()).await;
        }

        let tcp_server = self.inner_state.lock().unwrap().tcp_server.take();
        let tcp_sender = tcp_server
            .as_ref()
            .map(|tcp_server| tcp_server.clone_tcp_sender());

        let udp_server = inner_state!(self, udp_server).clone();
        if let Some(udp_server) = udp_server {
            let conn = inner_state!(self, udp_conn).clone().unwrap();
            let udp_only = self.config.local_tcp_server_addr.is_none();
            self.post_tunnel_log(
                format!(
                    "[TunnelOut] start serving udp via: {}",
                    conn.remote_address()
                )
                .as_str(),
            );
            UdpTunnel::start(conn, udp_server, tcp_sender, udp_only)
                .await
                .ok();
        }

        if let Some(mut tcp_server) = tcp_server {
            let conn = inner_state!(self, tcp_conn).take().unwrap();
            self.post_tunnel_log(
                format!(
                    "[TunnelOut] start serving tcp via: {}",
                    conn.remote_address()
                )
                .as_str(),
            );
            TcpTunnel::start(true, &conn, &mut tcp_server, pending_tcp_stream).await;

            let mut state = self.inner_state.lock().unwrap();
            state.tcp_conn = Some(conn);
            state.tcp_server = Some(tcp_server);
        }

        let mut inner_state = self.inner_state.lock().unwrap();
        if let Some(tcp_conn) = &inner_state.tcp_conn {
            let stats = tcp_conn.stats();
            let data = &mut inner_state.total_traffic_data;
            data.rx_bytes += stats.udp_rx.bytes;
            data.tx_bytes += stats.udp_tx.bytes;
            data.rx_dgrams += stats.udp_rx.datagrams;
            data.tx_dgrams += stats.udp_tx.datagrams;
        }
        Ok(())
    }

    async fn serve_incoming(&self) -> Result<()> {
        self.post_tunnel_log("start serving in [TunnelIn] mode...");

        if let Some(udp_server_addr) = self.config.local_udp_server_addr {
            let conn = inner_state!(self, udp_conn).clone().unwrap();
            let udp_only = self.config.local_tcp_server_addr.is_none();
            if udp_only {
                UdpTunnel::process(conn, udp_server_addr).await;
            } else {
                tokio::spawn(async move {
                    UdpTunnel::process(conn, udp_server_addr).await;
                });
            }
        }

        if let Some(addr) = self.config.local_tcp_server_addr {
            let conn = inner_state!(self, tcp_conn).clone().unwrap();
            TcpTunnel::process(conn, addr).await;
        }
        Ok(())
    }

    async fn report_traffic_data_in_background(&self, conn: Connection) {
        let state = self.inner_state.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(POST_TRAFFIC_DATA_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                let state = state.lock().unwrap();
                let stats = conn.stats();
                let data = {
                    // have to be very careful to avoid deadlock, don't hold the lock for too long
                    let total_traffic_data = &state.total_traffic_data;
                    TunnelTraffic {
                        rx_bytes: stats.udp_rx.bytes + total_traffic_data.rx_bytes,
                        tx_bytes: stats.udp_tx.bytes + total_traffic_data.tx_bytes,
                        rx_dgrams: stats.udp_rx.datagrams + total_traffic_data.rx_dgrams,
                        tx_dgrams: stats.udp_tx.datagrams + total_traffic_data.tx_dgrams,
                    }
                };
                state.post_tunnel_info(TunnelInfo::new(
                    TunnelInfoType::TunnelTraffic,
                    Box::new(data),
                ));
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

    pub fn get_state(&self) -> ClientState {
        inner_state!(self, client_state).clone()
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

    fn post_tunnel_log(&self, log: &str) {
        info!("{}", log);
        let state = self.inner_state.lock().unwrap();
        state.post_tunnel_info(TunnelInfo::new(
            TunnelInfoType::TunnelLog,
            Box::new(format!(
                "{} {log}",
                chrono::Local::now().format(TIME_FORMAT)
            )),
        ));
    }

    fn set_and_post_tunnel_state(&self, client_state: ClientState) {
        info!("client state: {client_state}");
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
        warn!("======================================= WARNING ======================================");
        warn!("Connecting to a server without verifying its certificate is DANGEROUS!!!");
        warn!("Provide the self-signed certificate for verification or connect with a domain name");
        warn!("======================= Be cautious, this is for TEST only!!! ========================");
        Ok(ServerCertVerified::assertion())
    }
}
