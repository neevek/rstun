use crate::{
    tunnel_info_bridge::{TrafficData, TunnelInfo, TunnelInfoBridge, TunnelInfoType},
    AccessServer, ClientConfig, ControlStream, SelectedCipherSuite, Tunnel, TunnelMessage,
    TUNNEL_MODE_OUT,
};
use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use quinn::{congestion, TransportConfig};
use quinn::{RecvStream, SendStream};
use quinn_proto::{IdleTimeout, VarInt};
use rs_utilities::{dns, log_and_bail};
use rustls::{client::ServerCertVerified, Certificate, RootCertStore, ServerName};
use rustls_platform_verifier::{self, Verifier};
use serde::Serialize;
use std::sync::{Arc, Mutex, RwLock};
use std::{fmt::Display, str::FromStr};
use std::{
    net::{IpAddr, SocketAddr},
    time::SystemTime,
};
use tokio::net::TcpStream;
#[cfg(not(target_os = "windows"))]
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::Duration;
use x509_parser::prelude::{FromDer, X509Certificate};

const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S.%3f";
const LOCAL_ADDR_STR: &str = "0.0.0.0:0";
const DEFAULT_SERVER_PORT: u16 = 3515;
const POST_TRAFFIC_DATA_INTERVAL_SECS: u64 = 10;

#[derive(Clone, Serialize)]
pub enum ClientState {
    Idle = 0,
    Preparing,
    Connecting,
    Connected,
    LoggingIn,
    Tunnelling,
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
            ClientState::Tunnelling => write!(f, "Tunnelling"),
            ClientState::Terminated => write!(f, "Terminated"),
        }
    }
}

pub struct Client {
    pub config: ClientConfig,
    access_server: Option<AccessServer>,
    remote_conn: Option<Arc<RwLock<quinn::Connection>>>,
    ctrl_stream: Option<ControlStream>,
    is_terminated: Arc<Mutex<bool>>,
    scheduled_start: bool,
    tunnel_info_bridge: TunnelInfoBridge,
    on_info_report_enabled: bool,
    total_traffic_data: Arc<Mutex<TrafficData>>,
    state: ClientState,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Client {
            config,
            access_server: None,
            remote_conn: None,
            ctrl_stream: None,
            is_terminated: Arc::new(Mutex::new(false)),
            scheduled_start: false,
            tunnel_info_bridge: TunnelInfoBridge::new(),
            on_info_report_enabled: false,
            total_traffic_data: Arc::new(Mutex::new(TrafficData::default())),
            state: ClientState::Idle,
        }
    }

    pub fn start_tunnelling(&mut self) {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(self.config.threads)
            .build()
            .unwrap()
            .block_on(async {
                self.start_access_server().await?;
                self.connect_and_serve().await;
                Ok::<(), anyhow::Error>(())
            })
            .ok();
    }

    pub async fn start_access_server(&mut self) -> Result<SocketAddr> {
        self.post_tunnel_log("preparing...");
        self.set_and_post_tunnel_state(ClientState::Preparing);

        // create a local access server for 'out' tunnel
        if self.config.mode == TUNNEL_MODE_OUT {
            self.post_tunnel_log(
                format!(
                    "starting access server for [TunnelOut] tunneling: {:?}",
                    self.config.local_access_server_addr.unwrap()
                )
                .as_str(),
            );

            let mut tmp_access_server =
                AccessServer::new(self.config.local_access_server_addr.unwrap());
            let bound_addr = tmp_access_server.bind().await?;
            tmp_access_server.start().await?;
            self.access_server = Some(tmp_access_server);

            info!("==========================================================");
            info!("[TunnelOut] access server bound to: {}", bound_addr);
            info!("==========================================================");
            return Ok(bound_addr);
        }

        bail!("call start_access_server() for TunnelOut mode only")
    }

    pub async fn connect_and_serve(&mut self) {
        info!(
            "connecting, idle_timeout:{}, retry_timeout:{}, threads:{}",
            self.config.max_idle_timeout_ms, self.config.wait_before_retry_ms, self.config.threads
        );

        let mut connect_retry_count = 0;
        let connect_max_retry = self.config.connect_max_retry;
        let wait_before_retry_ms = self.config.wait_before_retry_ms;

        loop {
            match self.connect().await {
                Ok(_) => {
                    connect_retry_count = 0;

                    if self.config.mode == TUNNEL_MODE_OUT {
                        self.serve_outgoing().await;
                    } else {
                        self.serve_incoming().await.ok();
                    }
                }

                Err(e) => {
                    error!("connect failed, err: {}", e);
                    if connect_max_retry > 0 {
                        connect_retry_count += 1;
                        if connect_retry_count >= connect_max_retry {
                            info!(
                                "quit after having retried for {} times",
                                connect_retry_count
                            );
                            break;
                        }
                    }

                    debug!(
                        "will wait for {}ms before retrying...",
                        wait_before_retry_ms
                    );
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

    async fn connect(&mut self) -> Result<()> {
        self.set_and_post_tunnel_state(ClientState::Connecting);

        let mut transport_cfg = TransportConfig::default();
        transport_cfg.receive_window(quinn::VarInt::from_u32(1024 * 1024)); //.unwrap();
        transport_cfg.send_window(1024 * 1024);
        transport_cfg.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
        transport_cfg.max_concurrent_bidi_streams(VarInt::from_u32(1024));

        if self.config.max_idle_timeout_ms > 0 {
            let timeout =
                IdleTimeout::from(VarInt::from_u32(self.config.max_idle_timeout_ms as u32));
            transport_cfg.max_idle_timeout(Some(timeout));
        }

        if self.config.keep_alive_interval_ms > 0 {
            transport_cfg.keep_alive_interval(Some(Duration::from_millis(
                self.config.keep_alive_interval_ms,
            )));
        }

        let (tls_client_cfg, domain) = self.parse_client_config_and_domain()?;

        let mut cfg = quinn::ClientConfig::new(Arc::new(tls_client_cfg));
        cfg.transport_config(Arc::new(transport_cfg));

        let remote_addr = Self::parse_server_addr(&self.config.server_addr).await?;
        let local_addr: SocketAddr = LOCAL_ADDR_STR.parse().unwrap();

        let mut endpoint = quinn::Endpoint::client(local_addr)?;
        endpoint.set_default_client_config(cfg);

        self.post_tunnel_log(
            format!(
                "connecting to {}, local_addr: {}",
                remote_addr,
                endpoint.local_addr().unwrap()
            )
            .as_str(),
        );

        let connection = endpoint.connect(remote_addr, domain.as_str())?.await?;

        self.set_and_post_tunnel_state(ClientState::Connected);
        self.post_tunnel_log(format!("connected to server: {:?}", remote_addr).as_str());

        let (mut quic_send, mut quic_recv) = connection
            .open_bi()
            .await
            .map_err(|e| error!("open bidirectional connection failed: {}", e))
            .unwrap();

        self.set_and_post_tunnel_state(ClientState::LoggingIn);
        self.post_tunnel_log("logging in...");

        Self::login(&self.config, &mut quic_send, &mut quic_recv).await?;

        self.set_and_post_tunnel_state(ClientState::Tunnelling);
        self.post_tunnel_log("logged in!");

        self.remote_conn = Some(Arc::new(RwLock::new(connection)));
        self.ctrl_stream = Some(ControlStream {
            quic_send,
            quic_recv,
        });

        Ok(())
    }

    async fn serve_outgoing(&mut self) {
        self.post_tunnel_log("start serving in [TunnelOut] mode...");

        self.report_traffic_data_in_background();

        let remote_conn = self.remote_conn.as_ref().unwrap();
        let ref conn = remote_conn.read().unwrap();

        // accept local connections and build a tunnel to remote
        while let Some(tcp_stream) = self.access_server.as_mut().unwrap().recv().await {
            match conn.open_bi().await {
                Ok(quic_stream) => {
                    debug!(
                        "[Out] open stream for conn, {} -> {}",
                        quic_stream.0.id().index(),
                        conn.remote_address(),
                    );

                    let tcp_stream = tcp_stream.into_split();
                    Tunnel::new().start(tcp_stream, quic_stream).await;
                }
                Err(e) => {
                    error!("failed to open_bi on remote connection: {}", e);
                    self.post_tunnel_log(
                        format!("connection failed, will reconnect: {}", e).as_str(),
                    );
                    break;
                }
            }
        }

        let stats = conn.stats();
        let mut data = self.total_traffic_data.as_ref().lock().unwrap();
        data.rx_bytes += stats.udp_rx.bytes;
        data.tx_bytes += stats.udp_tx.bytes;
        data.rx_dgrams += stats.udp_rx.datagrams;
        data.tx_dgrams += stats.udp_tx.datagrams;
    }

    async fn serve_incoming(&mut self) -> Result<()> {
        self.post_tunnel_log("start serving in [TunnelIn] mode...");

        self.observe_terminate_signals().await.map_err(|e| {
            self.post_tunnel_log("failed to observe signals");
            e
        })?;

        // this will take the lock exclusively, so remote_conn cannot be shared and we cannot
        // implement traffic data report for [IN] mode tunnelling using the same technique that
        // [Out] mode tunnelling uses
        let remote_conn = self.remote_conn.as_mut().unwrap().write().unwrap();
        while let Ok(quic_stream) = remote_conn.open_bi().await {
            match TcpStream::connect(self.config.local_access_server_addr.unwrap()).await {
                Ok(tcp_stream) => {
                    let tcp_stream = tcp_stream.into_split();
                    Tunnel::new().start(tcp_stream, quic_stream).await;
                }
                _ => {
                    error!("failed to connect to access server");
                }
            }
        }
        Ok(())
    }

    fn report_traffic_data_in_background(&self) {
        let remote_conn = Arc::downgrade(self.remote_conn.as_ref().unwrap());
        let total_traffic_data = self.total_traffic_data.clone();
        let tunnel_info_bridge = self.tunnel_info_bridge.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(POST_TRAFFIC_DATA_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                match remote_conn.upgrade() {
                    Some(remote_conn) => {
                        let stats = remote_conn.read().unwrap().stats();
                        let total_traffic_data = total_traffic_data.as_ref().lock().unwrap();
                        let data = TrafficData {
                            rx_bytes: stats.udp_rx.bytes + total_traffic_data.rx_bytes,
                            tx_bytes: stats.udp_tx.bytes + total_traffic_data.tx_bytes,
                            rx_dgrams: stats.udp_rx.datagrams + total_traffic_data.rx_dgrams,
                            tx_dgrams: stats.udp_tx.datagrams + total_traffic_data.tx_dgrams,
                        };
                        tunnel_info_bridge.post_tunnel_info(&TunnelInfo::new(
                            TunnelInfoType::Traffic,
                            Box::new(data),
                        ));
                    }
                    _ => {
                        info!("connection dropped!");
                        break;
                    }
                }
            }
        });
    }

    async fn observe_terminate_signals(&mut self) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            let mut quic_send = self.ctrl_stream.take().unwrap().quic_send;

            let is_terminated_flag = self.is_terminated.clone();

            tokio::spawn(async move {
                let mut ctrlc = signal(SignalKind::interrupt()).unwrap();
                let mut terminate = signal(SignalKind::terminate()).unwrap();
                tokio::select! {
                    _ = ctrlc.recv() => debug!("received SIGINT"),
                    _ = terminate.recv() => debug!("received SIGTERM"),
                }
                *is_terminated_flag.lock().unwrap() = true;

                TunnelMessage::send(&mut quic_send, &TunnelMessage::ReqTerminate)
                    .await
                    .ok();

                tokio::time::sleep(Duration::from_millis(1000)).await;
                std::process::exit(0);
            });
        }

        Ok(())
    }

    fn parse_client_config_and_domain(&self) -> Result<(rustls::ClientConfig, String)> {
        let cipher = *SelectedCipherSuite::from_str(&self.config.cipher).map_err(|_| {
            rustls::Error::General(format!("invalid cipher: {}", self.config.cipher))
        })?;

        if !Self::is_ip_addr(&self.config.server_addr) {
            let domain = match self.config.server_addr.rfind(':') {
                Some(colon_index) => self.config.server_addr[0..colon_index].to_string(),
                None => self.config.server_addr.to_string(),
            };

            let client_config = rustls::ClientConfig::builder()
                .with_cipher_suites(&[cipher])
                .with_safe_default_kx_groups()
                .with_safe_default_protocol_versions()?
                .with_custom_certificate_verifier(Arc::new(Verifier::new()))
                .with_no_client_auth();

            return Ok((client_config, domain));
        }

        if self.config.cert_path.is_empty() {
            let client_config = rustls::ClientConfig::builder()
                .with_cipher_suites(&[cipher])
                .with_safe_default_kx_groups()
                .with_safe_default_protocol_versions()?
                .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier::new()))
                .with_no_client_auth();

            warn!("No certificate is provided for verification, domain \"localhost\" is assumed");
            return Ok((client_config, "localhost".to_string()));
        }

        let cert: Certificate = Client::read_cert(self.config.cert_path.as_str())?;
        let mut roots = RootCertStore::empty();
        roots.add(&cert).context(format!(
            "certificate is not in DER format: {}",
            self.config.cert_path
        ))?;

        let (_rem, cert) = X509Certificate::from_der(cert.as_ref()).context(format!(
            "not a valid X509Certificate: {}",
            self.config.cert_path
        ))?;

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
            rustls::ClientConfig::builder()
                .with_cipher_suites(&[cipher])
                .with_safe_default_kx_groups()
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth(),
            common_name.to_string(),
        ))
    }

    fn should_retry(&mut self) -> bool {
        return !*self.is_terminated.lock().unwrap();
    }

    pub fn get_state(&self) -> ClientState {
        self.state.clone()
    }

    pub fn set_scheduled_start(&mut self, start: bool) {
        self.scheduled_start = start;
    }

    pub fn has_scheduled_start(&self) -> bool {
        self.scheduled_start
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
        if !resp.is_resp_success() {
            log_and_bail!("failed to login");
        }
        TunnelMessage::handle_message(&resp)?;
        debug!("finished login request!");
        Ok(())
    }

    fn read_cert(cert_path: &str) -> Result<rustls::Certificate> {
        let cert = std::fs::read(cert_path).context("failed to read cert file")?;
        let cert = rustls::Certificate(cert);

        Ok(cert)
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

        bail!("failed to resolve domain: {}", domain);
    }

    async fn lookup_server_ip(
        domain: &str,
        dot_server: &str,
        name_servers: Vec<String>,
    ) -> Result<IpAddr> {
        let resolver = if !dot_server.is_empty() {
            dns::resolver(dot_server, vec![])
        } else if !name_servers.is_empty() {
            dns::resolver("", name_servers)
        } else {
            rs_utilities::dns::resolver("", vec![])
        };

        let ip = resolver.await.lookup_first(domain).await?;
        info!("resolved {} to {}", domain, ip);
        Ok(ip)
    }

    fn post_tunnel_log(&self, log: &str) {
        info!("{}", log);
        self.post_tunnel_info(TunnelInfo::new(
            TunnelInfoType::TunnelLog,
            Box::new(format!(
                "{} {}",
                chrono::Local::now().format(TIME_FORMAT),
                log
            )),
        ));
    }

    fn set_and_post_tunnel_state(&mut self, state: ClientState) {
        info!("client state: {}", state);
        self.state = state;
        self.post_tunnel_info(TunnelInfo::new(
            TunnelInfoType::TunnelState,
            Box::new(self.state.to_string()),
        ));
    }

    fn post_tunnel_info<T>(&self, server_info: TunnelInfo<T>)
    where
        T: ?Sized + Serialize,
    {
        if self.on_info_report_enabled {
            self.tunnel_info_bridge.post_tunnel_info(&server_info);
        }
    }

    pub fn set_on_info_listener(&mut self, callback: impl FnMut(&str) + 'static + Send + Sync) {
        self.tunnel_info_bridge.set_listener(callback);
    }

    pub fn has_on_info_listener(&self) -> bool {
        self.tunnel_info_bridge.has_listener()
    }

    pub fn set_enable_on_info_report(&mut self, enable: bool) {
        info!("set_enable_on_info_report, enable:{}", enable);
        self.on_info_report_enabled = enable
    }
}

struct InsecureCertVerifier {}

impl InsecureCertVerifier {
    pub fn new() -> Self {
        InsecureCertVerifier {}
    }
}

impl rustls::client::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        warn!("======================================= WARNING ======================================");
        warn!("Connecting to a server without verifying its certificate is DANGEROUS!!!");
        warn!("Provide the self-signed certificate for verification or connect with a domain name");
        warn!("======================= Be cautious, this is for TEST only!!! ========================");
        Ok(ServerCertVerified::assertion())
    }
}
