use crate::{
    pem_util, socket_addr_with_unspecified_ip_port,
    tcp::tcp_tunnel::TcpTunnel,
    tunnel_info_bridge::{TunnelInfo, TunnelInfoBridge, TunnelInfoType, TunnelTraffic},
    tunnel_message::TunnelMessage,
    udp::{udp_server::UdpServer, udp_tunnel::UdpTunnel},
    ClientConfig, LoginInfo, SelectedCipherSuite, TcpServer, TunnelConfig, TunnelMode,
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
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    fmt::Display,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex, Once},
    time::Duration,
};
use tokio::net::TcpStream;

// Time format for logging timestamps
const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S.%3f";
// Default server port for QUIC connections
const DEFAULT_SERVER_PORT: u16 = 3515;
// Interval for reporting traffic statistics (30 seconds)
const POST_TRAFFIC_DATA_INTERVAL_SECS: u64 = 30;
static INIT: Once = Once::new();

// Client connection states during tunnel lifecycle
#[derive(Clone, Serialize, PartialEq)]
pub enum ClientState {
    Idle = 0,   // Initial state, no connections
    Connecting, // Attempting to establish QUIC connection
    Connected,  // QUIC connection established
    LoggingIn,  // Authenticating with server
    Tunneling,  // Active tunneling mode
    Stopping,   // Graceful shutdown in progress
    Terminated, // Completely stopped
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

// Internal state maintaining all active connections and servers
struct State {
    tcp_servers: HashMap<SocketAddr, TcpServer>, // TCP proxy servers
    udp_servers: HashMap<SocketAddr, UdpServer>, // UDP proxy servers
    endpoints: HashMap<SocketAddr, Endpoint>,    // QUIC endpoints
    connections: HashMap<SocketAddr, Connection>, // Active QUIC connections
    client_state: ClientState,                   // Current client state
    total_traffic_data: TunnelTraffic,           // Accumulated traffic stats
    tunnel_info_bridge: TunnelInfoBridge,        // Event reporting bridge
    on_info_report_enabled: bool,                // Enable/disable reporting
    migration_stop_sender: Option<tokio::sync::oneshot::Sender<()>>, // Stop migration task
    migration_handle: Option<tokio::task::JoinHandle<()>>, // Migration task handle
}

impl State {
    fn new() -> Self {
        Self {
            tcp_servers: HashMap::new(),
            udp_servers: HashMap::new(),
            endpoints: HashMap::new(),
            connections: HashMap::new(),
            client_state: ClientState::Idle,
            total_traffic_data: TunnelTraffic::default(),
            tunnel_info_bridge: TunnelInfoBridge::new(),
            on_info_report_enabled: false,
            migration_stop_sender: None,
            migration_handle: None,
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

impl Client {
    fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut State) -> R,
    {
        let mut guard = self.inner_state.lock().expect("Failed to lock state");
        f(&mut *guard)
    }

    fn with_state_read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&State) -> R,
    {
        let guard = self.inner_state.lock().expect("Failed to lock state");
        f(&*guard)
    }

    pub fn get_client_state(&self) -> ClientState {
        self.with_state_read(|state| state.client_state.clone())
    }

    // Initialize client with configuration and set up crypto provider
    pub fn new(config: ClientConfig) -> Self {
        // Ensure ring crypto provider is installed globally (once)
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

    // Start tunneling in blocking mode with signal handling
    pub fn start_tunneling(&mut self) {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(self.config.workers)
            .build()
            .unwrap()
            .block_on(async {
                let mut this = self.clone();
                this.connect_and_serve_async();

                match tokio::signal::ctrl_c().await {
                    Ok(()) => {
                        info!("Received Ctrl+C, initiating shutdown...");
                        this.stop_async().await;
                    }
                    Err(e) => {
                        error!("Failed to listen for Ctrl+C: {}", e);
                    }
                }
            });
    }

    // Start TCP server with exponential backoff retry logic
    pub async fn start_tcp_server(&self, addr: SocketAddr) -> Result<TcpServer> {
        let bind_tcp_server = || async { TcpServer::bind_and_start(addr).await };
        // Retry binding with exponential backoff (max 10 times, max 10s delay)
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

        // Store server reference in state
        self.with_state(|state| {
            state.tcp_servers.insert(addr, tcp_server.clone());
        });
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
        self.with_state(|state| {
            state.udp_servers.insert(addr, udp_server.clone());
        });
        Ok(udp_server)
    }

    pub fn get_config(&self) -> ClientConfig {
        self.config.clone()
    }

    #[allow(clippy::unnecessary_to_owned)]
    pub fn stop(&self) {
        self.set_and_post_tunnel_state(ClientState::Stopping);

        if let Ok(mut state) = self.inner_state.lock() {
            if let Some(sender) = state.migration_stop_sender.take() {
                let _ = sender.send(());
            }

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
            state.migration_handle = None;
        }

        std::thread::sleep(Duration::from_secs(3));
    }

    #[allow(clippy::unnecessary_to_owned)]
    pub async fn stop_async(&self) {
        self.set_and_post_tunnel_state(ClientState::Stopping);

        let mut tasks = tokio::task::JoinSet::new();

        if let Ok(mut state) = self.inner_state.lock() {
            if let Some(sender) = state.migration_stop_sender.take() {
                info!("Sending stop signal to migration task");
                let _ = sender.send(());
            }
        }

        if let Ok(mut state) = self.inner_state.lock() {
            if let Some(handle) = state.migration_handle.take() {
                info!("Waiting for migration task to complete");
                match tokio::time::timeout(Duration::from_secs(5), handle).await {
                    Ok(Ok(())) => {
                        info!("Migration task completed successfully");
                    }
                    Ok(Err(e)) => {
                        warn!("Migration task completed with error: {}", e);
                    }
                    Err(_) => {
                        warn!(
                            "Migration task did not complete within timeout, continuing shutdown"
                        );
                    }
                }
            }
        }

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
            state.migration_handle = None;
            state.migration_stop_sender = None;
        }

        let mut completed_tasks = 0;
        let total_tasks = tasks.len();

        while !tasks.is_empty() {
            match tokio::time::timeout(Duration::from_secs(2), tasks.join_next()).await {
                Ok(Some(_)) => {
                    completed_tasks += 1;
                }
                Ok(None) => break,
                Err(_) => {
                    warn!(
                        "Task join timed out, aborting remaining {} tasks",
                        tasks.len()
                    );
                    break;
                }
            }
        }

        info!(
            "Completed {}/{} shutdown tasks",
            completed_tasks, total_tasks
        );

        self.set_and_post_tunnel_state(ClientState::Terminated);
    }

    #[allow(clippy::unnecessary_to_owned)]
    pub fn connect_and_serve_async(&mut self) {
        for (index, tunnel_config) in self.config.tunnels.iter().cloned().enumerate() {
            let mut this = self.clone();
            tokio::spawn(async move {
                this.connect_and_serve(index, tunnel_config.clone()).await;
            });
        }

        self.report_traffic_data_in_background();
    }

    // Main connection and serving loop for each tunnel
    async fn connect_and_serve(&mut self, index: usize, tunnel_config: TunnelConfig) {
        let login_info = LoginInfo {
            password: self.config.password.clone(),
            tunnel_config: tunnel_config.clone(),
        };

        let mut pending_tcp_stream = None;
        loop {
            // Define connection establishment logic with retry
            let connect = || async {
                let login_cfg = self.prepare_login_config().await?;
                let mut endpoint = Endpoint::client(login_cfg.local_addr)?;
                endpoint.set_default_client_config(login_cfg.quinn_client_cfg);

                // Perform login handshake
                let conn = self
                    .login(
                        index,
                        &endpoint,
                        &login_info,
                        &login_cfg.remote_addr,
                        login_cfg.domain.as_str(),
                    )
                    .await?;

                Ok((conn, endpoint))
            };

            // Retry connection with unlimited attempts until shutdown
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
                Ok((conn, endpoint)) => {
                    let upstream_type = &tunnel_config.upstream.upstream_type;
                    let local_server_addr = tunnel_config.local_server_addr.unwrap();
                    let should_start_migration = {
                        let mut state = self.inner_state.lock().unwrap();
                        state.connections.insert(local_server_addr, conn.clone());
                        state.endpoints.insert(local_server_addr, endpoint);

                        self.config.hop_interval_seconds > 0 && state.migration_handle.is_none()
                    };
                    if should_start_migration {
                        info!(
                            "Starting migration task for tunnel {} with hop interval: {}s",
                            index, self.config.hop_interval_seconds
                        );
                        self.start_unified_migration_task();
                    }

                    if tunnel_config.mode == TunnelMode::Out {
                        match upstream_type {
                            UpstreamType::Tcp => {
                                self.serve_outbound_tcp(
                                    index,
                                    conn.clone(),
                                    local_server_addr,
                                    &mut pending_tcp_stream,
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

                    {
                        let mut state = self.inner_state.lock().unwrap();
                        state.connections.remove(&local_server_addr);
                        state.endpoints.remove(&local_server_addr);
                    }
                }

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

    // Start unified connection migration task for all endpoints
    fn start_unified_migration_task(&self) {
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();

        {
            let mut state = self.inner_state.lock().unwrap();
            state.migration_stop_sender = Some(stop_tx);
        }

        let state = self.inner_state.clone();
        let hop_interval_seconds = self.config.hop_interval_seconds;

        let handle = tokio::spawn(async move {
            info!("✅ migration task actually started");

            let mut interval = tokio::time::interval(Duration::from_secs(hop_interval_seconds));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let endpoints_to_migrate = match state.try_lock() {
                            Ok(guard) => {
                                guard.endpoints.iter()
                                    .filter_map(|(addr, endpoint)| {
                                        if let Some(conn) = guard.connections.get(addr) {
                                            if conn.close_reason().is_none() {
                                                Some((*addr, endpoint.clone()))
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    })
                                    .collect::<Vec<_>>()
                            },
                            Err(_) => {
                                warn!("Could not acquire lock during migration tick");
                                continue;
                            }
                        };

                        for (addr, endpoint) in endpoints_to_migrate {
                            info!("⛓ migrating connection: {}", addr);
                            let _ = Self::perform_connection_migration(&endpoint).await;
                        }
                    }
                    _ = &mut stop_rx => {
                        info!("🛑 migration task received stop signal");
                        break;
                    }
                }
            }

            info!("✅ Unified migration task exited");
        });

        {
            let mut state = self.inner_state.lock().unwrap();
            state.migration_handle = Some(handle);
        }
    }

    // Perform actual connection migration by rebinding to new local address
    async fn perform_connection_migration(endpoint: &Endpoint) -> Result<()> {
        let current_local_addr = endpoint.local_addr().map_err(|e| {
            error!("Failed to get current local address: {}", e);
            e
        })?;

        info!("Starting connection migration from: {}", current_local_addr);

        // Create new unspecified address with same IP version
        let new_local_addr = if current_local_addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 0)
        };

        let new_socket = match std::net::UdpSocket::bind(new_local_addr) {
            Ok(socket) => socket,
            Err(e) => {
                error!(
                    "Failed to bind new socket for migration from {}: {}",
                    current_local_addr, e
                );
                return Err(anyhow::Error::new(e));
            }
        };

        let actual_new_addr = new_socket.local_addr().map_err(|e| {
            error!("Failed to get new socket address: {}", e);
            e
        })?;

        info!(
            "Connection migration: {} -> {}",
            current_local_addr, actual_new_addr
        );

        endpoint.rebind(new_socket).map_err(|e| {
            error!(
                "Failed to rebind endpoint during migration: {} -> {}: {}",
                current_local_addr, actual_new_addr, e
            );
            anyhow::Error::new(e)
        })?;

        info!(
            "Connection migration successful: {} -> {}",
            current_local_addr, actual_new_addr
        );
        Ok(())
    }

    // Prepare QUIC transport and TLS configuration for connection
    async fn prepare_login_config(&self) -> Result<LoginConfig> {
        // Configure QUIC transport parameters
        let mut transport_cfg = TransportConfig::default();
        transport_cfg.stream_receive_window(VarInt::from_u32(1024 * 1024)); // 1MB stream window
        transport_cfg.receive_window(VarInt::from_u32(1024 * 1024 * 2)); // 2MB connection window
        transport_cfg.send_window(1024 * 1024 * 2); // 2MB send window
        transport_cfg.congestion_controller_factory(Arc::new(congestion::BbrConfig::default())); // Use BBR
        transport_cfg.max_concurrent_bidi_streams(VarInt::from_u32(1024)); // Max 1024 streams

        // Configure idle timeout if specified
        if self.config.quic_timeout_ms > 0 {
            let timeout = IdleTimeout::from(VarInt::from_u32(self.config.quic_timeout_ms as u32));
            transport_cfg.max_idle_timeout(Some(timeout));
            // Keep-alive at 2/3 of timeout interval
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

    // Perform login handshake with remote server
    async fn login(
        &self,
        index: usize,
        endpoint: &Endpoint,
        login_info: &LoginInfo,
        remote_addr: &SocketAddr,
        domain: &str,
    ) -> Result<Connection> {
        self.set_and_post_tunnel_state(ClientState::Connecting);
        // Log connection attempt with configuration details
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

        // Establish QUIC connection
        let conn = endpoint.connect(*remote_addr, domain)?.await?;
        // Open bidirectional stream for login
        let (mut quic_send, mut quic_recv) = conn
            .open_bi()
            .await
            .context("open bidirectional connection failed")?;

        self.set_and_post_tunnel_state(ClientState::Connected);

        // Send login request and wait for response
        let login_msg = TunnelMessage::ReqLogin(login_info.clone());
        TunnelMessage::send(&mut quic_send, &login_msg).await?;

        let resp = TunnelMessage::recv(&mut quic_recv).await?;
        // Handle login response
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

    async fn get_or_create_tcp_server(&mut self, addr: SocketAddr) -> Result<TcpServer> {
        let existing_server = self.with_state(|state| state.tcp_servers.get(&addr).cloned());
        match existing_server {
            Some(server) => Ok(server),
            None => self.start_tcp_server(addr).await,
        }
    }

    async fn serve_outbound_tcp(
        &mut self,
        index: usize,
        conn: Connection,
        local_server_addr: SocketAddr,
        pending_tcp_stream: &mut Option<TcpStream>,
    ) -> Result<()> {
        let mut tcp_server = self.get_or_create_tcp_server(local_server_addr).await?;

        self.post_tunnel_log(
            format!(
                "{index}:TCP_OUT start serving from {} via {}",
                tcp_server.addr(),
                conn.remote_address()
            )
            .as_str(),
        );

        self.set_and_post_tunnel_state(ClientState::Tunneling);

        TcpTunnel::start(
            true,
            &conn,
            &mut tcp_server,
            pending_tcp_stream,
            self.config.tcp_timeout_ms,
        )
        .await;

        Ok(())
    }

    async fn get_or_create_udp_server(&mut self, addr: SocketAddr) -> Result<UdpServer> {
        let existing_server = self.with_state(|state| state.udp_servers.get(&addr).cloned());
        match existing_server {
            Some(server) => Ok(server),
            None => self.start_udp_server(addr).await,
        }
    }

    async fn serve_outbound_udp(
        &mut self,
        index: usize,
        conn: Connection,
        local_server_addr: SocketAddr,
    ) -> Result<()> {
        let udp_server = self.get_or_create_udp_server(local_server_addr).await?;

        self.post_tunnel_log(
            format!(
                "{index}:UDP_OUT start serving from {} via {}",
                udp_server.addr(),
                conn.remote_address()
            )
            .as_str(),
        );

        self.set_and_post_tunnel_state(ClientState::Tunneling);

        UdpTunnel::start(&conn, udp_server, None, self.config.udp_timeout_ms)
            .await
            .ok();

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
        TcpTunnel::process(&conn, local_server_addr, self.config.tcp_timeout_ms).await;

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
        UdpTunnel::process(&conn, local_server_addr, self.config.udp_timeout_ms).await;

        Ok(())
    }

    fn should_quit(&self) -> bool {
        let state = self.get_state();
        state == ClientState::Stopping || state == ClientState::Terminated
    }

    // Background task for reporting traffic statistics
    fn report_traffic_data_in_background(&self) {
        let state = self.inner_state.clone();
        tokio::spawn(async move {
            // Create 30-second interval timer
            let mut interval =
                tokio::time::interval(Duration::from_secs(POST_TRAFFIC_DATA_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                // Collect traffic statistics from all connections
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

                // Add accumulated traffic data
                {
                    let total_traffic_data = &&state.lock().unwrap().total_traffic_data;
                    rx_bytes += total_traffic_data.rx_bytes;
                    tx_bytes += total_traffic_data.tx_bytes;
                    rx_dgrams += total_traffic_data.rx_dgrams;
                    tx_dgrams += total_traffic_data.tx_dgrams;
                }

                // Report traffic statistics
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

                // Exit if client is stopping
                if client_state == ClientState::Stopping || client_state == ClientState::Terminated
                {
                    break;
                }
            }
        });
    }

    fn get_crypto_provider(&self, cipher: &SupportedCipherSuite) -> Arc<CryptoProvider> {
        let base_provider = rustls::crypto::ring::default_provider();
        let mut cipher_suites = vec![*cipher];
        // Quinn assumes that the cipher suites contain this one
        cipher_suites.push(cipher_suite::TLS13_AES_128_GCM_SHA256);
        Arc::new(CryptoProvider {
            cipher_suites,
            ..base_provider
        })
    }

    fn create_client_config_builder(
        &self,
        cipher: &SupportedCipherSuite,
    ) -> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>, rustls::Error>
    {
        let cfg_builder =
            rustls::ClientConfig::builder_with_provider(self.get_crypto_provider(cipher))
                .with_protocol_versions(&[&rustls::version::TLS13])?;
        Ok(cfg_builder)
    }

    fn extract_domain_or_ip(&self) -> String {
        match self.config.server_addr.rfind(':') {
            Some(colon_index) => self.config.server_addr[0..colon_index].to_string(),
            None => self.config.server_addr.to_string(),
        }
    }

    // Parse and create TLS client configuration based on certificate settings
    fn parse_client_config_and_domain(&self) -> Result<(rustls::ClientConfig, String)> {
        let cipher = *SelectedCipherSuite::from_str(&self.config.cipher).map_err(|_| {
            rustls::Error::General(format!("invalid cipher: {}", self.config.cipher))
        })?;

        // No certificate provided - use different verification strategies
        if self.config.cert_path.is_empty() {
            // Use platform verifier for domain names
            if !Self::is_ip_addr(&self.config.server_addr) {
                let domain = self.extract_domain_or_ip();
                let client_config = self
                    .create_client_config_builder(&cipher)?
                    .with_platform_verifier()?
                    .with_no_client_auth();
                return Ok((client_config, domain));
            }

            // Use insecure verifier for IP addresses (testing only)
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

        // Certificate provided - load and use for verification
        let certs = pem_util::load_certificates_from_pem(self.config.cert_path.as_str())
            .context("failed to read from cert file")?;
        if certs.is_empty() {
            log_and_bail!(
                "No certificates found in provided file: {}",
                self.config.cert_path
            );
        }

        // Add all certificates to root certificate store
        let mut roots = RootCertStore::empty();
        for cert in &certs {
            roots.add(cert.clone()).context(format!(
                "failed to add certificate from file: {}",
                self.config.cert_path
            ))?;
        }

        // for self-signed certificates, generating IP-based TLS certificates is not difficult
        let domain_or_ip = self.extract_domain_or_ip();

        Ok((
            self.create_client_config_builder(&cipher)?
                .with_root_certificates(roots)
                .with_no_client_auth(),
            domain_or_ip,
        ))
    }

    pub fn get_state(&self) -> ClientState {
        self.get_client_state()
    }

    fn is_ip_addr(addr: &str) -> bool {
        addr.parse::<SocketAddr>().is_ok()
    }

    // Resolve server address using multiple DNS strategies
    async fn parse_server_addr(&self) -> Result<SocketAddr> {
        let addr = self.config.server_addr.as_str();
        // Try parsing as direct socket address first
        let sock_addr: Result<SocketAddr> = addr.parse().context("error will be ignored");
        if sock_addr.is_ok() {
            return sock_addr;
        }

        // Extract domain and port from address string
        let mut domain = addr;
        let mut port = DEFAULT_SERVER_PORT;
        let pos = addr.rfind(':');
        if let Some(pos) = pos {
            port = addr[(pos + 1)..]
                .parse()
                .with_context(|| format!("invalid address: {}", addr))?;
            domain = &addr[..pos];
        }

        // Try DNS-over-TLS servers first
        for dot in &self.config.dot_servers {
            if let Ok(ip) = Self::lookup_server_ip(domain, dot, vec![]).await {
                return Ok(SocketAddr::new(ip, port));
            }
        }

        // Try configured DNS servers
        if let Ok(ip) = Self::lookup_server_ip(domain, "", self.config.dns_servers.clone()).await {
            return Ok(SocketAddr::new(ip, port));
        }

        // Fall back to system DNS
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
        self.with_state(|state| {
            state.tunnel_info_bridge.set_listener(callback);
        });
    }

    pub fn has_on_info_listener(&self) -> bool {
        self.with_state(|state| state.tunnel_info_bridge.has_listener())
    }

    pub fn set_enable_on_info_report(&self, enable: bool) {
        info!("set_enable_on_info_report, enable:{enable}");
        self.with_state(|state| {
            state.on_info_report_enabled = enable;
        });
    }
}

// Insecure certificate verifier for testing purposes
#[derive(Debug)]
struct InsecureCertVerifier(Arc<CryptoProvider>);

impl InsecureCertVerifier {
    pub fn new(crypto: Arc<CryptoProvider>) -> Self {
        Self(crypto)
    }
}

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    // Always accept any certificate (DANGEROUS - testing only)
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::prelude::v1::Result<ServerCertVerified, rustls::Error> {
        static ONCE: Once = Once::new();
        // Show warning only once
        ONCE.call_once(|| {
            warn!("======================================= WARNING ======================================");
            warn!("Connecting to a server without verifying its certificate is DANGEROUS!!!");
            warn!("Provide the self-signed certificate for verification or connect with a domain name");
            warn!("======================= Be cautious, this is for TEST only!!! ========================");
        });
        Ok(ServerCertVerified::assertion())
    }

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
}
