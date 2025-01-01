use crate::tcp::tcp_server::{TcpMessage, TcpSender};
use crate::tcp::tcp_tunnel::TcpTunnel;
use crate::udp::udp_server::{UdpMessage, UdpSender};
use crate::udp::{udp_server::UdpServer, udp_tunnel::UdpTunnel};
use crate::{
    pem_util, ServerConfig, TcpServer, TcpTunnelInInfo, TcpTunnelOutInfo, TunnelMessage,
    TunnelType, UdpTunnelInInfo, UdpTunnelOutInfo, Upstream, UpstreamType, SUPPORTED_CIPHER_SUITES,
};
use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{congestion, Connection, Endpoint, TransportConfig};
use quinn_proto::{IdleTimeout, VarInt};
use rs_utilities::log_and_bail;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::time::Duration;

#[derive(Debug, Clone)]
struct ConnectedTcpInSession {
    conn: Connection,
    sender: TcpSender,
}

#[derive(Debug, Clone)]
struct ConnectedUdpInSession {
    conn: Connection,
    sender: UdpSender,
}

#[derive(Debug)]
struct State {
    config: ServerConfig,
    endpoint: Option<Endpoint>,
    tcp_sessions: Vec<ConnectedTcpInSession>,
    udp_sessions: Vec<ConnectedUdpInSession>,
}

impl State {
    pub fn new(config: ServerConfig) -> Self {
        State {
            config,
            endpoint: None,
            tcp_sessions: Vec::new(),
            udp_sessions: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct Server {
    inner_state: Arc<Mutex<State>>,
}

macro_rules! inner_state {
    ($self:ident, $field:ident) => {
        (*$self.inner_state.lock().unwrap()).$field
    };
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Server {
            inner_state: Arc::new(Mutex::new(State::new(config))),
        }
    }

    pub fn bind(&mut self) -> Result<SocketAddr> {
        let mut state = self.inner_state.lock().unwrap();
        let config = state.config.clone();
        let addr: SocketAddr = config
            .addr
            .parse()
            .context(format!("invalid address: {}", config.addr))?;

        let quinn_server_cfg = Self::load_quinn_server_config(&config)?;
        let endpoint = quinn::Endpoint::server(quinn_server_cfg, addr).map_err(|e| {
            error!("failed to bind tunnel server on address: {addr}, err: {e}");
            e
        })?;

        info!(
            "tunnel server is bound on address: {}, idle_timeout: {}",
            endpoint.local_addr()?,
            config.quic_timeout_ms
        );

        let ep = endpoint.clone();
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

        state.endpoint = Some(endpoint);
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
        if config.quic_timeout_ms > 0 {
            let timeout = IdleTimeout::from(VarInt::from_u32(config.quic_timeout_ms as u32));
            transport_cfg.max_idle_timeout(Some(timeout));
            transport_cfg
                .keep_alive_interval(Some(Duration::from_millis(config.quic_timeout_ms * 2 / 3)));
        }
        transport_cfg.max_concurrent_bidi_streams(VarInt::from_u32(1024));

        let quic_server_cfg = Arc::new(QuicServerConfig::try_from(tls_server_cfg)?);
        let mut quinn_server_cfg = quinn::ServerConfig::with_crypto(quic_server_cfg);
        quinn_server_cfg.transport = Arc::new(transport_cfg);
        Ok(quinn_server_cfg)
    }

    pub async fn serve(&self) -> Result<()> {
        let state = self.inner_state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                Self::clear_expired_sessions(state.clone());
            }
        });

        let endpoint = inner_state!(self, endpoint).take().context("failed")?;
        while let Some(client_conn) = endpoint.accept().await {
            let state = self.inner_state.clone();
            let config = inner_state!(self, config).clone();
            tokio::spawn(async move {
                let client_conn = client_conn.await?;
                let tun_type = Self::authenticate_connection(&config, client_conn).await?;

                match tun_type {
                    TunnelType::TcpOut(info) => {
                        TcpTunnel::process(info.conn, info.upstream_addr, config.tcp_timeout_ms)
                            .await;
                    }

                    TunnelType::UdpOut(info) => {
                        UdpTunnel::process(info.conn, info.upstream_addr, config.udp_timeout_ms)
                            .await
                    }

                    TunnelType::TcpIn(mut info) => {
                        state
                            .lock()
                            .unwrap()
                            .tcp_sessions
                            .push(ConnectedTcpInSession {
                                conn: info.conn.clone(),
                                sender: info.tcp_server.clone_tcp_sender(),
                            });

                        TcpTunnel::start(
                            false,
                            &info.conn,
                            &mut info.tcp_server,
                            &mut None,
                            config.tcp_timeout_ms,
                        )
                        .await;
                        info.tcp_server.shutdown().await.ok();
                    }

                    TunnelType::UdpIn(info) => {
                        state
                            .lock()
                            .unwrap()
                            .udp_sessions
                            .push(ConnectedUdpInSession {
                                conn: info.conn.clone(),
                                sender: info.udp_server.clone_udp_sender(),
                            });

                        UdpTunnel::start(
                            info.conn,
                            info.udp_server,
                            None,
                            false,
                            config.udp_timeout_ms,
                        )
                        .await
                        .ok();
                    }
                }

                Ok::<(), anyhow::Error>(())
            });
        }
        info!("quit!");

        Ok(())
    }

    async fn authenticate_connection(
        config: &ServerConfig,
        conn: quinn::Connection,
    ) -> Result<TunnelType> {
        let remote_addr = &conn.remote_address();

        info!("authenticating connection, addr:{remote_addr}");
        let (mut quic_send, mut quic_recv) = conn
            .accept_bi()
            .await
            .context(format!("login request not received in time: {remote_addr}"))?;

        info!("received bi_stream request: {remote_addr}");
        let tunnel_type;
        match TunnelMessage::recv(&mut quic_recv).await? {
            TunnelMessage::ReqTcpOutLogin(login_info) => {
                info!("received ReqTcpOutLogin request: {remote_addr}");

                Self::check_password(config.password.as_str(), login_info.password.as_str())?;

                let upstream_addr = Self::obtain_upstream_addr(
                    false,
                    UpstreamType::Tcp,
                    &login_info.upstream,
                    &config.default_tcp_upstream,
                )?;

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;

                tunnel_type = TunnelType::TcpOut(TcpTunnelOutInfo {
                    conn,
                    upstream_addr,
                });
                info!("sent response for ReqTcpOutLogin request: {remote_addr}");
            }

            TunnelMessage::ReqUdpOutLogin(login_info) => {
                info!("received ReqUdpOutLogin request: {remote_addr}");

                Self::check_password(config.password.as_str(), login_info.password.as_str())?;

                let upstream_addr = Self::obtain_upstream_addr(
                    false,
                    UpstreamType::Udp,
                    &login_info.upstream,
                    &config.default_udp_upstream,
                )?;

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;

                tunnel_type = TunnelType::UdpOut(UdpTunnelOutInfo {
                    conn,
                    upstream_addr,
                });
                info!("sent response for ReqUdpOutLogin request: {remote_addr}");
            }

            TunnelMessage::ReqTcpInLogin(login_info) => {
                info!("received ReqTcpInLogin request: {remote_addr}");

                Self::check_password(config.password.as_str(), login_info.password.as_str())?;

                let upstream_addr = Self::obtain_upstream_addr(
                    true,
                    UpstreamType::Tcp,
                    &login_info.upstream,
                    &config.default_tcp_upstream,
                )?;

                let tcp_server = match TcpServer::bind_and_start(upstream_addr).await {
                    Ok(tcp_server) => tcp_server,
                    Err(e) => {
                        TunnelMessage::send_failure(
                            &mut quic_send,
                            format!("udp server failed to bind at: {upstream_addr}"),
                        )
                        .await?;
                        log_and_bail!("login rejected: {e}");
                    }
                };

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;
                tunnel_type = TunnelType::TcpIn(TcpTunnelInInfo { conn, tcp_server });
                info!("sent response for ReqTcpInLogin request: {remote_addr}");
            }

            TunnelMessage::ReqUdpInLogin(login_info) => {
                info!("received ReqUdpInLogin request: {remote_addr}");

                Self::check_password(config.password.as_str(), login_info.password.as_str())?;

                let upstream_addr = Self::obtain_upstream_addr(
                    true,
                    UpstreamType::Udp,
                    &login_info.upstream,
                    &config.default_udp_upstream,
                )?;

                let udp_server = match UdpServer::bind_and_start(upstream_addr).await {
                    Ok(udp_server) => udp_server,
                    Err(e) => {
                        TunnelMessage::send_failure(
                            &mut quic_send,
                            format!("udp server failed to bind at: {upstream_addr}"),
                        )
                        .await?;
                        log_and_bail!("login rejected: {e}");
                    }
                };

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;
                tunnel_type = TunnelType::UdpIn(UdpTunnelInInfo { conn, udp_server });
                info!("sent response for ReqUdpInLogin request: {remote_addr}");
            }

            _ => {
                log_and_bail!("received unepxected message");
            }
        }

        info!("connection authenticated! addr: {remote_addr}");

        Ok(tunnel_type)
    }

    fn obtain_upstream_addr(
        is_tunnel_in: bool,
        upstream_type: UpstreamType,
        upstream: &Upstream,
        default_upstream: &Option<SocketAddr>,
    ) -> Result<SocketAddr> {
        Ok(match upstream {
            Upstream::PeerDefault => {
                if is_tunnel_in {
                    log_and_bail!("explicit port is required to start TunnelIn mode tunneling");
                }

                if default_upstream.is_none() {
                    log_and_bail!(
                        "explicit {upstream_type} upstream address must be specified when logging in because there's no default upstream specified for the server"
                    );
                }

                default_upstream.unwrap()
            }

            Upstream::ClientSpecified(addr) => {
                if is_tunnel_in && !addr.ip().is_unspecified() && !addr.ip().is_loopback() {
                    log_and_bail!(
                        "only loopback or unspecified IP is allowed for TunnelIn mode tunelling: {addr:?}, or simply specify a port without the IP part"
                    );
                }

                *addr
            }
        })
    }

    fn clear_expired_sessions(state: Arc<Mutex<State>>) {
        let mut state = state.lock().unwrap();
        state.udp_sessions.retain(|sess| {
            if sess.conn.close_reason().is_some() {
                let sess = sess.clone();
                tokio::spawn(async move {
                    sess.sender.send(UdpMessage::Quit).await.ok();
                    debug!("dropped udp session: {}", sess.conn.remote_address());
                });
                false
            } else {
                true
            }
        });

        state.tcp_sessions.retain(|sess| {
            if sess.conn.close_reason().is_some() {
                let sess = sess.clone();
                tokio::spawn(async move {
                    sess.sender.send(TcpMessage::Quit).await.ok();
                    debug!("dropped tcp session: {}", sess.conn.remote_address());
                });
                false
            } else {
                true
            }
        });
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
