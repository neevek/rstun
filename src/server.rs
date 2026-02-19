use crate::heartbeat;
use crate::tcp::tcp_tunnel::TcpTunnel;
use crate::tcp::{StreamMessage, StreamSender};
use crate::tunnel_message::TunnelMessage;
use crate::udp::udp_server::{UdpMessage, UdpSender};
use crate::udp::{udp_server::UdpServer, udp_tunnel::UdpTunnel};
use crate::{
    SUPPORTED_CIPHER_SUITES, ServerConfig, TcpServer, TcpTunnelInInfo, TcpTunnelOutInfo, Tunnel,
    TunnelConfig, TunnelMode, TunnelType, UdpTunnelInInfo, UdpTunnelOutInfo, UpstreamType,
    pem_util,
};
use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use quinn::IdleTimeout;
use quinn::VarInt;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Connection, Endpoint, SendStream, TransportConfig, congestion};
use rs_utilities::log_and_bail;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Once};
use tokio::net::TcpStream;
use tokio::time::Duration;

#[derive(Debug, Clone)]
struct ConnectedTcpInSession {
    conn: Connection,
    sender: StreamSender<TcpStream>,
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
        let endpoint = quinn::Endpoint::server(quinn_server_cfg, addr).inspect_err(|e| {
            error!("failed to bind tunnel server on address: {addr}, err: {e}");
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
        transport_cfg.stream_receive_window(VarInt::from_u32(1024 * 1024));
        transport_cfg.receive_window(VarInt::from_u32(1024 * 1024 * 2));
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
            let mut interval = tokio::time::interval(Duration::from_millis(2400));
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
                let result = async {
                    let client_conn = client_conn.await?;
                    let tun_type = Self::authenticate_connection(&config, client_conn).await?;

                    match tun_type {
                        TunnelType::TcpOut(info) => {
                            TcpTunnel::start_accepting(
                                &info.conn,
                                Some(info.upstream_addr),
                                config.tcp_timeout_ms,
                            )
                            .await
                            .ok();
                        }

                        TunnelType::UdpOut(info) => {
                            UdpTunnel::start_accepting(
                                &info.conn,
                                Some(info.upstream_addr),
                                config.udp_timeout_ms,
                            )
                            .await
                            .ok();
                        }

                        TunnelType::TcpIn(mut info) => {
                            state
                                .lock()
                                .unwrap()
                                .tcp_sessions
                                .push(ConnectedTcpInSession {
                                    conn: info.conn.clone(),
                                    sender: info.tcp_server.clone_sender(),
                                });

                            let tcp_receiver = match info.tcp_server.take_receiver() {
                                Ok(receiver) => receiver,
                                Err(e) => {
                                    warn!("tcp receiver unavailable, will drop session: {e}");
                                    return Ok::<(), anyhow::Error>(());
                                }
                            };
                            let tcp_receiver =
                                std::sync::Arc::new(tokio::sync::Mutex::new(tcp_receiver));

                            TcpTunnel::start_serving(
                                false,
                                &info.conn,
                                tcp_receiver,
                                &mut None,
                                config.tcp_timeout_ms,
                            )
                            .await
                            .ok();

                            info.tcp_server.shutdown().await.ok();
                        }

                        TunnelType::UdpIn(mut info) => {
                            state
                                .lock()
                                .unwrap()
                                .udp_sessions
                                .push(ConnectedUdpInSession {
                                    conn: info.conn.clone(),
                                    sender: info.udp_server.clone_sender(),
                                });

                            let mut udp_receiver = match info.udp_server.take_receiver() {
                                Ok(receiver) => receiver,
                                Err(e) => {
                                    warn!("udp receiver unavailable, will drop session: {e}");
                                    return Ok::<(), anyhow::Error>(());
                                }
                            };
                            let udp_sender = info.udp_server.clone_sender();

                            UdpTunnel::start_serving(
                                &info.conn,
                                &udp_sender,
                                &mut udp_receiver,
                                config.udp_timeout_ms,
                            )
                            .await
                            .ok();

                            info.udp_server.shutdown().await.ok();
                        }
                        TunnelType::DynamicUpstreamTcpOut(conn) => {
                            TcpTunnel::start_accepting(&conn, None, config.tcp_timeout_ms)
                                .await
                                .ok();
                        }
                        TunnelType::DynamicUpstreamUdpOut(conn) => {
                            UdpTunnel::start_accepting(&conn, None, config.udp_timeout_ms)
                                .await
                                .ok();
                        }
                    }

                    Ok::<(), anyhow::Error>(())
                }
                .await;

                if let Err(err) = result {
                    error!("connection handling failed: {err:?}");
                }
            });
        }
        info!("server stopped");

        Ok(())
    }

    async fn authenticate_connection(
        config: &ServerConfig,
        conn: quinn::Connection,
    ) -> Result<TunnelType> {
        let remote_addr = &conn.remote_address();

        info!("authenticating connection, remote_addr:{remote_addr}");
        let (mut quic_send, mut quic_recv) = conn
            .accept_bi()
            .await
            .context(format!("login request not received in time: {remote_addr}"))?;

        info!("received bi_stream request: {remote_addr}");
        match TunnelMessage::recv(&mut quic_recv).await? {
            TunnelMessage::ReqLogin(login_info) => {
                let tunnel_label = login_info.to_string();
                info!("[{tunnel_label}] received ReqLogin request: {remote_addr}");

                Self::check_password(config.password.as_str(), login_info.password.as_str())?;

                let heartbeat_conn = conn.clone();
                let tunnel_type = match login_info.tunnel {
                    Tunnel::NetworkBased(tunnel_config) => {
                        Self::derive_tunnel_type(conn, &mut quic_send, &tunnel_config, config)
                            .await?
                    }
                    Tunnel::ChannelBased(upstream_type) => match upstream_type {
                        UpstreamType::Tcp => TunnelType::DynamicUpstreamTcpOut(conn),
                        UpstreamType::Udp => TunnelType::DynamicUpstreamUdpOut(conn),
                    },
                };

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;
                info!("[{tunnel_label}] connection authenticated, remote_addr:{remote_addr}");

                Self::start_heartbeat_responder(tunnel_label, heartbeat_conn, quic_send, quic_recv);
                Ok(tunnel_type)
            }

            _ => {
                log_and_bail!("received unexpected message");
            }
        }
    }

    fn start_heartbeat_responder(
        tunnel_label: String,
        conn: quinn::Connection,
        mut quic_send: quinn::SendStream,
        mut quic_recv: quinn::RecvStream,
    ) {
        tokio::spawn(async move {
            tokio::select! {
                _ = conn.closed() => {
                    debug!(
                        "[{tunnel_label}] heartbeat responder stopping, remote_addr:{}",
                        conn.remote_address()
                    );
                }
                result = heartbeat::server_heartbeat(&mut quic_recv, &mut quic_send, || conn.close_reason().is_some()) => {
                    if let Err(err) = result {
                        if conn.close_reason().is_some() {
                            debug!(
                                "[{tunnel_label}] heartbeat responder closed, remote_addr:{}",
                                conn.remote_address()
                            );
                        } else {
                            warn!(
                                "[{tunnel_label}] heartbeat failed, closing connection, remote_addr:{}, err:{err}",
                                conn.remote_address()
                            );
                            conn.close(VarInt::from_u32(1), b"heartbeat failed");
                        }
                    }
                }
            }
        });
    }

    async fn derive_tunnel_type(
        conn: quinn::Connection,
        quic_send: &mut SendStream,
        tunnel_config: &TunnelConfig,
        config: &ServerConfig,
    ) -> Result<TunnelType> {
        let upstream_addr = match tunnel_config.upstream.upstream_type {
            UpstreamType::Tcp => {
                Self::obtain_upstream_addr(tunnel_config, &config.default_tcp_upstream)?
            }
            UpstreamType::Udp => {
                Self::obtain_upstream_addr(tunnel_config, &config.default_udp_upstream)?
            }
        };
        let tunnel_type = match tunnel_config.mode {
            TunnelMode::Out => match tunnel_config.upstream.upstream_type {
                UpstreamType::Tcp => TunnelType::TcpOut(TcpTunnelOutInfo {
                    conn,
                    upstream_addr,
                }),

                UpstreamType::Udp => TunnelType::UdpOut(UdpTunnelOutInfo {
                    conn,
                    upstream_addr,
                }),
            },

            TunnelMode::In => match tunnel_config.upstream.upstream_type {
                UpstreamType::Tcp => {
                    let tcp_server = match TcpServer::bind_and_start(upstream_addr).await {
                        Ok(tcp_server) => tcp_server,
                        Err(e) => {
                            TunnelMessage::send_failure(
                                quic_send,
                                format!("tcp server failed to bind at: {upstream_addr}"),
                            )
                            .await?;
                            log_and_bail!("tcp_IN login rejected: {e}");
                        }
                    };

                    TunnelType::TcpIn(TcpTunnelInInfo { conn, tcp_server })
                }

                UpstreamType::Udp => {
                    let udp_server = match UdpServer::bind_and_start(upstream_addr).await {
                        Ok(udp_server) => udp_server,
                        Err(e) => {
                            TunnelMessage::send_failure(
                                quic_send,
                                format!("udp server failed to bind at: {upstream_addr}"),
                            )
                            .await?;
                            log_and_bail!("udp_IN login rejected: {e}");
                        }
                    };

                    TunnelType::UdpIn(UdpTunnelInInfo { conn, udp_server })
                }
            },
        };

        Ok(tunnel_type)
    }

    fn obtain_upstream_addr(
        tunnel_config: &TunnelConfig,
        default_upstream: &Option<SocketAddr>,
    ) -> Result<SocketAddr> {
        Ok(match tunnel_config.upstream.upstream_addr {
            None => {
                if tunnel_config.mode == TunnelMode::In {
                    log_and_bail!("explicit port is required to start inbound tunneling");
                }

                if default_upstream.is_none() {
                    log_and_bail!(
                        "explicit {} upstream address must be specified when logging in because there's no default upstream specified for the server",
                        tunnel_config.upstream.upstream_type
                    );
                }

                default_upstream.unwrap()
            }

            Some(addr) => {
                if tunnel_config.mode == TunnelMode::In
                    && !addr.ip().is_unspecified()
                    && !addr.ip().is_loopback()
                {
                    log_and_bail!(
                        "only loopback or unspecified IP is allowed for inbound tunelling: {addr}, or simply specify a port without the IP part"
                    );
                }

                addr
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
                    sess.sender.send(StreamMessage::Quit).await.ok();
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
            static ONCE: Once = Once::new();
            ONCE.call_once(|| {
                info!("will use auto-generated self-signed certificate.");
                warn!("============================= WARNING ==============================");
                warn!("No valid certificate path is provided, a self-signed certificate");
                warn!("for the domain \"localhost\" is generated.");
                warn!("============== Be cautious, this is for TEST only!!! ===============");
            });

            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
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
