use crate::tcp::tcp_server::ChannelMessage;
use crate::{
    pem_util, ControlStream, ServerConfig, TcpServer, Tunnel, TunnelMessage, TunnelType,
    SUPPORTED_CIPHER_SUITES,
};
use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{congestion, Endpoint, TransportConfig};
use quinn_proto::{IdleTimeout, VarInt};
use rs_utilities::log_and_bail;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::Duration;

#[derive(Debug)]
pub struct Server {
    config: ServerConfig,
    tcp_server_ports: Mutex<Vec<u16>>,
    endpoint: Option<Endpoint>,
}

impl Server {
    pub fn new(config: ServerConfig) -> Arc<Self> {
        Arc::new(Server {
            config,
            tcp_server_ports: Mutex::new(Vec::new()),
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
        transport_cfg.receive_window(quinn::VarInt::from_u32(1024 * 1024 * 8));
        transport_cfg.send_window(1024 * 1024 * 8);
        transport_cfg.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
        if config.max_idle_timeout_ms > 0 {
            let timeout = IdleTimeout::from(VarInt::from_u32(config.max_idle_timeout_ms as u32));
            transport_cfg.max_idle_timeout(Some(timeout));
            transport_cfg
                .keep_alive_interval(Some(Duration::from_millis(config.max_idle_timeout_ms / 2)));
        }
        transport_cfg.max_concurrent_bidi_streams(VarInt::from_u32(1024));

        let quic_server_cfg = Arc::new(QuicServerConfig::try_from(tls_server_cfg)?);
        let mut quinn_server_cfg = quinn::ServerConfig::with_crypto(quic_server_cfg);
        quinn_server_cfg.transport = Arc::new(transport_cfg);
        Ok(quinn_server_cfg)
    }

    pub async fn serve(self: &Arc<Self>) -> Result<()> {
        let endpoint = self
            .endpoint
            .as_ref()
            .context("make sure bind() call succeeded!")?;

        while let Some(client_conn) = endpoint.accept().await {
            let mut this = self.clone();
            tokio::spawn(async move {
                let client_conn = client_conn.await?;
                let tun_type = this.authenticate_connection(client_conn).await?;

                match tun_type {
                    TunnelType::Out((client_conn, addr)) => {
                        info!(
                            "start tunnel streaming in TunnelOut mode, {} ↔  {addr}",
                            client_conn.remote_address(),
                        );

                        this.process_out_connection(client_conn, addr)
                            .await
                            .map_err(|e| error!("process_out_connection failed: {e}"))
                            .ok();
                    }

                    TunnelType::In((client_conn, tcp_server, ctrl_stream)) => {
                        info!(
                            "start tunnel streaming in IN mode, {} -> {}",
                            tcp_server.addr(),
                            client_conn.remote_address(),
                        );

                        this.process_in_connection(client_conn, tcp_server, ctrl_stream)
                            .await
                            .map_err(|e| error!("process_in_connection failed: {e}"))
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
        self: &mut Arc<Self>,
        client_conn: quinn::Connection,
    ) -> Result<TunnelType> {
        let remote_addr = &client_conn.remote_address();

        info!("received connection, authenticating... addr:{remote_addr}");
        let (mut quic_send, mut quic_recv) = client_conn
            .accept_bi()
            .await
            .context(format!("login request not received in time: {remote_addr}"))?;

        info!("received bi_stream request: {remote_addr}");
        let tunnel_type;
        match TunnelMessage::recv(&mut quic_recv).await? {
            TunnelMessage::ReqOutLogin(login_info) => {
                info!("received OutLogin request: {remote_addr}");

                Self::check_password(self.config.password.as_str(), login_info.password.as_str())?;

                let upstreams = &self.config.upstreams;
                let tcp_server_addr = match login_info.tcp_server_addr {
                    Some(tcp_server_addr) => tcp_server_addr,
                    None => SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                };

                let is_local = match tcp_server_addr.ip() {
                    IpAddr::V4(ipv4) => {
                        ipv4.is_private() || ipv4.is_loopback() || ipv4.is_unspecified()
                    }
                    IpAddr::V6(ipv6) => {
                        ipv6.is_loopback() || ipv6.is_loopback() || ipv6.is_unspecified()
                    }
                };
                if !is_local {
                    log_and_bail!("only local IPs are allowed for upstream: {tcp_server_addr}");
                }

                let upstream_addr = if tcp_server_addr.port() == 0 {
                    if upstreams.is_empty() {
                        log_and_bail!("explicit upstream address must be specified because there's no default set for the server");
                    }
                    let addr = upstreams.first().unwrap();
                    info!(
                        "will bind incoming TunnelIn request({}) to default address({addr})",
                        client_conn.remote_address()
                    );
                    addr
                } else {
                    if !upstreams.is_empty() && !upstreams.contains(&tcp_server_addr) {
                        log_and_bail!("upstream address not set: {tcp_server_addr}");
                    }
                    &tcp_server_addr
                };

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;
                tunnel_type = TunnelType::Out((client_conn, *upstream_addr));
                info!("sent response for OutLogin request: {remote_addr}");
            }

            TunnelMessage::ReqInLogin(login_info) => {
                info!("received InLogin request: {remote_addr}");

                Self::check_password(self.config.password.as_str(), login_info.password.as_str())?;
                let tcp_server_addr = match login_info.tcp_server_addr {
                    Some(tcp_server_addr) => tcp_server_addr,
                    None => SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                };
                if tcp_server_addr.port() == 0 {
                    log_and_bail!(
                        "explicit tcp_server_addr for TunnelIn mode tunelling is required: {tcp_server_addr:?}");
                }
                if !tcp_server_addr.ip().is_unspecified() && !tcp_server_addr.ip().is_loopback() {
                    log_and_bail!(
                        "only loopback or unspecified IP is allowed for TunnelIn mode tunelling: {tcp_server_addr:?}");
                }
                let upstream_addr = tcp_server_addr;

                let mut guarded_tcp_server_ports = self.tcp_server_ports.lock().await;
                if guarded_tcp_server_ports.contains(&upstream_addr.port()) {
                    TunnelMessage::send(
                        &mut quic_send,
                        &TunnelMessage::RespFailure("remote access port is in use".to_string()),
                    )
                    .await?;
                    log_and_bail!("remote access port is in use: {}", upstream_addr.port());
                }

                let tcp_server = match TcpServer::bind_and_start(upstream_addr).await {
                    Ok(tcp_server) => tcp_server,
                    Err(e) => {
                        TunnelMessage::send(
                            &mut quic_send,
                            &TunnelMessage::RespFailure("access server failed to bind".to_string()),
                        )
                        .await?;
                        log_and_bail!("access server failed to bind: {e}");
                    }
                };

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;
                tunnel_type = TunnelType::In((
                    client_conn,
                    tcp_server,
                    ControlStream {
                        quic_send,
                        quic_recv,
                    },
                ));

                guarded_tcp_server_ports.push(upstream_addr.port());

                info!("sent response for InLogin request: {remote_addr}");
            }

            _ => {
                log_and_bail!("received unepxected message");
            }
        }

        info!("connection authenticated! addr: {remote_addr}");

        Ok(tunnel_type)
    }

    async fn process_out_connection(
        self: &Arc<Self>,
        client_conn: quinn::Connection,
        upstream_addr: SocketAddr,
    ) -> Result<()> {
        let remote_addr = &client_conn.remote_address();

        loop {
            match client_conn.accept_bi().await {
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

    async fn process_in_connection(
        self: &Arc<Self>,
        client_conn: quinn::Connection,
        mut tcp_server: TcpServer,
        mut ctrl_stream: ControlStream,
    ) -> Result<()> {
        let tcp_sender = tcp_server.clone_tcp_sender();
        tokio::spawn(async move {
            TunnelMessage::recv(&mut ctrl_stream.quic_recv).await.ok();
            // send None to the previous session to signify exit, so the current
            // session can start immediately, see below
            tcp_sender.send(None).await.ok();
            Ok::<(), anyhow::Error>(())
        });

        tcp_server.set_active(true);
        while let Some(ChannelMessage::Request(tcp_stream)) = tcp_server.recv().await {
            match client_conn.open_bi().await {
                Ok(quic_stream) => Tunnel::new().start(false, tcp_stream, quic_stream),
                _ => {
                    log_and_bail!("failed to open bi_streams to client, quit");
                }
            }
        }

        let addr = tcp_server.addr();
        let mut guarded_tcp_server_ports = self.tcp_server_ports.lock().await;
        if let Some(index) = guarded_tcp_server_ports
            .iter()
            .position(|x| *x == addr.port())
        {
            guarded_tcp_server_ports.remove(index);
        }

        tcp_server.shutdown().await.ok();

        info!("access server quit: {addr}");

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
            (vec![CertificateDer::from(cert)], PrivateKeyDer::Pkcs8(key))
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
