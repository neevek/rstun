use crate::access_server::ChannelMessage;
use crate::{
    pem_util, AccessServer, ControlStream, ServerConfig, Tunnel, TunnelMessage, TunnelType,
};
use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use quinn::{congestion, Endpoint, TransportConfig};
use quinn_proto::{IdleTimeout, VarInt};
use rs_utilities::log_and_bail;
use rustls::{Certificate, PrivateKey};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::Duration;

#[derive(Debug)]
pub struct Server {
    config: ServerConfig,
    access_server_ports: Mutex<Vec<u16>>,
    endpoint: Option<Endpoint>,
}

impl Server {
    pub fn new(config: ServerConfig) -> Arc<Self> {
        Arc::new(Server {
            config,
            access_server_ports: Mutex::new(Vec::new()),
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
            Server::read_certs_and_key(config.cert_path.as_str(), config.key_path.as_str())
                .context("failed to read certificate or key")?;

        let crypto = rustls::ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

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

        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_cfg.transport = Arc::new(transport_cfg);
        Ok(server_cfg)
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
                            "start tunnel streaming in TunnelOut mode, {} ↔ {addr}",
                            client_conn.remote_address(),
                        );

                        this.process_out_connection(client_conn, addr)
                            .await
                            .map_err(|e| error!("process_out_connection failed: {e}"))
                            .ok();
                    }

                    TunnelType::In((client_conn, access_server, ctrl_stream)) => {
                        info!(
                            "start tunnel streaming in IN mode, {} -> {}",
                            access_server.addr(),
                            client_conn.remote_address(),
                        );

                        this.process_in_connection(client_conn, access_server, ctrl_stream)
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
                let access_server_addr = match login_info.access_server_addr {
                    Some(access_server_addr) => access_server_addr,
                    None => SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                };

                let is_local = match access_server_addr.ip() {
                    IpAddr::V4(ipv4) => {
                        ipv4.is_private() || ipv4.is_loopback() || ipv4.is_unspecified()
                    }
                    IpAddr::V6(ipv6) => {
                        ipv6.is_loopback() || ipv6.is_loopback() || ipv6.is_unspecified()
                    }
                };
                if !is_local {
                    log_and_bail!("only local IPs are allowed for upstream: {access_server_addr}");
                }

                let upstream_addr = if access_server_addr.port() == 0 {
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
                    if !upstreams.is_empty() && !upstreams.contains(&access_server_addr) {
                        log_and_bail!("upstream address not set: {access_server_addr}");
                    }
                    &access_server_addr
                };

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;
                tunnel_type = TunnelType::Out((client_conn, *upstream_addr));
                info!("sent response for OutLogin request: {remote_addr}");
            }

            TunnelMessage::ReqInLogin(login_info) => {
                info!("received InLogin request: {remote_addr}");

                Self::check_password(self.config.password.as_str(), login_info.password.as_str())?;
                let access_server_addr = match login_info.access_server_addr {
                    Some(access_server_addr) => access_server_addr,
                    None => SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                };
                if access_server_addr.port() == 0 {
                    log_and_bail!(
                        "explicit access_server_addr for TunnelIn mode tunelling is required: {access_server_addr:?}");
                }
                if !access_server_addr.ip().is_unspecified()
                    && !access_server_addr.ip().is_loopback()
                {
                    log_and_bail!(
                        "only loopback or unspecified IP is allowed for TunnelIn mode tunelling: {access_server_addr:?}");
                }
                let upstream_addr = access_server_addr;

                let mut guarded_access_server_ports = self.access_server_ports.lock().await;
                if guarded_access_server_ports.contains(&upstream_addr.port()) {
                    TunnelMessage::send(
                        &mut quic_send,
                        &TunnelMessage::RespFailure("remote access port is in use".to_string()),
                    )
                    .await?;
                    log_and_bail!("remote access port is in use: {}", upstream_addr.port());
                }

                let mut access_server = AccessServer::new(upstream_addr);
                if access_server.bind().await.is_err() {
                    TunnelMessage::send(
                        &mut quic_send,
                        &TunnelMessage::RespFailure("access server failed to bind".to_string()),
                    )
                    .await?;
                    log_and_bail!("access server failed to bind");
                }

                if access_server.start().await.is_err() {
                    TunnelMessage::send(
                        &mut quic_send,
                        &TunnelMessage::RespFailure("access server failed to start".to_string()),
                    )
                    .await?;
                    log_and_bail!("access server failed to start");
                }

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;
                tunnel_type = TunnelType::In((
                    client_conn,
                    access_server,
                    ControlStream {
                        quic_send,
                        quic_recv,
                    },
                ));

                guarded_access_server_ports.push(upstream_addr.port());

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
        mut access_server: AccessServer,
        mut ctrl_stream: ControlStream,
    ) -> Result<()> {
        let tcp_sender = access_server.clone_tcp_sender();
        tokio::spawn(async move {
            TunnelMessage::recv(&mut ctrl_stream.quic_recv).await.ok();
            // send None to signify exit
            tcp_sender.send(None).await.ok();
            Ok::<(), anyhow::Error>(())
        });

        access_server.set_drop_conn(false);
        let mut tcp_receiver = access_server.take_tcp_receiver();
        while let Some(Some(ChannelMessage::Request(tcp_stream))) = tcp_receiver.recv().await {
            match client_conn.open_bi().await {
                Ok(quic_stream) => Tunnel::new().start(false, tcp_stream, quic_stream),
                _ => {
                    log_and_bail!("failed to open bi_streams to client, quit");
                }
            }
        }

        let addr = access_server.addr();
        let mut guarded_access_server_ports = self.access_server_ports.lock().await;
        if let Some(index) = guarded_access_server_ports
            .iter()
            .position(|x| *x == addr.port())
        {
            guarded_access_server_ports.remove(index);
        }

        access_server.shutdown(tcp_receiver).await.ok();

        info!("access server quit: {addr}");

        Ok(())
    }

    fn read_certs_and_key(
        cert_path: &str,
        key_path: &str,
    ) -> Result<(Vec<Certificate>, PrivateKey)> {
        let (certs, key) = if cert_path.is_empty() {
            info!("will use auto-generated self-signed certificate.");
            warn!("============================= WARNING ==============================");
            warn!("No valid certificate path is provided, a self-signed certificate");
            warn!("for the domain \"localhost\" is generated.");
            warn!("============== Be cautious, this is for TEST only!!! ===============");
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let key = cert.serialize_private_key_der();
            let cert = cert.serialize_der()?;
            (vec![Certificate(cert)], PrivateKey(key))
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
