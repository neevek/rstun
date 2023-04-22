use crate::{AccessServer, ControlStream, ServerConfig, Tunnel, TunnelMessage, TunnelType};
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

    pub async fn bind(mut self: &mut Arc<Self>) -> Result<SocketAddr> {
        let config = &self.config;
        let (cert, key) =
            Server::read_cert_and_key(config.cert_path.as_str(), config.key_path.as_str())
                .context("failed to read certificate or key")?;

        let crypto = rustls::ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;

        let mut transport_cfg = TransportConfig::default();
        transport_cfg.receive_window(quinn::VarInt::from_u32(1024 * 1024)); //.unwrap();
        transport_cfg.send_window(1024 * 1024);
        transport_cfg.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
        if config.max_idle_timeout_ms > 0 {
            let timeout = IdleTimeout::from(VarInt::from_u32(config.max_idle_timeout_ms as u32));
            transport_cfg.max_idle_timeout(Some(timeout));
            transport_cfg
                .keep_alive_interval(Some(Duration::from_millis(config.max_idle_timeout_ms / 2)));
        }
        transport_cfg.max_concurrent_bidi_streams(VarInt::from_u32(1024));

        let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        cfg.transport = Arc::new(transport_cfg);

        let addr: SocketAddr = config
            .addr
            .parse()
            .context(format!("invalid address: {}", config.addr))?;

        let endpoint = quinn::Endpoint::server(cfg, addr).map_err(|e| {
            error!(
                "failed to bind tunnel server on address: {}, error: {}",
                addr, e
            );
            e
        })?;

        info!(
            "tunnel server is bound on address: {}, idle_timeout: {}",
            endpoint.local_addr()?,
            config.max_idle_timeout_ms
        );

        Arc::get_mut(&mut self).unwrap().endpoint = Some(endpoint);

        Ok(addr)
    }

    pub async fn serve(self: &Arc<Self>) -> Result<()> {
        let endpoint = self
            .endpoint
            .as_ref()
            .context("make sure start call succeeded!")?;

        while let Some(client_conn) = endpoint.accept().await {
            let mut this = self.clone();
            tokio::spawn(async move {
                let client_conn = client_conn.await?;
                let tun_type = this.authenticate_connection(client_conn).await?;

                match tun_type {
                    TunnelType::Out((client_conn, addr)) => {
                        info!(
                            "start tunnel streaming in OUT mode, {} -> {}",
                            client_conn.remote_address(),
                            addr
                        );

                        this.process_out_connection(client_conn, addr)
                            .await
                            .map_err(|e| error!("process_out_connection failed: {}", e))
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
                            .map_err(|e| error!("process_in_connection failed: {}", e))
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

        info!(
            "received connection, authenticating... addr:{}",
            remote_addr
        );

        let (mut quic_send, mut quic_recv) = client_conn.accept_bi().await.context(format!(
            "login request not received in time, addr: {}",
            remote_addr
        ))?;

        info!("received bi_stream request, addr: {}", remote_addr);
        let tunnel_type;
        match TunnelMessage::recv(&mut quic_recv).await? {
            TunnelMessage::ReqOutLogin(login_info) => {
                info!("received OutLogin request, addr: {}", remote_addr);

                Self::check_password(self.config.password.as_str(), login_info.password.as_str())?;

                let downstreams = &self.config.downstreams;
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
                    log_and_bail!(
                        "only local IPs are allowed for downstream, addr: {}",
                        access_server_addr
                    );
                }

                let downstream_addr = if access_server_addr.port() == 0 {
                    if downstreams.is_empty() {
                        log_and_bail!("explicit downstream address must be specified because there's no default set for the server");
                    }
                    let addr = downstreams.first().unwrap();
                    info!(
                        "will bind incoming TunnelIn request({}) to default address({})",
                        client_conn.remote_address(),
                        addr
                    );
                    addr
                } else {
                    if !downstreams.is_empty() && !downstreams.contains(&access_server_addr) {
                        log_and_bail!("downstream address not set: {}", access_server_addr);
                    }
                    &access_server_addr
                };

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;
                tunnel_type = TunnelType::Out((client_conn, *downstream_addr));
                info!("sent response for OutLogin request, addr: {}", remote_addr);
            }

            TunnelMessage::ReqInLogin(login_info) => {
                info!("received InLogin request, addr: {}", remote_addr);

                Self::check_password(self.config.password.as_str(), login_info.password.as_str())?;
                let access_server_addr = match login_info.access_server_addr {
                    Some(access_server_addr) => access_server_addr,
                    None => SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                };
                if access_server_addr.port() == 0 {
                    log_and_bail!(
                        "explicit access_server_addr for TunnelIn mode tunelling is required, addr: {:?}", access_server_addr
                    );
                }
                if !access_server_addr.ip().is_unspecified()
                    && !access_server_addr.ip().is_loopback()
                {
                    log_and_bail!(
                        "only loopback or unspecified IP is allowed for TunnelIn mode tunelling, addr: {:?}", access_server_addr
                    );
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

                info!("sent response for InLogin request, addr: {}", remote_addr);
            }

            _ => {
                log_and_bail!("received unepxected message");
            }
        }

        info!("connection authenticated! addr: {}", remote_addr);

        Ok(tunnel_type)
    }

    async fn process_out_connection(
        self: &Arc<Self>,
        client_conn: quinn::Connection,
        downstream_addr: SocketAddr,
    ) -> Result<()> {
        let remote_addr = &client_conn.remote_address();

        loop {
            match client_conn.accept_bi().await {
                Err(quinn::ConnectionError::TimedOut { .. }) => {
                    info!("connection timeout, addr: {}", remote_addr);
                    return Ok(());
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!("connection closed, addr: {}", remote_addr);
                    return Ok(());
                }
                Err(e) => {
                    log_and_bail!(
                        "failed to open bi_streams, addr: {}, err: {}",
                        remote_addr,
                        e
                    );
                }
                Ok(quic_stream) => tokio::spawn(async move {
                    match TcpStream::connect(&downstream_addr).await {
                        Ok(tcp_stream) => {
                            debug!(
                                "[Out] open stream for conn, {} -> {}",
                                quic_stream.0.id().index(),
                                downstream_addr,
                            );

                            let tcp_stream = tcp_stream.into_split();
                            Tunnel::new().start(tcp_stream, quic_stream).await;
                        }

                        Err(e) => {
                            error!("failed to connect to {}, err: {}", downstream_addr, e);
                        }
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
            match TunnelMessage::recv(&mut ctrl_stream.quic_recv).await {
                _ => {
                    // send None to signify exit
                    tcp_sender.send(None).await.ok();
                    Ok::<(), anyhow::Error>(())
                }
            }
        });

        let mut tcp_receiver = access_server.take_tcp_receiver();
        while let Some(Some(tcp_stream)) = tcp_receiver.recv().await {
            match client_conn.open_bi().await {
                Ok(quic_stream) => {
                    let tcp_stream = tcp_stream.into_split();
                    Tunnel::new().start(tcp_stream, quic_stream).await;
                }
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

        info!("will quit access server: {}", addr);

        Ok(())
    }

    fn read_cert_and_key(cert_path: &str, key_path: &str) -> Result<(Certificate, PrivateKey)> {
        let (cert, key) = if cert_path.is_empty() {
            info!("will use auto-generated self-signed certificate.");
            warn!("============================= WARNING ==============================");
            warn!("No valid certificate path is provided, a self-signed certificate");
            warn!("for the domain \"localhost\" is generated.");
            warn!("============== Be cautious, this is for TEST only!!! ===============");
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let key = cert.serialize_private_key_der();
            let cert = cert.serialize_der()?;
            (cert, key)
        } else {
            let cert = std::fs::read(cert_path)
                .context(format!("failed to read cert file: {}", cert_path))?;
            let key = std::fs::read(key_path)
                .context(format!("failed to read key file: {}", key_path))?;
            (cert, key)
        };

        Ok((Certificate(cert), PrivateKey(key)))
    }

    fn check_password(password1: &str, password2: &str) -> Result<()> {
        if password1 != password2 {
            log_and_bail!("passwords don't match!");
        }
        Ok(())
    }
}
