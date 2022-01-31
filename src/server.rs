use crate::ControlStream;
use crate::Tunnel;
use crate::TunnelMessage;
use crate::{AccessServer, ServerConfig, TunnelType};
use anyhow::{bail, Context, Result};
use byte_pool::BytePool;
use futures_util::StreamExt;
use log::{debug, error, info, warn};
use quinn::{congestion, TransportConfig};
use quinn_proto::{IdleTimeout, VarInt};
use rustls::{Certificate, PrivateKey};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::Duration;

type BufferPool = Arc<BytePool<Vec<u8>>>;
const IDLE_TIMEOUT: u64 = 30 * 1000;
static PERF_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    //rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
    //rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
];

#[derive(Debug)]
pub struct Server {
    config: ServerConfig,
    access_server_ports: Mutex<Vec<u16>>,
    buffer_pool: BufferPool,
}

impl Server {
    pub fn new(config: ServerConfig) -> Arc<Self> {
        Arc::new(Server {
            config,
            access_server_ports: Mutex::new(Vec::new()),
            buffer_pool: Arc::new(BytePool::<Vec<u8>>::new()),
        })
    }

    pub async fn start(self: &Arc<Self>) -> Result<()> {
        let config = &self.config;
        let (cert, key) =
            match Server::read_cert_and_key(config.cert_path.as_str(), config.key_path.as_str()) {
                Ok(v) => v,
                Err(_) => {
                    info!("generate temporary cert and key");
                    let cert =
                        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                    let key = cert.serialize_private_key_der();
                    let cert = cert.serialize_der().unwrap();
                    let cert = Certificate(cert.into());
                    let key = PrivateKey(key.into());
                    (cert, key)
                }
            };

        let crypto = rustls::ServerConfig::builder()
            .with_cipher_suites(PERF_CIPHER_SUITES)
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();

        let mut transport_cfg = TransportConfig::default();
        transport_cfg.receive_window(quinn::VarInt::from_u32(1024 * 1024)); //.unwrap();
        transport_cfg.send_window(1024 * 1024);
        transport_cfg.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
        let timeout = IdleTimeout::from(VarInt::from_u32(IDLE_TIMEOUT as u32));
        transport_cfg.max_idle_timeout(Some(timeout));
        transport_cfg.keep_alive_interval(Some(Duration::from_millis(IDLE_TIMEOUT / 2)));
        transport_cfg.max_concurrent_bidi_streams(VarInt::from_u32(1024));

        let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        cfg.transport = Arc::new(transport_cfg);

        let addr: SocketAddr = config
            .addr
            .parse()
            .context(format!("invalid address: {}", config.addr))?;

        let (endpoint, mut incoming) = quinn::Endpoint::server(cfg, addr)?;

        info!("server is bound to: {}", endpoint.local_addr()?);

        while let Some(client_conn) = incoming.next().await {
            let mut this = self.clone();
            tokio::spawn(async move {
                let tun_type = this.authenticate_connection(client_conn).await?;

                match tun_type {
                    TunnelType::Out((client_conn, addr)) => {
                        info!(
                            "start tunnel streaming in OUT mode, {} -> {}",
                            client_conn.connection.remote_address(),
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
                            client_conn.connection.remote_address(),
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
        connnecing: quinn::Connecting,
    ) -> Result<TunnelType> {
        let mut client_conn = connnecing.await?;

        let remote_addr = &client_conn.connection.remote_address();

        info!(
            "received connection, authenticating... addr:{}",
            remote_addr
        );

        let (mut quic_send, mut quic_recv) = client_conn.bi_streams.next().await.context(
            format!("login request not received in time, addr: {}", remote_addr),
        )??;

        let tunnel_type;
        match TunnelMessage::recv(&mut quic_recv).await? {
            TunnelMessage::ReqOutLogin(login_info) => {
                Self::check_password(self.config.password.as_str(), login_info.password.as_str())?;
                let downstream_addr = login_info.access_server_addr.parse().context(format!(
                    "invalid access server address: {}",
                    login_info.access_server_addr
                ))?;

                if !self.config.downstreams.contains(&downstream_addr) {
                    bail!(format!("invalid addr: {}", downstream_addr));
                }

                TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;
                tunnel_type = TunnelType::Out((client_conn, downstream_addr));
            }

            TunnelMessage::ReqInLogin(login_info) => {
                Self::check_password(self.config.password.as_str(), login_info.password.as_str())?;
                let upstream_addr: SocketAddr = login_info.access_server_addr.parse().context(
                    format!("invalid address: {}", login_info.access_server_addr),
                )?;

                let mut guarded_access_server_ports = self.access_server_ports.lock().await;
                if guarded_access_server_ports.contains(&upstream_addr.port()) {
                    TunnelMessage::send(
                        &mut quic_send,
                        &TunnelMessage::RespFailure("remote access port is in use".to_string()),
                    )
                    .await?;
                    error!("remote access port is in use: {}", upstream_addr.port());
                    bail!("remote access port is in use: {}", upstream_addr.port());
                }

                let mut access_server = AccessServer::new(upstream_addr);
                if access_server.bind().await.is_err() {
                    TunnelMessage::send(
                        &mut quic_send,
                        &TunnelMessage::RespFailure("access server failed to bind".to_string()),
                    )
                    .await?;
                    bail!("access server failed to bind");
                }

                if access_server.start().await.is_err() {
                    TunnelMessage::send(
                        &mut quic_send,
                        &TunnelMessage::RespFailure("access server failed to start".to_string()),
                    )
                    .await?;
                    bail!("access server failed to start");
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
            }

            _ => {
                bail!("received unepxected message");
            }
        }

        info!("connection authenticated! addr: {}", remote_addr);

        return Ok(tunnel_type);
    }

    async fn process_out_connection(
        self: &Arc<Self>,
        mut client_conn: quinn::NewConnection,
        downstream_addr: SocketAddr,
    ) -> Result<()> {
        let remote_addr = &client_conn.connection.remote_address();

        while let Some(quic_stream) = client_conn.bi_streams.next().await {
            match quic_stream {
                Err(quinn::ConnectionError::TimedOut { .. }) => {
                    info!("connection timeout, addr: {}", remote_addr);
                    return Ok(());
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!("connection closed, addr: {}", remote_addr);
                    return Ok(());
                }
                Err(e) => {
                    bail!(
                        "failed to open bi_streams, addr: {}, err: {}",
                        remote_addr,
                        e
                    );
                }
                Ok(quic_stream) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        match TcpStream::connect(&downstream_addr).await {
                            Ok(tcp_stream) => {
                                debug!(
                                    "[Out] open stream for conn, {} -> {}",
                                    quic_stream.0.id().index(),
                                    downstream_addr,
                                );

                                let tcp_stream = tcp_stream.into_split();
                                Tunnel::new(this.buffer_pool.clone())
                                    .start(tcp_stream, quic_stream)
                                    .await
                                    .ok();
                            }

                            Err(e) => {
                                error!("failed to connect to {}, err: {}", downstream_addr, e);
                            }
                        }
                    })
                }
            };
        }

        Ok(())
    }

    async fn process_in_connection(
        self: &Arc<Self>,
        client_conn: quinn::NewConnection,
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
            match client_conn.connection.open_bi().await {
                Ok(quic_stream) => {
                    let tcp_stream = tcp_stream.into_split();
                    Tunnel::new(self.buffer_pool.clone())
                        .start(tcp_stream, quic_stream)
                        .await
                        .ok();
                }
                _ => {
                    error!("failed to open bi_streams to client");
                    bail!("quit");
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
        let cert = std::fs::read(cert_path).context("failed to read cert file")?;
        let key = std::fs::read(key_path).context("failed to read key file")?;
        let cert = Certificate(cert.into());
        let key = PrivateKey(key.into());

        Ok((cert, key))
    }

    fn check_password(password1: &str, password2: &str) -> Result<()> {
        if password1 != password2 {
            warn!("passwords don't match!");
            bail!("passwords don't match!");
        }
        Ok(())
    }
}
