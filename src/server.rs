use crate::{AccessServer, ReadResult, ServerConfig, TunnelMessage, TunnelType};
use anyhow::{bail, Context, Result};
use byte_pool::BytePool;
use dashmap::DashMap;
use futures_util::{StreamExt, TryFutureExt};
use log::{debug, error, info, warn};
use quinn::{congestion, TransportConfig};
use quinn::{RecvStream, SendStream};
use quinn_proto::{IdleTimeout, VarInt};
use rustls::{Certificate, PrivateKey};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::Duration;

const IDLE_TIMEOUT: u64 = 30 * 1000;
static PERF_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    //rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
    //rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
];

#[derive(Debug)]
pub struct Server {
    config: ServerConfig,
    downstream_addrs: DashMap<String, SocketAddr>,
    access_servers: DashMap<String, AccessServer>,
    buffer_pool: BytePool<Vec<u8>>,
}

impl Server {
    pub fn new(config: ServerConfig) -> Arc<Self> {
        Arc::new(Server {
            config,
            downstream_addrs: DashMap::new(),
            access_servers: DashMap::new(),
            buffer_pool: BytePool::<Vec<u8>>::new(),
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
            .with_context(|| format!("invalid address: {}", config.addr))?;

        let (endpoint, mut incoming) = quinn::Endpoint::server(cfg, addr)?;

        info!("server is bound to: {}", endpoint.local_addr()?);

        for (name, str_addr) in &self.config.downstreams {
            if let Ok(addr) = str_addr.parse() {
                self.downstream_addrs.insert(name.clone(), addr);
            } else {
                warn!("failed to parse downstream address: {}", str_addr);
            }
        }

        while let Some(client_conn) = incoming.next().await {
            let this = self.clone();
            tokio::spawn(async move {
                if let Ok(tun_type) = this.authenticate_connection(client_conn).await {
                    match tun_type {
                        TunnelType::Out((client_conn, addr)) => {
                            info!(
                                "start tunnel streaming in OUT mode, {} -> {}",
                                client_conn.connection.remote_address(),
                                addr
                            );

                            this.handle_tunnel_out_connection(client_conn, addr)
                                .await
                                .map_err(|e| error!("handle_tunnel_out_connection failed: {}", e))
                                .ok();
                        }

                        TunnelType::In((client_conn, access_server)) => {
                            info!(
                                "start tunnel streaming in IN mode, {} -> {}",
                                access_server.addr(),
                                client_conn.connection.remote_address(),
                            );

                            this.handle_tunnel_in_connection(client_conn, access_server)
                                .await
                                .map_err(|e| error!("handle_tunnel_in_connection failed: {}", e))
                                .ok();
                        }
                    }
                }
            });
        }

        info!("quit!");

        Ok(())
    }

    async fn authenticate_connection(
        self: &Arc<Self>,
        connnecing: quinn::Connecting,
    ) -> Result<TunnelType> {
        let mut client_conn = connnecing.await?;

        let remote_addr = &client_conn.connection.remote_address();

        info!(
            "received connection, authenticating... addr:{ }",
            remote_addr
        );

        let mut stream = client_conn.bi_streams.next().await;
        if stream.is_none() {
            bail!("login request not received in time, addr: {}", remote_addr)
        }

        if let Ok((mut send, mut recv)) = stream.take().unwrap() {
            let mut login_info_len = [0_u8; 2];
            recv.read_exact(&mut login_info_len)
                .await
                .context("read login_info_len failed")?;

            let login_info_len = ((login_info_len[0] as usize) << 8) | (login_info_len[1] as usize);
            let mut login_info = vec![0; login_info_len];
            recv.read_exact(&mut login_info)
                .await
                .context("read login_info failed")?;

            let tun_msg = bincode::deserialize::<TunnelMessage>(&login_info)?;

            let tunnel_type;
            match tun_msg {
                TunnelMessage::OutLoginRequest(i) => {
                    Self::check_password(self.config.password.as_str(), i.password.as_str())?;
                    let downstream_addr = i.access_server_addr.parse().with_context(|| {
                        format!("invalid access server address: {}", i.access_server_addr)
                    })?;
                    send.write_all(b"ok").await?;
                    tunnel_type = TunnelType::Out((client_conn, downstream_addr));
                }

                TunnelMessage::InLoginRequest(i) => {
                    Self::check_password(self.config.password.as_str(), i.password.as_str())?;
                    if self.access_servers.contains_key(&i.access_server_addr) {
                        Self::send_msg_and_bail(&mut send, "remote access port is in use").await?;
                    }

                    let mut access_server = AccessServer::new(i.access_server_addr);
                    if access_server.bind().await.is_err() {
                        Self::send_msg_and_bail(&mut send, "access server failed to bind").await?;
                    }
                    if access_server.start().await.is_err() {
                        Self::send_msg_and_bail(&mut send, "access server failed to start").await?;
                    }
                    send.write_all(b"ok").await?;
                    tunnel_type = TunnelType::In((client_conn, access_server));
                }
            }

            info!("connection authenticated! addr: {}", remote_addr);

            return Ok(tunnel_type);
        }

        bail!("failed to authenticate connection({})", remote_addr)
    }

    async fn send_msg_and_bail(send: &mut quinn::SendStream, msg: &'static str) -> Result<()> {
        send.write_all(msg.as_bytes()).await?;
        error!("{}", msg);
        bail!(msg);
    }

    async fn handle_tunnel_out_connection(
        self: &Arc<Self>,
        mut client_conn: quinn::NewConnection,
        downstream_addr: SocketAddr,
    ) -> Result<()> {
        let remote_addr = &client_conn.connection.remote_address();

        while let Some(stream) = client_conn.bi_streams.next().await {
            match stream {
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
                Ok((send, recv)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        match TcpStream::connect(&downstream_addr).await {
                            Ok(peer_stream) => {
                                info!(
                                    "[Out] open stream for conn, {} -> {}",
                                    send.id().index(),
                                    downstream_addr,
                                );

                                this.handle_stream((send, recv), peer_stream)
                                    .map_err(|e| debug!("stream ended, err: {}", e))
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

    async fn handle_tunnel_in_connection(
        self: &Arc<Self>,
        client_conn: quinn::NewConnection,
        mut access_server: AccessServer,
    ) -> Result<()> {
        let client_conn = client_conn.connection;

        while let Some(access_conn) = access_server.tcp_receiver().recv().await {
            match client_conn.open_bi().await {
                Ok((send, recv)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        info!(
                            "[In] open stream for conn, {} -> {}",
                            send.id().index(),
                            access_conn.local_addr().unwrap()
                        );
                        this.handle_stream((send, recv), access_conn).await
                    });
                }

                Err(e) => {
                    error!("failed to open_bi on client connection: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_stream(
        self: &Arc<Self>,
        (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
        peer_stream: TcpStream,
    ) -> Result<()> {
        let (mut down_read, mut down_write) = peer_stream.into_split();

        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let result = this
                    .upstream_to_downstream(&mut recv, &mut down_write)
                    .await;
                if let Ok(ReadResult::EOF) | Err(_) = result {
                    break;
                }
            }
        });

        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let result = this.downstream_to_upstream(&mut down_read, &mut send).await;
                if let Ok(ReadResult::EOF) | Err(_) = result {
                    break;
                }
            }
        });

        Ok(())
    }

    async fn downstream_to_upstream(
        self: &Arc<Self>,
        down_read: &mut OwnedReadHalf,
        up_send: &mut SendStream,
    ) -> Result<ReadResult> {
        let mut buffer = self.buffer_pool.alloc(8192);
        let len_read = down_read.read(&mut buffer[..]).await?;

        if len_read > 0 {
            up_send.write_all(&buffer[..len_read]).await?;
            Ok(ReadResult::Succeeded)
        } else {
            up_send.finish().await?;
            Ok(ReadResult::EOF)
        }
    }

    async fn upstream_to_downstream(
        self: &Arc<Self>,
        up_recv: &mut RecvStream,
        down_write: &mut OwnedWriteHalf,
    ) -> Result<ReadResult> {
        let mut buffer = self.buffer_pool.alloc(8192);
        let result = up_recv.read(&mut buffer[..]).await?;
        if let Some(len_read) = result {
            down_write.write_all(&buffer[..len_read]).await?;
            Ok(ReadResult::Succeeded)
        } else {
            Ok(ReadResult::EOF)
        }
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
