use crate::{
    AccessServer, BufferPool, ClientConfig, ControlStream, Tunnel, TunnelMessage, TUNNEL_MODE_OUT,
};
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use log::{debug, error, info};
use quinn::{congestion, TransportConfig};
use quinn::{RecvStream, SendStream};
use quinn_proto::{IdleTimeout, VarInt};
use rs_utilities::dns;
use rustls::client::{ServerCertVerified, ServerName};
use rustls::Certificate;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc::Receiver;
use tokio::time::Duration;

const LOCAL_ADDR_STR: &str = "0.0.0.0:0";
const DEFAULT_SERVER_PORT: u16 = 3515;

pub struct Client {
    pub config: ClientConfig,
    remote_conn: Option<quinn::NewConnection>,
    ctrl_stream: Option<ControlStream>,
    buffer_pool: BufferPool,
    is_terminated: Arc<Mutex<bool>>,
    is_running: Mutex<bool>,
    scheduled_start: bool,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Client {
            config,
            remote_conn: None,
            ctrl_stream: None,
            buffer_pool: crate::new_buffer_pool(),
            is_terminated: Arc::new(Mutex::new(false)),
            is_running: Mutex::new(false),
            scheduled_start: false,
        }
    }

    pub fn start_tunnelling(&mut self) {
        info!(
            "connecting, idle_timeout:{}, retry_timeout:{}, threads:{}",
            self.config.max_idle_timeout_ms, self.config.wait_before_retry_ms, self.config.threads
        );

        *self.is_running.lock().unwrap() = true;

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(self.config.threads)
            .build()
            .unwrap()
            .block_on(async {
                self.connect_and_serve()
                    .await
                    .unwrap_or_else(|e| error!("connect failed: {}", e));
            });

        *self.is_running.lock().unwrap() = false;
    }

    async fn connect_and_serve(&mut self) -> Result<()> {
        // create a local access server for 'out' tunnel
        let mut access_server = None;
        if self.config.mode == TUNNEL_MODE_OUT {
            let mut tmp_access_server =
                AccessServer::new(self.config.local_access_server_addr.unwrap());
            tmp_access_server.bind().await?;
            tmp_access_server.start().await?;
            access_server = Some(tmp_access_server);
        }

        let mut connect_retry_count = 0;
        let connect_max_retry = self.config.connect_max_retry;
        let wait_before_retry_ms = self.config.wait_before_retry_ms;
        loop {
            match self.connect().await {
                Ok(_) => {
                    connect_retry_count = 0;
                    if self.config.mode == TUNNEL_MODE_OUT {
                        self.serve_outgoing(access_server.as_mut().unwrap().tcp_receiver_ref())
                            .await
                            .ok();
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
        }
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!("using cert: {}", self.config.cert_path);

        let cert: Certificate = Client::read_cert(self.config.cert_path.as_str())?;
        let crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(CertVerifier { cert: cert.clone() }))
            .with_no_client_auth();

        let mut transport_cfg = TransportConfig::default();
        transport_cfg.receive_window(quinn::VarInt::from_u32(1024 * 1024)); //.unwrap();
        transport_cfg.send_window(1024 * 1024);
        transport_cfg.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
        transport_cfg.max_concurrent_bidi_streams(VarInt::from_u32(1024));

        let timeout = IdleTimeout::from(VarInt::from_u32(self.config.max_idle_timeout_ms as u32));
        transport_cfg.max_idle_timeout(Some(timeout));
        transport_cfg.keep_alive_interval(Some(Duration::from_millis(
            self.config.keep_alive_interval_ms,
        )));

        let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
        cfg.transport = Arc::new(transport_cfg);

        let remote_addr = Self::parse_server_addr(&self.config.server_addr).await?;
        let local_addr: SocketAddr = LOCAL_ADDR_STR.parse().unwrap();

        let mut endpoint = quinn::Endpoint::client(local_addr)?;
        endpoint.set_default_client_config(cfg);
        info!(
            "connecting to {}, local_addr: {}",
            remote_addr,
            endpoint.local_addr().unwrap()
        );

        let connection = endpoint.connect(remote_addr, "localhost")?.await?;

        info!("connected");

        let (mut quic_send, mut quic_recv) = connection
            .connection
            .open_bi()
            .await
            .map_err(|e| error!("open bidirectional connection failed: {}", e))
            .unwrap();

        info!("logging in... server: {}", remote_addr);

        Self::login(&self.config, &mut quic_send, &mut quic_recv).await?;

        info!("logged in! server: {}", remote_addr);

        self.remote_conn = Some(connection);
        self.ctrl_stream = Some(ControlStream {
            quic_send,
            quic_recv,
        });
        Ok(())
    }

    async fn serve_outgoing(
        &mut self,
        local_conn_receiver: &mut Receiver<Option<TcpStream>>,
    ) -> Result<()> {
        info!("start serving...");

        let remote_conn = self.remote_conn.as_ref().unwrap();

        // accept local connections and build a tunnel to remote
        while let Some(tcp_stream) = local_conn_receiver.recv().await {
            let tcp_stream = unwrap_or_continue!(tcp_stream);
            match remote_conn.connection.open_bi().await {
                Ok(quic_stream) => {
                    debug!(
                        "[OUT] open stream for conn, {} -> {}",
                        quic_stream.0.id().index(),
                        remote_conn.connection.remote_address(),
                    );

                    let tcp_stream = tcp_stream.into_split();
                    Tunnel::new(self.buffer_pool.clone())
                        .start(tcp_stream, quic_stream)
                        .await
                        .ok();
                }
                Err(e) => {
                    error!("failed to open_bi on remote connection: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    async fn serve_incoming(&mut self) -> Result<()> {
        info!("start serving...");

        self.observe_terminate_signals().await?;

        let remote_conn = self.remote_conn.as_mut().unwrap();
        while let Some(quic_stream) = remote_conn.bi_streams.next().await {
            let quic_stream = quic_stream?;
            match TcpStream::connect(self.config.local_access_server_addr.unwrap()).await {
                Ok(tcp_stream) => {
                    let tcp_stream = tcp_stream.into_split();
                    Tunnel::new(self.buffer_pool.clone())
                        .start(tcp_stream, quic_stream)
                        .await
                        .ok();
                }
                _ => {
                    error!("failed to connect to access server");
                }
            }
        }
        Ok(())
    }

    async fn observe_terminate_signals(&mut self) -> Result<()> {
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

        Ok(())
    }

    fn should_retry(&mut self) -> bool {
        return !*self.is_terminated.lock().unwrap();
    }

    pub fn is_running(&self) -> bool {
        *self.is_running.lock().unwrap()
    }

    pub fn set_scheduled_start(&mut self) {
        self.scheduled_start = true;
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
        if resp.as_resp_success().is_none() {
            bail_with_log!("failed to login");
        }
        TunnelMessage::handle_message(&resp)?;
        debug!("finished login request!");
        Ok(())
    }

    fn read_cert(cert_path: &str) -> Result<rustls::Certificate> {
        let cert = std::fs::read(cert_path).context("failed to read cert file")?;
        let cert = rustls::Certificate(cert.into());

        Ok(cert)
    }

    async fn parse_server_addr(addr: &str) -> Result<SocketAddr> {
        let sock_addr: Result<SocketAddr> = addr.parse().context("error will be ignored");

        if sock_addr.is_ok() {
            return sock_addr;
        }

        let mut domain = addr;
        let mut port = DEFAULT_SERVER_PORT;
        let pos = addr.rfind(":");
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
        let resolver = if dot_server != "" {
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
}

struct CertVerifier {
    cert: Certificate,
}

impl rustls::client::ServerCertVerifier for CertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.0 != self.cert.0 {
            return Err(rustls::Error::General(format!(
                "server certificates doesn't match ours"
            )));
        }

        info!("certificate verified!");
        Ok(ServerCertVerified::assertion())
    }
}
