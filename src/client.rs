use crate::{BufferPool, ClientConfig, ControlStream, Tunnel, TunnelMessage};
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
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Client {
            config,
            remote_conn: None,
            ctrl_stream: None,
            buffer_pool: crate::new_buffer_pool(),
            is_terminated: Arc::new(Mutex::new(false)),
        }
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

    pub async fn serve_outgoing(
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

    pub async fn serve_incoming(&mut self) -> Result<()> {
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

    pub async fn observe_terminate_signals(&mut self) -> Result<()> {
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

    pub fn should_retry(&mut self) -> bool {
        return !*self.is_terminated.lock().unwrap();
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

        if let Ok(ip) =
            Self::lookup_server_ip(domain, rs_utilities::dns::DoTProvider::AliDNS, vec![]).await
        {
            return Ok(SocketAddr::new(ip, port));
        }

        if let Ok(ip) =
            Self::lookup_server_ip(domain, rs_utilities::dns::DoTProvider::DNSPod, vec![]).await
        {
            return Ok(SocketAddr::new(ip, port));
        }

        if let Ok(ip) = Self::lookup_server_ip(
            domain,
            rs_utilities::dns::DoTProvider::NotSpecified,
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

        if let Ok(ip) =
            Self::lookup_server_ip(domain, rs_utilities::dns::DoTProvider::NotSpecified, vec![])
                .await
        {
            return Ok(SocketAddr::new(ip, port));
        }

        bail!("failed to resolve domain: {}", domain);
    }

    async fn lookup_server_ip(
        domain: &str,
        dot_server: dns::DoTProvider,
        name_servers: Vec<String>,
    ) -> Result<IpAddr> {
        let resolver = if dot_server != dns::DoTProvider::NotSpecified {
            dns::tokio_resolver(dot_server, vec![])
        } else if !name_servers.is_empty() {
            dns::tokio_resolver(dns::DoTProvider::NotSpecified, name_servers)
        } else {
            rs_utilities::dns::tokio_resolver(rs_utilities::dns::DoTProvider::NotSpecified, vec![])
        };

        let ip = resolver.await.unwrap().lookup_first(domain).await?;
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
