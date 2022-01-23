use crate::ClientConfig;
use crate::ReadResult;
use anyhow::{bail, Context, Result};
use byte_pool::BytePool;
use log::{error, info};
use quinn::{congestion, TransportConfig};
use quinn::{RecvStream, SendStream};
use quinn_proto::{IdleTimeout, VarInt};
use rustls::client::ServerCertVerified;
use rustls::client::ServerName;
use rustls::Certificate;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Receiver;
use tokio::time::Duration;
extern crate libc;

const LOCAL_ADDR_STR: &str = "0.0.0.0:0";
type BufferPool = Arc<BytePool<Vec<u8>>>;

pub struct Client {
    config: ClientConfig,
    remote_conn: Option<quinn::Connection>,
    buffer_pool: BufferPool,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Client {
            config,
            remote_conn: None,
            buffer_pool: Arc::new(BytePool::<Vec<u8>>::new()),
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

        let remote_addr = self
            .config
            .server_addr
            .parse()
            .with_context(|| format!("invalid address: {}", self.config.server_addr))?;

        let local_addr: SocketAddr = LOCAL_ADDR_STR.parse().unwrap();

        let mut endpoint = quinn::Endpoint::client(local_addr)?;
        endpoint.set_default_client_config(cfg);
        info!(
            "connecting to {}, local_addr: {}",
            remote_addr,
            endpoint.local_addr().unwrap()
        );

        let quinn::NewConnection { connection, .. } =
            endpoint.connect(remote_addr, "localhost")?.await?;

        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| error!("open bidirectional connection failed: {}", e))
            .unwrap();

        info!("logging in... server: {}", remote_addr);

        Self::send_login_info(&self.config, &mut send, &mut recv).await?;

        info!("logged in! server: {}", remote_addr);

        self.remote_conn = Some(connection);
        Ok(())
    }

    pub async fn serve(&mut self, local_conn_receiver: &mut Receiver<TcpStream>) -> Result<()> {
        info!("start serving...");

        let remote_conn = &self.remote_conn.as_ref().unwrap();
        // accept local connections and build a tunnel to remote for accepted connections
        while let Some(local_conn) = local_conn_receiver.recv().await {
            match remote_conn.open_bi().await {
                Ok((remote_send, remote_recv)) => {
                    tokio::spawn(Self::handle_stream(
                        local_conn,
                        remote_send,
                        remote_recv,
                        self.buffer_pool.clone(),
                    ));
                }
                Err(e) => {
                    error!("failed to open_bi on remote connection: {}", e);
                    break;
                }
            }
        }

        info!("quit!");
        Ok(())
    }

    async fn handle_stream(
        local_conn: TcpStream,
        mut remote_send: SendStream,
        mut remote_recv: RecvStream,
        buffer_pool: BufferPool,
    ) -> Result<()> {
        let (mut local_read, mut local_write) = local_conn.into_split();
        info!(
            "open stream for local conn, {} -> {}",
            remote_send.id().index(),
            local_read.peer_addr().unwrap(),
        );
        let bp_clone = buffer_pool.clone();
        tokio::spawn(async move {
            loop {
                let result =
                    Self::local_to_remote(&mut local_read, &mut remote_send, &bp_clone).await;
                if let Ok(ReadResult::EOF) | Err(_) = result {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            loop {
                let result =
                    Self::remote_to_local(&mut remote_recv, &mut local_write, &buffer_pool).await;
                if let Ok(ReadResult::EOF) | Err(_) = result {
                    break;
                }
            }
        });
        Ok(())
    }

    async fn local_to_remote(
        local_read: &mut OwnedReadHalf,
        remote_send: &mut SendStream,
        buffer_pool: &BufferPool,
    ) -> Result<ReadResult> {
        let mut buffer = buffer_pool.alloc(8192);
        let len_read = local_read.read(&mut buffer[..]).await?;
        if len_read > 0 {
            remote_send.write_all(&buffer[..len_read]).await?;
            Ok(ReadResult::Succeeded)
        } else {
            remote_send.finish().await?;
            Ok(ReadResult::EOF)
        }
    }

    async fn remote_to_local(
        remote_recv: &mut RecvStream,
        local_write: &mut OwnedWriteHalf,
        buffer_pool: &BufferPool,
    ) -> Result<ReadResult> {
        let mut buffer = buffer_pool.alloc(8192);
        let result = remote_recv.read(&mut buffer[..]).await?;
        if let Some(len_read) = result {
            local_write.write_all(&buffer[..len_read]).await?;
            Ok(ReadResult::Succeeded)
        } else {
            Ok(ReadResult::EOF)
        }
    }

    async fn send_login_info(
        config: &ClientConfig,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        let tun_type = config.tun_type.as_ref().unwrap();
        let tun_type = bincode::serialize(tun_type).unwrap();
        send.write_u16(tun_type.len() as u16).await?;
        send.write_all(&tun_type).await?;

        let mut resp = [0_u8; 2];
        recv.read(&mut resp)
            .await
            .context("read login response failed")?;

        if resp[0] != b'o' && resp[1] != b'k' {
            let mut err_buf = vec![0_u8; 128];
            recv.read_to_end(&mut err_buf).await?;
            bail!(
                "failed to login, err: {}{}{}",
                resp[0] as char,
                resp[1] as char,
                String::from_utf8_lossy(&err_buf)
            );
        }

        Ok(())
    }

    fn read_cert(cert_path: &str) -> Result<rustls::Certificate> {
        let cert = std::fs::read(cert_path).context("failed to read cert file")?;
        let cert = rustls::Certificate(cert.into());

        Ok(cert)
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
