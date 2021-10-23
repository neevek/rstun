use crate::{AccessServer, ClientConfig, ForwardLoginInfo, TunnelType};
use anyhow::{bail, Context, Result};
use futures_util::AsyncWriteExt as FuturesAsyncWriteExt;
use log::{error, info};
use quinn::crypto::rustls::TLSError;
use quinn::{Certificate, Connection, RecvStream, SendStream, VarInt};
use rustls::ServerCertVerified;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::ReadHalf;
use tokio::net::tcp::WriteHalf;
use tokio::net::TcpStream;

const LOCAL_ADDR_STR: &str = "0.0.0.0:0";

pub struct Client {
    config: ClientConfig,
    conn: Connection,
    send_stream: SendStream,
    recv_stream: RecvStream,
    acc_server: AccessServer,
}

impl Client {
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        let mut cfg = quinn::ClientConfig::default();

        info!("using cert: {}", config.cert_path);

        let cert = Client::read_cert(config.cert_path.as_str())?;
        let tls_cfg = Arc::get_mut(&mut cfg.crypto).unwrap();
        tls_cfg
            .dangerous()
            .set_certificate_verifier(Arc::new(CertVerifier { cert: cert.clone() }));

        let mut cfg_builder = quinn::ClientConfigBuilder::new(cfg);
        cfg_builder.add_certificate_authority(cert)?;
        cfg_builder.protocols(&[b"\x05rstun"]);
        cfg_builder.enable_keylog();

        let remote_addr = config
            .addr
            .parse()
            .with_context(|| format!("invalid address: {}", config.addr))?;

        let local_addr = LOCAL_ADDR_STR
            .parse()
            .with_context(|| format!("invalid address: {}", config.addr))?;

        let mut endpoint_builder = quinn::Endpoint::builder();
        endpoint_builder.default_client_config(cfg_builder.build());

        let (endpoint, _) = endpoint_builder.bind(&local_addr)?;

        info!(
            "connecting to {}, local_addr: {}",
            remote_addr,
            endpoint.local_addr().unwrap()
        );

        let quinn::NewConnection { connection, .. } = endpoint
            .connect(&remote_addr, "localhost")?
            .await
            .context("connect failed!")?;

        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| error!("open bidirectional connection failed: {}", e))
            .unwrap();

        Self::send_login_info(&mut send, &mut recv).await?;

        info!("connected! server: {}", remote_addr);

        let mut acc_server = AccessServer::new(config.access_server_addr.clone());
        acc_server.bind().await?;

        Ok(Client {
            config,
            conn: connection,
            send_stream: send,
            recv_stream: recv,
            acc_server,
        })
    }

    async fn run(&self) -> Result<()> {
        let mut acc_server = AccessServer::new(self.config.access_server_addr.clone());
        acc_server.bind().await?;

        let (sender, mut receiver) = tokio::sync::mpsc::channel(500);
        acc_server.start(sender).await?;

        while let Some(mut local_conn) = receiver.recv().await {
            match self.conn.open_bi().await {
                Ok((mut remote_send, mut remote_recv)) => {
                    let (mut local_read, mut local_write) = local_conn.split();
                    //Self::local_to_remote(&mut local_read, &mut remote_send).await?;

                    tokio::select! {
                        _ = Self::local_to_remote(&mut local_read, &mut remote_send) => (),
                        _ = Self::remote_to_local(&mut remote_recv, &mut local_write) => ()
                    }
                }
                Err(e) => {
                    error!("failed to connect to remote server: {}", e);
                    // local_conn will be dropped here
                }
            }
        }

        Ok(())
    }

    async fn local_to_remote<'a>(
        local_read: &'a mut ReadHalf<'a>,
        remote_send: &'a mut SendStream,
    ) -> Result<()> {
        let mut buffer = vec![0_u8; 8192];
        match local_read.read(&mut buffer[..]).await {
            Ok(len_read) => {
                if remote_send.write_all(&buffer).await.is_err() {
                    remote_send.close().await.unwrap_or(());
                }
            }
            Err(e) => bail!("failed"),
        }
        Ok(())
    }

    async fn remote_to_local<'a>(
        remote_recv: &'a mut RecvStream,
        local_write: &'a mut WriteHalf<'a>,
    ) -> Result<()> {
        let mut buffer = vec![0_u8; 8192];
        match remote_recv.read(&mut buffer[..]).await {
            Ok(len_read) => {
                if local_write.write_all(&buffer).await.is_err() {
                    remote_recv.stop(VarInt::from_u32(1)).unwrap_or(());
                }
            }
            Err(e) => bail!("failed"),
        }
        Ok(())
    }

    //async fn serve(&self, local_conn: &mut TcpStream) -> Result<()> {
    //let (read_stream, write_stream) = local_conn.split();
    ////self.conn.open_bi().await
    //Ok(())
    //}

    async fn send_login_info(send: &mut SendStream, recv: &mut RecvStream) -> Result<()> {
        let tun_type = TunnelType::Forward(ForwardLoginInfo {
            password: "hello world!".to_string(),
            remote_downstream_name: "http".to_string(),
        });

        let tun_type = bincode::serialize(&tun_type).unwrap();
        send.write_u16(tun_type.len() as u16).await?;
        send.write_all(&tun_type).await?;

        let mut resp = [0_u8; 2];
        recv.read_exact(&mut resp)
            .await
            .context("read login response failed")?;

        if resp[0] != b'o' && resp[1] != b'k' {
            anyhow::bail!("failed to login!");
        }

        Ok(())
    }

    fn read_cert(cert_path: &str) -> Result<Certificate> {
        let cert = std::fs::read(cert_path).context("failed to read cert file")?;
        let cert = Certificate::from_pem(&cert[..]).context("failed to create Certificate")?;

        Ok(cert)
    }
}

struct CertVerifier {
    cert: Certificate,
}

impl rustls::ServerCertVerifier for CertVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::RootCertStore,
        presented_certs: &[rustls::Certificate],
        _: webpki::DNSNameRef,
        _: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        if presented_certs.len() != 1 {
            return Err(TLSError::General(format!(
                "server sent {} certificates, expected one",
                presented_certs.len()
            )));
        }
        if presented_certs[0].0 != self.cert.as_der() {
            return Err(TLSError::General(format!(
                "server certificates doesn't match ours"
            )));
        }

        info!("pass!");
        Ok(ServerCertVerified::assertion())
    }
}
