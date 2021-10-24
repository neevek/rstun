use crate::ReadResult;
use crate::{AccessServer, ClientConfig, ForwardLoginInfo, TunnelType};
use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use quinn::crypto::rustls::TLSError;
use quinn::TransportConfig;
use quinn::{Certificate, Connection, RecvStream, SendStream};
use rustls::ServerCertVerified;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::time::Duration;

const LOCAL_ADDR_STR: &str = "0.0.0.0:0";
const IDLE_TIMEOUT: u64 = 30 * 1000;

pub struct Client {
    config: ClientConfig,
    conn: Connection,
}

impl Client {
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        let mut transport_cfg = TransportConfig::default();
        transport_cfg
            .max_idle_timeout(Some(Duration::from_millis(IDLE_TIMEOUT)))
            .unwrap();
        transport_cfg.keep_alive_interval(Some(Duration::from_millis(IDLE_TIMEOUT / 2)));

        let mut cfg = quinn::ClientConfig::default();
        cfg.transport = Arc::new(transport_cfg);

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
            .server_addr
            .parse()
            .with_context(|| format!("invalid address: {}", config.server_addr))?;

        let local_addr = LOCAL_ADDR_STR.parse().unwrap();

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

        info!("logging in... server: {}", remote_addr);

        Self::send_login_info(&config, &mut send, &mut recv).await?;

        info!("logged in! server: {}", remote_addr);

        //tokio::spawn(async move {
        //let heartbeat_out = [0_u8; 1];
        //let mut heartbeat_in = [0_u8; 1];
        //let mut fail_count = 0;
        //let exchange_heartbeat_interval: Duration = Duration::from_secs(1);
        //loop {
        //tokio::time::sleep(exchange_heartbeat_interval).await;
        //debug!("sending heartbeat...");
        //tokio::select! {
        //Ok(_) = send.write_all(&heartbeat_out) => {}
        //Ok(_) = recv.read(&mut heartbeat_in) => {}
        //else => {
        //fail_count += 1;
        //warn!("heartbeat failed, count: {}", fail_count);
        //if fail_count > 10 {
        //break;
        //}
        //}
        //}
        //}
        //});

        Ok(Client {
            config,
            conn: connection,
        })
    }

    pub async fn run(&self) -> Result<()> {
        info!("start serving...");

        // start the access server to accept local connections
        let mut acc_server = AccessServer::new(self.config.local_access_server_addr.clone());
        acc_server.bind().await?;
        let (sender, mut receiver) = tokio::sync::mpsc::channel(500);
        acc_server.start(sender).await?;

        // accept local connections and build a tunnel to remote for accepted connections
        while let Some(mut local_conn) = receiver.recv().await {
            match self.conn.open_bi().await {
                Ok((mut remote_send, mut remote_recv)) => {
                    tokio::spawn(async move {
                        let mut local_read_result = ReadResult::Succeeded;
                        loop {
                            let (mut local_read, mut local_write) = local_conn.split();
                            let local2remote =
                                Self::local_to_remote(&mut local_read, &mut remote_send);
                            let remote2local =
                                Self::remote_to_local(&mut remote_recv, &mut local_write);

                            tokio::select! {
                                Ok(result) = local2remote, if !local_read_result.is_eof() => {
                                    local_read_result = result;
                                }
                                Ok(result) = remote2local => {
                                    if let ReadResult::EOF = result {
                                        debug!(">>>>>>>>>> quit2");
                                        break;
                                    }
                                }
                                else => {
                                    debug!(">>>>>>>>>> quit");
                                    break;
                                }
                            };
                        }
                    });
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

    async fn local_to_remote<'a>(
        local_read: &'a mut ReadHalf<'a>,
        remote_send: &'a mut SendStream,
    ) -> Result<ReadResult> {
        let mut buffer = vec![0_u8; 8192];
        let len_read = local_read.read(&mut buffer[..]).await?;

        if len_read > 0 {
            remote_send.write_all(&buffer[..len_read]).await?;
            debug!("<<< local to remote: {}", len_read);
            Ok(ReadResult::Succeeded)
        } else {
            debug!(">>> local to remote: >>> 1111");
            Ok(ReadResult::EOF)
        }
    }

    async fn remote_to_local<'a>(
        remote_recv: &'a mut RecvStream,
        local_write: &'a mut WriteHalf<'a>,
    ) -> Result<ReadResult> {
        let mut buffer = vec![0_u8; 8192];
        let result = remote_recv.read(&mut buffer[..]).await?;
        if let Some(len_read) = result {
            local_write.write_all(&buffer[..len_read]).await?;
            debug!(">>> up to down: {}", len_read);
            return Ok(ReadResult::Succeeded);
        }
        debug!(">>> up to down: >>> 000");
        Ok(ReadResult::EOF)
    }

    //async fn serve(&self, local_conn: &mut TcpStream) -> Result<()> {
    //let (read_stream, write_stream) = local_conn.split();
    ////self.conn.open_bi().await
    //Ok(())
    //}

    async fn send_login_info(
        config: &ClientConfig,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        let tun_type = TunnelType::Forward(ForwardLoginInfo {
            password: config.password.clone(),
            remote_downstream_name: config.remote_downstream_name.clone(),
        });

        let tun_type = bincode::serialize(&tun_type).unwrap();
        send.write_u16(tun_type.len() as u16).await?;
        send.write_all(&tun_type).await?;

        let mut resp = [0_u8; 2];
        recv.read(&mut resp)
            .await
            .context("read login response failed")?;

        if resp[0] != b'o' && resp[1] != b'k' {
            let mut err_buf = vec![0_u8; 128];
            recv.read_to_end(&mut err_buf).await?;
            anyhow::bail!(
                "failed to login, err: {}{}{}",
                resp[0] as char,
                resp[1] as char,
                String::from_utf8_lossy(&err_buf)
            );
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
