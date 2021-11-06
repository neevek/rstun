use crate::ReadResult;
use crate::{ClientConfig, ForwardLoginInfo, TunnelType};
use anyhow::{bail, Context, Result};
use log::{debug, error, info};
//use quinn::crypto::rustls::TLSError;
use quinn::TransportConfig;
use quinn::{RecvStream, SendStream};
use quinn_proto::{IdleTimeout, VarInt, VarIntBoundsExceeded};
use rustls::client::ServerCertVerified;
use rustls::client::ServerName;
use rustls::Certificate;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Receiver;
use tokio::time::Duration;
extern crate libc;

const LOCAL_ADDR_STR: &str = "0.0.0.0:0";

pub struct Client {
    config: ClientConfig,
    remote_conn: Option<quinn::Connection>,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Client {
            config,
            remote_conn: None,
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        let mut transport_cfg = TransportConfig::default();
        transport_cfg.receive_window(quinn::VarInt::from_u32(1024 * 1024)); //.unwrap();
        transport_cfg.send_window(1024 * 1024);

        let timeout = IdleTimeout::from(VarInt::from_u32(self.config.max_idle_timeout_ms as u32));
        transport_cfg.max_idle_timeout(Some(timeout));
        transport_cfg.keep_alive_interval(Some(Duration::from_millis(
            self.config.keep_alive_interval_ms,
        )));

        info!("using cert: {}", self.config.cert_path);

        let cert: Certificate = Client::read_cert(self.config.cert_path.as_str())?;
        //let mut tls_cfg = Arc::get_mut(&mut cfg.crypto).unwrap();
        //tls_cfg
        //.dangerous()
        //.set_certificate_verifier(Arc::new(CertVerifier { cert: cert.clone() }));

        let crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(CertVerifier { cert: cert.clone() }))
            .with_no_client_auth();

        let cfg = quinn::ClientConfig {
            crypto: Arc::new(crypto),
            transport: Arc::new(transport_cfg),
        };

        //let mut cfg_builder = quinn::ClientConfigBuilder::new(cfg);
        //cfg_builder.add_certificate_authority(cert)?;
        ////cfg_builder.protocols(&[b"\x05rstun"]);
        //cfg_builder.enable_keylog();

        let remote_addr = self
            .config
            .server_addr
            .parse()
            .with_context(|| format!("invalid address: {}", self.config.server_addr))?;

        let local_addr: SocketAddr = LOCAL_ADDR_STR.parse().unwrap();

        //endpoint_builder.default_client_config(cfg_builder.build());
        //endpoint_builder.set_default_client_config(cfg);

        //let udp_socket = std::net::UdpSocket::bind(&local_addr)?;

        //unsafe {
        //let optval: libc::c_int = 1024 * 1024 * 3;
        //let ret = libc::setsockopt(
        //udp_socket.as_raw_fd(),
        //libc::SOL_SOCKET,
        //libc::SO_SNDBUF,
        //&optval as *const _ as *const libc::c_void,
        //std::mem::size_of_val(&optval) as libc::socklen_t,
        //);
        //if ret != 0 {
        //error!(
        //"failed to set SO_SNDBUF, err: {}",
        //std::io::Error::last_os_error()
        //);
        //}

        //let optval: libc::c_int = 1024 * 1024 * 3;
        //let ret = libc::setsockopt(
        //udp_socket.as_raw_fd(),
        //libc::SOL_SOCKET,
        //libc::SO_RCVBUF,
        //&optval as *const _ as *const libc::c_void,
        //std::mem::size_of_val(&optval) as libc::socklen_t,
        //);
        //if ret != 0 {
        //error!(
        //"failed to set SO_RCVBUF, err: {}",
        //std::io::Error::last_os_error()
        //);
        //}
        //}

        //let (endpoint, _) = endpoint_builder.bind(&local_addr)?;
        //let (endpoint, _) = endpoint_builder.with_socket(udp_socket)?;

        let mut endpoint = quinn::Endpoint::client(local_addr)?;
        endpoint.set_default_client_config(cfg);
        info!(
            "connecting to {}, local_addr: {}",
            remote_addr,
            endpoint.local_addr().unwrap()
        );

        let quinn::NewConnection { connection, .. } = endpoint
            .connect(remote_addr, "localhost")?
            .await
            .context("connect failed!")?;

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
                    info!("current rtt: {:?}", remote_conn.rtt());
                    tokio::spawn(Self::handle_stream(local_conn, remote_send, remote_recv));
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
        mut local_conn: TcpStream,
        mut remote_send: SendStream,
        mut remote_recv: RecvStream,
    ) -> Result<()> {
        info!("open new stream, id: {}", remote_send.id().index());

        let mut local_read_result = ReadResult::Succeeded;
        loop {
            let (mut local_read, mut local_write) = local_conn.split();
            let local2remote = Self::local_to_remote(&mut local_read, &mut remote_send);
            let remote2local = Self::remote_to_local(&mut remote_recv, &mut local_write);

            tokio::select! {
                Ok(result) = local2remote, if !local_read_result.is_eof() => {
                    local_read_result = result;
                }
                Ok(result) = remote2local => {
                    if let ReadResult::EOF = result {
                        info!("quit stream after hitting EOF, stream_id: {}", remote_send.id().index());
                        break;
                    }
                }
                else => {
                    info!("quit unexpectedly, stream_id: {}", remote_send.id().index());
                    break;
                }
            };
        }
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
            info!(
                ">>>>>>>>>>>> LOCAL 2 REMOTE, id:{}, bytes:{}",
                remote_send.id().index(),
                len_read
            );
            Ok(ReadResult::Succeeded)
        } else {
            remote_send.finish().await?;
            info!(
                ">>>>>>>>>>>> LOCAL 2 REMOTE DONE, id:{}",
                remote_send.id().index(),
            );
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
            info!(
                ">>>>>>>>>>>> REMOTE 2 LOCAL, id:{}, bytes:{}",
                remote_recv.id().index(),
                len_read
            );
            Ok(ReadResult::Succeeded)
        } else {
            info!(
                ">>>>>>>>>>>> REMOTE 2 LOCAL DONE, id:{}",
                remote_recv.id().index(),
            );
            Ok(ReadResult::EOF)
        }
    }

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
        intermediates: &[Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    //fn verify_server_cert(
    //&self,
    //_: &rustls::RootCertStore,
    //presented_certs: &[rustls::Certificate],
    //_: webpki::DNSNameRef,
    //_: &[u8],
    //) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
    //if presented_certs.len() != 1 {
    //return Err(TLSError::General(format!(
    //"server sent {} certificates, expected one",
    //presented_certs.len()
    //)));
    //}
    //if presented_certs[0].0 != self.cert.as_der() {
    //return Err(TLSError::General(format!(
    //"server certificates doesn't match ours"
    //)));
    //}

    //info!("certificate verified!");
    //Ok(ServerCertVerified::assertion())
    //}
}
