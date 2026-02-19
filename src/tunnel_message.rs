use crate::{Tunnel, TunnelMode};
use anyhow::Result;
use anyhow::{Context, bail};
use bincode::config::{self, Configuration};
use enum_as_inner::EnumAsInner;
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_TUNNEL_MESSAGE_SIZE: usize = 64 * 1024;

#[derive(EnumAsInner, Serialize, Deserialize, Debug, Clone)]
pub enum TunnelMessage {
    ReqLogin(LoginInfo),
    ReqUdpStart(UdpPeerAddr),
    ReqHeartbeat(u64),
    RespHeartbeat(u64),
    RespFailure(String),
    RespSuccess,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LoginInfo {
    pub password: String,
    pub(crate) tunnel: Tunnel,
}

impl LoginInfo {
    pub fn format_with_remote_addr(&self, remote_addr: &SocketAddr) -> String {
        match &self.tunnel {
            Tunnel::ChannelBased(upstream_type) => {
                format!("{upstream_type}_ChannelBased →  {remote_addr}")
            }
            Tunnel::NetworkBased(cfg) => {
                let upstream = &cfg.upstream;
                let upstream_str = if let Some(upstream) = upstream.upstream_addr {
                    if upstream.ip().is_loopback() {
                        format!("{}:{}", remote_addr.ip(), upstream.port())
                    } else {
                        format!("{upstream}")
                    }
                } else {
                    String::from("PeerDefault")
                };

                match cfg.mode {
                    TunnelMode::Out => {
                        format!(
                            "{}_OUT →  {} →  {remote_addr} →  {upstream_str}",
                            upstream.upstream_type,
                            cfg.local_server_addr.unwrap()
                        )
                    }
                    TunnelMode::In => {
                        format!(
                            "{}_IN ←  {} ←  {remote_addr} ←  {upstream_str}",
                            upstream.upstream_type,
                            cfg.local_server_addr.unwrap()
                        )
                    }
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UdpPeerAddr(pub Option<SocketAddr>);

impl Display for LoginInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.tunnel {
            Tunnel::ChannelBased(upstream_type) => {
                f.write_str(format!("{upstream_type}_ChannelBased").as_str())
            }
            Tunnel::NetworkBased(cfg) => {
                f.write_str(format!("{}_{}", cfg.upstream.upstream_type, cfg.mode).as_str())
            }
        }
    }
}

impl Display for TunnelMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReqLogin(login_info) => f.write_str(login_info.to_string().as_str()),
            Self::ReqUdpStart(udp_peer_addr) => {
                f.write_str(format!("udp_start:{udp_peer_addr:?}").as_str())
            }
            Self::ReqHeartbeat(seq) => f.write_str(format!("heartbeat:req:{seq}").as_str()),
            Self::RespHeartbeat(seq) => f.write_str(format!("heartbeat:resp:{seq}").as_str()),
            Self::RespFailure(msg) => f.write_str(format!("fail:{msg}").as_str()),
            Self::RespSuccess => f.write_str("succeeded"),
        }
    }
}

impl TunnelMessage {
    pub async fn recv_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<TunnelMessage> {
        let msg_len = reader.read_u32().await? as usize;
        if msg_len > MAX_TUNNEL_MESSAGE_SIZE {
            bail!("tunnel message too large: {msg_len} > {MAX_TUNNEL_MESSAGE_SIZE}");
        }
        let mut msg = vec![0; msg_len];
        reader
            .read_exact(&mut msg)
            .await
            .context("read message failed")?;
        let tun_msg = bincode::serde::decode_from_slice::<TunnelMessage, Configuration>(
            &msg,
            config::standard(),
        )
        .context("deserialize message failed")?;
        Ok(tun_msg.0)
    }

    pub async fn send_to<W: AsyncWrite + Unpin>(writer: &mut W, msg: &TunnelMessage) -> Result<()> {
        let msg = bincode::serde::encode_to_vec(msg, config::standard())
            .context("serialize message failed")?;
        writer.write_u32(msg.len() as u32).await?;
        writer.write_all(&msg).await?;
        Ok(())
    }

    pub async fn recv(quic_recv: &mut RecvStream) -> Result<TunnelMessage> {
        Self::recv_from(quic_recv).await
    }

    pub async fn send(quic_send: &mut SendStream, msg: &TunnelMessage) -> Result<()> {
        Self::send_to(quic_send, msg).await
    }

    pub async fn send_failure(quic_send: &mut SendStream, msg: String) -> Result<()> {
        let msg = TunnelMessage::RespFailure(msg);
        Self::send(quic_send, &msg).await?;
        quic_send.flush().await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(())
    }

    pub async fn recv_raw(quic_recv: &mut RecvStream, data: &mut [u8]) -> Result<u16> {
        let msg_len = quic_recv.read_u16().await? as usize;
        if msg_len > data.len() {
            bail!("message too large: {msg_len}");
        }
        quic_recv
            .read_exact(&mut data[..msg_len])
            .await
            .context("read message failed")?;
        Ok(msg_len as u16)
    }

    pub async fn send_raw(quic_send: &mut SendStream, data: &[u8]) -> Result<()> {
        quic_send.write_u16(data.len() as u16).await?;
        quic_send.write_all(data).await?;
        Ok(())
    }

    pub fn handle_message(msg: &TunnelMessage) -> Result<()> {
        match msg {
            TunnelMessage::RespSuccess => Ok(()),
            TunnelMessage::RespFailure(msg) => bail!(format!("received failure, err: {msg}")),
            _ => bail!("unexpected message type"),
        }
    }
}
