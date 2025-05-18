use anyhow::Result;
use anyhow::{bail, Context};
use enum_as_inner::EnumAsInner;
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{TunnelMode, Upstream};

#[derive(EnumAsInner, Serialize, Deserialize, Debug, Clone)]
pub enum TunnelMessage {
    ReqLogin(LoginInfo),
    ReqUdpStart(UdpLocalAddr),
    RespFailure(String),
    RespSuccess,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LoginInfo {
    pub password: String,
    pub upstream: Upstream,
    pub mode: TunnelMode,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UdpLocalAddr(pub SocketAddr);

impl Display for LoginInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("{}_{}", self.upstream.upstream_type, self.mode).as_str())
    }
}

impl Display for TunnelMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReqLogin(login_info) => f.write_str(login_info.to_string().as_str()),
            _ => f.write_str("tunnel message"),
        }
    }
}

impl TunnelMessage {
    pub async fn recv(quic_recv: &mut RecvStream) -> Result<TunnelMessage> {
        let msg_len = quic_recv.read_u32().await? as usize;
        let mut msg = vec![0; msg_len];
        quic_recv
            .read_exact(&mut msg)
            .await
            .context("read message failed")?;

        let tun_msg =
            bincode::deserialize::<TunnelMessage>(&msg).context("deserialize message failed")?;
        Ok(tun_msg)
    }

    pub async fn send(quic_send: &mut SendStream, msg: &TunnelMessage) -> Result<()> {
        let msg = bincode::serialize(msg).context("serialize message failed")?;
        quic_send.write_u32(msg.len() as u32).await?;
        quic_send.write_all(&msg).await?;
        Ok(())
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
