use anyhow::Result;
use anyhow::{bail, Context};
use enum_as_inner::EnumAsInner;
use quinn::{RecvStream, SendStream};
use rs_utilities::Utils;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

#[derive(EnumAsInner, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum TunnelMessage {
    ReqInLogin(LoginInfo),
    ReqOutLogin(LoginInfo),
    ReqInConnection,
    ReqTerminate,
    RespFailure(String),
    RespSuccess,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct LoginInfo {
    pub password: String,
    pub access_server_addr: String, // ip:port tuple
}

impl TunnelMessage {
    pub async fn recv(quic_recv: &mut RecvStream) -> Result<TunnelMessage> {
        let mut msg_len = [0_u8; 4];
        quic_recv
            .read_exact(&mut msg_len)
            .await
            .context("read message length failed")?;

        let msg_len = Utils::to_u32_be(&msg_len) as usize;
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
        quic_send.flush().await?;
        Ok(())
    }

    pub fn handle_message(msg: &TunnelMessage) -> Result<()> {
        match msg {
            TunnelMessage::RespSuccess => Ok(()),
            TunnelMessage::RespFailure(msg) => bail!(format!("received failure, err: {}", msg)),
            _ => bail!("unexpected message type"),
        }
    }
}
