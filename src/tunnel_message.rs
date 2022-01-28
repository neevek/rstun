use anyhow::Result;
use anyhow::{bail, Context};
use enum_as_inner::EnumAsInner;
use quinn::{RecvStream, SendStream};
use tokio::io::AsyncWriteExt;

use crate::util;

#[derive(EnumAsInner, Serialize, Deserialize, Debug, PartialEq)]
pub enum TunnelMessage {
    ReqInLogin(LoginInfo),
    ReqOutLogin(LoginInfo),
    ReqInConnection,
    ReqTerminate,
    RespFailure(String),
    RespSuccess,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LoginInfo {
    pub password: String,
    pub access_server_addr: String, // ip:port tuple
}

impl TunnelMessage {
    pub async fn recv(recv_stream: &mut RecvStream) -> Result<TunnelMessage> {
        let mut msg_len = [0_u8; 4];
        recv_stream
            .read_exact(&mut msg_len)
            .await
            .context("read message length failed")?;

        let msg_len = util::as_u32_be(&msg_len) as usize;
        let mut msg = vec![0; msg_len];
        recv_stream
            .read_exact(&mut msg)
            .await
            .context("read message failed")?;

        let tun_msg =
            bincode::deserialize::<TunnelMessage>(&msg).context("deserialize message failed")?;
        Ok(tun_msg)
    }

    pub async fn send(send_stream: &mut SendStream, msg: &TunnelMessage) -> Result<()> {
        let msg = bincode::serialize(msg).context("serialize message failed")?;
        send_stream.write_u32(msg.len() as u32).await?;
        send_stream.write_all(&msg).await?;
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
