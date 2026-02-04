use crate::tunnel_message::TunnelMessage;
use anyhow::{Result, bail};
use log::{debug, warn};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, MissedTickBehavior};

#[derive(Clone, Copy, Debug)]
pub(crate) struct HeartbeatConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

impl HeartbeatConfig {
    pub fn is_enabled(&self) -> bool {
        self.interval > Duration::from_millis(0) && self.timeout > Duration::from_millis(0)
    }
}

pub(crate) async fn client_heartbeat<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    config: HeartbeatConfig,
    mut should_stop: F,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut() -> bool,
{
    if !config.is_enabled() {
        debug!("heartbeat disabled on client");
        return Ok(());
    }

    let mut ticker = tokio::time::interval(config.interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut seq: u64 = 0;

    loop {
        ticker.tick().await;
        if should_stop() {
            debug!("heartbeat stopped on client");
            return Ok(());
        }

        seq = seq.wrapping_add(1);
        TunnelMessage::send_to(writer, &TunnelMessage::ReqHeartbeat(seq)).await?;
        writer.flush().await?;

        let resp =
            match tokio::time::timeout(config.timeout, TunnelMessage::recv_from(reader)).await {
                Ok(resp) => resp?,
                Err(_) => {
                    bail!("heartbeat timeout after {:?}, seq:{seq}", config.timeout);
                }
            };

        match resp {
            TunnelMessage::RespHeartbeat(resp_seq) if resp_seq == seq => {
                // debug!("heartbeat ok, seq:{seq}");
            }
            TunnelMessage::RespHeartbeat(resp_seq) => {
                warn!("heartbeat sequence mismatch, expected:{seq}, got:{resp_seq}");
            }
            other => {
                warn!("unexpected heartbeat response: {other}");
            }
        }
    }
}

pub(crate) async fn server_heartbeat<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    config: HeartbeatConfig,
    mut should_stop: F,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut() -> bool,
{
    if !config.is_enabled() {
        debug!("heartbeat disabled on server");
        return Ok(());
    }

    loop {
        if should_stop() {
            debug!("heartbeat stopped on server");
            return Ok(());
        }

        let msg = match tokio::time::timeout(config.timeout, TunnelMessage::recv_from(reader)).await
        {
            Ok(msg) => msg?,
            Err(_) => {
                bail!("heartbeat timeout after {:?}", config.timeout);
            }
        };

        match msg {
            TunnelMessage::ReqHeartbeat(seq) => {
                TunnelMessage::send_to(writer, &TunnelMessage::RespHeartbeat(seq)).await?;
                writer.flush().await?;
            }
            other => {
                warn!("unexpected heartbeat request: {other}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel_message::TunnelMessage;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::io::split;
    use tokio::time::Duration;

    #[tokio::test]
    async fn server_replies_to_ping() {
        let (client, server) = tokio::io::duplex(1024);
        let (mut client_read, mut client_write) = split(client);
        let (mut server_read, mut server_write) = split(server);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        let server_task = tokio::spawn(async move {
            let config = HeartbeatConfig {
                interval: Duration::from_millis(10),
                timeout: Duration::from_millis(200),
            };
            let _ = server_heartbeat(&mut server_read, &mut server_write, config, || {
                stop_clone.load(Ordering::Relaxed)
            })
            .await;
        });

        TunnelMessage::send_to(&mut client_write, &TunnelMessage::ReqHeartbeat(7))
            .await
            .unwrap();
        let resp = TunnelMessage::recv_from(&mut client_read).await.unwrap();
        match resp {
            TunnelMessage::RespHeartbeat(seq) => assert_eq!(seq, 7),
            other => panic!("unexpected response: {other:?}"),
        }

        stop.store(true, Ordering::Relaxed);
        drop(client_read);
        drop(client_write);
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn client_heartbeat_times_out_without_pong() {
        let (client, _server) = tokio::io::duplex(1024);
        let (mut client_read, mut client_write) = split(client);
        let config = HeartbeatConfig {
            interval: Duration::from_millis(20),
            timeout: Duration::from_millis(60),
        };

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            client_heartbeat(&mut client_read, &mut client_write, config, || false),
        )
        .await
        .expect("heartbeat did not return in time");

        assert!(result.is_err(), "expected heartbeat timeout error");
    }

    #[tokio::test]
    async fn server_heartbeat_times_out_without_ping() {
        let (_client, server) = tokio::io::duplex(1024);
        let (mut server_read, mut server_write) = split(server);
        let config = HeartbeatConfig {
            interval: Duration::from_millis(20),
            timeout: Duration::from_millis(60),
        };

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            server_heartbeat(&mut server_read, &mut server_write, config, || false),
        )
        .await
        .expect("heartbeat did not return in time");

        assert!(result.is_err(), "expected heartbeat timeout error");
    }
}
