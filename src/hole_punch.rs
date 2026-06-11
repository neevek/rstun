//! Generic UDP hole punching.
//!
//! A [`Puncher`] owns one dual-role QUIC endpoint (client + server) on a single
//! UDP socket. It can discover that socket's server-observed (reflexive) address
//! via an rstun rendezvous, and establish a direct QUIC connection to a peer at
//! its reflexive address via **simultaneous open**. All TLS/identity is
//! caller-supplied — this module contains no peer/identity/mesh/auth vocabulary;
//! authentication is whatever the caller's `ClientConfig`/`ServerConfig` enforce.

use crate::Tunnel;
use crate::registry::protocol::RegistryMessage;
use crate::tunnel_message::{LoginInfo, TunnelMessage};
use anyhow::{Context, Result, bail};
use log::debug;
use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, ServerConfig};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::time::Duration;

/// Per-attempt dial/accept window and the retry gap between attempts.
const PUNCH_RETRY_GAP: Duration = Duration::from_millis(250);

/// On a successful punch both peers must converge on a single connection. The
/// dialer keeps its outbound connection; the accepter keeps its inbound one
/// (which is the dialer's outbound), so they agree on the same direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchRole {
    /// Keep the connection we dial out (the side with the smaller key, by
    /// convention).
    Dial,
    /// Keep the connection we accept inbound (still dials in the background to
    /// open our own NAT mapping).
    Accept,
}

/// A dual-role QUIC endpoint for NAT traversal.
///
/// Keep the `Puncher` alive for as long as any `Connection` it produced is in
/// use: a punched `Connection` keeps the endpoint driver running while open, but
/// dropping the `Puncher` together with the last `Connection` ends the driver, so
/// holders of a `punch()` result should retain the `Puncher` (e.g. behind an
/// `Arc`) alongside the connection.
pub struct Puncher {
    endpoint: Endpoint,
}

impl Puncher {
    /// Bind a dual-role endpoint on `local_addr`. `client_cfg` is the default
    /// client config used for punching (caller mTLS); `server_cfg` accepts the
    /// peer's punch. `SO_REUSEADDR` is set so the same local port can be reused
    /// across the throwaway reflexive connection and the punch.
    pub fn bind(
        local_addr: SocketAddr,
        client_cfg: ClientConfig,
        server_cfg: ServerConfig,
    ) -> Result<Self> {
        let domain = if local_addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket =
            Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create punch socket")?;
        // Allow re-binding the same port shortly after a previous Puncher on it
        // is dropped (e.g. a retried punch).
        socket
            .set_reuse_address(true)
            .context("set SO_REUSEADDR on punch socket")?;
        socket
            .bind(&local_addr.into())
            .with_context(|| format!("bind punch socket to {local_addr}"))?;
        // Quinn/tokio require a non-blocking socket; a blocking one would stall
        // the reactor, so a failure here is fatal (not best-effort).
        socket
            .set_nonblocking(true)
            .context("set punch socket non-blocking")?;
        let socket: std::net::UdpSocket = socket.into();

        let runtime =
            quinn::default_runtime().context("no async runtime available for quinn endpoint")?;
        let mut endpoint =
            Endpoint::new(EndpointConfig::default(), Some(server_cfg), socket, runtime)
                .context("build dual-role quinn endpoint")?;
        endpoint.set_default_client_config(client_cfg);
        Ok(Self { endpoint })
    }

    /// The local bound address of the punch socket.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().context("punch local_addr")
    }

    /// Discover this socket's server-observed (reflexive) address by opening a
    /// throwaway connection to an rstun rendezvous **over this endpoint's own
    /// socket** and asking `whats_my_addr`. `rendezvous_cfg` is the client config
    /// for the rendezvous (its TLS), distinct from the punch (peer mTLS) config.
    pub async fn reflexive(
        &self,
        rendezvous: SocketAddr,
        rendezvous_cfg: ClientConfig,
        sni: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<SocketAddr> {
        let conn = tokio::time::timeout(
            timeout,
            self.endpoint
                .connect_with(rendezvous_cfg, rendezvous, sni)?,
        )
        .await
        .context("reflexive connect timed out")?
        .context("reflexive connect failed")?;

        let (mut send, mut recv) = conn.open_bi().await.context("open reflexive stream")?;
        let login = LoginInfo {
            password: password.to_string(),
            tunnel: Tunnel::Registry,
            tcp_timeout_ms: 30_000,
            udp_timeout_ms: 30_000,
        };
        TunnelMessage::send(&mut send, &TunnelMessage::ReqLogin(login)).await?;
        match TunnelMessage::recv(&mut recv).await {
            Ok(TunnelMessage::RespSuccess(_)) => {}
            Ok(TunnelMessage::RespFailure(m)) => bail!("reflexive login rejected: {m}"),
            Ok(other) => bail!("unexpected reflexive login response: {other}"),
            Err(e) => bail!("reflexive login failed: {e}"),
        }
        TunnelMessage::send(
            &mut send,
            &TunnelMessage::Registry(RegistryMessage::WhatsMyAddr),
        )
        .await?;
        let addr = match TunnelMessage::recv(&mut recv).await? {
            TunnelMessage::Registry(RegistryMessage::MyAddr(addr)) => addr,
            other => bail!("unexpected whats_my_addr response: {other}"),
        };
        conn.close(0u32.into(), b"reflexive done");
        Ok(addr)
    }

    /// Establish a direct connection to `peer` via QUIC simultaneous open. Both
    /// peers call this concurrently (one `Dial`, one `Accept`); the outbound
    /// Initials open each NAT and the caller's mTLS authenticates. Retries with a
    /// fixed gap until `timeout`. On failure the caller falls back to relay.
    pub async fn punch(
        &self,
        peer: SocketAddr,
        sni: &str,
        role: PunchRole,
        timeout: Duration,
    ) -> Result<Connection> {
        match role {
            PunchRole::Dial => self.dial_until(peer, sni, timeout).await,
            PunchRole::Accept => {
                // Dial in the background purely to open our NAT mapping toward the
                // peer; keep the inbound connection the peer dials to us.
                let endpoint = self.endpoint.clone();
                let sni_owned = sni.to_string();
                let dialer = tokio::spawn(async move {
                    let _ = Self::dial_endpoint_until(&endpoint, peer, &sni_owned, timeout).await;
                });
                let result = self.accept_from(peer, timeout).await;
                dialer.abort();
                result
            }
        }
    }

    /// Repeatedly dial `peer` until a handshake completes or `timeout` elapses.
    async fn dial_until(
        &self,
        peer: SocketAddr,
        sni: &str,
        timeout: Duration,
    ) -> Result<Connection> {
        Self::dial_endpoint_until(&self.endpoint, peer, sni, timeout).await
    }

    async fn dial_endpoint_until(
        endpoint: &Endpoint,
        peer: SocketAddr,
        sni: &str,
        timeout: Duration,
    ) -> Result<Connection> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                bail!("punch dial to {peer} failed after {attempt} attempts");
            }
            let per_attempt = remaining.min(Duration::from_secs(2));
            match endpoint.connect(peer, sni) {
                Ok(connecting) => match tokio::time::timeout(per_attempt, connecting).await {
                    Ok(Ok(conn)) => return Ok(conn),
                    Ok(Err(e)) => debug!("[punch] dial to {peer} attempt {attempt} failed: {e}"),
                    Err(_) => debug!("[punch] dial to {peer} attempt {attempt} timed out"),
                },
                Err(e) => debug!("[punch] connect() to {peer} rejected: {e}"),
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("punch dial to {peer} failed after {attempt} attempts");
            }
            tokio::time::sleep(PUNCH_RETRY_GAP).await;
        }
    }

    /// Accept an inbound connection from `peer` (matched by IP) until `timeout`.
    async fn accept_from(&self, peer: SocketAddr, timeout: Duration) -> Result<Connection> {
        let accept = async {
            loop {
                match self.endpoint.accept().await {
                    Some(incoming) => {
                        // Match on IP only (the source port is unpredictable after
                        // NAT). This is just a noise filter — the caller's mTLS
                        // server config is the real authentication gate, so a
                        // different node behind the same NAT can't impersonate.
                        if incoming.remote_address().ip() == peer.ip() {
                            match incoming.await {
                                Ok(conn) => break Ok(conn),
                                Err(e) => debug!("[punch] inbound from {peer} failed: {e}"),
                            }
                        } else {
                            // Not our peer; refuse without a full handshake.
                            incoming.refuse();
                        }
                    }
                    None => break Err(anyhow::anyhow!("punch endpoint closed while accepting")),
                }
            }
        };
        match tokio::time::timeout(timeout, accept).await {
            Ok(res) => res,
            Err(_) => bail!("punch accept from {peer} timed out"),
        }
    }
}
