pub mod udp_server;
pub mod udp_tunnel;

use crate::TunnelTarget;
use byte_pool::Block;
use std::net::SocketAddr;
use tokio::sync::mpsc::{Receiver, Sender};

pub enum UdpMessage {
    Packet(UdpPacket),
    Quit,
}

pub type UdpSender = Sender<UdpMessage>;
pub type UdpReceiver = Receiver<UdpMessage>;

pub struct UdpPacket {
    pub payload: Block<'static, Vec<u8>>,
    pub local_addr: SocketAddr,
    /// Destination of this datagram. `Domain` targets resolve at the tunnel
    /// egress; `None` means the server's configured default upstream.
    pub peer_addr: Option<TunnelTarget>,
}
