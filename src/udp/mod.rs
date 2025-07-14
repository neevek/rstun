pub mod udp_server;
pub mod udp_tunnel;

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
    pub peer_addr: Option<SocketAddr>,
}
