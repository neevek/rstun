use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};

pub mod tcp_server;
pub mod tcp_tunnel;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    fn peer_addr(&self) -> std::io::Result<SocketAddr>;
}

impl AsyncStream for TcpStream {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
    }
}

pub enum TcpMessage<S: AsyncStream> {
    Request(S),
    RequestWithUpstream(S, SocketAddr),
    Quit,
}

pub type TcpSender<S> = Sender<TcpMessage<S>>;
pub type TcpReceiver<S> = Receiver<TcpMessage<S>>;
