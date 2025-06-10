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

pub struct StreamRequest<S: AsyncStream> {
    pub stream: S,
    pub dst_addr: Option<SocketAddr>,
}

pub enum StreamMessage<S: AsyncStream> {
    Request(StreamRequest<S>),
    Quit,
}

pub type StreamSender<S> = Sender<StreamMessage<S>>;
pub type StreamReceiver<S> = Receiver<StreamMessage<S>>;
