mod server;
use quinn::{RecvStream, SendStream};
pub use server::Server;
mod client;
pub use client::Client;
mod tunnel_message;
pub use tunnel_message::{LoginInfo, TunnelMessage};
mod access_server;
mod tunnel;
pub use tunnel::Tunnel;
mod util;
pub use access_server::AccessServer;
use byte_pool::BytePool;
use colored::Colorize;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate colored;
extern crate pretty_env_logger;

pub type BufferPool = Arc<BytePool<Vec<u8>>>;

fn new_buffer_pool() -> BufferPool {
    Arc::new(BytePool::<Vec<u8>>::new())
}

#[derive(Debug)]
pub enum TunnelType {
    Out((quinn::NewConnection, SocketAddr)),
    In((quinn::NewConnection, AccessServer, ControlStream)),
}

#[derive(Debug)]
pub struct ControlStream {
    pub quic_send: SendStream,
    pub quic_recv: RecvStream,
}

#[derive(Debug, Default)]
pub struct ClientConfig {
    pub local_access_server_addr: Option<SocketAddr>,
    pub cert_path: String,
    pub server_addr: String,
    pub connect_max_retry: usize,
    pub wait_before_retry_ms: u64,
    pub max_idle_timeout_ms: u64,
    pub keep_alive_interval_ms: u64,
    pub login_msg: Option<TunnelMessage>,
    pub loglevel: String,
    pub mode: &'static str,
}

#[derive(Default, Debug)]
pub struct ServerConfig {
    pub addr: String,
    pub password: String,
    pub cert_path: String,
    pub key_path: String,

    /// traffics to the rstun server will be relayed to servers
    /// specified by downstreams, client must specify a target
    /// downstream when it connects to the rstun server in OUT mode.
    pub downstreams: Vec<SocketAddr>,

    /// 0.0.0.0:3515
    pub dashboard_server: String,
    /// user:password
    pub dashboard_server_credential: String,
}

pub(crate) enum ReadResult {
    Succeeded,
    EOF,
}

impl ReadResult {
    #![allow(dead_code)]
    pub fn is_eof(&self) -> bool {
        if let Self::EOF = self {
            true
        } else {
            false
        }
    }
}

pub struct LogHelper {}
impl LogHelper {
    pub fn init_logger(loglevel_filter_str: &str) {
        let loglevel_filter;
        match loglevel_filter_str.as_ref() {
            "D" => loglevel_filter = log::LevelFilter::Debug,
            "I" => loglevel_filter = log::LevelFilter::Info,
            "W" => loglevel_filter = log::LevelFilter::Warn,
            "E" => loglevel_filter = log::LevelFilter::Error,
            _ => loglevel_filter = log::LevelFilter::Trace,
        }

        pretty_env_logger::formatted_timed_builder()
            .format(|buf, record| {
                let level = record.level();
                let level = match level {
                    log::Level::Trace => "T".white(),
                    log::Level::Debug => "D".green(),
                    log::Level::Info => "I".blue(),
                    log::Level::Warn => "W".yellow(),
                    log::Level::Error => "E".red(),
                };
                let filename = record.file().unwrap_or("unknown");
                let filename = &filename[filename.rfind('/').map(|pos| pos + 1).unwrap_or(0)..];
                writeln!(
                    buf,
                    "{} [{}:{}] [{}] - {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S.%3f"),
                    filename,
                    record.line().unwrap_or(0),
                    level,
                    record.args()
                )
            })
            .filter(Some("rstun"), loglevel_filter)
            .init();
    }
}
