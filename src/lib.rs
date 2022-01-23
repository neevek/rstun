mod server;
pub use server::Server;
mod client;
pub use client::Client;
mod access_server;
pub use access_server::AccessServer;
use enum_as_inner::EnumAsInner;
use std::{collections::HashMap, net::SocketAddr};

use colored::Colorize;
use std::io::Write;
extern crate colored;
extern crate pretty_env_logger;

#[macro_use]
extern crate serde_derive;
extern crate bincode;

#[derive(EnumAsInner, Serialize, Deserialize, Debug, PartialEq)]
pub enum TunnelMessage {
    InLoginRequest(LoginInfo),
    OutLoginRequest(LoginInfo),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LoginInfo {
    pub password: String,
    pub access_server_addr: String, // ip:port tuple
}

#[derive(Debug)]
pub enum TunnelType {
    Out((quinn::NewConnection, SocketAddr)),
    In((quinn::NewConnection, AccessServer)),
}

#[derive(Debug, Default)]
pub struct ClientConfig {
    pub local_access_server_addr: String,
    pub cert_path: String,
    pub server_addr: String,
    pub connect_max_retry: usize,
    pub wait_before_retry_ms: u64,
    pub max_idle_timeout_ms: u64,
    pub keep_alive_interval_ms: u64,
    pub login_msg: Option<TunnelMessage>,
    pub loglevel: String,
}

#[derive(Default, Debug)]
pub struct ServerConfig {
    pub addr: String,
    pub password: String,
    pub cert_path: String,
    pub key_path: String,

    /// name1=127.0.0.1:8080,name2=192.168.0.101:8899
    /// traffics to the rstun server will be relayed to servers
    /// specified by upstreams, each client must specify a target
    /// server when it connects to the rstun server.
    pub downstreams: HashMap<String, String>,

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
