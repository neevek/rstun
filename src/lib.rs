pub mod server_config;
pub use server_config::ServerConfig;
pub mod client_config;
pub use client_config::ClientConfig;
mod server;
pub use server::Server;
mod client;
pub use client::Client;
mod access_server;
pub use access_server::AccessServer;

use colored::Colorize;
use std::io::Write;
extern crate colored;
extern crate pretty_env_logger;

#[macro_use]
extern crate serde_derive;
extern crate bincode;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub(crate) enum TunnelType {
    Forward(ForwardLoginInfo),
    Reverse(ReverseLoginInfo),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct ForwardLoginInfo {
    password: String,
    remote_downstream_name: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct ReverseLoginInfo {
    password: String,
    remote_upstream_port: u16,
    allow_public_access: bool,
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
