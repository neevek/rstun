pub mod server_config;
use quinn::Read;
pub use server_config::ServerConfig;
pub mod client_config;
pub use client_config::ClientConfig;
mod session;
pub use session::Session;
mod server;
pub use server::Server;
mod client;
pub use client::Client;
mod access_server;
pub use access_server::AccessServer;

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
    pub fn is_eof(&self) -> bool {
        if let Self::EOF = self {
            true
        } else {
            false
        }
    }
}
