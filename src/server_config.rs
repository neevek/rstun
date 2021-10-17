use std::collections::HashMap;
use std::net::SocketAddr;

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
    pub upstreams: HashMap<String, SocketAddr>,

    /// 0.0.0.0:3515
    pub dashboard_server: String,
    /// user:password
    pub dashboard_server_credential: String,
}
