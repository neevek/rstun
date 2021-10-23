#[derive(Default, Clone)]
pub struct ClientConfig {
    pub addr: String,
    pub password: String,
    pub cert_path: String,
    pub access_server_addr: String,
}
