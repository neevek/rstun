#[derive(Default, Clone)]
pub struct ClientConfig {
    pub cert_path: String,
    pub server_addr: String,
    pub local_access_server_addr: String,
    pub remote_downstream_name: String,
    pub password: String,
}
