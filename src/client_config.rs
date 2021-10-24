#[derive(Default, Clone)]
pub struct ClientConfig {
    pub cert_path: String,
    pub server_addr: String,
    pub local_access_server_addr: String,
    pub remote_downstream_name: String,
    pub password: String,
    pub connect_max_retry: usize,
    pub wait_before_retry_ms: u64,
    pub max_idle_timeout_ms: u64,
    pub keep_alive_interval_ms: u64,
}
