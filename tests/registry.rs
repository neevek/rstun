//! Integration test for the generic registry: two clients register an opaque
//! (key, value) at a loopback server and one lists the roster and sees the
//! other. Also covers the `registry_validator` rejection path. Exercises the
//! `Tunnel::Registry` login path, the server roster, and the `RegistrySession`
//! client API end to end over real QUIC on loopback.

use rstun::{Client, ClientConfig, RegistryValidator, Server, ServerConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn server_config(addr: &str, password: &str, validator: Option<RegistryValidator>) -> ServerConfig {
    ServerConfig {
        addr: addr.to_string(),
        password: password.to_string(),
        cert_path: String::new(),
        key_path: String::new(),
        quic_timeout_ms: 30_000,
        tcp_timeout_ms: 30_000,
        udp_timeout_ms: 30_000,
        quic_receive_window: 0,
        stream_receive_window: 0,
        quic_send_window: 0,
        default_tcp_upstream: None,
        default_udp_upstream: None,
        channel_tcp_connector: None,
        channel_udp_connector: None,
        registry_validator: validator,
        dashboard_server: String::new(),
        dashboard_server_credential: String::new(),
    }
}

fn client(server_addr: &str, password: &str) -> Client {
    let cfg = ClientConfig {
        server_addr: server_addr.to_string(),
        password: password.to_string(),
        cipher: "chacha20-poly1305".to_string(),
        quic_timeout_ms: 30_000,
        ..Default::default()
    };
    Client::new(cfg)
}

fn start_server(server: Server) -> std::net::SocketAddr {
    let mut server = server;
    server.bind().expect("bind");
    let addr = server.local_addr().expect("local_addr");
    let server = Arc::new(server);
    {
        let s = server.clone();
        tokio::spawn(async move {
            s.serve().await.ok();
        });
    }
    addr
}

#[tokio::test]
async fn two_clients_register_and_list() {
    let password = "test-secret";
    let addr = start_server(Server::new(server_config("127.0.0.1:0", password, None)));
    let server_addr = addr.to_string();

    // Client A registers key "alice" with an opaque value.
    let client_a = client(&server_addr, password);
    let mut session_a = client_a.registry_connect().await.expect("A connect");
    session_a
        .register("alice".into(), b"value-a".to_vec())
        .await
        .expect("A register");

    // Client B registers key "bob".
    let client_b = client(&server_addr, password);
    let mut session_b = client_b.registry_connect().await.expect("B connect");
    session_b
        .register("bob".into(), b"value-b".to_vec())
        .await
        .expect("B register");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let entries = session_a.list().await.expect("A list");

    // A sees B (with B's opaque value) but not itself.
    let bob = entries.iter().find(|e| e.key == "bob");
    assert!(bob.is_some(), "expected to see bob in {entries:?}");
    assert_eq!(bob.unwrap().value, b"value-b");
    assert!(
        !entries.iter().any(|e| e.key == "alice"),
        "listing must exclude the requester"
    );
}

#[tokio::test]
async fn validator_can_reject_registration() {
    let password = "test-secret";
    // Reject any registration whose value isn't exactly b"ok".
    let validator: RegistryValidator = Arc::new(|_key, value| {
        if value == b"ok" {
            Ok(())
        } else {
            anyhow::bail!("nope")
        }
    });
    let addr = start_server(Server::new(server_config(
        "127.0.0.1:0",
        password,
        Some(validator),
    )));
    let server_addr = addr.to_string();

    let mut accepted = client(&server_addr, password)
        .registry_connect()
        .await
        .expect("connect");
    assert!(
        accepted.register("a".into(), b"ok".to_vec()).await.is_ok(),
        "valid registration should be accepted"
    );

    let mut rejected = client(&server_addr, password)
        .registry_connect()
        .await
        .expect("connect");
    assert!(
        rejected
            .register("b".into(), b"bad".to_vec())
            .await
            .is_err(),
        "validator should reject the registration"
    );
}

#[tokio::test]
async fn relay_pipes_bytes_between_two_clients() {
    let password = "test-secret";
    let addr = start_server(Server::new(server_config("127.0.0.1:0", password, None)));
    let server_addr = addr.to_string();

    // B registers and serves one inbound relay (echo).
    let mut session_b = client(&server_addr, password)
        .registry_connect()
        .await
        .expect("B connect");
    session_b
        .register("bob".into(), b"vb".to_vec())
        .await
        .expect("B register");
    let mut incoming_b = session_b.take_incoming().expect("incoming receiver");
    let echo = tokio::spawn(async move {
        let mut inc = incoming_b.recv().await.expect("inbound relay");
        assert_eq!(inc.from_key, "alice");
        assert_eq!(inc.header, b"hi-header");
        let mut buf = [0u8; 5];
        inc.stream.read_exact(&mut buf).await.expect("read");
        inc.stream.write_all(&buf).await.expect("echo");
        inc.stream.flush().await.expect("flush");
        // hold the pipe open until the reader has consumed the echo
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    // A registers and opens a relay to B, expecting its bytes echoed back.
    let mut session_a = client(&server_addr, password)
        .registry_connect()
        .await
        .expect("A connect");
    session_a
        .register("alice".into(), b"va".to_vec())
        .await
        .expect("A register");
    let mut stream = session_a
        .relay_handle()
        .open_relay("bob", b"hi-header".to_vec())
        .await
        .expect("open relay");
    stream.write_all(b"hello").await.expect("write");
    stream.flush().await.expect("flush");
    let mut back = [0u8; 5];
    stream.read_exact(&mut back).await.expect("read echo");
    assert_eq!(&back, b"hello");

    echo.await.ok();
    // keep B's session alive until the relay completed
    drop(session_b);
}

#[tokio::test]
async fn whats_my_addr_returns_observed_address() {
    let password = "test-secret";
    let addr = start_server(Server::new(server_config("127.0.0.1:0", password, None)));
    let server_addr = addr.to_string();

    let mut session = client(&server_addr, password)
        .registry_connect()
        .await
        .expect("connect");
    let observed = session.whats_my_addr().await.expect("whats_my_addr");
    // The client connected from loopback, so the server observes a 127.0.0.1
    // source with an ephemeral port.
    assert!(
        observed.ip().is_loopback(),
        "expected loopback, got {observed}"
    );
    assert_ne!(observed.port(), 0, "expected a real ephemeral port");
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let addr = start_server(Server::new(server_config(
        "127.0.0.1:0",
        "right-password",
        None,
    )));
    let result = client(&addr.to_string(), "wrong-password")
        .registry_connect()
        .await;
    assert!(result.is_err(), "wrong password must be rejected");
}
