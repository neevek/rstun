# rstun

`rstun` is a Rust TCP/UDP tunnel over QUIC (TLS 1.3), built on top of
[quinn](https://github.com/quinn-rs/quinn).

It provides:

- `rstun server`: server mode
- `rstun client`: client mode
- `rstun` library APIs (including event streaming and channel-based tunneling)

## What It Does

- Runs one long-lived QUIC connection per configured tunnel mapping.
- Supports both TCP and UDP.
- Supports two mapping modes:
  - `OUT`: client listens locally, server forwards to upstream target.
  - `IN`: server listens publicly, client forwards to its local target.
- Reconnects automatically when a tunnel drops.
- Sends heartbeat probes (configurable, can be disabled).
- Can periodically rebind the client UDP socket (`--hop-interval-ms`) for endpoint migration.

## Tunnel Mapping Format

Client mappings use:

```text
MODE^[ip:]port^[ip:]port
```

Where:

- `MODE` is `OUT` or `IN`
- field 2 is the client-side local address
- field 3 is the server-side address (or `ANY` for `OUT`)

Behavior by mode:

| Mode | Client field 2 | Client field 3 | Result |
| --- | --- | --- | --- |
| `OUT` | local listen addr on client | upstream addr on server (`ANY` allowed) | local client traffic is sent through server to upstream |
| `IN` | local target addr on client | server listen addr | traffic accepted by server is sent back to client target |

Rules enforced by code:

- At least one of `--tcp-mappings` or `--udp-mappings` must be non-empty.
- `ANY` is only meaningful in field 3 for `OUT`; it uses server default upstream (`--tcp-upstream` / `--udp-upstream`).
- If an address is a bare port (for example `8080`), it is interpreted as `127.0.0.1:8080`.
- For `IN`, server-side address must be explicit and must use loopback/unspecified IP (or bare port).

## Quick Start

### Simplest local test (auto-generated self-signed certificate)

This is the shortest way to run `rstun` locally for a quick smoke test.

```sh
# terminal 1
cargo run --bin rstun -- server -a 3515 -p 1234 -t 8080

# terminal 2
cargo run --bin rstun -- client -a 127.0.0.1:3515 -p 1234 -t "OUT^9000^ANY"
```

Then send traffic to `127.0.0.1:9000`; it will be forwarded to server upstream `127.0.0.1:8080`.

Important:

- This works without `--cert/--key` because server auto-generates a cert for `localhost`.
- The client connects using an IP (`127.0.0.1`), which uses the code's insecure test verifier path when no `--cert` is supplied.
- Use this only for local testing.

### 1. Generate a local cert/key (for testing)

```sh
./gen_cert_and_key.sh localhost
```

### 2. Start server

```sh
cargo run --bin rstun -- server \
  -a 0.0.0.0:3515 \
  -p devpass \
  -c localhost.crt.pem \
  -k localhost.key.pem \
  -t 127.0.0.1:8080 \
  -u 127.0.0.1:5353
```

### 3. Start client (OUT examples)

```sh
cargo run --bin rstun -- client \
  -a localhost:3515 \
  -p devpass \
  -c localhost.crt.pem \
  -t "OUT^127.0.0.1:1080^ANY" \
  -u "OUT^127.0.0.1:1053^ANY"
```

This uses server defaults (`-t` / `-u`) because `ANY` is specified.

### 4. Start client (IN example)

```sh
cargo run --bin rstun -- client \
  -a localhost:3515 \
  -p devpass \
  -c localhost.crt.pem \
  -t "IN^127.0.0.1:3000^0.0.0.0:18080"
```

Connections to `server:18080` are forwarded to `client:3000`.

## TLS and Certificate Behavior

Server:

- If `--cert` is empty, server auto-generates a self-signed certificate for `localhost` (testing only).
- If `--cert` is set, `--key` must point to a compatible PEM private key.

Client:

- If `--cert` is provided, certificates are loaded from PEM and used as trust roots.
- If `--cert` is empty and `--server-addr` is a domain, platform certificate verification is used.
- If `--cert` is empty and `--server-addr` is an IP:port, certificate verification is disabled (warning is logged; testing only).

Supported ciphers:

- `chacha20-poly1305` (default)
- `aes-256-gcm`
- `aes-128-gcm`

## Connection Lifecycle and Reliability

- Client retries connection with exponential backoff until stopped.
- One bidirectional stream is used for login and heartbeat.
- Data is multiplexed through additional bidirectional QUIC streams:
  - TCP: one QUIC stream per accepted TCP connection.
  - UDP: stream-per-peer style handling with timeout-based cleanup.
- Heartbeat failure closes connection and triggers reconnect.
- Traffic statistics are emitted every 30 seconds.

## Observability

The client exposes an internal event bus (`register_for_events`) that emits JSON-serializable events:

- tunnel state (`connecting`, `connected`, `tunneling`)
- tunnel logs
- traffic counters (bytes, datagrams, packet loss, RTT, congestion data)

## Build and Run

```sh
cargo build
cargo run --bin rstun -- --help
cargo run --bin rstun -- server --help
cargo run --bin rstun -- client --help
cargo test
```

Important option groups:

- `rstun server`: `--addr`, `--password`, `--tcp-upstream`, `--udp-upstream`, `--cert`, `--key`
- `rstun client`: `--server-addr`, `--password`, `--tcp-mappings`, `--udp-mappings`, `--cert`, `--cipher`
- timeouts: `--quic-timeout-ms`, `--tcp-timeout-ms`, `--udp-timeout-ms`
- heartbeat (client): `--heartbeat-interval-ms`, `--heartbeat-timeout-ms`
- client DNS resolution hints: `--dot`, `--dns`
- client endpoint migration: `--hop-interval-ms` (minimum effective value is 5000 ms when enabled)

## License

MIT. See `LICENSE`.
