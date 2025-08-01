# rstun

A high-performance TCP/UDP tunnel over QUIC, written in Rust.

rstun leverages the [Quinn](https://github.com/quinn-rs/quinn) library for [QUIC](https://quicwg.org/) transport, providing efficient, low-latency, and secure bidirectional communication. All traffic is protected by QUIC's integrated TLS layer.

---

## Features

- **Multiple TCP and UDP tunnels**: Support for running multiple tunnels (TCP and/or UDP) simultaneously in a single client or server instance.
- **Bidirectional tunneling**: Both inbound (IN) and outbound (OUT) modes for flexible deployment.
- **Modern encryption**: Security via QUIC's TLS 1.3 layer, with configurable cipher suites.
- **Automatic or custom certificates**: Use your own certificate/key or let rstun generate a self-signed certificate for testing.
- **Connection migration**: Optional periodic migration of QUIC connection to new random local UDP ports to avoid throttling during long data transfers.
- **Traffic statistics**: Real-time tunnel traffic reporting.

---

## Operating Modes

### Inbound Tunneling (IN Mode)
Expose a local service (e.g., web server) to the public internet securely through the QUIC tunnel. Useful for making services behind NAT/firewall accessible externally.

### Outbound Tunneling (OUT Mode)
Tunnel local outbound traffic through the server, which then forwards it to the specified destination. Commonly used to encrypt and route traffic from a local network to external servers.

---

## Components

- **rstunc** (client): Establishes and manages tunnels to the server.
- **rstund** (server): Accepts incoming connections and forwards TCP/UDP traffic according to configuration.

---

## Example Usage

### Start the server

```sh
rstund \
  --addr 0.0.0.0:6060 \
  --tcp-upstream 8800 \
  --udp-upstream 8.8.8.8:53 \
  --password 123456 \
  --cert path/to/cert.der \
  --key path/to/key.der
```

- `--addr` — IP:port to listen on.
- `--tcp-upstream` — Default TCP upstream for OUT tunnels (if client does not specify one).
- `--udp-upstream` — Default UDP upstream for OUT tunnels (if client does not specify one).
- `--password` — Required for client authentication.
- `--cert`/`--key` — Certificate and private key for the server. If omitted, a self-signed certificate for `localhost` is generated (for testing only).

### Start the client (multiple tunnels example)

```sh
rstunc \
  --server-addr 1.2.3.4:6060 \
  --password 123456 \
  --cert path/to/cert.der \
  --tcp-mappings "OUT^0.0.0.0:9900^8800,IN^127.0.0.1:8080^9000" \
  --udp-mappings "OUT^0.0.0.0:9900^8.8.8.8:53" \
  --hop-interval-ms 30000 \
  --loglevel D
```

- `--tcp-mappings` and `--udp-mappings` now accept **comma-separated lists** of mappings, each in the form `MODE^[ip:]port^[ip:]port` (e.g., `OUT^8000^ANY`).
- `MODE` is either `OUT` or `IN`.
- `ANY` as the destination means the server's default upstream is used.
- `--hop-interval-ms` — Optional parameter to enable connection migration by periodically changing local UDP ports at the specified interval(ms).

#### Simple test

```sh
# Start server with auto-generated self-signed certificate
rstund -a 9000 -p 1234

# Start client with both TCP and UDP tunnels and connection migration every 30 seconds
rstunc \
  --server-addr 127.0.0.1:9000 \
  --password 1234 \
  --tcp-mappings "OUT^0.0.0.0:9900^8800" \
  --udp-mappings "IN^127.0.0.1:8080^9000" \
  --hop-interval-ms 30000
```

---

## Command-Line Options

### rstund (server)

```
Usage: rstund [OPTIONS] --addr <ADDR> --password <PASSWORD>

Options:
  -a, --addr <ADDR>            Address ([ip:]port) to listen on
  -t, --tcp-upstream <ADDR>    Default TCP upstream for OUT tunnels ([ip:]port)
  -u, --udp-upstream <ADDR>    Default UDP upstream for OUT tunnels ([ip:]port)
  -p, --password <PASSWORD>    Server password (required)
  -c, --cert <CERT>            Path to certificate file (optional)
  -k, --key <KEY>              Path to key file (optional)
  -w, --workers <N>            Number of async worker threads [default: 0]
      --quic-timeout-ms <MS>   QUIC idle timeout (ms) [default: 40000]
      --tcp-timeout-ms <MS>    TCP idle timeout (ms) [default: 30000]
      --udp-timeout-ms <MS>    UDP idle timeout (ms) [default: 30000]
  -l, --loglevel <LEVEL>       Log level [default: I] [T, D, I, W, E]
  -h, --help                   Print help
  -V, --version                Print version
```

### rstunc (client)

```
Usage: rstunc [OPTIONS] --server-addr <ADDR> --password <PASSWORD>

Options:
  -a, --server-addr <ADDR>         Server address (<domain:ip>[:port])
  -p, --password <PASSWORD>        Password for server authentication
  -t, --tcp-mappings <MAPPINGS>    Comma-separated list of TCP tunnel mappings (MODE^[ip:]port^[ip:]port)
  -u, --udp-mappings <MAPPINGS>    Comma-separated list of UDP tunnel mappings (MODE^[ip:]port^[ip:]port)
  -c, --cert <CERT>                Path to certificate file (optional)
  -e, --cipher <CIPHER>            Cipher suite [default: chacha20-poly1305] [chacha20-poly1305, aes-256-gcm, aes-128-gcm]
  -w, --workers <N>                Number of async worker threads [default: 0]
  -r, --wait-before-retry-ms <MS>  Wait before retry (ms) [default: 5000]
      --quic-timeout-ms <MS>       QUIC idle timeout (ms) [default: 30000]
      --tcp-timeout-ms <MS>        TCP idle timeout (ms) [default: 30000]
      --udp-timeout-ms <MS>        UDP idle timeout (ms) [default: 5000]
      --hop-interval-ms <MS> Interval in millseconds for connection migration to new random local UDP port (optional,default:0 means disabled)
      --dot <DOT>                  Comma-separated DoT servers for DNS resolution
      --dns <DNS>                  Comma-separated DNS servers for resolution
  -l, --loglevel <LEVEL>           Log level [default: I] [T, D, I, W, E]
  -h, --help                       Print help
  -V, --version                    Print version
```

---

## Connection Migration

The client supports optional connection migration via the `--hop-interval-ms` parameter. When specified, the QUIC connection will periodically migrate to a new random local UDP port at the given interval (in millseconds). This feature helps avoid UDP throttling that may occur during long data transfers while maintaining the upper-layer QUIC connection without interruption.

**Benefits:**
- Prevents UDP port-based rate limiting during extended data transfers
- Maintains seamless connectivity without breaking existing tunnels
- Helps bypass certain network restrictions that may throttle long-lived UDP flows

**Usage:**
- If `--hop-interval-ms` is not specified, connection migration is disabled
- Recommended intervals range from 60 to 600 seconds depending on network conditions
- Shorter intervals provide more frequent migration but may cause brief latency spikes

---

## Notes

- **Multiple tunnels**: You can specify multiple TCP and/or UDP tunnels in a single client or server instance using the new `--tcp-mappings` and `--udp-mappings` options.
- **Mapping format**: Each mapping is `MODE^[ip:]port^[ip:]port`, where `MODE` is `OUT` or `IN`.
- **Self-signed certificates**: If no certificate is provided, a self-signed certificate for `localhost` is generated (for testing only).
- **Security**: For production, always use a valid certificate and connect via domain name.
- **Connection migration**: Use `--hop-interval-ms` to enable periodic port migration for improved performance in environments with UDP throttling.

---

## License

This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, you can obtain one at [http://mozilla.org/MPL/2.0/](http://mozilla.org/MPL/2.0/).
