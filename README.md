rstun
=====

A secured UDP tunnel written in Rust.

rstun builds on [Quinn](https://github.com/quinn-rs/quinn), which is an implementation of the IETF [QUIC](https://quicwg.org/) transport protocol.

rstun consists of two binaries, `rstunc` for client and `rstund` for server. `rstund` accepts connections from `rstunc`.

`rstunc` connects to the server to build a secured tunnel to allow data to be exchanged between two ends, it initiates the connection in one of two modes:

  * The `IN` mode for exposing a local port to the internet through the server.
  * The `OUT` mode for securing data going out from local to the internet through the server.

All traffic going through the tunnel is secured by the builtin TLS layer of the QUIC protocol, when the negotiation of the connection completes and a tunnel is built, QUIC streams can be initiated from both ends, for the `OUT` mode, streams are initiated from the client, and for the `IN` mode, it is just the opposite.

Usage
-----

* Start the server

```
rstund \
  --addr 0.0.0.0:6060 \
  --downstreams 8800 \
  --password 123456 \
  --cert path/to/cert.der \
  --key path/to/key.der
```
  - `addr` specifies the ip:port that the server is listening on.
  - `downstreams` specifies a TCP port which traffic from the client through the tunnel will be relayed to on the server, this is applicable for `OUT` mode tunnels only, multiple space-separated downstreams can be set. Note this argument is optional, if it is not specified, all open ports of the server are exposed to the clients through the tunnel. So make sure to specify downstreams if exposing all open ports of the server is not desired.
  - `password`, password of the server, the client `rstunc` is required to send this password to successfully build a tunnel with the server.
  - `cert` and `key` are certificate and private key for the domain of the server and they must be in `DER` format (binary format), self-signed certificate is allowed, but you will have to connect to the server using IP address and the certificate will also be required by `rstunc` for verification in this case (see below). Anyway, getting a certificate for your domain from a trusted CA and connecting to the server using domain name is always recommended. Note `cert` and `key` are optional, if they are not specified, the domain `localhost` is assumed and a self-signed certificate is generated on the fly, but this is for TEST only, Man-In-The-Middle attack can occur with such setting, so make sure **it is only used for TEST**!

* Start the client

```
rstunc
  --mode OUT \
  --server-addr 1.2.3.4:6060 \
  --password 123456 \
  --cert path/to/cert.der \
  --addr-mapping 0.0.0.0:9900^8800
```
  - `mode` here is `OUT` for `TunnelOut`, for securing traffic from local to the server through the tunnel.
  - `server-addr`, a TCP server that runs locally for accepting requests and forwarding all the traffic to the server through the tunnel.
  - `password`, same as that for the server.
  - `cert`, see explanation above for `rstund`. Note this is also optional if connecting to the server with a domain name, or the server `rstund` runs with an auto-generated self-signed certificate (see the TEST example below).
  - `addr-mapping` is an address mapping between two `ip:port` pairs separated by the `^` character, the format is `[ip:]port^[ip:]port`, in the example above, a local port `9900` is mapped to the remote port `8800` of the `1.2.3.4` server that runs `rstund`. i.e. all traffic from the local port `9900` will be forwarded to the remote port `8800` through the tunnel.

* Simple TEST example

The following commands run a server and a client that connects to the server in their simplest ways:


```
# Remote: run the server with auto-generated self-signed certificate
rstund -l 9000 -p 1234

# Local: connect to the server (127.0.0.1:9000) and bind the local port 9900 to remote port 8800
rstunc -m OUT -r 127.0.0.1:9000 -p 1234 -a 0.0.0.0:9900^8800

```

* Complete options for `rstund`

```
rstun 0.4.0

USAGE:
    rstund [OPTIONS] --addr <ADDR> --password <PASSWORD>

OPTIONS:
    -l, --addr <ADDR>
            Address ([ip:]port pair) to listen on

    -d, --downstreams <DOWNSTREAMS>
            Exposed downstreams as the receiving end of the tunnel, e.g. -d [ip:]port, The entire
            local network is exposed through the tunnel if empty

    -p, --password <PASSWORD>
            Password of the tunnel server

    -c, --cert <CERT>
            Path to the certificate file in DER format, if empty, a self-signed certificate with the
            domain "localhost" will be used [default: ]

    -k, --key <KEY>
            Path to the key file in DER format, can be empty if no cert is provided [default: ]

    -t, --threads <THREADS>
            Threads to run async tasks [default: 0]

    -w, --max-idle-timeout-ms <MAX_IDLE_TIMEOUT_MS>
            Max idle timeout for the connection [default: 40000]

    -L, --loglevel <LOGLEVEL>
            [default: I] [possible values: T, D, I, W, E]

    -h, --help
            Print help information

    -V, --version
            Print version information
```

* Complete options for `rstunc`

```
rstun 0.4.0

USAGE:
    rstunc [OPTIONS] --mode <MODE> --server-addr <SERVER_ADDR> --password <PASSWORD> --addr-mapping <ADDR_MAPPING>

OPTIONS:
    -m, --mode <MODE>
            Create a tunnel running in IN or OUT mode [possible values: IN, OUT]

    -r, --server-addr <SERVER_ADDR>
            Address (<domain:ip>[:port] pair) of rstund, default port is 3515

    -p, --password <PASSWORD>
            Password to connect with rstund

    -a, --addr-mapping <ADDR_MAPPING>
            LOCAL and REMOTE mapping in [ip:]port^[ip:]port format, e.g. 8080^0.0.0.0:9090

    -c, --cert <CERT>
            Path to the certificate file in DER format, only needed for self signed certificate
            [default: ]

    -e, --cipher <CIPHER>
            Preferred cipher suite [default: chacha20-poly1305] [possible values: chacha20-poly1305,
            aes-256-gcm, aes-128-gcm]

    -t, --threads <THREADS>
            Threads to run async tasks [default: 0]

    -w, --wait-before-retry-ms <WAIT_BEFORE_RETRY_MS>
            Wait time before trying [default: 5000]

    -i, --max-idle-timeout-ms <MAX_IDLE_TIMEOUT_MS>
            Max idle timeout for the connection [default: 150000]

    -l, --loglevel <LOGLEVEL>
            Log level [default: I] [possible values: T, D, I, W, E]

    -h, --help
            Print help information

    -V, --version
            Print version information
```

License
-------

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.
