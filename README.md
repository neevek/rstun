rstun
=====

A secured UDP tunnel written in Rust.

rstun builds on [Quinn](https://github.com/quinn-rs/quinn), which is an implementation of the IETF [QUIC](https://quicwg.org/) transport protocol.

rstun consists of two binaries, `rstunc` for client and `rstund` for server. `rstund` accepts connections from `rstunc`.

`rstunc` connects to the server to build a secured tunnel to allow data to be exchanged between two ends, it initiates the connection in one of two modes:

  * The TunnelIn mode for exposing a local port to the internet through the server.
  * The TunnelOut mode for securing data going out from local to the internet through the server.

All data going through the tunnel is secured by the builtin TLS layer of the QUIC protocol, when the negotiation of the connection completes and a tunnel is built, QUIC streams can be initiated from both ends, for the TunnelOut mode, streams are initiated from the client, and for the IN mode, it is just the opposite.

Usage
-----

* Start the server

```
rstund \
  --addr 0.0.0.0:6060 \
  --downstream 8800 \
  --password 123456 \
  --cert path/to/certificate.der \
  --key path/to/priv_key.der
```
`addr` specifies the ip:port that the server is listening on, `downstream` specifies a TCP port which traffic from the client through the tunnel will be relayed to, this is applicable for TunnelOut mode tunnels only. For `cert` and `key`, the requirement is that they must be in DER format, I use a self signed certificate for testing. Note currently the certificate is checked bytewise by the client, that is why the same certificate must be specified for the client.

* Start the client
```
rstunc
  --mode TunnelOut \
  --server-addr 1.2.3.4:6060 \
  --password 123456 \
  --cert path/to/certificate.der \
  --addr-mapping 0.0.0.0:9900^8800
```
For the arguments, I think only `addr-mapping` needs some explanation, this is an address mapping between two ip:port pairs separated by the `^` character, the format is `[ip:]port^[ip:]port`, in the example above, a local port `9900` is mapped to the remote port `8800` of the `1.2.3.4` host that runs `rstund`.

License
-------

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.
