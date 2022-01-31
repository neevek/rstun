rstun
=====

A UDP secured tunnel written in Rust.

rstun builds on [quinn](https://github.com/quinn-rs/quinn), which is an implementation of the IETF [QUIC](https://quicwg.org/) transport protocol.

rstun consists of two binaries, `rstunc` for client and `rstund` for daemon. `rstund` accepts connections from `rstunc`.

`rstunc` connects to the daemon to build a secured tunnel to allow data to be exchanged between two ends, `rstunc` initiates the connection in one of two modes (IN and OUT):

  * The IN mode is used for exposing a local port to the internet through the daemon.
  * The OUT mode is used for securing data going out from local to the internet through the daemon.

... DOC to be continued
