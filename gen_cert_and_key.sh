#!/bin/bash

domain=$1
if [[ $domain = "" ]]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

openssl req \
    -newkey rsa:2048 \
    -x509 \
    -nodes \
    -keyout $domain.key.pem \
    -new \
    -out $domain.crt.pem \
    -subj /CN=$domain \
    -reqexts SAN \
    -extensions SAN \
    -config <(cat /System/Library/OpenSSL/openssl.cnf \
        <(printf '[SAN]\nsubjectAltName=DNS:localhost')) \
    -sha256 \
    -days 3650
