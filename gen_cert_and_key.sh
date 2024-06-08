#!/bin/bash

domain=$1
if [[ $domain = "" ]]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

openssl_cnf=
platform=$(uname 2> /dev/null)

if [[ "$platform" = "Darwin" ]]; then
    openssl_cnf="/System/Library/OpenSSL/openssl.cnf"
elif [[ "$platform" = "Linux" ]]; then
    openssl_cnf="/etc/ssl/openssl.cnf"
else
    echo "Not supported!"
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
    -config <(cat $openssl_cnf \
        <(printf "[SAN]\nsubjectAltName=DNS:$domain")) \
    -sha256 \
    -days 3650
