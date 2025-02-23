#!/bin/bash

domain_or_ip=$1
if [[ -z $domain_or_ip ]]; then
  echo "usage: $0 <domain or ip>"
  exit 1
fi

openssl_cnf=
platform=$(uname 2> /dev/null)

if [[ "$platform" = "Darwin" ]]; then
    openssl_cnf="/System/Library/OpenSSL/openssl.cnf"
elif [[ "$platform" = "Linux" ]]; then
    openssl_cnf="/etc/ssl/openssl.cnf"
else
    echo "not supported!"
    exit 1
fi

if [[ $domain_or_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || $domain_or_ip =~ : ]]; then
    san_type="IP"
else
    san_type="DNS"
fi

openssl req \
    -newkey rsa:2048 \
    -x509 \
    -nodes \
    -keyout $domain_or_ip.key.pem \
    -new \
    -out $domain_or_ip.crt.pem \
    -subj /CN=$domain_or_ip \
    -reqexts san \
    -extensions san \
    -config <(cat $openssl_cnf \
        <(printf "[san]\nsubjectAltName=$san_type:$domain_or_ip")) \
    -sha256 \
    -days 3650
