#!/bin/bash

in_key=$1
out_key=$2
if [[ $1 = "" ]] || [[ $2 = "" ]]; then
  echo "Usage: $0 <EC_KEY_FILE> <PKCS8_KEY_FILE>"
  exit 1
fi

openssl pkcs8 -topk8 -nocrypt -in "$in_key" -out "$out_key"
