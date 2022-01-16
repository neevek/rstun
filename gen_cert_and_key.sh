# 1. generate rstun.key and rstun.crt

openssl req \
    -newkey rsa:2048 \
    -x509 \
    -nodes \
    -keyout rstun.key \
    -new \
    -out rstun.crt \
    -subj /CN=localhost \
    -reqexts SAN \
    -extensions SAN \
    -config <(cat /System/Library/OpenSSL/openssl.cnf \
        <(printf '[SAN]\nsubjectAltName=DNS:localhost')) \
    -sha256 \
    -days 3650

# 2. convert rstun.crt to DER format

openssl x509 -outform DER -in rstun.crt -out rstun_cert.der

# 3. convert rstun.key to DER format

openssl rsa -in rstun.key -outform DER -out rstun_key.der
