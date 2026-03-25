# syntax=docker/dockerfile:1.7

FROM alpine:latest AS downloader

ARG RSTUN_REPO=neevek/rstun
ARG RSTUN_VERSION=latest

RUN apk add --no-cache curl libarchive-tools

RUN set -eu; \
    arch="$(uname -m)"; \
    case "${arch}" in \
      x86_64) filename="rstun-x86_64-unknown-linux-musl.tar.gz" ;; \
      aarch64) filename="rstun-aarch64-unknown-linux-musl.tar.gz" ;; \
      *) echo "unsupported architecture: ${arch}" >&2; exit 1 ;; \
    esac; \
    if [ "${RSTUN_VERSION}" = "latest" ]; then \
      tar_url="https://github.com/${RSTUN_REPO}/releases/latest/download/${filename}"; \
    else \
      tar_url="https://github.com/${RSTUN_REPO}/releases/download/${RSTUN_VERSION}/${filename}"; \
    fi; \
    curl -fsSL "${tar_url}" -o /tmp/rstun.tar.gz; \
    bsdtar -xf /tmp/rstun.tar.gz -C /tmp; \
    bin="$(find /tmp -maxdepth 3 -type f -name rstun | head -n1)"; \
    if [ -z "${bin}" ]; then \
      echo "rstun binary not found in release asset" >&2; \
      exit 1; \
    fi; \
    install -m 0755 "${bin}" /out/rstun

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=downloader /out/rstun /usr/local/bin/rstun
ENTRYPOINT ["rstun"]
CMD ["--help"]
