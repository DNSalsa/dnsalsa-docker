# DNSalsa connector: cloudflared plus a small pairing page, nothing else.
# Published as ghcr.io/dnsalsa/connector by .github/workflows/publish.yml. Or build it yourself:
#   docker build -t dnsalsa-connector https://github.com/DNSalsa/dnsalsa-docker.git#main
FROM alpine:3.23

ARG TARGETARCH
# cloudflared from Cloudflare's GitHub releases, checked against a pinned checksum.
# Updated by .github/workflows/cloudflared.yml (a pull request every time Cloudflare releases a new version).
ARG CLOUDFLARED_VERSION=2026.11.0

RUN apk add --no-cache python3 ca-certificates curl \
 && case "${TARGETARCH}" in \
      amd64) ARCH=amd64; SUM=51f7c68b57ed7269164075d7e789efce5b59355982f06392deeb037d982a51fd ;; \
      arm64) ARCH=arm64; SUM=abe54a006acf9faf2d19ee9d953cb0d0804e92f59c5382a162e57b84d086f56f ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}"; exit 1 ;; \
    esac \
 && curl -fsSL -o /usr/local/bin/cloudflared \
      "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-${ARCH}" \
 && echo "${SUM}  /usr/local/bin/cloudflared" | sha256sum -c - \
 && chmod +x /usr/local/bin/cloudflared \
 && apk del curl \
 && adduser -D -H -u 1000 dnsalsa \
 && mkdir /data && chown dnsalsa:dnsalsa /data

COPY app /app

ENV DNSALSA_DATA=/data
USER dnsalsa
VOLUME /data
EXPOSE 8099
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8099/status',timeout=3)"
CMD ["python3", "-u", "/app/main.py"]
