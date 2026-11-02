# DNSalsa connector: cloudflared plus a small pairing page, nothing else.
# Published as ghcr.io/dnsalsa/connector by .github/workflows/publish.yml. Or build it yourself:
#   docker build -t dnsalsa-connector https://github.com/DNSalsa/dnsalsa-docker.git#main
FROM alpine:3.23

ARG TARGETARCH
# cloudflared from Cloudflare's GitHub releases, checked against a pinned checksum.
# Updated by .github/workflows/cloudflared.yml (a pull request every time Cloudflare releases a new version).
ARG CLOUDFLARED_VERSION=2026.10.7

RUN apk add --no-cache python3 ca-certificates curl \
 && case "${TARGETARCH}" in \
      amd64) ARCH=amd64; SUM=1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872 ;; \
      arm64) ARCH=arm64; SUM=3df43aedc9ff291d1735b5cb576cb97e0b157488796db2e32b28aecabb445775 ;; \
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
