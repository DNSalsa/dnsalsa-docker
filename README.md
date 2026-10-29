# DNSalsa connector

Put a service in your network online at your own dnsalsa.nl address: a NAS, a server, Home Assistant without apps. No port forwarding, and your home IP stays hidden. A small Docker container runs the tunnel and pairs with your [DNSalsa](https://dnsalsa.nl) account by a code, so you never copy a token. You need a DNSalsa account with the Remote subscription.

Running Home Assistant OS or Supervised? Use the [DNSalsa app](https://github.com/DNSalsa/dnsalsa-ha) instead.

## Install

1. In your [DNSalsa dashboard](https://dnsalsa.nl/dashboard): hostname → **Setup → Cloudflare Tunnel**. Enter the route, the service as the container sees it, and press *Create tunnel*. For example:
   - a NAS: `https://192.168.1.10:5001` (tick *Skip TLS verification* for a self-signed certificate)
   - Home Assistant on another machine: `http://192.168.1.20:8123`
   - a service on the machine that runs the connector: `http://host.docker.internal:8123`
2. Save [`compose.yaml`](compose.yaml) in an empty folder on a machine in your network and run `docker compose up -d`.
3. Open http://127.0.0.1:8099 on that machine, or run `docker logs dnsalsa-connector`. It shows a code like `K7QP-4XM2`.
4. In the dashboard, choose **DNSalsa connector** and enter the code. Within a few seconds the connector starts the tunnel, and your address works.

Change the route later in the dashboard; the connector follows without pairing again. *Pair again* on the page connects it to another hostname or account.

## Home Assistant behind the route

The connector notices when the route leads to Home Assistant and checks whether Home Assistant accepts traffic from the tunnel. If not, the page shows the steps: **Settings → System → Network → HTTP Server → Reverse proxy**, turn on *Trust X-Forwarded-For* and add the trusted proxy. In `configuration.yaml`:

```yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 172.30.57.0/24   # Home Assistant on the same machine as the connector
```

Home Assistant on another machine sees the traffic come from the LAN IP of the machine running the connector. Put that IP in `trusted_proxies` and in `DNSALSA_TRUSTED_PROXY` in `compose.yaml`, so the page shows the right address.

## Updates

| Tag | What you get |
|---|---|
| `latest` | Every new version (default in `compose.yaml`) |
| `1.0` | New 1.0.x versions only |
| `1.0.0` | Exactly this version |

Update with `docker compose pull && docker compose up -d`. Changes are in [`CHANGELOG.md`](CHANGELOG.md). Images for amd64 and arm64 (Raspberry Pi 4 and 5, most NAS models). Build it yourself instead: `docker build -t dnsalsa-connector https://github.com/DNSalsa/dnsalsa-docker.git#main`.

## Settings

| Variable | Default | What it does |
|---|---|---|
| `DNSALSA_TRUSTED_PROXY` | empty | Address shown in the Home Assistant steps |
| `DNSALSA_NAME` | container hostname | Name shown in the dashboard when you enter the code |
| `DNSALSA_PORT` | `8099` | Port of the page |

The state (the tunnel token) lives in the `dnsalsa-connector` volume, readable only by the container's user. Remove the volume to forget the pairing.

## Fonts

The page uses Space Grotesk and Space Mono (`app/fonts/`), both under the SIL Open Font License 1.1.
