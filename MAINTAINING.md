# Maintaining the DNSalsa connector

- **New version:** raise `VERSION` and add a line to `CHANGELOG.md`. On the push to `main`, `.github/workflows/publish.yml` runs the tests and publishes `ghcr.io/dnsalsa/connector` with tags `<version>`, `<major.minor>` and `latest`. A push without a new version publishes nothing; *Actions → Publish → Run workflow* publishes the current version again.
- **Test before a release:** a push to `dev` publishes `ghcr.io/dnsalsa/connector:dev` every time (never `latest`). Set `image: ghcr.io/dnsalsa/connector:dev` in a test `compose.yaml`. Merging to `main` with a new `VERSION` is the release.
- **Dynamic DNS needs the server:** 1.1.0 uses `/api/ip`, `ipv4=none` / `ipv6=none` and pairing with `mode: "ddns"`. Deploy the DNSalsa server with those before releasing.
- **New cloudflared:** every Monday `.github/workflows/cloudflared.yml` checks for a new release and opens a pull request with the new version, both SHA-256 checksums (checked against Cloudflare's release notes) and a new `VERSION`. Merging it publishes the image. Keep the same cloudflared version in `DNSalsa/dnsalsa` and `DNSalsa/dnsalsa-ha`.
- **Base image:** `alpine:3.23` in the `Dockerfile`; raise it now and then.
- **Tests:** `python3 -m unittest discover -s tests` (standard library only). GitHub Actions runs them on every push and pull request, and builds and starts the image.
- **Run without Docker:** `DNSALSA_DATA=/tmp/d DNSALSA_SERVER=https://staging.dnsalsa.nl python3 app/main.py`, then open http://127.0.0.1:8099.
- **Pairing API:** `POST /api/pair/start` with `kind: "connector"` and `ddns: true`, then `/api/pair/poll`; the dashboard claims the code with the route, or with `mode: "ddns"` for dynamic DNS (the poll then returns an update token). See the README of `DNSalsa/dnsalsa`.
