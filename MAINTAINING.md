# Maintaining the DNSalsa connector

- **New version:** raise `VERSION` and add a line to `CHANGELOG.md`. On the push to `main`, `.github/workflows/publish.yml` runs the tests and publishes `ghcr.io/dnsalsa/connector` with tags `<version>`, `<major.minor>` and `latest`. A push without a new version publishes nothing; *Actions → Publish → Run workflow* publishes the current version again.
- **New cloudflared:** every Monday `.github/workflows/cloudflared.yml` checks for a new release and opens a pull request with the new version, both SHA-256 checksums (checked against Cloudflare's release notes) and a new `VERSION`. Merging it publishes the image. Keep the same cloudflared version in `DNSalsa/dnsalsa` and `DNSalsa/dnsalsa-ha`.
- **Base image:** `alpine:3.23` in the `Dockerfile`; raise it now and then.
- **Tests:** `python3 -m unittest discover -s tests` (standard library only). GitHub Actions runs them on every push and pull request, and builds and starts the image.
- **Run without Docker:** `DNSALSA_DATA=/tmp/d DNSALSA_SERVER=https://staging.dnsalsa.nl python3 app/main.py`, then open http://127.0.0.1:8099.
- **Pairing API:** `POST /api/pair/start` with `kind: "connector"`, then `/api/pair/poll`; the dashboard claims the code with the route. See the README of `DNSalsa/dnsalsa`.
