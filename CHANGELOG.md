# Changelog

## 1.2.0

- Security: the page only shows the pairing code and the buttons to someone this machine trusts. Whoever enters that code in their own DNSalsa account decides where the connector sends traffic, so a code seen by someone else on your network could open your network to them.
  - New `DNSALSA_PASSWORD`: with it, the page shows a login with just that password and works from any device. Set it when you open the page from other devices, as in the TrueNAS app.
  - Without a password, only `localhost` and `127.0.0.1` (plus names in `DNSALSA_HOSTS`) get the code. Other devices see the state but not the code.
  - New `dnsalsa` command in the container: `dnsalsa code`, `dnsalsa status` and `dnsalsa unpair`. In TrueNAS: the app's Shell.
  - The page refuses requests for other host names, which stops DNS rebinding from a website, and buttons need a header that other sites can't send. The page can't be framed.

## 1.1.5

- cloudflared 2026.11.0.

## 1.1.4

- While it waits for pairing, the page updates in place instead of reloading every 4 seconds: no flash, and much less data.

## 1.1.3

- A **Copy** button next to the pairing code.

## 1.1.2

- Clearer pairing steps: step 2 explains what the route is, with an example for a service on another machine and one on this machine.

## 1.1.1

- cloudflared 2026.10.7.

## 1.1.0

- Dynamic DNS without a tunnel, also on a free DNSalsa account. Pair under **Setup → Dynamic DNS → DNSalsa connector** in the dashboard, and the connector keeps your hostname on your home address: it looks up your IPv4 and IPv6 address and sends both to DNSalsa in one update.
- On the page: switches for IPv4 and IPv6, and how often to check (30 seconds to 1 hour, 5 minutes by default). Turning one off removes that record. `DNSALSA_IPV4`, `DNSALSA_IPV6` and `DNSALSA_INTERVAL` in `compose.yaml` set the starting values.
- An address the connector can't find three times in a row (you lost IPv6, say) gets its record removed, so the name doesn't point at an old address.

## 1.0.0

- First version: pair with a code, the route comes from the DNSalsa dashboard, and a check of the reverse proxy setting when Home Assistant is behind the route.
