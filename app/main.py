"""DNSalsa connector: a Docker container that puts one of your services online at your dnsalsa.nl address.

Pairs with a DNSalsa account by a short code. With a tunnel (Remote) it runs cloudflared with the tunnel token
DNSalsa hands over; where the traffic goes (the route) is set in the DNSalsa dashboard. Without one it keeps a
dynamic-DNS hostname on the current home address: it looks up its IPv4 and IPv6 address and calls the update API
itself. Shows its state on a small page (port 8099) and in the container log.

Only the Python standard library: no packages to install or update.
"""
import base64
import hmac
import html
import http.client
import ipaddress
import json
import os
import random
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA = os.environ.get('DNSALSA_DATA', '/data')
STATE_FILE = os.path.join(DATA, 'state.json')
PREFS_FILE = os.path.join(DATA, 'prefs.json')   # dynamic DNS settings from the page; survive "Pair again"
PORT = int(os.environ.get('DNSALSA_PORT', '8099'))
CLOUDFLARED = os.environ.get('DNSALSA_CLOUDFLARED', '/usr/local/bin/cloudflared')
METRICS = '127.0.0.1:20241'
# Address Home Assistant sees the tunnel traffic come from, for the reverse proxy steps (see compose.yaml).
TRUSTED_PROXY = os.environ.get('DNSALSA_TRUSTED_PROXY', '')
USER_AGENT = 'dnsalsa-connector/1.2'
# The page shows the pairing code, and whoever enters that code in their own DNSalsa account decides where this
# connector's tunnel leads. So the code and the buttons only show to someone this machine trusts:
#   DNSALSA_PASSWORD set: anyone who logs in with it on the page, from any address.
#   Not set: only requests for localhost or a name in DNSALSA_HOSTS. The Host check stops DNS rebinding, where a
#   website points its own name at 127.0.0.1 to read this page.
# Everyone else sees a page without the code, and gets it with `dnsalsa code` in the container's shell, or the log.
PASSWORD = os.environ.get('DNSALSA_PASSWORD', '')
SESSION_TTL = 7 * 86400
SESSIONS = {}                    # login cookie -> expiry; a restart logs everyone out
SESSIONS_LOCK = threading.Lock()
FAILS = []                       # times of wrong passwords, to slow down guessing
# The `dnsalsa` command in the container's shell proves itself with this file, readable only by the container user.
CLI_TOKEN_FILES = (os.path.join(DATA, '.cli-token'), '/tmp/.dnsalsa-cli-token')   # /tmp when /data isn't writable
CLI_TOKEN = secrets.token_urlsafe(32)
LOCAL_HOSTS = {'localhost', '127.0.0.1', '::1'} | {h.strip().lower() for h in os.environ.get('DNSALSA_HOSTS', '').split(',') if h.strip()}
MISSES_BEFORE_REMOVE = 3   # lookups in a row without an address before its record goes


def log(msg):
    print(f'[dnsalsa] {msg}', flush=True)


def server():
    return (os.environ.get('DNSALSA_SERVER') or 'https://dnsalsa.nl').rstrip('/')


class State:
    """Everything the UI shows, guarded by one lock."""

    def __init__(self):
        self.lock = threading.Lock()
        self.saved = self._load()      # {mode, token, hostname, url, service} once paired; mode 'tunnel' or 'ddns'
        self.code = None               # pairing code shown to the user
        self.code_expires = 0
        self.error = None
        self.service = None            # current route, from cloudflared once it runs
        self.is_ha = False             # the route leads to Home Assistant
        self.proxy_ok = None           # reverse proxy setting in Home Assistant (only when is_ha)
        self.connected = False
        self.wake = threading.Event()  # nudges the background loops
        self.ddns = Ddns()             # dynamic DNS without a tunnel

    def _load(self):
        try:
            with open(STATE_FILE) as f:
                s = json.load(f)
            return s if s.get('token') else None
        except (OSError, ValueError):
            return None

    def save(self, data):
        tmp = STATE_FILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_FILE)
        with self.lock:
            self.saved = data
            self.code = None

    def forget(self):
        try:
            os.remove(STATE_FILE)
        except OSError:
            pass
        with self.lock:
            self.saved = None
            self.connected = False
            self.error = None
            self.service = None
            self.is_ha = False
            self.proxy_ok = None
            self.ddns = Ddns()


def mode(saved):
    """'tunnel' (Remote, cloudflared) or 'ddns' (only the address records). Pairings from before 1.3.0 are tunnels."""
    return (saved or {}).get('mode') or 'tunnel'


class Ddns:
    """What the dynamic-DNS loop last saw; read by the page."""

    def __init__(self):
        self.records = {'ipv4': None, 'ipv6': None}   # as DNSalsa has them now
        self.found = {'ipv4': None, 'ipv6': None}     # what the last lookup found
        self.misses = {'ipv4': 0, 'ipv6': 0}          # lookups in a row without an address
        self.last_ok = None                           # time of the last successful update call
        self.error = None
        self.ipv6_remote = False                      # free account: DNSalsa left IPv6 out
        self.wake = threading.Event()                 # settings changed: update now


STATE = State()


# Dynamic DNS settings. DNSALSA_IPV4, DNSALSA_IPV6 and DNSALSA_INTERVAL give the starting values; the page
# overrides them (prefs.json), so a server without a browser can be set up from compose.yaml alone.
INTERVALS = [(30, '30 seconds'), (60, '1 minute'), (300, '5 minutes'), (900, '15 minutes'), (3600, '1 hour')]
DEFAULT_INTERVAL = 300


def prefs():
    try:
        with open(PREFS_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _env_bool(name):
    return os.environ.get(name, 'true').strip().lower() not in ('0', 'false', 'no', 'off')


def ddns_settings():
    p = prefs()
    try:
        env_interval = int(os.environ.get('DNSALSA_INTERVAL') or DEFAULT_INTERVAL)
    except ValueError:
        env_interval = DEFAULT_INTERVAL
    interval = p.get('interval', env_interval)
    return {'ipv4': p.get('ipv4', _env_bool('DNSALSA_IPV4')) is not False, 'ipv6': p.get('ipv6', _env_bool('DNSALSA_IPV6')) is not False,
            'interval': interval if interval in dict(INTERVALS) else DEFAULT_INTERVAL}


def http_json(method, url, body=None, headers=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Content-Type': 'application/json', 'User-Agent': USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b'{}')
        except ValueError:
            return e.code, {}


def device_name():
    """Shown in the dashboard when the user enters the code. DNSALSA_NAME, else the Docker host's container name."""
    return f"DNSalsa connector ({os.environ.get('DNSALSA_NAME') or socket.gethostname()})"[:80]


# ── Pairing ──
def pairing_loop():
    while True:
        if STATE.saved:
            STATE.wake.wait(30)
            STATE.wake.clear()
            continue
        base = server()
        try:
            status, r = http_json('POST', f'{base}/api/pair/start', {'device': device_name(), 'kind': 'connector', 'ddns': True})
            if status != 200:
                raise RuntimeError(r.get('message') or f'HTTP {status}')
            with STATE.lock:
                STATE.code, STATE.code_expires, STATE.error = r['code'], r['expiresAt'] / 1000, None
            log(f"Pairing code: {r['code']}  In your DNSalsa dashboard: hostname > Setup > Cloudflare Tunnel > DNSalsa connector, "
                "or Dynamic DNS > DNSalsa connector.")
            secret = r['secret']
            while time.time() < STATE.code_expires and not STATE.saved:
                time.sleep(3)
                status, p = http_json('POST', f'{base}/api/pair/poll', {'secret': secret})
                if status == 200 and p.get('status') == 'paired':
                    STATE.save({'mode': p.get('mode') or 'tunnel', 'token': p['token'], 'hostname': p['hostname'], 'url': p['url'],
                                'service': p.get('service')})
                    if p.get('mode') == 'ddns':
                        log(f"Paired. Keeping {p['hostname']} on this home's address")
                    else:
                        log(f"Paired. {p['url']} will serve {p.get('service') or 'the route set in your dashboard'}")
                    STATE.wake.set()
                    STATE.ddns.wake.set()
                    break
                if status == 410:
                    break
                if status != 200:
                    raise RuntimeError(p.get('message') or f'HTTP {status}')
        except Exception as e:  # noqa: BLE001  network trouble: show it and try again
            with STATE.lock:
                STATE.error = f'Could not reach DNSalsa: {e}'
            log(STATE.error)
            time.sleep(30)


# ── cloudflared ──
def tunnel_loop():
    proc = None
    quick_exits = 0
    while True:
        saved = STATE.saved if mode(STATE.saved) == 'tunnel' else None
        if not saved:
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait(10)
            proc = None
            STATE.wake.wait(5)
            STATE.wake.clear()
            continue
        if proc is None or proc.poll() is not None:
            if proc is not None:
                quick_exits = quick_exits + 1 if time.time() - started < 30 else 0
                if quick_exits >= 5:
                    with STATE.lock:
                        STATE.error = ('Cloudflare keeps refusing the tunnel. If you removed this hostname or its tunnel '
                                       'in the DNSalsa dashboard, press "Pair again".')
                    time.sleep(60)
            env = {**os.environ, 'TUNNEL_TOKEN': saved['token']}   # not on the command line, so it stays out of ps
            proc = subprocess.Popen([CLOUDFLARED, 'tunnel', '--no-autoupdate', '--metrics', METRICS, 'run'], env=env)
            started = time.time()
            log('cloudflared started')
        try:
            with urllib.request.urlopen(f'http://{METRICS}/ready', timeout=3) as r:
                ok = r.status == 200
        except Exception:  # noqa: BLE001
            ok = False
        with STATE.lock:
            if ok and not STATE.connected:
                log('Tunnel connected')
            STATE.connected = ok
            if ok:
                STATE.error = None
                quick_exits = 0
        STATE.wake.wait(10 if ok else 3)   # check often until connected, then calmly
        STATE.wake.clear()


# ── Dynamic DNS without a tunnel ──
def _connection(scheme, family):
    """An http.client connection class that only connects over one address family (like curl -4 / -6)."""
    base_cls = http.client.HTTPSConnection if scheme == 'https' else http.client.HTTPConnection

    class FamilyConnection(base_cls):
        def connect(self):
            err = OSError('no address')
            for af, kind, proto, _, addr in socket.getaddrinfo(self.host, self.port, family, socket.SOCK_STREAM):
                sock = socket.socket(af, kind, proto)
                try:
                    sock.settimeout(self.timeout)
                    sock.connect(addr)
                except OSError as e:
                    sock.close()
                    err = e
                    continue
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host) if scheme == 'https' else sock
                return
            raise err
    return FamilyConnection


def lookup_ip(base, family):
    """Our public address of one family, as DNSalsa's /api/ip sees it, or None (no such address, or offline)."""
    u = urllib.parse.urlsplit(base)
    conn = _connection(u.scheme, family)(u.hostname, u.port, timeout=8)
    try:
        conn.request('GET', '/api/ip', headers={'User-Agent': USER_AGENT})
        r = conn.getresponse()
        text = r.read(100).decode('ascii', 'replace').strip() if r.status == 200 else ''
    except (OSError, http.client.HTTPException):
        return None
    finally:
        conn.close()
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    # DNSalsa refuses private addresses, and one bad address would block the other family's update too.
    if ip.version != (4 if family == socket.AF_INET else 6) or not (ip.is_global or os.environ.get('DNSALSA_ALLOW_PRIVATE')):
        return None
    return str(ip)


def ddns_update():
    """One round: look up both addresses, send what we found in one call. Returns seconds until the next round."""
    saved, d = STATE.saved, STATE.ddns
    settings = ddns_settings()
    interval = settings['interval'] + random.uniform(1, 5)   # a bit more than the interval: DNSalsa allows one call per 30 s
    base = server()
    body = {'type': 'both'}
    for key, family in (('ipv4', socket.AF_INET), ('ipv6', socket.AF_INET6)):
        if not settings[key]:
            body[key] = 'none'        # turned off on this page: that record goes
            d.found[key], d.misses[key] = None, 0
            continue
        ip = lookup_ip(base, family)
        d.found[key] = ip
        if ip:
            d.misses[key] = 0
            body[key] = ip
        else:
            d.misses[key] += 1
            if d.misses[key] >= MISSES_BEFORE_REMOVE:
                body[key] = 'none'    # gone for a while (no IPv6 any more, say): don't leave a dead record
    if len(body) == 1:
        d.error = 'Could not find your address. Is the internet connection down? Trying again soon.'
        return min(interval, 60)
    try:
        status, r = http_json('POST', f'{base}/api/update', body, headers={'Authorization': f"Bearer {saved['token']}"})
    except Exception as e:  # noqa: BLE001  network trouble
        d.error = f'Could not reach DNSalsa: {e}'
        return min(interval, 60)
    if status == 200:
        changed = r.get('changed')
        d.records = {'ipv4': r.get('ipv4'), 'ipv6': r.get('ipv6')}
        d.ipv6_remote = r.get('ipv6Skipped') == 'remote_only'
        d.last_ok, d.error = time.time(), None
        if changed:
            log(f"Updated {saved['hostname']}: IPv4 {d.records['ipv4'] or 'none'}, IPv6 {d.records['ipv6'] or 'none'}")
        return interval
    if status == 429:
        return 31 + random.uniform(0, 3)
    if status == 401:
        d.error = 'DNSalsa no longer accepts this connector\'s token: you made a new one in the dashboard, or removed the hostname. Press "Pair again".'
    elif status == 409:
        d.error = r.get('message') or 'This hostname runs through a tunnel now. Press "Pair again".'
    else:
        d.error = r.get('message') or f'DNSalsa answered HTTP {status}.'
    log(d.error)
    return interval


def ddns_loop():
    while True:
        wait = 5
        if mode(STATE.saved) == 'ddns':
            wait = ddns_update()
        d = STATE.ddns
        d.wake.wait(wait)
        d.wake.clear()



# ── Route and the Home Assistant reverse proxy setting ──
def current_service():
    """The route as cloudflared runs it now (it follows changes in the dashboard), else the one from pairing."""
    saved = STATE.saved or {}
    try:
        with urllib.request.urlopen(f'http://{METRICS}/config', timeout=3) as r:
            cfg = json.loads(r.read() or b'{}')
        rules = ((cfg.get('config') or {}).get('ingress') or [])
        for rule in rules:
            if rule.get('hostname') == saved.get('hostname') and rule.get('service'):
                return rule['service']
    except Exception:  # noqa: BLE001  cloudflared not (yet) running: fall back
        pass
    return saved.get('service')


def check_proxy(service=None):
    """Is the route Home Assistant, and does it accept traffic from the tunnel?

    Home Assistant answers 400 to a forwarded request when 'Trust X-Forwarded-For' is off or we aren't trusted.
    /manifest.json needs no login, so this check never shows up as a failed login in Home Assistant.
    203.0.113.7 is a documentation address (TEST-NET-3) that no real visitor has."""
    service = service or current_service()
    is_ha, ok = False, None
    if service and service.startswith(('http://', 'https://')):
        url = service.rstrip('/') + '/manifest.json'
        ctx = None
        if url.startswith('https://'):
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # only reading a public page of a LAN service
        try:
            with urllib.request.urlopen(url, timeout=5, context=ctx) as r:
                is_ha = b'Home Assistant' in r.read(4096)
        except Exception:  # noqa: BLE001  not HA, or down: nothing to check
            is_ha = False
        if is_ha:
            req = urllib.request.Request(url, headers={'X-Forwarded-For': '203.0.113.7'})
            try:
                with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                    ok = r.status != 400
            except urllib.error.HTTPError as e:
                ok = e.code != 400
            except Exception:  # noqa: BLE001  restarting: unknown for now
                ok = None
    with STATE.lock:
        STATE.service, STATE.is_ha, STATE.proxy_ok = service, is_ha, ok
    return ok


def proxy_loop():
    while True:
        if STATE.saved and mode(STATE.saved) == 'tunnel':
            check_proxy()
        time.sleep(15 if STATE.saved and STATE.service is None else 60)   # soon after pairing, then calmly


# ── Status page ──
FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fonts')


def _font(name):
    try:
        with open(os.path.join(FONT_DIR, name), 'rb') as f:
            return 'data:font/woff2;base64,' + base64.b64encode(f.read()).decode()
    except OSError:
        return ''


FLAME = ('<svg class="flame" viewBox="0 0 52 70" aria-hidden="true"><defs><linearGradient id="fl" x1="0" y1="70" x2="52" y2="0" '
         'gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#b3122a"/><stop offset=".5" stop-color="#d9401c"/>'
         '<stop offset="1" stop-color="#f0782a"/></linearGradient></defs>'
         '<path d="M26 68 C10 68 4 54 4 42 C4 28 14 22 18 10 C20 4 22 0 26 0 C26 8 30 12 34 16 C38 20 48 28 48 42 C48 56 42 68 26 68Z" fill="url(#fl)"/>'
         '<path d="M26 60 C18 60 14 52 14 44 C14 36 20 32 22 26 C24 34 30 36 34 44 C34 52 32 60 26 60Z" fill="#fff" fill-opacity=".14"/></svg>')

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNSalsa connector</title><style>
@font-face{font-family:'Space Grotesk';src:url(__SANS__) format('woff2');font-weight:300 700;font-display:swap}
@font-face{font-family:'Space Mono';src:url(__MONO__) format('woff2');font-weight:700;font-display:swap}
:root{color-scheme:dark;--red:oklch(48% .23 22);--orange:oklch(63% .22 42);--heat:oklch(72% .2 55);
--bg:oklch(11% .015 22);--card:oklch(15% .018 22);--card2:oklch(18% .02 22);--line:oklch(24% .015 22);
--muted:oklch(66% .012 55);--fg:oklch(96% .008 55);--ok:oklch(74% .16 150);
--flame:linear-gradient(120deg,var(--red),var(--orange) 55%,var(--heat));
--sans:'Space Grotesk',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;--mono:'Space Mono',ui-monospace,Menlo,Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:15px/1.6 var(--sans);-webkit-font-smoothing:antialiased;min-height:100vh;
background-image:radial-gradient(60rem 30rem at 50% -12rem,oklch(48% .23 22 / .22),transparent 70%)}
main{max-width:620px;margin:0 auto;padding:28px 16px 40px;display:grid;gap:14px}
header{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.flame{width:26px;height:35px;flex:none;filter:drop-shadow(0 0 12px oklch(63% .22 42 / .45))}
.brand{font-weight:600;font-size:22px;letter-spacing:-.01em}.brand span{color:var(--orange)}
.pill{margin-left:auto;display:inline-flex;align-items:center;gap:7px;font-size:13px;font-weight:500;padding:5px 11px;border-radius:99px;
border:1px solid var(--line);background:var(--card);color:var(--muted);white-space:nowrap}
.pill i{width:8px;height:8px;border-radius:50%;background:currentColor}
.pill.ok{color:var(--ok);border-color:oklch(74% .16 150 / .35)}.pill.ok i{box-shadow:0 0 10px currentColor}
.pill.wait{color:var(--heat);border-color:oklch(72% .2 55 / .35)}.pill.wait i{animation:pulse 1.4s ease-in-out infinite}
@keyframes pulse{50%{opacity:.3}}
@media(prefers-reduced-motion:reduce){.pill.wait i{animation:none}}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;display:grid;gap:12px}
.card.hero{background:linear-gradient(var(--card2),var(--card)) padding-box,var(--flame) border-box;border:1px solid transparent}
.card.warn{border-left:3px solid var(--heat)}
.label{font:700 11px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
h2{font-size:17px;font-weight:600;letter-spacing:-.01em}h2.warn{color:var(--heat)}
.code{font:700 clamp(34px,10vw,48px)/1.05 var(--mono);letter-spacing:.06em;background:var(--flame);-webkit-background-clip:text;background-clip:text;color:transparent}
.addr{font-size:clamp(18px,5vw,22px);font-weight:600;word-break:break-all}
a{color:var(--orange);text-underline-offset:3px}a:hover{color:var(--heat)}
.muted{color:var(--muted)}.small{font-size:13px}.ok{color:var(--ok)}
ol{padding-left:22px;display:grid;gap:6px}li::marker{color:var(--orange);font-weight:600}
button,a.btn{font:500 14px var(--sans);padding:9px 16px;border-radius:9px;border:1px solid var(--line);background:var(--card2);color:var(--fg);
cursor:pointer;text-decoration:none;display:inline-block}
button:hover,a.btn:hover{border-color:var(--muted);color:var(--fg)}
.primary{background:var(--flame)!important;border-color:transparent!important;color:#fff!important;font-weight:600!important}
.primary:hover{filter:brightness(1.1)}
button:disabled{opacity:.5;cursor:wait}
code{font:700 14px var(--mono);background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:4px 8px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.copy{margin-top:6px}.copy button{padding:5px 11px;font-size:13px}
.check{display:flex;gap:10px;align-items:center}.check svg{flex:none;color:var(--ok)}
.recs{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;align-items:baseline}.recs dt{font:700 11px/1.9 var(--mono);letter-spacing:.14em;color:var(--muted)}
.recs dd{font:700 14px var(--mono);word-break:break-all}.recs dd.off{color:var(--muted);font-weight:400;font-family:var(--sans)}
.set{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;border-top:1px solid var(--line)}.set:first-of-type{border-top:0}
.set small{display:block;color:var(--muted);font-size:13px}
.switch{appearance:none;-webkit-appearance:none;flex:none;width:44px;height:26px;border-radius:99px;background:var(--line);position:relative;cursor:pointer;transition:background .15s}
.switch::after{content:'';position:absolute;top:3px;left:3px;width:20px;height:20px;border-radius:50%;background:var(--fg);transition:transform .15s}
.switch:checked{background:var(--orange)}.switch:checked::after{transform:translateX(18px)}
.switch:focus-visible,select:focus-visible{outline:2px solid var(--heat);outline-offset:2px}
input[type=password]{font:500 14px var(--sans);padding:9px 12px;border-radius:9px;border:1px solid var(--line);background:var(--card2);color:var(--fg);width:100%}
input[type=password]:focus-visible{outline:2px solid var(--heat);outline-offset:2px}
.err{color:var(--heat);font-size:13px}
select{font:500 14px var(--sans);padding:7px 10px;border-radius:9px;border:1px solid var(--line);background:var(--card2);color:var(--fg)}
@media(prefers-reduced-motion:reduce){.switch,.switch::after{transition:none}}
footer{margin-top:6px;text-align:center;font-size:12px;color:var(--muted)}footer a{color:var(--muted)}
</style></head><body><main__REFRESH__>
<header>__FLAME__<div class="brand">DNS<span>alsa</span> <span class="muted small">connector</span></div>__PILL__</header>
__BODY__
<footer><a href="https://dnsalsa.nl" target="_blank" rel="noopener">dnsalsa.nl</a> · <a href="mailto:info@dnsalsa.nl">info@dnsalsa.nl</a></footer>
</main><script>
// Refresh by swapping <main> in place instead of reloading the whole page (no flash, and the inline fonts aren't sent
// along every 4 seconds).
let tm;
function schedule(){clearTimeout(tm);if(document.querySelector('main[data-refresh]'))tm=setTimeout(soft,4000)}
async function soft(){
try{const r=await fetch(location.href,{cache:'no-store'});if(!r.ok)throw 0;
const m=new DOMParser().parseFromString(await r.text(),'text/html').querySelector('main');if(!m)throw 0;
document.querySelector('main').replaceWith(m);bind(m)}catch(e){}
schedule()}
function bind(root){
root.querySelectorAll('form[data-post]').forEach(f=>f.addEventListener('submit',async e=>{e.preventDefault();
const b=f.querySelector('button');if(b)b.disabled=true;
try{const r=await fetch(f.dataset.post,{method:'POST',headers:{'X-DNSalsa':'1'},body:new URLSearchParams(new FormData(f))});
const er=f.querySelector('[data-err]');if(!r.ok&&er){er.textContent=r.status===429?'Too many tries. Wait a minute.':'Wrong password.';if(b)b.disabled=false;return}}catch(e){}soft()}));
// Settings save as soon as you flip a switch or pick an interval.
root.querySelectorAll('form[data-auto]').forEach(f=>f.addEventListener('change',()=>f.requestSubmit()));
// Copy also works on plain http:// (no secure context), where navigator.clipboard is missing.
root.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',async()=>{
const t=document.getElementById(b.dataset.copy).textContent;let ok=false;
try{await navigator.clipboard.writeText(t);ok=true}catch(e){}
if(!ok){const a=document.createElement('textarea');a.value=t;document.body.append(a);a.select();
try{ok=document.execCommand('copy')}catch(e){}a.remove()}
b.textContent=ok?'Copied':'Select and copy';setTimeout(()=>b.textContent='Copy',2000)}))}
bind(document);schedule();
</script></body></html>"""
PAGE = PAGE.replace('__SANS__', _font('space-grotesk-latin-wght-normal.woff2')).replace('__MONO__', _font('space-mono-latin-700-normal.woff2')).replace('__FLAME__', FLAME)

CHECK = ('<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" '
         'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>')


def ago(t):
    secs = int(time.time() - t)
    if secs < 60:
        return 'just now'
    mins = secs // 60
    return f"{mins} minute{'s' if mins != 1 else ''} ago" if mins < 60 else f"{mins // 60} h ago"


def render_ddns(saved):
    """The page without a tunnel: the address records, the settings, and what's still needed for remote access."""
    d, settings = STATE.ddns, ddns_settings()
    if d.error:
        pill = '<span class="pill wait"><i></i>Problem</span>'
    elif d.last_ok:
        pill = '<span class="pill ok"><i></i>Updating</span>'
    else:
        pill = '<span class="pill wait"><i></i>Starting</span>'
    parts = []
    if d.error:
        parts.append(f'<div class="card warn"><p>{html.escape(d.error)}</p></div>')

    def rec(key, label):
        if not settings[key]:
            return f'<dt>{label}</dt><dd class="off">Off</dd>'
        if d.records[key]:
            return f'<dt>{label}</dt><dd>{html.escape(d.records[key])}</dd>'
        why = 'IPv6 comes with Remote' if key == 'ipv6' and d.ipv6_remote else ('none found' if d.last_ok else 'checking…')
        return f'<dt>{label}</dt><dd class="off">{why}</dd>'
    when = f'Last update {ago(d.last_ok)}.' if d.last_ok else 'Looking up your address…'
    host = html.escape(saved['hostname'])
    parts.append(f'''<div class="card hero"><div class="label">Your address</div><div class="addr">{host}</div>
<dl class="recs">{rec('ipv4', 'IPV4')}{rec('ipv6', 'IPV6')}</dl>
<p class="muted small">{when} DNSalsa only changes the record when your address changes.</p></div>''')
    opts = ''.join(f'<option value="{v}"{" selected" if v == settings["interval"] else ""}>{l}</option>' for v, l in INTERVALS)
    v6_note = ('<small>Your account gets IPv4 only; IPv6 comes with Remote.</small>' if d.ipv6_remote
               else '<small>Turning one off removes that record.</small>')
    parts.append(f'''<div class="card"><h2>Settings</h2><form data-post="settings" data-auto>
<label class="set"><span>IPv4<small>The A record.</small></span><input class="switch" type="checkbox" name="ipv4"{' checked' if settings['ipv4'] else ''}></label>
<label class="set"><span>IPv6{v6_note}</span><input class="switch" type="checkbox" name="ipv6"{' checked' if settings['ipv6'] else ''}></label>
<label class="set"><span>Check every<small>A lookup costs nothing; DNS only changes when your address does.</small></span>
<select name="interval">{opts}</select></label></form></div>''')
    parts.append('''<div class="card"><h2>Reaching a service from outside</h2>
<p class="muted small">This address points at your home. To open a service with it from outside, your router needs a port forward to
that service. With DNSalsa Remote you need no port forward, and your home IP stays hidden.</p></div>''')
    parts.append('''<div class="card"><h2>Pair again</h2><p class="muted small">Use another hostname, another DNSalsa account, or Remote.
This connector stops updating the current address.</p>
<form class="row" data-post="unpair"><button>Pair again</button></form></div>''')
    refresh = '' if d.last_ok and not d.error else ' data-refresh'
    return PAGE.replace('__PILL__', pill).replace('__BODY__', '\n'.join(parts)).replace('__REFRESH__', refresh)


def render():
    if mode(STATE.saved) == 'ddns' and STATE.saved:
        return render_ddns(STATE.saved)
    with STATE.lock:
        saved, code, expires, error = STATE.saved, STATE.code, STATE.code_expires, STATE.error
        service, is_ha, proxy_ok, connected = STATE.service, STATE.is_ha, STATE.proxy_ok, STATE.connected
    base = html.escape(server())
    parts = []
    if not saved:
        pill = '<span class="pill"><i></i>Not paired</span>'
    elif connected:
        pill = '<span class="pill ok"><i></i>Connected</span>'
    else:
        pill = '<span class="pill wait"><i></i>Connecting</span>'
    if error:
        parts.append(f'<div class="card warn"><p>{html.escape(error)}</p></div>')
    if not saved:
        if code:
            mins = max(1, int((expires - time.time()) / 60))
            parts.append(f'''<div class="card hero"><div class="label">Pairing code</div>
<div class="row"><div class="code" id="pair-code">{html.escape(code)}</div><button type="button" data-copy="pair-code">Copy</button></div>
<ol><li>Open <a href="{base}/dashboard" target="_blank" rel="noopener">your DNSalsa dashboard</a>.</li>
<li>For remote access: open the hostname and choose <b>Setup → Cloudflare Tunnel</b>. As the route, enter the address of
the service you want to reach, the way this container reaches it: <code>http://192.168.1.20:8123</code> for Home Assistant on another
machine, <code>http://host.docker.internal:8123</code> for a service on this machine. Then choose <b>DNSalsa connector</b> and enter
the code above.</li>
<li>Or keep a hostname on your home address: <b>Setup → Dynamic DNS → DNSalsa connector</b>, and enter the code.</li>
<li>This page updates by itself.</li></ol>
<p class="muted small">The code works for {mins} more minute{'s' if mins != 1 else ''}; after that you get a new one here.</p></div>''')
        else:
            parts.append('<div class="card"><p class="muted">Getting a pairing code…</p></div>')
    else:
        url = html.escape(saved['url'])
        route = f'<p class="muted small">Serves <code>{html.escape(service)}</code>. Change the route in your DNSalsa dashboard; no need to pair again.</p>' if service else ''
        parts.append(f'''<div class="card hero"><div class="label">Your address</div>
<a class="addr" href="{url}" target="_blank" rel="noopener">{url}</a>{route}</div>''')
    if saved and is_ha and proxy_ok is False:
        net = html.escape(TRUSTED_PROXY) if TRUSTED_PROXY else 'the IP address of the machine running this container'
        copy = f'<span class="row copy"><code id="net">{net}</code><button type="button" data-copy="net">Copy</button></span>' if TRUSTED_PROXY else f'<b>{net}</b>'
        parts.append(f'''<div class="card warn"><h2 class="warn">One setting needed in Home Assistant</h2>
<p>Home Assistant blocks traffic from the tunnel until you allow it. In Home Assistant, open <b>Settings → System → Network</b>:</p>
<ol><li>Scroll to <b>HTTP Server</b>, part <b>Reverse proxy</b>.</li>
<li>Turn on <b>Trust X-Forwarded-For</b>.</li>
<li>Add this address as a trusted proxy: {copy}</li>
<li>Recommended, same section: turn on <b>Enable IP banning</b>, turn off <b>Unlimited login attempts</b> and set <b>Login attempts before ban</b> to <b>10</b>.</li>
<li>Save, and confirm the new settings after Home Assistant restarts.</li></ol>
<p class="muted small">Already have a proxy in that list? Add this address, keep the others. This page turns green by itself once it works.</p>
<form class="row" data-post="check"><button>Check again</button></form></div>''')
    elif saved and is_ha and proxy_ok:
        parts.append(f'''<div class="card"><div class="check">{CHECK}<p>Home Assistant accepts traffic from the tunnel.</p></div>
<p class="muted small">Tip: in <b>Settings → System → Network</b>, turn on <b>Enable IP banning</b> with <b>Login attempts before ban</b> at 10.</p></div>''')
    if saved:
        parts.append('''<div class="card"><h2>Pair again</h2><p class="muted small">Use another hostname or another DNSalsa account.
This disconnects the current address from this connector.</p>
<form class="row" data-post="unpair"><button>Pair again</button></form></div>''')
    refresh = '' if (saved and connected and (proxy_ok or not is_ha)) else ' data-refresh'
    return PAGE.replace('__PILL__', pill).replace('__BODY__', '\n'.join(parts)).replace('__REFRESH__', refresh)


def render_locked():
    """For someone this connector doesn't trust (see PASSWORD): the state, but no pairing code and no buttons."""
    with STATE.lock:
        saved, connected = STATE.saved, STATE.connected
    if not saved:
        pill = '<span class="pill"><i></i>Not paired</span>'
    elif connected or mode(saved) == 'ddns':
        pill = '<span class="pill ok"><i></i>Paired</span>'
    else:
        pill = '<span class="pill wait"><i></i>Connecting</span>'
    body = '''<div class="card"><h2>Pairing code in the log</h2>
<p>This page is open on your network, so it doesn't show the pairing code: anyone who enters that code in their own
DNSalsa account decides where this connector sends traffic.</p>
<ol><li>Run <code>dnsalsa code</code> in the container's shell: in TrueNAS under Apps, this app, Shell; with Docker
<code>docker exec dnsalsa-connector dnsalsa code</code>. The code is also in the app's logs.</li>
<li>Or set a password for this page (<code>DNSALSA_PASSWORD</code>) to use it from your network.</li></ol></div>'''
    return PAGE.replace('__PILL__', pill).replace('__BODY__', body).replace('__REFRESH__', ' data-refresh')


def render_login():
    body = '''<div class="card"><h2>Log in</h2>
<form data-post="login" class="row"><label class="label" for="pw" style="width:100%">Password for this page</label>
<input id="pw" name="password" type="password" autocomplete="current-password" autofocus required>
<button type="submit" class="primary">Log in</button> <span class="err" data-err aria-live="polite"></span></form></div>'''
    return PAGE.replace('__PILL__', '').replace('__BODY__', body).replace('__REFRESH__', '')


def save_settings(form):
    """The settings form: a ticked switch is sent as 'on', an unticked one not at all."""
    f = urllib.parse.parse_qs(form)
    try:
        interval = int(f.get('interval', [DEFAULT_INTERVAL])[0])
    except ValueError:
        interval = DEFAULT_INTERVAL
    p = {**prefs(), 'ipv4': 'ipv4' in f, 'ipv6': 'ipv6' in f, 'interval': interval if interval in dict(INTERVALS) else DEFAULT_INTERVAL}
    tmp = PREFS_FILE + '.tmp'
    with open(tmp, 'w') as fh:
        json.dump(p, fh)
    os.replace(tmp, PREFS_FILE)
    log(f"Settings: IPv4 {'on' if p['ipv4'] else 'off'}, IPv6 {'on' if p['ipv6'] else 'off'}, every {p['interval']} s")
    STATE.ddns.wake.set()   # apply now


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _host(self):
        h = (self.headers.get('Host') or '').strip().lower()
        if h.startswith('['):
            return h[1:h.find(']')] if ']' in h else h
        return h.rsplit(':', 1)[0] if h.count(':') == 1 else h

    def _cookie(self):
        for part in (self.headers.get('Cookie') or '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == 'dnsalsa_session':
                return v
        return ''

    def _trusted(self):
        """Who may see the pairing code and press the buttons; see PASSWORD."""
        cli = self.headers.get('X-DNSalsa-Cli') or ''
        if cli and hmac.compare_digest(cli.encode(), CLI_TOKEN.encode()):
            return True
        if PASSWORD:
            token = self._cookie()
            with SESSIONS_LOCK:
                exp = SESSIONS.get(token)
                if exp and exp < time.time():
                    SESSIONS.pop(token, None)
                    exp = None
            return bool(token and exp)
        return self._host() in LOCAL_HOSTS

    def _login(self):
        """One password, no username. Ten wrong ones in a minute and everyone waits a minute."""
        now = time.time()
        FAILS[:] = [t for t in FAILS if t > now - 60]
        if len(FAILS) >= 10:
            return self._send(429, '{"error":"slow_down"}', 'application/json')
        form = urllib.parse.parse_qs(self.rfile.read(min(int(self.headers.get('Content-Length') or 0), 2000)).decode('utf-8', 'replace'))
        given = (form.get('password') or [''])[0]
        if not hmac.compare_digest(given.encode(), PASSWORD.encode()):
            FAILS.append(now)
            log('Wrong password on the page')
            return self._send(401, '{"error":"wrong_password"}', 'application/json')
        token = secrets.token_urlsafe(32)
        with SESSIONS_LOCK:
            SESSIONS[token] = now + SESSION_TTL
        self._send(200, '{"ok":true}', 'application/json',
                   cookie=f'dnsalsa_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}')

    def _allowed(self):
        """POSTs change things (unpair, settings): only from this page, never from another site. The X-DNSalsa header
        can't be sent cross-site without a CORS preflight, which this server never answers."""
        if self.command == 'POST':
            origin = self.headers.get('Origin')
            host = self.headers.get('Host', '')
            cli = self.headers.get('X-DNSalsa-Cli') or ''
            if cli and hmac.compare_digest(cli.encode(), CLI_TOKEN.encode()):
                return True   # the shell command: no browser, no Origin
            if (origin and origin.split('://', 1)[-1] != host) or self.headers.get('X-DNSalsa') != '1':
                self.send_error(403)
                return False
        return True

    def _send(self, code, body, ctype='text/html; charset=utf-8', cookie=None):
        data = body.encode()
        self.send_response(code)
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Frame-Options', 'DENY')   # no clickjacking the Pair again button
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        trusted = self._trusted()
        if self.path.rstrip('/').endswith('status'):
            # The healthcheck uses this too, so it answers without login; the code only goes to someone trusted.
            with STATE.lock:
                d = STATE.ddns
                return self._send(200, json.dumps({'paired': bool(STATE.saved), 'mode': mode(STATE.saved) if STATE.saved else None,
                                                   'records': d.records, 'lastUpdate': d.last_ok, 'ddnsError': d.error,
                                                   'code': STATE.code if trusted else None, 'connected': STATE.connected,
                                                   'service': STATE.service, 'homeAssistant': STATE.is_ha,
                                                   'proxyOk': STATE.proxy_ok, 'error': STATE.error}), 'application/json')
        if trusted:
            page = render()
            if PASSWORD:
                page = page.replace('<footer>', '<form data-post="logout" class="row" style="justify-content:center"><button type="submit">Log out</button></form>\n<footer>', 1)
            return self._send(200, page)
        self._send(200, render_login() if PASSWORD else render_locked())

    def do_POST(self):
        path = self.path.rstrip('/')
        if path.endswith('login') and PASSWORD:
            return self._login() if self._allowed() else None
        if not self._trusted():
            return self.send_error(403)
        if not self._allowed():
            return
        if path.endswith('logout'):
            with SESSIONS_LOCK:
                SESSIONS.pop(self._cookie(), None)
            return self._send(200, '{"ok":true}', 'application/json', cookie='dnsalsa_session=; Path=/; Max-Age=0')
        if path.endswith('check'):
            check_proxy()
        elif path.endswith('settings'):
            save_settings(self.rfile.read(min(int(self.headers.get('Content-Length') or 0), 2000)).decode('utf-8', 'replace'))
        elif path.endswith('unpair'):
            STATE.forget()
            log('Unpaired; getting a new pairing code')
            STATE.wake.set()
        self._send(200, '{"ok":true}', 'application/json')


CLI_HELP = '''Usage: dnsalsa <command>
  code     the pairing code to enter on dnsalsa.nl
  status   paired or not
  unpair   forget the pairing and get a new code'''


def cli(args):
    """`dnsalsa code` and friends, in the container's shell. Asks the running connector over 127.0.0.1."""
    cmd = args[0] if args else ''
    if cmd not in ('code', 'status', 'unpair'):
        print(CLI_HELP)
        return 0 if cmd in ('', 'help', '-h', '--help') else 2
    token = ''
    for path in CLI_TOKEN_FILES:
        try:
            with open(path) as f:
                token = f.read().strip()
            break
        except OSError:
            continue
    if not token:
        print('The connector is not running in this container.', file=sys.stderr)
        return 1

    def call(path, post=False):
        req = urllib.request.Request(f'http://127.0.0.1:{PORT}/{path}', data=b'' if post else None,
                                     method='POST' if post else 'GET', headers={'X-DNSalsa-Cli': token})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.load(r)
    try:
        if cmd == 'unpair':
            call('unpair', post=True)
            for _ in range(30):
                time.sleep(0.5)
                st = call('status')
                if st.get('code'):
                    break
        else:
            st = call('status')
    except (OSError, ValueError) as e:
        print(f'Could not reach the connector: {e}', file=sys.stderr)
        return 1
    if st.get('paired') and cmd != 'unpair':
        print(f"Paired ({st.get('mode')})." + ('' if cmd == 'status' else ' Run "dnsalsa unpair" to pair again.'))
        return 0
    if st.get('code'):
        print(st['code'] if cmd == 'code' else f"Not paired. Pairing code: {st['code']}")
        if cmd != 'code':
            print('Enter it on dnsalsa.nl under Setup within 15 minutes.')
        return 0
    print('No pairing code yet. Try again in a few seconds.' + (f" ({st['error']})" if st.get('error') else ''))
    return 1


def main():
    os.makedirs(DATA, exist_ok=True)
    for path in CLI_TOKEN_FILES:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(CLI_TOKEN)
            break
        except OSError:
            continue
    for fn in (pairing_loop, tunnel_loop, proxy_loop, ddns_loop):
        threading.Thread(target=fn, daemon=True).start()
    log(f'DNSalsa connector running, server {server()}. Status page on port {PORT}.')
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.exit(cli(sys.argv[1:]))
    main()
