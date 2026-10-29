"""DNSalsa connector: a Docker container that puts one of your services online at your dnsalsa.nl address.

Pairs with a DNSalsa account by a short code, then runs cloudflared with the tunnel token DNSalsa
hands over. Where the traffic goes (the route) is set in the DNSalsa dashboard. Shows its state on a
small page (port 8099) and in the container log.

Only the Python standard library: no packages to install or update.
"""
import base64
import html
import json
import os
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA = os.environ.get('DNSALSA_DATA', '/data')
STATE_FILE = os.path.join(DATA, 'state.json')
PORT = int(os.environ.get('DNSALSA_PORT', '8099'))
CLOUDFLARED = os.environ.get('DNSALSA_CLOUDFLARED', '/usr/local/bin/cloudflared')
METRICS = '127.0.0.1:20241'
# Address Home Assistant sees the tunnel traffic come from, for the reverse proxy steps (see compose.yaml).
TRUSTED_PROXY = os.environ.get('DNSALSA_TRUSTED_PROXY', '')


def log(msg):
    print(f'[dnsalsa] {msg}', flush=True)


def server():
    return (os.environ.get('DNSALSA_SERVER') or 'https://dnsalsa.nl').rstrip('/')


class State:
    """Everything the UI shows, guarded by one lock."""

    def __init__(self):
        self.lock = threading.Lock()
        self.saved = self._load()      # {token, hostname, url, service} once paired
        self.code = None               # pairing code shown to the user
        self.code_expires = 0
        self.error = None
        self.service = None            # current route, from cloudflared once it runs
        self.is_ha = False             # the route leads to Home Assistant
        self.proxy_ok = None           # reverse proxy setting in Home Assistant (only when is_ha)
        self.connected = False
        self.wake = threading.Event()  # nudges the background loops

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


STATE = State()


def http_json(method, url, body=None, headers=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Content-Type': 'application/json', 'User-Agent': 'dnsalsa-ha/1.0', **(headers or {})})
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
            status, r = http_json('POST', f'{base}/api/pair/start', {'device': device_name(), 'kind': 'connector'})
            if status != 200:
                raise RuntimeError(r.get('message') or f'HTTP {status}')
            with STATE.lock:
                STATE.code, STATE.code_expires, STATE.error = r['code'], r['expiresAt'] / 1000, None
            log(f"Pairing code: {r['code']}  In your DNSalsa dashboard: hostname > Setup > Cloudflare Tunnel > DNSalsa connector.")
            secret = r['secret']
            while time.time() < STATE.code_expires and not STATE.saved:
                time.sleep(3)
                status, p = http_json('POST', f'{base}/api/pair/poll', {'secret': secret})
                if status == 200 and p.get('status') == 'paired':
                    STATE.save({'token': p['token'], 'hostname': p['hostname'], 'url': p['url'], 'service': p.get('service')})
                    log(f"Paired. {p['url']} will serve {p.get('service') or 'the route set in your dashboard'}")
                    STATE.wake.set()
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
        saved = STATE.saved
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
        if STATE.saved:
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
footer{margin-top:6px;text-align:center;font-size:12px;color:var(--muted)}footer a{color:var(--muted)}
</style></head><body><main>
<header>__FLAME__<div class="brand">DNS<span>alsa</span> <span class="muted small">connector</span></div>__PILL__</header>
__BODY__
<footer><a href="https://dnsalsa.nl" target="_blank" rel="noopener">dnsalsa.nl</a> · <a href="mailto:info@dnsalsa.nl">info@dnsalsa.nl</a></footer>
</main><script>
document.querySelectorAll('form[data-post]').forEach(f=>f.addEventListener('submit',async e=>{e.preventDefault();
const b=f.querySelector('button');b.disabled=true;await fetch(f.dataset.post,{method:'POST'});location.reload();}));
// Copy also works on plain http:// (no secure context), where navigator.clipboard is missing.
document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',async()=>{
const t=document.getElementById(b.dataset.copy).textContent;let ok=false;
try{await navigator.clipboard.writeText(t);ok=true}catch(e){}
if(!ok){const a=document.createElement('textarea');a.value=t;document.body.append(a);a.select();
try{ok=document.execCommand('copy')}catch(e){}a.remove()}
b.textContent=ok?'Copied':'Select and copy';setTimeout(()=>b.textContent='Copy',2000)}));
__REFRESH__
</script></body></html>"""
PAGE = PAGE.replace('__SANS__', _font('space-grotesk-latin-wght-normal.woff2')).replace('__MONO__', _font('space-mono-latin-700-normal.woff2')).replace('__FLAME__', FLAME)

CHECK = ('<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" '
         'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>')


def render():
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
<div class="code">{html.escape(code)}</div>
<ol><li>Open <a href="{base}/dashboard" target="_blank" rel="noopener">your DNSalsa dashboard</a>.</li>
<li>At the hostname you want, choose <b>Setup → Cloudflare Tunnel</b> and set the route: the service, as seen from this container.</li>
<li>Choose <b>DNSalsa connector</b> and enter the code above. This page updates by itself.</li></ol>
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
    refresh = '' if (saved and connected and (proxy_ok or not is_ha)) else 'setTimeout(()=>location.reload(),4000);'
    return PAGE.replace('__PILL__', pill).replace('__BODY__', '\n'.join(parts)).replace('__REFRESH__', refresh)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _allowed(self):
        """Docker's port mapping decides who reaches this page; compose.yaml binds it to 127.0.0.1.
        Pairing and unpairing are POSTs, so a page on another site can't trigger them without this check."""
        if self.command == 'POST':
            origin = self.headers.get('Origin')
            host = self.headers.get('Host', '')
            if origin and origin.split('://', 1)[-1] != host:
                self.send_error(403)
                return False
        return True

    def _send(self, code, body, ctype='text/html; charset=utf-8'):
        data = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._allowed():
            return
        if self.path.rstrip('/').endswith('status'):
            with STATE.lock:
                return self._send(200, json.dumps({'paired': bool(STATE.saved), 'code': STATE.code, 'connected': STATE.connected,
                                                   'service': STATE.service, 'homeAssistant': STATE.is_ha,
                                                   'proxyOk': STATE.proxy_ok, 'error': STATE.error}), 'application/json')
        self._send(200, render())

    def do_POST(self):
        if not self._allowed():
            return
        path = self.path.rstrip('/')
        if path.endswith('check'):
            check_proxy()
        elif path.endswith('unpair'):
            STATE.forget()
            log('Unpaired; getting a new pairing code')
            STATE.wake.set()
        self._send(200, '{"ok":true}', 'application/json')


def main():
    os.makedirs(DATA, exist_ok=True)
    for fn in (pairing_loop, tunnel_loop, proxy_loop):
        threading.Thread(target=fn, daemon=True).start()
    log(f'DNSalsa connector running, server {server()}. Status page on port {PORT}.')
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()


if __name__ == '__main__':
    main()
