"""Tests for the DNSalsa connector. Standard library only: python3 -m unittest discover -s tests"""
import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = tempfile.mkdtemp(prefix='dnsalsa-connector-test-')
os.environ['DNSALSA_DATA'] = DATA
sys.path.insert(0, os.path.join(ROOT, 'app'))
import main  # noqa: E402  (needs DNSALSA_DATA set first)


def serve(handler_cls):
    """Start a throwaway HTTP server; returns (base_url, server)."""
    srv = ThreadingHTTPServer(('127.0.0.1', 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f'http://127.0.0.1:{srv.server_address[1]}', srv


def stop(srv):
    srv.shutdown()
    srv.server_close()


class FakeService(BaseHTTPRequestHandler):
    """Home Assistant (400 to a forwarded request unless the proxy is trusted), or any other web service."""
    home_assistant = True
    trusted = False
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        FakeService.seen.append((self.path, dict(self.headers)))
        if not FakeService.home_assistant:
            body = b'<html>NAS login</html>'
            code = 200
        else:
            body = b'{"name":"Home Assistant","short_name":"Assistant"}'
            code = 400 if self.headers.get('X-Forwarded-For') and not FakeService.trusted else 200
        self.send_response(code)
        self.end_headers()
        self.wfile.write(body)


class RouteCheck(unittest.TestCase):
    def setUp(self):
        self.url, self.srv = serve(FakeService)
        FakeService.seen, FakeService.home_assistant, FakeService.trusted = [], True, False

    def tearDown(self):
        stop(self.srv)
        main.STATE.forget()

    def test_home_assistant_not_trusted_yet(self):
        self.assertIs(main.check_proxy(self.url), False)
        self.assertTrue(main.STATE.is_ha)

    def test_home_assistant_trusted(self):
        FakeService.trusted = True
        self.assertIs(main.check_proxy(self.url), True)

    def test_uses_a_public_page_without_login(self):
        main.check_proxy(self.url)
        path, headers = FakeService.seen[-1]
        self.assertEqual(path, '/manifest.json')
        self.assertNotIn('Authorization', headers)
        self.assertEqual(headers.get('X-Forwarded-For'), '203.0.113.7')

    def test_other_services_are_left_alone(self):
        FakeService.home_assistant = False
        self.assertIsNone(main.check_proxy(self.url))
        self.assertFalse(main.STATE.is_ha)
        self.assertEqual(len(FakeService.seen), 1, 'no forwarded request to a service that is not Home Assistant')

    def test_down_or_not_http_is_nothing_to_check(self):
        self.assertIsNone(main.check_proxy('http://127.0.0.1:9'))
        self.assertIsNone(main.check_proxy('ssh://192.168.1.10:22'))
        self.assertFalse(main.STATE.is_ha)

    def test_route_falls_back_to_the_one_from_pairing(self):
        main.METRICS = '127.0.0.1:9'   # no cloudflared running
        with main.STATE.lock:
            main.STATE.saved = {'token': 't', 'hostname': 'jansen.dnsalsa.nl', 'url': 'https://jansen.dnsalsa.nl', 'service': 'http://nas:5000'}
        self.assertEqual(main.current_service(), 'http://nas:5000')


class FakeCloudflared(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        cfg = {'version': 3, 'config': {'ingress': [
            {'hostname': 'jansen-nas.dnsalsa.nl', 'service': 'https://192.168.1.10:5001'},
            {'hostname': 'jansen.dnsalsa.nl', 'service': 'http://192.168.1.20:8123'},
            {'service': 'http_status:404'}]}}
        data = json.dumps(cfg).encode()
        self.send_response(200 if self.path == '/config' else 404)
        self.end_headers()
        self.wfile.write(data)


class CurrentRoute(unittest.TestCase):
    def test_follows_route_changes_from_cloudflared(self):
        url, srv = serve(FakeCloudflared)
        old = main.METRICS
        main.METRICS = url.split('://', 1)[1]
        try:
            with main.STATE.lock:
                main.STATE.saved = {'token': 't', 'hostname': 'jansen.dnsalsa.nl', 'url': 'https://jansen.dnsalsa.nl', 'service': 'http://old:1'}
            self.assertEqual(main.current_service(), 'http://192.168.1.20:8123', 'its own hostname, not an extra service')
        finally:
            main.METRICS = old
            stop(srv)
            main.STATE.forget()


class FakeDNSalsa(BaseHTTPRequestHandler):
    polls = 0
    started = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length') or 0)) or b'{}')
        if self.path == '/api/pair/start':
            FakeDNSalsa.started.append(body)
            out = {'code': 'K7QP-4XM2', 'secret': 's' * 32, 'kind': body.get('kind'), 'expiresAt': (time.time() + 900) * 1000}
        elif self.path == '/api/pair/poll':
            assert body.get('secret') == 's' * 32
            FakeDNSalsa.polls += 1
            out = {'status': 'waiting'} if FakeDNSalsa.polls < 2 else \
                {'status': 'paired', 'token': 'tok-123', 'hostname': 'jansen.dnsalsa.nl', 'url': 'https://jansen.dnsalsa.nl',
                 'service': 'https://192.168.1.10:5001'}
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(data)


class Pairing(unittest.TestCase):
    def test_code_then_token_and_route_saved_privately(self):
        url, srv = serve(FakeDNSalsa)
        os.environ['DNSALSA_SERVER'] = url
        real_time = main.time
        main.time = types.SimpleNamespace(time=real_time.time, sleep=lambda s: real_time.sleep(0.02))
        try:
            main.STATE.forget()
            threading.Thread(target=main.pairing_loop, daemon=True).start()
            for _ in range(200):
                if main.STATE.saved:
                    break
                real_time.sleep(0.02)
            self.assertEqual(FakeDNSalsa.started[0]['kind'], 'connector', 'DNSalsa needs to know the route comes from the dashboard')
            self.assertTrue(FakeDNSalsa.started[0]['device'].startswith('DNSalsa connector ('))
            self.assertEqual(main.STATE.saved['service'], 'https://192.168.1.10:5001')
            self.assertIsNone(main.STATE.code, 'the code disappears once paired')
            self.assertEqual(stat.S_IMODE(os.stat(main.STATE_FILE).st_mode), 0o600, 'the tunnel token is only readable by the connector')
            self.assertEqual(main.State()._load()['token'], 'tok-123', 'survives a restart')
        finally:
            main.time = real_time
            del os.environ['DNSALSA_SERVER']
            stop(srv)
            main.STATE.forget()


class Page(unittest.TestCase):
    def tearDown(self):
        main.STATE.forget()
        with main.STATE.lock:
            main.STATE.code = None
        main.TRUSTED_PROXY = ''

    def test_pairing_code_steps_and_escaping(self):
        with main.STATE.lock:
            main.STATE.code, main.STATE.code_expires = 'K7QP-4XM2', time.time() + 600
            main.STATE.error = '<script>alert(1)</script>'
        page = main.render()
        self.assertIn('K7QP-4XM2', page)
        self.assertIn('DNSalsa connector', page)
        self.assertIn('Not paired', page)
        self.assertNotIn('<script>alert(1)', page)
        self.assertIn('&lt;script&gt;', page)

    def test_route_shown_and_no_home_assistant_steps_for_other_services(self):
        with main.STATE.lock:
            main.STATE.saved = {'token': 't', 'hostname': 'jansen.dnsalsa.nl', 'url': 'https://jansen.dnsalsa.nl'}
            main.STATE.connected, main.STATE.service, main.STATE.is_ha = True, 'https://192.168.1.10:5001', False
        page = main.render()
        self.assertIn('https://192.168.1.10:5001', page)
        self.assertNotIn('Trust X-Forwarded-For', page)
        self.assertNotIn('setTimeout(()=>location.reload()', page, 'no auto-refresh once connected')

    def test_home_assistant_steps_until_it_works(self):
        main.TRUSTED_PROXY = '172.30.57.0/24'
        with main.STATE.lock:
            main.STATE.saved = {'token': 't', 'hostname': 'jansen.dnsalsa.nl', 'url': 'https://jansen.dnsalsa.nl'}
            main.STATE.connected, main.STATE.service, main.STATE.is_ha, main.STATE.proxy_ok = True, 'http://192.168.1.20:8123', True, False
        page = main.render()
        self.assertIn('Trust X-Forwarded-For', page)
        self.assertIn('172.30.57.0/24', page)
        self.assertIn('Login attempts before ban</b> to <b>10', page)
        with main.STATE.lock:
            main.STATE.proxy_ok = True
        page = main.render()
        self.assertNotIn('Trust X-Forwarded-For', page)
        self.assertIn('accepts traffic from the tunnel', page)

    def test_fonts_are_embedded(self):
        self.assertIn('data:font/woff2;base64,', main.PAGE, 'the page has no external requests')


class Requests(unittest.TestCase):
    def stub(self, method, headers):
        sent = []
        return types.SimpleNamespace(command=method, headers=headers, send_error=lambda c: sent.append(c)), sent

    def test_page_open_to_anyone_who_reaches_the_port(self):
        s, _ = self.stub('GET', {'Host': '192.168.1.5:8099'})
        self.assertTrue(main.Handler._allowed(s))

    def test_another_site_cannot_unpair(self):
        s, sent = self.stub('POST', {'Host': '127.0.0.1:8099', 'Origin': 'https://evil.example'})
        self.assertFalse(main.Handler._allowed(s))
        self.assertEqual(sent, [403])
        s, _ = self.stub('POST', {'Host': '127.0.0.1:8099', 'Origin': 'http://127.0.0.1:8099'})
        self.assertTrue(main.Handler._allowed(s))


class Release(unittest.TestCase):
    """Checks that keep a release consistent; the workflows rely on these formats."""

    def read(self, *p):
        with open(os.path.join(ROOT, *p)) as f:
            return f.read()

    def test_version_has_a_changelog_entry(self):
        version = self.read('VERSION').strip()
        self.assertRegex(version, r'^\d+\.\d+\.\d+$')
        first = re.search(r'^## ([\d.]+)', self.read('CHANGELOG.md'), re.M).group(1)
        self.assertEqual(version, first, 'raise VERSION and add a CHANGELOG entry together')

    def test_cloudflared_pinned_with_checksums(self):
        dockerfile = self.read('Dockerfile')
        self.assertRegex(dockerfile, r'(?m)^ARG CLOUDFLARED_VERSION=\d{4}\.\d+\.\d+$')
        self.assertRegex(dockerfile, r'ARCH=amd64; SUM=[0-9a-f]{64} ;;')
        self.assertRegex(dockerfile, r'ARCH=arm64; SUM=[0-9a-f]{64} ;;')
        self.assertIn('sha256sum -c', dockerfile)

    def test_compose_matches(self):
        compose = self.read('compose.yaml')
        self.assertIn('image: ghcr.io/dnsalsa/connector:latest', compose)
        self.assertIn('IMAGE: ghcr.io/dnsalsa/connector', self.read('.github', 'workflows', 'publish.yml'))
        net = re.search(r'DNSALSA_TRUSTED_PROXY: (\S+)', compose).group(1)
        self.assertIn(f'subnet: {net}', compose, 'the address Home Assistant trusts is the compose network')
        self.assertIn(f'127.0.0.1:{main.PORT}:{main.PORT}', compose)


if __name__ == '__main__':
    unittest.main()
