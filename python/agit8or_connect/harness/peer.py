"""One harness worker: a ReferencePeer served over real HTTPS on 127.0.0.1.

    python -m agit8or_connect.harness.peer CONFIG.json

Several workers of the same installation can run at once: they bind the same port with SO_REUSEPORT (the
kernel spreads connections between them), share state through `state.json` under a file lock, and share the
replay, rate-limit, approval and destination stores through one SQLite database. Outbound requests go through
GuardedTransport with approved destinations; the peer's public names resolve (by the harness resolver) to
documentation addresses that the dialer maps to 127.0.0.1 ports. Nothing listens on anything but 127.0.0.1.

Control requests (`POST /_harness/op`, bearer token from the config) drive administrator actions. They exist
only in this test harness.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .. import discovery
from ..approvals import ActionApprovals, AdminAuth, ElevatedGrantPolicy
from ..errors import ConnectError
from ..extensions import HARDENING_EXTENSIONS, NonceIssuer
from ..http import Response
from ..keystore import FileMasterKeys, PrivateKeyCipher
from ..ratelimit import RateLimiter
from ..reference_peer import REFERENCE_CATALOG, ReferencePeer
from ..storage import (SqlActionApprovalStore, SqlDestinationStore, SqlGrantApprovalStore, SqliteBackend,
                       SqlRateLimitStore, SqlReplayStore)
from ..transport import GuardedTransport
from .state import locked_state

_local = threading.local()


class HttpsNetwork:
    """The reference peer's Network, over GuardedTransport. Destinations are keyed by origin."""

    def __init__(self, cfg: dict, destinations: SqlDestinationStore):
        self.cfg, self.destinations = cfg, destinations

    def register(self, base_url, handler):
        pass

    def current_source(self):
        return getattr(_local, 'source', None)

    def _transport(self, origin: str) -> GuardedTransport:
        with open(self.cfg['resolver_file']) as f:          # re-read: tests change "DNS" while running
            resolver_map = json.load(f)
        ports = self.cfg['dial_ports']                       # documentation address -> local port

        def resolver(host, port, *a):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port)) for ip in resolver_map.get(host, [])]

        def dialer(ip, port, timeout, source_address=None):
            s = socket.create_connection(('127.0.0.1', ports[ip]), timeout=timeout)
            return s, ip                                     # the validated address the test mapped to
        return GuardedTransport(self.destinations, origin, resolver=resolver, _dialer=dialer, total_timeout=10)

    def request(self, method, url, headers=None, body=None, source=None) -> Response:
        origin = discovery.origin(url)
        t = self._transport(origin)
        try:
            return t.request(method, url, headers=dict(headers or {}), body=body or None)
        except ConnectError as e:
            if e.code == 'destination_changed':
                self.destinations.block(origin, getattr(e, 'evidence', {}) or {'code': e.code})
            raise


def build_peer(cfg: dict):
    db = SqliteBackend(cfg['database'])
    db.migrate()
    destinations = SqlDestinationStore(db)
    net = HttpsNetwork(cfg, destinations)
    replay = SqlReplayStore(db)
    limits = RateLimiter(SqlRateLimitStore(db))
    peer = ReferencePeer(cfg['base_url'], net, display_name=cfg['name'], replay=replay, rate_limiter=limits,
                         extensions=HARDENING_EXTENSIONS if cfg.get('extensions') else None)
    peer.elevated = ElevatedGrantPolicy(SqlGrantApprovalStore(db), REFERENCE_CATALOG,
                                        kill_switch=lambda: peer.kill_switch)
    peer.actions = ActionApprovals(SqlActionApprovalStore(db), kill_switch=lambda: peer.kill_switch)
    peer.nonces = NonceIssuer(bytes.fromhex(cfg['nonce_secret_hex']))
    cipher = PrivateKeyCipher(FileMasterKeys(cfg['master_key_file']))
    return peer, cipher, net


def _admin(arg):
    import time
    return AdminAuth(arg, int(time.time())) if arg else None


def control(peer: ReferencePeer, op: str, a: dict):
    """Administrator actions the tests drive. Returns JSON-able results."""
    if op == 'info':
        return {'installation_id': peer.installation_id, 'connections': {
            cid: {'state': c.state, 'role': c.role, 'remote_connection_id': c.remote_connection_id,
                  'negotiated': c.negotiated, 'keys': {k: v['state'] for k, v in c.keys.items()},
                  'received_events': [e['id'] for e in c.received_events]}
            for cid, c in peer.connections.items()}, 'requests': peer.requests, 'pid': os.getpid()}
    if op == 'create_invitation':
        return {'code': peer.create_invitation()}
    if op == 'start_pairing':
        c = peer.start_pairing(a['base'], a['code'], requested_scopes=a['scopes'])
        return {'connection_id': c.id, 'request_id': c.request_id, 'sas': c.sas}
    if op == 'approve':
        c = peer.approve(a['request_id'], scopes=a['scopes'], tenant_grants=a.get('tenant_grants', []),
                         admin=_admin(a.get('admin')))
        return {'state': c.state}
    if op == 'second_approve':
        return {'state': peer.second_approve(a['request_id'], admin=_admin(a['admin'])).state}
    if op == 'poll':
        return {'status': peer.poll(a['connection_id'])}
    if op == 'accept':
        peer.accept(a['connection_id'])
        return {'state': peer.connections[a['connection_id']].state}
    if op == 'get_token':
        t = peer.get_token(a['connection_id'], a.get('scopes', ()), actor=a.get('actor'))
        return {'scope': t['scope'], 'access_token': t['access_token']}
    if op == 'call':
        r = peer.call(a['connection_id'], a.get('method', 'GET'), a['url'], tenant=a.get('tenant'),
                      body=json.dumps(a['body']).encode() if 'body' in a else b'',
                      token=a.get('token'))
        return {'status': r.status, 'body': json.loads(r.body or b'null')}
    if op == 'send_event':
        r = peer.send_event(a['connection_id'], a['type'], a.get('tenant', ''), a.get('data', {}),
                            event_id=a.get('event_id'))
        return {'status': r.status, 'body': json.loads(r.body or b'null')}
    if op == 'rotate':
        return {'rotated': peer.rotate(a['connection_id'], overlap=a.get('overlap', 3600))}
    if op == 'kill_switch':
        peer.set_kill_switch(bool(a['engaged']))
        return {'kill_switch': peer.kill_switch}
    if op == 'export_client':
        # TEST ONLY: hands the second implementation (TypeScript) the calling side of this connection.
        from ..keys import private_key_to_pem
        c = peer.connections[a['connection_id']]
        kid, key = c.active_key()
        return {'client_id': c.remote_connection_id, 'private_key_pem': private_key_to_pem(key), 'kid': kid,
                'endpoints': c.remote_endpoints, 'remote_installation': c.remote_installation,
                'installation_id': peer.installation_id, 'negotiated': c.negotiated}
    raise ConnectError('invalid_request', f'unknown harness op {op}', 400)


def make_handler(cfg, peer, cipher):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *a):
            pass

        def _reply(self, r: Response):
            self.send_response(r.status)
            for k, v in r.headers.items():
                self.send_header(k, v)
            self.send_header('Content-Length', str(len(r.body)))
            self.send_header('Agit8or-Harness-Worker', str(os.getpid()))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(r.body)
            self.close_connection = True

        def _body(self):
            n = int(self.headers.get('Content-Length') or 0)
            if n > 1024 * 1024:
                raise ConnectError('too_large', 'body too large', 413)
            return self.rfile.read(n) if n else b''

        def _do(self, method):
            try:
                body = self._body()
            except ConnectError as e:
                return self._reply(Response(e.status, {'Content-Type': 'application/json'},
                                            json.dumps(e.as_dict()).encode()))
            path = urlsplit(self.path).path
            _local.source = self.client_address[0]
            with locked_state(peer, cfg['state_dir'], cipher):
                if path == '/_harness/op' and method == 'POST':
                    if self.headers.get('Authorization') != f'Bearer {cfg["control_token"]}':
                        return self._reply(Response(403, {}, b''))
                    req = json.loads(body)
                    try:
                        out = {'ok': True, 'result': control(peer, req['op'], req.get('args', {}))}
                    except ConnectError as e:
                        out = {'ok': False, 'error': e.code, 'message': e.message}
                    return self._reply(Response(200, {'Content-Type': 'application/json'}, json.dumps(out).encode()))
                url = cfg['base_url'] + self.path
                headers = {k: v for k, v in self.headers.items()}
                return self._reply(peer.handle(method, url, headers, body))

        def do_GET(self):
            self._do('GET')

        def do_POST(self):
            self._do('POST')

    return Handler


class ReusePortServer(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        super().server_bind()

    def handle_error(self, request, client_address):
        pass


def main(argv):
    with open(argv[0]) as f:
        cfg = json.load(f)
    peer, cipher, _ = build_peer(cfg)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cfg['cert_file'], cfg['key_file'])
    srv = ReusePortServer(('127.0.0.1', cfg['listen_port']), make_handler(cfg, peer, cipher))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print('ready', flush=True)
    srv.serve_forever()


if __name__ == '__main__':
    main(sys.argv[1:])
