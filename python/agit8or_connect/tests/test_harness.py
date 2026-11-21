"""Real-network integration harness: two installations, each served by several worker processes over HTTPS on
127.0.0.1 with a test-only CA, persistent SQLite stores, a restart, a DNS change, the kill switch, negotiated
extensions, and the TypeScript SDK as a second implementation of the calling side.

Evidence label: local real-network (TCP + TLS over loopback, separate OS processes). Public names resolve to
documentation addresses through the harness resolver; the dialer maps them to 127.0.0.1 ports. Not run on
Windows (SO_REUSEPORT, fcntl). Set AGIT8OR_CONNECT_SKIP_HARNESS=1 to skip.
"""
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

from agit8or_connect import tokens
from agit8or_connect.destinations import new_destination
from agit8or_connect.keys import private_key_from_pem
from agit8or_connect.keystore import generate_master_key
from agit8or_connect.storage import SqlDestinationStore, SqliteBackend
from agit8or_connect.tests.tls_support import TestPKI
from cryptography.hazmat.primitives import serialization

PY_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TS_ROOT = os.path.join(os.path.dirname(PY_ROOT), 'typescript')
WORKERS = 2
API = '/connect/v1'


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Conn(http.client.HTTPSConnection):
    """Connect to 127.0.0.1 but verify the certificate for the public test name."""

    def __init__(self, name, port, ctx):
        super().__init__(name, port, context=ctx, timeout=20)

    def connect(self):
        raw = socket.create_connection(('127.0.0.1', self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


@unittest.skipIf(os.environ.get('AGIT8OR_CONNECT_SKIP_HARNESS') or sys.platform == 'win32', 'harness skipped')
class HttpsHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='a8c-harness-')
        cls.pki = TestPKI()
        cls.ctx = ssl.create_default_context(cadata=cls.pki.ca_pem)
        cls.peers = {}
        cls.resolver_file = os.path.join(cls.dir, 'resolver.json')
        names = {'a': ('peer-a.example.test', '203.0.113.10'), 'b': ('peer-b.example.test', '203.0.113.20')}
        dial = {}
        for label, (name, ip) in names.items():
            port = free_port()
            dial[ip] = port
            cls.peers[label] = {'name': name, 'ip': ip, 'port': port, 'base': f'https://{name}:{port}'}
        cls.write_resolver({n: [ip] for n, ip in names.values()})
        for label, p in cls.peers.items():
            d = os.path.join(cls.dir, label)
            os.makedirs(d)
            cert, key = cls.pki.leaf(names=(p['name'],), days=30)
            cert_file, key_file = os.path.join(d, 'cert.pem'), os.path.join(d, 'key.pem')
            with open(cert_file, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
            mk = os.path.join(d, 'master-keys.json')
            fd = os.open(mk, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump({'current': 'mk1', 'keys': {'mk1': generate_master_key()}}, f)
            cfg = {'name': f'Harness {label.upper()}', 'base_url': p['base'], 'listen_port': p['port'],
                   'cert_file': cert_file, 'key_file': key_file, 'database': os.path.join(d, 'connect.db'),
                   'state_dir': d, 'master_key_file': mk, 'nonce_secret_hex': os.urandom(32).hex(),
                   'control_token': os.urandom(16).hex(), 'resolver_file': cls.resolver_file, 'dial_ports': dial,
                   'extensions': True}
            p['cfg'] = cfg
            p['cfg_file'] = os.path.join(d, 'config.json')
            with open(p['cfg_file'], 'w') as f:
                json.dump(cfg, f)
            db = SqliteBackend(cfg['database'])
            db.migrate()
            other = cls.peers['b' if label == 'a' else 'a'] if len(cls.peers) == 2 else None
            p['db'] = db
        for label, p in cls.peers.items():           # each side approves the other's destination
            other = cls.peers['b' if label == 'a' else 'a']
            origin = f'https://{other["name"]}:{other["port"]}'
            SqlDestinationStore(p['db']).put(new_destination(origin, other['name'], other['port'],
                                                             [f'{other["ip"]}/32'], ca_pem=cls.pki.ca_pem,
                                                             approved_by=['harness-admin-1', 'harness-admin-2']))
        cls.procs = {'a': [], 'b': []}
        for label in cls.peers:
            cls.start(label)

    @classmethod
    def write_resolver(cls, mapping):
        tmp = cls.resolver_file + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(mapping, f)
        os.replace(tmp, cls.resolver_file)

    @classmethod
    def start(cls, label):
        p = cls.peers[label]
        for _ in range(WORKERS):
            proc = subprocess.Popen([sys.executable, '-m', 'agit8or_connect.harness.peer', p['cfg_file']], cwd=PY_ROOT,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            line = proc.stdout.readline().strip()
            if line != 'ready':
                proc.kill()
                raise RuntimeError(f'worker did not start: {proc.stderr.read()[-2000:]}')
            cls.procs[label].append(proc)

    @classmethod
    def stop(cls, label):
        for proc in cls.procs[label]:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
            for s in (proc.stdout, proc.stderr):
                s.close()
        cls.procs[label] = []

    @classmethod
    def tearDownClass(cls):
        for label in list(cls.procs):
            cls.stop(label)
        shutil.rmtree(cls.dir, ignore_errors=True)

    def raw(self, label, method, path, headers=None, body=b''):
        p = self.peers[label]
        c = _Conn(p['name'], p['port'], self.ctx)
        try:
            c.request(method, path, body=body or None, headers=headers or {})
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            c.close()

    def op(self, label, op, **args):
        st, h, body = self.raw(label, 'POST', '/_harness/op',
                               {'Authorization': f'Bearer {self.peers[label]["cfg"]["control_token"]}',
                                'Content-Type': 'application/json'}, json.dumps({'op': op, 'args': args}).encode())
        self.assertEqual(st, 200, body)
        out = json.loads(body)
        out['_worker'] = h.get('Agit8or-Harness-Worker')
        return out

    def ok(self, label, op, **args):
        out = self.op(label, op, **args)
        self.assertTrue(out['ok'], out)
        return out['result']

    def test_harness_end_to_end(self):
        a, b = self.peers['a'], self.peers['b']
        # --- pairing over HTTPS, through GuardedTransport in both directions --------------------------
        code = self.ok('b', 'create_invitation')['code']
        started = self.ok('a', 'start_pairing', base=b['base'], code=code, scopes=['connection:read', 'events:publish'])
        self.ok('b', 'approve', request_id=started['request_id'], scopes=['connection:read', 'events:publish'])
        self.assertEqual(self.ok('a', 'poll', connection_id=started['connection_id'])['status'], 'approved')
        self.ok('a', 'accept', connection_id=started['connection_id'])
        cid = started['connection_id']
        info_a = self.ok('a', 'info')
        self.assertEqual(info_a['connections'][cid]['state'], 'active')
        self.assertEqual(info_a['connections'][cid]['negotiated'], {'action-approval': 1, 'actor': 1, 'dpop-nonce': 1})

        # --- several workers really serve one installation ----------------------------------------------
        pids = {self.op('b', 'info')['_worker'] for _ in range(24)}
        self.assertGreaterEqual(len(pids), 2, 'requests were spread over more than one worker process')

        # --- tokens (dpop-nonce/1 retry) and an API call -----------------------------------------------
        tok = self.ok('a', 'get_token', connection_id=cid, actor='user:7')
        test_url = b['base'] + f'{API}/test'
        r = self.ok('a', 'call', connection_id=cid, url=test_url, token=tok['access_token'])
        self.assertEqual(r['status'], 200)

        # --- a DPoP proof is single use across workers and across a restart ---------------------------
        client = self.ok('a', 'export_client', connection_id=cid)
        key = private_key_from_pem(client['private_key_pem'])
        st, h, body = self.raw('b', 'GET', f'{API}/test', {'Authorization': f'DPoP {tok["access_token"]}',
                                                            'DPoP': tokens.build_dpop_proof(key, 'GET', test_url,
                                                                                            access_token=tok['access_token'])})
        nonce = h.get('DPoP-Nonce')
        self.assertEqual(st, 401, 'no nonce yet')
        proof = tokens.build_dpop_proof(key, 'GET', test_url, access_token=tok['access_token'], nonce=nonce)
        hdrs = {'Authorization': f'DPoP {tok["access_token"]}', 'DPoP': proof}
        self.assertEqual(self.raw('b', 'GET', f'{API}/test', hdrs)[0], 200)
        replays = {self.raw('b', 'GET', f'{API}/test', hdrs)[0] for _ in range(4)}
        self.assertEqual(replays, {401}, 'replayed on every worker')

        # --- events: delivered once, duplicate recognised ---------------------------------------------
        ev = '11111111-2222-4333-8444-555555555555'
        self.assertEqual(self.ok('a', 'send_event', connection_id=cid, type='connect.test', event_id=ev)['body']['status'],
                         'accepted')
        self.assertEqual(self.ok('a', 'send_event', connection_id=cid, type='connect.test', event_id=ev)['body']['status'],
                         'duplicate')

        # --- restart every worker of B: state, keys (encrypted at rest) and replay records survive ------
        self.stop('b')
        self.start('b')
        self.assertEqual(self.raw('b', 'GET', f'{API}/test', hdrs)[0], 401, 'replay store survived the restart')
        r = self.ok('a', 'call', connection_id=cid, url=test_url)
        self.assertEqual(r['status'], 200)
        with open(os.path.join(self.dir, 'b', 'state.json')) as f:
            state_text = f.read()
        self.assertNotIn('PRIVATE KEY', state_text)
        self.assertIn('a8ck1.', state_text)

        # --- second implementation: TypeScript SDK as the caller -----------------------------------------
        node = shutil.which('node')
        if node:
            tcfg = dict(client, ca_pem=self.pki.ca_pem, doc_ip=b['ip'], dial_port=b['port'])
            tfile = os.path.join(self.dir, 'ts-client.json')
            with open(tfile, 'w') as f:
                json.dump(tcfg, f)
            out = subprocess.run([node, 'test/harness_client.ts', tfile], cwd=TS_ROOT, capture_output=True, text=True,
                                 timeout=120)
            self.assertEqual(out.returncode, 0, out.stderr[-3000:])
            res = json.loads(out.stdout.strip().splitlines()[-1])
            if os.environ.get('AGIT8OR_CONNECT_HARNESS_VERBOSE'):
                print('typescript client:', json.dumps(res, sort_keys=True), file=sys.stderr)
            self.assertEqual(res['test_status'], 200, res)
            self.assertEqual(res['test_body']['connection_id'], client['client_id'])
            self.assertTrue(res.get('token_nonce_retry'), 'TypeScript client followed use_dpop_nonce')
            self.assertEqual(res['replay_status'], 401)
            self.assertEqual(res['event']['status'], 'accepted')
            self.assertEqual(res['event_again']['status'], 'duplicate')
            self.assertIn(res['event_id'], self.ok('b', 'info')['connections'][client['client_id']]['received_events'])
        elif os.environ.get('CONFORMANCE_REQUIRE_NODE'):
            self.fail('node is required for the second-implementation step')

        # --- kill switch on B ---------------------------------------------------------------------------
        self.ok('b', 'kill_switch', engaged=True)
        r = self.op('a', 'call', connection_id=cid, url=test_url)
        self.assertEqual((r['ok'], r.get('error')), (False, 'kill_switch'), r)
        self.ok('b', 'kill_switch', engaged=False)
        self.assertEqual(self.ok('b', 'info')['connections'][client['client_id']]['state'], 'suspended',
                         'releasing the kill switch resumes nothing')

        # --- DNS change: B's name now resolves elsewhere -> A refuses and blocks, and stays blocked ------
        self.write_resolver({a['name']: [a['ip']], b['name']: ['203.0.113.99']})
        r = self.op('a', 'get_token', connection_id=cid)
        self.assertEqual(r.get('error'), 'destination_changed', r)
        self.write_resolver({a['name']: [a['ip']], b['name']: [b['ip']]})
        r = self.op('a', 'get_token', connection_id=cid)
        self.assertEqual(r.get('error'), 'security_blocked', 'blocked until an administrator reviews the change')


if __name__ == '__main__':
    unittest.main()
