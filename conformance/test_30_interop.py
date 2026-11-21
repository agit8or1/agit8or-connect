"""Reference-peer interoperability: two independent in-memory installations,
built only on the Python SDK, pair and talk in every version combination.

| initiator | responder | expected flow |
| 1.0       | 1.0       | v1 code flow  |
| 1.0       | 1.1       | v1 code flow  |
| 1.1       | 1.0       | v1 code flow (Quick Connect refused with extension_not_negotiated) |
| 1.1       | 1.1       | Quick Connect, and the code flow still works |

Plus the properties every implementation must keep: equal SAS on both sides,
single-use codes, default-deny of an unapproved source on qc_exchange, tenant
isolation between two installations using the same tenant ids, revocation."""
import json
import unittest

import _support  # noqa: F401  (puts the SDK on sys.path)
from agit8or_connect import discovery, quick_connect as qc
from agit8or_connect.errors import ConnectError
from agit8or_connect.reference_peer import API, Network, ReferencePeer

SCOPES = ['connection:read', 'customers:read', 'events:publish']
A_SRC, B_SRC = '203.0.113.10', '198.51.100.7'


class Clock:
    def __init__(self, t=1767225600):
        self.t = t

    def __call__(self):
        return self.t


def make(a_qc, b_qc, net=None, clock=None, a_base='https://initiator.example.test'):
    clock, net = clock or Clock(), net or Network()
    a = ReferencePeer(a_base, net, display_name='Initiator', clock=clock, tenants={'org-1': 'Initiator customer'},
                      quick_connect=a_qc, egress=[A_SRC + '/32'], source_address=A_SRC)
    b = ReferencePeer('https://responder.example.test', net, display_name='Responder', clock=clock,
                      quick_connect=b_qc, egress=['198.51.100.0/28'], source_address=B_SRC)
    return a, b, net, clock


def approve_both(a, b, conn):
    b.approve(conn.request_id, scopes=SCOPES, tenant_grants=[
        {'remote_tenant': 'org-1', 'local_tenant': 'cust-1', 'scopes': ['customers:read', 'events:publish']}],
        requested_scopes=['connection:read'])
    assert a.poll(conn.id) == 'approved'
    a.accept(conn.id, scopes=['connection:read'])
    return b.connections[b.requests[conn.request_id]]


def code_flow(a, b):
    code = b.create_invitation()
    conn = a.start_pairing(b.base, code, requested_scopes=SCOPES, proposed_tenants=[{'id': 'org-1'}])
    return conn, approve_both(a, b, conn)


def quick_connect(a, b, approve=True):
    url = a.qc_start(b.base, requested_scopes=SCOPES)
    back = b.qc_authorize(b.qc_review(url), approve=approve)
    conn = a.qc_callback(back, proposed_tenants=[{'id': 'org-1', 'label': 'Customer'}])
    return conn, approve_both(a, b, conn)


class VersionMatrix(unittest.TestCase):
    def assert_working(self, a, b, conn, bconn):
        self.assertRegex(conn.sas, r'^\d{4}-\d{4}$')
        self.assertEqual(conn.sas, bconn.sas)
        r = a.call(conn.id, 'GET', b.url(f'{API}/customers/current'), tenant='org-1')
        self.assertEqual(r.status, 200, r.body)
        self.assertEqual(b.call(bconn.id, 'POST', a.url(f'{API}/test')).status, 200)
        a.send_event(conn.id, 'alert.raised', 'org-1', {'alert_id': 'x'})

    def test_1_0_to_1_0(self):
        a, b, *_ = make(False, False)
        self.assert_working(a, b, *code_flow(a, b))

    def test_1_0_to_1_1(self):
        a, b, *_ = make(False, True)
        self.assert_working(a, b, *code_flow(a, b))
        self.assertEqual(discovery.fetch(a.network, b.base).version, '1')

    def test_1_1_to_1_0_falls_back(self):
        a, b, net, _ = make(True, False)
        with self.assertRaises(ConnectError) as e:
            a.qc_start(b.base, requested_scopes=SCOPES)
        self.assertEqual(e.exception.code, 'extension_not_negotiated')
        self.assertFalse(any(u.endswith(qc.EXCHANGE_PATH) for _, u in net.log))
        self.assert_working(a, b, *code_flow(a, b))

    def test_1_1_to_1_1_quick_connect(self):
        a, b, net, _ = make(True, True)
        self.assert_working(a, b, *quick_connect(a, b))
        self.assertFalse(any('password' in u.lower() for _, u in net.log))

    def test_1_1_to_1_1_code_flow_still_works(self):
        a, b, *_ = make(True, True)
        self.assert_working(a, b, *code_flow(a, b))


class RequiredProperties(unittest.TestCase):
    def test_unapproved_source_refused_before_anything_is_recorded(self):
        a, b, *_ = make(True, True)
        a.source_address = '192.0.2.99'
        with self.assertRaises(ConnectError) as e:
            quick_connect(a, b)
        self.assertEqual((e.exception.code, e.exception.status), ('source_not_authorised', 403))
        self.assertFalse(any(c.state == 'awaiting_local_approval' for c in b.connections.values()))

    def test_denied_authorisation(self):
        a, b, *_ = make(True, True)
        with self.assertRaises(ConnectError) as e:
            quick_connect(a, b, approve=False)
        self.assertEqual(e.exception.code, 'access_denied')

    def test_downgrade_after_accept_detected(self):
        a, b, *_ = make(True, True)
        back = b.qc_authorize(b.qc_review(a.qc_start(b.base, requested_scopes=SCOPES)))
        b.qc_advertise = False
        with self.assertRaises(ConnectError) as e:
            a.qc_callback(back)
        self.assertEqual(e.exception.code, 'downgrade_detected')

    def test_pairing_code_single_use(self):
        a, b, *_ = make(False, False)
        code = b.create_invitation()
        a.start_pairing(b.base, code, requested_scopes=['customers:read'])
        with self.assertRaises(ConnectError) as e:
            a.start_pairing(b.base, code, requested_scopes=['customers:read'])
        self.assertEqual(e.exception.code, 'invalid_pairing_code')

    def test_two_installations_with_identical_tenant_ids_stay_apart(self):
        clock, net = Clock(), Network()
        a1, b, *_ = make(False, False, net=net, clock=clock, a_base='https://one.example.test')
        a2 = ReferencePeer('https://two.example.test', net, display_name='Second', clock=clock,
                           tenants={'org-1': 'Second customer'})
        c1, _ = code_flow(a1, b)
        code = b.create_invitation()
        c2 = a2.start_pairing(b.base, code, requested_scopes=SCOPES, proposed_tenants=[{'id': 'org-1'}])
        b.approve(c2.request_id, scopes=SCOPES, tenant_grants=[
            {'remote_tenant': 'org-1', 'local_tenant': 'cust-2', 'scopes': ['customers:read']}])
        self.assertEqual(a2.poll(c2.id), 'approved')
        a2.accept(c2.id)
        n1 = json.loads(a1.call(c1.id, 'GET', b.url(f'{API}/customers/current'), tenant='org-1').body)['name']
        n2 = json.loads(a2.call(c2.id, 'GET', b.url(f'{API}/customers/current'), tenant='org-1').body)['name']
        self.assertNotEqual(n1, n2)

    def test_revoked_connection_refuses_tokens(self):
        a, b, *_ = make(False, False)
        conn, bconn = code_flow(a, b)
        b.revoke(bconn.id)
        with self.assertRaises(ConnectError):
            a.get_token(conn.id)


if __name__ == '__main__':
    unittest.main()
