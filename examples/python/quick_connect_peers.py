"""Minimal Python peers: two in-memory installations built only on the
reference SDK pair with Quick Connect, finish with the v1 approval, make an
authorised call, send a signed event and run the diagnostics probe.

    cd python && python ../examples/python/quick_connect_peers.py

`ReferencePeer` routes requests through an in-memory `Network` instead of
sockets; read agit8or_connect/reference_peer.py for every server-side check
in order. Example only; not production code."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'python'))

from agit8or_connect.reference_peer import API, Network, ReferencePeer  # noqa: E402

SCOPES = ['connection:read', 'customers:read', 'events:publish']

net = Network()
a = ReferencePeer('https://initiator.example.test', net, display_name='Initiator', quick_connect=True,
                  egress=['203.0.113.10/32'], source_address='203.0.113.10', tenants={'org-1': 'A customer'})
b = ReferencePeer('https://responder.example.test', net, display_name='Responder', quick_connect=True,
                  egress=['198.51.100.7/32'], source_address='198.51.100.7')

# 1. A's administrator starts Quick Connect; the browser carries the invitation to B's own admin UI.
browser_url = a.qc_start(b.base, requested_scopes=SCOPES)
# 2. B's administrator (signed in to B) reviews and approves; B redirects the browser back to A.
review_id = b.qc_review(browser_url)
callback_url = b.qc_authorize(review_id, approve=True)
# 3. A verifies the accept, reads B's discovery, and POSTs the exchange from its declared egress.
conn = a.qc_callback(callback_url, proposed_tenants=[{'id': 'org-1', 'label': 'Customer'}])
bconn = b.connections[b.requests[conn.request_id]]
print('SAS at A:', conn.sas, ' SAS at B:', bconn.sas)
assert conn.sas == bconn.sas

# 4. From here on it is v1: both administrators compare the SAS and approve scopes and customers.
b.approve(conn.request_id, scopes=SCOPES, requested_scopes=['connection:read'], tenant_grants=[
    {'remote_tenant': 'org-1', 'local_tenant': 'cust-1', 'scopes': ['customers:read', 'events:publish']}])
assert a.poll(conn.id) == 'approved'
a.accept(conn.id, scopes=['connection:read'])

r = a.call(conn.id, 'GET', b.url(f'{API}/customers/current'), tenant='org-1')
print('A -> B customers/current:', r.status, r.body.decode())
a.send_event(conn.id, 'alert.raised', 'org-1', {'alert_id': 'example-1', 'severity': 'low'})
print('B received events:', len(bconn.received_events))
print('probe from A, observed source at B:', a.qc_probe(conn.id)['observed_source'])
