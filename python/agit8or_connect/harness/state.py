"""Persist a ReferencePeer between requests and across restarts (harness only).

Private keys are stored as keystore envelopes (AES-256-GCM, row-bound AAD), never in plaintext; the master
key lives in a separate 0600 file. Quick Connect attempt state is not persisted: the harness exercises the v1
code flow, tokens, resources, events, rotation and the kill switch.
"""
from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from dataclasses import asdict, fields

from .. import keys
from ..keystore import PrivateKeyCipher, row_aad
from ..reference_peer import PeerConnection, ReferencePeer
from ..tenants import TenantGrant

_CONN_FIELDS = {f.name for f in fields(PeerConnection)}
_SKIP = {'keys', 'remote_keys', 'request_key', 'token_cache'}


def dump(peer: ReferencePeer, cipher: PrivateKeyCipher) -> dict:
    conns = {}
    for cid, c in peer.connections.items():
        d = {k: getattr(c, k) for k in _CONN_FIELDS - _SKIP}
        d['keys'] = {kid: {'private': cipher.encrypt(k['private'], row_aad('connect_key', 'private', f'{cid}:{kid}'))
                           if k['private'] is not None else None,
                           'state': k['state'], 'activated_at': k['activated_at'], 'retire_after': k['retire_after']}
                     for kid, k in c.keys.items()}
        d['remote_keys'] = {kid: keys.public_jwk(pk) for kid, pk in c.remote_keys.items()}
        d['request_key'] = keys.public_jwk(c.request_key) if c.request_key is not None else None
        conns[cid] = d
    return {
        'installation_id': peer.installation_id, 'app': peer.app, 'pepper': peer.pepper.hex(),
        'invitations': peer.invitations, 'connections': conns, 'requests': peer.requests,
        'grants': [asdict(g) for g in peer.grants.grants.values()], 'tenants': peer.tenants,
        'kill_switch': peer.kill_switch,
    }


def load(peer: ReferencePeer, data: dict, cipher: PrivateKeyCipher) -> None:
    peer.installation_id = data['installation_id']
    peer.app = data['app']
    peer.pepper = bytes.fromhex(data['pepper'])
    peer.invitations = data['invitations']
    peer.requests = data['requests']
    peer.tenants = data['tenants']
    peer.kill_switch = data['kill_switch']
    peer.grants.grants = {}
    for g in data['grants']:
        g['scopes'] = tuple(g['scopes'])
        peer.grants.add(TenantGrant(**g))
    peer.connections = {}
    for cid, d in data['connections'].items():
        d = dict(d)
        ks = d.pop('keys')
        rk = d.pop('remote_keys')
        req = d.pop('request_key')
        c = PeerConnection(**{k: v for k, v in d.items() if k in _CONN_FIELDS})
        c.keys = {kid: {'private': cipher.decrypt(k['private'], row_aad('connect_key', 'private', f'{cid}:{kid}'))
                        if k['private'] else None,
                        'state': k['state'], 'activated_at': k['activated_at'], 'retire_after': k['retire_after']}
                  for kid, k in ks.items()}
        c.remote_keys = {kid: keys.public_key_from_jwk(j) for kid, j in rk.items()}
        c.request_key = keys.public_key_from_jwk(req) if req else None
        peer.connections[cid] = c


@contextmanager
def locked_state(peer: ReferencePeer, directory: str, cipher: PrivateKeyCipher):
    """Exclusive lock across worker processes; restore before, persist after (atomic replace)."""
    lock_path = os.path.join(directory, 'state.lock')
    state_path = os.path.join(directory, 'state.json')
    with open(lock_path, 'a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            if os.path.exists(state_path):
                with open(state_path) as f:
                    load(peer, json.load(f), cipher)
            yield peer
            tmp = state_path + f'.{os.getpid()}.tmp'
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(dump(peer, cipher), f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, state_path)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
