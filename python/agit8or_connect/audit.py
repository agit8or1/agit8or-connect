"""Tamper-evident audit hash chain (PROTOCOL.md §11).

    hash_n = SHA-256( canonical_json({"prev": hash_{n-1}, "record": record_n}) )

hash_0's prev is GENESIS (64 zeros). Changing, removing or reordering any
record changes every later hash; `verify_chain` returns the index of the
first record that does not match. Records must not contain secrets or
customer content: identifiers, operation names, scopes and results only.
"""
from __future__ import annotations

from typing import Iterable, Optional, Tuple

from .canonical import canonical_json, sha256_hex

GENESIS = '0' * 64


def entry_hash(prev_hash: str, record: dict) -> str:
    return sha256_hex(canonical_json({'prev': prev_hash, 'record': record}))


def verify_chain(entries: Iterable[Tuple[dict, str, str]], start_prev: str = GENESIS) -> Optional[int]:
    """entries: (record, stored prev_hash, stored hash) in order. None when
    intact, else the index of the first broken entry."""
    prev = start_prev
    for i, (record, stored_prev, stored_hash) in enumerate(entries):
        if stored_prev != prev or entry_hash(prev, record) != stored_hash:
            return i
        prev = stored_hash
    return None


# --- redaction --------------------------------------------------------------------------------------
#
# Audit records hold identifiers, operation names, scopes and results only. `redact` enforces that for records
# that pass through `SqlAuditLog.append`: values under secret-looking keys, and any string that looks like a JWS,
# a PEM block, a long base64/hex blob or a pairing code, are replaced by a short digest marker; strings are capped.

import re as _re  # noqa: E402

_SECRET_KEY = _re.compile(r'(?i)(secret|password|passwd|token|assertion|dpop|authorization|private|pepper|'
                          r'cookie|session|code|verifier|seed|api[_-]?key|credential|signature)')
_JWS = _re.compile(r'^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$')
_BLOB = _re.compile(r'^[A-Za-z0-9+/_=-]{40,}$')
_PAIRING_CODE = _re.compile(r'^\d{5}-\d{5}$')
_SAFE_KEYS = {'code_sha256_prefix', 'error_code', 'status_code'}
MAX_AUDIT_STRING = 256
MAX_AUDIT_DEPTH = 4
# Identifiers that look like blobs but are expected in records (hashes, thumbprints, ids):
_ID_KEYS = _re.compile(r'(?i)(^|_)(id|kid|jkt|thumbprint|hash|digest|fingerprint|sha256)$')


def _marker(value: str) -> str:
    return 'redacted:' + sha256_hex(value.encode('utf-8'))[:12]


def redact(record, _depth: int = 0, _key: str = ''):
    if _depth > MAX_AUDIT_DEPTH:
        return '[nested]'
    if isinstance(record, dict):
        out = {}
        for k, v in list(record.items())[:64]:
            k = str(k)[:64]
            if k not in _SAFE_KEYS and _SECRET_KEY.search(k) and not _ID_KEYS.search(k):
                out[k] = _marker(canonical_json(v)) if v not in (None, '', [], {}) else v
            else:
                out[k] = redact(v, _depth + 1, k)
        return out
    if isinstance(record, (list, tuple)):
        return [redact(v, _depth + 1, _key) for v in list(record)[:64]]
    if isinstance(record, str):
        s = record
        if _JWS.match(s) or '-----BEGIN' in s or _PAIRING_CODE.match(s) or \
                (_BLOB.match(s) and not _ID_KEYS.search(_key)):
            return _marker(s)
        return s[:MAX_AUDIT_STRING]
    if record is None or isinstance(record, (bool, int)):
        return record
    if isinstance(record, float):
        return int(record)
    return str(record)[:MAX_AUDIT_STRING]


# --- signed checkpoints and verified exports -------------------------------------------------------
#
# A checkpoint is a JWS (typ audit-checkpoint+jwt) by an installation audit key over {iss, seq, hash, iat}.
# Publishing checkpoints somewhere the database writer cannot change (another system, a peer, a printed
# report) anchors the chain: rewriting history now also needs the audit key and every published checkpoint.

TYP_CHECKPOINT = 'audit-checkpoint+jwt'


def sign_checkpoint(private_key, *, issuer: str, seq: int, head_hash: str, now: Optional[int] = None) -> str:
    import time as _time
    from . import jws, keys
    if not isinstance(seq, int) or seq < 1 or not _re.fullmatch(r'[0-9a-f]{64}', head_hash or ''):
        raise ValueError('checkpoint needs a positive seq and a SHA-256 hex hash')
    return jws.sign_compact(private_key, {'alg': 'EdDSA', 'typ': TYP_CHECKPOINT, 'kid': keys.thumbprint(private_key)},
                            {'iss': issuer, 'seq': seq, 'hash': head_hash,
                             'iat': int(_time.time() if now is None else now)})


def verify_checkpoint(token: str, public_key, *, issuer: str) -> dict:
    from . import jws
    from .errors import ConnectError
    c = jws.verify_compact(token, public_key, typ=TYP_CHECKPOINT, issuer=issuer, required=('iss', 'seq', 'hash', 'iat'))
    if not isinstance(c.get('seq'), int) or c['seq'] < 1 or not _re.fullmatch(r'[0-9a-f]{64}', str(c.get('hash'))):
        raise ConnectError('invalid_request', 'checkpoint claims malformed', 400)
    return c


def export_bundle(entries, checkpoint_jws: str, *, issuer: str, start_prev: str = GENESIS,
                  start_seq: int = 1) -> dict:
    """entries: [{'seq','record','prev_hash','hash'}] in order, ending at the checkpoint's seq."""
    return {'format': 'agit8or-connect-audit-export/1', 'issuer': issuer, 'start_seq': start_seq,
            'start_prev': start_prev, 'entries': list(entries), 'checkpoint': checkpoint_jws}


def verify_export(bundle: dict, public_key, *, issuer: str, known_checkpoints=()) -> dict:
    """Verify an export: format, contiguous seq, every hash, the final hash equals the signed checkpoint, and
    every `known_checkpoints` entry ({'seq','hash'}) inside the range matches (a rewritten history fails here
    even with the audit key). Returns {'seq', 'hash', 'count'}; raises ConnectError('audit_invalid')."""
    from .errors import ConnectError

    def bad(msg):
        return ConnectError('audit_invalid', msg, 400)
    if not isinstance(bundle, dict) or bundle.get('format') != 'agit8or-connect-audit-export/1':
        raise bad('not an audit export')
    if bundle.get('issuer') != issuer:
        raise bad('export from another installation')
    entries = bundle.get('entries') or []
    if not entries:
        raise bad('empty export')
    seq0 = bundle.get('start_seq')
    if not isinstance(seq0, int) or seq0 < 1:
        raise bad('start_seq malformed')
    if seq0 == 1 and bundle.get('start_prev') != GENESIS:
        raise bad('an export from the start must begin at the genesis hash')
    for i, e in enumerate(entries):
        if e.get('seq') != seq0 + i:
            raise bad(f'entry {i} out of sequence')
    broken = verify_chain([(e['record'], e['prev_hash'], e['hash']) for e in entries], bundle.get('start_prev', GENESIS))
    if broken is not None:
        raise bad(f'chain broken at seq {seq0 + broken}')
    try:
        cp = verify_checkpoint(bundle.get('checkpoint', ''), public_key, issuer=issuer)
    except ConnectError:
        raise bad('checkpoint does not verify')
    last = entries[-1]
    if cp['seq'] != last['seq'] or cp['hash'] != last['hash']:
        raise bad('export does not end at its signed checkpoint')
    by_seq = {e['seq']: e['hash'] for e in entries}
    for k in known_checkpoints:
        if k['seq'] in by_seq and by_seq[k['seq']] != k['hash']:
            raise bad(f'history differs from the published checkpoint at seq {k["seq"]}')
        if seq0 - 1 == k['seq'] and bundle.get('start_prev') != k['hash']:
            raise bad('export does not continue from the published checkpoint')
    return {'seq': last['seq'], 'hash': last['hash'], 'count': len(entries)}
