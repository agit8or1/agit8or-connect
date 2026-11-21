"""Negotiated extensions added after revision 1.1 (PROTOCOL.md §18). Each is advertised in the discovery
`extensions` member and used for a connection only when BOTH installations advertise it at pairing; the
negotiated set is stored with the connection. A 1.0 or 1.1 peer advertises none of them, so nothing changes
for it: no new claim is required, no new header is sent, no request is refused for lacking them.

- `dpop-nonce/1`  RFC 9449 §8 server-provided nonces in DPoP proofs (limits pre-generated proofs).
- `actor/1`       an access token may name the person a call is made for: `act: {"sub": "<opaque id>"}`.
- `action-approval/1`  the receiver may require a per-action approval (PROTOCOL.md §7.4).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from typing import Callable, Dict, Mapping, Optional, Sequence

from .errors import ConnectError

EXT_DPOP_NONCE, EXT_ACTOR, EXT_ACTION_APPROVAL = 'dpop-nonce', 'actor', 'action-approval'
HARDENING_EXTENSIONS: Dict[str, Sequence[int]] = {EXT_DPOP_NONCE: (1,), EXT_ACTOR: (1,), EXT_ACTION_APPROVAL: (1,)}


def negotiate(theirs: Mapping[str, Sequence[int]], ours: Mapping[str, Sequence[int]] = HARDENING_EXTENSIONS
              ) -> Dict[str, int]:
    from .quick_connect import negotiate_extensions
    return negotiate_extensions(theirs, ours)


def discovery_extensions(ours: Mapping[str, Sequence[int]] = HARDENING_EXTENSIONS) -> Dict[str, int]:
    """Members to merge into the discovery document's `extensions` object."""
    return {k: max(v) for k, v in ours.items()}


# --- dpop-nonce/1 --------------------------------------------------------------------------------------

USE_DPOP_NONCE = 'use_dpop_nonce'
NONCE_HEADER = 'DPoP-Nonce'
_NONCE_RE = re.compile(r'^[A-Za-z0-9_-]{32,64}$')


class NonceIssuer:
    """Stateless nonces: base64url(window index || HMAC-SHA256(secret, context || index)[:16]).

    `context` binds the nonce to where it is used (for example "token" or the connection id); a nonce is
    valid in its window and the next one (default 2 x 300 s). All workers share `secret`, so no shared state
    is needed; single use is still guaranteed by the proof's jti in the replay store."""

    def __init__(self, secret: bytes, *, window: int = 300, clock: Callable[[], float] = time.time):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError('nonce secret must be at least 32 bytes')
        self.secret, self.window, self.clock = secret, window, clock

    def _mac(self, context: str, index: int) -> bytes:
        return hmac.new(self.secret, b'dpop-nonce/1\n' + context.encode() + b'\n' + struct.pack('>Q', index),
                        hashlib.sha256).digest()[:16]

    def issue(self, context: str) -> str:
        index = int(self.clock()) // self.window
        return base64.urlsafe_b64encode(struct.pack('>Q', index) + self._mac(context, index)).decode().rstrip('=')

    def valid(self, nonce: Optional[str], context: str) -> bool:
        if not isinstance(nonce, str) or not _NONCE_RE.match(nonce):
            return False
        try:
            raw = base64.urlsafe_b64decode(nonce + '=' * (-len(nonce) % 4))
        except ValueError:
            return False
        if len(raw) != 24:
            return False
        index = struct.unpack('>Q', raw[:8])[0]
        now_index = int(self.clock()) // self.window
        if index not in (now_index, now_index - 1):
            return False
        return hmac.compare_digest(raw[8:], self._mac(context, index))

    def check(self, nonce: Optional[str], context: str) -> None:
        """Raise use_dpop_nonce (401) carrying a fresh nonce when the proof's nonce is missing or stale."""
        if not self.valid(nonce, context):
            e = ConnectError(USE_DPOP_NONCE, 'a fresh DPoP nonce is required', 401)
            e.dpop_nonce = self.issue(context)
            raise e


def nonce_checker(issuer: Optional[NonceIssuer], negotiated: Mapping[str, int], context: str):
    """The `nonce_check` callable for tokens.verify_dpop_proof, or None when the connection did not negotiate
    dpop-nonce/1 (then any `nonce` claim is ignored, as RFC 9449 allows)."""
    if issuer is None or negotiated.get(EXT_DPOP_NONCE) != 1:
        return None
    return lambda nonce: issuer.check(nonce, context)


# --- actor/1 ----------------------------------------------------------------------------------------------

ACTOR_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
INVALID_ACTOR = 'invalid_actor'


def validate_actor(sub) -> str:
    """Opaque, pseudonymous ids only (no e-mail addresses or names): 1-128 of [A-Za-z0-9._:-]."""
    if not isinstance(sub, str) or not ACTOR_RE.match(sub):
        raise ConnectError(INVALID_ACTOR, 'actor must be an opaque id of 1-128 characters [A-Za-z0-9._:-]', 400)
    return sub


def actor_claim(sub: str) -> dict:
    return {'act': {'sub': validate_actor(sub)}}


def actor_of(claims: Mapping, negotiated: Mapping[str, int]) -> Optional[str]:
    """The actor of a verified access token, or None. A token naming an actor on a connection that did not
    negotiate actor/1, a nested delegation chain or a malformed actor is refused (invalid_token)."""
    act = claims.get('act')
    if act is None:
        return None
    if negotiated.get(EXT_ACTOR) != 1:
        raise ConnectError('invalid_token', 'actor tokens were not negotiated for this connection', 401)
    if not isinstance(act, dict) or set(act) - {'sub'} or not isinstance(act.get('sub'), str):
        raise ConnectError('invalid_token', 'actor claim malformed (nested delegation is not supported)', 401)
    try:
        return validate_actor(act['sub'])
    except ConnectError:
        raise ConnectError('invalid_token', 'actor claim malformed', 401)


def operator_for(connection_id: str, actor: Optional[str]) -> str:
    """The operator recorded on per-action approvals and audit entries."""
    return f'actor:{connection_id}:{actor}' if actor else f'connection:{connection_id}'


def new_nonce_secret() -> bytes:
    return secrets.token_bytes(32)
