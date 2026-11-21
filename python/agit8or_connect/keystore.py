"""Private-key protection at rest (PROTOCOL.md §2: MUST for production hosts).

    keys = FileMasterKeys('/etc/app/connect-master-keys.json')     # or EnvMasterKeys / your KMS adapter
    cipher = PrivateKeyCipher(keys)
    aad = row_aad('connect_key', 'private_key', row_uuid)
    blob = cipher.encrypt(private_key, aad)                          # store blob in the row
    key = cipher.decrypt(blob, aad)                                  # only when signing
    blob = cipher.rewrap(blob, aad)                                  # after a master-key rotation

Format: ``a8ck1.<master key id>.<base64url nonce>.<base64url AES-256-GCM ciphertext+tag>``. The associated
data is ``agit8or-connect key-v1\\n<master key id>\\n<row aad>``, so a ciphertext copied to another row,
column or table, or relabelled with another master key id, fails to decrypt.

Master keys never live next to the data they protect: `MasterKeyProvider` is the boundary (a file outside
the database with 0600 permissions owned by the service user, an environment variable injected by the
service manager, or an adapter to a KMS/HSM). The SDK refuses a key file other users can read.

Unavailable keys are an error, never a fallback: a missing master key id raises `key_unavailable` (503);
an authentication failure raises `key_corrupt`. Neither message contains key material.
"""
from __future__ import annotations

import base64
import contextlib
import json
import os
import stat
import tempfile
from typing import Dict, Iterator, Optional, Protocol, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

from .errors import ConnectError

KEY_UNAVAILABLE = 'key_unavailable'
KEY_CORRUPT = 'key_corrupt'
PREFIX = 'a8ck1'
_AAD_PREFIX = b'agit8or-connect key-v1\n'


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def row_aad(table: str, column: str, row_id: str) -> bytes:
    """``<table>.<column>#<row id>`` — bind a ciphertext to exactly one row and column."""
    for part in (table, column, row_id):
        if not isinstance(part, str) or not part or any(c in part for c in '\n#'):
            raise ValueError('table, column and row id must be non-empty and contain no "#" or newline')
    return f'{table}.{column}#{row_id}'.encode('utf-8')


class MasterKeyProvider(Protocol):
    def current(self) -> Tuple[str, bytes]: ...

    def get(self, key_id: str) -> bytes: ...


def _check_keys(current: str, keys: Dict[str, bytes]) -> None:
    if current not in keys:
        raise ConnectError(KEY_UNAVAILABLE, 'the current master key is not configured', 503)
    for kid, k in keys.items():
        if not kid or '.' in kid or len(kid) > 64:
            raise ConnectError(KEY_UNAVAILABLE, 'master key id malformed', 503)
        if len(k) != 32:
            raise ConnectError(KEY_UNAVAILABLE, 'master keys must be 32 bytes (AES-256)', 503)


class StaticMasterKeys:
    """Keys supplied by the caller (tests, or a host that fetched them from a KMS)."""

    def __init__(self, keys: Dict[str, bytes], current: str):
        _check_keys(current, keys)
        self._keys = dict(keys)
        self._current = current

    def current(self):
        return self._current, self._keys[self._current]

    def get(self, key_id):
        try:
            return self._keys[key_id]
        except KeyError:
            raise ConnectError(KEY_UNAVAILABLE, 'master key not available', 503) from None


def _parse_key_json(text: str) -> StaticMasterKeys:
    try:
        doc = json.loads(text)
        keys = {str(k): _unb64(str(v)) for k, v in doc['keys'].items()}
        return StaticMasterKeys(keys, str(doc['current']))
    except ConnectError:
        raise
    except Exception as e:  # noqa: BLE001
        raise ConnectError(KEY_UNAVAILABLE, 'master key document malformed', 503) from e


class FileMasterKeys(StaticMasterKeys):
    """JSON ``{"current": "<id>", "keys": {"<id>": "<base64url 32 bytes>"}}`` in a file that only its owner
    can read (mode 0600 or 0400) and that belongs to the current user. Anything else is refused."""

    def __init__(self, path: str):
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        except OSError as e:
            raise ConnectError(KEY_UNAVAILABLE, 'master key file cannot be opened', 503) from e
        try:
            st = os.fstat(fd)
            if hasattr(os, 'getuid') and (st.st_uid != os.getuid() or st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
                raise ConnectError(KEY_UNAVAILABLE, 'master key file must be owned by this user and not readable '
                                                    'by others (chmod 600)', 503)
            with os.fdopen(fd, 'r', encoding='utf-8') as f:
                fd = -1
                parsed = _parse_key_json(f.read(65536))
        finally:
            if fd >= 0:
                os.close(fd)
        super().__init__(parsed._keys, parsed._current)


class EnvMasterKeys(StaticMasterKeys):
    """The same JSON document in an environment variable set by the service manager."""

    def __init__(self, variable: str = 'AGIT8OR_CONNECT_MASTER_KEYS'):
        text = os.environ.get(variable)
        if not text:
            raise ConnectError(KEY_UNAVAILABLE, f'{variable} is not set', 503)
        parsed = _parse_key_json(text)
        super().__init__(parsed._keys, parsed._current)


def generate_master_key() -> str:
    """A new 32-byte master key, base64url (for the key document)."""
    return _b64(os.urandom(32))


class PrivateKeyCipher:
    def __init__(self, provider: MasterKeyProvider):
        self.provider = provider

    @staticmethod
    def _aad(key_id: str, aad: bytes) -> bytes:
        if not isinstance(aad, (bytes, bytearray)) or not aad:
            raise ValueError('row-bound associated data is required (see row_aad)')
        return _AAD_PREFIX + key_id.encode('ascii') + b'\n' + bytes(aad)

    def encrypt_bytes(self, plaintext: bytes, aad: bytes, *, _nonce: Optional[bytes] = None) -> str:
        """`_nonce` exists only so test vectors are reproducible; never pass it in production."""
        key_id, key = self.provider.current()
        nonce = _nonce if _nonce is not None else os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext, self._aad(key_id, aad))
        return f'{PREFIX}.{key_id}.{_b64(nonce)}.{_b64(ct)}'

    def decrypt_bytes(self, blob: str, aad: bytes) -> bytes:
        try:
            prefix, key_id, nonce_s, ct_s = blob.split('.')
            if prefix != PREFIX:
                raise ValueError
            nonce, ct = _unb64(nonce_s), _unb64(ct_s)
            if len(nonce) != 12 or len(ct) < 17:
                raise ValueError
        except (ValueError, AttributeError) as e:
            raise ConnectError(KEY_CORRUPT, 'encrypted key record malformed', 500) from e
        key = self.provider.get(key_id)
        try:
            return AESGCM(key).decrypt(nonce, ct, self._aad(key_id, aad))
        except InvalidTag as e:
            raise ConnectError(KEY_CORRUPT, 'encrypted key record does not authenticate for this row', 500) from e

    def encrypt(self, private_key: Ed25519PrivateKey, aad: bytes) -> str:
        raw = private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())
        return self.encrypt_bytes(raw, aad)

    def decrypt(self, blob: str, aad: bytes) -> Ed25519PrivateKey:
        raw = self.decrypt_bytes(blob, aad)
        if len(raw) != 32:
            raise ConnectError(KEY_CORRUPT, 'encrypted key record has the wrong length', 500)
        return Ed25519PrivateKey.from_private_bytes(raw)

    def key_id_of(self, blob: str) -> str:
        parts = blob.split('.') if isinstance(blob, str) else []
        return parts[1] if len(parts) == 4 and parts[0] == PREFIX else ''

    def needs_rewrap(self, blob: str) -> bool:
        return self.key_id_of(blob) != self.provider.current()[0]

    def rewrap(self, blob: str, aad: bytes) -> str:
        """Re-encrypt under the current master key (rotation). Same row-bound associated data."""
        return self.encrypt_bytes(self.decrypt_bytes(blob, aad), aad)


@contextlib.contextmanager
def secret_tempfile(data: bytes, *, suffix: str = '') -> Iterator[str]:
    """For a TLS library that only takes a file path: an anonymous in-memory file on Linux
    (memfd, path /proc/self/fd/N), otherwise a 0600 file in a fresh 0700 directory. The content is
    overwritten and the file removed on exit, also on error."""
    if hasattr(os, 'memfd_create') and os.path.isdir('/proc/self/fd'):
        fd = os.memfd_create('agit8or-connect-secret', getattr(os, 'MFD_CLOEXEC', 0))
        try:
            os.write(fd, data)
            yield f'/proc/self/fd/{fd}'
        finally:
            with contextlib.suppress(OSError):
                os.ftruncate(fd, 0)
            os.close(fd)
        return
    d = tempfile.mkdtemp(prefix='agit8or-connect-')
    os.chmod(d, 0o700)
    path = os.path.join(d, 'secret' + suffix)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.close(fd)
        fd = -1
        yield path
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(OSError):
            with open(path, 'r+b') as f:
                f.write(b'\0' * len(data))
        with contextlib.suppress(OSError):
            os.remove(path)
        with contextlib.suppress(OSError):
            os.rmdir(d)


def redacted_key_repr(blob: Optional[str]) -> str:
    """What may appear in logs or exports for an encrypted key column: format and master key id only."""
    if not isinstance(blob, str) or not blob.startswith(PREFIX + '.'):
        return '<no key>'
    return f'<encrypted key, master key {blob.split(".")[1]}>'
