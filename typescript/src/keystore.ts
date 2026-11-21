/**
 * Private-key protection at rest — same envelope as python/agit8or_connect/keystore.py
 * (`a8ck1.<master key id>.<nonce>.<AES-256-GCM ciphertext+tag>`, associated data
 * "agit8or-connect key-v1\n" + key id + "\n" + row aad), pinned by test-vectors/key-envelope.json.
 */
import { createCipheriv, createDecipheriv, createPrivateKey, randomBytes, type KeyObject } from 'node:crypto';
import { closeSync, fstatSync, openSync, readFileSync, constants } from 'node:fs';
import { ConnectError } from './index.ts';

const PREFIX = 'a8ck1';
export interface MasterKeyProvider { current(): [string, Buffer]; get(keyId: string): Buffer }

export function rowAad(table: string, column: string, rowId: string): Buffer {
  for (const p of [table, column, rowId]) if (typeof p !== 'string' || !p || /[\n#]/.test(p)) throw new Error('table, column and row id must be non-empty and contain no "#" or newline');
  return Buffer.from(`${table}.${column}#${rowId}`, 'utf8');
}

export class StaticMasterKeys implements MasterKeyProvider {
  keys: Map<string, Buffer>;
  currentId: string;
  constructor(keys: Record<string, Buffer>, currentId: string) {
    this.currentId = currentId;
    this.keys = new Map(Object.entries(keys));
    if (!this.keys.has(currentId)) throw new ConnectError('key_unavailable', 'the current master key is not configured', 503);
    for (const [k, v] of this.keys) if (!k || k.includes('.') || k.length > 64 || v.length !== 32) throw new ConnectError('key_unavailable', 'master keys must be 32 bytes with a short id', 503);
  }
  current(): [string, Buffer] { return [this.currentId, this.keys.get(this.currentId)!]; }
  get(id: string): Buffer { const k = this.keys.get(id); if (!k) throw new ConnectError('key_unavailable', 'master key not available', 503); return k; }
}

function parseKeyDoc(text: string): StaticMasterKeys {
  try {
    const doc = JSON.parse(text);
    return new StaticMasterKeys(Object.fromEntries(Object.entries(doc.keys as Record<string, string>).map(([k, v]) => [k, Buffer.from(v, 'base64url')])), String(doc.current));
  } catch (e) { if (e instanceof ConnectError) throw e; throw new ConnectError('key_unavailable', 'master key document malformed', 503); }
}

/** A 0600 file owned by this user; anything else is refused. */
export function fileMasterKeys(path: string): StaticMasterKeys {
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); } catch { throw new ConnectError('key_unavailable', 'master key file cannot be opened', 503); }
  try {
    const st = fstatSync(fd);
    if ((typeof process.getuid === 'function' && st.uid !== process.getuid()) || (st.mode & 0o077) !== 0) {
      throw new ConnectError('key_unavailable', 'master key file must be owned by this user and not readable by others (chmod 600)', 503);
    }
    return parseKeyDoc(readFileSync(fd, 'utf8'));
  } finally { closeSync(fd); }
}

export function envMasterKeys(variable = 'AGIT8OR_CONNECT_MASTER_KEYS'): StaticMasterKeys {
  const t = process.env[variable];
  if (!t) throw new ConnectError('key_unavailable', `${variable} is not set`, 503);
  return parseKeyDoc(t);
}

export class PrivateKeyCipher {
  provider: MasterKeyProvider;
  constructor(provider: MasterKeyProvider) { this.provider = provider; }
  private aad(keyId: string, aad: Buffer) {
    if (!aad?.length) throw new Error('row-bound associated data is required (see rowAad)');
    return Buffer.concat([Buffer.from(`agit8or-connect key-v1\n${keyId}\n`, 'ascii'), aad]);
  }
  encryptBytes(plain: Buffer, aad: Buffer, _nonce?: Buffer): string {
    const [id, key] = this.provider.current();
    const nonce = _nonce ?? randomBytes(12);
    const c = createCipheriv('aes-256-gcm', key, nonce);
    c.setAAD(this.aad(id, aad));
    const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
    return `${PREFIX}.${id}.${nonce.toString('base64url')}.${ct.toString('base64url')}`;
  }
  decryptBytes(blob: string, aad: Buffer): Buffer {
    const parts = typeof blob === 'string' ? blob.split('.') : [];
    if (parts.length !== 4 || parts[0] !== PREFIX) throw new ConnectError('key_corrupt', 'encrypted key record malformed', 500);
    const nonce = Buffer.from(parts[2], 'base64url'), ct = Buffer.from(parts[3], 'base64url');
    if (nonce.length !== 12 || ct.length < 17) throw new ConnectError('key_corrupt', 'encrypted key record malformed', 500);
    const key = this.provider.get(parts[1]);
    try {
      const d = createDecipheriv('aes-256-gcm', key, nonce);
      d.setAAD(this.aad(parts[1], aad));
      d.setAuthTag(ct.subarray(ct.length - 16));
      return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
    } catch { throw new ConnectError('key_corrupt', 'encrypted key record does not authenticate for this row', 500); }
  }
  /** Ed25519 private key from its 32-byte seed. */
  decryptPrivateKey(blob: string, aad: Buffer): KeyObject {
    const seed = this.decryptBytes(blob, aad);
    if (seed.length !== 32) throw new ConnectError('key_corrupt', 'encrypted key record has the wrong length', 500);
    return createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  }
  encryptPrivateKey(key: KeyObject, aad: Buffer): string {
    const der = key.export({ format: 'der', type: 'pkcs8' }) as Buffer;
    return this.encryptBytes(der.subarray(der.length - 32), aad);
  }
  needsRewrap(blob: string): boolean { return blob.split('.')[1] !== this.provider.current()[0]; }
  rewrap(blob: string, aad: Buffer): string { return this.encryptBytes(this.decryptBytes(blob, aad), aad); }
}
