/**
 * GuardedTransport (TypeScript) — the same checks, in the same order, as python/agit8or_connect/transport.py:
 * approved destination from the policy (fail closed), https-only URL on exactly that host and port, one DNS
 * resolution whose every answer must be approved (refused address classes never), a socket to the validated
 * address with the connected address verified, TLS >= 1.2 with chain and name verification always on (a
 * private CA replaces the system store), SPKI pins and expiry warnings before any request byte, no redirects,
 * no proxies (the socket is opened here; no Agent, no proxy environment), request/response caps and one
 * deadline over the whole exchange.
 */
import { request as httpRequest, type IncomingMessage } from 'node:http';
import { connect as netConnect, isIP, type Socket } from 'node:net';
import { connect as tlsConnect, checkServerIdentity, type TLSSocket, type PeerCertificate } from 'node:tls';
import { lookup } from 'node:dns/promises';
import { createHash, X509Certificate } from 'node:crypto';
import { ConnectError } from './index.ts';
import { classifyAddress, normalizeAddress } from './addresses.ts';
import { type ApprovedDestination, type DestinationPolicy, destinationUnavailable, matchDestination, normalizeHost, validateDestination } from './destinations.ts';

export interface TransportResponse {
  status: number; headers: Record<string, string>; body: Buffer; peerAddress: string;
  certificate: CertificateDetails; warnings: string[]; header(name: string): string;
}
export interface CertificateDetails { subject: string; issuer: string; sans: string[]; not_after: number; spki_sha256: string; serial: string }
export type Resolver = (host: string) => Promise<string[]>;
/** Test seam: where to open the TCP connection for a validated address, and which remote address to expect. */
export type Dialer = (ip: string, port: number) => { host: string; port: number; expectRemote: string };

export interface GuardedTransportOptions {
  maxResponseBytes?: number; maxRequestBytes?: number; connectTimeoutMs?: number; totalTimeoutMs?: number;
  resolver?: Resolver; clock?: () => number; expiryWarningDays?: number; localAddress?: string;
  onWarning?: (connectionId: string, warning: string) => void; _dialer?: Dialer;
}

const FORBIDDEN = new Set(['host', 'proxy-authorization', 'proxy-connection', 'transfer-encoding', 'connection', 'content-length']);
const ce = (code: string, msg: string, status = 502) => new ConnectError(code, msg, status);

export const defaultResolver: Resolver = async (host) => (await lookup(host, { all: true, verbatim: true })).map((a) => a.address);

export function spkiSha256(cert: X509Certificate): string {
  return createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('base64url');
}

export function certificateDetails(cert: X509Certificate): CertificateDetails {
  const sans = (cert.subjectAltName ?? '').split(', ').filter(Boolean).map((s) => s.replace(/^(DNS|IP Address):/, ''));
  return { subject: cert.subject.replace(/\n/g, ',').slice(0, 256), issuer: cert.issuer.replace(/\n/g, ',').slice(0, 256), sans: sans.slice(0, 32),
    not_after: Math.floor(new Date(cert.validTo).getTime() / 1000), spki_sha256: spkiSha256(cert), serial: cert.serialNumber.toLowerCase().slice(0, 64) };
}

function tlsError(e: NodeJS.ErrnoException, host: string): ConnectError {
  const code = String(e.code ?? '');
  if (code === 'ERR_TLS_CERT_ALTNAME_INVALID') return ce('certificate_name_mismatch', `the certificate is not valid for ${host}`);
  if (/CERT|SELF_SIGNED|UNABLE_TO|VERIFY|ISSUER/.test(code)) return ce('certificate_invalid', `the certificate of ${host} did not verify`);
  return ce('transport_error', `TLS handshake with ${host} failed (${code || e.name})`);
}

class Deadline {
  end: number;
  constructor(ms: number) { this.end = Date.now() + ms; }
  left(): number { const r = this.end - Date.now(); if (r <= 0) throw ce('deadline_exceeded', 'the request did not complete in time', 504); return r; }
}

function withTimeout<T>(p: Promise<T>, ms: number, onTimeout: () => ConnectError, cleanup?: () => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => { cleanup?.(); reject(onTimeout()); }, ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}

export class GuardedTransport {
  policy: DestinationPolicy; connectionId: string; o: Required<Omit<GuardedTransportOptions, 'localAddress' | 'onWarning' | '_dialer'>> & GuardedTransportOptions;
  constructor(policy: DestinationPolicy, connectionId: string, o: GuardedTransportOptions = {}) {
    if (!policy || !connectionId) throw new Error('GuardedTransport needs a destination policy and a connection id');
    this.policy = policy; this.connectionId = connectionId;
    this.o = { maxResponseBytes: 2 * 1024 * 1024, maxRequestBytes: 1024 * 1024, connectTimeoutMs: 5000, totalTimeoutMs: 15000,
      resolver: defaultResolver, clock: () => Date.now() / 1000, expiryWarningDays: 21, ...o };
  }

  async destination(): Promise<ApprovedDestination> {
    let d: ApprovedDestination;
    try { d = await this.policy.get(this.connectionId); } catch (e) {
      if (e instanceof ConnectError) throw e;
      throw destinationUnavailable(`approved destination could not be loaded (${(e as Error).name})`);
    }
    if (!d || typeof d !== 'object') throw destinationUnavailable('approved destination policy returned no record');
    try { validateDestination(d); } catch (e) { throw destinationUnavailable(`approved destination invalid: ${(e as Error).message}`); }
    if (d.connection_id !== this.connectionId) throw destinationUnavailable('approved destination belongs to another connection');
    if (d.state === 'security_blocked') throw new ConnectError('security_blocked', 'this connection is security blocked: an administrator must review the destination change', 403);
    return d;
  }

  checkAddresses(d: ApprovedDestination, resolved: string[], now: number): string[] {
    const out: string[] = [];
    for (const a of resolved) {
      const info = classifyAddress(a);
      if (info.refused) throw ce('blocked_destination', `${d.host} resolves to a ${info.category} address, which is never allowed`);
      const dial = normalizeAddress(a) ?? info.address;
      const entry = matchDestination(d, dial, now) ?? matchDestination(d, info.address, now);
      if (!entry || (info.private && !entry.private)) {
        const e = ce('destination_changed', `${d.host} resolves to an address that is not approved for this connection`) as ConnectError & { evidence?: unknown };
        e.evidence = { code: 'destination_changed', host: d.host, port: d.port, approved: d.addresses.map((x) => x.net), observed: resolved, at: Math.floor(now) };
        throw e;
      }
      out.push(dial);
    }
    return out;
  }

  async request(method: string, url: string, headers: Record<string, string> = {}, body?: Buffer | string): Promise<TransportResponse> {
    const deadline = new Deadline(this.o.totalTimeoutMs);
    const d = await this.destination();
    let u: URL;
    try { u = new URL(url); } catch { throw ce('blocked_destination', 'URL malformed', 400); }
    if (u.protocol !== 'https:') throw ce('blocked_destination', 'only https is allowed', 400);
    if (u.username || u.password || u.hash) throw ce('blocked_destination', 'URL must not carry user info or a fragment', 400);
    let host: string;
    try { host = normalizeHost(u.hostname); } catch { throw ce('blocked_destination', 'URL host malformed', 400); }
    const port = u.port ? Number(u.port) : 443;
    if (host !== d.host || port !== d.port) throw ce('blocked_destination', 'URL is not on the approved destination of this connection', 400);
    const payload = body === undefined ? undefined : Buffer.from(body);
    if (payload && payload.length > this.o.maxRequestBytes) throw ce('too_large', 'request body too large', 413);
    for (const [k, v] of Object.entries(headers)) {
      if (FORBIDDEN.has(k.toLowerCase()) || /[\r\n]/.test(k + v)) throw ce('blocked_destination', `header ${k} may not be set`, 400);
    }
    const resolved = isIP(host) ? [host] : await withTimeout(this.o.resolver(host).catch(() => { throw ce('transport_error', `${host} did not resolve`); }),
      deadline.left(), () => ce('transport_error', `${host} did not resolve in time`, 504));
    if (!resolved.length) throw ce('transport_error', `${host} did not resolve`);
    const now = this.o.clock();
    const candidates = this.checkAddresses(d, resolved.map((a) => normalizeAddress(a) ?? a), now);
    const conn = await this.connect(host, port, candidates, d, deadline, now);
    for (const w of conn.warnings) { try { this.o.onWarning?.(this.connectionId, w); } catch { /* never breaks a request */ } }
    return this.exchange(conn, method, host, port, `${u.pathname || '/'}${u.search}`, headers, payload, deadline);
  }

  private async connect(host: string, port: number, candidates: string[], d: ApprovedDestination, deadline: Deadline, now: number) {
    let last: unknown = null;
    for (const ip of candidates) {
      const target = this.o._dialer ? this.o._dialer(ip, port) : { host: ip, port, expectRemote: ip };
      let raw: Socket;
      try {
        raw = await withTimeout(new Promise<Socket>((resolve, reject) => {
          const s = netConnect({ host: target.host, port: target.port, localAddress: this.o.localAddress });
          s.once('connect', () => resolve(s)); s.once('error', reject);
        }), Math.min(this.o.connectTimeoutMs, deadline.left()), () => ce('transport_error', `${host} did not accept a connection in time`, 504));
      } catch (e) { if (e instanceof ConnectError && e.code === 'deadline_exceeded') throw e; last = e; continue; }
      if (normalizeAddress(raw.remoteAddress ?? '') !== normalizeAddress(target.expectRemote)) {
        raw.destroy();
        throw ce('blocked_destination', 'the connected peer is not the validated address');
      }
      const tls = await withTimeout(new Promise<TLSSocket>((resolve, reject) => {
        const t = tlsConnect({ socket: raw, servername: isIP(host) ? undefined : host, ca: d.ca_pem ?? undefined, minVersion: 'TLSv1.2',
          rejectUnauthorized: true, checkServerIdentity: (_h: string, cert: PeerCertificate) => checkServerIdentity(host, cert) });
        t.once('secureConnect', () => resolve(t)); t.once('error', (e) => { raw.destroy(); reject(tlsError(e as NodeJS.ErrnoException, host)); });
      }), deadline.left(), () => ce('deadline_exceeded', 'the request did not complete in time', 504), () => raw.destroy());
      const x509 = tls.getPeerX509Certificate();
      if (!x509) { tls.destroy(); throw ce('certificate_invalid', 'no peer certificate'); }
      const certificate = certificateDetails(x509);
      if ((d.spki_pins ?? []).length && !d.spki_pins!.includes(certificate.spki_sha256)) {
        tls.destroy();
        throw ce('spki_mismatch', `the certificate key of ${host} is not one of the pinned keys`);
      }
      const warnings: string[] = [];
      if (certificate.not_after - now < this.o.expiryWarningDays * 86400) {
        warnings.push(`certificate_expiring: the certificate of ${host} expires in ${Math.max(0, Math.floor((certificate.not_after - now) / 86400))} day(s)`);
      }
      return { tls, address: ip, certificate, warnings };
    }
    throw ce('transport_error', `${host} could not be reached (${(last as Error | null)?.name ?? 'no address'})`);
  }

  private exchange(conn: { tls: TLSSocket; address: string; certificate: CertificateDetails; warnings: string[] }, method: string, host: string,
    port: number, path: string, headers: Record<string, string>, body: Buffer | undefined, deadline: Deadline): Promise<TransportResponse> {
    const hostHeader = (isIP(host) === 6 ? `[${host}]` : host) + (port === 443 ? '' : `:${port}`);
    const max = this.o.maxResponseBytes;
    return new Promise((resolve, reject) => {
      let done = false;
      const fail = (e: unknown) => { if (!done) { done = true; clearTimeout(timer); conn.tls.destroy(); reject(e); } };
      const timer = setTimeout(() => fail(ce('deadline_exceeded', 'the request did not complete in time', 504)), Math.max(1, deadline.end - Date.now()));
      const req = httpRequest({ method: method.toUpperCase(), path, setHost: false, createConnection: () => conn.tls,
        headers: { ...headers, Host: hostHeader, Connection: 'close', ...(body ? { 'Content-Length': String(body.length) } : {}) } },
      (res: IncomingMessage) => {
        const chunks: Buffer[] = []; let total = 0;
        res.on('data', (c: Buffer) => { total += c.length; if (total > max) { fail(ce('too_large', 'response too large')); res.destroy(); } else chunks.push(c); });
        res.on('end', () => {
          if (done) return;
          done = true; clearTimeout(timer); conn.tls.destroy();
          const hs: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) hs[k] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
          resolve({ status: res.statusCode ?? 0, headers: hs, body: Buffer.concat(chunks), peerAddress: conn.address, certificate: conn.certificate,
            warnings: [...conn.warnings], header: (n: string) => hs[n.toLowerCase()] ?? '' });
        });
        res.on('error', (e) => fail(ce('transport_error', `${host} could not be reached (${e.name})`)));
      });
      req.on('error', (e) => fail(e instanceof ConnectError ? e : ce('transport_error', `${host} could not be reached (${e.name})`)));
      if (body) req.write(body);
      req.end();
    });
  }
}
