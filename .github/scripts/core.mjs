// BIM9_Connect activation service - pure logic (no network, no GitHub).
// Mirrors Main\TrialLicencse\LicenseCore.cs of the add-in: hashes, key
// formats, request encryption and registry signing MUST stay identical.
import crypto from 'node:crypto';

export const PRODUCT = 'BIM9_Connect';
export const V1_LAST_DAY = '2027-12-31';   // = LegacyKeyV1.LastAcceptedDay
export const V1_MAX_MACHINES = 3;          // = LegacyKeyV1.MaxMachines
const CMD_WINDOW_DAYS = 7;                 // signed commands older than this are refused
const MACHINE_HASH = /^[A-Za-z0-9_-]{22}$/;

// ---------------------------------------------------------------- encoding

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const unb64u = (s) => Buffer.from(String(s ?? ''), 'base64url');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();

export function shortHash(text) {
  return b64u(sha256(Buffer.from(text, 'utf8')).subarray(0, 16));
}

export const normalize = (raw) => String(raw ?? '').replace(/\s+/g, '');

export function canonicalKey(raw) {
  const k = normalize(raw);
  return /^bim9\./i.test(k) ? 'BIM9.' + k.slice(5) : k;
}

export const keyHash = (key) => shortHash('BIM9-KEY|' + canonicalKey(key));
export const machineHashOf = (code) => shortHash('BIM9-MID|' + String(code).trim().toUpperCase());
export const legacyId = (v1, machineHash) => shortHash('BIM9-V1|' + normalize(v1) + '|' + machineHash);
export const legacyGroup = (v1) => shortHash('BIM9-V1K|' + normalize(v1));

// ---------------------------------------------------------------- keys

export function publicKeyFromXY(xyB64) {
  const xy = Buffer.from(xyB64, 'base64');
  if (xy.length !== 64) throw new Error('public key must be 64 bytes (X||Y)');
  return crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: b64u(xy.subarray(0, 32)), y: b64u(xy.subarray(32)) },
    format: 'jwk',
  });
}

// {d, x, y} in standard base64, as written by LicenseKeyGen.
export function privateKeyFromParts(p) {
  const conv = (s) => b64u(Buffer.from(s, 'base64'));
  return crypto.createPrivateKey({
    key: { kty: 'EC', crv: 'P-256', d: conv(p.d), x: conv(p.x), y: conv(p.y) },
    format: 'jwk',
  });
}

// LICENSE_SERVICE_KEY secret (JSON written by "LicenseKeyGen service-init").
export function loadServiceKeys(json) {
  const j = typeof json === 'string' ? JSON.parse(json) : json;
  if (!j?.sign || !j?.decrypt || !j?.issuer_xy || !j?.legacy_hmac) throw new Error('LICENSE_SERVICE_KEY is incomplete');
  const xy = (p) => Buffer.concat([Buffer.from(p.x, 'base64'), Buffer.from(p.y, 'base64')]).toString('base64');
  return {
    signPriv: privateKeyFromParts(j.sign),
    signPub: publicKeyFromXY(xy(j.sign)),
    decryptPriv: privateKeyFromParts(j.decrypt),
    decryptPubXY: xy(j.decrypt),
    issuerPub: publicKeyFromXY(j.issuer_xy),     // signs license keys AND vendor commands
    legacySecret: Buffer.from(j.legacy_hmac, 'base64'),
    // After a key rotation ("service-init --force"): still read the list signed
    // with the old key, and requests from builds that encrypt to the old key.
    prevSignPub: j.previous_sign_xy ? publicKeyFromXY(j.previous_sign_xy) : null,
    prevDecryptPriv: j.previous_decrypt ? privateKeyFromParts(j.previous_decrypt) : null,
  };
}

export function openRegistryAny(envelope, keys) {
  return openRegistry(envelope, keys.signPub) ?? (keys.prevSignPub ? openRegistry(envelope, keys.prevSignPub) : null);
}

function openRequestAny(env, keys) {
  try {
    return openRequest(env, keys.decryptPriv);
  } catch (e) {
    if (!keys.prevDecryptPriv) throw e;
    return openRequest(env, keys.prevDecryptPriv);
  }
}

export function verifyP1363(pub, ascii, sigB64u) {
  const sig = unb64u(sigB64u);
  if (sig.length !== 64) return false;
  try {
    return crypto.verify('sha256', Buffer.from(String(ascii), 'ascii'), { key: pub, dsaEncoding: 'ieee-p1363' }, sig);
  } catch {
    return false;
  }
}

export function signP1363(priv, ascii) {
  return b64u(crypto.sign('sha256', Buffer.from(ascii, 'ascii'), { key: priv, dsaEncoding: 'ieee-p1363' }));
}

// ---------------------------------------------------------------- requests
// ECIES: ECDH P-256 (ephemeral, from the add-in) -> SHA-256("BIM9-ENC"||Z) /
// SHA-256("BIM9-MAC"||Z) -> AES-256-CBC + HMAC-SHA256(iv||ct).

export function openRequest(env, decryptPriv) {
  if (!env || env.bim9 !== 1) throw new Error('not a BIM9 request');
  const exy = unb64u(env.e);
  if (exy.length !== 64) throw new Error('bad ephemeral key');
  const ephPub = crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: b64u(exy.subarray(0, 32)), y: b64u(exy.subarray(32)) },
    format: 'jwk',
  });
  const z = crypto.diffieHellman({ privateKey: decryptPriv, publicKey: ephPub });
  const kEnc = sha256(Buffer.concat([Buffer.from('BIM9-ENC', 'ascii'), z]));
  const kMac = sha256(Buffer.concat([Buffer.from('BIM9-MAC', 'ascii'), z]));
  const iv = unb64u(env.iv), ct = unb64u(env.ct), tag = unb64u(env.tag);
  const expect = crypto.createHmac('sha256', kMac).update(Buffer.concat([iv, ct])).digest();
  if (tag.length !== expect.length || !crypto.timingSafeEqual(tag, expect)) throw new Error('bad request tag');
  const d = crypto.createDecipheriv('aes-256-cbc', kEnc, iv);
  return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
}

// Same as the add-in's LicenseService.Seal (used by the tests).
export function sealRequest(obj, decryptPubXY) {
  const servicePub = publicKeyFromXY(decryptPubXY);
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const z = crypto.diffieHellman({ privateKey, publicKey: servicePub });
  const kEnc = sha256(Buffer.concat([Buffer.from('BIM9-ENC', 'ascii'), z]));
  const kMac = sha256(Buffer.concat([Buffer.from('BIM9-MAC', 'ascii'), z]));
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-cbc', kEnc, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  const tag = crypto.createHmac('sha256', kMac).update(Buffer.concat([iv, ct])).digest();
  const jwk = publicKey.export({ format: 'jwk' });
  const e = Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  return { bim9: 1, e: b64u(e), iv: b64u(iv), ct: b64u(ct), tag: b64u(tag) };
}

export function envelopeFromBody(body) {
  const m = /```json\s*([\s\S]*?)```/.exec(String(body ?? ''));
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch { return null; }
}

// ---------------------------------------------------------------- license keys

export function parseKeyV2(raw, issuerPub) {
  const key = canonicalKey(raw);
  if (!key.startsWith('BIM9.')) return { error: 'invalid_key' };
  const body = key.slice(5);
  const dot = body.indexOf('.');
  if (dot <= 0 || dot !== body.lastIndexOf('.') || dot === body.length - 1) return { error: 'invalid_key' };
  const p = body.slice(0, dot), s = body.slice(dot + 1);
  if (!verifyP1363(issuerPub, p, s)) return { error: 'invalid_key' };
  let payload;
  try { payload = JSON.parse(unb64u(p).toString('utf8')); } catch { return { error: 'invalid_key' }; }
  if (payload?.v !== 2 || payload.prod !== PRODUCT) return { error: 'invalid_key' };
  return { key, kh: keyHash(key), payload };
}

export function parseKeyV1(raw, legacySecret) {
  const key = normalize(raw);
  const parts = key.split('|');
  if (parts.length !== 3 || !/^\d{4}-\d{2}-\d{2}$/.test(parts[0])) return { error: 'invalid_key' };
  const mac = crypto.createHmac('sha256', legacySecret).update(parts[0] + '|' + parts[1], 'utf8').digest('base64');
  const a = Buffer.from(mac), b = Buffer.from(parts[2]);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { error: 'invalid_key' };
  return { key, day: parts[0] };
}

// ---------------------------------------------------------------- registry

export function emptyRegistry() {
  return { v: 1, prod: PRODUCT, seq: 0, updated: '', keys: {}, legacy: {}, cmds: {} };
}

export function signRegistry(reg, signPriv) {
  const payload = b64u(Buffer.from(JSON.stringify(reg), 'utf8'));
  return { payload, sig: signP1363(signPriv, payload) };
}

export function openRegistry(envelope, signPub) {
  if (!envelope?.payload || !envelope?.sig) return null;
  if (!verifyP1363(signPub, envelope.payload, envelope.sig)) return null;
  const doc = JSON.parse(unb64u(envelope.payload).toString('utf8'));
  if (doc?.v !== 1 || doc.prod !== PRODUCT) return null;
  return doc;
}

const day = (now) => now.toISOString().slice(0, 10);

function nextSeq(prev, now) {
  const stamp = Number(now.toISOString().replace(/\D/g, '').slice(0, 14)); // yyyyMMddHHmmss
  return Math.max(stamp, (Number(prev) || 0) + 1);
}

const ok = (code, changed = false) => ({ ok: true, code, changed });
const reject = (code) => ({ ok: false, code, changed: false });

/**
 * Applies every request (oldest first) to a copy of the registry.
 * requests: [{ number, body }]  ->  { registry, results: [{ number, ok, code }], changed }
 */
export function processRequests({ registry, requests, keys, now = new Date() }) {
  const reg = structuredClone(registry ?? emptyRegistry());
  reg.keys ??= {};
  reg.legacy ??= {};
  reg.cmds ??= {};
  const results = [];
  let changed = false;

  for (const req of [...requests].sort((a, b) => a.number - b.number)) {
    let r;
    try {
      const env = envelopeFromBody(req.body);
      r = env ? handle(reg, openRequestAny(env, keys), keys, now) : reject('invalid_request');
    } catch {
      r = reject('invalid_request');
    }
    if (r.changed) changed = true;
    results.push({ number: req.number, ok: r.ok, code: r.code });
  }

  if (changed) {
    reg.seq = nextSeq(reg.seq, now);
    reg.updated = now.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const oldest = now.getTime() - (CMD_WINDOW_DAYS + 1) * 86400e3;
    for (const [id, ts] of Object.entries(reg.cmds)) if (Date.parse(ts) < oldest) delete reg.cmds[id];
  }
  return { registry: reg, results, changed };
}

function handle(reg, msg, keys, now) {
  const today = day(now);
  switch (msg?.t) {
    case 'activate': {
      if (!MACHINE_HASH.test(msg.m ?? '')) return reject('invalid_request');
      const k = parseKeyV2(msg.key, keys.issuerPub);
      if (k.error) return reject(k.error);
      if (k.payload.exp && k.payload.exp < today) return reject('expired');
      const e = reg.keys[k.kh];
      if (!e) {
        reg.keys[k.kh] = { s: 'bound', m: msg.m, a: today };     // period starts today
        return ok('activated', true);
      }
      if (e.s === 'revoked') return reject('revoked');
      if (e.s === 'bound' && e.m === msg.m) return ok('already_active');
      if (e.s !== 'bound') {                                       // defensive: unknown state
        reg.keys[k.kh] = { s: 'bound', m: msg.m, a: e.a ?? today };
        return ok('activated', true);
      }
      return reject('other_machine');
    }

    case 'exchange': {
      if (!MACHINE_HASH.test(msg.m ?? '')) return reject('invalid_request');
      const k = parseKeyV1(msg.v1, keys.legacySecret);
      if (k.error) return reject(k.error);
      if (k.day < today) return reject('expired');
      if (k.day > V1_LAST_DAY) return reject('not_eligible');
      const group = legacyGroup(k.key);
      if ((reg.v1revoked ?? []).includes(group)) return reject('revoked');
      const id = legacyId(k.key, msg.m);
      const e = reg.legacy[id];
      if (e) return e.s === 'revoked' ? reject('revoked') : ok('already_active');
      const used = Object.values(reg.legacy).filter((x) => x.k === group && x.s === 'bound').length;
      if (used >= V1_MAX_MACHINES) return reject('machine_limit');
      reg.legacy[id] = { s: 'bound', m: msg.m, a: today, u: k.day, k: group };
      return ok('activated', true);
    }

    case 'cmd':
      return command(reg, msg, keys, now);

    default:
      return reject('invalid_request');
  }
}

// Vendor commands, signed with the key that signs license keys.
function command(reg, msg, keys, now) {
  if (!msg.p || !msg.sig || !verifyP1363(keys.issuerPub, msg.p, msg.sig)) return reject('bad_signature');
  let c;
  try { c = JSON.parse(unb64u(msg.p).toString('utf8')); } catch { return reject('invalid_request'); }
  const ts = Date.parse(c?.ts);
  if (!c?.id || !Number.isFinite(ts) || Math.abs(now.getTime() - ts) > CMD_WINDOW_DAYS * 86400e3) return reject('expired_command');
  if (reg.cmds[c.id]) return reject('replay');

  const today = day(now);
  let r;
  switch (c.op) {
    case 'revoke': {
      if (!c.kh) return reject('invalid_request');
      reg.keys[c.kh] = { ...(reg.keys[c.kh] ?? {}), s: 'revoked' };
      r = ok('done', true);
      break;
    }
    case 'unrevoke': {
      const e = reg.keys[c.kh];
      if (!e) return reject('not_found');
      if (e.m && e.a) e.s = 'bound';
      else delete reg.keys[c.kh];
      r = ok('done', true);
      break;
    }
    case 'move':
    case 'bind': {
      if (!c.kh || !MACHINE_HASH.test(c.m ?? '')) return reject('invalid_request');
      const e = reg.keys[c.kh];
      if (e?.s === 'revoked') return reject('revoked');
      // "move" keeps the original activation date, so the period is not reset.
      reg.keys[c.kh] = { s: 'bound', m: c.m, a: c.a ?? e?.a ?? today };
      r = ok('done', true);
      break;
    }
    case 'reset': {
      if (!c.kh) return reject('invalid_request');
      delete reg.keys[c.kh];
      r = ok('done', true);
      break;
    }
    case 'revoke-v1': {
      if (!c.v1g) return reject('invalid_request');
      reg.v1revoked = [...new Set([...(reg.v1revoked ?? []), c.v1g])];
      for (const e of Object.values(reg.legacy)) if (e.k === c.v1g) e.s = 'revoked';
      r = ok('done', true);
      break;
    }
    default:
      return reject('invalid_request');
  }
  reg.cmds[c.id] = c.ts;
  return r;
}
