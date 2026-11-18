/**
 * ChatVerse backend — Cloudflare Worker + D1 (Firebase-compatible REST)
 * Free tier, no credit card. Node.js ki zaroorat nahi.
 *
 * Endpoints (jo ChatVerse app use karti hai):
 *   POST /v1/accounts:signUp | :signInWithPassword | :lookup | :update | :delete | :sendOobCode
 *   POST /v1/token                     (refresh token)
 *   GET|PATCH|POST|DELETE /v1/projects/:p/databases/:db/documents[/path]
 *   POST /v1/projects/:p/databases/:db/documents:runQuery
 *   GET  /healthz
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization,Content-Type,X-Firebase-Locale,X-Client-Version',
  'Access-Control-Max-Age': '86400'
};

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS, ...extra }
  });

const err = (status, message, code) =>
  json({ error: { code: status, message, status: code || httpStatus(status) } }, status);

const httpStatus = s => s === 400 ? 'INVALID_ARGUMENT' : s === 401 ? 'UNAUTHENTICATED'
  : s === 403 ? 'PERMISSION_DENIED' : s === 404 ? 'NOT_FOUND'
  : s === 409 ? 'ALREADY_EXISTS' : s === 429 ? 'RESOURCE_EXHAUSTED' : 'INTERNAL';

/* ---------------- crypto helpers ---------------- */
const enc = new TextEncoder();
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlDecode = s => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
};
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const randHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signJwt(payload, secret) {
  const head = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const data = head + '.' + body;
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(data));
  return data + '.' + b64url(sig);
}

async function verifyJwt(token, secret) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const [h, b, s] = parts;
  const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), b64urlDecode(s), enc.encode(h + '.' + b));
  if (!ok) return null;
  let p;
  try { p = JSON.parse(new TextDecoder().decode(b64urlDecode(b))); } catch { return null; }
  if (p.exp && Date.now() / 1000 > p.exp) return null;
  return p;
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return 'pbkdf2$100000$' + hex(salt) + '$' + hex(bits);
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith('pbkdf2$')) return false;
  const [, iter, saltHex, hashHex] = stored.split('$');
  const salt = Uint8Array.from(saltHex.match(/../g).map(x => parseInt(x, 16)));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: Number(iter), hash: 'SHA-256' }, key, 256);
  const a = hex(bits), b = hashHex;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* ---------------- Firestore value codec ---------------- */
function encodeValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (typeof v === 'string') return { stringValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(encodeValue) } };
  if (typeof v === 'object') {
    const fields = {};
    for (const k of Object.keys(v)) fields[k] = encodeValue(v[k]);
    return { mapValue: { fields } };
  }
  return { stringValue: String(v) };
}
const encodeFields = obj => {
  const out = {};
  for (const k of Object.keys(obj || {})) out[k] = encodeValue(obj[k]);
  return out;
};
function decodeValue(v) {
  if (!v || typeof v !== 'object') return null;
  if ('nullValue' in v) return null;
  if ('booleanValue' in v) return !!v.booleanValue;
  if ('integerValue' in v) return Number(v.integerValue);
  if ('doubleValue' in v) return Number(v.doubleValue);
  if ('stringValue' in v) return v.stringValue;
  if ('timestampValue' in v) return v.timestampValue;
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(decodeValue);
  if ('mapValue' in v) return decodeFields(v.mapValue.fields || {});
  if ('referenceValue' in v) return v.referenceValue;
  return null;
}
const decodeFields = f => {
  const out = {};
  for (const k of Object.keys(f || {})) out[k] = decodeValue(f[k]);
  return out;
};

/* ---------------- router ---------------- */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (path === '/healthz' || path === '/') {
      let db = 'unknown';
      try { const r = await env.DB.prepare('SELECT 1 AS ok').first(); db = r && r.ok === 1 ? 'ok' : 'fail'; } catch (e) { db = 'fail'; }
      return json({ ok: true, db, service: 'chatverse-worker', time: new Date().toISOString() });
    }

    try {
      if (path.startsWith('/v1/accounts:')) return await authRoute(request, env, path);
      if (path === '/v1/token') return await refreshRoute(request, env);
      if (path.includes('/databases/') && path.includes('/documents')) return await docRoute(request, env, url);
      return err(404, 'Not found: ' + path);
    } catch (e) {
      return err(500, 'Server error: ' + (e && e.message ? e.message : String(e)));
    }
  }
};

/* ---------------- auth ---------------- */
async function readBody(request) {
  try { return await request.json(); } catch { return {}; }
}

async function issueTokens(env, user) {
  const now = Math.floor(Date.now() / 1000);
  const idToken = await signJwt({
    iss: 'chatverse', aud: env.PROJECT_ID || 'chatverse', sub: user.uid,
    email: user.email, auth_time: now, iat: now, exp: now + 3600,
    user_id: user.uid, tv: user.token_version || 0
  }, env.JWT_SECRET);
  const refreshToken = randHex(32);
  await env.DB.prepare('INSERT INTO refresh_tokens (token, uid, created_at) VALUES (?,?,?)')
    .bind(refreshToken, user.uid, Date.now()).run();
  return { idToken, refreshToken, expiresIn: '3600' };
}

function userView(u) {
  return {
    localId: u.uid, email: u.email, emailVerified: !!u.email_verified,
    displayName: u.display_name || undefined, photoUrl: u.photo_url || undefined,
    disabled: !!u.disabled, createdAt: String(u.created_at || Date.now()),
    passwordHash: undefined, providerUserInfo: []
  };
}

async function authRoute(request, env, path) {
  const op = path.split(':')[1];
  const body = await readBody(request);

  if (op === 'signUp') {
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return err(400, 'INVALID_EMAIL');
    if (password.length < 6) return err(400, 'WEAK_PASSWORD : Password should be at least 6 characters');
    const exists = await env.DB.prepare('SELECT uid FROM users WHERE email = ?').bind(email).first();
    if (exists) return err(400, 'EMAIL_EXISTS');
    const uid = randHex(12) + Math.random().toString(36).slice(2, 8);
    const hash = await hashPassword(password);
    await env.DB.prepare(
      'INSERT INTO users (uid, email, password_hash, display_name, photo_url, email_verified, disabled, token_version, created_at) VALUES (?,?,?,?,?,0,0,0,?)'
    ).bind(uid, email, hash, body.displayName || null, body.photoUrl || null, Date.now()).run();
    const user = await env.DB.prepare('SELECT * FROM users WHERE uid = ?').bind(uid).first();
    const t = await issueTokens(env, user);
    return json({ kind: 'identitytoolkit#SignupNewUserResponse', localId: uid, email, ...t });
  }

  if (op === 'signInWithPassword') {
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
    if (!user || user.disabled) return err(400, 'INVALID_LOGIN_CREDENTIALS');
    const ok = await verifyPassword(password, user.password_hash);
    if (!ok) return err(400, 'INVALID_LOGIN_CREDENTIALS');
    const t = await issueTokens(env, user);
    return json({ kind: 'identitytoolkit#VerifyPasswordResponse', localId: user.uid, email, displayName: user.display_name || undefined, ...t });
  }

  if (op === 'lookup') {
    const me = await requireAuth(request, env);
    if (!me) return err(401, 'Missing or invalid token');
    const user = await env.DB.prepare('SELECT * FROM users WHERE uid = ?').bind(me.sub).first();
    if (!user) return err(404, 'USER_NOT_FOUND');
    return json({ kind: 'identitytoolkit#GetAccountInfoResponse', users: [userView(user)] });
  }

  if (op === 'update') {
    const me = await requireAuth(request, env);
    if (!me) return err(401, 'Missing or invalid token');
    const sets = [], vals = [];
    if (body.displayName !== undefined) { sets.push('display_name = ?'); vals.push(body.displayName); }
    if (body.photoUrl !== undefined) { sets.push('photo_url = ?'); vals.push(body.photoUrl); }
    if (body.password !== undefined) { sets.push('password_hash = ?'); vals.push(await hashPassword(String(body.password))); sets.push('token_version = token_version + 1'); }
    if (!sets.length) return err(400, 'NO_FIELDS');
    vals.push(me.sub);
    await env.DB.prepare('UPDATE users SET ' + sets.join(', ') + ' WHERE uid = ?').bind(...vals).run();
    const user = await env.DB.prepare('SELECT * FROM users WHERE uid = ?').bind(me.sub).first();
    return json({ kind: 'identitytoolkit#SetAccountInfoResponse', localId: user.uid, email: user.email, displayName: user.display_name || undefined });
  }

  if (op === 'delete') {
    const me = await requireAuth(request, env);
    if (!me) return err(401, 'Missing or invalid token');
    await env.DB.prepare('DELETE FROM users WHERE uid = ?').bind(me.sub).run();
    await env.DB.prepare('DELETE FROM refresh_tokens WHERE uid = ?').bind(me.sub).run();
    return json({ kind: 'identitytoolkit#DeleteAccountResponse' });
  }

  if (op === 'sendOobCode' || op === 'resetPassword') {
    return json({ kind: 'identitytoolkit#GetOobConfirmationCodeResponse', email: String(body.email || '').toLowerCase(), note: 'Email bhejne ke liye SMTP nahi hai — admin se password reset karwao.' });
  }

  return err(404, 'Unknown accounts op: ' + op);
}

async function refreshRoute(request, env) {
  let body = {};
  const ct = request.headers.get('content-type') || '';
  if (ct.includes('application/json')) body = await readBody(request);
  else { const t = await request.text(); for (const kv of t.split('&')) { const [k, v] = kv.split('='); body[decodeURIComponent(k)] = decodeURIComponent(v || ''); } }
  const token = body.refresh_token;
  if (!token) return err(400, 'MISSING_REFRESH_TOKEN');
  const row = await env.DB.prepare('SELECT * FROM refresh_tokens WHERE token = ?').bind(token).first();
  if (!row) return err(401, 'INVALID_REFRESH_TOKEN');
  const user = await env.DB.prepare('SELECT * FROM users WHERE uid = ?').bind(row.uid).first();
  if (!user || user.disabled) return err(401, 'USER_DISABLED');
  const now = Math.floor(Date.now() / 1000);
  const idToken = await signJwt({ iss: 'chatverse', aud: env.PROJECT_ID || 'chatverse', sub: user.uid, email: user.email, iat: now, exp: now + 3600, user_id: user.uid }, env.JWT_SECRET);
  return json({ access_token: idToken, expires_in: '3600', token_type: 'Bearer', refresh_token: token, id_token: idToken, user_id: user.uid, project_id: env.PROJECT_ID || 'chatverse' });
}

async function requireAuth(request, env) {
  const h = request.headers.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  return await verifyJwt(m[1].trim(), env.JWT_SECRET);
}

/* ---------------- documents ---------------- */
function docPathFromUrl(path) {
  const i = path.indexOf('/documents');
  if (i < 0) return null;
  let rest = path.slice(i + '/documents'.length);
  rest = rest.replace(/^\//, '');
  return rest ? decodeURIComponent(rest) : '';
}

function docName(env, p) {
  const pid = env.PROJECT_ID || 'chatverse';
  return `projects/${pid}/databases/(default)/documents/${p}`;
}

function splitPath(p) {
  const segs = p.split('/');
  if (segs.length % 2 !== 0) return null;
  const collection = segs.slice(0, -1).join('/');
  return { collection, id: segs[segs.length - 1] };
}

async function docRoute(request, env, url) {
  const method = request.method;
  const isRunQuery = url.pathname.endsWith(':runQuery');
  const isAgg = url.pathname.endsWith(':runAggregationQuery');
  if (isRunQuery || isAgg) return await runQuery(request, env);

  const p = docPathFromUrl(url.pathname);
  if (p === null) return err(400, 'Bad documents path');

  if (!p) {                                  // list root collections
    const me = await requireAuth(request, env);
    if (!me) return err(401, 'Missing or invalid token');
    const rows = await env.DB.prepare('SELECT DISTINCT collection FROM docs').all();
    return json({ collections: (rows.results || []).map(r => ({ name: docName(env, r.collection) })) });
  }

  const segs = p.split('/');
  const isCollection = segs.length % 2 !== 0;

  if (isCollection) {
    const me = await requireAuth(request, env);
    if (!me) return err(401, 'Missing or invalid token');
    const collection = segs.join('/');

    if (method === 'GET') {
      const pageSize = Math.min(Number(url.searchParams.get('pageSize') || 30), 300);
      const rows = await env.DB.prepare('SELECT * FROM docs WHERE collection = ? LIMIT 2000').bind(collection).all();
      const docs = (rows.results || []).slice(0, pageSize).map(r => ({
        name: docName(env, r.path), fields: JSON.parse(r.fields),
        createTime: r.create_time, updateTime: r.update_time
      }));
      return json(docs.length ? { documents: docs } : {});
    }

    if (method === 'POST') {
      if (!canWrite(me, collection, '')) return err(403, 'PERMISSION_DENIED');
      const body = await readBody(request);
      const id = url.searchParams.get('documentId') || (randHex(8) + Date.now().toString(36));
      const np = collection + '/' + id;
      const now = new Date().toISOString();
      const fields = body.fields || {};
      await env.DB.prepare('INSERT OR REPLACE INTO docs (path, collection, doc_id, fields, data, create_time, update_time) VALUES (?,?,?,?,?,?,?)')
        .bind(np, collection, id, JSON.stringify(fields), JSON.stringify(decodeFields(fields)), now, now).run();
      return json({ name: docName(env, np), fields, createTime: now, updateTime: now });
    }

    return err(405, 'Method not allowed on collection');
  }

  const parts = splitPath(p);
  if (!parts) return err(400, 'Document path must be collection/id');

  if (method === 'GET') {
    const me = await requireAuth(request, env);
    if (!me) return err(401, 'Missing or invalid token');
    const row = await env.DB.prepare('SELECT * FROM docs WHERE path = ?').bind(p).first();
    if (!row) return err(404, 'No such document: ' + p);
    return json({ name: docName(env, p), fields: JSON.parse(row.fields), createTime: row.create_time, updateTime: row.update_time });
  }

  if (method === 'PATCH') {
    const me = await requireAuth(request, env);
    if (!me) return err(401, 'Missing or invalid token');
    if (!canWrite(me, parts.collection, parts.id)) return err(403, 'PERMISSION_DENIED');
    const body = await readBody(request);
    const incoming = body.fields || {};
    const existing = await env.DB.prepare('SELECT * FROM docs WHERE path = ?').bind(p).first();
    const mask = url.searchParams.getAll('updateMask.fieldPaths');
    let fields = {};
    if (mask.length) {
      fields = existing ? JSON.parse(existing.fields) : {};
      for (const f of mask) { if (incoming[f] !== undefined) fields[f] = incoming[f]; else delete fields[f]; }
    } else {
      fields = incoming;
    }
    const now = new Date().toISOString();
    const data = JSON.stringify(decodeFields(fields));
    if (existing) {
      await env.DB.prepare('UPDATE docs SET fields = ?, data = ?, update_time = ? WHERE path = ?')
        .bind(JSON.stringify(fields), data, now, p).run();
    } else {
      await env.DB.prepare('INSERT INTO docs (path, collection, doc_id, fields, data, create_time, update_time) VALUES (?,?,?,?,?,?,?)')
        .bind(p, parts.collection, parts.id, JSON.stringify(fields), data, now, now).run();
    }
    const row = await env.DB.prepare('SELECT * FROM docs WHERE path = ?').bind(p).first();
    return json({ name: docName(env, p), fields: JSON.parse(row.fields), createTime: row.create_time, updateTime: row.update_time });
  }

  if (method === 'POST') {                    // create with generated id (or ?documentId=)
    const me = await requireAuth(request, env);
    if (!me) return err(401, 'Missing or invalid token');
    if (!canWrite(me, parts.collection, parts.id)) return err(403, 'PERMISSION_DENIED');
    const body = await readBody(request);
    const id = url.searchParams.get('documentId') || (parts.id !== '' ? parts.id : randHex(8) + Date.now().toString(36));
    const np = parts.collection + '/' + id;
    const now = new Date().toISOString();
    const fields = body.fields || {};
    await env.DB.prepare('INSERT OR REPLACE INTO docs (path, collection, doc_id, fields, data, create_time, update_time) VALUES (?,?,?,?,?,?,?)')
      .bind(np, parts.collection, id, JSON.stringify(fields), JSON.stringify(decodeFields(fields)), now, now).run();
    return json({ name: docName(env, np), fields, createTime: now, updateTime: now });
  }

  if (method === 'DELETE') {
    const me = await requireAuth(request, env);
    if (!me) return err(401, 'Missing or invalid token');
    if (!canWrite(me, parts.collection, parts.id)) return err(403, 'PERMISSION_DENIED');
    await env.DB.prepare('DELETE FROM docs WHERE path = ?').bind(p).run();
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json', ...CORS } });
  }

  return err(405, 'Method not allowed');
}

/* simple, honest authorization (full Firestore rules engine nahi hai) */
function canWrite(me, collection, id) {
  if (!me || !me.sub) return false;
  const c = collection.split('/')[0];
  if (c === 'users') return id === me.sub || id === '';       // apna hi doc
  if (c === 'handles') return true;                            // username claim
  if (c === 'admins' || c === 'bans' || c === 'config') return false; // admin panel se hi
  return true;                                                 // posts/reels/dm/etc: signed-in
}

async function runQuery(request, env) {
  const me = await requireAuth(request, env);
  if (!me) return err(401, 'Missing or invalid token');
  const body = await readBody(request);
  const sq = (body.structuredQuery || {});
  const from = sq.from && sq.from[0] ? sq.from[0].collectionId : null;
  if (!from) return err(400, 'from.collectionId required');
  const limit = Math.min(Number((sq.limit && sq.limit.value) || 100), 300);

  let rows = await env.DB.prepare('SELECT * FROM docs WHERE collection = ? LIMIT 2000').bind(from).all();
  let docs = (rows.results || []).map(r => ({ path: r.path, data: JSON.parse(r.data), fields: JSON.parse(r.fields), create_time: r.create_time }));

  for (const f of (sq.where && sq.where.compositeFilter ? sq.where.compositeFilter.filters : (sq.where ? [sq.where] : []))) {
    if (!f || !f.fieldFilter) continue;
    const { field, op, value } = f.fieldFilter;
    const key = (field.fieldPath || '').split('.').pop();
    const want = decodeValue(value);
    docs = docs.filter(d => {
      const have = d.data[key];
      if (op === 'EQUAL') return JSON.stringify(have) === JSON.stringify(want);
      if (op === 'NOT_EQUAL') return JSON.stringify(have) !== JSON.stringify(want);
      if (op === 'ARRAY_CONTAINS') return Array.isArray(have) && have.some(x => JSON.stringify(x) === JSON.stringify(want));
      if (op === 'IN') return Array.isArray(want) && want.some(x => JSON.stringify(x) === JSON.stringify(have));
      if (op === 'LESS_THAN') return have < want;
      if (op === 'GREATER_THAN') return have > want;
      return true;
    });
  }
  if (sq.orderBy && sq.orderBy.length) {
    const ob = sq.orderBy[0];
    const key = (ob.field && ob.field.fieldPath || '').split('.').pop();
    const dir = ob.direction === 'DESCENDING' ? -1 : 1;
    docs.sort((a, b) => (a.data[key] > b.data[key] ? 1 : a.data[key] < b.data[key] ? -1 : 0) * dir);
  }
  docs = docs.slice(0, limit);

  return json(docs.map(d => ({
    document: { name: docName(env, d.path), fields: d.fields, createTime: d.create_time, updateTime: d.create_time },
    readTime: new Date().toISOString()
  })));
}
