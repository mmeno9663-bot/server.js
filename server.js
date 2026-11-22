'use strict';
/*
 * سيرفر منصة الطلاب: الحسابات + تسجيل الدخول + تحكم المالك
 * قاعدة البيانات: PostgreSQL (Neon) عبر متغير DATABASE_URL
 * يحتاج مكتبة pg في package.json
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Pool, types } = require('pg');

/* ---------------- الإعدادات ---------------- */
const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const OWNER_KEY = process.env.OWNER_KEY || '';
const DATABASE_URL = process.env.DATABASE_URL || '';
const TRUST_PROXY = process.env.TRUST_PROXY !== '0';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const TOKEN_DAYS = 30;
const DAY = 86400000;

if (OWNER_KEY.length < 8) {
  console.error('خطأ: لازم تضبط OWNER_KEY (٨ أحرف على الأقل). هذا هو رمز دخول لوحة المالك.');
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error('خطأ: لازم تضبط DATABASE_URL (رابط قاعدة Neon).');
  process.exit(1);
}

/* ---------------- قاعدة البيانات ---------------- */
types.setTypeParser(20, v => Number(v)); // BIGINT يرجع رقم عادي مو نص
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000
});
pool.on('error', e => console.error('pg pool error:', e.message));

// يحوّل علامات ? إلى $1,$2,...
const Q = (sql, params = []) => {
  let i = 0;
  return pool.query(sql.replace(/\?/g, () => '$' + (++i)), params);
};
const one = async (sql, p) => (await Q(sql, p)).rows[0] || null;
const all = async (sql, p) => (await Q(sql, p)).rows;
const run = async (sql, p) => (await Q(sql, p)).rowCount;

async function init() {
  await Q(`CREATE TABLE IF NOT EXISTS accounts(
    uid SERIAL PRIMARY KEY,
    k TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    ar TEXT, en TEXT, nc TEXT,
    nid TEXT UNIQUE,
    sx TEXT,
    pw TEXT NOT NULL,
    sq TEXT,
    ct INTEGER DEFAULT 0,
    lk INTEGER DEFAULT 0,
    dis BIGINT DEFAULT 0,
    tv INTEGER DEFAULT 0,
    fails INTEGER DEFAULT 0,
    lock_until BIGINT DEFAULT 0,
    created BIGINT,
    last_login BIGINT
  )`);
  await Q(`CREATE TABLE IF NOT EXISTS otps(
    id SERIAL PRIMARY KEY,
    k TEXT, purpose TEXT, ref TEXT, code TEXT,
    exp BIGINT, tries INTEGER DEFAULT 0, used INTEGER DEFAULT 0
  )`);
  await Q('CREATE INDEX IF NOT EXISTS otps_idx ON otps(k, purpose, ref)');
  await Q('CREATE TABLE IF NOT EXISTS used_proofs(jti TEXT PRIMARY KEY, exp BIGINT)');
  await Q('CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL)');
  SECRET = await loadSecret();
}

/* المفتاح السري يتخزن في القاعدة عشان ما يتغير مع كل إعادة تشغيل */
let SECRET = '';
async function loadSecret() {
  if (process.env.SECRET && process.env.SECRET.length >= 16) return process.env.SECRET;
  let r = await one("SELECT v FROM settings WHERE k='secret'");
  if (!r) {
    await Q("INSERT INTO settings(k,v) VALUES('secret',?) ON CONFLICT (k) DO NOTHING", [crypto.randomBytes(32).toString('hex')]);
    r = await one("SELECT v FROM settings WHERE k='secret'");
  }
  return r.v;
}

/* ---------------- أدوات ---------------- */
const norm = p => String(p || '').replace(/\D/g, '').replace(/^0+/, '');
const key9 = p => norm(p).slice(-9);
const AR_DIGITS = '٠١٢٣٤٥٦٧٨٩';
const toEnDigits = s => String(s || '').replace(/[٠-٩]/g, d => AR_DIGITS.indexOf(d));
const PURPOSES = ['up', 'fg', 'ed'];
const MAX_INT = 2147483647;

function phoneNorm(r) {
  let s = toEnDigits(r).trim().replace(/[\s\-().]/g, '');
  if (s.startsWith('00')) s = '+' + s.slice(2);
  return /^\+[1-9]\d{7,14}$/.test(s) ? s : null;
}
function emailOk(e) {
  e = String(e || '').trim();
  return e.length <= 254 && /^[A-Za-z0-9][A-Za-z0-9._%+-]{0,62}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}$/.test(e) && !e.includes('..');
}
const arOk = v => /^[\u0600-\u06FF]+( [\u0600-\u06FF]+){3,}$/.test(v) && v.length <= 80;
const enOk = v => /^[A-Za-z'\-]+( [A-Za-z'\-]+){3,}$/.test(v) && v.length <= 80;
const nidOk = v => /^[A-Z0-9]{5,24}$/.test(v);
const ncOk = v => /^[A-Z]{2}$/.test(v);
const pwOk = v => typeof v === 'string' && v.length >= 6 && v.length <= 128;
const cleanName = v => String(v || '').trim().replace(/\s+/g, ' ');
const cleanNid = v => toEnDigits(v).replace(/[\s-]/g, '').toUpperCase();

const b64u = b => Buffer.from(b).toString('base64url');
function sign(obj) {
  const p = b64u(JSON.stringify(obj));
  return p + '.' + crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
}
function unsign(s) {
  if (typeof s !== 'string') return null;
  const [p, g] = s.split('.');
  if (!p || !g) return null;
  const e = crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
  const a = Buffer.from(g), b = Buffer.from(e);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const o = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    return o && o.exp > Date.now() ? o : null;
  } catch (e2) { return null; }
}
const safeEq = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};

const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? rej(e) : res(k))));
async function hashPw(pw) {
  const s = crypto.randomBytes(16);
  return s.toString('hex') + ':' + (await scrypt(pw, s)).toString('hex');
}
async function checkPw(pw, stored) {
  const [s, h] = stored.split(':');
  const x = await scrypt(pw, Buffer.from(s, 'hex'));
  return crypto.timingSafeEqual(x, Buffer.from(h, 'hex'));
}
let dummyHash = null;

/* تحديد المحاولات */
const hits = new Map();
function limited(key, max, win) {
  const now = Date.now();
  let h = hits.get(key);
  if (!h || now > h.t) { h = { n: 0, t: now + win }; hits.set(key, h); }
  h.n++;
  return h.n > max;
}
const fl = new Map();
function failState(key) {
  const n = Date.now();
  let h = fl.get(key);
  if (!h || n > h.t) { h = { n: 0, t: n + 10 * 60000 }; fl.set(key, h); }
  return h;
}
setInterval(async () => {
  const n = Date.now();
  for (const [k, v] of hits) if (n > v.t) hits.delete(k);
  for (const [k, v] of fl) if (n > v.t) fl.delete(k);
  try {
    await Q('DELETE FROM otps WHERE exp<?', [n - DAY]);
    await Q('DELETE FROM used_proofs WHERE exp<?', [n]);
  } catch (e) { console.error('cleanup error:', e.message); }
}, 600000).unref();

/* ---------------- HTTP ---------------- */
class HttpErr extends Error {
  constructor(status, code, extra) { super(code); this.status = status; this.code = code; this.extra = extra || {}; }
}
const fail = (s, c, x) => { throw new HttpErr(s, c, x); };

// يحوّل خطأ "مكرر" من القاعدة إلى رد مفهوم
function dupErr(e) {
  if (e && e.code === '23505') {
    const c = String(e.constraint || '');
    return new HttpErr(409, c.includes('email') ? 'email_taken' : c.includes('nid') ? 'nid_taken' : 'phone_taken');
  }
  return e;
}

const corsH = () => ({
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Max-Age': '86400'
});
const secH = () => ({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });

function send(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...corsH(), ...secH() });
  res.end(JSON.stringify(obj));
}
async function readBody(req) {
  let n = 0; const ch = [];
  for await (const c of req) { n += c.length; if (n > 40000) fail(413, 'too_large'); ch.push(c); }
  if (!n) return {};
  let o;
  try { o = JSON.parse(Buffer.concat(ch).toString('utf8')); } catch (e) { fail(400, 'invalid'); }
  if (!o || typeof o !== 'object' || Array.isArray(o)) fail(400, 'invalid');
  return o;
}
function clientIp(req) {
  if (TRUST_PROXY) {
    const x = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (x.length) return x[x.length - 1];
  }
  return req.socket.remoteAddress || '?';
}

/* ---------------- حالة الحساب ---------------- */
function statusOf(a) {
  if (a.lk) return { error: 'locked' };
  if (a.dis > Date.now()) return { error: 'disabled', extra: { until: a.dis } };
  return null;
}
const pub = a => ({
  p: a.phone, e: a.email, ar: a.ar, en: a.en, nc: a.nc, nid: a.nid, sx: a.sx,
  sq: a.sq ? JSON.parse(a.sq) : null, ct: !!a.ct, lk: !!a.lk, dis: a.dis > Date.now() ? a.dis : 0
});
const own = a => ({
  id: a.uid, p: a.phone, e: a.email, ar: a.ar, en: a.en, nc: a.nc, nid: a.nid, sx: a.sx,
  lk: !!a.lk, dis: a.dis > Date.now() ? a.dis : 0, created: a.created, last: a.last_login
});
const userToken = a => sign({ r: 'user', u: a.uid, tv: a.tv, exp: Date.now() + TOKEN_DAYS * DAY });

async function authUser(req) {
  const h = req.headers.authorization || '';
  const o = unsign(h.startsWith('Bearer ') ? h.slice(7) : '');
  if (!o || o.r !== 'user') fail(401, 'expired');
  const a = await one('SELECT * FROM accounts WHERE uid=?', [o.u]);
  if (!a) fail(401, 'deleted');
  if (a.tv !== o.tv) fail(401, 'revoked');
  const s = statusOf(a);
  if (s) fail(403, s.error, s.extra);
  return a;
}
function authOwner(req) {
  const h = req.headers.authorization || '';
  const o = unsign(h.startsWith('Bearer ') ? h.slice(7) : '');
  if (!o || o.r !== 'owner') fail(401, 'expired');
  return true;
}

/* إثبات التحقق (يُستهلك مرة واحدة) */
function makeProof(purpose, k) {
  return sign({ t: 'proof', pu: purpose, k, j: crypto.randomUUID(), exp: Date.now() + 10 * 60000 });
}
async function consumeProof(proof, purpose, k) {
  const o = unsign(proof);
  if (!o || o.t !== 'proof' || o.pu !== purpose || o.k !== k) fail(400, 'bad_proof');
  const n = await run('INSERT INTO used_proofs(jti,exp) VALUES(?,?) ON CONFLICT (jti) DO NOTHING', [o.j, o.exp]);
  if (!n) fail(400, 'bad_proof');
}

function validateSq(sq) {
  if (sq === null) return null;
  if (!sq || typeof sq !== 'object') fail(400, 'invalid');
  const { q, s, h } = sq;
  const okQ = Array.isArray(q) && q.length === 3 && q.every(n => Number.isInteger(n) && n >= 0 && n <= 8) && new Set(q).size === 3;
  const okH = Array.isArray(h) && h.length === 3 && h.every(x => typeof x === 'string' && x.length <= 100);
  if (!okQ || !okH || typeof s !== 'string' || s.length > 100) fail(400, 'invalid');
  return JSON.stringify({ q, s, h });
}

/* ---------------- المسارات ---------------- */
const routes = [];
const R = (m, p, h, auth) => routes.push({ m, auth, h, re: new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$') });

R('GET', '/api/health', async () => { await Q('SELECT 1'); return { ok: true }; });

/* --- التسجيل --- */
R('POST', '/api/register', async c => {
  if (limited('reg:' + c.ip, 20, 10 * 60000)) fail(429, 'too_many');
  const b = c.body;
  const phone = phoneNorm(b.phone), email = String(b.email || '').trim().toLowerCase();
  const ar = cleanName(b.ar), en = cleanName(b.en), nid = cleanNid(b.nid), nc = String(b.nc || '').toUpperCase();
  if (!phone || key9(phone).length < 7 || !emailOk(email) || !arOk(ar) || !enOk(en) || !nidOk(nid) || !ncOk(nc)
    || !['M', 'F'].includes(b.sx) || !pwOk(b.password)) fail(400, 'invalid');
  const k = key9(phone);
  const taken = async () => {
    if (await one('SELECT 1 FROM accounts WHERE k=?', [k])) return 'phone_taken';
    if (await one('SELECT 1 FROM accounts WHERE email=?', [email])) return 'email_taken';
    if (await one('SELECT 1 FROM accounts WHERE nid=?', [nid])) return 'nid_taken';
    return null;
  };
  let t = await taken();
  if (t) fail(409, t);
  const pw = await hashPw(b.password);
  t = await taken();
  if (t) fail(409, t);
  await consumeProof(b.proof, 'up', k);
  const now = Date.now();
  let a;
  try {
    a = await one(
      'INSERT INTO accounts(k,phone,email,ar,en,nc,nid,sx,pw,created,last_login) VALUES(?,?,?,?,?,?,?,?,?,?,?) RETURNING *',
      [k, phone, email, ar, en, nc, nid, b.sx, pw, now, now]);
  } catch (e) { throw dupErr(e); }
  return { token: userToken(a), account: pub(a) };
});

/* --- الدخول --- */
R('POST', '/api/login', async c => {
  if (limited('login:' + c.ip, 40, 60000)) fail(429, 'too_many');
  const id = String(c.body.id || '').trim(), password = String(c.body.password || '');
  if (!id || password.length > 128) fail(400, 'invalid');
  let a;
  if (id.includes('@')) a = await one('SELECT * FROM accounts WHERE email=?', [id.toLowerCase()]);
  else { const k = key9(toEnDigits(id)); a = k.length >= 7 ? await one('SELECT * FROM accounts WHERE k=?', [k]) : null; }
  if (!a) {
    dummyHash = dummyHash || await hashPw('dummy');
    await checkPw(password, dummyHash);
    fail(404, 'no_account');
  }
  if (Date.now() < a.lock_until) fail(429, 'too_many');
  if (!(await checkPw(password, a.pw))) {
    const f = a.fails + 1;
    if (f >= 5) await Q('UPDATE accounts SET fails=0, lock_until=? WHERE uid=?', [Date.now() + 60000, a.uid]);
    else await Q('UPDATE accounts SET fails=? WHERE uid=?', [f, a.uid]);
    fail(401, 'bad_password');
  }
  await Q('UPDATE accounts SET fails=0, lock_until=0, last_login=? WHERE uid=?', [Date.now(), a.uid]);
  const s = statusOf(a);
  if (s) fail(403, s.error, s.extra);
  return { token: userToken(a), account: pub(a) };
});

/* --- حساب المستخدم --- */
R('GET', '/api/me', async c => ({ account: pub(c.acct) }), 'user');

R('POST', '/api/me/verify-password', async c => {
  if (limited('vp:' + c.acct.uid, 10, 60000)) fail(429, 'too_many');
  if (!(await checkPw(String(c.body.password || ''), c.acct.pw))) fail(401, 'bad_password');
  return { ok: true };
}, 'user');

R('PUT', '/api/me', async c => {
  const a = c.acct, b = c.body, set = {};
  let sensitive = false;

  if (typeof b.p === 'string' && b.p !== a.phone) {
    const ph = phoneNorm(b.p);
    if (!ph || key9(ph).length < 7) fail(400, 'invalid');
    const k = key9(ph);
    if (k !== a.k && await one('SELECT 1 FROM accounts WHERE k=? AND uid<>?', [k, a.uid])) fail(409, 'phone_taken');
    set.phone = ph; set.k = k;
  }
  if (typeof b.e === 'string' && b.e.trim().toLowerCase() !== a.email) {
    const e = b.e.trim().toLowerCase();
    if (!emailOk(e)) fail(400, 'invalid');
    if (await one('SELECT 1 FROM accounts WHERE email=? AND uid<>?', [e, a.uid])) fail(409, 'email_taken');
    set.email = e;
  }
  if (typeof b.sx === 'string' && b.sx !== a.sx) {
    if (!['M', 'F'].includes(b.sx)) fail(400, 'invalid');
    set.sx = b.sx;
  }
  if (typeof b.ar === 'string' && cleanName(b.ar) !== a.ar) {
    if (!arOk(cleanName(b.ar))) fail(400, 'invalid');
    set.ar = cleanName(b.ar); sensitive = true;
  }
  if (typeof b.en === 'string' && cleanName(b.en) !== a.en) {
    if (!enOk(cleanName(b.en))) fail(400, 'invalid');
    set.en = cleanName(b.en); sensitive = true;
  }
  if (typeof b.nc === 'string' && b.nc.toUpperCase() !== a.nc) {
    if (!ncOk(b.nc.toUpperCase())) fail(400, 'invalid');
    set.nc = b.nc.toUpperCase(); sensitive = true;
  }
  if (typeof b.nid === 'string' && cleanNid(b.nid) !== a.nid) {
    const n = cleanNid(b.nid);
    if (!nidOk(n)) fail(400, 'invalid');
    if (await one('SELECT 1 FROM accounts WHERE nid=? AND uid<>?', [n, a.uid])) fail(409, 'nid_taken');
    set.nid = n; sensitive = true;
  }
  if ('sq' in b) {
    const v = validateSq(b.sq);
    if (v !== a.sq) set.sq = v;
  }
  if (typeof b.ct === 'boolean' && b.ct !== !!a.ct) set.ct = b.ct ? 1 : 0;

  if (sensitive) await consumeProof(b.proof, 'ed', a.k);
  const cols = Object.keys(set);
  if (cols.length) {
    try {
      await Q('UPDATE accounts SET ' + cols.map(x => x + '=?').join(',') + ' WHERE uid=?', [...cols.map(x => set[x]), a.uid]);
    } catch (e) { throw dupErr(e); }
  }
  return { account: pub(await one('SELECT * FROM accounts WHERE uid=?', [a.uid])) };
}, 'user');

R('DELETE', '/api/me', async c => {
  await Q('DELETE FROM accounts WHERE uid=?', [c.acct.uid]);
  return { ok: true };
}, 'user');

/* --- رموز التحقق (يصدرها المالك فقط) --- */
R('POST', '/api/otp/check', async c => {
  if (limited('otp:' + c.ip, 40, 60000)) fail(429, 'too_many');
  const { phone, purpose, ref, code } = c.body;
  const k = key9(toEnDigits(phone));
  if (!PURPOSES.includes(purpose) || !/^\d{6}$/.test(String(ref)) || !/^\d{5}$/.test(String(code)) || k.length < 7) fail(400, 'invalid');
  const row = await one('SELECT * FROM otps WHERE k=? AND purpose=? AND ref=? AND used=0 AND exp>? ORDER BY id DESC LIMIT 1',
    [k, purpose, String(ref), Date.now()]);
  if (!row) fail(400, 'bad_code');
  if (row.tries >= 5) fail(429, 'too_many');
  if (!safeEq(row.code, String(code))) {
    await Q('UPDATE otps SET tries=tries+1 WHERE id=?', [row.id]);
    fail(400, 'bad_code');
  }
  await Q('UPDATE otps SET used=1 WHERE id=?', [row.id]);
  return { proof: makeProof(purpose, k) };
});

/* --- استعادة كلمة المرور --- */
R('POST', '/api/lookup', async c => {
  if (limited('lk:' + c.ip, 15, 60000)) fail(429, 'too_many');
  const v = toEnDigits(String(c.body.v || '')).trim();
  if (!v || v.length > 254) fail(400, 'invalid');
  let a = null, by = '';
  if (v.includes('@')) { a = await one('SELECT * FROM accounts WHERE email=?', [v.toLowerCase()]); by = 'em'; }
  else {
    a = await one('SELECT * FROM accounts WHERE nid=?', [cleanNid(v)]); by = 'nid';
    if (!a) { const k = key9(v); if (k.length >= 7) { a = await one('SELECT * FROM accounts WHERE k=?', [k]); by = 'ph'; } }
  }
  if (!a) fail(404, 'not_found');
  const first = s => String(s || '').split(' ')[0];
  const sq = a.sq ? JSON.parse(a.sq) : null;
  return { by, account: { p: a.phone, ar: first(a.ar), en: first(a.en), sq: sq ? { q: sq.q } : null } };
});

R('POST', '/api/recover/verify', async c => {
  if (limited('rv:' + c.ip, 30, 10 * 60000)) fail(429, 'too_many');
  const k = key9(toEnDigits(c.body.phone));
  const a = k.length >= 7 ? await one('SELECT * FROM accounts WHERE k=?', [k]) : null;
  if (!a) fail(404, 'not_found');
  const fs_ = failState('rv:' + a.uid);
  if (fs_.n >= 5) fail(429, 'too_many');
  let ok = false;
  const m = c.body.method;
  if (m === 'em') ok = safeEq(String(c.body.value || '').trim().toLowerCase(), a.email);
  else if (m === 'nid') ok = safeEq(cleanNid(c.body.value), a.nid || '');
  else if (m === 'sq' && a.sq && Array.isArray(c.body.answers) && c.body.answers.length === 3) {
    const sq = JSON.parse(a.sq);
    ok = true;
    for (let i = 0; i < 3; i++) {
      const ans = String(c.body.answers[i] || '').slice(0, 200);
      const h = await new Promise((res, rej) => crypto.pbkdf2(Buffer.from(ans, 'utf8'), Buffer.from(sq.s, 'base64'), 150000, 32, 'sha256',
        (e, k2) => (e ? rej(e) : res(k2.toString('base64')))));
      if (!ans || !safeEq(h, sq.h[i])) ok = false;
    }
  } else fail(400, 'invalid');
  if (!ok) { fs_.n++; fail(400, 'mismatch'); }
  fl.delete('rv:' + a.uid);
  return { proof: makeProof('fg', a.k) };
});

R('POST', '/api/reset', async c => {
  if (limited('rs:' + c.ip, 20, 10 * 60000)) fail(429, 'too_many');
  const k = key9(toEnDigits(c.body.phone));
  const a = k.length >= 7 ? await one('SELECT * FROM accounts WHERE k=?', [k]) : null;
  if (!a) fail(404, 'not_found');
  if (!pwOk(c.body.password)) fail(400, 'invalid');
  const pw = await hashPw(c.body.password);
  await consumeProof(c.body.proof, 'fg', a.k);
  await Q('UPDATE accounts SET pw=?, tv=tv+1, fails=0, lock_until=0 WHERE uid=?', [pw, a.uid]);
  return { ok: true };
});

/* --- لوحة المالك --- */
R('POST', '/api/owner/login', async c => {
  if (limited('ow:' + c.ip, 8, 60000)) fail(429, 'too_many');
  if (!safeEq(String(c.body.key || ''), OWNER_KEY)) fail(401, 'bad_key');
  return { token: sign({ r: 'owner', exp: Date.now() + 2 * 3600000 }) };
});

R('GET', '/api/owner/accounts', async c => {
  const id = c.query.get('id'), q = (c.query.get('q') || '').trim();
  let rows;
  if (id) {
    const n = Number(id);
    rows = (Number.isInteger(n) && n > 0 && n <= MAX_INT) ? await all('SELECT * FROM accounts WHERE uid=?', [n]) : [];
  } else if (!q) rows = await all('SELECT * FROM accounts ORDER BY uid DESC LIMIT 50');
  else {
    const conds = [], params = [];
    const qd = toEnDigits(q);
    if (qd.includes('@')) { conds.push('email=?'); params.push(qd.toLowerCase()); }
    conds.push('nid=?'); params.push(cleanNid(qd));
    const k = key9(qd);
    if (k.length >= 7) { conds.push('k=?'); params.push(k); }
    const like = '%' + q.replace(/[%_\\]/g, '') + '%';
    conds.push('ar ILIKE ?', 'en ILIKE ?'); params.push(like, like);
    rows = await all('SELECT * FROM accounts WHERE ' + conds.join(' OR ') + ' ORDER BY uid DESC LIMIT 50', params);
  }
  return { accounts: rows.map(own) };
}, 'owner');

R('POST', '/api/owner/otp', async c => {
  const k = key9(toEnDigits(c.body.phone)), ref = String(c.body.ref || '');
  if (!PURPOSES.includes(c.body.purpose) || !/^\d{6}$/.test(ref) || k.length < 7) fail(400, 'invalid');
  const code = String(crypto.randomInt(0, 100000)).padStart(5, '0');
  const exp = Date.now() + 15 * 60000;
  await Q('DELETE FROM otps WHERE k=? AND purpose=? AND ref=?', [k, c.body.purpose, ref]);
  await Q('INSERT INTO otps(k,purpose,ref,code,exp) VALUES(?,?,?,?,?)', [k, c.body.purpose, ref, code, exp]);
  return { code, expires: exp };
}, 'owner');

const acctById = async id => {
  const n = Number(id);
  if (!Number.isInteger(n) || n < 1 || n > MAX_INT) fail(404, 'not_found');
  const a = await one('SELECT * FROM accounts WHERE uid=?', [n]);
  if (!a) fail(404, 'not_found');
  return a;
};
R('POST', '/api/owner/accounts/:id/lock', async c => {
  const a = await acctById(c.params.id), lock = c.body.lock ? 1 : 0;
  await Q('UPDATE accounts SET lk=? WHERE uid=?', [lock, a.uid]);
  return { ok: true };
}, 'owner');
R('POST', '/api/owner/accounts/:id/disable', async c => {
  const a = await acctById(c.params.id), h = Number(c.body.hours);
  if (!Number.isFinite(h) || h < 0 || h > 72) fail(400, 'invalid');
  await Q('UPDATE accounts SET dis=? WHERE uid=?', [h ? Date.now() + Math.round(h * 3600000) : 0, a.uid]);
  return { ok: true };
}, 'owner');
R('POST', '/api/owner/accounts/:id/password', async c => {
  const a = await acctById(c.params.id);
  if (!pwOk(c.body.password)) fail(400, 'invalid');
  const pw = await hashPw(c.body.password);
  await Q('UPDATE accounts SET pw=?, tv=tv+1, fails=0, lock_until=0 WHERE uid=?', [pw, a.uid]);
  return { ok: true };
}, 'owner');
R('POST', '/api/owner/accounts/:id/revoke', async c => {
  const a = await acctById(c.params.id);
  await Q('UPDATE accounts SET tv=tv+1 WHERE uid=?', [a.uid]);
  return { ok: true };
}, 'owner');
R('DELETE', '/api/owner/accounts/:id', async c => {
  const a = await acctById(c.params.id);
  await Q('DELETE FROM accounts WHERE uid=?', [a.uid]);
  return { ok: true };
}, 'owner');

/* ---------------- الملفات الثابتة (الواجهة) ---------------- */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json'
};
function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  try { rel = decodeURIComponent(rel); } catch (e) { res.writeHead(400); return res.end(); }
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('غير موجود'); }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600',
      ...secH()
    });
    res.end(req.method === 'HEAD' ? undefined : buf);
  });
}

/* ---------------- الخادم ---------------- */
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (req.method === 'OPTIONS') { res.writeHead(204, corsH()); return res.end(); }
    if (!url.pathname.startsWith('/api/')) {
      if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
      return serveStatic(req, res, url.pathname);
    }
    for (const r of routes) {
      if (r.m !== req.method) continue;
      const m = r.re.exec(url.pathname);
      if (!m) continue;
      const ctx = { req, ip: clientIp(req), query: url.searchParams, params: m.groups || {}, body: {} };
      if (r.auth === 'user') ctx.acct = await authUser(req);
      if (r.auth === 'owner') authOwner(req);
      if (req.method !== 'GET') ctx.body = await readBody(req);
      return send(res, 200, await r.h(ctx));
    }
    fail(404, 'not_found');
  } catch (e) {
    if (e instanceof HttpErr) return send(res, e.status, { error: e.code, ...e.extra });
    console.error(e);
    send(res, 500, { error: 'server' });
  }
});

init()
  .then(() => server.listen(PORT, () => console.log('السيرفر شغال على المنفذ ' + PORT + ' (PostgreSQL)')))
  .catch(e => { console.error('فشل الاتصال بالقاعدة:', e.message); process.exit(1); });
