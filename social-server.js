'use strict';
/*
 * منصة ALMARKA الاجتماعية: منشورات + إعجابات + تعليقات + بلاغات.
 * يُستدعى من server.js هكذا:
 *   require('./social-server')({ file, getAccount })
 * ويرجع دالة async (req, res) => true إذا عالج الطلب، وإلا false.
 * بدون مكتبات خارجية. التخزين في ملف JSON (كتابة ذرية).
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const MAX_POST = 1500, MAX_COMMENT = 500;
const MAX_POSTS_KEPT = 500, MAX_POSTS_LISTED = 100, MAX_COMMENTS = 200;
const HIDE_AT_REPORTS = 5;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

module.exports = function createSocial(opts) {
  const FILE = opts.file;
  const getAccount = opts.getAccount;

  /* ---------- التخزين ---------- */
  let data = { joined: {}, posts: [] };
  try {
    const d = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    if (d && typeof d === 'object') {
      data.joined = d.joined && typeof d.joined === 'object' ? d.joined : {};
      data.posts = Array.isArray(d.posts) ? d.posts : [];
    }
  } catch (e) { /* أول تشغيل أو ملف تالف: نبدأ فارغ */ }

  let saveTimer = null;
  function save() {
    if (saveTimer) return;
    saveTimer = setTimeout(() => {
      saveTimer = null;
      try {
        fs.mkdirSync(path.dirname(FILE), { recursive: true });
        const tmp = FILE + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(data));
        fs.renameSync(tmp, FILE);
      } catch (e) { console.error('social save failed:', e.message); }
    }, 300);
    saveTimer.unref && saveTimer.unref();
  }
  const flush = () => {
    if (!saveTimer) return;
    clearTimeout(saveTimer); saveTimer = null;
    try { fs.writeFileSync(FILE + '.tmp', JSON.stringify(data)); fs.renameSync(FILE + '.tmp', FILE); } catch (e) { /* ignore */ }
  };
  process.on('SIGTERM', flush);
  process.on('exit', flush);

  /* ---------- أدوات ---------- */
  class Err extends Error { constructor(s, c) { super(c); this.status = s; this.code = c; } }
  const fail = (s, c) => { throw new Err(s, c); };

  function send(res, status, obj) {
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(JSON.stringify(obj));
  }

  async function readBody(req) {
    let n = 0; const ch = [];
    for await (const c of req) { n += c.length; if (n > 20000) fail(413, 'too_large'); ch.push(c); }
    if (!n) return {};
    let o;
    try { o = JSON.parse(Buffer.concat(ch).toString('utf8')); } catch (e) { fail(400, 'invalid'); }
    if (!o || typeof o !== 'object' || Array.isArray(o)) fail(400, 'invalid');
    return o;
  }

  const AR_DIGITS = '٠١٢٣٤٥٦٧٨٩';
  const toEn = s => String(s || '').replace(/[٠-٩]/g, d => AR_DIGITS.indexOf(d));
  const key9 = p => toEn(p).replace(/\D/g, '').replace(/^0+/, '').slice(-9);
  const cleanNid = v => toEn(v).replace(/[\s-]/g, '').toUpperCase();

  /* اسم العرض: الاسم الأول + الأخير */
  function displayName(a) {
    const parts = String(a.ar || a.en || '').trim().split(/\s+/).filter(Boolean);
    if (!parts.length) return 'مستخدم';
    return parts.length > 1 ? parts[0] + ' ' + parts[parts.length - 1] : parts[0];
  }

  const cleanText = (v, max) => {
    const t = String(v == null ? '' : v).replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim();
    if (!t || t.length > max) fail(400, 'invalid');
    return t;
  };

  /* تحديد معدل بسيط لكل مستخدم */
  const hits = new Map();
  function limited(key, max, win) {
    const now = Date.now();
    let h = hits.get(key);
    if (!h || now > h.t) { h = { n: 0, t: now + win }; hits.set(key, h); }
    h.n++;
    return h.n > max;
  }
  setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (n > v.t) hits.delete(k); }, 300000).unref();

  const findPost = id => data.posts.find(p => p.id === id) || fail(404, 'not_found');

  function view(p, uid) {
    return {
      id: p.id, name: p.name, t: p.t, text: p.text,
      likes: p.likes.length, liked: p.likes.includes(uid), mine: p.uid === uid,
      comments: p.comments.map(c => ({ name: c.name, text: c.text, t: c.t }))
    };
  }

  /* ---------- المعالج ---------- */
  return async function handle(req, res) {
    const url = new URL(req.url, 'http://x');
    const pn = url.pathname.replace(/\/+$/, '');
    if (!pn.startsWith('/api/social/') && pn !== '/api/social') return false;

    const m = req.method;
    let route = null, id = null;
    if (m === 'GET' && pn === '/api/social/me') route = 'me';
    else if (m === 'POST' && pn === '/api/social/join') route = 'join';
    else if (m === 'GET' && pn === '/api/social/posts') route = 'list';
    else if (m === 'POST' && pn === '/api/social/posts') route = 'post';
    else {
      const x = /^\/api\/social\/posts\/([A-Za-z0-9_-]{1,64})(?:\/(like|report|comment))?$/.exec(pn);
      if (x) {
        id = x[1];
        if (m === 'DELETE' && !x[2]) route = 'delete';
        else if (m === 'POST' && x[2]) route = x[2];
      }
    }
    if (!route) return false;

    try {
      const acc = getAccount(req);
      if (!acc) fail(401, 'expired');
      const uid = String(acc.id);

      if (route === 'me') return send(res, 200, { joined: !!data.joined[uid] }), true;

      if (route === 'join') {
        if (limited('sj:' + uid, 10, 60000)) fail(429, 'too_many');
        const b = await readBody(req);
        const v = toEn(String(b.id || '')).trim();
        if (!v || v.length > 254) fail(400, 'invalid');
        let ok = false;
        if (v.includes('@')) ok = v.toLowerCase() === String(acc.e || '').toLowerCase();
        else {
          ok = (!!acc.nid && cleanNid(v) === acc.nid) || (key9(v).length >= 7 && key9(v) === key9(acc.p));
        }
        if (!ok) fail(400, 'mismatch');
        data.joined[uid] = Date.now();
        save();
        return send(res, 200, { joined: true }), true;
      }

      /* كل ما بعد الانضمام يحتاج عضوية */
      if (!data.joined[uid]) fail(403, 'not_joined');

      if (route === 'list') {
        const list = data.posts
          .filter(p => p.reports.length < HIDE_AT_REPORTS || p.uid === uid)
          .slice(-MAX_POSTS_LISTED).reverse()
          .map(p => view(p, uid));
        return send(res, 200, { posts: list }), true;
      }

      if (route === 'post') {
        if (limited('sp:' + uid, 10, 60000)) fail(429, 'too_many');
        const b = await readBody(req);
        const text = cleanText(b.text, MAX_POST);
        const p = { id: crypto.randomBytes(9).toString('base64url'), uid, name: displayName(acc), t: Date.now(), text, likes: [], reports: [], comments: [] };
        data.posts.push(p);
        if (data.posts.length > MAX_POSTS_KEPT) data.posts.splice(0, data.posts.length - MAX_POSTS_KEPT);
        save();
        return send(res, 200, { post: view(p, uid) }), true;
      }

      const p = findPost(id);

      if (route === 'delete') {
        if (p.uid !== uid) fail(403, 'forbidden');
        data.posts.splice(data.posts.indexOf(p), 1);
        save();
        return send(res, 200, { ok: true }), true;
      }

      if (route === 'like') {
        if (limited('sl:' + uid, 60, 60000)) fail(429, 'too_many');
        const i = p.likes.indexOf(uid);
        if (i >= 0) p.likes.splice(i, 1); else p.likes.push(uid);
        save();
        return send(res, 200, { liked: i < 0, likes: p.likes.length }), true;
      }

      if (route === 'report') {
        if (limited('sr:' + uid, 20, 60000)) fail(429, 'too_many');
        if (!p.reports.includes(uid)) { p.reports.push(uid); save(); }
        return send(res, 200, { ok: true }), true;
      }

      if (route === 'comment') {
        if (limited('sc:' + uid, 20, 60000)) fail(429, 'too_many');
        const b = await readBody(req);
        const text = cleanText(b.text, MAX_COMMENT);
        if (p.comments.length >= MAX_COMMENTS) fail(400, 'invalid');
        p.comments.push({ uid, name: displayName(acc), text, t: Date.now() });
        save();
        return send(res, 200, { ok: true }), true;
      }

      return false;
    } catch (e) {
      if (e instanceof Err) return send(res, e.status, { error: e.code }), true;
      console.error('social error:', e);
      return send(res, 500, { error: 'server' }), true;
    }
  };
};
