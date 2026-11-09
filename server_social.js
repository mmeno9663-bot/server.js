'use strict';
/*
 * منصة ALMARKA الاجتماعية — يُستدعى من server.js:
 *   require('./social-server')({ file, getAccount })
 * يرجع دالة (req,res) => true لو عالج الطلب، false لو لا.
 * التخزين: ملف JSON واحد (opts.file) بكتابة آمنة.
 */
const fs = require('node:fs');
const crypto = require('node:crypto');

module.exports = function ({ file, getAccount }) {
  const ORIGIN = process.env.ALLOWED_ORIGIN || '*';
  const MAX_POSTS = 500, FEED = 100, MAX_COMMENTS = 100;
  let db = { members: {}, posts: [] };
  try { db = Object.assign(db, JSON.parse(fs.readFileSync(file, 'utf8'))); } catch (e) { /* أول تشغيل */ }

  let timer = null;
  function save() {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      try { fs.writeFileSync(file + '.tmp', JSON.stringify(db)); fs.renameSync(file + '.tmp', file); }
      catch (e) { console.error('social save:', e.message); }
    }, 500);
  }

  class Err extends Error { constructor(s, c) { super(c); this.s = s; this.c = c; } }
  const send = (res, status, obj) => {
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': ORIGIN,
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(JSON.stringify(obj));
  };
  async function readBody(req) {
    let n = 0; const ch = [];
    for await (const c of req) { n += c.length; if (n > 10000) throw new Err(413, 'too_large'); ch.push(c); }
    if (!n) return {};
    try {
      const o = JSON.parse(Buffer.concat(ch).toString('utf8'));
      return o && typeof o === 'object' && !Array.isArray(o) ? o : {};
    } catch (e) { throw new Err(400, 'invalid'); }
  }

  const hits = new Map();
  const limited = (k, max, win) => {
    const now = Date.now();
    let h = hits.get(k);
    if (!h || now > h.t) { h = { n: 0, t: now + win }; hits.set(k, h); }
    return ++h.n > max;
  };
  setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (n > v.t) hits.delete(k); }, 300000).unref();

  const toEn = s => String(s || '').replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));
  const k9 = p => toEn(p).replace(/\D/g, '').replace(/^0+/, '').slice(-9);
  const nameOf = a => String(a.ar || a.en || 'طالب').split(' ').slice(0, 2).join(' ');
  const view = (p, uid) => ({
    id: p.id, name: p.name, t: p.t, text: p.text, likes: p.likes.length,
    liked: p.likes.includes(uid), mine: p.uid === uid,
    comments: p.comments.map(c => ({ name: c.name, text: c.text }))
  });

  return async function handle(req, res) {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname.replace(/\/+$/, '');
    if (!p.startsWith('/api/social')) return false;
    try {
      const acct = getAccount(req);
      if (!acct) throw new Err(401, 'expired');
      const uid = String(acct.id), m = req.method;

      if (m === 'GET' && p === '/api/social/me') {
        send(res, 200, { joined: !!db.members[uid] });
        return true;
      }
      if (m === 'POST' && p === '/api/social/join') {
        if (limited('j:' + uid, 10, 60000)) throw new Err(429, 'too_many');
        const b = await readBody(req), raw = toEn(b.id).trim();
        if (!raw || raw.length > 254) throw new Err(400, 'invalid');
        let ok;
        if (raw.includes('@')) ok = String(acct.e || '').toLowerCase() === raw.toLowerCase();
        else {
          const nid = raw.replace(/[\s-]/g, '').toUpperCase(), k = k9(raw);
          ok = (acct.nid && acct.nid === nid) || (k.length >= 7 && k9(acct.p) === k);
        }
        if (!ok) throw new Err(400, 'mismatch');
        db.members[uid] = Date.now(); save();
        send(res, 200, { ok: true });
        return true;
      }

      const r = /^\/api\/social\/posts(?:\/([^/]+)(?:\/(like|report|comment))?)?$/.exec(p);
      if (!r) throw new Err(404, 'not_found');
      if (!db.members[uid]) throw new Err(403, 'not_joined');
      const [, id, act] = r;

      if (!id) {
        if (m === 'GET') {
          send(res, 200, { posts: db.posts.slice(-FEED).reverse().map(x => view(x, uid)) });
          return true;
        }
        if (m === 'POST') {
          if (limited('p:' + uid, 8, 60000)) throw new Err(429, 'too_many');
          const text = String((await readBody(req)).text || '').trim().slice(0, 1500);
          if (!text) throw new Err(400, 'invalid');
          db.posts.push({ id: crypto.randomBytes(6).toString('hex'), uid, name: nameOf(acct), t: Date.now(),
            text, likes: [], reports: [], comments: [] });
          if (db.posts.length > MAX_POSTS) db.posts.splice(0, db.posts.length - MAX_POSTS);
          save(); send(res, 200, { ok: true });
          return true;
        }
        throw new Err(405, 'invalid');
      }

      const post = db.posts.find(x => x.id === id);
      if (!post) throw new Err(404, 'not_found');

      if (!act && m === 'DELETE') {
        if (post.uid !== uid) throw new Err(403, 'forbidden');
        db.posts.splice(db.posts.indexOf(post), 1); save();
        send(res, 200, { ok: true });
        return true;
      }
      if (m === 'POST' && act) {
        if (limited('a:' + uid, 30, 60000)) throw new Err(429, 'too_many');
        const b = await readBody(req);
        if (act === 'like') {
          const i = post.likes.indexOf(uid);
          if (i < 0) post.likes.push(uid); else post.likes.splice(i, 1);
        } else if (act === 'report') {
          if (!post.reports.includes(uid)) post.reports.push(uid);
        } else {
          const text = String(b.text || '').trim().slice(0, 500);
          if (!text) throw new Err(400, 'invalid');
          if (post.comments.length >= MAX_COMMENTS) throw new Err(400, 'invalid');
          post.comments.push({ uid, name: nameOf(acct), text, t: Date.now() });
        }
        save(); send(res, 200, { ok: true });
        return true;
      }
      throw new Err(405, 'invalid');
    } catch (e) {
      if (e instanceof Err) { send(res, e.s, { error: e.c }); return true; }
      console.error('social:', e);
      send(res, 500, { error: 'server' });
      return true;
    }
  };
};
