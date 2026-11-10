// PBOX account sync for the plain-http Pbox-cloud server (no express needed).
// Every Google account only reads/writes its own file (looked up from its verified Google id).
const fs = require('fs'), path = require('path'), https = require('https'), crypto = require('crypto');
const waiters = new Map();                       // sub -> [functions waiting for a change]

function jget(url, headers) {
  return new Promise(function (resolve, reject) {
    const r = https.get(url, { headers: headers || {} }, function (res) {
      let b = '';
      res.on('data', function (c) { b += c; if (b.length > 16384) r.destroy(); });
      res.on('end', function () { try { resolve({ status: res.statusCode, json: JSON.parse(b) }); } catch (e) { reject(e); } });
    });
    r.on('error', reject);
    r.setTimeout(10000, function () { r.destroy(new Error('google timeout')); });
  });
}

// The page signs in with a Google ACCESS token (the server's own login only knew ID tokens).
async function verifyAccessToken(token, clientId) {
  const ti = await jget('https://oauth2.googleapis.com/tokeninfo?access_token=' + encodeURIComponent(token));
  if (ti.status !== 200) throw new Error('google rejected the token');
  if (clientId && ti.json.aud !== clientId && ti.json.azp !== clientId) throw new Error('token is for a different app');
  const ui = await jget('https://www.googleapis.com/oauth2/v3/userinfo', { Authorization: 'Bearer ' + token });
  if (ui.status !== 200 || !ui.json.sub || !ui.json.email || ui.json.email_verified === false) throw new Error('token has no user info');
  return { sub: ui.json.sub, email: String(ui.json.email).toLowerCase(), name: ui.json.name || '' };
}


// ---------- username + password accounts (works without Google) ----------
// Passwords are never stored: only a salted scrypt hash. Accounts look like  name@pbox.local  to the rest of the app.
const pwFails = new Map();                       // key -> { n, t }   (per IP and per username)
function pwLocked(k) { const f = pwFails.get(k); return !!f && f.n >= 8 && Date.now() - f.t < 600000; }
function pwFail(k) { const f = pwFails.get(k); if (!f || Date.now() - f.t >= 600000) pwFails.set(k, { n: 1, t: Date.now() }); else { f.n++; f.t = Date.now(); } }
const regLog = new Map();                        // ip -> [timestamps]
function regTooMany(ip) { const a = (regLog.get(ip) || []).filter(function (t) { return Date.now() - t < 3600000; }); regLog.set(ip, a); return a.length >= 5; }
function usersFile(dir) { return path.join(dir, 'users.json'); }
function loadUsers(dir) { try { const j = JSON.parse(fs.readFileSync(usersFile(dir), 'utf8')); return j && typeof j === 'object' ? j : {}; } catch (e) { return {}; } }
function saveUsers(dir, u) { const f = usersFile(dir), tmp = f + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(u)); fs.renameSync(tmp, f); }
function scrypt(pw, salt) { return new Promise(function (res, rej) { crypto.scrypt(pw, salt, 32, { N: 16384, r: 8, p: 1 }, function (e, k) { e ? rej(e) : res(k); }); }); }
function clientIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(); }

function handlePassword(req, res, p, ctx) {
  const send = ctx.send, J = JSON.stringify;
  ctx.readBody(req, 2048, function (body) {
    (async function () {
      let j; try { j = JSON.parse(body); } catch (e) { return send(res, 400, J({ error: 'bad JSON' })); }
      const name = String(j.username || '').trim().toLowerCase(), pw = String(j.password || '');
      if (!/^[a-z0-9_]{3,20}$/.test(name)) return send(res, 400, J({ error: 'badname' }));
      if (pw.length < 8 || pw.length > 128) return send(res, 400, J({ error: 'badpass' }));
      const ip = clientIp(req), kIp = 'ip:' + ip, kUser = 'u:' + name;
      if (pwLocked(kIp) || pwLocked(kUser)) return send(res, 429, J({ error: 'toomany' }));
      const users = loadUsers(ctx.dataDir);
      if (p === '/auth/register') {
        if (regTooMany(ip)) return send(res, 429, J({ error: 'toomany' }));
        if (users[name]) return send(res, 409, J({ error: 'exists' }));
        const salt = crypto.randomBytes(16);
        users[name] = { salt: salt.toString('hex'), hash: (await scrypt(pw, salt)).toString('hex'), created: Date.now() };
        try { saveUsers(ctx.dataDir, users); } catch (e) { return send(res, 500, J({ error: 'could not save' })); }
        (regLog.get(ip) || regLog.set(ip, []).get(ip)).push(Date.now());
      } else {
        const u = users[name];
        const salt = Buffer.from(u ? u.salt : crypto.randomBytes(16).toString('hex'), 'hex');   // same work whether or not the name exists
        const got = await scrypt(pw, salt), want = Buffer.from(u ? u.hash : '00'.repeat(32), 'hex');
        if (!u || got.length !== want.length || !crypto.timingSafeEqual(got, want)) { pwFail(kIp); pwFail(kUser); return send(res, 401, J({ error: 'wrong' })); }
      }
      const email = name + '@pbox.local';
      const session = ctx.makeSession('pw-' + name, email);
      send(res, 200, J({ ok: true, session: session, email: email, canControl: !!ctx.canControl({ email: email }) }));
    })().catch(function () { send(res, 500, J({ error: 'server error' })); });
  });
}

// Returns true when it handled the request.  ctx = { getSession, send, readBody, dataDir, makeSession, canControl }
function handle(req, res, u, p, ctx) {
  if (req.method === 'POST' && (p === '/auth/register' || p === '/auth/login')) { handlePassword(req, res, p, ctx); return true; }
  if (p.indexOf('/sync/') !== 0) return false;
  const send = ctx.send, J = JSON.stringify;
  if (req.method === 'GET' && p === '/sync/ping') { send(res, 200, J({ sync: true })); return true; }
  const s = ctx.getSession(req);
  if (!s) { send(res, 401, J({ error: 'not logged in' })); return true; }
  const key = String(s.sub).replace(/[^a-zA-Z0-9]/g, '_');
  const file = path.join(ctx.dataDir, 'sync-' + key + '.json');
  const load = function () { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return null; } };
  const rev = function () { const d = load(); return d ? d.rev : 0; };
  const wake = function () { (waiters.get(key) || []).splice(0).forEach(function (f) { f(); }); };

  if (req.method === 'GET' && p === '/sync/pull') { const d = load(); send(res, 200, J({ obj: d ? d.obj : null, rev: d ? d.rev : 0 })); return true; }

  if (req.method === 'GET' && p === '/sync/meta') {           // long poll: answers as soon as another device changes something
    const have = u.searchParams.get('rev') || '';
    if (u.searchParams.get('wait') !== '1' || have !== String(rev())) { send(res, 200, J({ rev: rev() })); return true; }
    let done = false;
    const fin = function () { if (done) return; done = true; send(res, 200, J({ rev: rev() })); };
    const list = waiters.get(key) || []; list.push(fin); waiters.set(key, list);
    const t = setTimeout(fin, 25000);
    req.on('close', function () { done = true; clearTimeout(t); });
    return true;
  }

  if (req.method === 'POST' && p === '/sync/push') {
    ctx.readBody(req, 5000000, function (body) {
      let j; try { j = JSON.parse(body); } catch (e) { return send(res, 400, J({ error: 'bad JSON' })); }
      const old = load(), r = Math.max((old ? old.rev : 0) + 1, Date.now());   // never repeats, even after a delete
      try { fs.writeFileSync(file, JSON.stringify({ rev: r, obj: j.obj || null })); } catch (e) { return send(res, 500, J({ error: 'could not save' })); }
      send(res, 200, J({ rev: r })); wake();
    });
    return true;
  }

  if (req.method === 'POST' && p === '/sync/delete') {
    try { fs.unlinkSync(file); } catch (e) {}
    send(res, 200, J({ ok: true })); wake(); return true;
  }
  send(res, 404, J({ error: 'not found' })); return true;
}
module.exports = { handle: handle, verifyAccessToken: verifyAccessToken };
