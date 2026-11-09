// PBOX cloud API  -  a tiny state server, no npm packages needed (Node 18+).
//
//   ESP32      polls   GET  /status    -> plain text "open" or "close"
//              fast:   GET  /status?wait=1&last=<open|close>  -> waits (up to ~20 s) until the command CHANGES, then answers
//   Web page   sends   POST /command   -> {"cmd":"open"|"close"}  (auth: session of an allowed email, or the secret key)
//   Web page   reads   GET  /state     -> JSON: current command + whether the ESP32 polled recently
//
//   ACCOUNT SYNC:
//     POST /auth/google   {"idToken":"..."}  -> verifies the Google sign-in once, returns a long-lived session token
//     POST /auth/logout   (Authorization: Bearer ...)  -> deletes that session
//     GET  /account       -> {"ok":true,"data":{...},"updatedAt":...}   your saved page data
//     PUT  /account       {"data":{...}}  -> saves your page data (max ~500 KB)
//     DELETE /account     -> wipes the cloud copy AND the session (used by "delete account")
//
//   Raspberry Pi camera:  WebSocket  wss://<server>/ws/camera
//              Pi    first sends {"role":"camera","key":"..."}  then one JPEG per message
//              page  first sends {"role":"viewer","session":"..."}  (or {"role":"viewer","key":"..."})  and receives JPEGs live

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const pboxSync = require('./pbox-sync');

const PORT = process.env.PORT || 3000;
const KEY = process.env.PBOX_KEY || '';
const CLIENT_ID = process.env.PBOX_CLIENT_ID || '';
const ALLOWED = (process.env.PBOX_ALLOWED_EMAILS || '').split(',').map(function (s) { return s.trim().toLowerCase(); }).filter(Boolean);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const STATE_FILE = process.env.STATE_FILE || path.join(DATA_DIR, 'state.json');
const SESSION_FILE = path.join(DATA_DIR, 'sessions.json');
const SESSION_DAYS = Number(process.env.PBOX_SESSION_DAYS) || 365;
const MAX_ACCOUNT_BYTES = 500000;
const ONLINE_MS = 10000;
const LONGPOLL_MS = Number(process.env.LONGPOLL_MS) || 20000;

try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) { console.log('DATA_DIR not writable:', e.message); }

let state = { cmd: 'close', updatedAt: Date.now() };
let deviceLastSeen = 0;
const waiters = new Set();
const viewers = new Set();
let cam = null;
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const WS_MAX = 2000000;

try {
  const j = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  if (j && (j.cmd === 'open' || j.cmd === 'close')) state = { cmd: j.cmd, updatedAt: j.updatedAt || Date.now() };
} catch (e) {}
function saveState() { try { fs.writeFileSync(STATE_FILE, JSON.stringify(state)); } catch (e) {} }

const sessions = new Map();
try {
  const j = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
  if (j && typeof j === 'object') Object.keys(j).forEach(function (t) {
    const s = j[t];
    if (s && s.sub && s.email && Date.now() - (s.lastSeen || 0) < SESSION_DAYS * 86400000) sessions.set(t, s);
  });
} catch (e) {}
function saveSessions() { try { const o = {}; sessions.forEach(function (s, t) { o[t] = s; }); fs.writeFileSync(SESSION_FILE, JSON.stringify(o)); } catch (e) {} }
setInterval(function () {
  const cutoff = Date.now() - SESSION_DAYS * 86400000;
  let changed = false;
  sessions.forEach(function (s, t) { if ((s.lastSeen || 0) < cutoff) { sessions.delete(t); changed = true; } });
  if (changed) saveSessions();
}, 3600000).unref();

function getSession(req) {
  const m = String(req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const s = sessions.get(m[1].trim());
  if (!s) return null;
  s.lastSeen = Date.now();
  return s;
}

function canControl(sess) {
  if (!sess) return false;
  if (ALLOWED.length === 0) return true;
  return ALLOWED.indexOf(String(sess.email).toLowerCase()) >= 0;
}

function verifyGoogleToken(idToken) {
  return new Promise(function (resolve, reject) {
    const req = https.get('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken), function (res) {
      let body = '';
      res.on('data', function (c) { body += c; if (body.length > 8192) req.destroy(); });
      res.on('end', function () {
        if (res.statusCode !== 200) return reject(new Error('google rejected the token (' + res.statusCode + ')'));
        try {
          const j = JSON.parse(body);
          if (CLIENT_ID && j.aud !== CLIENT_ID) return reject(new Error('token is for a different app (aud mismatch)'));
          if (Number(j.exp) * 1000 < Date.now()) return reject(new Error('token expired'));
          if (!j.sub || !j.email) return reject(new Error('token has no user info'));
          resolve({ sub: j.sub, email: String(j.email).toLowerCase(), name: j.name || '' });
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, function () { req.destroy(new Error('google timeout')); });
  });
}

const fails = new Map();
function clientIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(); }
function tooManyFails(ip) { const f = fails.get(ip); return f && f.n >= 10 && Date.now() - f.t < 600000; }
function noteFail(ip) { const f = fails.get(ip); if (!f || Date.now() - f.t >= 600000) fails.set(ip, { n: 1, t: Date.now() }); else f.n++; }
function sameKey(a, b) { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }

function release(w) {
  if (!waiters.has(w)) return;
  waiters.delete(w); clearTimeout(w.timer);
  deviceLastSeen = Date.now();
  send(w.res, 200, state.cmd, 'text/plain');
}

function send(res, code, body, type) {
  res.writeHead(code, {
    'Content-Type': type || 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function readBody(req, limit, cb) {
  let body = '';
  req.on('data', function (c) { body += c; if (body.length > limit) req.destroy(); });
  req.on('end', function () { cb(body); });
}

function wsSend(socket, opcode, payload) {
  const len = payload.length; let header;
  if (len < 126) header = Buffer.from([0x80 | opcode, len]);
  else if (len < 65536) { header = Buffer.alloc(4); header[0] = 0x80 | opcode; header[1] = 126; header.writeUInt16BE(len, 2); }
  else { header = Buffer.alloc(10); header[0] = 0x80 | opcode; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2); }
  socket.write(header); if (len) socket.write(payload);
}
function wsJson(socket, obj) { try { wsSend(socket, 1, Buffer.from(JSON.stringify(obj))); } catch (e) {} }
function wsParser(socket, onMessage, onClose) {
  let buf = Buffer.alloc(0), frags = [], fragOp = 0, fragSize = 0;
  socket.on('data', function (chunk) {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length < 2) return;
      const b0 = buf[0], b1 = buf[1], fin = !!(b0 & 0x80), op = b0 & 0x0f, masked = !!(b1 & 0x80);
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; const big = buf.readBigUInt64BE(2); if (big > BigInt(WS_MAX)) return socket.destroy(); len = Number(big); off = 10; }
      if (len > WS_MAX || !masked) return socket.destroy();
      if (buf.length < off + 4 + len) return;
      const mask = buf.subarray(off, off + 4), payload = Buffer.from(buf.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < len; i++) payload[i] ^= mask[i & 3];
      buf = buf.subarray(off + 4 + len);
      if (op === 8) { onClose(); try { wsSend(socket, 8, Buffer.alloc(0)); } catch (e) {} socket.end(); return; }
      if (op === 9) { try { wsSend(socket, 10, payload); } catch (e) {} continue; }
      if (op === 10) continue;
      if (op === 0) {
        fragSize += payload.length; if (fragSize > WS_MAX) return socket.destroy();
        frags.push(payload); if (fin) { const m = Buffer.concat(frags); frags = []; fragSize = 0; onMessage(fragOp, m); }
        continue;
      }
      if (!fin) { fragOp = op; frags = [payload]; fragSize = payload.length; continue; }
      onMessage(op, payload);
    }
  });
}
function notifyWant() { if (cam) wsJson(cam.socket, { want: viewers.size > 0 }); }

function accountFile(sub) { return path.join(DATA_DIR, 'account-' + sub.replace(/[^a-zA-Z0-9]/g, '_') + '.json'); }

const server = http.createServer(function (req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname;

  if (req.method === 'OPTIONS') return send(res, 204, '');
  
  if (pboxSync.handle(req, res, u, p, { getSession: getSession, send: send, readBody: readBody, dataDir: DATA_DIR })) return;

  if (req.method === 'GET' && p === '/status') {
    deviceLastSeen = Date.now();
    const last = u.searchParams.get('last');
    if (u.searchParams.get('wait') === '1' && (last === 'open' || last === 'close') && last === state.cmd) {
      const w = { res: res };
      w.timer = setTimeout(function () { release(w); }, LONGPOLL_MS);
      waiters.add(w);
      req.on('close', function () { clearTimeout(w.timer); waiters.delete(w); });
      return;
    }
    return send(res, 200, state.cmd, 'text/plain');
  }

  if (req.method === 'GET' && p === '/state') {
    const now = Date.now();
    return send(res, 200, JSON.stringify({
      cmd: state.cmd, updatedAt: state.updatedAt,
      deviceLastSeen: deviceLastSeen || null,
      deviceOnline: waiters.size > 0 || (deviceLastSeen > 0 && now - deviceLastSeen < ONLINE_MS),
      cameraOnline: !!cam,
      serverTime: now
    }));
  }

  if (req.method === 'POST' && p === '/auth/google') {
    return readBody(req, 8192, function (body) {
      let j = {};
      try { j = JSON.parse(body); } catch (e) { return send(res, 400, JSON.stringify({ error: 'bad JSON' })); }
      if (!CLIENT_ID) return send(res, 503, JSON.stringify({ error: 'PBOX_CLIENT_ID is not set on the server' }));
      if (!j.access_token && (!j.idToken || typeof j.idToken !== 'string' || j.idToken.length > 4096)) return send(res, 400, JSON.stringify({ error: 'token missing' }));
   (j.access_token ? pboxSync.verifyAccessToken(String(j.access_token), CLIENT_ID) : verifyGoogleToken(j.idToken)).then(function (g) {
        const token = crypto.randomBytes(24).toString('base64url');
        sessions.set(token, { sub: g.sub, email: g.email, createdAt: Date.now(), lastSeen: Date.now() });
        saveSessions();
        console.log(new Date().toISOString(), 'login ->', g.email);
        return send(res, 200, JSON.stringify({ ok: true, session: token, email: g.email, canControl: canControl(sessions.get(token)) }));
      }).catch(function (e) {
        return send(res, 401, JSON.stringify({ error: 'google login failed: ' + e.message }));
      });
    });
  }

  if (req.method === 'POST' && p === '/auth/logout') {
    const s = getSession(req);
    if (s) {
      sessions.forEach(function (v, t) { if (v === s) sessions.delete(t); });
      saveSessions();
    }
    return send(res, 200, JSON.stringify({ ok: true }));
  }

  if ((p === '/account' || p === '/account/') && req.method === 'GET') {
    const s = getSession(req);
    if (!s) return send(res, 401, JSON.stringify({ error: 'not logged in' }));
    let saved = null;
    try { saved = JSON.parse(fs.readFileSync(accountFile(s.sub), 'utf8')); } catch (e) {}
    return send(res, 200, JSON.stringify({ ok: true, data: saved ? saved.data : null, updatedAt: saved ? saved.updatedAt : null, email: s.email }));
  }

  if ((p === '/account' || p === '/account/') && req.method === 'PUT') {
    const s = getSession(req);
    if (!s) return send(res, 401, JSON.stringify({ error: 'not logged in' }));
    return readBody(req, MAX_ACCOUNT_BYTES, function (body) {
      if (body.length > MAX_ACCOUNT_BYTES) return send(res, 413, JSON.stringify({ error: 'data too large (max 500 KB)' }));
      let data = null;
      try { data = JSON.parse(body); } catch (e) { return send(res, 400, JSON.stringify({ error: 'bad JSON' })); }
      try {
        fs.writeFileSync(accountFile(s.sub), JSON.stringify({ data: data, updatedAt: Date.now() }));
      } catch (e) { return send(res, 500, JSON.stringify({ error: 'could not save' })); }
      return send(res, 200, JSON.stringify({ ok: true, updatedAt: Date.now() }));
    });
  }

  if ((p === '/account' || p === '/account/') && req.method === 'DELETE') {
    const s = getSession(req);
    if (!s) return send(res, 401, JSON.stringify({ error: 'not logged in' }));
    try { fs.unlinkSync(accountFile(s.sub)); } catch (e) {}
    sessions.forEach(function (v, t) { if (v === s) sessions.delete(t); });
    saveSessions();
    console.log(new Date().toISOString(), 'account deleted ->', s.email);
    return send(res, 200, JSON.stringify({ ok: true }));
  }

  if (req.method === 'POST' && p === '/command') {
    const ip = clientIp(req);
    return readBody(req, 2048, function (body) {
      if (tooManyFails(ip)) return send(res, 429, JSON.stringify({ error: 'too many wrong keys' }));
      let j = {};
      try { j = JSON.parse(body); } catch (e) { return send(res, 400, JSON.stringify({ error: 'bad JSON' })); }
      const sess = getSession(req);
      const bySession = canControl(sess);
      let byKey = false;
      if (!bySession && KEY && j.key) {
        if (sameKey(j.key, KEY)) byKey = true; else noteFail(ip);
      }
      if (!bySession && !byKey) {
        return send(res, 401, JSON.stringify({ error: 'not allowed to control' }));
      }
      if (j.cmd !== 'open' && j.cmd !== 'close') return send(res, 400, JSON.stringify({ error: 'cmd must be open or close' }));
      const changed = state.cmd !== j.cmd;
      state = { cmd: j.cmd, updatedAt: Date.now() };
      saveState();
      if (changed) Array.from(waiters).forEach(release);
      console.log(new Date().toISOString(), 'command ->', state.cmd, bySession ? '(' + sess.email + ')' : '(key)');
      return send(res, 200, JSON.stringify({ ok: true, cmd: state.cmd, updatedAt: state.updatedAt }));
    });
  }

  if (req.method === 'GET' && p === '/') return send(res, 200, 'PBOX cloud API is running', 'text/plain');
  send(res, 404, 'not found', 'text/plain');
});

server.on('upgrade', function (req, socket) {
  const p = new URL(req.url, 'http://x').pathname;
  if (p !== '/ws/camera' || String(req.headers.upgrade).toLowerCase() !== 'websocket' || !req.headers['sec-websocket-key']) {
    socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n'); return socket.destroy();
  }
  const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + WS_GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);
  const ip = clientIp(req), me = { socket: socket, role: null };
  const authTimer = setTimeout(function () { if (!me.role) socket.destroy(); }, 5000);
  const pinger = setInterval(function () { try { wsSend(socket, 9, Buffer.alloc(0)); } catch (e) {} }, 25000);
  let closed = false;
  function cleanup() {
    if (closed) return; closed = true; clearTimeout(authTimer); clearInterval(pinger);
    if (me.role === 'camera' && cam === me) cam = null;
    if (me.role === 'viewer') { viewers.delete(me); notifyWant(); }
  }
  socket.on('close', cleanup); socket.on('error', function () {});
  wsParser(socket, function (op, payload) {
    if (!me.role) {
      let j; if (op !== 1) return socket.destroy();
      try { j = JSON.parse(payload.toString()); } catch (e) { return socket.destroy(); }
      if (tooManyFails(ip)) { wsJson(socket, { error: 'too many wrong keys' }); return socket.end(); }
      if (j.role === 'camera') {
        if (!KEY || !sameKey(j.key || '', KEY)) { noteFail(ip); wsJson(socket, { error: 'wrong key' }); return socket.end(); }
        if (cam && cam !== me) { try { cam.socket.destroy(); } catch (e) {} }
        cam = me; me.role = 'camera';
        wsJson(socket, { ok: true, want: viewers.size > 0 });
      } else if (j.role === 'viewer') {
        let ok = false, sess = null;
        if (j.session) { sess = sessions.get(String(j.session)) || null; ok = canControl(sess); }
        if (!ok && KEY && j.key && sameKey(j.key, KEY)) ok = true;
        if (!ok) { noteFail(ip); wsJson(socket, { error: 'not allowed' }); return socket.end(); }
        me.role = 'viewer'; me.email = sess ? sess.email : null; viewers.add(me);
        wsJson(socket, { ok: true, camera: !!cam });
        notifyWant();
      } else return socket.destroy();
      return;
    }
    if (me.role === 'camera' && op === 2 && payload.length > 3 && payload[0] === 0xFF && payload[1] === 0xD8) {
      viewers.forEach(function (v) { if (v.socket.writableLength < 400000) wsSend(v.socket, 2, payload); });
    }
  }, cleanup);
});

server.listen(PORT, function () {
  console.log('PBOX cloud API on port ' + PORT);
  console.log('  allowed emails : ' + (ALLOWED.length ? ALLOWED.join(', ') : '(none - open to all Google accounts)'));
  console.log('  google client  : ' + (CLIENT_ID ? 'set' : 'NOT SET'));
});
