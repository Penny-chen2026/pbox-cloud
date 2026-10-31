// PBOX cloud API  -  a tiny state server, no npm packages needed (Node 18+).
//
//   ESP32      polls   GET  /status    -> plain text "open" or "close"
//              fast:   GET  /status?wait=1&last=<open|close>  -> waits (up to ~20 s) until the command CHANGES, then answers
//                      at once, so the servo reacts in well under a second (the sketch pbox_esp32.ino uses this)
//   Web page   sends   POST /command   -> {"cmd":"open"|"close","key":"..."} (needs the secret key)
//   Web page   reads   GET  /state     -> JSON: current command + whether the ESP32 polled recently
//   Raspberry Pi camera (optional) - LIVE VIDEO from any network. The Pi only makes an OUTGOING connection:
//              WebSocket  wss://<server>/ws/camera
//              Pi    first sends {"role":"camera","key":"..."}  then one JPEG per message, only while a page is watching
//              page  first sends {"role":"viewer","key":"..."}  and receives every JPEG the moment it arrives
//              The server only passes the frames on. Nothing is stored. No extra npm packages are needed.
//
// Set the secret key as an environment variable before starting:
//   PBOX_KEY=my-long-secret node server.js
// Without PBOX_KEY the server refuses every command, so nobody can open the box by accident.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const KEY = process.env.PBOX_KEY || '';
const STATE_FILE = process.env.STATE_FILE || path.join(__dirname, 'state.json');
const ONLINE_MS = 10000;                      // >10 s without any request from the ESP32 (and none waiting) = offline
const LONGPOLL_MS = Number(process.env.LONGPOLL_MS) || 20000;   // how long a waiting request is held

let state = { cmd: 'close', updatedAt: Date.now() };
let deviceLastSeen = 0;
const waiters = new Set();                    // ESP32 requests that are waiting for the next change
const viewers = new Set();                    // pages watching the live camera
let cam = null;                               // the connected Pi camera (WebSocket)
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const WS_MAX = 2000000;                       // biggest WebSocket message we accept (one JPEG is ~30 KB)
try {
  const j = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  if (j && (j.cmd === 'open' || j.cmd === 'close')) state = { cmd: j.cmd, updatedAt: j.updatedAt || Date.now() };
} catch (e) { /* first start: no file yet */ }
function saveState() { try { fs.writeFileSync(STATE_FILE, JSON.stringify(state)); } catch (e) { /* read-only disk is fine */ } }

// very small brute-force guard: 10 wrong keys per 10 minutes per address
const fails = new Map();
function clientIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(); }
function tooManyFails(ip) { const f = fails.get(ip); return f && f.n >= 10 && Date.now() - f.t < 600000; }
function noteFail(ip) { const f = fails.get(ip); if (!f || Date.now() - f.t >= 600000) fails.set(ip, { n: 1, t: Date.now() }); else f.n++; }
function sameKey(a, b) { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }

function release(w) {                         // answer one waiting request with the current command
  if (!waiters.has(w)) return;
  waiters.delete(w); clearTimeout(w.timer);
  deviceLastSeen = Date.now();
  send(w.res, 200, state.cmd, 'text/plain');
}

function send(res, code, body, type) {
  res.writeHead(code, {
    'Content-Type': type || 'application/json',
    'Access-Control-Allow-Origin': '*',            // lets the PBOX page (opened from a file or any site) talk to this API
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

// ---------- minimal WebSocket (RFC 6455), no packages ----------
function wsSend(socket, opcode, payload) {
  const len = payload.length; let header;
  if (len < 126) header = Buffer.from([0x80 | opcode, len]);
  else if (len < 65536) { header = Buffer.alloc(4); header[0] = 0x80 | opcode; header[1] = 126; header.writeUInt16BE(len, 2); }
  else { header = Buffer.alloc(10); header[0] = 0x80 | opcode; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2); }
  socket.write(header); if (len) socket.write(payload);
}
function wsJson(socket, obj) { try { wsSend(socket, 1, Buffer.from(JSON.stringify(obj))); } catch (e) { /* closed */ } }
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
      if (len > WS_MAX || !masked) return socket.destroy();          // clients must mask their frames
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

const server = http.createServer(function (req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname;

  if (req.method === 'OPTIONS') return send(res, 204, '');

  // ESP32 polling: the answer is ONLY the word open / close
  if (req.method === 'GET' && p === '/status') {
    deviceLastSeen = Date.now();
    const last = u.searchParams.get('last');
    if (u.searchParams.get('wait') === '1' && (last === 'open' || last === 'close') && last === state.cmd) {
      // nothing new yet: hold the request until the command changes (or the time is up)
      const w = { res: res };
      w.timer = setTimeout(function () { release(w); }, LONGPOLL_MS);
      waiters.add(w);
      req.on('close', function () { clearTimeout(w.timer); waiters.delete(w); });
      return;
    }
    return send(res, 200, state.cmd, 'text/plain');
  }

  // web page: current command + is the ESP32 alive?
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

  // web page: change the command (secret key required)
  if (req.method === 'POST' && p === '/command') {
    const ip = clientIp(req);
    let body = '';
    req.on('data', function (c) { body += c; if (body.length > 2048) req.destroy(); });
    req.on('end', function () {
      if (!KEY) return send(res, 503, JSON.stringify({ error: 'PBOX_KEY is not set on the server' }));
      if (tooManyFails(ip)) return send(res, 429, JSON.stringify({ error: 'too many wrong keys, try again later' }));
      let j = {};
      try { j = JSON.parse(body); } catch (e) { return send(res, 400, JSON.stringify({ error: 'bad JSON' })); }
      if (!sameKey(j.key || '', KEY)) { noteFail(ip); return send(res, 401, JSON.stringify({ error: 'wrong key' })); }
      if (j.cmd !== 'open' && j.cmd !== 'close') return send(res, 400, JSON.stringify({ error: 'cmd must be open or close' }));
      const changed = state.cmd !== j.cmd;
      state = { cmd: j.cmd, updatedAt: Date.now() };
      saveState();
      if (changed) Array.from(waiters).forEach(release);   // wake the ESP32 right now
      console.log(new Date().toISOString(), 'command ->', state.cmd);
      return send(res, 200, JSON.stringify({ ok: true, cmd: state.cmd, updatedAt: state.updatedAt }));
    });
    return;
  }

  if (req.method === 'GET' && p === '/') return send(res, 200, 'PBOX cloud API is running', 'text/plain');
  send(res, 404, 'not found', 'text/plain');
});

// ---------- live camera over WebSocket ----------
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
  const pinger = setInterval(function () { try { wsSend(socket, 9, Buffer.alloc(0)); } catch (e) {} }, 25000);   // keeps proxies from closing an idle connection
  let closed = false;
  function cleanup() {
    if (closed) return; closed = true; clearTimeout(authTimer); clearInterval(pinger);
    if (me.role === 'camera' && cam === me) cam = null;
    if (me.role === 'viewer') { viewers.delete(me); notifyWant(); }
  }
  socket.on('close', cleanup); socket.on('error', function () {});
  wsParser(socket, function (op, payload) {
    if (!me.role) {                                   // the first message must be {"role":..., "key":...}
      let j; if (op !== 1) return socket.destroy();
      try { j = JSON.parse(payload.toString()); } catch (e) { return socket.destroy(); }
      if (tooManyFails(ip)) { wsJson(socket, { error: 'too many wrong keys, try again later' }); return socket.end(); }
      if (!KEY || !sameKey(j.key || '', KEY)) { noteFail(ip); wsJson(socket, { error: KEY ? 'wrong key' : 'PBOX_KEY is not set on the server' }); return socket.end(); }
      if (j.role === 'camera') {
        if (cam && cam !== me) { try { cam.socket.destroy(); } catch (e) {} }
        cam = me; me.role = 'camera';
        wsJson(socket, { ok: true, want: viewers.size > 0 });
      } else if (j.role === 'viewer') {
        me.role = 'viewer'; viewers.add(me);
        wsJson(socket, { ok: true, camera: !!cam });
        notifyWant();
      } else return socket.destroy();
      return;
    }
    if (me.role === 'camera' && op === 2 && payload.length > 3 && payload[0] === 0xFF && payload[1] === 0xD8) {
      viewers.forEach(function (v) { if (v.socket.writableLength < 400000) wsSend(v.socket, 2, payload); });   // skip frames for a slow viewer
    }
  }, cleanup);
});

server.listen(PORT, function () {
  console.log('PBOX cloud API on port ' + PORT + (KEY ? '' : '  (WARNING: PBOX_KEY is not set - commands are refused)'));
});
