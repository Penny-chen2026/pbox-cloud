// PBOX cloud API  -  a tiny state server, no npm packages needed (Node 18+).
//
//   ESP32      polls   GET  /status    -> plain text "open" or "close"
//              fast:   GET  /status?wait=1&last=<open|close>  -> waits (up to ~20 s) until the command CHANGES, then answers
//                      at once, so the servo reacts in well under a second (the sketch pbox_esp32.ino uses this)
//   Web page   sends   POST /command   -> {"cmd":"open"|"close","key":"..."} (needs the secret key)
//   Web page   reads   GET  /state     -> JSON: current command + whether the ESP32 polled recently
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

server.listen(PORT, function () {
  console.log('PBOX cloud API on port ' + PORT + (KEY ? '' : '  (WARNING: PBOX_KEY is not set - commands are refused)'));
});
