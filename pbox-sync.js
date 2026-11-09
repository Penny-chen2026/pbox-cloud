// PBOX account sync — add to your existing Render/Express server:
//   const pboxSync = require('./pbox-sync');  app.use(pboxSync({ googleClientId: 'YOUR_CLIENT_ID' }));
// Each Google account only ever reads/writes its own record (looked up from a verified Google email).
const express = require('express'), crypto = require('crypto'), fs = require('fs'), path = require('path');

module.exports = function pboxSync(opt) {
  const CLIENT_ID = opt.googleClientId;
  const DIR = opt.dataDir || process.env.PBOX_DATA_DIR || path.join(__dirname, 'pbox-data');   // use a persistent disk on Render
  fs.mkdirSync(DIR, { recursive: true });
  const r = express.Router();
  const sessions = new Map();                 // session token -> email
  const waiters = new Map();                  // email -> [functions waiting for a change]
  const h = (s) => crypto.createHash('sha256').update(s).digest('hex');
  const file = (email) => path.join(DIR, h(email) + '.json');
  const sessFile = path.join(DIR, '_sessions.json');
  try { Object.entries(JSON.parse(fs.readFileSync(sessFile, 'utf8'))).forEach(([k, v]) => sessions.set(k, v)); } catch (e) {}
  const saveSess = () => { try { fs.writeFileSync(sessFile, JSON.stringify(Object.fromEntries(sessions))); } catch (e) {} };
  const load = (email) => { try { return JSON.parse(fs.readFileSync(file(email), 'utf8')); } catch (e) { return null; } };
  const wake = (email) => { (waiters.get(email) || []).splice(0).forEach((f) => f()); };

  r.use((req, res, next) => {                 // the page may be hosted on another address
    res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' });
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });
  r.get('/sync/ping', (q, res) => res.json({ sync: true }));

  // Google sign-in: the page sends its Google access token once; we check it belongs to THIS app and give back a long-lived session.
  r.post('/auth/google', express.json({ limit: '10kb' }), async (req, res) => {
    try {
      const tok = String((req.body || {}).access_token || '');
      if (!tok) return res.sendStatus(400);
      const ti = await (await fetch('https://oauth2.googleapis.com/tokeninfo?access_token=' + encodeURIComponent(tok))).json();
      if (!ti || (ti.aud !== CLIENT_ID && ti.azp !== CLIENT_ID)) return res.sendStatus(401);
      const ui = await (await fetch('https://www.googleapis.com/oauth2/v3/userinfo', { headers: { Authorization: 'Bearer ' + tok } })).json();
      if (!ui || !ui.email || ui.email_verified === false) return res.sendStatus(401);
      const email = String(ui.email).toLowerCase(), session = crypto.randomBytes(32).toString('hex');
      sessions.set(session, email); saveSess();
      res.json({ session, email });
    } catch (e) { res.sendStatus(500); }
  });

  const auth = (req, res, next) => {
    const m = /^Bearer (.+)$/.exec(req.get('Authorization') || ''), email = m && sessions.get(m[1]);
    if (!email) return res.sendStatus(401);
    req.email = email; next();
  };
  r.get('/sync/pull', auth, (req, res) => { const d = load(req.email); res.json({ obj: d ? d.obj : null, rev: d ? d.rev : 0 }); });
  r.post('/sync/push', auth, express.json({ limit: '5mb' }), (req, res) => {
    const old = load(req.email), rev = Math.max((old ? old.rev : 0) + 1, Date.now());   // never repeats, even after a delete
    fs.writeFileSync(file(req.email), JSON.stringify({ rev, obj: (req.body || {}).obj || null }));
    res.json({ rev }); wake(req.email);
  });
  // Long poll: answers as soon as another device changes something (or after 25 s).
  r.get('/sync/meta', auth, (req, res) => {
    const cur = () => { const d = load(req.email); return d ? d.rev : 0; };
    const have = String(req.query.rev || '');
    if (!req.query.wait || have !== String(cur())) return res.json({ rev: cur() });
    let done = false;
    const fin = () => { if (done) return; done = true; res.json({ rev: cur() }); };
    const list = waiters.get(req.email) || []; list.push(fin); waiters.set(req.email, list);
    setTimeout(fin, 25000); req.on('close', () => { done = true; });
  });
  r.post('/sync/delete', auth, express.json(), (req, res) => { try { fs.unlinkSync(file(req.email)); } catch (e) {} res.json({ ok: true }); wake(req.email); });
  return r;
};
