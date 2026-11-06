const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, 'data');
const FILE = path.join(DATA, 'reports.json');
fs.mkdirSync(DATA, { recursive: true });
let db = { total: 0, numbers: {}, recent: [] };
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
const save = () => fs.writeFile(FILE, JSON.stringify(db), () => {});

app.set('trust proxy', 1);
app.use(express.json({ limit: '5kb' }));
const pick = f => fs.existsSync(path.join(__dirname, 'public', f)) ? path.join(__dirname, 'public', f) : path.join(__dirname, f);
app.get('/', (_, res) => res.sendFile(pick('index.html')));

const hits = new Map();
const limit = (req, res, next) => {
  const now = Date.now(), k = req.ip;
  const arr = (hits.get(k) || []).filter(t => now - t < 60000);
  if (arr.length >= 10) return res.status(429).json({ error: 'Too many requests. Wait a minute.' });
  arr.push(now); hits.set(k, arr); next();
};
const clean = n => '+' + String(n || '').replace(/\D/g, '');
const valid = n => /^\+\d{7,15}$/.test(n);
const mask = n => n.slice(0, 5) + '*'.repeat(Math.max(n.length - 8, 2)) + n.slice(-3);
const TYPES = ['Fake investment / crypto', 'Romance scam', 'Impersonating someone', 'Fake job offer', 'Lottery / prize', 'Phishing link', 'Money request', 'Other'];

app.get('/api/config', (_, res) => res.json({
  email: process.env.SUPPORT_EMAIL || 'support@whatsapp.com',
  waNumber: (process.env.SUPPORT_WA_NUMBER || '').replace(/\D/g, ''),
  types: TYPES
}));

app.get('/api/stats', (_, res) => {
  const top = Object.entries(db.numbers).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([n, c]) => ({ number: mask(n), count: c }));
  res.json({ total: db.total, unique: Object.keys(db.numbers).length, top, recent: db.recent.slice(0, 6) });
});

app.get('/api/check', limit, (req, res) => {
  const n = clean(req.query.number);
  if (!valid(n)) return res.status(400).json({ error: 'Invalid number' });
  res.json({ count: db.numbers[n] || 0 });
});

app.post('/api/report', limit, (req, res) => {
  const n = clean(req.body.number);
  const type = TYPES.includes(req.body.type) ? req.body.type : 'Other';
  if (!valid(n)) return res.status(400).json({ error: 'Enter the number with country code, e.g. +263771234567' });
  db.numbers[n] = (db.numbers[n] || 0) + 1;
  db.total++;
  db.recent.unshift({ number: mask(n), type, at: Date.now() });
  db.recent = db.recent.slice(0, 20);
  save();
  res.json({ count: db.numbers[n] });
});

const crypto = require('crypto');
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const auth = (req, res, next) => {
  const k = String(req.get('x-admin-key') || '');
  const a = Buffer.from(k), b = Buffer.from(ADMIN_KEY);
  if (!ADMIN_KEY || a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Wrong key' });
  next();
};
app.get('/admin', (_, res) => res.sendFile(pick('admin.html')));
app.get('/api/admin/data', limit, auth, (_, res) => {
  const rows = Object.entries(db.numbers).sort((a, b) => b[1] - a[1]).map(([number, count]) => ({ number, count }));
  res.json({ total: db.total, rows, recent: db.recent });
});
app.delete('/api/admin/number', limit, auth, (req, res) => {
  const n = clean(req.query.number);
  if (db.numbers[n]) { db.total -= db.numbers[n]; delete db.numbers[n]; save(); }
  res.json({ ok: true });
});
app.get('/api/admin/export.csv', limit, auth, (_, res) => {
  res.type('text/csv').send('number,reports\n' + Object.entries(db.numbers).map(([n, c]) => n + ',' + c).join('\n'));
});

app.listen(PORT, () => console.log('Whitekid Wp Ban running on ' + PORT));
