// server.js
import express from 'express';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ── Database ──
const db = new Database('safarilink.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    business_type TEXT NOT NULL,
    company_name  TEXT NOT NULL,
    contact_name  TEXT NOT NULL,
    email         TEXT NOT NULL,
    phone         TEXT NOT NULL,
    region        TEXT NOT NULL,
    description   TEXT DEFAULT '',
    status        TEXT DEFAULT 'pending',
    created_at    TEXT DEFAULT (datetime('now')),
    reviewed_at   TEXT
  );

  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    company_name  TEXT,
    contact_name  TEXT,
    status        TEXT DEFAULT 'active',
    created_at    TEXT DEFAULT (datetime('now'))
  );
`);

// ── Admin auth ──
const ADMIN_TOKEN = 'safarilink-admin-2026';

function adminAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || auth !== `Bearer ${ADMIN_TOKEN}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ═══════════ PUBLIC ROUTES ═══════════

// Submit access request
app.post('/api/access-request', (req, res) => {
  const { businessType, companyName, contactName, email, phone, region, description } = req.body;

  if (!businessType || !companyName || !contactName || !email || !phone || !region) {
    return res.status(400).json({ error: 'All required fields must be filled.' });
  }

  const exists = db.prepare('SELECT id FROM access_requests WHERE email = ?').get(email);
  if (exists) {
    return res.status(409).json({ error: 'A request with this email already exists.' });
  }

  const result = db.prepare(`
    INSERT INTO access_requests (business_type, company_name, contact_name, email, phone, region, description)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(businessType, companyName, contactName, email, phone, region, description || '');

  res.json({ success: true, id: result.lastInsertRowid });
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password, role } = req.body;

  const user = db.prepare('SELECT * FROM users WHERE email = ? AND role = ?').get(email, role);
  if (!user) {
    return res.status(401).json({ error: 'Invalid email, password, or role.' });
  }
  if (user.status !== 'active') {
    return res.status(403).json({ error: 'Account inactive. Contact support.' });
  }

  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid email, password, or role.' });
  }

  // Return role → frontend redirects
  res.json({ success: true, role: user.role, companyName: user.company_name });
});

// ═══════════ ADMIN ROUTES ═══════════

// List all requests
app.get('/api/admin/access-requests', adminAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM access_requests ORDER BY created_at DESC').all();
  res.json(rows);
});

// Approve
app.post('/api/admin/approve/:id', adminAuth, (req, res) => {
  const r = db.prepare('SELECT * FROM access_requests WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Request not found' });
  if (r.status !== 'pending') return res.status(400).json({ error: 'Already processed' });

  const tempPwd = crypto.randomBytes(6).toString('hex');
  const hash = bcrypt.hashSync(tempPwd, 10);

  db.prepare(`
    INSERT INTO users (email, password_hash, role, company_name, contact_name)
    VALUES (?, ?, ?, ?, ?)
  `).run(r.email, hash, r.business_type, r.company_name, r.contact_name);

  db.prepare(`UPDATE access_requests SET status='approved',
    reviewed_at=datetime('now') WHERE id=?`).run(r.id);

  res.json({ success: true, email: r.email, tempPassword: tempPwd });
});

// Reject
app.post('/api/admin/reject/:id', adminAuth, (req, res) => {
  const r = db.prepare('SELECT id FROM access_requests WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Not found' });

  db.prepare(`UPDATE access_requests SET status='rejected',
    reviewed_at=datetime('now') WHERE id=?`).run(r.id);

  res.json({ success: true });
});

// Stats for admin dashboard
app.get('/api/admin/stats', adminAuth, (req, res) => {
  const pending  = db.prepare(`SELECT COUNT(*) as c FROM access_requests WHERE status='pending'`).get();
  const approved = db.prepare(`SELECT COUNT(*) as c FROM access_requests WHERE status='approved'`).get();
  const totalUsers = db.prepare(`SELECT COUNT(*) as c FROM users`).get();
  res.json({ pending: pending.c, approved: approved.c, totalUsers: totalUsers.c });
});

// ── Start ──
app.listen(PORT, () => {
  console.log(`SafariLink server → http://localhost:${PORT}`);
  console.log(`Admin panel     → http://localhost:${PORT}/admin.html`);
});
