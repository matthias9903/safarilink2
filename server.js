// server.js — SafariLink backend (fixed for hosting)
// Works on Railway / Render / any Node host with a disk for SQLite

import express from 'express';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// Secrets — set these in Railway/Render dashboard (Variables)
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'safarilink-admin-2026';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'safarilink-admin-2026';

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ── Database (file stays on disk so data survives restarts) ──
const dbPath = process.env.DB_PATH || path.join(__dirname, 'data', 'safarilink.db');
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(dbPath);
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
    must_change_password INTEGER DEFAULT 0,
    created_at    TEXT DEFAULT (datetime('now'))
  );
`);

// Add column if upgrading an old DB
try {
  db.exec(`ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0`);
} catch (_) { /* already exists */ }

function adminAuth(req, res, next) {
  const auth = (req.headers.authorization || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth;
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ═══════════ PUBLIC ═══════════

// Request access (from request-access.html)
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

// Partner login (from login.html)
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

  res.json({
    success: true,
    role: user.role,
    companyName: user.company_name,
    contactName: user.contact_name,
    email: user.email,
    mustChangePassword: !!user.must_change_password
  });
});

// Change password (partner after first login with temp password)
app.post('/api/change-password', (req, res) => {
  const { email, currentPassword, newPassword } = req.body;

  if (!email || !currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Email, current password and new password are required.' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) {
    return res.status(401).json({ error: 'User not found.' });
  }

  const valid = bcrypt.compareSync(currentPassword, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Current password is incorrect.' });
  }

  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare(`
    UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?
  `).run(hash, user.id);

  res.json({ success: true, message: 'Password updated. You can continue.' });
});

// ═══════════ ADMIN ═══════════

// Admin login (admin.html)
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    return res.json({ token: ADMIN_TOKEN });
  }
  res.status(401).json({ error: 'Invalid password' });
});

// List access requests (admin.html)
app.get('/api/admin/requests', adminAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM access_requests ORDER BY created_at DESC').all();
  res.json(rows);
});

// Alias for older code
app.get('/api/admin/access-requests', adminAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM access_requests ORDER BY created_at DESC').all();
  res.json(rows);
});

// Approve → creates user with temporary password
app.post('/api/admin/approve/:id', adminAuth, (req, res) => {
  const r = db.prepare('SELECT * FROM access_requests WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Request not found' });
  if (r.status !== 'pending') return res.status(400).json({ error: 'Already processed' });

  const tempPwd = crypto.randomBytes(4).toString('hex'); // 8-char temp password
  const hash = bcrypt.hashSync(tempPwd, 10);

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(r.email);
  if (!existing) {
    db.prepare(`
      INSERT INTO users (email, password_hash, role, company_name, contact_name, must_change_password)
      VALUES (?, ?, ?, ?, ?, 1)
    `).run(r.email, hash, r.business_type, r.company_name, r.contact_name);
  } else {
    // Reactivate / reset password if they already had an account
    db.prepare(`
      UPDATE users SET password_hash = ?, role = ?, company_name = ?, contact_name = ?,
        status = 'active', must_change_password = 1 WHERE email = ?
    `).run(hash, r.business_type, r.company_name, r.contact_name, r.email);
  }

  db.prepare(`
    UPDATE access_requests SET status = 'approved', reviewed_at = datetime('now') WHERE id = ?
  `).run(r.id);

  res.json({
    success: true,
    email: r.email,
    tempPassword: tempPwd,
    role: r.business_type,
    note: 'Send this temporary password to the user. They must change it on first login.'
  });
});

// Reject
app.post('/api/admin/reject/:id', adminAuth, (req, res) => {
  const r = db.prepare('SELECT id FROM access_requests WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Not found' });

  db.prepare(`
    UPDATE access_requests SET status = 'rejected', reviewed_at = datetime('now') WHERE id = ?
  `).run(r.id);

  res.json({ success: true });
});

// Stats
app.get('/api/admin/stats', adminAuth, (req, res) => {
  const pending = db.prepare(`SELECT COUNT(*) as c FROM access_requests WHERE status = 'pending'`).get();
  const approved = db.prepare(`SELECT COUNT(*) as c FROM access_requests WHERE status = 'approved'`).get();
  const totalUsers = db.prepare(`SELECT COUNT(*) as c FROM users`).get();
  res.json({ pending: pending.c, approved: approved.c, totalUsers: totalUsers.c });
});

// Health check (useful for hosts)
app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'SafariLink' });
});

// ── Start ──
app.listen(PORT, () => {
  console.log(`SafariLink → http://localhost:${PORT}`);
  console.log(`Admin panel → http://localhost:${PORT}/admin.html`);
  console.log(`DB file     → ${dbPath}`);
});
