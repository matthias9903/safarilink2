// server.js — SafariLink backend
// Railway / Render / any Node host with disk for SQLite

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

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'safarilink-admin-2026';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'safarilink-admin-2026';

// Owner test account (all dashboards)
const OWNER_EMAIL = 'dreamtrailsexpedictions@gmail.com';
const OWNER_TEMP_PASSWORD = process.env.OWNER_TEMP_PASSWORD || 'SafariLink2026';

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(__dirname));

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
    documents_note TEXT DEFAULT '',
    status        TEXT DEFAULT 'pending',
    created_at    TEXT DEFAULT (datetime('now')),
    reviewed_at   TEXT
  );

  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    company_name  TEXT,
    contact_name  TEXT,
    status        TEXT DEFAULT 'active',
    must_change_password INTEGER DEFAULT 0,
    created_at    TEXT DEFAULT (datetime('now')),
    UNIQUE(email, role)
  );
`);

try { db.exec(`ALTER TABLE access_requests ADD COLUMN documents_note TEXT DEFAULT ''`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0`); } catch (_) {}

// Migrate to UNIQUE(email, role) so one email can have many dashboard roles
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users_new (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      email         TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role          TEXT NOT NULL,
      company_name  TEXT,
      contact_name  TEXT,
      status        TEXT DEFAULT 'active',
      must_change_password INTEGER DEFAULT 0,
      created_at    TEXT DEFAULT (datetime('now')),
      UNIQUE(email, role)
    );
  `);
  const countOld = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const countNew = db.prepare('SELECT COUNT(*) as c FROM users_new').get().c;
  if (countOld > 0 && countNew === 0) {
    db.exec(`
      INSERT OR IGNORE INTO users_new
        (id, email, password_hash, role, company_name, contact_name, status, must_change_password, created_at)
      SELECT id, email, password_hash, role, company_name, contact_name, status, must_change_password, created_at
      FROM users;
      DROP TABLE users;
      ALTER TABLE users_new RENAME TO users;
    `);
  } else {
    try { db.exec('DROP TABLE IF EXISTS users_new'); } catch (_) {}
  }
} catch (e) {
  console.warn('User table migration note:', e.message);
}

function seedOwnerAccounts() {
  const roles = ['accommodation', 'fleet', 'guide', 'tour-operator', 'service-offering'];
  const hash = bcrypt.hashSync(OWNER_TEMP_PASSWORD, 10);
  const insert = db.prepare(`
    INSERT INTO users (email, password_hash, role, company_name, contact_name, must_change_password, status)
    VALUES (?, ?, ?, ?, ?, 0, 'active')
    ON CONFLICT(email, role) DO UPDATE SET
      password_hash = excluded.password_hash,
      status = 'active',
      must_change_password = 0
  `);
  for (const role of roles) {
    insert.run(OWNER_EMAIL, hash, role, 'Dreamtrails Expeditions', 'Dreamtrails Admin');
  }
  console.log('Owner account ready:', OWNER_EMAIL, 'roles:', roles.join(', '));
}
seedOwnerAccounts();

function adminAuth(req, res, next) {
  const auth = (req.headers.authorization || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth;
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.post('/api/access-request', (req, res) => {
  const {
    businessType, companyName, contactName, email, phone, region, description, documentsNote
  } = req.body || {};

  if (!businessType || !companyName || !contactName || !email || !phone || !region) {
    return res.status(400).json({ error: 'All required fields must be filled' });
  }

  const result = db.prepare(`
    INSERT INTO access_requests
      (business_type, company_name, contact_name, email, phone, region, description, documents_note)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    businessType, companyName, contactName, email, phone, region,
    description || '', documentsNote || ''
  );

  res.json({ success: true, id: result.lastInsertRowid });
});

app.post('/api/login', (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  let user = null;
  if (role) {
    user = db.prepare(
      `SELECT * FROM users WHERE email = ? AND role = ? AND status = 'active'`
    ).get(email, role);
  }
  if (!user) {
    // Same password may exist on multiple roles — pick requested role if password matches any
    const candidates = db.prepare(
      `SELECT * FROM users WHERE email = ? AND status = 'active'`
    ).all(email);
    for (const c of candidates) {
      if (bcrypt.compareSync(password, c.password_hash)) {
        if (role && c.role === role) { user = c; break; }
        if (!user) user = c;
      }
    }
  } else if (!bcrypt.compareSync(password, user.password_hash)) {
    user = null;
  }

  if (!user) {
    return res.status(401).json({ success: false, error: 'Invalid email or password' });
  }

  const effectiveRole = (role && db.prepare(
    `SELECT role FROM users WHERE email = ? AND role = ? AND status = 'active'`
  ).get(email, role)) ? role : user.role;

  // Prefer the role they selected if that account exists with same password
  let outRole = user.role;
  if (role) {
    const preferred = db.prepare(
      `SELECT * FROM users WHERE email = ? AND role = ? AND status = 'active'`
    ).get(email, role);
    if (preferred && bcrypt.compareSync(password, preferred.password_hash)) {
      outRole = preferred.role;
      user = preferred;
    }
  }

  res.json({
    success: true,
    role: outRole,
    companyName: user.company_name,
    contactName: user.contact_name,
    mustChangePassword: !!user.must_change_password
  });
});

app.post('/api/change-password', (req, res) => {
  const { email, currentPassword, newPassword } = req.body || {};
  if (!email || !currentPassword || !newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }

  const users = db.prepare(`SELECT * FROM users WHERE email = ?`).all(email);
  if (!users.length) return res.status(401).json({ error: 'Current password is incorrect' });

  const ok = users.some(u => bcrypt.compareSync(currentPassword, u.password_hash));
  if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });

  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare(`UPDATE users SET password_hash = ?, must_change_password = 0 WHERE email = ?`).run(hash, email);
  res.json({ success: true });
});

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  res.json({ success: true, token: ADMIN_TOKEN });
});

app.get('/api/admin/requests', adminAuth, (req, res) => {
  res.json(db.prepare(`SELECT * FROM access_requests ORDER BY created_at DESC`).all());
});

app.get('/api/admin/access-requests', adminAuth, (req, res) => {
  res.json(db.prepare(`SELECT * FROM access_requests ORDER BY created_at DESC`).all());
});

app.get('/api/admin/requests/:id', adminAuth, (req, res) => {
  const r = db.prepare(`SELECT * FROM access_requests WHERE id = ?`).get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  res.json(r);
});

app.post('/api/admin/approve/:id', adminAuth, (req, res) => {
  const r = db.prepare('SELECT * FROM access_requests WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Request not found' });
  if (r.status !== 'pending') return res.status(400).json({ error: 'Already processed' });

  const tempPwd = crypto.randomBytes(4).toString('hex');
  const hash = bcrypt.hashSync(tempPwd, 10);

  db.prepare(`
    INSERT INTO users (email, password_hash, role, company_name, contact_name, must_change_password, status)
    VALUES (?, ?, ?, ?, ?, 1, 'active')
    ON CONFLICT(email, role) DO UPDATE SET
      password_hash = excluded.password_hash,
      company_name = excluded.company_name,
      contact_name = excluded.contact_name,
      status = 'active',
      must_change_password = 1
  `).run(r.email, hash, r.business_type, r.company_name, r.contact_name);

  db.prepare(`
    UPDATE access_requests SET status = 'approved', reviewed_at = datetime('now') WHERE id = ?
  `).run(r.id);

  res.json({
    success: true,
    email: r.email,
    tempPassword: tempPwd,
    role: r.business_type,
    companyName: r.company_name,
    contactName: r.contact_name,
    note: 'Send this temporary password to the user. They should change it on first login.'
  });
});

app.post('/api/admin/reject/:id', adminAuth, (req, res) => {
  const r = db.prepare('SELECT id FROM access_requests WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  db.prepare(`
    UPDATE access_requests SET status = 'rejected', reviewed_at = datetime('now') WHERE id = ?
  `).run(r.id);
  res.json({ success: true });
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
  const pending = db.prepare(`SELECT COUNT(*) as c FROM access_requests WHERE status = 'pending'`).get();
  const approved = db.prepare(`SELECT COUNT(*) as c FROM access_requests WHERE status = 'approved'`).get();
  const totalUsers = db.prepare(`SELECT COUNT(*) as c FROM users`).get();
  res.json({ pending: pending.c, approved: approved.c, totalUsers: totalUsers.c });
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'SafariLink' });
});

app.listen(PORT, () => {
  console.log(`SafariLink → http://localhost:${PORT}`);
  console.log(`Admin panel → http://localhost:${PORT}/admin-dashboard.html`);
  console.log(`DB file     → ${dbPath}`);
});
