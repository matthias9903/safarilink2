// server.js — SafariLink backend
import express from 'express';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import multer from 'multer';
import nodemailer from 'nodemailer';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'safarilink-admin-2026';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'safarilink-admin-2026';
const OWNER_EMAIL = 'dreamtrailsexpedictions@gmail.com';
const OWNER_TEMP_PASSWORD = process.env.OWNER_TEMP_PASSWORD || 'SafariLink2026';

// Optional email (Gmail example): set EMAIL_USER + EMAIL_PASS (app password) on Railway
const EMAIL_USER = process.env.EMAIL_USER || '';
const EMAIL_PASS = process.env.EMAIL_PASS || '';
const EMAIL_FROM = process.env.EMAIL_FROM || EMAIL_USER || 'noreply@safarilink.app';

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

const dataDir = process.env.DB_PATH
  ? path.dirname(process.env.DB_PATH)
  : path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const uploadsDir = path.join(dataDir, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

app.use('/uploads', express.static(uploadsDir));
app.use(express.static(__dirname));

const dbPath = process.env.DB_PATH || path.join(dataDir, 'safarilink.db');
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
    documents_json TEXT DEFAULT '[]',
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
try { db.exec(`ALTER TABLE access_requests ADD COLUMN documents_json TEXT DEFAULT '[]'`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0`); } catch (_) {}

// Migrate users unique(email,role)
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      company_name TEXT,
      contact_name TEXT,
      status TEXT DEFAULT 'active',
      must_change_password INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(email, role)
    );
  `);
  const countOld = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const countNew = db.prepare('SELECT COUNT(*) as c FROM users_new').get().c;
  if (countOld > 0 && countNew === 0) {
    db.exec(`
      INSERT OR IGNORE INTO users_new
        (id, email, password_hash, role, company_name, contact_name, status, must_change_password, created_at)
      SELECT id, email, password_hash, role, company_name, contact_name, status, must_change_password, created_at FROM users;
      DROP TABLE users;
      ALTER TABLE users_new RENAME TO users;
    `);
  } else {
    try { db.exec('DROP TABLE IF EXISTS users_new'); } catch (_) {}
  }
} catch (e) {
  console.warn('migration:', e.message);
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
  console.log('Owner seeded:', OWNER_EMAIL);
}
seedOwnerAccounts();

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, Date.now() + '-' + safe);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024, files: 10 },
  fileFilter: (_req, file, cb) => {
    const ok = /\.(pdf|jpe?g|png|webp|docx?)$/i.test(file.originalname);
    cb(ok ? null : new Error('Unsupported file type'), ok);
  }
});

async function sendMail(to, subject, text) {
  if (!EMAIL_USER || !EMAIL_PASS) {
    console.log('[email skipped — set EMAIL_USER and EMAIL_PASS]', { to, subject });
    return { sent: false, reason: 'Email not configured on server' };
  }
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: EMAIL_USER, pass: EMAIL_PASS }
    });
    await transporter.sendMail({ from: EMAIL_FROM, to, subject, text });
    return { sent: true };
  } catch (err) {
    console.error('email error', err.message);
    return { sent: false, reason: err.message };
  }
}

function adminAuth(req, res, next) {
  const auth = (req.headers.authorization || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth;
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ── Public: access request (JSON or multipart with files)
function handleAccessRequest(req, res) {
  const body = req.body || {};
  const businessType = body.businessType || body.business_type;
  const companyName = body.companyName || body.company_name;
  const contactName = body.contactName || body.contact_name;
  const email = body.email;
  const phone = body.phone;
  const region = body.region;
  const description = body.description || '';
  const documentsNote = body.documentsNote || body.documents_note || '';

  if (!businessType || !companyName || !contactName || !email || !phone || !region) {
    return res.status(400).json({ error: 'All required fields must be filled' });
  }

  const files = (req.files || []).map(f => ({
    originalName: f.originalname,
    filename: f.filename,
    size: f.size,
    url: '/uploads/' + f.filename
  }));

  const result = db.prepare(`
    INSERT INTO access_requests
      (business_type, company_name, contact_name, email, phone, region, description, documents_note, documents_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    businessType, companyName, contactName, email, phone, region,
    description, documentsNote, JSON.stringify(files)
  );

  res.json({ success: true, id: result.lastInsertRowid, documents: files.length });
}

app.post('/api/access-request', (req, res, next) => {
  const ct = req.headers['content-type'] || '';
  if (ct.includes('multipart/form-data')) {
    upload.array('businessDocuments', 10)(req, res, (err) => {
      if (err) return res.status(400).json({ error: err.message });
      handleAccessRequest(req, res);
    });
  } else {
    handleAccessRequest(req, res);
  }
});

// Admin can upload extra docs onto a request
app.post('/api/admin/requests/:id/documents', adminAuth, (req, res) => {
  upload.array('documents', 10)(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    const r = db.prepare('SELECT * FROM access_requests WHERE id = ?').get(req.params.id);
    if (!r) return res.status(404).json({ error: 'Not found' });
    let existing = [];
    try { existing = JSON.parse(r.documents_json || '[]'); } catch (_) {}
    const added = (req.files || []).map(f => ({
      originalName: f.originalname,
      filename: f.filename,
      size: f.size,
      url: '/uploads/' + f.filename
    }));
    const merged = existing.concat(added);
    db.prepare('UPDATE access_requests SET documents_json = ? WHERE id = ?')
      .run(JSON.stringify(merged), r.id);
    res.json({ success: true, documents: merged });
  });
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
    if (user && !bcrypt.compareSync(password, user.password_hash)) user = null;
  }
  if (!user) {
    const candidates = db.prepare(
      `SELECT * FROM users WHERE email = ? AND status = 'active'`
    ).all(email);
    for (const c of candidates) {
      if (bcrypt.compareSync(password, c.password_hash)) {
        if (role && c.role === role) { user = c; break; }
        if (!user) user = c;
      }
    }
  }
  if (!user) {
    return res.status(401).json({ success: false, error: 'Invalid email or password' });
  }

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
  if (!users.length || !users.some(u => bcrypt.compareSync(currentPassword, u.password_hash))) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare(`UPDATE users SET password_hash = ?, must_change_password = 0 WHERE email = ?`).run(hash, email);
  res.json({ success: true });
});

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Invalid password' });
  res.json({ success: true, token: ADMIN_TOKEN });
});

app.get('/api/admin/requests', adminAuth, (req, res) => {
  const rows = db.prepare(`SELECT * FROM access_requests ORDER BY created_at DESC`).all();
  res.json(rows.map(r => {
    let documents = [];
    try { documents = JSON.parse(r.documents_json || '[]'); } catch (_) {}
    return { ...r, documents };
  }));
});

app.get('/api/admin/requests/:id', adminAuth, (req, res) => {
  const r = db.prepare(`SELECT * FROM access_requests WHERE id = ?`).get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  let documents = [];
  try { documents = JSON.parse(r.documents_json || '[]'); } catch (_) {}
  res.json({ ...r, documents });
});

app.post('/api/admin/approve/:id', adminAuth, async (req, res) => {
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

  db.prepare(`UPDATE access_requests SET status = 'approved', reviewed_at = datetime('now') WHERE id = ?`).run(r.id);

  const loginUrl = (process.env.PUBLIC_URL || '').replace(/\/$/, '') || '';
  const mailText = [
    `Hello ${r.contact_name},`,
    ``,
    `Your SafariLink access request for "${r.company_name}" (${r.business_type}) has been APPROVED.`,
    ``,
    `Login email: ${r.email}`,
    `Temporary password: ${tempPwd}`,
    `Role: ${r.business_type}`,
    loginUrl ? `Login: ${loginUrl}/login.html` : `Login at the SafariLink login page.`,
    ``,
    `Please change your password after first login.`,
    ``,
    `— SafariLink Team`
  ].join('\n');

  const mailResult = await sendMail(
    r.email,
    'SafariLink — Access approved',
    mailText
  );

  res.json({
    success: true,
    email: r.email,
    tempPassword: tempPwd,
    role: r.business_type,
    companyName: r.company_name,
    contactName: r.contact_name,
    emailSent: mailResult.sent,
    emailNote: mailResult.reason || null,
    note: 'Temporary password created. Email sent if EMAIL_USER/EMAIL_PASS are configured.'
  });
});

app.post('/api/admin/reject/:id', adminAuth, async (req, res) => {
  const r = db.prepare('SELECT * FROM access_requests WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Not found' });

  db.prepare(`UPDATE access_requests SET status = 'rejected', reviewed_at = datetime('now') WHERE id = ?`).run(r.id);

  const reason = (req.body && req.body.reason) || 'Your application did not meet our current partner criteria.';
  const mailText = [
    `Hello ${r.contact_name},`,
    ``,
    `Thank you for applying to SafariLink for "${r.company_name}".`,
    ``,
    `Unfortunately your access request has been declined at this time.`,
    `Reason: ${reason}`,
    ``,
    `You may apply again later with updated information.`,
    ``,
    `— SafariLink Team`
  ].join('\n');

  const mailResult = await sendMail(r.email, 'SafariLink — Access request update', mailText);

  res.json({ success: true, emailSent: mailResult.sent, emailNote: mailResult.reason || null });
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
  const pending = db.prepare(`SELECT COUNT(*) as c FROM access_requests WHERE status = 'pending'`).get();
  const approved = db.prepare(`SELECT COUNT(*) as c FROM access_requests WHERE status = 'approved'`).get();
  const totalUsers = db.prepare(`SELECT COUNT(*) as c FROM users`).get();
  res.json({ pending: pending.c, approved: approved.c, totalUsers: totalUsers.c });
});

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'SafariLink',
    emailConfigured: !!(EMAIL_USER && EMAIL_PASS)
  });
});

app.listen(PORT, () => {
  console.log(`SafariLink → http://localhost:${PORT}`);
  console.log(`Admin → http://localhost:${PORT}/admin-dashboard.html`);
  console.log(`DB → ${dbPath}`);
});
