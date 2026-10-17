/**
 * SafariLink — production backend
 * Deploy on Railway with a volume at /app/data
 */
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
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT) || 3000;
const IS_PROD = process.env.NODE_ENV === 'production' || !!process.env.RAILWAY_ENVIRONMENT;

// ── Secrets (required in production) ──────────────────────────
function requireSecret(name, fallback) {
  const v = process.env[name];
  if (v && String(v).trim()) return String(v).trim();
  if (IS_PROD) {
    console.error(`[FATAL] Missing required env var: ${name}`);
    process.exit(1);
  }
  console.warn(`[dev] Using default for ${name} — set this in production`);
  return fallback;
}

const ADMIN_TOKEN = requireSecret('ADMIN_TOKEN', 'dev-admin-token-change-me');
const ADMIN_PASSWORD = requireSecret('ADMIN_PASSWORD', 'dev-admin-password');
const OWNER_EMAIL = (process.env.OWNER_EMAIL || 'dreamtrailsexpedictions@gmail.com').toLowerCase();
const OWNER_TEMP_PASSWORD = process.env.OWNER_TEMP_PASSWORD || 'SafariLink2026';

const EMAIL_USER = process.env.EMAIL_USER || '';
const EMAIL_PASS = process.env.EMAIL_PASS || '';
const EMAIL_FROM = process.env.EMAIL_FROM || EMAIL_USER || 'noreply@safarilink.app';
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/$/, '');

const ALLOWED_ROLES = new Set([
  'accommodation',
  'fleet',
  'guide',
  'tour-operator',
  'service-offering'
]);

// ── App hardening ─────────────────────────────────────────────
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: false, // static HTML uses inline scripts
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in 15 minutes.' }
});

const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' }
});

// ── Data directories ───────────────────────────────────────────
const dataDir = process.env.DB_PATH
  ? path.dirname(process.env.DB_PATH)
  : path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const uploadsDir = path.join(dataDir, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

app.use('/uploads', express.static(uploadsDir, {
  fallthrough: false,
  setHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'private, max-age=3600');
  }
}));

app.use(express.static(__dirname, {
  index: 'index.html',
  extensions: ['html']
}));

// ── Database ──────────────────────────────────────────────────
const dbPath = process.env.DB_PATH || path.join(dataDir, 'safarilink.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

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

  CREATE INDEX IF NOT EXISTS idx_requests_status ON access_requests(status);
  CREATE INDEX IF NOT EXISTS idx_requests_email ON access_requests(email);
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
`);

try { db.exec(`ALTER TABLE access_requests ADD COLUMN documents_note TEXT DEFAULT ''`); } catch (_) {}
try { db.exec(`ALTER TABLE access_requests ADD COLUMN documents_json TEXT DEFAULT '[]'`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0`); } catch (_) {}

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
  console.warn('migration note:', e.message);
}

function seedOwnerAccounts() {
  if (!OWNER_EMAIL || !OWNER_TEMP_PASSWORD) return;
  const roles = [...ALLOWED_ROLES];
  const hash = bcrypt.hashSync(OWNER_TEMP_PASSWORD, 12);
  const insert = db.prepare(`
    INSERT INTO users (email, password_hash, role, company_name, contact_name, must_change_password, status)
    VALUES (?, ?, ?, ?, ?, 0, 'active')
    ON CONFLICT(email, role) DO UPDATE SET
      password_hash = excluded.password_hash,
      status = 'active',
      must_change_password = 0
  `);
  const tx = db.transaction(() => {
    for (const role of roles) {
      insert.run(OWNER_EMAIL, hash, role, 'Dreamtrails Expeditions', 'Dreamtrails Admin');
    }
  });
  tx();
  console.log('Owner accounts ready for', OWNER_EMAIL);
}
seedOwnerAccounts();

// ── Helpers ───────────────────────────────────────────────────
function adminAuth(req, res, next) {
  const auth = (req.headers.authorization || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth;
  if (!token || token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) && email.length <= 254;
}

function cleanStr(v, max = 500) {
  if (v == null) return '';
  return String(v).trim().slice(0, max);
}

function parseDocuments(json) {
  try {
    const d = JSON.parse(json || '[]');
    return Array.isArray(d) ? d : [];
  } catch {
    return [];
  }
}

async function sendMail(to, subject, text) {
  if (!EMAIL_USER || !EMAIL_PASS) {
    console.log('[email skipped]', { to, subject });
    return { sent: false, reason: 'Email not configured (set EMAIL_USER and EMAIL_PASS)' };
  }
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: EMAIL_USER, pass: EMAIL_PASS }
    });
    await transporter.sendMail({ from: EMAIL_FROM, to, subject, text });
    return { sent: true };
  } catch (err) {
    console.error('[email error]', err.message);
    return { sent: false, reason: 'Failed to send email' };
  }
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase().slice(0, 10);
    const base = path.basename(file.originalname || 'file', ext)
      .replace(/[^a-zA-Z0-9._-]/g, '_')
      .slice(0, 80);
    cb(null, `${Date.now()}-${crypto.randomBytes(4).toString('hex')}-${base}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024, files: 10 },
  fileFilter: (_req, file, cb) => {
    const ok = /\.(pdf|jpe?g|png|webp|docx?)$/i.test(file.originalname || '');
    if (!ok) return cb(new Error('Unsupported file type. Use PDF, JPG, PNG, WEBP, DOC, or DOCX.'));
    cb(null, true);
  }
});

function mapFiles(files) {
  return (files || []).map(f => ({
    originalName: f.originalname,
    filename: f.filename,
    size: f.size,
    url: '/uploads/' + f.filename
  }));
}

// ── Routes ────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  let dbOk = false;
  try {
    db.prepare('SELECT 1').get();
    dbOk = true;
  } catch (_) {}
  res.status(dbOk ? 200 : 503).json({
    ok: dbOk,
    service: 'SafariLink',
    env: IS_PROD ? 'production' : 'development',
    emailConfigured: !!(EMAIL_USER && EMAIL_PASS),
    time: new Date().toISOString()
  });
});

function handleAccessRequest(req, res) {
  const body = req.body || {};
  const businessType = cleanStr(body.businessType || body.business_type, 64);
  const companyName = cleanStr(body.companyName || body.company_name, 200);
  const contactName = cleanStr(body.contactName || body.contact_name, 200);
  const email = cleanStr(body.email, 254).toLowerCase();
  const phone = cleanStr(body.phone, 40);
  const region = cleanStr(body.region, 120);
  const description = cleanStr(body.description, 4000);
  const documentsNote = cleanStr(body.documentsNote || body.documents_note, 2000);

  if (!businessType || !companyName || !contactName || !email || !phone || !region) {
    return res.status(400).json({ error: 'All required fields must be filled' });
  }
  if (!ALLOWED_ROLES.has(businessType)) {
    return res.status(400).json({ error: 'Invalid business type' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  const files = mapFiles(req.files);
  try {
    const result = db.prepare(`
      INSERT INTO access_requests
        (business_type, company_name, contact_name, email, phone, region, description, documents_note, documents_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      businessType, companyName, contactName, email, phone, region,
      description, documentsNote, JSON.stringify(files)
    );
    res.status(201).json({ success: true, id: result.lastInsertRowid, documents: files.length });
  } catch (err) {
    console.error('access-request error', err.message);
    res.status(500).json({ error: 'Could not save request' });
  }
}

app.post('/api/access-request', publicLimiter, (req, res) => {
  const ct = req.headers['content-type'] || '';
  if (ct.includes('multipart/form-data')) {
    upload.array('businessDocuments', 10)(req, res, (err) => {
      if (err) return res.status(400).json({ error: err.message || 'Upload failed' });
      handleAccessRequest(req, res);
    });
  } else {
    handleAccessRequest(req, res);
  }
});

app.post('/api/login', authLimiter, (req, res) => {
  const email = cleanStr(req.body?.email, 254).toLowerCase();
  const password = req.body?.password;
  const role = cleanStr(req.body?.role, 64);

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  if (!isValidEmail(email)) {
    return res.status(401).json({ success: false, error: 'Invalid email or password' });
  }

  let user = null;
  if (role && ALLOWED_ROLES.has(role)) {
    user = db.prepare(
      `SELECT * FROM users WHERE email = ? AND role = ? AND status = 'active'`
    ).get(email, role);
    if (user && !bcrypt.compareSync(String(password), user.password_hash)) user = null;
  }
  if (!user) {
    const candidates = db.prepare(
      `SELECT * FROM users WHERE email = ? AND status = 'active'`
    ).all(email);
    for (const c of candidates) {
      if (bcrypt.compareSync(String(password), c.password_hash)) {
        if (role && c.role === role) { user = c; break; }
        if (!user) user = c;
      }
    }
  }
  if (!user) {
    return res.status(401).json({ success: false, error: 'Invalid email or password' });
  }

  let outRole = user.role;
  if (role && ALLOWED_ROLES.has(role)) {
    const preferred = db.prepare(
      `SELECT * FROM users WHERE email = ? AND role = ? AND status = 'active'`
    ).get(email, role);
    if (preferred && bcrypt.compareSync(String(password), preferred.password_hash)) {
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

app.post('/api/change-password', authLimiter, (req, res) => {
  const email = cleanStr(req.body?.email, 254).toLowerCase();
  const currentPassword = req.body?.currentPassword;
  const newPassword = req.body?.newPassword;

  if (!email || !currentPassword || !newPassword || String(newPassword).length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  if (String(newPassword).length > 128) {
    return res.status(400).json({ error: 'Password too long' });
  }

  const users = db.prepare(`SELECT * FROM users WHERE email = ?`).all(email);
  if (!users.length || !users.some(u => bcrypt.compareSync(String(currentPassword), u.password_hash))) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  const hash = bcrypt.hashSync(String(newPassword), 12);
  db.prepare(`UPDATE users SET password_hash = ?, must_change_password = 0 WHERE email = ?`).run(hash, email);
  res.json({ success: true });
});

app.post('/api/admin/login', authLimiter, (req, res) => {
  const password = req.body?.password;
  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  res.json({ success: true, token: ADMIN_TOKEN });
});

app.get('/api/admin/requests', adminAuth, (_req, res) => {
  const rows = db.prepare(`SELECT * FROM access_requests ORDER BY created_at DESC`).all();
  res.json(rows.map(r => ({ ...r, documents: parseDocuments(r.documents_json) })));
});

app.get('/api/admin/requests/:id', adminAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid id' });
  const r = db.prepare(`SELECT * FROM access_requests WHERE id = ?`).get(id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  res.json({ ...r, documents: parseDocuments(r.documents_json) });
});

app.post('/api/admin/requests/:id/documents', adminAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid id' });

  upload.array('documents', 10)(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || 'Upload failed' });
    const r = db.prepare('SELECT * FROM access_requests WHERE id = ?').get(id);
    if (!r) return res.status(404).json({ error: 'Not found' });
    const existing = parseDocuments(r.documents_json);
    const merged = existing.concat(mapFiles(req.files));
    db.prepare('UPDATE access_requests SET documents_json = ? WHERE id = ?')
      .run(JSON.stringify(merged), id);
    res.json({ success: true, documents: merged });
  });
});

app.post('/api/admin/approve/:id', adminAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid id' });

  const r = db.prepare('SELECT * FROM access_requests WHERE id = ?').get(id);
  if (!r) return res.status(404).json({ error: 'Request not found' });
  if (r.status !== 'pending') return res.status(400).json({ error: 'Already processed' });
  if (!ALLOWED_ROLES.has(r.business_type)) {
    return res.status(400).json({ error: 'Invalid business type on request' });
  }

  const tempPwd = crypto.randomBytes(5).toString('hex'); // 10 chars
  const hash = bcrypt.hashSync(tempPwd, 12);

  const tx = db.transaction(() => {
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
    `).run(id);
  });
  tx();

  const loginLine = PUBLIC_URL
    ? `Login: ${PUBLIC_URL}/login.html`
    : 'Login at the SafariLink login page.';

  const mailText = [
    `Hello ${r.contact_name},`,
    ``,
    `Your SafariLink access request for "${r.company_name}" (${r.business_type}) has been APPROVED.`,
    ``,
    `Login email: ${r.email}`,
    `Temporary password: ${tempPwd}`,
    `Role: ${r.business_type}`,
    loginLine,
    ``,
    `Please change your password after first login.`,
    ``,
    `— SafariLink Team`
  ].join('\n');

  const mailResult = await sendMail(r.email, 'SafariLink — Access approved', mailText);

  res.json({
    success: true,
    email: r.email,
    tempPassword: tempPwd,
    role: r.business_type,
    companyName: r.company_name,
    contactName: r.contact_name,
    emailSent: mailResult.sent,
    emailNote: mailResult.reason || null
  });
});

app.post('/api/admin/reject/:id', adminAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid id' });

  const r = db.prepare('SELECT * FROM access_requests WHERE id = ?').get(id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  if (r.status !== 'pending') return res.status(400).json({ error: 'Already processed' });

  db.prepare(`
    UPDATE access_requests SET status = 'rejected', reviewed_at = datetime('now') WHERE id = ?
  `).run(id);

  const reason = cleanStr(req.body?.reason, 500) ||
    'Your application did not meet our current partner criteria.';

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

app.get('/api/admin/stats', adminAuth, (_req, res) => {
  const pending = db.prepare(`SELECT COUNT(*) as c FROM access_requests WHERE status = 'pending'`).get();
  const approved = db.prepare(`SELECT COUNT(*) as c FROM access_requests WHERE status = 'approved'`).get();
  const totalUsers = db.prepare(`SELECT COUNT(*) as c FROM users`).get();
  res.json({ pending: pending.c, approved: approved.c, totalUsers: totalUsers.c });
});

// SPA-ish fallback: avoid leaking paths for missing API
app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, _req, res, _next) => {
  console.error('[error]', err.message);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
  }
  res.status(500).json({ error: IS_PROD ? 'Server error' : err.message });
});

const server = app.listen(PORT, () => {
  console.log(`SafariLink listening on :${PORT} (${IS_PROD ? 'production' : 'development'})`);
  console.log(`DB: ${dbPath}`);
});

function shutdown(signal) {
  console.log(`Received ${signal}, shutting down…`);
  server.close(() => {
    try { db.close(); } catch (_) {}
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
