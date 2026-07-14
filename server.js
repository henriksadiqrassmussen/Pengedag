require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

// v1.6.18e TIME ENTRY SAFE FIX
// Skal ligge foer rate-limit, auth, JSON parser og alle routes.
function getAllowedCorsOrigins() {
  const fromEnv = (process.env.CORS_ORIGINS || '')
    .split(',')
    .map(x => x.trim().replace(/^['"]|['"]$/g, ''))
    .filter(Boolean);
  const defaults = [
    'https://pengedag.dk',
    'https://www.pengedag.dk',
    'http://pengedag.dk',
    'http://www.pengedag.dk'
  ];
  return Array.from(new Set([...defaults, ...fromEnv]));
}

function hardCors(req, res, next) {
  const origin = req.headers.origin;
  const allowed = getAllowedCorsOrigins();
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'false');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, Accept, X-Requested-With, X-Request-Id');
  res.setHeader('Access-Control-Expose-Headers', 'X-Request-Id, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  return next();
}

app.use(hardCors);

const JSON_LIMIT = process.env.JSON_LIMIT || '10mb';
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 300);
const LOGIN_RATE_LIMIT_MAX = Number(process.env.LOGIN_RATE_LIMIT_MAX || 10);
const SECURITY_CONTACT_EMAIL = process.env.SECURITY_CONTACT_EMAIL || 'vault1973@gmail.com';

function securityHeaders(req, res, next) {
  const requestId = crypto.randomBytes(8).toString('hex');
  req.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin'); // v1.6.18c: tillad pengedag.dk -> Railway API
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
}

const rateBuckets = new Map();
function clientIp(req) {
  return (req.headers['x-forwarded-for'] || req.ip || req.socket?.remoteAddress || 'unknown').toString().split(',')[0].trim();
}
function makeRateLimiter(name, max, windowMs) {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${name}:${clientIp(req)}`;
    let bucket = rateBuckets.get(key);
    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
    }
    bucket.count += 1;
    rateBuckets.set(key, bucket);
    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, max - bucket.count)));
    res.setHeader('X-RateLimit-Reset', String(Math.ceil(bucket.resetAt / 1000)));
    if (bucket.count > max) {
      return res.status(429).json({ ok: false, error: 'For mange forespoergsler. Proev igen senere.', requestId: req.requestId });
    }
    next();
  };
}
function isStrongSecret(value) {
  return typeof value === 'string' && value.length >= 32 && !value.includes('DEV_ONLY') && !value.includes('CHANGE_ME');
}

app.use(securityHeaders);
app.use(makeRateLimiter('global', RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS));
// v1.6.18g: payslip month/date + work_date + hours fix.
app.use(express.json({ limit: JSON_LIMIT }));

const VERSION = '1.7.0-lonprofil-full-server';
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'DEV_ONLY_CHANGE_ME_PENGEDAG';
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.warn('ADVARSEL: DATABASE_URL mangler. Railway backend skal have DATABASE_URL fra PostgreSQL service.');
}
if (!process.env.JWT_SECRET) {
  console.warn('ADVARSEL: JWT_SECRET mangler. Tilfoej JWT_SECRET i Railway Variables foer rigtig drift.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    return await client.query(sql, params);
  } finally {
    client.release();
  }
}

async function tableExists(name) {
  const r = await query(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1) AS exists`, [name]);
  return !!r.rows[0].exists;
}

async function columnExists(table, column) {
  const r = await query(`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name=$2) AS exists`, [table, column]);
  return !!r.rows[0].exists;
}

async function addColumnIfMissing(table, column, definition) {
  const exists = await columnExists(table, column);
  if (!exists) {
    console.log(`Migration: tilfoejer ${table}.${column}`);
    await query(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

async function safeCreateIndex(name, table, column) {
  const exists = await columnExists(table, column);
  if (!exists) {
    console.warn(`Springer index ${name} over: ${table}.${column} findes ikke endnu`);
    return;
  }
  await query(`CREATE INDEX IF NOT EXISTS ${name} ON ${table}(${column})`);
}


async function auditTriggerExists() {
  const r = await query(`
    SELECT EXISTS (
      SELECT 1 FROM pg_trigger WHERE tgname='trg_audit_log_no_update_delete'
    ) AS exists
  `);
  return !!r.rows[0].exists;
}

async function backfillAuditHashes() {
  const exists = await tableExists('audit_log');
  if (!exists) return;

  // v1.6.6: Reparer altid hash-kaeden foer immutable trigger aktiveres.
  // Hvis triggeren allerede findes fra v1.6.5, fjernes den midlertidigt,
  // hash-kaeden genberegnes sikkert, og triggeren oprettes igen bagefter.
  await query(`DROP TRIGGER IF EXISTS trg_audit_log_no_update_delete ON audit_log`);

  const r = await query(`SELECT * FROM audit_log ORDER BY created_at ASC, id ASC`);
  let prevHash = 'GENESIS';
  let seq = 1;

  for (const row of r.rows) {
    const repaired = {
      ...row,
      sequence_number: seq,
      prev_hash: prevHash,
      actor_user_id: row.actor_user_id || '',
      actor_email: row.actor_email || '',
      actor_role: row.actor_role || 'legacy',
      action: row.action || '',
      target_type: row.target_type || row.entity_type || '',
      target_id: row.target_id || row.entity_id || '',
      details_json: row.details_json || row.payload || {},
      created_at: row.created_at || new Date()
    };

    repaired.row_hash = buildAuditHash(repaired);

    await query(`
      UPDATE audit_log
      SET sequence_number=$2,
          prev_hash=$3,
          row_hash=$4,
          actor_user_id=$5,
          actor_email=$6,
          actor_role=$7,
          action=$8,
          target_type=$9,
          target_id=$10,
          details_json=$11
      WHERE id=$1
    `, [
      row.id,
      repaired.sequence_number,
      repaired.prev_hash,
      repaired.row_hash,
      repaired.actor_user_id,
      repaired.actor_email,
      repaired.actor_role,
      repaired.action,
      repaired.target_type,
      repaired.target_id,
      repaired.details_json
    ]);

    prevHash = repaired.row_hash;
    seq += 1;
  }

  console.log('Audit log hash repair OK: ' + r.rows.length + ' raekker');
}

async function installImmutableAuditTrigger() {
  await query(`
    CREATE OR REPLACE FUNCTION prevent_audit_log_update_delete()
    RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'audit_log is immutable: UPDATE/DELETE is not allowed';
    END;
    $$ LANGUAGE plpgsql;
  `);
  await query(`DROP TRIGGER IF EXISTS trg_audit_log_no_update_delete ON audit_log`);
  await query(`
    CREATE TRIGGER trg_audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_update_delete();
  `);
  console.log('Audit log immutable trigger OK');
}

async function initDb() {
  // 1) Grundtabeller foerst. Ingen indexes foer kolonner er sikret.
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'employee',
      employee_id TEXT DEFAULT '',
      name TEXT DEFAULT '',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS time_entries (
      id TEXT PRIMARY KEY,
      user_id TEXT DEFAULT '',
      employee_id TEXT DEFAULT '',
      employee_name TEXT DEFAULT '',
      email TEXT DEFAULT '',
      customer_id TEXT DEFAULT '',
      customer_name TEXT DEFAULT '',
      date TEXT DEFAULT '',
      start_time TEXT DEFAULT '',
      end_time TEXT DEFAULT '',
      pause_minutes INTEGER DEFAULT 0,
      note TEXT DEFAULT '',
      status TEXT DEFAULT 'Afventer',
      approved_by TEXT DEFAULT '',
      rejected_by TEXT DEFAULT '',
      calculation_json JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      actor_user_id TEXT DEFAULT '',
      actor_email TEXT DEFAULT '',
      actor_role TEXT DEFAULT '',
      sequence_number BIGINT DEFAULT 0,
      prev_hash TEXT DEFAULT '',
      row_hash TEXT DEFAULT '',
      action TEXT NOT NULL,
      target_type TEXT DEFAULT '',
      target_id TEXT DEFAULT '',
      details_json JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS overtime_rules (
      employee_id TEXT PRIMARY KEY,
      rule_json JSONB DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS payslips (
      id TEXT PRIMARY KEY,
      employee_id TEXT DEFAULT '',
      employee_name TEXT DEFAULT '',
      period TEXT DEFAULT '',
      data_json JSONB DEFAULT '{}'::jsonb,
      created_by TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);


  await query(`
    CREATE TABLE IF NOT EXISTS attachments (
      id TEXT PRIMARY KEY,
      uploader_user_id TEXT DEFAULT '',
      uploader_email TEXT DEFAULT '',
      uploader_role TEXT DEFAULT '',
      original_filename TEXT DEFAULT '',
      mime_type TEXT DEFAULT '',
      file_size INTEGER DEFAULT 0,
      sha256 TEXT DEFAULT '',
      storage_kind TEXT DEFAULT 'postgres_bytea',
      linked_type TEXT DEFAULT '',
      linked_id TEXT DEFAULT '',
      file_data BYTEA NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // 2) Migrations til gamle v1.6.0/v1.6.1 tabeller. Disse koerer foer indexes.
  await addColumnIfMissing('time_entries', 'user_id', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'employee_id', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'employee_name', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'email', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'customer_id', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'customer_name', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'date', "TEXT DEFAULT ''");
  // v1.6.18f: gamle databaser kan have NOT NULL work_date. Vi skriver til begge felter.
  await addColumnIfMissing('time_entries', 'work_date', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'start_time', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'end_time', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'pause_minutes', "INTEGER DEFAULT 0");
  await addColumnIfMissing('time_entries', 'note', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'status', "TEXT DEFAULT 'Afventer'");
  await addColumnIfMissing('time_entries', 'approved_by', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'rejected_by', "TEXT DEFAULT ''");
  await addColumnIfMissing('time_entries', 'calculation_json', "JSONB DEFAULT '{}'::jsonb");
  await addColumnIfMissing('time_entries', 'created_at', 'TIMESTAMPTZ NOT NULL DEFAULT NOW()');
  await addColumnIfMissing('time_entries', 'updated_at', 'TIMESTAMPTZ NOT NULL DEFAULT NOW()');

  await addColumnIfMissing('audit_log', 'actor_user_id', "TEXT DEFAULT ''");
  await addColumnIfMissing('audit_log', 'actor_email', "TEXT DEFAULT ''");
  await addColumnIfMissing('audit_log', 'actor_role', "TEXT DEFAULT ''");
  await addColumnIfMissing('audit_log', 'sequence_number', "BIGINT DEFAULT 0");
  await addColumnIfMissing('audit_log', 'prev_hash', "TEXT DEFAULT ''");
  await addColumnIfMissing('audit_log', 'row_hash', "TEXT DEFAULT ''");
  await addColumnIfMissing('audit_log', 'action', "TEXT DEFAULT ''");
  await addColumnIfMissing('audit_log', 'target_type', "TEXT DEFAULT ''");
  await addColumnIfMissing('audit_log', 'target_id', "TEXT DEFAULT ''");
  await addColumnIfMissing('audit_log', 'details_json', "JSONB DEFAULT '{}'::jsonb");
  // v1.6.10: Gamle Pengedag-databaser kan have disse NOT NULL legacy-kolonner.
  // Vi sikrer dem, og audit()-funktionen skriver til baade nye og gamle kolonnenavne.
  await addColumnIfMissing('audit_log', 'entity_type', "TEXT DEFAULT ''");
  await addColumnIfMissing('audit_log', 'entity_id', "TEXT DEFAULT ''");
  await addColumnIfMissing('audit_log', 'payload', "JSONB DEFAULT '{}'::jsonb");
  await addColumnIfMissing('audit_log', 'created_at', 'TIMESTAMPTZ NOT NULL DEFAULT NOW()');

  await addColumnIfMissing('users', 'employee_id', "TEXT DEFAULT ''");
  await addColumnIfMissing('users', 'name', "TEXT DEFAULT ''");
  await addColumnIfMissing('users', 'active', 'BOOLEAN NOT NULL DEFAULT TRUE');

  await addColumnIfMissing('attachments', 'uploader_user_id', "TEXT DEFAULT ''");
  await addColumnIfMissing('attachments', 'uploader_email', "TEXT DEFAULT ''");
  await addColumnIfMissing('attachments', 'uploader_role', "TEXT DEFAULT ''");
  await addColumnIfMissing('attachments', 'original_filename', "TEXT DEFAULT ''");
  await addColumnIfMissing('attachments', 'mime_type', "TEXT DEFAULT ''");
  await addColumnIfMissing('attachments', 'file_size', 'INTEGER DEFAULT 0');
  await addColumnIfMissing('attachments', 'sha256', "TEXT DEFAULT ''");
  await addColumnIfMissing('attachments', 'storage_kind', "TEXT DEFAULT 'postgres_bytea'");
  await addColumnIfMissing('attachments', 'linked_type', "TEXT DEFAULT ''");
  await addColumnIfMissing('attachments', 'linked_id', "TEXT DEFAULT ''");
  await addColumnIfMissing('attachments', 'created_at', 'TIMESTAMPTZ NOT NULL DEFAULT NOW()');


  // 3) Goer audit log uforanderlig og hash-kaedet.
  // Gamle audit-rows faar hash/sequence foer triggeren laaser UPDATE/DELETE.
  await backfillAuditHashes();
  await installImmutableAuditTrigger();

  // 4) Foerst nu indexes. SafeCreate checker kolonnen foer index.
  await safeCreateIndex('idx_time_entries_user_id', 'time_entries', 'user_id');
  await safeCreateIndex('idx_time_entries_employee_id', 'time_entries', 'employee_id');
  await safeCreateIndex('idx_time_entries_status', 'time_entries', 'status');
  await safeCreateIndex('idx_audit_log_actor_user_id', 'audit_log', 'actor_user_id');
  await safeCreateIndex('idx_audit_log_action', 'audit_log', 'action');
  await safeCreateIndex('idx_audit_log_target_id', 'audit_log', 'target_id');
  await safeCreateIndex('idx_audit_log_sequence_number', 'audit_log', 'sequence_number');
  await safeCreateIndex('idx_audit_log_row_hash', 'audit_log', 'row_hash');
  await safeCreateIndex('idx_attachments_uploader_user_id', 'attachments', 'uploader_user_id');
  await safeCreateIndex('idx_attachments_linked_id', 'attachments', 'linked_id');
  await safeCreateIndex('idx_attachments_sha256', 'attachments', 'sha256');

  console.log('Database migrations OK - Pengedag ' + VERSION);
}

function makeId(prefix) {
  return prefix + '_' + Date.now() + '_' + Math.random().toString(16).slice(2);
}

function stableJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableJson).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + stableJson(value[k])).join(',') + '}';
}

function sha256(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

function buildAuditHash(row) {
  return sha256([
    row.sequence_number || 0,
    row.prev_hash || '',
    row.id || '',
    row.actor_user_id || '',
    row.actor_email || '',
    row.actor_role || '',
    row.action || '',
    row.target_type || '',
    row.target_id || '',
    stableJson(row.details_json || {}),
    row.created_at ? new Date(row.created_at).toISOString() : ''
  ].join('|'));
}

function calcHours(start, end, pauseMinutes) {
  const [sh, sm] = String(start || '00:00').split(':').map(Number);
  const [eh, em] = String(end || '00:00').split(':').map(Number);
  let a = sh * 60 + sm;
  let b = eh * 60 + em;
  if (b < a) b += 24 * 60;
  const minutes = Math.max(0, b - a - (Number(pauseMinutes) || 0));
  return Math.round((minutes / 60) * 100) / 100;
}

async function audit(actor, action, targetType, targetId, details = {}) {
  const latest = await query(`SELECT sequence_number, row_hash FROM audit_log ORDER BY sequence_number DESC, created_at DESC LIMIT 1`);
  const lastSeq = latest.rows.length ? Number(latest.rows[0].sequence_number || 0) : 0;
  const prevHash = latest.rows.length ? (latest.rows[0].row_hash || 'GENESIS') : 'GENESIS';

  const idTypeResult = await query(`
    SELECT data_type, column_default
    FROM information_schema.columns
    WHERE table_name='audit_log' AND column_name='id'
    LIMIT 1
  `);
  const idType = idTypeResult.rows[0]?.data_type || 'text';
  const columnDefault = idTypeResult.rows[0]?.column_default || '';
  const numericId = ['integer', 'bigint', 'smallint', 'numeric'].includes(idType);

  // v1.6.11: Hvis audit_log.id er SERIAL/BIGSERIAL, skal vi kende id'et FOER hash beregnes.
  // Ellers bliver row_hash lavet med id=null, mens verify senere bruger det rigtige id (fx 4),
  // og saa faar vi row_hash_mismatch. Derfor reserverer vi naeste sequence-id selv.
  let preallocatedAuditId = null;
  if (numericId) {
    try {
      const seq = await query(`SELECT pg_get_serial_sequence('audit_log','id') AS seq`);
      const seqName = seq.rows[0]?.seq;
      if (seqName) {
        const next = await query(`SELECT nextval($1::regclass) AS id`, [seqName]);
        preallocatedAuditId = next.rows[0]?.id;
      }
    } catch (e) {
      console.warn('Kunne ikke forud-reservere audit_log.id:', e.message);
    }
  }

  const createdAt = new Date();

  const row = {
    id: numericId ? preallocatedAuditId : makeId('audit'),
    actor_user_id: actor?.id || '',
    actor_email: actor?.email || '',
    actor_role: actor?.role || '',
    sequence_number: lastSeq + 1,
    prev_hash: prevHash,
    action,
    target_type: targetType || '',
    target_id: targetId || '',
    details_json: details || {},
    created_at: createdAt
  };
  row.row_hash = buildAuditHash(row);

  // v1.6.11: Robust INSERT til baade nye og gamle audit_log-skemaer.
  // Nogle gamle databaser har NOT NULL kolonnerne entity_type/entity_id/payload.
  // Derfor bygger vi INSERT dynamisk ud fra de kolonner, databasen faktisk har.
  const colsResult = await query(`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name='audit_log'
  `);
  const existingCols = new Set(colsResult.rows.map(r => r.column_name));

  const data = {
    actor_user_id: row.actor_user_id,
    actor_email: row.actor_email,
    actor_role: row.actor_role,
    sequence_number: row.sequence_number,
    prev_hash: row.prev_hash,
    row_hash: row.row_hash,
    action: row.action,
    target_type: row.target_type,
    target_id: row.target_id,
    details_json: row.details_json,
    // Legacy-kolonner:
    entity_type: row.target_type,
    entity_id: row.target_id,
    payload: row.details_json,
    created_at: createdAt
  };

  if (existingCols.has('id')) {
    if (numericId && preallocatedAuditId !== null && preallocatedAuditId !== undefined) {
      data.id = preallocatedAuditId;
    } else if (!numericId && !columnDefault.includes('nextval')) {
      data.id = row.id;
    }
  }

  const preferredOrder = [
    'id',
    'actor_user_id', 'actor_email', 'actor_role',
    'sequence_number', 'prev_hash', 'row_hash',
    'action',
    'target_type', 'target_id', 'details_json',
    'entity_type', 'entity_id', 'payload',
    'created_at'
  ];

  const insertCols = preferredOrder.filter(c => existingCols.has(c) && Object.prototype.hasOwnProperty.call(data, c));
  const values = insertCols.map(c => data[c]);
  const placeholders = insertCols.map((_, i) => `$${i + 1}`);

  await query(
    `INSERT INTO audit_log (${insertCols.join(', ')}) VALUES (${placeholders.join(', ')})`,
    values
  );
}
function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role, employeeId: user.employee_id || '' }, JWT_SECRET, { expiresIn: '12h' });
}

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return res.status(401).json({ ok: false, error: 'Mangler Bearer token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const r = await query('SELECT id,email,role,employee_id,name,active FROM users WHERE id=$1', [decoded.id]);
    if (!r.rows.length || !r.rows[0].active) return res.status(401).json({ ok: false, error: 'Ugyldig bruger' });
    req.user = r.rows[0];
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: 'Ugyldigt token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ ok: false, error: 'Ikke logget ind' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ ok: false, error: 'Ingen adgang', role: req.user.role });
    next();
  };
}

app.get('/', (req, res) => res.json({ ok: true, app: 'Pengedag Backend PostgreSQL Login', version: VERSION, database: 'postgresql' }));
app.get('/health', async (req, res) => {
  try {
    await query('SELECT 1 AS ok');
    res.json({ ok: true, status: 'healthy', version: VERSION, database: 'connected', time: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ ok: false, status: 'database_error', version: VERSION, error: e.message });
  }
});

app.get('/api/mobile/routes', (req, res) => res.json({ ok: true, version: VERSION, routes: [
  'GET /health', 'POST /api/auth/bootstrap-admin', 'POST /api/auth/login', 'GET /api/auth/me', 'POST /api/auth/change-password', 'POST /api/auth/users',
  'POST /api/mobile/time-entry', 'GET /api/mobile/times', 'GET /api/employee/dashboard', 'POST /api/mobile/time-entries/:id/approve', 'POST /api/mobile/time-entries/:id/reject', 'POST /api/bilag/upload', 'GET /api/bilag', 'GET /api/bilag/:id', 'GET /api/bilag/:id/download', 'GET /api/admin/backup/export', 'POST /api/admin/backup/restore', 'GET /api/admin/revisor/export', 'GET /api/admin/saft/preview', 'GET /api/legal/gdpr', 'GET /api/legal/dpa', 'GET /api/gdpr/my-data', 'GET /api/admin/gdpr/export-user/:userId', 'POST /api/admin/gdpr/record-request', 'GET /api/admin/audit-log', 'GET /api/admin/audit-log/verify', 'GET /api/admin/security/status', 'POST /api/admin/security/record-check'
]}));

app.get('/api/admin/security/status', auth, requireRole('admin','auditor'), async (req, res) => {
  const checks = {
    nodeEnvProduction: process.env.NODE_ENV === 'production',
    jwtSecretStrong: isStrongSecret(process.env.JWT_SECRET || ''),
    databaseUrlPresent: !!DATABASE_URL,
    jsonLimit: JSON_LIMIT,
    globalRateLimit: { windowMs: RATE_LIMIT_WINDOW_MS, max: RATE_LIMIT_MAX },
    loginRateLimit: { windowMs: RATE_LIMIT_WINDOW_MS, max: LOGIN_RATE_LIMIT_MAX },
    securityHeaders: ['X-Content-Type-Options','X-Frame-Options','Referrer-Policy','Permissions-Policy','Strict-Transport-Security'],
    corsLockedToOrigins: !!(process.env.CORS_ORIGINS || '').trim(),
    securityContactEmail: SECURITY_CONTACT_EMAIL
  };
  const warnings = [];
  if (!checks.nodeEnvProduction) warnings.push('NODE_ENV er ikke production');
  if (!checks.jwtSecretStrong) warnings.push('JWT_SECRET boer vaere mindst 32 tegn og ikke standardtekst');
  if (!checks.corsLockedToOrigins) warnings.push('CORS_ORIGINS er ikke sat; API tillader derfor browserkald fra alle origins');
  res.json({ ok: true, version: VERSION, checks, warnings });
});

app.post('/api/admin/security/record-check', auth, requireRole('admin','auditor'), async (req, res) => {
  await audit(req.user, 'SECURITY_CHECK', 'security', req.requestId || 'manual', {
    note: req.body?.note || 'Manuel sikkerhedskontrol',
    ip: clientIp(req),
    userAgent: req.headers['user-agent'] || '',
    version: VERSION
  });
  res.json({ ok: true, message: 'Sikkerhedskontrol skrevet i audit log', requestId: req.requestId });
});

app.post('/api/auth/bootstrap-admin', async (req, res) => {
  const existing = await query("SELECT COUNT(*)::int AS count FROM users WHERE role='admin'");
  if (existing.rows[0].count > 0) return res.status(403).json({ ok: false, error: 'Admin findes allerede' });
  const { email, password, name } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok: false, error: 'email og password kraeves' });
  const id = makeId('usr');
  const hash = await bcrypt.hash(password, 12);
  await query('INSERT INTO users (id,email,password_hash,role,name) VALUES ($1,$2,$3,$4,$5)', [id, email.toLowerCase(), hash, 'admin', name || 'Admin']);
  await audit({ id, email }, 'bootstrap_admin', 'user', id, { email });
  res.json({ ok: true, user: { id, email: email.toLowerCase(), role: 'admin', name: name || 'Admin' }, token: signToken({ id, email: email.toLowerCase(), role: 'admin', employee_id: '' }) });
});

app.post('/api/auth/login', makeRateLimiter('login', LOGIN_RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS), async (req, res) => {
  const { email, password } = req.body || {};
  const r = await query('SELECT * FROM users WHERE email=$1', [String(email || '').toLowerCase()]);
  if (!r.rows.length) return res.status(401).json({ ok: false, error: 'Forkert login' });
  const user = r.rows[0];
  const ok = await bcrypt.compare(password || '', user.password_hash);
  if (!ok) return res.status(401).json({ ok: false, error: 'Forkert login' });
  await audit(user, 'login', 'user', user.id, {});
  res.json({ ok: true, user: { id: user.id, email: user.email, role: user.role, employeeId: user.employee_id, name: user.name }, token: signToken(user) });
});

app.get('/api/auth/me', auth, (req, res) => res.json({ ok: true, user: req.user }));

app.post('/api/auth/change-password', auth, makeRateLimiter('change-password', 8, RATE_LIMIT_WINDOW_MS), async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body || {};
  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ ok: false, error: 'Nuværende adgangskode, ny adgangskode og gentagelse kræves' });
  }
  if (String(newPassword) !== String(confirmPassword)) {
    return res.status(400).json({ ok: false, error: 'Ny adgangskode og gentagelse er ikke ens' });
  }
  if (String(newPassword).length < 12) {
    return res.status(400).json({ ok: false, error: 'Ny adgangskode skal være mindst 12 tegn' });
  }
  if (String(newPassword) === String(currentPassword)) {
    return res.status(400).json({ ok: false, error: 'Ny adgangskode må ikke være den samme som den gamle' });
  }
  const weak = ['password', 'adgangskode', '123456', 'pengedag'];
  const lowered = String(newPassword).toLowerCase();
  if (weak.some(w => lowered === w || lowered.includes(w + '123'))) {
    return res.status(400).json({ ok: false, error: 'Ny adgangskode er for svag' });
  }
  const r = await query('SELECT * FROM users WHERE id=$1', [req.user.id]);
  if (!r.rows.length) return res.status(401).json({ ok: false, error: 'Bruger findes ikke' });
  const user = r.rows[0];
  const ok = await bcrypt.compare(String(currentPassword), user.password_hash);
  if (!ok) {
    await audit(req.user, 'CHANGE_PASSWORD_FAILED', 'user', req.user.id, { reason: 'wrong_current_password', ip: clientIp(req), requestId: req.requestId });
    return res.status(401).json({ ok: false, error: 'Nuværende adgangskode er forkert' });
  }
  const newHash = await bcrypt.hash(String(newPassword), 12);
  await query('UPDATE users SET password_hash=$1 WHERE id=$2', [newHash, req.user.id]);
  await audit(req.user, 'CHANGE_PASSWORD', 'user', req.user.id, { email: req.user.email, role: req.user.role, ip: clientIp(req), requestId: req.requestId });
  res.json({ ok: true, message: 'Adgangskode er ændret. Log ind igen med den nye adgangskode.', requestId: req.requestId });
});


app.post('/api/auth/users', auth, requireRole('admin', 'owner'), async (req, res) => {
  const { email, password, role, employeeId, name } = req.body || {};
  const allowed = ['admin', 'owner', 'employee', 'auditor'];
  if (!email || !password || !allowed.includes(role)) return res.status(400).json({ ok: false, error: 'email, password og gyldig role kraeves' });
  const id = makeId('usr');
  const hash = await bcrypt.hash(password, 12);
  await query('INSERT INTO users (id,email,password_hash,role,employee_id,name) VALUES ($1,$2,$3,$4,$5,$6)', [id, email.toLowerCase(), hash, role, employeeId || '', name || '']);
  await audit(req.user, 'create_user', 'user', id, { email, role, employeeId, name });
  res.json({ ok: true, user: { id, email: email.toLowerCase(), role, employeeId: employeeId || '', name: name || '' } });
});

app.post(['/api/mobile/time-entry','/api/mobile/time-entries','/api/mobile/times','/api/mobile/timesheets','/api/mobile/entries'], auth, async (req, res) => {
  try {
    const body = req.body || {};
    const id = makeId('mob');
    const employeeId = String(body.employeeId || body.employee_id || req.user.employee_id || '').trim();

    if (!employeeId) {
      return res.status(400).json({ ok: false, error: 'employeeId mangler', requestId: req.requestId });
    }

    if (req.user.role === 'employee' && req.user.employee_id && employeeId !== req.user.employee_id) {
      return res.status(403).json({ ok: false, error: 'Medarbejder kan kun sende egne timer', requestId: req.requestId });
    }

    const employeeName = String(body.employeeName || body.employee_name || req.user.name || '').trim();
    const date = String(body.date || '').trim();
    const start = String(body.start || body.startTime || body.start_time || '').trim();
    const end = String(body.end || body.endTime || body.end_time || '').trim();
    const pauseMinutes = Number(body.pauseMinutes ?? body.pause_minutes ?? 0) || 0;

    if (!date || !start || !end) {
      return res.status(400).json({ ok: false, error: 'Dato, start og slut skal udfyldes', requestId: req.requestId });
    }

    const hours = calcHours(start, end, pauseMinutes);
    const calc = { hours, normalHours: hours, overtimeHours: 0 };

    await query(`INSERT INTO time_entries (id,user_id,employee_id,employee_name,email,customer_id,customer_name,date,work_date,start_time,end_time,pause_minutes,note,status,calculation_json)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb)`,
      [
        id,
        req.user.id || '',
        employeeId,
        employeeName,
        String(body.email || req.user.email || ''),
        String(body.customerId || body.customer_id || ''),
        String(body.customerName || body.customer_name || ''),
        date,
        date,
        start,
        end,
        pauseMinutes,
        String(body.note || ''),
        'Afventer',
        JSON.stringify(calc)
      ]
    );

    await audit(req.user, 'CREATE_TIME_ENTRY', 'time_entry', id, { employeeId, employeeName, date, start, end, pauseMinutes, hours, requestId: req.requestId });

    return res.json({
      ok: true,
      entry: { id, employeeId, employeeName, date, start, end, pauseMinutes, note: String(body.note || ''), status: 'Afventer', calculation: calc },
      requestId: req.requestId
    });
  } catch (e) {
    console.error('TIME_ENTRY_CREATE_FAILED', { requestId: req.requestId, error: e.message, stack: e.stack });
    return res.status(500).json({ ok: false, error: 'Opret time fejlede', details: e.message, requestId: req.requestId });
  }
});

app.get(['/api/mobile/times','/api/mobile/time-entries','/api/mobile/timesheets','/api/mobile/entries'], auth, async (req, res) => {
  let r;
  if (req.user.role === 'employee') {
    r = await query('SELECT * FROM time_entries WHERE user_id=$1 OR employee_id=$2 ORDER BY created_at DESC LIMIT 200', [req.user.id, req.user.employee_id || '']);
  } else {
    r = await query('SELECT * FROM time_entries ORDER BY created_at DESC LIMIT 200');
  }
  const entries = r.rows.map(x => ({
    id: x.id, employeeId: x.employee_id, employeeName: x.employee_name, email: x.email,
    customerId: x.customer_id, customerName: x.customer_name, date: x.date, start: x.start_time, end: x.end_time,
    pauseMinutes: x.pause_minutes, note: x.note, status: x.status, calculation: x.calculation_json, createdAt: x.created_at
  }));
  res.json({ ok: true, count: entries.length, entries });
});


app.get('/api/employee/dashboard', auth, async (req, res) => {
  // Samlet endpoint til medarbejder-dashboardet. Medarbejdere ser kun egne data.
  let timeRows;
  if (req.user.role === 'employee') {
    timeRows = await query('SELECT * FROM time_entries WHERE user_id=$1 OR employee_id=$2 ORDER BY created_at DESC LIMIT 200', [req.user.id, req.user.employee_id || '']);
  } else {
    timeRows = await query('SELECT * FROM time_entries ORDER BY created_at DESC LIMIT 200');
  }

  const timeIds = timeRows.rows.map(x => x.id);
  let attachmentRows = { rows: [] };
  if (timeIds.length) {
    attachmentRows = await query(`SELECT id,original_filename,mime_type,file_size,sha256,linked_type,linked_id,created_at
      FROM attachments
      WHERE linked_type='time_entry' AND linked_id = ANY($1::text[])
      ORDER BY created_at DESC LIMIT 200`, [timeIds]);
  }

  const entries = timeRows.rows.map(x => ({
    id: x.id,
    employeeId: x.employee_id,
    employeeName: x.employee_name,
    date: x.date,
    start: x.start_time,
    end: x.end_time,
    pauseMinutes: x.pause_minutes,
    note: x.note,
    status: x.status,
    calculation: x.calculation_json,
    createdAt: x.created_at
  }));

  const attachments = attachmentRows.rows.map(x => ({
    id: x.id,
    filename: x.original_filename,
    mimeType: x.mime_type,
    fileSize: x.file_size,
    sha256: x.sha256,
    linkedType: x.linked_type,
    linkedId: x.linked_id,
    createdAt: x.created_at
  }));

  res.json({
    ok: true,
    user: { id: req.user.id, email: req.user.email, role: req.user.role, employeeId: req.user.employee_id || '', name: req.user.name || '' },
    summary: {
      timeEntries: entries.length,
      attachments: attachments.length,
      pending: entries.filter(x => x.status === 'Afventer').length,
      approved: entries.filter(x => x.status === 'Godkendt').length,
      rejected: entries.filter(x => x.status === 'Afvist').length
    },
    entries,
    attachments
  });
});

app.post('/api/mobile/time-entries/:id/approve', auth, requireRole('admin','owner'), async (req, res) => {
  await query("UPDATE time_entries SET status='Godkendt', approved_by=$2, updated_at=NOW() WHERE id=$1", [req.params.id, req.user.id]);
  await audit(req.user, 'approve_time_entry', 'time_entry', req.params.id, {});
  res.json({ ok: true, id: req.params.id, status: 'Godkendt' });
});

app.post('/api/mobile/time-entries/:id/reject', auth, requireRole('admin','owner'), async (req, res) => {
  await query("UPDATE time_entries SET status='Afvist', rejected_by=$2, updated_at=NOW() WHERE id=$1", [req.params.id, req.user.id]);
  await audit(req.user, 'reject_time_entry', 'time_entry', req.params.id, { reason: req.body?.reason || '' });
  res.json({ ok: true, id: req.params.id, status: 'Afvist' });
});

app.get('/api/admin/audit-log', auth, requireRole('admin','auditor'), async (req, res) => {
  const r = await query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 300');
  res.json({ ok: true, count: r.rows.length, entries: r.rows });
});


app.get('/api/admin/audit-log/verify', auth, requireRole('admin','auditor'), async (req, res) => {
  const r = await query('SELECT * FROM audit_log ORDER BY sequence_number ASC, created_at ASC, id ASC');
  let previousHash = 'GENESIS';
  const problems = [];
  for (const row of r.rows) {
    const seq = Number(row.sequence_number || 0);
    if (!row.row_hash || !row.prev_hash || !seq) {
      problems.push({ id: row.id, problem: 'missing_hash_fields' });
      continue;
    }
    if (row.prev_hash !== previousHash) {
      problems.push({ id: row.id, sequenceNumber: seq, problem: 'prev_hash_mismatch' });
    }
    const expected = buildAuditHash({
      ...row,
      sequence_number: seq,
      details_json: row.details_json || {},
      created_at: row.created_at
    });
    if (expected !== row.row_hash) {
      problems.push({ id: row.id, sequenceNumber: seq, problem: 'row_hash_mismatch' });
    }
    previousHash = row.row_hash;
  }
  res.json({
    ok: problems.length === 0,
    immutable: true,
    checkedRows: r.rows.length,
    problems,
    message: problems.length === 0 ? 'Audit log hash-kaede er OK' : 'Audit log har afvigelser'
  });
});


const ALLOWED_ATTACHMENT_TYPES = new Set(['time_entry', 'invoice', 'payslip', 'employee', 'customer', 'other']);
const ALLOWED_MIME_TYPES = new Set(['application/pdf', 'image/jpeg', 'image/png', 'image/webp', 'text/plain']);
const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;

function extractBase64File(input) {
  let raw = String(input || '');
  const match = raw.match(/^data:([^;]+);base64,(.*)$/);
  if (match) return { mimeFromDataUrl: match[1], base64: match[2] };
  return { mimeFromDataUrl: '', base64: raw };
}

async function canAccessAttachment(user, attachment) {
  if (!user || !attachment) return false;
  if (['admin', 'owner', 'auditor'].includes(user.role)) return true;
  if (attachment.uploader_user_id === user.id) return true;
  if (user.role === 'employee' && attachment.linked_type === 'time_entry' && attachment.linked_id) {
    const r = await query('SELECT id FROM time_entries WHERE id=$1 AND (user_id=$2 OR employee_id=$3) LIMIT 1', [attachment.linked_id, user.id, user.employee_id || '']);
    return r.rows.length > 0;
  }
  return false;
}

app.post('/api/bilag/upload', auth, async (req, res) => {
  const body = req.body || {};
  const filename = String(body.filename || body.originalFilename || 'bilag').replace(/[\\/]/g, '_').slice(0, 180);
  const linkedType = String(body.linkedType || body.linked_type || body.type || 'other');
  const linkedId = String(body.linkedId || body.linked_id || body.entityId || '');
  const { mimeFromDataUrl, base64 } = extractBase64File(body.fileBase64 || body.base64 || body.data || '');
  const mimeType = String(body.mimeType || body.mime_type || mimeFromDataUrl || 'application/octet-stream');

  if (!base64) return res.status(400).json({ ok: false, error: 'fileBase64 mangler' });
  if (!ALLOWED_ATTACHMENT_TYPES.has(linkedType)) return res.status(400).json({ ok: false, error: 'Ugyldig linkedType', allowed: Array.from(ALLOWED_ATTACHMENT_TYPES) });
  if (!ALLOWED_MIME_TYPES.has(mimeType)) return res.status(400).json({ ok: false, error: 'Filtype er ikke tilladt', mimeType, allowed: Array.from(ALLOWED_MIME_TYPES) });

  let buffer;
  try {
    buffer = Buffer.from(base64, 'base64');
  } catch (e) {
    return res.status(400).json({ ok: false, error: 'Ugyldig base64-fil' });
  }
  if (!buffer.length) return res.status(400).json({ ok: false, error: 'Tom fil' });
  if (buffer.length > MAX_ATTACHMENT_BYTES) return res.status(413).json({ ok: false, error: 'Bilag er for stort', maxBytes: MAX_ATTACHMENT_BYTES });

  // Medarbejder maa kun knytte bilag til egne timer.
  if (req.user.role === 'employee' && linkedType === 'time_entry' && linkedId) {
    const r = await query('SELECT id FROM time_entries WHERE id=$1 AND (user_id=$2 OR employee_id=$3) LIMIT 1', [linkedId, req.user.id, req.user.employee_id || '']);
    if (!r.rows.length) return res.status(403).json({ ok: false, error: 'Medarbejder kan kun uploade bilag til egne timer' });
  }

  const id = makeId('bilag');
  const hash = sha256(buffer);
  await query(`INSERT INTO attachments
    (id,uploader_user_id,uploader_email,uploader_role,original_filename,mime_type,file_size,sha256,storage_kind,linked_type,linked_id,file_data)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [id, req.user.id, req.user.email, req.user.role, filename, mimeType, buffer.length, hash, 'postgres_bytea', linkedType, linkedId, buffer]
  );
  try {
    await audit(req.user, 'CREATE_BILAG', 'bilag', id, { filename, mimeType, fileSize: buffer.length, sha256: hash, linkedType, linkedId, storageKind: 'postgres_bytea' });
  } catch (e) {
    console.error('KRITISK: Bilag blev gemt, men audit-log fejlede:', e.message);
    return res.status(500).json({ ok: false, error: 'Bilag blev gemt, men audit-log fejlede', auditError: e.message, attachmentId: id });
  }
  res.json({ ok: true, attachment: { id, filename, mimeType, fileSize: buffer.length, sha256: hash, linkedType, linkedId, storageKind: 'postgres_bytea' } });
});

app.get('/api/bilag', auth, async (req, res) => {
  const linkedType = String(req.query.linkedType || req.query.linked_type || '');
  const linkedId = String(req.query.linkedId || req.query.linked_id || '');
  const params = [];
  let where = 'WHERE 1=1';
  if (linkedType) { params.push(linkedType); where += ` AND linked_type=$${params.length}`; }
  if (linkedId) { params.push(linkedId); where += ` AND linked_id=$${params.length}`; }

  if (req.user.role === 'employee') {
    params.push(req.user.id); const pUser = params.length;
    params.push(req.user.employee_id || ''); const pEmp = params.length;
    where += ` AND (uploader_user_id=$${pUser} OR (linked_type='time_entry' AND linked_id IN (SELECT id FROM time_entries WHERE user_id=$${pUser} OR employee_id=$${pEmp})))`;
  }

  const r = await query(`SELECT id,uploader_user_id,uploader_email,uploader_role,original_filename,mime_type,file_size,sha256,storage_kind,linked_type,linked_id,created_at FROM attachments ${where} ORDER BY created_at DESC LIMIT 300`, params);
  res.json({ ok: true, count: r.rows.length, attachments: r.rows.map(x => ({
    id: x.id, uploaderUserId: x.uploader_user_id, uploaderEmail: x.uploader_email, uploaderRole: x.uploader_role,
    filename: x.original_filename, mimeType: x.mime_type, fileSize: x.file_size, sha256: x.sha256,
    storageKind: x.storage_kind, linkedType: x.linked_type, linkedId: x.linked_id, createdAt: x.created_at
  })) });
});

app.get('/api/bilag/:id', auth, async (req, res) => {
  const r = await query('SELECT id,uploader_user_id,uploader_email,uploader_role,original_filename,mime_type,file_size,sha256,storage_kind,linked_type,linked_id,created_at FROM attachments WHERE id=$1', [req.params.id]);
  if (!r.rows.length) return res.status(404).json({ ok: false, error: 'Bilag ikke fundet' });
  if (!(await canAccessAttachment(req.user, r.rows[0]))) return res.status(403).json({ ok: false, error: 'Ingen adgang til bilag' });
  const x = r.rows[0];
  res.json({ ok: true, attachment: {
    id: x.id, uploaderUserId: x.uploader_user_id, uploaderEmail: x.uploader_email, uploaderRole: x.uploader_role,
    filename: x.original_filename, mimeType: x.mime_type, fileSize: x.file_size, sha256: x.sha256,
    storageKind: x.storage_kind, linkedType: x.linked_type, linkedId: x.linked_id, createdAt: x.created_at
  }});
});

app.get('/api/bilag/:id/download', auth, async (req, res) => {
  const r = await query('SELECT * FROM attachments WHERE id=$1', [req.params.id]);
  if (!r.rows.length) return res.status(404).json({ ok: false, error: 'Bilag ikke fundet' });
  const x = r.rows[0];
  if (!(await canAccessAttachment(req.user, x))) return res.status(403).json({ ok: false, error: 'Ingen adgang til bilag' });
  await audit(req.user, 'DOWNLOAD_BILAG', 'bilag', x.id, { filename: x.original_filename, linkedType: x.linked_type, linkedId: x.linked_id });
  res.setHeader('Content-Type', x.mime_type || 'application/octet-stream');
  res.setHeader('Content-Length', x.file_size || x.file_data.length);
  res.setHeader('Content-Disposition', `attachment; filename="${String(x.original_filename || 'bilag').replace(/"/g, '')}"`);
  res.send(x.file_data);
});



// v1.6.13: Revisor-eksport / SAF-T-forberedelse
// Vigtigt: Dette er SAF-T-FORBEREDELSE, ikke en officiel Erhvervsstyrelsen-godkendt SAF-T fil.
// Formaal: give revisor en samlet, kontrollerbar eksport med timer, bilag, loensedler, regler og audit-log.
function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (/[";\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

function toCsv(rows, columns) {
  const header = columns.map(c => csvEscape(c.label || c.key)).join(';');
  const body = rows.map(row => columns.map(c => csvEscape(typeof c.value === 'function' ? c.value(row) : row[c.key])).join(';')).join('\n');
  return header + (body ? '\n' + body : '');
}

function safeDateOnly(value) {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toISOString().slice(0, 10);
}

function calcHoursForExport(row) {
  if (row.hours !== undefined && row.hours !== null && row.hours !== '') return Number(row.hours) || 0;
  const start = String(row.start_time || row.start || '');
  const end = String(row.end_time || row.end || '');
  const pause = Number(row.pause_minutes || row.pauseMinutes || 0) || 0;
  const m = (t) => {
    const parts = String(t).split(':').map(Number);
    if (parts.length < 2 || Number.isNaN(parts[0]) || Number.isNaN(parts[1])) return null;
    return parts[0] * 60 + parts[1];
  };
  const a = m(start), b = m(end);
  if (a === null || b === null) return 0;
  let diff = b - a;
  if (diff < 0) diff += 24 * 60;
  diff -= pause;
  return Math.max(0, Math.round((diff / 60) * 100) / 100);
}

async function buildRevisorExport(reqUser) {
  const data = await readAllForBackup();
  const exportId = makeId('revisor_export');
  const exportedAt = new Date().toISOString();

  const timeEntries = data.time_entries || [];
  const attachments = data.attachments || [];
  const payslips = data.payslips || [];
  const overtimeRules = data.overtime_rules || [];
  const auditRows = data.audit_log_readonly || [];

  const attachmentsByLinkedId = {};
  for (const a of attachments) {
    const key = String(a.linked_type || '') + ':' + String(a.linked_id || '');
    if (!attachmentsByLinkedId[key]) attachmentsByLinkedId[key] = [];
    attachmentsByLinkedId[key].push({ id: a.id, filename: a.original_filename, sha256: a.sha256, file_size: a.file_size });
  }

  const timeRows = timeEntries.map(t => ({
    id: t.id,
    date: safeDateOnly(t.date),
    employee_id: t.employee_id || t.employeeId || '',
    employee_name: t.employee_name || t.employeeName || '',
    start: t.start_time || t.start || '',
    end: t.end_time || t.end || '',
    pause_minutes: t.pause_minutes || t.pauseMinutes || 0,
    hours: calcHoursForExport(t),
    status: t.status || '',
    note: t.note || '',
    attachments: attachmentsByLinkedId['time_entry:' + t.id] || []
  }));

  const summary = {
    totalTimeEntries: timeRows.length,
    totalHours: Math.round(timeRows.reduce((sum, x) => sum + (Number(x.hours) || 0), 0) * 100) / 100,
    totalAttachments: attachments.length,
    totalPayslips: payslips.length,
    totalOvertimeRules: overtimeRules.length,
    totalAuditRows: auditRows.length,
    employees: Array.from(new Set(timeRows.map(x => x.employee_id).filter(Boolean))).length
  };

  const files = {
    'README_REVISOR.txt': [
      'Pengedag revisor-eksport',
      'Eksport-id: ' + exportId,
      'Eksporteret: ' + exportedAt,
      'Backend: ' + VERSION,
      '',
      'Indhold:',
      '- manifest.json: teknisk manifest, hash og optaellinger',
      '- time_entries.csv: timesedler/timer',
      '- attachments_index.csv: bilagsoversigt med SHA-256',
      '- payslips.csv: loensedler',
      '- overtime_rules.csv: overtidsregler',
      '- audit_log.csv: immutable rettelseslog',
      '- saft_preparation.json: SAF-T-forberedende datastruktur',
      '',
      'Bemærk: Dette er SAF-T-forberedelse og revisorpakke, ikke en officiel SAF-T XML-fil.'
    ].join('\n'),
    'time_entries.csv': toCsv(timeRows, [
      { key: 'id' }, { key: 'date' }, { key: 'employee_id' }, { key: 'employee_name' },
      { key: 'start' }, { key: 'end' }, { key: 'pause_minutes' }, { key: 'hours' }, { key: 'status' }, { key: 'note' },
      { key: 'attachments', value: r => (r.attachments || []).map(a => a.id + ':' + a.filename).join('|') }
    ]),
    'attachments_index.csv': toCsv(attachments, [
      { key: 'id' }, { key: 'original_filename', label: 'filename' }, { key: 'mime_type' }, { key: 'file_size' },
      { key: 'sha256' }, { key: 'storage_kind' }, { key: 'linked_type' }, { key: 'linked_id' },
      { key: 'uploader_email' }, { key: 'uploader_role' }, { key: 'created_at' }
    ]),
    'payslips.csv': toCsv(payslips, [
      { key: 'id' }, { key: 'employee_id' }, { key: 'period_start' }, { key: 'period_end' },
      { key: 'gross_pay' }, { key: 'net_pay' }, { key: 'created_at' }
    ]),
    'overtime_rules.csv': toCsv(overtimeRules, [
      { key: 'employee_id' }, { key: 'normal_rate' }, { key: 'overtime_rate' }, { key: 'customer_rate' }, { key: 'vat_percent' }, { key: 'updated_at' }
    ]),
    'audit_log.csv': toCsv(auditRows, [
      { key: 'sequence_number' }, { key: 'id' }, { key: 'created_at' }, { key: 'action' },
      { key: 'actor_email' }, { key: 'actor_role' }, { key: 'target_type' }, { key: 'target_id' },
      { key: 'prev_hash' }, { key: 'row_hash' }
    ])
  };

  const saftPreparation = {
    notice: 'SAF-T-forberedelse: strukturerede data til revisor/videre konvertering. Ikke officiel SAF-T XML.',
    company: { system: 'Pengedag', backendVersion: VERSION },
    sourceDocuments: {
      timeEntries: timeRows,
      attachmentsIndex: attachments.map(a => ({ id: a.id, filename: a.original_filename, sha256: a.sha256, linkedType: a.linked_type, linkedId: a.linked_id })),
      payslips,
      overtimeRules,
      auditLog: auditRows.map(a => ({ sequence_number: a.sequence_number, id: a.id, action: a.action, target_type: a.target_type, target_id: a.target_id, actor_email: a.actor_email, actor_role: a.actor_role, created_at: a.created_at, prev_hash: a.prev_hash, row_hash: a.row_hash }))
    },
    controlTotals: summary
  };

  const manifest = {
    app: 'Pengedag',
    exportType: 'revisor_saft_preparation',
    exportId,
    backendVersion: VERSION,
    exportedAt,
    exportedBy: { id: reqUser.id, email: reqUser.email, role: reqUser.role },
    counts: summary,
    files: Object.keys(files).concat(['manifest.json', 'saft_preparation.json']),
    legalNote: 'Dette er en revisor-eksport og SAF-T-forberedelse, ikke en officiel godkendelse eller officiel SAF-T XML-fil.'
  };

  const packageWithoutHashes = { manifest, files, saft_preparation: saftPreparation };
  const packageHash = sha256(stableJson(packageWithoutHashes));
  manifest.sha256 = packageHash;
  files['manifest.json'] = JSON.stringify(manifest, null, 2);
  files['saft_preparation.json'] = JSON.stringify(saftPreparation, null, 2);

  return { manifest, files, saft_preparation: saftPreparation };
}

app.get('/api/admin/revisor/export', auth, requireRole('admin','owner','auditor'), async (req, res) => {
  const pkg = await buildRevisorExport(req.user);
  await audit(req.user, 'CREATE_REVISOR_EXPORT', 'revisor_export', pkg.manifest.exportId, { exportId: pkg.manifest.exportId, counts: pkg.manifest.counts, sha256: pkg.manifest.sha256 });
  res.json({ ok: true, revisorExport: pkg });
});

app.get('/api/admin/saft/preview', auth, requireRole('admin','owner','auditor'), async (req, res) => {
  const pkg = await buildRevisorExport(req.user);
  await audit(req.user, 'CREATE_SAFT_PREVIEW', 'saft_preparation', pkg.manifest.exportId, { exportId: pkg.manifest.exportId, counts: pkg.manifest.counts, sha256: pkg.manifest.sha256 });
  res.json({ ok: true, notice: 'SAF-T-forberedelse - ikke officiel SAF-T XML', manifest: pkg.manifest, saft_preparation: pkg.saft_preparation });
});


// v1.6.14: GDPR / DPA / dokumentation
// Formaal: give klar dokumentation, datakort, brugerdata-eksport og audit-log for GDPR-handlinger.
// Bemærk: Dette er teknisk GDPR-understøttelse og dokumentationskladder - ikke juridisk rådgivning.
function gdprDocument() {
  return {
    title: 'Pengedag GDPR-dokumentation',
    version: VERSION,
    status: 'Kladde til drift og revisor/partnergennemgang',
    generatedAt: new Date().toISOString(),
    controller: {
      name: 'Pengedag-kunden / virksomheden der bruger systemet',
      role: 'Dataansvarlig'
    },
    processor: {
      name: 'Pengedag',
      role: 'Databehandler / teknisk systemleverandoer'
    },
    purpose: [
      'Registrering af arbejdstid og godkendelse',
      'Forberedelse af loensedler og fakturagrundlag',
      'Bilagsopbevaring og dokumentation',
      'Revisor-eksport og teknisk kontrolspor',
      'Sikker drift, fejlfinding og adgangsstyring'
    ],
    dataCategories: [
      { category: 'Brugere', examples: ['navn', 'email', 'rolle', 'medarbejder-id', 'aktiv-status'] },
      { category: 'Timer', examples: ['dato', 'start/slut', 'pause', 'timer', 'status', 'note'] },
      { category: 'Bilag', examples: ['filnavn', 'mime-type', 'filstoerrelse', 'SHA-256 hash', 'filindhold i PostgreSQL BYTEA', 'tilknytning'] },
      { category: 'Loensedler', examples: ['periode', 'medarbejder', 'loenseddeldata_json'] },
      { category: 'Audit log', examples: ['handling', 'rolle', 'email', 'target', 'hash-kaede', 'tidspunkt'] }
    ],
    securityMeasures: [
      'Login med JWT-token',
      'Rollebaseret adgang: admin, owner, employee, auditor',
      'PostgreSQL database',
      'Bilag med SHA-256 fil-hash',
      'Immutable audit-log med hash-kaede',
      'Backup/export og revisor-export skrives i audit log',
      'Restore overskriver ikke eksisterende id’er og sletter ikke live data'
    ],
    retentionDraft: {
      timeEntries: 'Efter kundens lovpligtige opbevaringskrav og interne politik',
      attachments: 'Efter kundens lovpligtige opbevaringskrav og interne politik',
      auditLog: 'Boer opbevares som kontrolspor og ikke slettes uden dokumenteret hjemmel',
      inactiveUsers: 'Boer kunne deaktiveres og evt. anonymiseres efter politik'
    },
    dataSubjectRightsSupported: [
      'Eksport af egne brugerdata via /api/gdpr/my-data',
      'Admin/revisor eksport af brugerdata via /api/admin/gdpr/export-user/:userId',
      'Registrering af GDPR-anmodning via /api/admin/gdpr/record-request',
      'Alle GDPR-handlinger skrives i immutable audit log'
    ],
    disclaimer: 'Dette er teknisk dokumentation og en driftskladde. Endelig GDPR-tekst/DPA boer gennemgaas af ansvarlig virksomhed og evt. juridisk raadgiver.'
  };
}

function dpaDocument() {
  return {
    title: 'Pengedag Databehandleraftale - DPA kladde',
    version: VERSION,
    generatedAt: new Date().toISOString(),
    parties: {
      controller: 'Kunden / virksomheden der bruger Pengedag',
      processor: 'Pengedag / systemleverandoer'
    },
    clauses: [
      { section: 'Formaal', text: 'Databehandleren behandler personoplysninger for at levere timer, bilag, loensedler, revisor-eksport, backup og adgangsstyring.' },
      { section: 'Instruks', text: 'Databehandleren maa kun behandle data efter kundens dokumenterede instruks og til drift af Pengedag.' },
      { section: 'Fortrolighed', text: 'Adgang til data skal begraenses til relevante roller og driftsbehov.' },
      { section: 'Sikkerhed', text: 'Systemet bruger rollebaseret adgang, audit-log, hash-kontrol, PostgreSQL og login-token.' },
      { section: 'Underleverandoerer', text: 'Hosting/database og eventuelle tredjepartsleverandoerer skal listes og godkendes efter kundens aftale.' },
      { section: 'Bistand', text: 'Systemet understoetter dataeksport, revisor-eksport og registrering af GDPR-anmodninger.' },
      { section: 'Sletning/returnering', text: 'Ved aftalens ophoer skal data kunne eksporteres og derefter slettes/anonymiseres efter kundens instruks.' },
      { section: 'Dokumentation', text: 'Audit-log og eksportfunktioner kan bruges som teknisk dokumentation for handlinger.' }
    ],
    disclaimer: 'DPA-kladden er ikke juridisk rådgivning og skal tilpasses den konkrete virksomhed og underleverandoerer.'
  };
}

function redactUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    role: row.role,
    employee_id: row.employee_id || '',
    name: row.name || '',
    active: !!row.active,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

async function buildUserDataExport(userId) {
  const userR = await query('SELECT id,email,role,employee_id,name,active,created_at,updated_at FROM users WHERE id=$1', [userId]);
  if (!userR.rows.length) return null;
  const u = userR.rows[0];
  const employeeId = u.employee_id || '';

  const timeEntries = employeeId
    ? await query('SELECT * FROM time_entries WHERE employee_id=$1 ORDER BY created_at ASC, id ASC', [employeeId])
    : { rows: [] };

  const attachments = await query(`
    SELECT id,uploader_user_id,uploader_email,uploader_role,original_filename,mime_type,file_size,sha256,storage_kind,linked_type,linked_id,created_at
    FROM attachments
    WHERE uploader_user_id=$1 OR uploader_email=$2 OR linked_id IN (SELECT id FROM time_entries WHERE employee_id=$3)
    ORDER BY created_at ASC, id ASC
  `, [u.id, u.email, employeeId]);

  const payslips = employeeId
    ? await query('SELECT * FROM payslips WHERE employee_id=$1 ORDER BY created_at ASC, id ASC', [employeeId])
    : { rows: [] };

  const auditRows = await query(`
    SELECT * FROM audit_log
    WHERE actor_user_id=$1 OR actor_email=$2 OR target_id=$1 OR target_id IN (SELECT id FROM time_entries WHERE employee_id=$3)
    ORDER BY sequence_number ASC, created_at ASC, id ASC
  `, [u.id, u.email, employeeId]);

  const exportData = {
    exportType: 'gdpr_user_data_export',
    generatedAt: new Date().toISOString(),
    subject: redactUser(u),
    data: {
      user: redactUser(u),
      time_entries: timeEntries.rows,
      attachments_index: attachments.rows,
      payslips: payslips.rows,
      audit_log_related: auditRows.rows
    },
    note: 'Bilagsfilindhold er ikke inkluderet her; bilag kan downloades via bilag-download med adgangskontrol.'
  };
  exportData.sha256 = sha256(stableJson(exportData));
  return exportData;
}

app.get('/api/legal/gdpr', (req, res) => {
  res.json({ ok: true, gdpr: gdprDocument() });
});

app.get('/api/legal/dpa', (req, res) => {
  res.json({ ok: true, dpa: dpaDocument() });
});

app.get('/api/gdpr/my-data', auth, async (req, res) => {
  const data = await buildUserDataExport(req.user.id);
  if (!data) return res.status(404).json({ ok: false, error: 'Bruger ikke fundet' });
  await audit(req.user, 'GDPR_EXPORT_MY_DATA', 'user', req.user.id, { sha256: data.sha256, email: req.user.email });
  res.json({ ok: true, export: data });
});

app.get('/api/admin/gdpr/export-user/:userId', auth, requireRole('admin','owner','auditor'), async (req, res) => {
  const data = await buildUserDataExport(req.params.userId);
  if (!data) return res.status(404).json({ ok: false, error: 'Bruger ikke fundet' });
  await audit(req.user, 'GDPR_EXPORT_USER_DATA', 'user', req.params.userId, { sha256: data.sha256, subjectEmail: data.subject.email });
  res.json({ ok: true, export: data });
});

app.post('/api/admin/gdpr/record-request', auth, requireRole('admin','owner'), async (req, res) => {
  const requestType = String(req.body?.requestType || '').trim() || 'unspecified';
  const subjectUserId = String(req.body?.subjectUserId || '').trim();
  const subjectEmail = String(req.body?.subjectEmail || '').trim();
  const status = String(req.body?.status || 'received').trim();
  const note = String(req.body?.note || '').trim();
  const requestId = makeId('gdpr_req');
  const record = { requestId, requestType, subjectUserId, subjectEmail, status, note, recordedAt: new Date().toISOString() };
  await audit(req.user, 'GDPR_RECORD_REQUEST', 'gdpr_request', requestId, record);
  res.json({ ok: true, request: record });
});


// v1.6.12: Backup / eksport / kontrolleret gendannelse
// Designvalg: Restore sletter ALDRIG live data og overskriver ikke eksisterende id'er.
// Den importerer kun manglende rækker og skriver handlingen i immutable audit_log.
function backupSafeUser(row) {
  return {
    id: row.id,
    email: row.email,
    role: row.role,
    employee_id: row.employee_id || '',
    name: row.name || '',
    active: !!row.active,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

async function readAllForBackup() {
  const users = await query('SELECT id,email,role,employee_id,name,active,created_at,updated_at FROM users ORDER BY created_at ASC, id ASC');
  const timeEntries = await query('SELECT * FROM time_entries ORDER BY created_at ASC, id ASC');
  const attachments = await query('SELECT * FROM attachments ORDER BY created_at ASC, id ASC');
  const overtimeRules = await query('SELECT * FROM overtime_rules ORDER BY employee_id ASC');
  const payslips = await query('SELECT * FROM payslips ORDER BY created_at ASC, id ASC');
  const auditRows = await query('SELECT * FROM audit_log ORDER BY sequence_number ASC, created_at ASC, id ASC');

  return {
    users: users.rows.map(backupSafeUser),
    time_entries: timeEntries.rows,
    attachments: attachments.rows.map(x => ({
      id: x.id,
      uploader_user_id: x.uploader_user_id,
      uploader_email: x.uploader_email,
      uploader_role: x.uploader_role,
      original_filename: x.original_filename,
      mime_type: x.mime_type,
      file_size: x.file_size,
      sha256: x.sha256,
      storage_kind: x.storage_kind,
      linked_type: x.linked_type,
      linked_id: x.linked_id,
      created_at: x.created_at,
      file_base64: x.file_data ? Buffer.from(x.file_data).toString('base64') : ''
    })),
    overtime_rules: overtimeRules.rows,
    payslips: payslips.rows,
    audit_log_readonly: auditRows.rows
  };
}

app.get('/api/admin/backup/export', auth, requireRole('admin','owner','auditor'), async (req, res) => {
  const data = await readAllForBackup();
  const manifest = {
    app: 'Pengedag',
    backupVersion: '1.0',
    backendVersion: VERSION,
    exportedAt: new Date().toISOString(),
    exportedBy: { id: req.user.id, email: req.user.email, role: req.user.role },
    counts: {
      users: data.users.length,
      time_entries: data.time_entries.length,
      attachments: data.attachments.length,
      overtime_rules: data.overtime_rules.length,
      payslips: data.payslips.length,
      audit_log_readonly: data.audit_log_readonly.length
    },
    notes: 'Audit log medtages read-only. Restore importerer ikke historiske audit rows; selve restore-handlingen logges som RESTORE_BACKUP_IMPORT.'
  };
  const backup = { manifest, data };
  const backupHash = sha256(stableJson(backup));
  backup.manifest.sha256 = backupHash;
  await audit(req.user, 'CREATE_BACKUP_EXPORT', 'backup', backupHash, { counts: manifest.counts, backupHash });
  res.json({ ok: true, backup });
});

app.post('/api/admin/backup/restore', auth, requireRole('admin'), async (req, res) => {
  const body = req.body || {};
  const dryRun = body.dryRun !== false;
  const confirm = String(body.confirm || '');
  const backup = body.backup || {};
  const data = backup.data || body.data || {};

  if (!dryRun && confirm !== 'GENDAN_PENGEDAG') {
    return res.status(400).json({ ok: false, error: 'For rigtig gendannelse skal confirm være GENDAN_PENGEDAG. Brug dryRun=true for test.' });
  }

  const result = {
    dryRun,
    inserted: { time_entries: 0, attachments: 0, overtime_rules: 0, payslips: 0 },
    skippedExisting: { time_entries: 0, attachments: 0, overtime_rules: 0, payslips: 0 },
    warnings: []
  };

  const timeEntries = Array.isArray(data.time_entries) ? data.time_entries : [];
  const attachments = Array.isArray(data.attachments) ? data.attachments : [];
  const overtimeRules = Array.isArray(data.overtime_rules) ? data.overtime_rules : [];
  const payslips = Array.isArray(data.payslips) ? data.payslips : [];

  for (const x of timeEntries) {
    if (!x.id) continue;
    const exists = await query('SELECT id FROM time_entries WHERE id=$1 LIMIT 1', [x.id]);
    if (exists.rows.length) { result.skippedExisting.time_entries++; continue; }
    result.inserted.time_entries++;
    if (!dryRun) {
      await query(`INSERT INTO time_entries (id,user_id,employee_id,employee_name,email,customer_id,customer_name,date,start_time,end_time,pause_minutes,note,status,approved_by,rejected_by,calculation_json,created_at,updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
        [x.id, x.user_id || '', x.employee_id || '', x.employee_name || '', x.email || '', x.customer_id || '', x.customer_name || '', x.date || '', x.start_time || '', x.end_time || '', Number(x.pause_minutes || 0), x.note || '', x.status || 'Afventer', x.approved_by || '', x.rejected_by || '', x.calculation_json || {}, x.created_at || new Date(), x.updated_at || new Date()]
      );
    }
  }

  for (const x of attachments) {
    if (!x.id) continue;
    const exists = await query('SELECT id FROM attachments WHERE id=$1 LIMIT 1', [x.id]);
    if (exists.rows.length) { result.skippedExisting.attachments++; continue; }
    const buffer = Buffer.from(String(x.file_base64 || ''), 'base64');
    if (!buffer.length) { result.warnings.push({ attachmentId: x.id, warning: 'mangler file_base64 - sprunget over' }); continue; }
    result.inserted.attachments++;
    if (!dryRun) {
      const hash = x.sha256 || sha256(buffer);
      await query(`INSERT INTO attachments (id,uploader_user_id,uploader_email,uploader_role,original_filename,mime_type,file_size,sha256,storage_kind,linked_type,linked_id,file_data,created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [x.id, x.uploader_user_id || '', x.uploader_email || '', x.uploader_role || '', x.original_filename || 'bilag', x.mime_type || 'application/octet-stream', buffer.length, hash, x.storage_kind || 'postgres_bytea', x.linked_type || '', x.linked_id || '', buffer, x.created_at || new Date()]
      );
    }
  }

  for (const x of overtimeRules) {
    if (!x.employee_id) continue;
    const exists = await query('SELECT employee_id FROM overtime_rules WHERE employee_id=$1 LIMIT 1', [x.employee_id]);
    if (exists.rows.length) { result.skippedExisting.overtime_rules++; continue; }
    result.inserted.overtime_rules++;
    if (!dryRun) {
      await query('INSERT INTO overtime_rules (employee_id, rule_json, updated_at) VALUES ($1,$2,$3)', [x.employee_id, x.rule_json || {}, x.updated_at || new Date()]);
    }
  }

  for (const x of payslips) {
    if (!x.id) continue;
    const exists = await query('SELECT id FROM payslips WHERE id=$1 LIMIT 1', [x.id]);
    if (exists.rows.length) { result.skippedExisting.payslips++; continue; }
    result.inserted.payslips++;
    if (!dryRun) {
      await query('INSERT INTO payslips (id, employee_id, employee_name, period, data_json, created_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)', [x.id, x.employee_id || '', x.employee_name || '', x.period || '', x.data_json || {}, x.created_by || '', x.created_at || new Date()]);
    }
  }

  if (!dryRun) {
    await audit(req.user, 'RESTORE_BACKUP_IMPORT', 'backup', backup.manifest?.sha256 || 'manual', result);
  }
  res.json({ ok: true, result });
});

app.get('/api/mobile/overtime-rules/:employeeId', auth, async (req, res) => {
  const r = await query('SELECT * FROM overtime_rules WHERE employee_id=$1', [req.params.employeeId]);
  res.json({ ok: true, rule: r.rows[0]?.rule_json || {} });
});
app.post('/api/mobile/overtime-rules', auth, requireRole('admin','owner'), async (req, res) => {
  const employeeId = req.body.employeeId || req.body.employee_id || '';
  if (!employeeId) return res.status(400).json({ ok:false, error:'employeeId mangler' });
  await query(`INSERT INTO overtime_rules (employee_id, rule_json, updated_at) VALUES ($1,$2,NOW()) ON CONFLICT (employee_id) DO UPDATE SET rule_json=$2, updated_at=NOW()`, [employeeId, req.body.rule || req.body]);
  await audit(req.user, 'save_overtime_rule', 'employee', employeeId, req.body);
  res.json({ ok:true, employeeId });
});
app.post('/api/mobile/payslip', auth, requireRole('admin','owner'), async (req, res) => {
  // v1.6.18g: robust payslip route.
  // Accepts period = YYYY-MM, period = YYYY-MM-DD, or periodStart/periodEnd.
  // Looks at both legacy work_date and date columns, and reads hours from calculation_json.
  try {
    const employeeId = String(req.body.employeeId || req.body.employee_id || '').trim();
    if (!employeeId) return res.status(400).json({ ok:false, error:'employeeId mangler', requestId:req.requestId });

    const employeeName = String(req.body.employeeName || req.body.employee_name || '').trim();
    let periodStart = String(req.body.periodStart || req.body.period_start || '').trim();
    let periodEnd = String(req.body.periodEnd || req.body.period_end || '').trim();
    let period = String(req.body.period || '').trim();

    function lastDayOfMonth(yyyyMM) {
      const [y, m] = yyyyMM.split('-').map(Number);
      const d = new Date(Date.UTC(y, m, 0));
      return String(d.getUTCDate()).padStart(2, '0');
    }

    // Hvis frontend sender 2026-07, brug hele måneden.
    if (!periodStart && !periodEnd && /^\d{4}-\d{2}$/.test(period)) {
      periodStart = `${period}-01`;
      periodEnd = `${period}-${lastDayOfMonth(period)}`;
    }

    // Hvis frontend ved fejl sender 2026-07-13, tolker vi det som måneden 2026-07.
    if (!periodStart && !periodEnd && /^\d{4}-\d{2}-\d{2}$/.test(period)) {
      const ym = period.slice(0, 7);
      periodStart = `${ym}-01`;
      periodEnd = `${ym}-${lastDayOfMonth(ym)}`;
      period = ym;
    }

    // Hvis kun start er sendt som YYYY-MM, brug måneden.
    if (periodStart && /^\d{4}-\d{2}$/.test(periodStart) && !periodEnd) {
      period = periodStart;
      periodEnd = `${periodStart}-${lastDayOfMonth(periodStart)}`;
      periodStart = `${periodStart}-01`;
    }

    if (!period && periodStart && periodEnd) period = `${periodStart} - ${periodEnd}`;
    if (!period) period = new Date().toISOString().slice(0, 7);

    let entries = [];
    try {
      let q = `SELECT * FROM time_entries WHERE employee_id=$1`;
      const params = [employeeId];
      if (periodStart && periodEnd) {
        // v1.6.18i: ignorer gamle rækker uden dato i lønseddel-søgning.
        q += ` AND NULLIF(COALESCE(NULLIF(work_date::text,''), NULLIF(date::text,'')), '')::date >= $2::date
               AND NULLIF(COALESCE(NULLIF(work_date::text,''), NULLIF(date::text,'')), '')::date <= $3::date`;
        params.push(periodStart, periodEnd);
      }
      q += ` ORDER BY NULLIF(COALESCE(NULLIF(work_date::text,''), NULLIF(date::text,'')), '')::date ASC NULLS LAST, start_time ASC, id ASC`;
      const er = await query(q, params);
      entries = er.rows || [];
    } catch (e) {
      console.warn('Payslip entries lookup warning:', e.message);
      return res.status(500).json({ ok:false, error:'Kunne ikke hente timer til lønseddel', details:e.message, requestId:req.requestId });
    }

    const approvedEntries = entries.filter(x => {
      const st = String(x.status || '').toLowerCase();
      return st.includes('godkend') || st.includes('approved');
    });

    function hoursFromEntry(x) {
      // 1) Direkte kolonner hvis de findes.
      const direct = Number(x.hours || x.total_hours || x.calculated_hours || 0);
      if (direct > 0) return direct;

      // 2) calculation_json kan være object eller string.
      try {
        const cj = typeof x.calculation_json === 'string' ? JSON.parse(x.calculation_json || '{}') : (x.calculation_json || {});
        const h = Number(cj.hours || cj.normalHours || cj.totalHours || 0);
        if (h > 0) return h;
      } catch (_) {}

      // 3) Fallback: beregn fra start/slut/pause.
      try {
        const start = String(x.start_time || x.start || '');
        const end = String(x.end_time || x.end || '');
        const pause = Number(x.pause_minutes || x.pauseMinutes || 0) || 0;
        if (start && end) return calcHours(start, end, pause);
      } catch (_) {}
      return 0;
    }

    const totalHours = approvedEntries.reduce((sum, x) => sum + hoursFromEntry(x), 0);

    const id = makeId('pay');
    const dataJson = {
      ...req.body,
      employeeId,
      employeeName,
      period,
      periodStart,
      periodEnd,
      generatedAt: new Date().toISOString(),
      generatedBy: req.user.email || req.user.id,
      entriesFound: entries.length,
      approvedEntries: approvedEntries.length,
      totalHours,
      entries: approvedEntries.map(x => ({
        id: x.id,
        date: x.work_date || x.date,
        start: x.start_time,
        end: x.end_time,
        pauseMinutes: x.pause_minutes,
        status: x.status,
        hours: hoursFromEntry(x)
      }))
    };

    const colsResult = await query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name='payslips'
    `);
    const existingCols = new Set(colsResult.rows.map(r => r.column_name));
    const data = {
      id,
      employee_id: employeeId,
      employee_name: employeeName,
      period,
      data_json: dataJson,
      created_by: req.user.id || '',
      created_at: new Date()
    };
    const preferred = ['id','employee_id','employee_name','period','data_json','created_by','created_at'];
    const insertCols = preferred.filter(c => existingCols.has(c));
    const values = insertCols.map(c => data[c]);
    const placeholders = insertCols.map((_, i) => `$${i+1}`);

    if (!insertCols.includes('id')) {
      return res.status(500).json({ ok:false, error:'Payslips table mangler id-kolonne', requestId:req.requestId });
    }

    await query(`INSERT INTO payslips (${insertCols.join(', ')}) VALUES (${placeholders.join(', ')})`, values);

    try {
      await audit(req.user, 'CREATE_PAYSLIP', 'payslip', id, { employeeId, period, periodStart, periodEnd, entriesFound: entries.length, approvedEntries: approvedEntries.length, totalHours });
    } catch (auditErr) {
      console.error('Payslip audit failed:', auditErr.message);
      return res.status(500).json({ ok:false, error:'Lønseddel blev gemt, men audit-log fejlede', auditError:auditErr.message, payslipId:id, requestId:req.requestId });
    }

    return res.json({ ok:true, id, payslip: { id, employeeId, employeeName, period, periodStart, periodEnd, totalHours, entriesFound: entries.length, approvedEntries: approvedEntries.length } });
  } catch (e) {
    console.error('Payslip route failed:', e);
    return res.status(500).json({ ok:false, error:'Lønseddel fejlede i backend', details:e.message, requestId:req.requestId });
  }
});
app.get('/api/mobile/payslip/:employeeId', auth, async (req, res) => {
  const r = await query('SELECT * FROM payslips WHERE employee_id=$1 ORDER BY created_at DESC LIMIT 20', [req.params.employeeId]);
  res.json({ ok:true, count:r.rows.length, payslips:r.rows });
});

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ ok: false, error: 'Request er for stor', limit: JSON_LIMIT, requestId: req.requestId });
  }
  if (err && String(err.message || '').includes('CORS')) {
    return res.status(403).json({ ok: false, error: 'CORS origin ikke tilladt', requestId: req.requestId });
  }
  console.error('Uventet serverfejl', req.requestId, err);
  res.status(500).json({ ok: false, error: 'Serverfejl', requestId: req.requestId });
});

app.use((req, res) => {
  res.status(404).json({ ok: false, error: 'Not found', path: req.path, requestId: req.requestId });
});

initDb()
  .then(() => 

// ===============================
// Pengedag v1.7.0 Lønprofil
// ===============================
async function ensureSalarySettingsTableV170() {
  await query(`CREATE TABLE IF NOT EXISTS employee_salary_settings (
    id TEXT PRIMARY KEY,
    employee_id TEXT UNIQUE NOT NULL,
    employee_name TEXT DEFAULT '',
    employee_email TEXT DEFAULT '',
    normal_rate NUMERIC DEFAULT 160,
    overtime_rate NUMERIC DEFAULT 220,
    customer_rate NUMERIC DEFAULT 320,
    pension_percent NUMERIC DEFAULT 8,
    employer_pension_percent NUMERIC DEFAULT 4,
    employee_pension_percent NUMERIC DEFAULT 4,
    am_bidrag_percent NUMERIC DEFAULT 8,
    tax_percent NUMERIC DEFAULT 38,
    deduction NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'DKK',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);
}

app.get('/api/admin/employees/:employeeId/salary-settings', auth, requireRole('admin','owner','auditor'), async (req,res)=>{
  try {
    await ensureSalarySettingsTableV170();
    const r = await query('SELECT * FROM employee_salary_settings WHERE employee_id=$1',[req.params.employeeId]);
    if (!r.rows.length) return res.json({ok:true,found:false,salarySettings:{employeeId:req.params.employeeId,normalRate:160,overtimeRate:220,pensionPercent:8,taxPercent:38,currency:'DKK'}});
    res.json({ok:true,found:true,salarySettings:r.rows[0]});
  } catch(e){res.status(500).json({ok:false,error:e.message});}
});

app.put('/api/admin/employees/:employeeId/salary-settings', auth, requireRole('admin','owner'), async (req,res)=>{
  try {
    await ensureSalarySettingsTableV170();
    const b=req.body||{};
    const employeeId=req.params.employeeId;
    const old=await query('SELECT * FROM employee_salary_settings WHERE employee_id=$1',[employeeId]);
    await query(`INSERT INTO employee_salary_settings
    (id,employee_id,employee_name,employee_email,normal_rate,overtime_rate,customer_rate,pension_percent,employer_pension_percent,employee_pension_percent,am_bidrag_percent,tax_percent,deduction,currency,updated_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW())
    ON CONFLICT(employee_id) DO UPDATE SET
    employee_name=EXCLUDED.employee_name,
    employee_email=EXCLUDED.employee_email,
    normal_rate=EXCLUDED.normal_rate,
    overtime_rate=EXCLUDED.overtime_rate,
    customer_rate=EXCLUDED.customer_rate,
    pension_percent=EXCLUDED.pension_percent,
    employer_pension_percent=EXCLUDED.employer_pension_percent,
    employee_pension_percent=EXCLUDED.employee_pension_percent,
    am_bidrag_percent=EXCLUDED.am_bidrag_percent,
    tax_percent=EXCLUDED.tax_percent,
    deduction=EXCLUDED.deduction,
    currency=EXCLUDED.currency,
    updated_at=NOW()`,[
      'sal_'+employeeId,employeeId,b.employeeName||'',b.employeeEmail||'',
      Number(b.normalRate||160),Number(b.overtimeRate||220),Number(b.customerRate||320),
      Number(b.pensionPercent||8),Number(b.employerPensionPercent||4),Number(b.employeePensionPercent||4),
      Number(b.amBidragPercent||8),Number(b.taxPercent||38),Number(b.deduction||0),b.currency||'DKK'
    ]);
    await audit(req.user,'CHANGE_SALARY_SETTINGS','employee_salary_settings',employeeId,{old:old.rows[0]||null,new:b});
    res.json({ok:true,message:'Lønprofil gemt'});
  } catch(e){res.status(500).json({ok:false,error:e.message});}
});

app.get('/api/employee/my-salary-settings', auth, async (req,res)=>{
  try {
    await ensureSalarySettingsTableV170();
    const employeeId=req.user.employee_id || req.user.employeeId || '';
    const r=await query('SELECT * FROM employee_salary_settings WHERE employee_id=$1',[employeeId]);
    res.json({ok:true,salarySettings:r.rows[0]||null});
  } catch(e){res.status(500).json({ok:false,error:e.message});}
});

app.listen(PORT, () => console.log(`Pengedag backend ${VERSION} on port ${PORT}`)))
  .catch(err => {
    console.error('Kunne ikke starte database:', err);
    process.exit(1);
  });
