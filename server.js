require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' }));

const VERSION = '1.6.9-bilag-audit-strict-fix';
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
  const createdAt = new Date();

  const row = {
    id: numericId ? null : makeId('audit'),
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

  // v1.6.9: Gamle databaser har ofte audit_log.id som SERIAL/INTEGER.
  // Her lader vi PostgreSQL selv lave id'et, så INSERT ikke fejler på id-type eller sekvens.
  // Hvis id er TEXT, bruger vi vores eget audit-id.
  if (numericId || columnDefault.includes('nextval')) {
    await query(
      `INSERT INTO audit_log (actor_user_id, actor_email, actor_role, sequence_number, prev_hash, row_hash, action, target_type, target_id, details_json, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [row.actor_user_id, row.actor_email, row.actor_role, row.sequence_number, row.prev_hash, row.row_hash, action, row.target_type, row.target_id, row.details_json, createdAt]
    );
  } else {
    await query(
      `INSERT INTO audit_log (id, actor_user_id, actor_email, actor_role, sequence_number, prev_hash, row_hash, action, target_type, target_id, details_json, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [row.id, row.actor_user_id, row.actor_email, row.actor_role, row.sequence_number, row.prev_hash, row.row_hash, action, row.target_type, row.target_id, row.details_json, createdAt]
    );
  }
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
  'GET /health', 'POST /api/auth/bootstrap-admin', 'POST /api/auth/login', 'GET /api/auth/me', 'POST /api/auth/users',
  'POST /api/mobile/time-entry', 'GET /api/mobile/times', 'POST /api/mobile/time-entries/:id/approve', 'POST /api/mobile/time-entries/:id/reject', 'POST /api/bilag/upload', 'GET /api/bilag', 'GET /api/bilag/:id', 'GET /api/bilag/:id/download', 'GET /api/admin/audit-log', 'GET /api/admin/audit-log/verify'
]}));

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

app.post('/api/auth/login', async (req, res) => {
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
  const body = req.body || {};
  const id = makeId('mob');
  const employeeId = body.employeeId || body.employee_id || req.user.employee_id || '';
  if (req.user.role === 'employee' && req.user.employee_id && employeeId && employeeId !== req.user.employee_id) {
    return res.status(403).json({ ok: false, error: 'Medarbejder kan kun sende egne timer' });
  }
  const employeeName = body.employeeName || body.employee_name || req.user.name || '';
  const start = body.start || body.startTime || body.start_time || '';
  const end = body.end || body.endTime || body.end_time || '';
  const pauseMinutes = Number(body.pauseMinutes || body.pause_minutes || 0);
  const hours = calcHours(start, end, pauseMinutes);
  const calc = { hours, normalHours: hours, overtimeHours: 0 };
  await query(`INSERT INTO time_entries (id,user_id,employee_id,employee_name,email,customer_id,customer_name,date,start_time,end_time,pause_minutes,note,status,calculation_json)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [id, req.user.id, employeeId, employeeName, body.email || '', body.customerId || '', body.customerName || '', body.date || '', start, end, pauseMinutes, body.note || '', 'Afventer', calc]
  );
  await audit(req.user, 'create_time_entry', 'time_entry', id, { employeeId, employeeName, date: body.date, hours });
  res.json({ ok: true, entry: { id, employeeId, employeeName, date: body.date || '', start, end, pauseMinutes, note: body.note || '', status: 'Afventer', calculation: calc } });
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
  const id = makeId('pay');
  await query('INSERT INTO payslips (id, employee_id, employee_name, period, data_json, created_by) VALUES ($1,$2,$3,$4,$5,$6)', [id, req.body.employeeId || '', req.body.employeeName || '', req.body.period || '', req.body, req.user.id]);
  await audit(req.user, 'create_payslip', 'payslip', id, req.body);
  res.json({ ok:true, id });
});
app.get('/api/mobile/payslip/:employeeId', auth, async (req, res) => {
  const r = await query('SELECT * FROM payslips WHERE employee_id=$1 ORDER BY created_at DESC LIMIT 20', [req.params.employeeId]);
  res.json({ ok:true, count:r.rows.length, payslips:r.rows });
});

initDb()
  .then(() => app.listen(PORT, () => console.log(`Pengedag backend ${VERSION} on port ${PORT}`)))
  .catch(err => {
    console.error('Kunne ikke starte database:', err);
    process.exit(1);
  });
