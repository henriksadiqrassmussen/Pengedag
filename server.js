require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'development';
const VERSION = '1.6.1-postgres-jwt-rbac';

if (!DATABASE_URL) {
  console.warn('ADVARSEL: DATABASE_URL mangler. Til Railway: tilføj PostgreSQL service og DATABASE_URL variable.');
}

if (!JWT_SECRET) {
  console.warn('ADVARSEL: JWT_SECRET mangler. Tilføj JWT_SECRET environment variable.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// ============== Auth Middleware ==============
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ ok: false, error: 'Missing authorization token' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ ok: false, error: 'Invalid or expired token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ ok: false, error: 'Insufficient permissions' });
    }
    next();
  };
}

// ============== Utility Functions ==============
function toMinutes(time) {
  if (!time || !/^\d{1,2}:\d{2}$/.test(String(time))) return 0;
  const [h, m] = String(time).split(':').map(Number);
  return h * 60 + m;
}

function roundTo(value, step = 0.25) {
  const s = Number(step) || 0.25;
  return Math.round(value / s) * s;
}

function overlap(a1, a2, b1, b2) {
  return Math.max(0, Math.min(a2, b2) - Math.max(a1, b1));
}

function calculateNightOvertimeMinutes(start, end, input = {}) {
  const rule = input.overtimeRule || input.rules || {};
  const enabled = rule.nightOvertimeAuto ?? input.nightOvertimeAuto ?? 'ja';
  if (enabled === false || enabled === 'nej' || enabled === 'false') return 0;
  const from = toMinutes(rule.nightOvertimeFrom || input.nightOvertimeFrom || '22:00');
  const to = toMinutes(rule.nightOvertimeTo || input.nightOvertimeTo || '06:00');
  let mins = 0;
  for (let d = -1; d <= 1; d++) {
    const base = d * 24 * 60;
    if (from <= to) {
      mins += overlap(start, end, base + from, base + to);
    } else {
      mins += overlap(start, end, base + from, base + 24 * 60 + to);
    }
  }
  return Math.max(0, mins);
}

function calculateEntry(input = {}) {
  const rule = input.overtimeRule || input.rules || {};
  const start = toMinutes(input.startTime);
  let end = toMinutes(input.endTime);
  if (end <= start) end += 24 * 60;
  const pauseMinutes = Number(input.pauseMinutes || 0);
  const rawMinutes = Math.max(0, end - start - pauseMinutes);
  const rawHours = rawMinutes / 60;
  const hours = Number(rawHours.toFixed(2));

  const normalRate = Number(input.normalRate || input.hourlyRate || rule.normalRate || 160);
  const overtimeRate = Number(input.overtimeRate || rule.overtimeRate || rule.standardOvertidTimeloen || 220);
  const customerRate = Number(input.customerRate || rule.customerRate || 320);
  const vatRate = Number(input.vatRate ?? rule.vatRate ?? 25);
  const overtimeAfterHours = Number(input.overtimeAfterHours || rule.overtimeDailyAfter || rule.overtimeAfterHours || 7.5);
  const roundStep = Number(input.overtimeRoundStep || rule.overtimeRound || rule.overtimeRoundStep || 0.25);

  const dailyOvertime = hours > overtimeAfterHours ? hours - overtimeAfterHours : 0;
  let nightMinutes = calculateNightOvertimeMinutes(start, end, input);
  if (pauseMinutes > 0 && nightMinutes > 0) nightMinutes = Math.max(0, nightMinutes - pauseMinutes);
  const nightOvertime = nightMinutes / 60;
  const overtimeHours = Number(Math.min(hours, roundTo(Math.max(dailyOvertime, nightOvertime), roundStep)).toFixed(2));
  const normalHours = Number(Math.max(0, hours - overtimeHours).toFixed(2));
  const normalPay = Number((normalHours * normalRate).toFixed(2));
  const overtimePay = Number((overtimeHours * overtimeRate).toFixed(2));
  const employeePay = Number((normalPay + overtimePay).toFixed(2));
  const customerTotalExVat = Number((hours * customerRate).toFixed(2));
  const customerVat = Number((customerTotalExVat * vatRate / 100).toFixed(2));
  const customerTotalIncVat = Number((customerTotalExVat + customerVat).toFixed(2));
  const marginExVat = Number((customerTotalExVat - employeePay).toFixed(2));

  return { hours, normalHours, overtimeHours, normalRate, overtimeRate, customerRate, vatRate, normalPay, overtimePay, employeePay, customerTotalExVat, customerVat, customerTotalIncVat, marginExVat, nightOvertimeHours: Number(nightOvertime.toFixed(2)) };
}

async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    return await client.query(sql, params);
  } finally {
    client.release();
  }
}

async function audit(action, entityType, entityId, payload = {}, userId = null) {
  await query(
    `INSERT INTO audit_log (action, entity_type, entity_id, user_id, payload) VALUES ($1,$2,$3,$4,$5)`,
    [action, entityType, entityId, userId, JSON.stringify(payload)]
  );
}

async function initDb() {
  // Users table
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'employee',
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Time entries table
  await query(`
    CREATE TABLE IF NOT EXISTS time_entries (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      employee_id TEXT NOT NULL DEFAULT '',
      employee_name TEXT NOT NULL DEFAULT '',
      email TEXT NOT NULL DEFAULT '',
      customer_id TEXT NOT NULL DEFAULT '',
      customer_name TEXT NOT NULL DEFAULT '',
      job_id TEXT NOT NULL DEFAULT '',
      work_date DATE NOT NULL,
      start_time TEXT NOT NULL DEFAULT '',
      end_time TEXT NOT NULL DEFAULT '',
      pause_minutes INTEGER NOT NULL DEFAULT 0,
      note TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'Afventer',
      calculation JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      approved_at TIMESTAMPTZ,
      approved_by TEXT,
      rejected_at TIMESTAMPTZ,
      rejected_by TEXT,
      reject_reason TEXT NOT NULL DEFAULT ''
    );
  `);

  // Overtime rules table
  await query(`
    CREATE TABLE IF NOT EXISTS overtime_rules (
      employee_id TEXT PRIMARY KEY,
      rules JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Payslips table
  await query(`
    CREATE TABLE IF NOT EXISTS payslips (
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL DEFAULT '',
      employee_name TEXT NOT NULL DEFAULT '',
      period_start DATE,
      period_end DATE,
      status TEXT NOT NULL DEFAULT 'Afventer kontrol',
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Audit log table
  await query(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id BIGSERIAL PRIMARY KEY,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT NOT NULL,
      user_id TEXT,
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Indexes
  await query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_time_entries_user_id ON time_entries(user_id);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_time_entries_status ON time_entries(status);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_time_entries_work_date ON time_entries(work_date);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);`);
}

function normalizeEntry(body = {}) {
  const now = new Date().toISOString();
  const entry = {
    id: body.id || `mob_${Date.now()}_${Math.random().toString(16).slice(2)}`,
    employeeId: body.employeeId || body.medarbejderId || '',
    employeeName: body.employeeName || body.name || body.navn || '',
    email: body.email || '',
    customerId: body.customerId || '',
    customerName: body.customerName || '',
    jobId: body.jobId || '',
    date: body.date || new Date().toISOString().slice(0, 10),
    startTime: body.startTime || body.start || '',
    endTime: body.endTime || body.end || '',
    pauseMinutes: Number(body.pauseMinutes || body.pause || 0),
    note: body.note || '',
    status: body.status && body.status !== 'Lokal' ? body.status : 'Afventer',
    createdAt: body.createdAt || now,
    updatedAt: now
  };
  entry.calculation = calculateEntry({ ...body, ...entry });
  return entry;
}

function dbRowToEntry(row) {
  return {
    id: row.id,
    employeeId: row.employee_id,
    employeeName: row.employee_name,
    email: row.email,
    customerId: row.customer_id,
    customerName: row.customer_name,
    jobId: row.job_id,
    date: row.work_date instanceof Date ? row.work_date.toISOString().slice(0,10) : String(row.work_date).slice(0,10),
    startTime: row.start_time,
    endTime: row.end_time,
    pauseMinutes: row.pause_minutes,
    note: row.note,
    status: row.status,
    calculation: row.calculation || {},
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    approvedAt: row.approved_at,
    approvedBy: row.approved_by,
    rejectedAt: row.rejected_at,
    rejectedBy: row.rejected_by,
    rejectReason: row.reject_reason
  };
}

// ============== Public Routes ==============
app.get('/', (req, res) => {
  res.json({ ok: true, app: 'Pengedag Backend PostgreSQL', version: VERSION, database: DATABASE_URL ? 'postgresql' : 'missing DATABASE_URL' });
});

app.get('/health', async (req, res) => {
  try {
    const r = await query('SELECT NOW() AS now');
    res.json({ ok: true, status: 'healthy', version: VERSION, database: 'connected', time: r.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, status: 'database_error', version: VERSION, error: err.message });
  }
});

// ============== Auth Routes ==============
app.post('/api/auth/bootstrap-admin', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password required' });
    }

    // Check if any admin exists
    const existing = await query('SELECT * FROM users WHERE role = $1', ['admin']);
    if (existing.rows.length > 0) {
      return res.status(403).json({ ok: false, error: 'Admin already exists' });
    }

    const userId = `usr_${Date.now()}_${Math.random().toString(16).slice(2)}`;
    const passwordHash = await bcryptjs.hash(password, 10);

    await query(
      `INSERT INTO users (id, email, name, password_hash, role, active) VALUES ($1,$2,$3,$4,$5,$6)`,
      [userId, email, name || 'Admin', passwordHash, 'admin', true]
    );

    await audit('BOOTSTRAP_ADMIN', 'user', userId, { email }, userId);

    res.json({ ok: true, user: { id: userId, email, name: name || 'Admin', role: 'admin' } });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password required' });
    }

    const result = await query('SELECT * FROM users WHERE email = $1 AND active = true', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const passwordValid = await bcryptjs.compare(password, user.password_hash);
    if (!passwordValid) {
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });
    }

    const token = jwt.sign({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    }, JWT_SECRET, { expiresIn: '7d' });

    await audit('LOGIN', 'user', user.id, { email }, user.id);

    res.json({ ok: true, token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/auth/me', verifyToken, (req, res) => {
  res.json({ ok: true, user: req.user });
});

app.post('/api/auth/users', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    if (!email || !password || !role) {
      return res.status(400).json({ ok: false, error: 'Email, password, and role required' });
    }

    if (!['admin', 'owner', 'employee', 'auditor'].includes(role)) {
      return res.status(400).json({ ok: false, error: 'Invalid role' });
    }

    const userId = `usr_${Date.now()}_${Math.random().toString(16).slice(2)}`;
    const passwordHash = await bcryptjs.hash(password, 10);

    await query(
      `INSERT INTO users (id, email, name, password_hash, role, active) VALUES ($1,$2,$3,$4,$5,$6)`,
      [userId, email, name || email, passwordHash, role, true]
    );

    await audit('CREATE_USER', 'user', userId, { email, role }, req.user.id);

    res.json({ ok: true, user: { id: userId, email, name: name || email, role } });
  } catch (err) {
    if (err.message.includes('duplicate key')) {
      return res.status(400).json({ ok: false, error: 'Email already exists' });
    }
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ============== Time Entry Routes (Protected) ==============
app.get('/api/mobile/routes', (req, res) => {
  res.json({ ok: true, version: VERSION, routes: [
    'GET /health',
    'POST /api/auth/bootstrap-admin',
    'POST /api/auth/login',
    'GET /api/auth/me (requires token)',
    'POST /api/auth/users (requires token, admin only)',
    'GET /api/mobile/times (requires token)',
    'POST /api/mobile/time-entry (requires token)',
    'POST /api/mobile/time-entries/:id/approve (requires token, owner/admin only)',
    'POST /api/mobile/time-entries/:id/reject (requires token, owner/admin only)',
    'GET /api/mobile/overtime-rules/:employeeId',
    'POST /api/mobile/overtime-rules',
    'POST /api/mobile/payslip',
    'GET /api/mobile/payslip/:employeeId',
    'GET /api/admin/audit-log (requires token, admin/auditor only)'
  ]});
});

async function listEntries(req, res) {
  const limit = Math.min(Number(req.query.limit || 100), 500);
  const status = req.query.status;
  const employeeId = req.query.employeeId;
  const params = [];
  let where = [];

  // Employees can only see their own entries
  if (req.user.role === 'employee') {
    params.push(req.user.id);
    where.push(`user_id = $${params.length}`);
  }

  if (status) { params.push(status); where.push(`status = $${params.length}`); }
  if (employeeId) { params.push(employeeId); where.push(`employee_id = $${params.length}`); }

  params.push(limit);
  const sql = `SELECT * FROM time_entries ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY created_at DESC LIMIT $${params.length}`;
  const r = await query(sql, params);
  res.json({ ok: true, count: r.rows.length, entries: r.rows.map(dbRowToEntry) });
}

['/api/mobile/time-entries', '/api/mobile/times'].forEach(route => {
  app.get(route, verifyToken, (req, res) => listEntries(req, res).catch(err => res.status(500).json({ ok: false, error: err.message })));
});

async function addEntry(req, res) {
  const entry = normalizeEntry(req.body || {});
  const c = entry.calculation;

  await query(`
    INSERT INTO time_entries (id, user_id, employee_id, employee_name, email, customer_id, customer_name, job_id, work_date, start_time, end_time, pause_minutes, note, status, calculation, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
    ON CONFLICT (id) DO UPDATE SET
      employee_id=EXCLUDED.employee_id, employee_name=EXCLUDED.employee_name, email=EXCLUDED.email, customer_id=EXCLUDED.customer_id, customer_name=EXCLUDED.customer_name,
      job_id=EXCLUDED.job_id, work_date=EXCLUDED.work_date, start_time=EXCLUDED.start_time, end_time=EXCLUDED.end_time, pause_minutes=EXCLUDED.pause_minutes,
      note=EXCLUDED.note, status=EXCLUDED.status, calculation=EXCLUDED.calculation, updated_at=NOW()
  `, [entry.id, req.user.id, entry.employeeId, entry.employeeName, entry.email, entry.customerId, entry.customerName, entry.jobId, entry.date, entry.startTime, entry.endTime, entry.pauseMinutes, entry.note, entry.status, JSON.stringify(c), entry.createdAt, entry.updatedAt]);

  await audit('CREATE_TIME_ENTRY', 'time_entry', entry.id, entry, req.user.id);

  res.json({ ok: true, entry });
}

['/api/mobile/time-entry', '/api/mobile/time-entries'].forEach(route => {
  app.post(route, verifyToken, (req, res) => addEntry(req, res).catch(err => res.status(500).json({ ok: false, error: err.message })));
});

app.post('/api/mobile/time-entries/:id/approve', verifyToken, requireRole('owner', 'admin'), async (req, res) => {
  try {
    const id = req.params.id;
    const r = await query(`UPDATE time_entries SET status='Godkendt', approved_at=NOW(), approved_by=$2, updated_at=NOW(), rejected_at=NULL, rejected_by=NULL, reject_reason='' WHERE id=$1 RETURNING *`, [id, req.user.id]);
    if (!r.rows[0]) return res.status(404).json({ ok: false, error: 'Time entry not found' });
    await audit('APPROVE_TIME_ENTRY', 'time_entry', id, { by: req.user.id }, req.user.id);
    res.json({ ok: true, entry: dbRowToEntry(r.rows[0]) });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.post('/api/mobile/time-entries/:id/reject', verifyToken, requireRole('owner', 'admin'), async (req, res) => {
  try {
    const id = req.params.id;
    const reason = req.body?.reason || req.body?.note || '';
    const r = await query(`UPDATE time_entries SET status='Afvist', rejected_at=NOW(), rejected_by=$2, updated_at=NOW(), reject_reason=$3 WHERE id=$1 RETURNING *`, [id, req.user.id, reason]);
    if (!r.rows[0]) return res.status(404).json({ ok: false, error: 'Time entry not found' });
    await audit('REJECT_TIME_ENTRY', 'time_entry', id, { reason, by: req.user.id }, req.user.id);
    res.json({ ok: true, entry: dbRowToEntry(r.rows[0]) });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.get('/api/mobile/overtime-rules/:employeeId', async (req, res) => {
  try {
    const r = await query('SELECT * FROM overtime_rules WHERE employee_id=$1', [req.params.employeeId]);
    res.json({ ok: true, employeeId: req.params.employeeId, rules: r.rows[0]?.rules || {} });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.post('/api/mobile/overtime-rules', async (req, res) => {
  try {
    const employeeId = req.body.employeeId || req.body.medarbejderId || '';
    if (!employeeId) return res.status(400).json({ ok: false, error: 'employeeId mangler' });
    const rules = req.body.rules || req.body;
    await query(`INSERT INTO overtime_rules (employee_id, rules, updated_at) VALUES ($1,$2,NOW()) ON CONFLICT (employee_id) DO UPDATE SET rules=EXCLUDED.rules, updated_at=NOW()`, [employeeId, JSON.stringify(rules)]);
    await audit('UPSERT_OVERTIME_RULES', 'overtime_rules', employeeId, rules);
    res.json({ ok: true, employeeId, rules });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.post('/api/mobile/payslip', async (req, res) => {
  try {
    const id = req.body.id || `pay_${Date.now()}_${Math.random().toString(16).slice(2)}`;
    const employeeId = req.body.employeeId || req.body.medarbejderId || '';
    const employeeName = req.body.employeeName || req.body.name || req.body.navn || '';
    const status = req.body.status || 'Afventer kontrol';
    await query(`INSERT INTO payslips (id, employee_id, employee_name, period_start, period_end, status, payload, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW()) ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, payload=EXCLUDED.payload, updated_at=NOW()`, [id, employeeId, employeeName, req.body.periodStart || null, req.body.periodEnd || null, status, JSON.stringify(req.body)]);
    await audit('UPSERT_PAYSLIP', 'payslip', id, req.body);
    res.json({ ok: true, payslip: { id, employeeId, employeeName, status, payload: req.body } });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.get('/api/mobile/payslip/:employeeId', async (req, res) => {
  try {
    const r = await query(`SELECT * FROM payslips WHERE employee_id=$1 ORDER BY created_at DESC LIMIT 25`, [req.params.employeeId]);
    res.json({ ok: true, count: r.rows.length, payslips: r.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ============== Admin Routes ==============
app.get('/api/admin/audit-log', verifyToken, requireRole('admin', 'auditor'), async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit || 100), 500);
    const r = await query(`SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $1`, [limit]);
    res.json({ ok: true, count: r.rows.length, auditLog: r.rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ============== Error Handler ==============
app.use((req, res) => {
  res.status(404).json({ ok: false, error: 'Route not found', path: req.path });
});

// ============== Start Server ==============
initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Pengedag PostgreSQL backend ${VERSION} on port ${PORT}`));
  })
  .catch(err => {
    console.error('Kunne ikke starte database:', err);
    process.exit(1);
  });

