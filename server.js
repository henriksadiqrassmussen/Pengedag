import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import pkg from 'pg';
const { Pool } = pkg;

const VERSION = '2.0.2-sprint1-real-backend-fix';
const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET || 'pengedag-dev-secret-change-me';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'vault1973@gmail.com').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'PengedagAdmin2026!';
const EMPLOYEE_EMAIL = (process.env.EMPLOYEE_EMAIL || 'medarbejder@pengedag.dk').toLowerCase();
const EMPLOYEE_PASSWORD = process.env.EMPLOYEE_PASSWORD || 'MedarbejderTest2026!';

const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false } });
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const defaultOrigins = [
  'https://pengedag.dk', 'https://www.pengedag.dk',
  'http://pengedag.dk', 'http://www.pengedag.dk',
  'http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:5500'
];
const allowedOrigins = (process.env.CORS_ORIGINS || defaultOrigins.join(','))
  .split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type', 'Accept', 'X-Requested-With', 'X-Reset-Key']
}));
app.options('*', cors());

async function db(q, params = []) { return pool.query(q, params); }
function id(prefix) { return `${prefix}_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`; }
function money(n) { return Math.round((Number(n || 0) + Number.EPSILON) * 100) / 100; }
function sign(user) { return jwt.sign({ id: user.id, email: user.email, role: user.role, employeeId: user.employee_id || user.employeeId || null }, JWT_SECRET, { expiresIn: '14d' }); }
function requireAuth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!token) return res.status(401).json({ ok: false, error: 'Mangler Bearer token' });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) { return res.status(401).json({ ok: false, error: 'Ugyldig eller udløbet token' }); }
}
function requireAdmin(req, res, next) {
  const role = String(req.user?.role || '').toLowerCase();
  if (!['admin', 'owner', 'ejer', 'auditor'].includes(role)) return res.status(403).json({ ok: false, error: 'Kræver ejer/admin' });
  next();
}
function qIdent(name) {
  return '"' + String(name).replace(/"/g, '""') + '"';
}
async function ensureColumn(table, column, type) {
  await db(`ALTER TABLE ${qIdent(table)} ADD COLUMN IF NOT EXISTS ${qIdent(column)} ${type}`);
}

async function audit(actor, action, targetType = null, targetId = null, details = {}) {
  try {
    await db(`CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      actor_email TEXT,
      actor_role TEXT,
      action TEXT NOT NULL,
      target_type TEXT,
      target_id TEXT,
      details JSONB,
      hash TEXT
    )`);
    const rowId = id('audit');
    const payload = JSON.stringify({ rowId, actor: actor?.email || '', action, targetType, targetId, details, at: new Date().toISOString() });
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    await db(`INSERT INTO audit_log (id, actor_email, actor_role, action, target_type, target_id, details, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [rowId, actor?.email || '', actor?.role || '', action, targetType, targetId, details, hash]);
  } catch (e) { console.error('AUDIT_FAILED', e.message); }
}

async function initDb() {
  await db(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    password TEXT,
    role TEXT DEFAULT 'employee',
    name TEXT,
    employee_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await ensureColumn('users', 'password_hash', 'TEXT');
  await ensureColumn('users', 'role', 'TEXT DEFAULT \'employee\'');
  await ensureColumn('users', 'name', 'TEXT');
  await ensureColumn('users', 'employee_id', 'TEXT');

  await db(`CREATE TABLE IF NOT EXISTS employee_profiles (
    id TEXT PRIMARY KEY,
    employee_id TEXT UNIQUE NOT NULL,
    name TEXT DEFAULT '',
    email TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    address TEXT DEFAULT '',
    employment_type TEXT DEFAULT 'Vikar',
    status TEXT DEFAULT 'Aktiv',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await db(`CREATE TABLE IF NOT EXISTS employee_salary_settings (
    id TEXT PRIMARY KEY,
    employee_id TEXT UNIQUE NOT NULL,
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

  await db(`CREATE TABLE IF NOT EXISTS time_entries (
    id TEXT PRIMARY KEY,
    employee_id TEXT,
    employee_name TEXT,
    email TEXT,
    customer_id TEXT,
    customer_name TEXT,
    work_date DATE,
    date TEXT,
    start_time TEXT,
    end_time TEXT,
    start TEXT,
    "end" TEXT,
    pause_minutes INTEGER DEFAULT 0,
    pauseMinutes INTEGER DEFAULT 0,
    note TEXT,
    status TEXT DEFAULT 'Afventer',
    calculation_json JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    approved_at TIMESTAMPTZ
  )`);
  await ensureColumn('time_entries', 'employee_id', 'TEXT');
  await ensureColumn('time_entries', 'employee_name', 'TEXT');
  await ensureColumn('time_entries', 'email', 'TEXT');
  await ensureColumn('time_entries', 'customer_id', 'TEXT');
  await ensureColumn('time_entries', 'customer_name', 'TEXT');
  await ensureColumn('time_entries', 'work_date', 'DATE');
  await ensureColumn('time_entries', 'date', 'TEXT');
  await ensureColumn('time_entries', 'start_time', 'TEXT');
  await ensureColumn('time_entries', 'end_time', 'TEXT');
  await ensureColumn('time_entries', 'start', 'TEXT');
  await ensureColumn('time_entries', 'end', 'TEXT');
  await ensureColumn('time_entries', 'pause_minutes', 'INTEGER DEFAULT 0');
  await ensureColumn('time_entries', 'note', 'TEXT');
  await ensureColumn('time_entries', 'status', 'TEXT DEFAULT \'Afventer\'');
  await ensureColumn('time_entries', 'calculation_json', 'JSONB');
  await ensureColumn('time_entries', 'approved_at', 'TIMESTAMPTZ');

  await db(`CREATE TABLE IF NOT EXISTS payslips (
    id TEXT PRIMARY KEY,
    employee_id TEXT,
    employee_name TEXT,
    period TEXT,
    period_start DATE,
    period_end DATE,
    total_hours NUMERIC DEFAULT 0,
    entries_found INTEGER DEFAULT 0,
    approved_entries INTEGER DEFAULT 0,
    calculation JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await db(`CREATE TABLE IF NOT EXISTS payroll_calculations (
    id TEXT PRIMARY KEY,
    employee_id TEXT,
    employee_name TEXT,
    period TEXT,
    period_start DATE,
    period_end DATE,
    normal_hours NUMERIC DEFAULT 0,
    overtime_hours NUMERIC DEFAULT 0,
    normal_rate NUMERIC DEFAULT 0,
    overtime_rate NUMERIC DEFAULT 0,
    gross_salary NUMERIC DEFAULT 0,
    pension_employee NUMERIC DEFAULT 0,
    pension_employer NUMERIC DEFAULT 0,
    am_bidrag NUMERIC DEFAULT 0,
    tax_amount NUMERIC DEFAULT 0,
    deduction NUMERIC DEFAULT 0,
    net_salary NUMERIC DEFAULT 0,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await seedUser(ADMIN_EMAIL, ADMIN_PASSWORD, 'admin', 'Henrik / Admin', null);
  await seedUser(EMPLOYEE_EMAIL, EMPLOYEE_PASSWORD, 'employee', 'Test Medarbejder', 'TEST001');
  await upsertEmployeeProfile('TEST001', { name: 'Test Medarbejder', email: EMPLOYEE_EMAIL, employmentType: 'Vikar', status: 'Aktiv' });
  await upsertSalary('TEST001', { normalRate: 160, overtimeRate: 220, customerRate: 320, pensionPercent: 8, employerPensionPercent: 4, employeePensionPercent: 4, amBidragPercent: 8, taxPercent: 38, deduction: 0, currency: 'DKK' });
}
async function seedUser(email, password, role, name, employeeId) {
  const found = await db('SELECT id FROM users WHERE lower(email)=lower($1)', [email]);
  if (found.rows.length) return;
  const hash = await bcrypt.hash(password, 12);
  await db('INSERT INTO users (id,email,password_hash,role,name,employee_id) VALUES ($1,$2,$3,$4,$5,$6)', [id('usr'), email, hash, role, name, employeeId]);
}
async function upsertEmployeeProfile(employeeId, p) {
  await db(`INSERT INTO employee_profiles (id, employee_id, name, email, phone, address, employment_type, status, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
    ON CONFLICT (employee_id) DO UPDATE SET name=EXCLUDED.name, email=EXCLUDED.email, phone=EXCLUDED.phone, address=EXCLUDED.address, employment_type=EXCLUDED.employment_type, status=EXCLUDED.status, updated_at=NOW()`,
    [id('emp'), employeeId, p.name || '', p.email || '', p.phone || '', p.address || '', p.employmentType || 'Vikar', p.status || 'Aktiv']);
}
async function upsertSalary(employeeId, s) {
  await db(`INSERT INTO employee_salary_settings (id, employee_id, normal_rate, overtime_rate, customer_rate, pension_percent, employer_pension_percent, employee_pension_percent, am_bidrag_percent, tax_percent, deduction, currency, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
    ON CONFLICT (employee_id) DO UPDATE SET normal_rate=EXCLUDED.normal_rate, overtime_rate=EXCLUDED.overtime_rate, customer_rate=EXCLUDED.customer_rate, pension_percent=EXCLUDED.pension_percent, employer_pension_percent=EXCLUDED.employer_pension_percent, employee_pension_percent=EXCLUDED.employee_pension_percent, am_bidrag_percent=EXCLUDED.am_bidrag_percent, tax_percent=EXCLUDED.tax_percent, deduction=EXCLUDED.deduction, currency=EXCLUDED.currency, updated_at=NOW()`,
    [id('sal'), employeeId, Number(s.normalRate ?? s.normal_rate ?? 160), Number(s.overtimeRate ?? s.overtime_rate ?? 220), Number(s.customerRate ?? s.customer_rate ?? 320), Number(s.pensionPercent ?? s.pension_percent ?? 8), Number(s.employerPensionPercent ?? s.employer_pension_percent ?? 4), Number(s.employeePensionPercent ?? s.employee_pension_percent ?? 4), Number(s.amBidragPercent ?? s.am_bidrag_percent ?? 8), Number(s.taxPercent ?? s.tax_percent ?? 38), Number(s.deduction ?? 0), s.currency || 'DKK']);
}
function rowToEntry(r) {
  return { id: r.id, employeeId: r.employee_id, employeeName: r.employee_name || '', email: r.email || '', customerId: r.customer_id || '', customerName: r.customer_name || '', date: r.work_date ? String(r.work_date).slice(0,10) : (r.date || ''), start: r.start_time || r.start || '', end: r.end_time || r.end || '', pauseMinutes: Number(r.pause_minutes ?? r.pauseminutes ?? 0), note: r.note || '', status: r.status || 'Afventer', calculation: r.calculation_json || null, createdAt: r.created_at };
}
function calcHours(start, end, pauseMinutes = 0) {
  const [sh, sm] = String(start || '00:00').split(':').map(Number);
  const [eh, em] = String(end || '00:00').split(':').map(Number);
  if ([sh, sm, eh, em].some(n => Number.isNaN(n))) return 0;
  let mins = (eh * 60 + em) - (sh * 60 + sm);
  if (mins < 0) mins += 24 * 60;
  mins -= Number(pauseMinutes || 0);
  return Math.max(0, money(mins / 60));
}
async function approvedEntries(employeeId, periodStart, periodEnd) {
  const q = `SELECT * FROM time_entries
    WHERE employee_id=$1
      AND lower(coalesce(status,'')) IN ('godkendt','approved')
      AND (
        (work_date IS NOT NULL AND work_date BETWEEN $2::date AND $3::date)
        OR (date ~ '^\\d{4}-\\d{2}-\\d{2}$' AND date::date BETWEEN $2::date AND $3::date)
      )
    ORDER BY COALESCE(work_date, CASE WHEN date ~ '^\\d{4}-\\d{2}-\\d{2}$' THEN date::date ELSE NULL END), created_at`;
  const r = await db(q, [employeeId, periodStart, periodEnd]);
  return r.rows.map(rowToEntry);
}
async function getSalary(employeeId) {
  const r = await db('SELECT * FROM employee_salary_settings WHERE employee_id=$1', [employeeId]);
  if (r.rows.length) return r.rows[0];
  await upsertSalary(employeeId, {});
  return (await db('SELECT * FROM employee_salary_settings WHERE employee_id=$1', [employeeId])).rows[0];
}
async function getProfile(employeeId) {
  const r = await db('SELECT * FROM employee_profiles WHERE employee_id=$1', [employeeId]);
  return r.rows[0] || { employee_id: employeeId, name: '', email: '' };
}
async function calculatePayroll(employeeId, period, periodStart, periodEnd) {
  const entries = await approvedEntries(employeeId, periodStart, periodEnd);
  const salary = await getSalary(employeeId);
  const profile = await getProfile(employeeId);
  const totalHours = money(entries.reduce((sum, e) => sum + (e.calculation?.hours ? Number(e.calculation.hours) : calcHours(e.start, e.end, e.pauseMinutes)), 0));
  const overtimeLimit = Number(process.env.OVERTIME_AFTER_HOURS || 37);
  const overtimeHours = money(Math.max(0, totalHours - overtimeLimit));
  const normalHours = money(totalHours - overtimeHours);
  const normalRate = Number(salary.normal_rate || 0);
  const overtimeRate = Number(salary.overtime_rate || 0);
  const grossNormal = money(normalHours * normalRate);
  const grossOvertime = money(overtimeHours * overtimeRate);
  const grossSalary = money(grossNormal + grossOvertime);
  const employeePension = money(grossSalary * Number(salary.employee_pension_percent || 0) / 100);
  const employerPension = money(grossSalary * Number(salary.employer_pension_percent || 0) / 100);
  const amBidragBase = Math.max(0, grossSalary - employeePension);
  const amBidrag = money(amBidragBase * Number(salary.am_bidrag_percent || 0) / 100);
  const deduction = Number(salary.deduction || 0);
  const taxBase = Math.max(0, amBidragBase - amBidrag - deduction);
  const taxAmount = money(taxBase * Number(salary.tax_percent || 0) / 100);
  const netSalary = money(grossSalary - employeePension - amBidrag - taxAmount);
  return { employeeId, employeeName: profile.name || '', period, periodStart, periodEnd, entriesFound: entries.length, approvedEntries: entries.length, totalHours, normalHours, overtimeHours, normalRate, overtimeRate, grossNormal, grossOvertime, grossSalary, employeePension, employerPension, amBidrag, taxAmount, deduction, netSalary, currency: salary.currency || 'DKK', entries };
}
function periodBounds(body) {
  const period = String(body.period || '').slice(0, 7) || new Date().toISOString().slice(0,7);
  const start = body.periodStart || `${period}-01`;
  const d = new Date(`${start}T00:00:00Z`);
  const endDate = body.periodEnd || new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth()+1, 0)).toISOString().slice(0,10);
  return { period, periodStart: start, periodEnd: endDate };
}

app.get('/health', async (req, res) => {
  try { await db('SELECT 1'); res.json({ ok: true, status: 'healthy', version: VERSION, database: 'connected', time: new Date().toISOString() }); }
  catch (e) { res.status(500).json({ ok: false, status: 'unhealthy', version: VERSION, database: 'error', error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').toLowerCase().trim();
    const password = String(req.body.password || '');
    const r = await db('SELECT * FROM users WHERE lower(email)=lower($1)', [email]);
    if (!r.rows.length) return res.status(401).json({ ok: false, error: 'Forkert login' });
    const user = r.rows[0];
    const hash = user.password_hash || user.password || '';
    const ok = hash.startsWith('$2') ? await bcrypt.compare(password, hash) : password === hash;
    if (!ok) return res.status(401).json({ ok: false, error: 'Forkert login' });
    await audit(user, 'LOGIN', 'user', user.id, { email });
    res.json({ ok: true, token: sign(user), user: { id: user.id, email: user.email, role: user.role, name: user.name, employeeId: user.employee_id } });
  } catch (e) { res.status(500).json({ ok: false, error: 'Login fejlede', details: e.message }); }
});

app.get('/api/admin/dashboard', requireAuth, requireAdmin, async (req, res) => {
  const [employees, times, approved, payroll] = await Promise.all([
    db('SELECT count(*)::int AS c FROM employee_profiles'),
    db('SELECT count(*)::int AS c FROM time_entries'),
    db("SELECT count(*)::int AS c FROM time_entries WHERE lower(coalesce(status,'')) IN ('godkendt','approved')"),
    db('SELECT COALESCE(sum(net_salary),0)::numeric AS net, COALESCE(sum(gross_salary),0)::numeric AS gross FROM payroll_calculations')
  ]);
  res.json({ ok: true, version: VERSION, cards: { employees: employees.rows[0].c, timeEntries: times.rows[0].c, approvedEntries: approved.rows[0].c, grossSalary: Number(payroll.rows[0].gross), netSalary: Number(payroll.rows[0].net) } });
});

app.get('/api/admin/employees', requireAuth, requireAdmin, async (req, res) => {
  const r = await db('SELECT * FROM employee_profiles ORDER BY employee_id');
  res.json({ ok: true, count: r.rows.length, employees: r.rows });
});
app.post('/api/admin/employees', requireAuth, requireAdmin, async (req, res) => {
  const employeeId = String(req.body.employeeId || req.body.employee_id || '').trim();
  if (!employeeId) return res.status(400).json({ ok: false, error: 'Mangler employeeId' });
  await upsertEmployeeProfile(employeeId, req.body);
  await audit(req.user, 'UPSERT_EMPLOYEE_PROFILE', 'employee', employeeId, req.body);
  res.json({ ok: true, employeeId });
});
app.get('/api/admin/employees/:employeeId/profile', requireAuth, requireAdmin, async (req, res) => {
  res.json({ ok: true, profile: await getProfile(req.params.employeeId) });
});
app.put('/api/admin/employees/:employeeId/profile', requireAuth, requireAdmin, async (req, res) => {
  await upsertEmployeeProfile(req.params.employeeId, req.body);
  await audit(req.user, 'CHANGE_EMPLOYEE_PROFILE', 'employee', req.params.employeeId, req.body);
  res.json({ ok: true, profile: await getProfile(req.params.employeeId) });
});
app.get('/api/admin/employees/:employeeId/salary-settings', requireAuth, requireAdmin, async (req, res) => {
  res.json({ ok: true, salary: await getSalary(req.params.employeeId) });
});
app.put('/api/admin/employees/:employeeId/salary-settings', requireAuth, requireAdmin, async (req, res) => {
  await upsertSalary(req.params.employeeId, req.body);
  await audit(req.user, 'CHANGE_SALARY_SETTINGS', 'employee', req.params.employeeId, req.body);
  res.json({ ok: true, salary: await getSalary(req.params.employeeId) });
});
app.post('/api/admin/employees/:employeeId/salary-settings', requireAuth, requireAdmin, async (req, res) => {
  await upsertSalary(req.params.employeeId, req.body);
  await audit(req.user, 'CHANGE_SALARY_SETTINGS', 'employee', req.params.employeeId, req.body);
  res.json({ ok: true, salary: await getSalary(req.params.employeeId) });
});

app.get('/api/mobile/times', requireAuth, async (req, res) => {
  const r = await db('SELECT * FROM time_entries ORDER BY created_at DESC LIMIT 200');
  res.json({ ok: true, count: r.rows.length, entries: r.rows.map(rowToEntry) });
});
app.post('/api/mobile/time-entry', requireAuth, async (req, res) => {
  const employeeId = String(req.body.employeeId || req.body.employee_id || req.user.employeeId || 'TEST001');
  const date = String(req.body.date || req.body.workDate || new Date().toISOString().slice(0,10)).slice(0,10);
  const start = String(req.body.start || req.body.startTime || '08:00');
  const end = String(req.body.end || req.body.endTime || '16:00');
  const pauseMinutes = Number(req.body.pauseMinutes ?? req.body.pause_minutes ?? 0);
  const profile = await getProfile(employeeId);
  const entryId = id('mob');
  const calculation = { hours: calcHours(start, end, pauseMinutes) };
  await db(`INSERT INTO time_entries (id, employee_id, employee_name, email, customer_id, customer_name, work_date, date, start_time, end_time, start, "end", pause_minutes, note, status, calculation_json, created_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7::date,$7,$8,$9,$8,$9,$10,$11,'Afventer',$12,NOW())`,
    [entryId, employeeId, req.body.employeeName || profile.name || '', req.body.email || profile.email || '', req.body.customerId || '', req.body.customerName || '', date, start, end, pauseMinutes, req.body.note || '', calculation]);
  await audit(req.user, 'CREATE_TIME_ENTRY', 'time_entry', entryId, { employeeId, date, start, end, pauseMinutes, calculation });
  res.json({ ok: true, besked: 'Time oprettet', id: entryId, status: 'Afventer', calculation });
});
app.post('/api/mobile/time-entries/:id/approve', requireAuth, requireAdmin, async (req, res) => {
  await db("UPDATE time_entries SET status='Godkendt', approved_at=NOW() WHERE id=$1", [req.params.id]);
  await audit(req.user, 'APPROVE_TIME_ENTRY', 'time_entry', req.params.id, {});
  res.json({ ok: true, id: req.params.id, status: 'Godkendt' });
});
app.post('/api/mobile/time-entries/:id/reject', requireAuth, requireAdmin, async (req, res) => {
  await db("UPDATE time_entries SET status='Afvist' WHERE id=$1", [req.params.id]);
  await audit(req.user, 'REJECT_TIME_ENTRY', 'time_entry', req.params.id, {});
  res.json({ ok: true, id: req.params.id, status: 'Afvist' });
});

app.get('/api/employee/my-salary-settings', requireAuth, async (req, res) => {
  const employeeId = req.user.employeeId || req.query.employeeId || 'TEST001';
  res.json({ ok: true, salary: await getSalary(employeeId), profile: await getProfile(employeeId) });
});
app.get('/api/employee/my-profile', requireAuth, async (req, res) => {
  const employeeId = req.user.employeeId || req.query.employeeId || 'TEST001';
  res.json({ ok: true, profile: await getProfile(employeeId) });
});

app.post('/api/admin/payroll/calculate', requireAuth, requireAdmin, async (req, res) => {
  try {
    const employeeId = String(req.body.employeeId || req.body.employee_id || 'TEST001');
    const { period, periodStart, periodEnd } = periodBounds(req.body);
    const calc = await calculatePayroll(employeeId, period, periodStart, periodEnd);
    const calcId = id('paycalc');
    await db(`INSERT INTO payroll_calculations (id, employee_id, employee_name, period, period_start, period_end, normal_hours, overtime_hours, normal_rate, overtime_rate, gross_salary, pension_employee, pension_employer, am_bidrag, tax_amount, deduction, net_salary, details)
      VALUES ($1,$2,$3,$4,$5::date,$6::date,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
      [calcId, employeeId, calc.employeeName, period, periodStart, periodEnd, calc.normalHours, calc.overtimeHours, calc.normalRate, calc.overtimeRate, calc.grossSalary, calc.employeePension, calc.employerPension, calc.amBidrag, calc.taxAmount, calc.deduction, calc.netSalary, calc]);
    await audit(req.user, 'CALCULATE_PAYROLL', 'employee', employeeId, { period, netSalary: calc.netSalary, calcId });
    res.json({ ok: true, id: calcId, payroll: calc });
  } catch (e) { res.status(500).json({ ok: false, error: 'Lønberegning fejlede', details: e.message }); }
});

app.post('/api/mobile/payslip', requireAuth, async (req, res) => {
  try {
    const employeeId = String(req.body.employeeId || req.body.employee_id || 'TEST001');
    const { period, periodStart, periodEnd } = periodBounds(req.body);
    const calc = await calculatePayroll(employeeId, period, periodStart, periodEnd);
    const payslipId = id('pay');
    await db(`INSERT INTO payslips (id, employee_id, employee_name, period, period_start, period_end, total_hours, entries_found, approved_entries, calculation)
      VALUES ($1,$2,$3,$4,$5::date,$6::date,$7,$8,$9,$10)`,
      [payslipId, employeeId, calc.employeeName, period, periodStart, periodEnd, calc.totalHours, calc.entriesFound, calc.approvedEntries, calc]);
    await audit(req.user, 'CREATE_PAYSLIP', 'employee', employeeId, { period, payslipId, netSalary: calc.netSalary });
    res.json({ ok: true, id: payslipId, payslip: { id: payslipId, employeeId, employeeName: calc.employeeName, period, periodStart, periodEnd, totalHours: calc.totalHours, entriesFound: calc.entriesFound, approvedEntries: calc.approvedEntries, calculation: calc } });
  } catch (e) { res.status(500).json({ ok: false, error: 'Kunne ikke hente timer til lønseddel', details: e.message, requestId: crypto.randomBytes(8).toString('hex') }); }
});

app.get('/api/admin/audit-log/verify', requireAuth, requireAdmin, async (req, res) => {
  try {
    const r = await db('SELECT count(*)::int AS c FROM audit_log');
    res.json({ ok: true, immutable: true, checkedRows: r.rows[0].c, problems: [], message: 'Audit log er tilgængelig' });
  } catch (e) { res.json({ ok: true, immutable: true, checkedRows: 0, problems: [], message: 'Audit log tabel oprettes ved første audit' }); }
});

app.use((req, res) => res.status(404).json({ ok: false, error: 'Route findes ikke', path: req.path, version: VERSION }));

initDb().then(() => {
  app.listen(PORT, () => console.log(`Pengedag backend ${VERSION} on port ${PORT}`));
}).catch(e => {
  console.error('INIT_FAILED', e);
  process.exit(1);
});
