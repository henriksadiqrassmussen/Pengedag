require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "DEV_ONLY_CHANGE_ME";
const DATABASE_URL = process.env.DATABASE_URL;

app.use(helmet());
app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));

if (!DATABASE_URL) {
  console.warn("ADVARSEL: DATABASE_URL mangler. Til Railway: tilføj PostgreSQL DATABASE_URL på backend-servicen.");
}
if (JWT_SECRET === "DEV_ONLY_CHANGE_ME") {
  console.warn("ADVARSEL: JWT_SECRET mangler. Til Railway: tilføj en lang hemmelig JWT_SECRET variable.");
}

const pool = new Pool({
  connectionString: DATABASE_URL || "postgres://postgres:postgres@localhost:5432/postgres",
  ssl: DATABASE_URL && !DATABASE_URL.includes("localhost") ? { rejectUnauthorized: false } : false
});

function nowIso() {
  return new Date().toISOString();
}

function makeId(prefix) {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(6).toString("hex")}`;
}

async function query(sql, params = []) {
  const result = await pool.query(sql, params);
  return result;
}

async function audit(action, actorUserId, targetType, targetId, details = {}) {
  try {
    await query(
      `INSERT INTO audit_log (id, created_at, action, actor_user_id, target_type, target_id, details_json)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [makeId("audit"), nowIso(), action, actorUserId || "system", targetType || "system", targetId || "", JSON.stringify(details)]
    );
  } catch (err) {
    console.error("Audit log fejl:", err.message);
  }
}

async function initDb() {
  // Step 1: Create tables if they do not exist
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('owner','employee','auditor','admin')),
      employee_id TEXT,
      active BOOLEAN NOT NULL DEFAULT TRUE
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS time_entries (
      id TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      employee_id TEXT NOT NULL,
      employee_name TEXT NOT NULL,
      email TEXT DEFAULT '',
      customer_id TEXT DEFAULT '',
      customer_name TEXT DEFAULT '',
      work_date DATE NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT NOT NULL,
      pause_minutes INTEGER NOT NULL DEFAULT 0,
      note TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'Afventer',
      approved_by TEXT DEFAULT '',
      approved_at TIMESTAMPTZ,
      rejected_by TEXT DEFAULT '',
      rejected_at TIMESTAMPTZ,
      calculation_json JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS overtime_rules (
      employee_id TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      normal_rate NUMERIC NOT NULL DEFAULT 160,
      overtime_rate NUMERIC NOT NULL DEFAULT 220,
      customer_rate NUMERIC NOT NULL DEFAULT 320,
      overtime_after_hours NUMERIC NOT NULL DEFAULT 8,
      night_start TEXT NOT NULL DEFAULT '22:00',
      night_end TEXT NOT NULL DEFAULT '06:00',
      night_overtime_enabled BOOLEAN NOT NULL DEFAULT TRUE
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS payslips (
      id TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      employee_id TEXT NOT NULL,
      period TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Afventer kontrol',
      data_json JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL,
      action TEXT NOT NULL,
      actor_user_id TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      details_json JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `);

  // Step 2: Add missing columns to existing tables (safe migrations)
  // This handles v1.6.0 databases that have old table structures
  console.log("Running v1.6.2 database migrations...");
  
  // Migrate time_entries table
  await query(`ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS user_id TEXT DEFAULT '';`);
  await query(`ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS email TEXT DEFAULT '';`);
  await query(`ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS customer_id TEXT DEFAULT '';`);
  await query(`ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS customer_name TEXT DEFAULT '';`);
  await query(`ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS approved_by TEXT DEFAULT '';`);
  await query(`ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;`);
  await query(`ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS rejected_by TEXT DEFAULT '';`);
  await query(`ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMPTZ;`);
  await query(`ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS calculation_json JSONB NOT NULL DEFAULT '{}'::jsonb;`);

  // Migrate users table
  await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_id TEXT;`);
  await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;`);

  // CRITICAL: Migrate audit_log table - add missing columns BEFORE creating indexes
  // The old v1.6.0 audit_log table may have different structure, so we ensure all columns exist
  await query(`ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS id TEXT;`);
  await query(`ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();`);
  await query(`ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT '';`);
  await query(`ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS actor_user_id TEXT DEFAULT '';`);
  await query(`ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS target_type TEXT DEFAULT '';`);
  await query(`ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS target_id TEXT DEFAULT '';`);
  await query(`ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS details_json JSONB NOT NULL DEFAULT '{}'::jsonb;`);

  // Step 3: Create indexes only AFTER all columns exist
  console.log("Creating database indexes...");
  await query(`CREATE INDEX IF NOT EXISTS idx_time_entries_user_id ON time_entries(user_id);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_time_entries_employee_id ON time_entries(employee_id);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_time_entries_status ON time_entries(status);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_audit_log_actor_user_id ON audit_log(actor_user_id);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);`);
  
  console.log("Database migrations completed successfully");
}

function createToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
      employeeId: user.employee_id || ""
    },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) return res.status(401).json({ ok: false, error: "Mangler login token" });
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await query("SELECT * FROM users WHERE id=$1 AND active=true", [payload.sub]);
    if (!result.rows.length) return res.status(401).json({ ok: false, error: "Bruger findes ikke eller er deaktiveret" });
    req.user = result.rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: "Ugyldigt eller udløbet login" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ ok: false, error: "Login kræves" });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ ok: false, error: "Ingen adgang", requiredRoles: roles, yourRole: req.user.role });
    }
    next();
  };
}

function toPublicUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    employeeId: row.employee_id || "",
    active: row.active,
    createdAt: row.created_at
  };
}

function calcHours(start, end, pauseMinutes) {
  const [sh, sm] = String(start).split(":").map(Number);
  const [eh, em] = String(end).split(":").map(Number);
  let startM = sh * 60 + sm;
  let endM = eh * 60 + em;
  if (endM < startM) endM += 24 * 60;
  const worked = Math.max(0, endM - startM - (Number(pauseMinutes) || 0));
  return Math.round((worked / 60) * 100) / 100;
}

async function getRule(employeeId) {
  const r = await query("SELECT * FROM overtime_rules WHERE employee_id=$1", [employeeId]);
  if (r.rows.length) return r.rows[0];
  return {
    normal_rate: 160,
    overtime_rate: 220,
    customer_rate: 320,
    overtime_after_hours: 8,
    night_overtime_enabled: true
  };
}

async function buildCalculation(employeeId, start, end, pauseMinutes) {
  const rule = await getRule(employeeId);
  const hours = calcHours(start, end, pauseMinutes);
  const overtimeHours = Math.max(0, hours - Number(rule.overtime_after_hours || 8));
  const normalHours = Math.max(0, hours - overtimeHours);
  const employeePay = Math.round((normalHours * Number(rule.normal_rate || 160) + overtimeHours * Number(rule.overtime_rate || 220)) * 100) / 100;
  const customerTotalExVat = Math.round(hours * Number(rule.customer_rate || 320) * 100) / 100;
  const customerVat = Math.round(customerTotalExVat * 0.25 * 100) / 100;
  const customerTotalIncVat = Math.round((customerTotalExVat + customerVat) * 100) / 100;
  const marginExVat = Math.round((customerTotalExVat - employeePay) * 100) / 100;
  return { hours, normalHours, overtimeHours, employeePay, customerTotalExVat, customerVat, customerTotalIncVat, marginExVat };
}

app.get("/", async (req, res) => {
  let database = "unknown";
  try {
    await query("SELECT 1");
    database = "postgresql";
  } catch (_) {
    database = "disconnected";
  }
  res.json({ ok: true, app: "Pengedag Backend Login", version: "1.6.2-login-migrationfix", database });
});

app.get("/health", async (req, res) => {
  try {
    await query("SELECT 1");
    res.json({ ok: true, status: "healthy", version: "1.6.2-login-migrationfix", database: "connected" });
  } catch (err) {
    res.status(500).json({ ok: false, status: "database_error", version: "1.6.2-login-migrationfix", database: "disconnected", error: err.message });
  }
});

app.get("/api/mobile/routes", (req, res) => {
  res.json({
    ok: true,
    version: "1.6.2-login-migrationfix",
    auth: "Bearer token required on protected routes",
    routes: [
      "POST /api/auth/bootstrap-admin",
      "POST /api/auth/login",
      "GET /api/auth/me",
      "POST /api/auth/users",
      "GET /api/auth/users",
      "GET /api/mobile/time-entries",
      "GET /api/mobile/times",
      "POST /api/mobile/time-entry",
      "POST /api/mobile/time-entries/:id/approve",
      "POST /api/mobile/time-entries/:id/reject",
      "GET /api/admin/audit-log"
    ]
  });
});

app.post("/api/auth/bootstrap-admin", async (req, res) => {
  const existing = await query("SELECT COUNT(*)::int AS count FROM users WHERE role='admin'");
  if (existing.rows[0].count > 0) {
    return res.status(403).json({ ok: false, error: "Admin findes allerede. Brug login." });
  }
  const { name, email, password } = req.body || {};
  if (!name || !email || !password || password.length < 8) {
    return res.status(400).json({ ok: false, error: "name, email og password på mindst 8 tegn kræves" });
  }
  const id = makeId("usr");
  const hash = await bcrypt.hash(password, 12);
  await query(
    `INSERT INTO users (id, created_at, updated_at, name, email, password_hash, role, employee_id, active)
     VALUES ($1,$2,$3,$4,$5,$6,'admin','',true)`,
    [id, nowIso(), nowIso(), name, String(email).toLowerCase(), hash]
  );
  await audit("bootstrap_admin", id, "user", id, { email });
  const user = (await query("SELECT * FROM users WHERE id=$1", [id])).rows[0];
  res.json({ ok: true, user: toPublicUser(user), token: createToken(user) });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok: false, error: "email og password kræves" });
  const result = await query("SELECT * FROM users WHERE email=$1 AND active=true", [String(email).toLowerCase()]);
  if (!result.rows.length) return res.status(401).json({ ok: false, error: "Forkert login" });
  const user = result.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ ok: false, error: "Forkert login" });
  await audit("login", user.id, "user", user.id, { email: user.email });
  res.json({ ok: true, user: toPublicUser(user), token: createToken(user) });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ ok: true, user: toPublicUser(req.user) });
});

app.post("/api/auth/users", requireAuth, requireRole("admin", "owner"), async (req, res) => {
  const { name, email, password, role, employeeId } = req.body || {};
  const allowed = ["owner", "employee", "auditor", "admin"];
  if (!name || !email || !password || !allowed.includes(role)) {
    return res.status(400).json({ ok: false, error: "name, email, password og gyldig role kræves" });
  }
  if (password.length < 8) return res.status(400).json({ ok: false, error: "password skal være mindst 8 tegn" });
  const id = makeId("usr");
  const hash = await bcrypt.hash(password, 12);
  try {
    await query(
      `INSERT INTO users (id, created_at, updated_at, name, email, password_hash, role, employee_id, active)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true)`,
      [id, nowIso(), nowIso(), name, String(email).toLowerCase(), hash, role, employeeId || ""]
    );
    await audit("create_user", req.user.id, "user", id, { email, role });
    const user = (await query("SELECT * FROM users WHERE id=$1", [id])).rows[0];
    res.json({ ok: true, user: toPublicUser(user) });
  } catch (err) {
    res.status(400).json({ ok: false, error: "Kunne ikke oprette bruger", details: err.message });
  }
});

app.get("/api/auth/users", requireAuth, requireRole("admin", "owner", "auditor"), async (req, res) => {
  const result = await query("SELECT * FROM users ORDER BY created_at DESC");
  res.json({ ok: true, count: result.rows.length, users: result.rows.map(toPublicUser) });
});

app.post(["/api/mobile/time-entry", "/api/mobile/time-entries", "/api/mobile/times", "/api/mobile/timesheets", "/api/mobile/entries"], requireAuth, requireRole("employee", "owner", "admin"), async (req, res) => {
  const body = req.body || {};
  const employeeId = req.user.role === "employee" ? (req.user.employee_id || body.employeeId || req.user.id) : (body.employeeId || body.employee_id || "");
  const employeeName = req.user.role === "employee" ? req.user.name : (body.employeeName || body.employee_name || "");
  const date = body.date || body.workDate || body.work_date;
  const start = body.start || body.startTime || body.start_time;
  const end = body.end || body.endTime || body.end_time;
  const pauseMinutes = Number(body.pauseMinutes || body.pause_minutes || 0);
  if (!employeeId || !employeeName || !date || !start || !end) {
    return res.status(400).json({ ok: false, error: "employeeId, employeeName, date, start og end kræves" });
  }
  const id = makeId("mob");
  const calc = await buildCalculation(employeeId, start, end, pauseMinutes);
  await query(
    `INSERT INTO time_entries (id, created_at, updated_at, user_id, employee_id, employee_name, email, customer_id, customer_name, work_date, start_time, end_time, pause_minutes, note, status, calculation_json)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'Afventer',$15)`,
    [id, nowIso(), nowIso(), req.user.id, employeeId, employeeName, body.email || req.user.email || "", body.customerId || "", body.customerName || "", date, start, end, pauseMinutes, body.note || "", JSON.stringify(calc)]
  );
  await audit("create_time_entry", req.user.id, "time_entry", id, { employeeId, date, start, end });
  const entry = (await query("SELECT * FROM time_entries WHERE id=$1", [id])).rows[0];
  res.json({ ok: true, entry: normalizeEntry(entry) });
});

function normalizeEntry(row) {
  return {
    id: row.id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    userId: row.user_id || "",
    employeeId: row.employee_id,
    employeeName: row.employee_name,
    email: row.email,
    customerId: row.customer_id,
    customerName: row.customer_name,
    date: row.work_date,
    start: row.start_time,
    end: row.end_time,
    pauseMinutes: row.pause_minutes,
    note: row.note,
    status: row.status,
    approvedBy: row.approved_by,
    approvedAt: row.approved_at,
    rejectedBy: row.rejected_by,
    rejectedAt: row.rejected_at,
    calculation: row.calculation_json || {}
  };
}

app.get(["/api/mobile/time-entries", "/api/mobile/times", "/api/mobile/timesheets", "/api/mobile/entries"], requireAuth, requireRole("owner", "admin", "auditor", "employee"), async (req, res) => {
  let result;
  if (req.user.role === "employee") {
    result = await query("SELECT * FROM time_entries WHERE employee_id=$1 ORDER BY created_at DESC", [req.user.employee_id || req.user.id]);
  } else {
    result = await query("SELECT * FROM time_entries ORDER BY created_at DESC");
  }
  res.json({ ok: true, count: result.rows.length, entries: result.rows.map(normalizeEntry) });
});

app.post("/api/mobile/time-entries/:id/approve", requireAuth, requireRole("owner", "admin"), async (req, res) => {
  const id = req.params.id;
  const result = await query(
    `UPDATE time_entries SET status='Godkendt', approved_by=$1, approved_at=$2, updated_at=$2 WHERE id=$3 RETURNING *`,
    [req.user.id, nowIso(), id]
  );
  if (!result.rows.length) return res.status(404).json({ ok: false, error: "Timeseddel ikke fundet" });
  await audit("approve_time_entry", req.user.id, "time_entry", id, {});
  res.json({ ok: true, entry: normalizeEntry(result.rows[0]) });
});

app.post("/api/mobile/time-entries/:id/reject", requireAuth, requireRole("owner", "admin"), async (req, res) => {
  const id = req.params.id;
  const result = await query(
    `UPDATE time_entries SET status='Afvist', rejected_by=$1, rejected_at=$2, updated_at=$2 WHERE id=$3 RETURNING *`,
    [req.user.id, nowIso(), id]
  );
  if (!result.rows.length) return res.status(404).json({ ok: false, error: "Timeseddel ikke fundet" });
  await audit("reject_time_entry", req.user.id, "time_entry", id, { reason: req.body?.reason || "" });
  res.json({ ok: true, entry: normalizeEntry(result.rows[0]) });
});

app.get("/api/mobile/overtime-rules/:employeeId", requireAuth, requireRole("owner", "admin", "auditor", "employee"), async (req, res) => {
  if (req.user.role === "employee" && req.params.employeeId !== (req.user.employee_id || req.user.id)) {
    return res.status(403).json({ ok: false, error: "Medarbejder må kun se egne regler" });
  }
  const rule = await getRule(req.params.employeeId);
  res.json({ ok: true, rule });
});

app.post("/api/mobile/overtime-rules", requireAuth, requireRole("owner", "admin"), async (req, res) => {
  const b = req.body || {};
  if (!b.employeeId) return res.status(400).json({ ok: false, error: "employeeId kræves" });
  await query(
    `INSERT INTO overtime_rules (employee_id, created_at, updated_at, normal_rate, overtime_rate, customer_rate, overtime_after_hours, night_start, night_end, night_overtime_enabled)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     ON CONFLICT (employee_id) DO UPDATE SET updated_at=$3, normal_rate=$4, overtime_rate=$5, customer_rate=$6, overtime_after_hours=$7, night_start=$8, night_end=$9, night_overtime_enabled=$10`,
    [b.employeeId, nowIso(), nowIso(), b.normalRate || 160, b.overtimeRate || 220, b.customerRate || 320, b.overtimeAfterHours || 8, b.nightStart || "22:00", b.nightEnd || "06:00", b.nightOvertimeEnabled !== false]
  );
  await audit("set_overtime_rule", req.user.id, "employee", b.employeeId, b);
  res.json({ ok: true });
});

app.post("/api/mobile/payslip", requireAuth, requireRole("owner", "admin"), async (req, res) => {
  const b = req.body || {};
  const id = makeId("pay");
  if (!b.employeeId || !b.period) return res.status(400).json({ ok: false, error: "employeeId og period kræves" });
  await query(
    `INSERT INTO payslips (id, created_at, updated_at, employee_id, period, status, data_json) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [id, nowIso(), nowIso(), b.employeeId, b.period, b.status || "Afventer kontrol", JSON.stringify(b.data || b)]
  );
  await audit("create_payslip", req.user.id, "payslip", id, { employeeId: b.employeeId, period: b.period });
  res.json({ ok: true, id });
});

app.get("/api/mobile/payslip/:employeeId", requireAuth, requireRole("owner", "admin", "auditor", "employee"), async (req, res) => {
  if (req.user.role === "employee" && req.params.employeeId !== (req.user.employee_id || req.user.id)) {
    return res.status(403).json({ ok: false, error: "Medarbejder må kun se egne lønsedler" });
  }
  const r = await query("SELECT * FROM payslips WHERE employee_id=$1 ORDER BY created_at DESC", [req.params.employeeId]);
  res.json({ ok: true, count: r.rows.length, payslips: r.rows });
});

app.get("/api/admin/audit-log", requireAuth, requireRole("admin", "owner", "auditor"), async (req, res) => {
  const r = await query("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200");
  res.json({ ok: true, count: r.rows.length, auditLog: r.rows });
});

app.use((req, res) => {
  res.status(404).json({ ok: false, error: "Not found", path: req.path });
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Pengedag login backend on port ${PORT}`));
  })
  .catch((err) => {
    console.error("Kunne ikke starte database:", err);
    process.exit(1);
  });

