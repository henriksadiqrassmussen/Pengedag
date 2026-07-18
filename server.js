
import express from "express";
import cors from "cors";
import pkg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import PDFDocument from "pdfkit";
import nodemailer from "nodemailer";

const { Pool } = pkg;
const app = express();

const VERSION = "2.2.1-restore-perfect-ui";
console.log("### PENGEDAG SERVER.JS 2.2.1 RESTORE PERFECT UI LOADED ###");

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "pengedag-dev-secret-change-me";
const DATABASE_URL = process.env.DATABASE_URL;

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "2mb" }));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && DATABASE_URL.includes("railway") ? { rejectUnauthorized:false } : undefined
});

async function q(sql, params=[]) { return pool.query(sql, params); }
function uid(prefix="id") { return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2)}`; }
function num(v, fallback=0) { const n = Number(v); return Number.isFinite(n) ? n : fallback; }

function hoursBetween(start, end, pauseMinutes=0) {
  if (!start || !end) return 0;
  const [sh, sm] = String(start).split(":").map(Number);
  const [eh, em] = String(end).split(":").map(Number);
  if (!Number.isFinite(sh) || !Number.isFinite(eh)) return 0;
  let a = sh * 60 + (sm || 0);
  let b = eh * 60 + (em || 0);
  if (b < a) b += 24 * 60;
  return Math.max(0, (b - a - num(pauseMinutes)) / 60);
}

async function ensureCoreTables() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    role TEXT DEFAULT 'employee',
    name TEXT,
    employee_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'employee'`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_id TEXT`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`);

  await q(`CREATE TABLE IF NOT EXISTS employee_salary_settings (
    employee_id TEXT PRIMARY KEY,
    normal_rate NUMERIC DEFAULT 160,
    overtime_rate NUMERIC DEFAULT 220,
    customer_rate NUMERIC DEFAULT 320,
    pension_percent NUMERIC DEFAULT 8,
    pension_employer_percent NUMERIC DEFAULT 4,
    pension_employee_percent NUMERIC DEFAULT 4,
    am_percent NUMERIC DEFAULT 8,
    tax_percent NUMERIC DEFAULT 38,
    deduction NUMERIC DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await q(`ALTER TABLE employee_salary_settings ADD COLUMN IF NOT EXISTS normal_rate NUMERIC DEFAULT 160`);
  await q(`ALTER TABLE employee_salary_settings ADD COLUMN IF NOT EXISTS overtime_rate NUMERIC DEFAULT 220`);
  await q(`ALTER TABLE employee_salary_settings ADD COLUMN IF NOT EXISTS customer_rate NUMERIC DEFAULT 320`);
  await q(`ALTER TABLE employee_salary_settings ADD COLUMN IF NOT EXISTS pension_percent NUMERIC DEFAULT 8`);
  await q(`ALTER TABLE employee_salary_settings ADD COLUMN IF NOT EXISTS pension_employer_percent NUMERIC DEFAULT 4`);
  await q(`ALTER TABLE employee_salary_settings ADD COLUMN IF NOT EXISTS pension_employee_percent NUMERIC DEFAULT 4`);
  await q(`ALTER TABLE employee_salary_settings ADD COLUMN IF NOT EXISTS am_percent NUMERIC DEFAULT 8`);
  await q(`ALTER TABLE employee_salary_settings ADD COLUMN IF NOT EXISTS tax_percent NUMERIC DEFAULT 38`);
  await q(`ALTER TABLE employee_salary_settings ADD COLUMN IF NOT EXISTS deduction NUMERIC DEFAULT 0`);
  await q(`ALTER TABLE employee_salary_settings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`);

  await q(`CREATE TABLE IF NOT EXISTS pd_time_entries (
    id TEXT PRIMARY KEY,
    employee_id TEXT NOT NULL,
    employee_name TEXT,
    email TEXT,
    work_date DATE NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    pause_minutes NUMERIC DEFAULT 0,
    note TEXT,
    status TEXT DEFAULT 'Afventer',
    hours NUMERIC DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    approved_at TIMESTAMPTZ,
    approved_by TEXT
  )`);

  await q(`CREATE TABLE IF NOT EXISTS pd_payroll_calculations (
    id TEXT PRIMARY KEY,
    employee_id TEXT,
    employee_name TEXT,
    period TEXT,
    total_hours NUMERIC DEFAULT 0,
    gross_salary NUMERIC DEFAULT 0,
    pension_employee NUMERIC DEFAULT 0,
    pension_employer NUMERIC DEFAULT 0,
    am_bidrag NUMERIC DEFAULT 0,
    tax_amount NUMERIC DEFAULT 0,
    net_salary NUMERIC DEFAULT 0,
    revenue NUMERIC DEFAULT 0,
    margin NUMERIC DEFAULT 0,
    payload JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    actor_email TEXT,
    action TEXT,
    target_type TEXT,
    target_id TEXT,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await q(`ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS details JSONB`);
}

async function seedUser(email, password, role, name, employeeId) {
  const hash = await bcrypt.hash(password, 10);
  const existing = await q("SELECT id FROM users WHERE email=$1", [email]);
  if (existing.rows.length) {
    await q(`UPDATE users SET password_hash=$2, role=$3, name=$4, employee_id=$5 WHERE email=$1`,
      [email, hash, role, name, employeeId]);
  } else {
    await q(`INSERT INTO users (id,email,password_hash,role,name,employee_id) VALUES ($1,$2,$3,$4,$5,$6)`,
      [uid("user"), email, hash, role, name, employeeId]);
  }
}

async function seed() {
  await ensureCoreTables();
  await seedUser("vault1973@gmail.com", "PengedagAdmin2026!", "admin", "Ejer", "ADMIN");
  await seedUser("medarbejder@pengedag.dk", "MedarbejderTest2026!", "employee", "Test Medarbejder", "TEST001");
  await q(`INSERT INTO employee_salary_settings (employee_id) VALUES ('TEST001') ON CONFLICT (employee_id) DO NOTHING`);
}

function sign(user) {
  return jwt.sign({ id:user.id, email:user.email, role:user.role, name:user.name, employeeId:user.employee_id }, JWT_SECRET, { expiresIn:"7d" });
}

function auth(role=null) {
  return async (req,res,next) => {
    try {
      const h = req.headers.authorization || "";
      const token = h.startsWith("Bearer ") ? h.slice(7) : "";
      if (!token) return res.status(401).json({ ok:false, error:"Mangler login-token" });
      const user = jwt.verify(token, JWT_SECRET);
      if (role && user.role !== role) return res.status(403).json({ ok:false, error:"Ingen adgang" });
      req.user = user;
      next();
    } catch(e) {
      return res.status(401).json({ ok:false, error:"Ugyldigt login", details:e.message });
    }
  };
}

async function audit(user, action, targetType, targetId, details={}) {
  try {
    await ensureCoreTables();
    await q(`INSERT INTO audit_log (id,actor_email,action,target_type,target_id,details)
      VALUES ($1,$2,$3,$4,$5,$6)`, [uid("audit"), user?.email || "", action, targetType, targetId, details]);
  } catch(e) { console.error("audit ignored", e.message); }
}

app.get("/health", async (req,res) => {
  try {
    await ensureCoreTables();
    await q("SELECT 1");
    res.json({ ok:true, status:"healthy", version:VERSION, marker:"RESTORE_UI_2_2_1", database:"connected", time:new Date().toISOString() });
  } catch(e) {
    res.status(500).json({ ok:false, status:"unhealthy", version:VERSION, error:e.message });
  }
});

app.post("/api/auth/login", async (req,res) => {
  try {
    await ensureCoreTables();
    const { email, password } = req.body || {};
    const r = await q("SELECT * FROM users WHERE email=$1", [String(email || "").toLowerCase()]);
    if (!r.rows.length) return res.status(401).json({ ok:false, error:"Forkert login" });
    const user = r.rows[0];
    const ok = await bcrypt.compare(String(password || ""), user.password_hash || "");
    if (!ok) return res.status(401).json({ ok:false, error:"Forkert login" });
    res.json({ ok:true, token:sign(user), user:{ email:user.email, role:user.role, name:user.name, employeeId:user.employee_id }});
  } catch(e) {
    res.status(500).json({ ok:false, error:"Login-fejl", details:e.message });
  }
});

app.post("/api/mobile/time-entry", auth(), async (req,res) => {
  try {
    await ensureCoreTables();
    const b = req.body || {};
    const employeeId = String(b.employeeId || req.user.employeeId || "TEST001");
    const employeeName = String(b.employeeName || req.user.name || "Medarbejder");
    const date = String(b.date || b.workDate || new Date().toISOString().slice(0,10)).slice(0,10);
    const start = String(b.start || b.startTime || "08:00").slice(0,5);
    const end = String(b.end || b.endTime || "16:00").slice(0,5);
    const pause = num(b.pauseMinutes ?? b.pause ?? 0);
    const hours = Number(hoursBetween(start, end, pause).toFixed(2));
    const id = uid("mob");

    await q(`INSERT INTO pd_time_entries
      (id, employee_id, employee_name, email, work_date, start_time, end_time, pause_minutes, note, status, hours)
      VALUES ($1,$2,$3,$4,$5::date,$6,$7,$8,$9,'Afventer',$10)`,
      [id, employeeId, employeeName, req.user.email || "", date, start, end, pause, String(b.note || ""), hours]);

    await audit(req.user, "CREATE_TIME_ENTRY", "pd_time_entry", id, { employeeId, date, start, end, hours });
    res.json({ ok:true, message:"Time oprettet", id, hours, status:"Afventer" });
  } catch(e) {
    console.error("CREATE_TIME_ENTRY_ERROR", e);
    res.status(500).json({ ok:false, error:"Kunne ikke oprette time", details:e.message, code:e.code || null });
  }
});

app.get("/api/mobile/times", auth(), async (req,res) => {
  try {
    await ensureCoreTables();
    const r = await q(`SELECT id, employee_id AS "employeeId", employee_name AS "employeeName", email,
      work_date::text AS date, start_time AS start, end_time AS "end",
      pause_minutes AS "pauseMinutes", note, status, hours, created_at AS "createdAt",
      approved_at AS "approvedAt", approved_by AS "approvedBy"
      FROM pd_time_entries ORDER BY created_at DESC LIMIT 500`);
    res.json({ ok:true, count:r.rows.length, entries:r.rows.map(x => ({ ...x, hours:Number(x.hours || 0) })) });
  } catch(e) {
    res.status(500).json({ ok:false, error:"Kunne ikke hente timer", details:e.message, code:e.code || null });
  }
});

app.post("/api/mobile/time-entries/:id/approve", auth("admin"), async (req,res) => {
  try {
    await ensureCoreTables();
    const r = await q(`UPDATE pd_time_entries SET status='Godkendt', approved_at=NOW(), approved_by=$2 WHERE id=$1 RETURNING *`, [req.params.id, req.user.email]);
    if (!r.rows.length) return res.status(404).json({ ok:false, error:"Time ikke fundet" });
    await audit(req.user, "APPROVE_TIME_ENTRY", "pd_time_entry", req.params.id, {});
    res.json({ ok:true, entry:r.rows[0] });
  } catch(e) {
    res.status(500).json({ ok:false, error:"Kunne ikke godkende time", details:e.message, code:e.code || null });
  }
});

app.get("/api/admin/employees/:employeeId/salary-settings", auth("admin"), async (req,res) => {
  try {
    await ensureCoreTables();
    const employeeId = req.params.employeeId;
    await q(`INSERT INTO employee_salary_settings (employee_id) VALUES ($1) ON CONFLICT (employee_id) DO NOTHING`, [employeeId]);
    const r = await q(`SELECT * FROM employee_salary_settings WHERE employee_id=$1`, [employeeId]);
    const s = r.rows[0] || {};
    res.json({ ok:true, settings:{
      employee_id: employeeId,
      normal_rate: Number(s.normal_rate ?? 160), overtime_rate: Number(s.overtime_rate ?? 220), customer_rate: Number(s.customer_rate ?? 320),
      pension_percent: Number(s.pension_percent ?? 8), pension_employer_percent: Number(s.pension_employer_percent ?? 4),
      pension_employee_percent: Number(s.pension_employee_percent ?? 4), am_percent: Number(s.am_percent ?? 8),
      tax_percent: Number(s.tax_percent ?? 38), deduction: Number(s.deduction ?? 0),
      normalRate: Number(s.normal_rate ?? 160), overtimeRate: Number(s.overtime_rate ?? 220), customerRate: Number(s.customer_rate ?? 320),
      pensionPercent: Number(s.pension_percent ?? 8), pensionEmployerPercent: Number(s.pension_employer_percent ?? 4),
      pensionEmployeePercent: Number(s.pension_employee_percent ?? 4), amPercent: Number(s.am_percent ?? 8), taxPercent: Number(s.tax_percent ?? 38)
    }});
  } catch(e) {
    res.status(500).json({ ok:false, error:"Kunne ikke hente lønprofil", details:e.message, code:e.code || null });
  }
});

app.put("/api/admin/employees/:employeeId/salary-settings", auth("admin"), async (req,res) => {
  try {
    await ensureCoreTables();
    const employeeId = req.params.employeeId;
    const b = req.body || {};
    const vals = [employeeId, num(b.normalRate ?? b.normal_rate,160), num(b.overtimeRate ?? b.overtime_rate,220), num(b.customerRate ?? b.customer_rate,320), num(b.pensionPercent ?? b.pension_percent,8), num(b.pensionEmployerPercent ?? b.pension_employer_percent,4), num(b.pensionEmployeePercent ?? b.pension_employee_percent,4), num(b.amPercent ?? b.am_percent,8), num(b.taxPercent ?? b.tax_percent,38), num(b.deduction,0)];
    await q(`INSERT INTO employee_salary_settings
      (employee_id, normal_rate, overtime_rate, customer_rate, pension_percent, pension_employer_percent, pension_employee_percent, am_percent, tax_percent, deduction, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
      ON CONFLICT (employee_id) DO UPDATE SET normal_rate=EXCLUDED.normal_rate, overtime_rate=EXCLUDED.overtime_rate, customer_rate=EXCLUDED.customer_rate, pension_percent=EXCLUDED.pension_percent, pension_employer_percent=EXCLUDED.pension_employer_percent, pension_employee_percent=EXCLUDED.pension_employee_percent, am_percent=EXCLUDED.am_percent, tax_percent=EXCLUDED.tax_percent, deduction=EXCLUDED.deduction, updated_at=NOW()`, vals);
    res.json({ ok:true, message:"Lønprofil gemt" });
  } catch(e) {
    res.status(500).json({ ok:false, error:"Kunne ikke gemme lønprofil", details:e.message, code:e.code || null });
  }
});

async function salarySettings(employeeId) {
  await q(`INSERT INTO employee_salary_settings (employee_id) VALUES ($1) ON CONFLICT (employee_id) DO NOTHING`, [employeeId]);
  const r = await q("SELECT * FROM employee_salary_settings WHERE employee_id=$1", [employeeId]);
  return r.rows[0] || {};
}

async function calculatePayroll(employeeId, period) {
  await ensureCoreTables();
  const start = `${period}-01`;
  const endDate = new Date(Number(period.slice(0,4)), Number(period.slice(5,7)), 0).toISOString().slice(0,10);
  const tr = await q(`SELECT * FROM pd_time_entries WHERE employee_id=$1 AND status='Godkendt' AND work_date BETWEEN $2::date AND $3::date ORDER BY created_at DESC`, [employeeId, start, endDate]);
  const totalHours = Number(tr.rows.reduce((s,e) => s + num(e.hours), 0).toFixed(2));
  const normalHours = Math.min(totalHours, 160);
  const overtimeHours = Math.max(0, totalHours - 160);
  const s = await salarySettings(employeeId);
  const normalRate = num(s.normal_rate,160), overtimeRate = num(s.overtime_rate,220), customerRate = num(s.customer_rate,320);
  const grossSalary = Number((normalHours*normalRate + overtimeHours*overtimeRate).toFixed(2));
  const pensionEmployee = Number((grossSalary * num(s.pension_employee_percent,4) / 100).toFixed(2));
  const pensionEmployer = Number((grossSalary * num(s.pension_employer_percent,4) / 100).toFixed(2));
  const amBase = Math.max(0, grossSalary - pensionEmployee);
  const amBidrag = Number((amBase * num(s.am_percent,8) / 100).toFixed(2));
  const taxBase = Math.max(0, amBase - amBidrag - num(s.deduction,0));
  const taxAmount = Number((taxBase * num(s.tax_percent,38) / 100).toFixed(2));
  const netSalary = Number((grossSalary - pensionEmployee - amBidrag - taxAmount).toFixed(2));
  const revenue = Number((totalHours * customerRate).toFixed(2));
  const margin = Number((revenue - grossSalary - pensionEmployer).toFixed(2));
  return { employeeId, employeeName:tr.rows[0]?.employee_name || employeeId, period, periodStart:start, periodEnd:endDate, approvedEntries:tr.rows.length, totalHours, normalHours, overtimeHours, normalRate, overtimeRate, customerRate, grossSalary, pensionEmployee, pensionEmployer, amBidrag, taxAmount, netSalary, revenue, margin, entries:tr.rows };
}

app.post("/api/admin/payroll/calculate", auth("admin"), async (req,res) => {
  try {
    const c = await calculatePayroll(String(req.body.employeeId || "TEST001"), String(req.body.period || new Date().toISOString().slice(0,7)));
    const id = uid("paycalc");
    try { await q(`INSERT INTO pd_payroll_calculations (id, employee_id, employee_name, period, total_hours, gross_salary, pension_employee, pension_employer, am_bidrag, tax_amount, net_salary, revenue, margin, payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, [id,c.employeeId,c.employeeName,c.period,c.totalHours,c.grossSalary,c.pensionEmployee,c.pensionEmployer,c.amBidrag,c.taxAmount,c.netSalary,c.revenue,c.margin,c]); } catch(e) { console.error("payroll log ignored", e.message); }
    res.json({ ok:true, id, calculation:c });
  } catch(e) {
    res.status(500).json({ ok:false, error:"Kunne ikke beregne løn", details:e.message, code:e.code || null });
  }
});

function createPdf(payload) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin:44, size:"A4" });
    const chunks = [];
    doc.on("data", d => chunks.push(d)); doc.on("end", () => resolve(Buffer.concat(chunks))); doc.on("error", reject);
    doc.fontSize(24).text("Pengedag"); doc.fontSize(16).text("Lønseddel"); doc.moveDown();
    doc.fontSize(10).text(`Periode: ${payload.periodStart} - ${payload.periodEnd}`); doc.text(`Medarbejder: ${payload.employeeName || payload.employeeId}`); doc.moveDown();
    [["Timer i alt", payload.totalHours],["Bruttoløn", `${payload.grossSalary} kr.`],["Pension medarbejder", `${payload.pensionEmployee} kr.`],["Pension arbejdsgiver", `${payload.pensionEmployer} kr.`],["AM-bidrag", `${payload.amBidrag} kr.`],["Skat", `${payload.taxAmount} kr.`],["Netto", `${payload.netSalary} kr.`]].forEach(([a,b]) => doc.text(`${a}: ${b}`));
    doc.end();
  });
}

app.post("/api/admin/payslip/pdf", auth("admin"), async (req,res) => {
  try {
    const c = req.body.calculation || await calculatePayroll(String(req.body.employeeId || "TEST001"), String(req.body.period || new Date().toISOString().slice(0,7)));
    const pdf = await createPdf(c);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="loenseddel-${c.employeeId}-${c.period}.pdf"`);
    res.send(pdf);
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke lave PDF", details:e.message }); }
});

app.post("/api/admin/payslip/email", auth("admin"), async (req,res) => {
  try {
    if (!process.env.SMTP_HOST) return res.json({ ok:true, simulated:true, message:"Email simuleret. SMTP er ikke sat op endnu." });
    const transporter = nodemailer.createTransport({ host:process.env.SMTP_HOST, port:Number(process.env.SMTP_PORT || 587), secure:String(process.env.SMTP_SECURE || "false") === "true", auth:{ user:process.env.SMTP_USER, pass:process.env.SMTP_PASS }});
    await transporter.sendMail({ from:process.env.SMTP_FROM || process.env.SMTP_USER, to:req.body.to || "medarbejder@pengedag.dk", subject:"Din lønseddel fra Pengedag", text:"Din lønseddel er klar i Pengedag." });
    res.json({ ok:true, message:"Email sendt" });
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke sende email", details:e.message }); }
});

app.get("/api/admin/reports/summary", auth("admin"), async (req,res) => {
  try {
    const c = await calculatePayroll(String(req.query.employeeId || "TEST001"), String(req.query.period || new Date().toISOString().slice(0,7)));
    res.json({ ok:true, report:{ totalHours:c.totalHours, approvedEntries:c.approvedEntries, grossSalary:c.grossSalary, netSalary:c.netSalary, revenue:c.revenue, margin:c.margin }});
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke hente rapport", details:e.message }); }
});

app.get("/api/debug/times-count", auth("admin"), async (req,res) => {
  try { await ensureCoreTables(); const r = await q("SELECT COUNT(*)::int AS count, MAX(created_at)::text AS latest FROM pd_time_entries"); res.json({ ok:true, version:VERSION, marker:"RESTORE_UI_2_2_1", pd_time_entries:r.rows[0] }); }
  catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

seed().then(() => app.listen(PORT, () => console.log(`Pengedag backend ${VERSION} on port ${PORT}`))).catch(err => { console.error("Startup error", err); app.listen(PORT, () => console.log(`Pengedag backend ${VERSION} on port ${PORT} - started with warning`)); });
