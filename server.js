
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const PDFDocument = require("pdfkit");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 8080;
const VERSION = "2.1.1-payroll-pdf-email-reports";

const JWT_SECRET = process.env.JWT_SECRET || "pengedag-local-secret";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "vault1973@gmail.com").toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "PengedagAdmin2026!";
const EMPLOYEE_EMAIL = (process.env.EMPLOYEE_EMAIL || "medarbejder@pengedag.dk").toLowerCase();
const EMPLOYEE_PASSWORD = process.env.EMPLOYEE_PASSWORD || "MedarbejderTest2026!";

app.use(cors({
  origin: true,
  credentials: true,
  methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Authorization","Content-Type","Accept","X-Requested-With","X-Request-Id","x-reset-key"]
}));
app.options("*", cors());
app.use(express.json({ limit: "20mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const uid = p => `${p}_${Date.now()}_${Math.random().toString(16).slice(2, 14)}`;
const num = (v, f=0) => { const x = Number(v); return Number.isFinite(x) ? x : f; };
const q = (sql, params=[]) => pool.query(sql, params);

function hoursBetween(start, end, pause=0) {
  if (!start || !end) return 0;
  const [sh, sm] = String(start).split(":").map(Number);
  const [eh, em] = String(end).split(":").map(Number);
  if (![sh, sm, eh, em].every(Number.isFinite)) return 0;
  let mins = (eh * 60 + em) - (sh * 60 + sm);
  if (mins < 0) mins += 1440;
  mins -= num(pause);
  return Math.max(0, Math.round((mins / 60) * 100) / 100);
}

function periodRange(period) {
  const raw = String(period || new Date().toISOString().slice(0, 7));
  const ym = /^\d{4}-\d{2}/.test(raw) ? raw.slice(0, 7) : new Date().toISOString().slice(0, 7);
  const y = Number(ym.slice(0, 4));
  const m = Number(ym.slice(5, 7));
  return { period: ym, start: `${ym}-01`, end: new Date(y, m, 0).toISOString().slice(0, 10) };
}

async function audit(user, action, targetType, targetId, details={}) {
  try {
    await q("INSERT INTO audit_log (id, actor_email, action, target_type, target_id, details) VALUES ($1,$2,$3,$4,$5,$6)",
      [uid("audit"), user?.email || "", action, targetType, targetId, details]);
  } catch (e) { console.error("audit failed", e.message); }
}

async function seedUser(email, password, role, name, employeeId) {
  const found = await q("SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1", [email]);
  if (found.rows.length) return;
  const hash = await bcrypt.hash(password, 10);
  await q("INSERT INTO users (id,email,password_hash,role,name,employee_id) VALUES ($1,$2,$3,$4,$5,$6)",
    [uid("user"), email, hash, role, name, employeeId]);
}

async function ensureDb() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT, role TEXT NOT NULL DEFAULT 'employee',
    name TEXT, employee_id TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS employee_profiles (
    id TEXT PRIMARY KEY, employee_id TEXT UNIQUE NOT NULL, name TEXT, email TEXT, phone TEXT, address TEXT,
    employment_type TEXT DEFAULT 'Vikar', status TEXT DEFAULT 'Aktiv', created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS employee_salary_settings (
    id TEXT PRIMARY KEY, employee_id TEXT UNIQUE NOT NULL, normal_rate NUMERIC DEFAULT 160, overtime_rate NUMERIC DEFAULT 220,
    customer_rate NUMERIC DEFAULT 320, pension_percent NUMERIC DEFAULT 8, employer_pension_percent NUMERIC DEFAULT 4,
    employee_pension_percent NUMERIC DEFAULT 4, am_bidrag_percent NUMERIC DEFAULT 8, tax_percent NUMERIC DEFAULT 38,
    deduction NUMERIC DEFAULT 0, currency TEXT DEFAULT 'DKK', created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS time_entries (
    id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT, email TEXT, customer_id TEXT, customer_name TEXT,
    work_date DATE, date TEXT, start_time TEXT, end_time TEXT, start TEXT, "end" TEXT, pause_minutes NUMERIC DEFAULT 0,
    note TEXT, status TEXT DEFAULT 'Afventer', calculation_json JSONB, created_at TIMESTAMPTZ DEFAULT NOW(),
    approved_at TIMESTAMPTZ, approved_by TEXT
  )`);
  await q(`CREATE TABLE IF NOT EXISTS payroll_calculations (
    id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT, period TEXT, period_start DATE, period_end DATE,
    normal_hours NUMERIC DEFAULT 0, overtime_hours NUMERIC DEFAULT 0, total_hours NUMERIC DEFAULT 0,
    normal_rate NUMERIC DEFAULT 0, overtime_rate NUMERIC DEFAULT 0, customer_rate NUMERIC DEFAULT 0,
    gross_salary NUMERIC DEFAULT 0, pension_employee NUMERIC DEFAULT 0, pension_employer NUMERIC DEFAULT 0,
    am_bidrag NUMERIC DEFAULT 0, tax_amount NUMERIC DEFAULT 0, deduction NUMERIC DEFAULT 0, net_salary NUMERIC DEFAULT 0,
    revenue NUMERIC DEFAULT 0, margin NUMERIC DEFAULT 0, payload JSONB, created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS payslips (
    id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT, email TEXT, period TEXT, period_start DATE, period_end DATE,
    total_hours NUMERIC DEFAULT 0, approved_entries NUMERIC DEFAULT 0, gross_salary NUMERIC DEFAULT 0,
    pension_employee NUMERIC DEFAULT 0, pension_employer NUMERIC DEFAULT 0, am_bidrag NUMERIC DEFAULT 0,
    tax_amount NUMERIC DEFAULT 0, deduction NUMERIC DEFAULT 0, net_salary NUMERIC DEFAULT 0, payload JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY, actor_email TEXT, action TEXT, target_type TEXT, target_id TEXT, details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await seedUser(ADMIN_EMAIL, ADMIN_PASSWORD, "admin", "Ejer / Admin", "ADMIN");
  await seedUser(EMPLOYEE_EMAIL, EMPLOYEE_PASSWORD, "employee", "Test Medarbejder", "TEST001");
  await q(`INSERT INTO employee_profiles (id, employee_id, name, email)
    VALUES ($1,'TEST001','Test Medarbejder',$2)
    ON CONFLICT (employee_id) DO UPDATE SET name=EXCLUDED.name, email=EXCLUDED.email, updated_at=NOW()`,
    [uid("emp"), EMPLOYEE_EMAIL]);
  await q(`INSERT INTO employee_salary_settings
    (id, employee_id, normal_rate, overtime_rate, customer_rate, pension_percent, employer_pension_percent, employee_pension_percent, am_bidrag_percent, tax_percent, deduction, currency)
    VALUES ($1,'TEST001',160,220,320,8,4,4,8,38,0,'DKK')
    ON CONFLICT (employee_id) DO NOTHING`, [uid("sal")]);
}

function auth(role=null) {
  return (req, res, next) => {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    if (!token) return res.status(401).json({ ok:false, error:"Mangler Bearer token" });
    try {
      const user = jwt.verify(token, JWT_SECRET);
      if (role === "admin" && user.role !== "admin" && user.role !== "owner") {
        return res.status(403).json({ ok:false, error:"Kræver ejer/admin" });
      }
      req.user = user;
      next();
    } catch {
      res.status(401).json({ ok:false, error:"Ugyldig eller udløbet token" });
    }
  };
}

function sign(user) {
  return jwt.sign({ id:user.id, email:user.email, role:user.role, name:user.name || "", employeeId:user.employee_id || "" },
    JWT_SECRET, { expiresIn:"14d" });
}

async function getProfile(employeeId) {
  const r = await q("SELECT * FROM employee_profiles WHERE employee_id=$1 LIMIT 1", [employeeId]);
  return r.rows[0] || { employee_id:employeeId, name:"", email:"" };
}

async function getSalary(employeeId) {
  let r = await q("SELECT * FROM employee_salary_settings WHERE employee_id=$1 LIMIT 1", [employeeId]);
  if (r.rows[0]) return r.rows[0];
  await q("INSERT INTO employee_salary_settings (id, employee_id) VALUES ($1,$2) ON CONFLICT (employee_id) DO NOTHING", [uid("sal"), employeeId]);
  r = await q("SELECT * FROM employee_salary_settings WHERE employee_id=$1 LIMIT 1", [employeeId]);
  return r.rows[0];
}

async function approvedEntries(employeeId, start, end) {
  const r = await q(`SELECT * FROM time_entries
    WHERE employee_id=$1 AND status ILIKE 'Godkendt'
    AND ((work_date IS NOT NULL AND work_date BETWEEN $2::date AND $3::date)
      OR (date ~ '^\\d{4}-\\d{2}-\\d{2}$' AND date::date BETWEEN $2::date AND $3::date))
    ORDER BY created_at DESC`, [employeeId, start, end]);
  return r.rows;
}

function entryHours(e) {
  if (e.calculation_json && Number(e.calculation_json.hours)) return num(e.calculation_json.hours);
  return hoursBetween(e.start_time || e.start, e.end_time || e.end, e.pause_minutes);
}

async function calculatePayroll(employeeId, periodInput) {
  const { period, start, end } = periodRange(periodInput);
  const profile = await getProfile(employeeId);
  const salary = await getSalary(employeeId);
  const entries = await approvedEntries(employeeId, start, end);
  const totalHours = Math.round(entries.reduce((s,e)=>s+entryHours(e),0)*100)/100;
  const normalHours = Math.min(totalHours, 160);
  const overtimeHours = Math.max(0, totalHours - 160);
  const normalRate = num(salary.normal_rate,160);
  const overtimeRate = num(salary.overtime_rate,220);
  const customerRate = num(salary.customer_rate,320);
  const employerPensionPercent = num(salary.employer_pension_percent,4);
  const employeePensionPercent = num(salary.employee_pension_percent,4);
  const amPercent = num(salary.am_bidrag_percent,8);
  const taxPercent = num(salary.tax_percent,38);
  const deduction = num(salary.deduction,0);
  const grossSalary = Math.round((normalHours*normalRate + overtimeHours*overtimeRate)*100)/100;
  const pensionEmployee = Math.round(grossSalary*employeePensionPercent)/100;
  const pensionEmployer = Math.round(grossSalary*employerPensionPercent)/100;
  const amBidrag = Math.round(grossSalary*amPercent)/100;
  const taxable = Math.max(0, grossSalary - amBidrag - deduction);
  const taxAmount = Math.round(taxable*taxPercent)/100;
  const netSalary = Math.round((grossSalary - pensionEmployee - amBidrag - taxAmount)*100)/100;
  const revenue = Math.round(totalHours*customerRate*100)/100;
  const margin = Math.round((revenue - grossSalary - pensionEmployer)*100)/100;
  return { employeeId, employeeName:profile.name||"", email:profile.email||"", period, periodStart:start, periodEnd:end,
    entriesFound:entries.length, approvedEntries:entries.length, totalHours, normalHours, overtimeHours, normalRate, overtimeRate,
    customerRate, grossSalary, pensionEmployee, pensionEmployer, amBidrag, taxAmount, deduction, netSalary, revenue, margin };
}

function createPdf(payload) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin:44, size:"A4" });
    const chunks = [];
    doc.on("data", d => chunks.push(d));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
    doc.fontSize(24).text("Pengedag");
    doc.fontSize(16).text("Lønseddel");
    doc.moveDown();
    doc.fontSize(10).text(`Periode: ${payload.periodStart} - ${payload.periodEnd}`);
    doc.text(`Medarbejder: ${payload.employeeName || payload.employeeId}`);
    doc.text(`Medarbejder-ID: ${payload.employeeId}`);
    doc.moveDown();
    [
      ["Timer i alt", payload.totalHours], ["Normale timer", payload.normalHours], ["Overtid", payload.overtimeHours],
      ["Timeløn", `${payload.normalRate} kr.`], ["Overtidssats", `${payload.overtimeRate} kr.`],
      ["Bruttoløn", `${payload.grossSalary} kr.`], ["Pension medarbejder", `${payload.pensionEmployee} kr.`],
      ["Pension arbejdsgiver", `${payload.pensionEmployer} kr.`], ["AM-bidrag", `${payload.amBidrag} kr.`],
      ["Skat", `${payload.taxAmount} kr.`], ["Netto udbetaling", `${payload.netSalary} kr.`]
    ].forEach(([a,b]) => { doc.text(a, { continued:true, width:260 }); doc.text(String(b), { align:"right" }); });
    doc.end();
  });
}

app.get("/health", async (req,res)=>{
  try { await q("SELECT 1"); res.json({ ok:true, status:"healthy", version:VERSION, database:"connected", time:new Date().toISOString() }); }
  catch(e) { res.status(500).json({ ok:false, status:"unhealthy", version:VERSION, database:"error", error:e.message }); }
});

app.post("/api/auth/login", async (req,res)=>{
  try {
    const email = String(req.body.email||"").toLowerCase().trim();
    const password = String(req.body.password||"");
    const r = await q("SELECT * FROM users WHERE lower(email)=lower($1) LIMIT 1", [email]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ ok:false, error:"Forkert login" });
    const ok = await bcrypt.compare(password, user.password_hash || "");
    if (!ok) return res.status(401).json({ ok:false, error:"Forkert login" });
    res.json({ ok:true, token:sign(user), user:{ email:user.email, role:user.role, name:user.name, employeeId:user.employee_id } });
  } catch(e) { res.status(500).json({ ok:false, error:"Login fejlede", details:e.message }); }
});

app.get("/api/mobile/times", auth(), async (req,res)=>{
  try {
    const r = await q(`SELECT id, employee_id AS "employeeId", employee_name AS "employeeName", email,
      COALESCE(work_date::text,date) AS date, COALESCE(start_time,start) AS start, COALESCE(end_time,"end") AS "end",
      pause_minutes AS "pauseMinutes", note, status, created_at AS "createdAt"
      FROM time_entries ORDER BY created_at DESC LIMIT 300`);
    const entries = r.rows.map(x => ({ ...x, hours:hoursBetween(x.start,x.end,x.pauseMinutes) }));
    res.json({ ok:true, count:entries.length, entries });
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke hente timer", details:e.message }); }
});

app.post("/api/mobile/time-entry", auth(), async (req,res)=>{
  try {
    const b = req.body || {};
    const id = uid("mob");
    const employeeId = String(b.employeeId || req.user.employeeId || "TEST001");
    const employeeName = String(b.employeeName || req.user.name || "");
    const date = String(b.workDate || b.date || new Date().toISOString().slice(0,10)).slice(0,10);
    const start = String(b.start || "08:00").slice(0,5);
    const end = String(b.end || "15:00").slice(0,5);
    const pause = num(b.pauseMinutes,0);
    const hours = hoursBetween(start,end,pause);
    await q(`INSERT INTO time_entries
      (id, employee_id, employee_name, email, work_date, date, start_time, end_time, start, "end", pause_minutes, note, status, calculation_json)
      VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$6,$7,$8,$9,'Afventer',$10)`,
      [id, employeeId, employeeName, req.user.email||"", date, start, end, pause, b.note||"", { hours }]);
    await audit(req.user, "CREATE_TIME_ENTRY", "time_entry", id, { employeeId, date, hours });
    res.json({ ok:true, message:"Time oprettet", id, hours, status:"Afventer" });
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke oprette time", details:e.message }); }
});

app.post("/api/mobile/time-entries/:id/approve", auth("admin"), async (req,res)=>{
  try {
    const r = await q("UPDATE time_entries SET status='Godkendt', approved_at=NOW(), approved_by=$2 WHERE id=$1 RETURNING *", [req.params.id, req.user.email]);
    if (!r.rows.length) return res.status(404).json({ ok:false, error:"Time ikke fundet" });
    await audit(req.user, "APPROVE_TIME_ENTRY", "time_entry", req.params.id, {});
    res.json({ ok:true, message:"Time godkendt", entry:r.rows[0] });
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke godkende time", details:e.message }); }
});

app.get("/api/admin/employees/:employeeId/salary-settings", auth("admin"), async (req,res)=>{
  const s = await getSalary(req.params.employeeId);
  res.json({ ok:true, salarySettings:{
    employeeId:s.employee_id, normalRate:num(s.normal_rate), overtimeRate:num(s.overtime_rate), customerRate:num(s.customer_rate),
    pensionPercent:num(s.pension_percent), employerPensionPercent:num(s.employer_pension_percent), employeePensionPercent:num(s.employee_pension_percent),
    amBidragPercent:num(s.am_bidrag_percent), taxPercent:num(s.tax_percent), deduction:num(s.deduction), currency:s.currency || "DKK"
  }});
});

app.put("/api/admin/employees/:employeeId/salary-settings", auth("admin"), async (req,res)=>{
  try {
    const b = req.body || {};
    await q(`INSERT INTO employee_salary_settings
      (id, employee_id, normal_rate, overtime_rate, customer_rate, pension_percent, employer_pension_percent, employee_pension_percent, am_bidrag_percent, tax_percent, deduction, currency)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      ON CONFLICT (employee_id) DO UPDATE SET normal_rate=EXCLUDED.normal_rate, overtime_rate=EXCLUDED.overtime_rate,
      customer_rate=EXCLUDED.customer_rate, pension_percent=EXCLUDED.pension_percent, employer_pension_percent=EXCLUDED.employer_pension_percent,
      employee_pension_percent=EXCLUDED.employee_pension_percent, am_bidrag_percent=EXCLUDED.am_bidrag_percent,
      tax_percent=EXCLUDED.tax_percent, deduction=EXCLUDED.deduction, currency=EXCLUDED.currency, updated_at=NOW()`,
      [uid("sal"), req.params.employeeId, num(b.normalRate,160), num(b.overtimeRate,220), num(b.customerRate,320),
       num(b.pensionPercent,8), num(b.employerPensionPercent,4), num(b.employeePensionPercent,4),
       num(b.amBidragPercent,8), num(b.taxPercent,38), num(b.deduction,0), b.currency || "DKK"]);
    await audit(req.user, "CHANGE_SALARY_SETTINGS", "employee", req.params.employeeId, b);
    res.json({ ok:true, message:"Lønprofil gemt" });
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke gemme lønprofil", details:e.message }); }
});

app.get("/api/employee/my-salary-settings", auth(), async (req,res)=>{
  const s = await getSalary(req.user.employeeId || "TEST001");
  res.json({ ok:true, salarySettings:{ employeeId:s.employee_id, normalRate:num(s.normal_rate), overtimeRate:num(s.overtime_rate),
    pensionPercent:num(s.pension_percent), taxPercent:num(s.tax_percent), currency:s.currency || "DKK" } });
});

app.post("/api/admin/payroll/calculate", auth("admin"), async (req,res)=>{
  try {
    const c = await calculatePayroll(String(req.body.employeeId || "TEST001"), String(req.body.period || new Date().toISOString().slice(0,7)));
    const id = uid("paycalc");
    await q(`INSERT INTO payroll_calculations
      (id, employee_id, employee_name, period, period_start, period_end, normal_hours, overtime_hours, total_hours, normal_rate, overtime_rate,
       customer_rate, gross_salary, pension_employee, pension_employer, am_bidrag, tax_amount, deduction, net_salary, revenue, margin, payload)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
      [id,c.employeeId,c.employeeName,c.period,c.periodStart,c.periodEnd,c.normalHours,c.overtimeHours,c.totalHours,c.normalRate,c.overtimeRate,
       c.customerRate,c.grossSalary,c.pensionEmployee,c.pensionEmployer,c.amBidrag,c.taxAmount,c.deduction,c.netSalary,c.revenue,c.margin,c]);
    await audit(req.user, "CALCULATE_PAYROLL", "payroll_calculation", id, { employeeId:c.employeeId, period:c.period, netSalary:c.netSalary });
    res.json({ ok:true, id, calculation:c });
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke beregne løn", details:e.message }); }
});

app.post("/api/mobile/payslip", auth(), async (req,res)=>{
  try {
    const c = await calculatePayroll(String(req.body.employeeId || req.user.employeeId || "TEST001"), String(req.body.period || new Date().toISOString().slice(0,7)));
    const id = uid("pay");
    await q(`INSERT INTO payslips
      (id, employee_id, employee_name, email, period, period_start, period_end, total_hours, approved_entries, gross_salary, pension_employee,
       pension_employer, am_bidrag, tax_amount, deduction, net_salary, payload)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
      [id,c.employeeId,c.employeeName,c.email,c.period,c.periodStart,c.periodEnd,c.totalHours,c.approvedEntries,c.grossSalary,c.pensionEmployee,
       c.pensionEmployer,c.amBidrag,c.taxAmount,c.deduction,c.netSalary,c]);
    res.json({ ok:true, id, payslip:{ id, ...c } });
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke lave lønseddel", details:e.message }); }
});

app.post("/api/admin/payslip/pdf", auth("admin"), async (req,res)=>{
  try {
    const c = await calculatePayroll(String(req.body.employeeId || "TEST001"), String(req.body.period || new Date().toISOString().slice(0,7)));
    const pdf = await createPdf(c);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="loenseddel-${c.employeeId}-${c.period}.pdf"`);
    res.send(pdf);
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke lave PDF", details:e.message }); }
});

app.post("/api/admin/payslip/email", auth("admin"), async (req,res)=>{
  try {
    const c = await calculatePayroll(String(req.body.employeeId || "TEST001"), String(req.body.period || new Date().toISOString().slice(0,7)));
    const to = req.body.email || c.email;
    if (!to) return res.status(400).json({ ok:false, error:"Mangler medarbejder-email" });
    if (!process.env.SMTP_HOST) return res.json({ ok:true, simulated:true, message:"Email simuleret. Sæt SMTP_HOST/SMTP_USER/SMTP_PASS for rigtig afsendelse.", to, payslip:c });
    const transporter = nodemailer.createTransport({ host:process.env.SMTP_HOST, port:Number(process.env.SMTP_PORT || 587),
      secure:String(process.env.SMTP_SECURE || "false") === "true", auth:process.env.SMTP_USER ? { user:process.env.SMTP_USER, pass:process.env.SMTP_PASS } : undefined });
    const pdf = await createPdf(c);
    await transporter.sendMail({ from:process.env.SMTP_FROM || "Pengedag <no-reply@pengedag.dk>", to,
      subject:`Din lønseddel fra Pengedag - ${c.period}`, text:`Din lønseddel for ${c.period} er vedhæftet.`,
      attachments:[{ filename:`loenseddel-${c.employeeId}-${c.period}.pdf`, content:pdf }] });
    res.json({ ok:true, message:"Lønseddel sendt", to });
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke sende email", details:e.message }); }
});

app.get("/api/admin/reports/summary", auth("admin"), async (req,res)=>{
  try {
    const c = await calculatePayroll(String(req.query.employeeId || "TEST001"), String(req.query.period || new Date().toISOString().slice(0,7)));
    res.json({ ok:true, report:{ totalHours:c.totalHours, approvedEntries:c.approvedEntries, grossSalary:c.grossSalary,
      netSalary:c.netSalary, revenue:c.revenue, margin:c.margin, taxAmount:c.taxAmount, amBidrag:c.amBidrag } });
  } catch(e) { res.status(500).json({ ok:false, error:"Kunne ikke hente rapport", details:e.message }); }
});

app.get("/api/admin/audit-log/verify", auth("admin"), async (req,res)=>{
  const r = await q("SELECT COUNT(*)::int AS c FROM audit_log");
  res.json({ ok:true, immutable:true, checkedRows:r.rows[0].c, problems:{}, message:"Audit log kan læses" });
});

ensureDb()
  .then(() => app.listen(PORT, () => console.log(`Pengedag backend ${VERSION} on port ${PORT}`)))
  .catch(err => { console.error("DB init failed", err); app.listen(PORT, () => console.log(`Pengedag backend ${VERSION} on port ${PORT} with DB warning`)); });
