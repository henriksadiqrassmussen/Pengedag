
import express from "express";
import cors from "cors";
import pkg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import PDFDocument from "pdfkit";
import nodemailer from "nodemailer";

const { Pool } = pkg;
const app = express();
const VERSION = "2.2.6-audit-safe-fix";
console.log("### PENGEDAG SERVER.JS 2.2.6 AUDIT SAFE FIX LOADED ###");

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "pengedag-dev-secret-change-me";
const DATABASE_URL = process.env.DATABASE_URL;

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "2mb" }));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && DATABASE_URL.includes("railway") ? { rejectUnauthorized:false } : undefined
});

const q = (sql, params=[]) => pool.query(sql, params);
const uid = (p="id") => `${p}_${Date.now()}_${Math.random().toString(16).slice(2)}`;
const num = (v, f=0) => Number.isFinite(Number(v)) ? Number(v) : f;

function hoursBetween(start,end,pause=0){
  const [sh,sm]=String(start||"").split(":").map(Number);
  const [eh,em]=String(end||"").split(":").map(Number);
  if(!Number.isFinite(sh)||!Number.isFinite(eh)) return 0;
  let a=sh*60+(sm||0), b=eh*60+(em||0);
  if(b<a) b+=1440;
  return Math.max(0,(b-a-num(pause))/60);
}

async function ensure(){
  await q(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    role TEXT DEFAULT 'employee',
    name TEXT,
    employee_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  for (const sql of [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'employee'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_id TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`
  ]) await q(sql);

  // NY ren tabel til lønprofil. Undgår gammel employee_salary_settings med id-fejl.
  await q(`CREATE TABLE IF NOT EXISTS pd_salary_settings (
    id TEXT PRIMARY KEY,
    employee_id TEXT UNIQUE NOT NULL,
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
  for (const sql of [
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS id TEXT`,
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS employee_id TEXT`,
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS normal_rate NUMERIC DEFAULT 160`,
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS overtime_rate NUMERIC DEFAULT 220`,
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS customer_rate NUMERIC DEFAULT 320`,
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS pension_percent NUMERIC DEFAULT 8`,
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS pension_employer_percent NUMERIC DEFAULT 4`,
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS pension_employee_percent NUMERIC DEFAULT 4`,
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS am_percent NUMERIC DEFAULT 8`,
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS tax_percent NUMERIC DEFAULT 38`,
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS deduction NUMERIC DEFAULT 0`,
    `ALTER TABLE pd_salary_settings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`
  ]) await q(sql);
  await q(`CREATE UNIQUE INDEX IF NOT EXISTS pd_salary_settings_employee_id_uidx ON pd_salary_settings(employee_id)`);

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

async function seedUser(email,password,role,name,employeeId){
  const hash=await bcrypt.hash(password,10);
  const r=await q(`SELECT id FROM users WHERE email=$1`,[email]);
  if(r.rows.length){
    await q(`UPDATE users SET password_hash=$2, role=$3, name=$4, employee_id=$5 WHERE email=$1`,[email,hash,role,name,employeeId]);
  }else{
    await q(`INSERT INTO users (id,email,password_hash,role,name,employee_id) VALUES ($1,$2,$3,$4,$5,$6)`,[uid("user"),email,hash,role,name,employeeId]);
  }
}

async function ensureSalary(employeeId){
  await ensure();
  await q(`INSERT INTO pd_salary_settings
    (id,employee_id,normal_rate,overtime_rate,customer_rate,pension_percent,pension_employer_percent,pension_employee_percent,am_percent,tax_percent,deduction,updated_at)
    VALUES ($1,$2,160,220,320,8,4,4,8,38,0,NOW())
    ON CONFLICT (employee_id) DO NOTHING`,[uid("sal"),employeeId]);
  const r=await q(`SELECT * FROM pd_salary_settings WHERE employee_id=$1`,[employeeId]);
  return r.rows[0]||{};
}

async function seed(){
  await ensure();
  await seedUser("vault1973@gmail.com","PengedagAdmin2026!","admin","Ejer","ADMIN");
  await seedUser("medarbejder@pengedag.dk","MedarbejderTest2026!","employee","Test Medarbejder","TEST001");
  await ensureSalary("TEST001");
}

function sign(u){ return jwt.sign({id:u.id,email:u.email,role:u.role,name:u.name,employeeId:u.employee_id},JWT_SECRET,{expiresIn:"7d"}); }

function auth(role=null){
  return (req,res,next)=>{
    try{
      const h=req.headers.authorization||"";
      const token=h.startsWith("Bearer ")?h.slice(7):"";
      if(!token) return res.status(401).json({ok:false,error:"Mangler login-token"});
      const user=jwt.verify(token,JWT_SECRET);
      if(role && user.role!==role) return res.status(403).json({ok:false,error:"Ingen adgang"});
      req.user=user; next();
    }catch(e){ res.status(401).json({ok:false,error:"Ugyldigt login",details:e.message}); }
  };
}

async function audit(user, action, entityType, entityId, metadata = {}) {
  // Audit må aldrig stoppe løn, PDF eller email.
  // Nogle ældre databaser har audit_log.id som BIGINT, derfor indsætter vi ikke tekst-id i id-kolonnen.
  try {
    const actorId = user?.id || user?.sub || "system";
    const safeEntityId = String(entityId ?? "");
    const safeMetadata = JSON.stringify(metadata ?? {});

    await q(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id BIGSERIAL PRIMARY KEY,
        actor_id TEXT,
        action TEXT,
        entity_type TEXT,
        entity_id TEXT,
        metadata JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    const cols = await q(`
      SELECT column_name, data_type
      FROM information_schema.columns
      WHERE table_name = 'audit_log'
    `);

    const names = new Set(cols.rows.map(r => r.column_name));

    if (names.has("actor_id") && names.has("entity_type") && names.has("entity_id") && names.has("metadata")) {
      await q(
        `INSERT INTO audit_log (actor_id, action, entity_type, entity_id, metadata)
         VALUES ($1,$2,$3,$4,$5::jsonb)`,
        [String(actorId), String(action), String(entityType), safeEntityId, safeMetadata]
      );
      return;
    }

    // Fallback til meget gamle skemaer
    if (names.has("user_id") && names.has("action")) {
      await q(
        `INSERT INTO audit_log (user_id, action, details)
         VALUES ($1,$2,$3)`,
        [String(actorId), String(action), safeMetadata]
      );
      return;
    }
  } catch (e) {
    console.warn("audit ignored", e.message);
  }
}

app.get("/health",async(req,res)=>{
  try{ await ensure(); await q("SELECT 1"); res.json({ok:true,status:"healthy",version:VERSION,marker:"AUDIT_SAFE_FIX_2_2_6",database:"connected",time:new Date().toISOString()}); }
  catch(e){ res.status(500).json({ok:false,status:"unhealthy",version:VERSION,error:e.message}); }
});

app.post("/api/auth/login",async(req,res)=>{
  try{
    await ensure();
    const {email,password}=req.body||{};
    const r=await q(`SELECT * FROM users WHERE email=$1`,[String(email||"").toLowerCase()]);
    if(!r.rows.length) return res.status(401).json({ok:false,error:"Forkert login"});
    const u=r.rows[0];
    if(!await bcrypt.compare(String(password||""),u.password_hash||"")) return res.status(401).json({ok:false,error:"Forkert login"});
    res.json({ok:true,token:sign(u),user:{email:u.email,role:u.role,name:u.name,employeeId:u.employee_id}});
  }catch(e){ res.status(500).json({ok:false,error:"Login-fejl",details:e.message}); }
});

app.post("/api/mobile/time-entry",auth(),async(req,res)=>{
  try{
    await ensure();
    const b=req.body||{};
    const employeeId=String(b.employeeId||req.user.employeeId||"TEST001");
    const employeeName=String(b.employeeName||req.user.name||"Medarbejder");
    const date=String(b.date||new Date().toISOString().slice(0,10)).slice(0,10);
    const start=String(b.start||"08:00").slice(0,5);
    const end=String(b.end||"16:00").slice(0,5);
    const pause=num(b.pauseMinutes??b.pause??0);
    const hours=Number(hoursBetween(start,end,pause).toFixed(2));
    const id=uid("mob");
    await q(`INSERT INTO pd_time_entries (id,employee_id,employee_name,email,work_date,start_time,end_time,pause_minutes,note,status,hours)
      VALUES ($1,$2,$3,$4,$5::date,$6,$7,$8,$9,'Afventer',$10)`,[id,employeeId,employeeName,req.user.email||"",date,start,end,pause,String(b.note||""),hours]);
    await audit(req.user,"CREATE_TIME_ENTRY","pd_time_entry",id,{employeeId,date,start,end,hours});
    res.json({ok:true,message:"Time oprettet",id,hours,status:"Afventer"});
  }catch(e){ res.status(500).json({ok:false,error:"Kunne ikke oprette time",details:e.message,code:e.code||null}); }
});

app.get("/api/mobile/times",auth(),async(req,res)=>{
  try{
    await ensure();
    const r=await q(`SELECT id,employee_id AS "employeeId",employee_name AS "employeeName",email,work_date::text AS date,start_time AS start,end_time AS "end",pause_minutes AS "pauseMinutes",note,status,hours,created_at AS "createdAt",approved_at AS "approvedAt",approved_by AS "approvedBy" FROM pd_time_entries ORDER BY created_at DESC LIMIT 500`);
    res.json({ok:true,count:r.rows.length,entries:r.rows.map(x=>({...x,hours:Number(x.hours||0)}))});
  }catch(e){ res.status(500).json({ok:false,error:"Kunne ikke hente timer",details:e.message,code:e.code||null}); }
});

app.post("/api/mobile/time-entries/:id/approve",auth("admin"),async(req,res)=>{
  try{
    await ensure();
    const r=await q(`UPDATE pd_time_entries SET status='Godkendt',approved_at=NOW(),approved_by=$2 WHERE id=$1 RETURNING *`,[req.params.id,req.user.email]);
    if(!r.rows.length) return res.status(404).json({ok:false,error:"Time ikke fundet"});
    await audit(req.user,"APPROVE_TIME_ENTRY","pd_time_entry",req.params.id,{});
    res.json({ok:true,entry:r.rows[0]});
  }catch(e){ res.status(500).json({ok:false,error:"Kunne ikke godkende time",details:e.message,code:e.code||null}); }
});

app.get("/api/admin/employees/:employeeId/salary-settings",auth("admin"),async(req,res)=>{
  try{
    const employeeId=req.params.employeeId||"TEST001";
    const s=await ensureSalary(employeeId);
    res.json({ok:true,source:"pd_salary_settings",settings:{
      id:s.id,employee_id:employeeId,
      normal_rate:Number(s.normal_rate??160),overtime_rate:Number(s.overtime_rate??220),customer_rate:Number(s.customer_rate??320),
      pension_percent:Number(s.pension_percent??8),pension_employer_percent:Number(s.pension_employer_percent??4),pension_employee_percent:Number(s.pension_employee_percent??4),
      am_percent:Number(s.am_percent??8),tax_percent:Number(s.tax_percent??38),deduction:Number(s.deduction??0),
      normalRate:Number(s.normal_rate??160),overtimeRate:Number(s.overtime_rate??220),customerRate:Number(s.customer_rate??320),
      pensionPercent:Number(s.pension_percent??8),pensionEmployerPercent:Number(s.pension_employer_percent??4),pensionEmployeePercent:Number(s.pension_employee_percent??4),
      amPercent:Number(s.am_percent??8),taxPercent:Number(s.tax_percent??38)
    }});
  }catch(e){ console.error("GET_SALARY_ERROR",e); res.status(500).json({ok:false,error:"Kunne ikke hente lønprofil",details:e.message,code:e.code||null}); }
});

app.put("/api/admin/employees/:employeeId/salary-settings",auth("admin"),async(req,res)=>{
  try{
    await ensure();
    const employeeId=req.params.employeeId||"TEST001", b=req.body||{};
    await q(`INSERT INTO pd_salary_settings
      (id,employee_id,normal_rate,overtime_rate,customer_rate,pension_percent,pension_employer_percent,pension_employee_percent,am_percent,tax_percent,deduction,updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
      ON CONFLICT (employee_id) DO UPDATE SET normal_rate=EXCLUDED.normal_rate,overtime_rate=EXCLUDED.overtime_rate,customer_rate=EXCLUDED.customer_rate,pension_percent=EXCLUDED.pension_percent,pension_employer_percent=EXCLUDED.pension_employer_percent,pension_employee_percent=EXCLUDED.pension_employee_percent,am_percent=EXCLUDED.am_percent,tax_percent=EXCLUDED.tax_percent,deduction=EXCLUDED.deduction,updated_at=NOW()`,
      [uid("sal"),employeeId,num(b.normalRate??b.normal_rate,160),num(b.overtimeRate??b.overtime_rate,220),num(b.customerRate??b.customer_rate,320),num(b.pensionPercent??b.pension_percent,8),num(b.pensionEmployerPercent??b.pension_employer_percent,4),num(b.pensionEmployeePercent??b.pension_employee_percent,4),num(b.amPercent??b.am_percent,8),num(b.taxPercent??b.tax_percent,38),num(b.deduction,0)]);
    const s=await ensureSalary(employeeId);
    await audit(req.user,"SAVE_SALARY_SETTINGS","pd_salary_settings",employeeId,{employeeId});
    res.json({ok:true,message:"Lønprofil gemt",source:"pd_salary_settings",settings:s});
  }catch(e){ console.error("SAVE_SALARY_ERROR",e); res.status(500).json({ok:false,error:"Kunne ikke gemme lønprofil",details:e.message,code:e.code||null}); }
});

app.get("/api/employee/my-salary-settings",auth(),async(req,res)=>{
  try{ const s=await ensureSalary(req.user.employeeId||"TEST001"); res.json({ok:true,source:"pd_salary_settings",settings:s}); }
  catch(e){ res.status(500).json({ok:false,error:"Kunne ikke hente min lønprofil",details:e.message,code:e.code||null}); }
});

async function calculatePayroll(employeeId,period){
  await ensure();
  const start=`${period}-01`;
  const endDate=new Date(Number(period.slice(0,4)),Number(period.slice(5,7)),0).toISOString().slice(0,10);
  const tr=await q(`SELECT * FROM pd_time_entries WHERE employee_id=$1 AND status='Godkendt' AND work_date BETWEEN $2::date AND $3::date ORDER BY created_at DESC`,[employeeId,start,endDate]);
  const totalHours=Number(tr.rows.reduce((s,e)=>s+num(e.hours),0).toFixed(2));
  const normalHours=Math.min(totalHours,160), overtimeHours=Math.max(0,totalHours-160);
  const s=await ensureSalary(employeeId);
  const normalRate=num(s.normal_rate,160), overtimeRate=num(s.overtime_rate,220), customerRate=num(s.customer_rate,320);
  const grossSalary=Number((normalHours*normalRate+overtimeHours*overtimeRate).toFixed(2));
  const pensionEmployee=Number((grossSalary*num(s.pension_employee_percent,4)/100).toFixed(2));
  const pensionEmployer=Number((grossSalary*num(s.pension_employer_percent,4)/100).toFixed(2));
  const amBase=Math.max(0,grossSalary-pensionEmployee);
  const amBidrag=Number((amBase*num(s.am_percent,8)/100).toFixed(2));
  const taxBase=Math.max(0,amBase-amBidrag-num(s.deduction,0));
  const taxAmount=Number((taxBase*num(s.tax_percent,38)/100).toFixed(2));
  const netSalary=Number((grossSalary-pensionEmployee-amBidrag-taxAmount).toFixed(2));
  const revenue=Number((totalHours*customerRate).toFixed(2));
  const margin=Number((revenue-grossSalary-pensionEmployer).toFixed(2));
  return {employeeId,employeeName:tr.rows[0]?.employee_name||employeeId,period,periodStart:start,periodEnd:endDate,approvedEntries:tr.rows.length,totalHours,normalHours,overtimeHours,normalRate,overtimeRate,customerRate,grossSalary,pensionEmployee,pensionEmployer,amBidrag,taxAmount,netSalary,revenue,margin,entries:tr.rows};
}

app.post("/api/admin/payroll/calculate",auth("admin"),async(req,res)=>{
  try{
    const c=await calculatePayroll(String(req.body.employeeId||"TEST001"),String(req.body.period||new Date().toISOString().slice(0,7)));
    const id=uid("paycalc");
    try{ await q(`INSERT INTO pd_payroll_calculations (id,employee_id,employee_name,period,total_hours,gross_salary,pension_employee,pension_employer,am_bidrag,tax_amount,net_salary,revenue,margin,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,[id,c.employeeId,c.employeeName,c.period,c.totalHours,c.grossSalary,c.pensionEmployee,c.pensionEmployer,c.amBidrag,c.taxAmount,c.netSalary,c.revenue,c.margin,c]); }catch(e){ console.error("payroll log ignored",e.message); }
    res.json({ok:true,id,calculation:c});
  }catch(e){ res.status(500).json({ok:false,error:"Kunne ikke beregne løn",details:e.message,code:e.code||null}); }
});


function drawBox(doc, x, y, w, h, title, value, color="#111827"){
  doc.roundedRect(x,y,w,h,12).fillAndStroke("#F8FAFC","#E5E7EB");
  doc.fillColor("#6B7280").fontSize(8).text(title,x+12,y+10,{width:w-24});
  doc.fillColor(color).fontSize(13).font("Helvetica-Bold").text(String(value),x+12,y+27,{width:w-24});
  doc.font("Helvetica");
}

function drawRow(doc, label, value, x, y, w){
  doc.fillColor("#6B7280").fontSize(9).text(label,x,y,{width:w/2});
  doc.fillColor("#111827").fontSize(9).font("Helvetica-Bold").text(String(value),x+w/2,y,{width:w/2,align:"right"});
  doc.font("Helvetica");
  doc.moveTo(x,y+15).lineTo(x+w,y+15).strokeColor("#E5E7EB").lineWidth(0.6).stroke();
}

function createPdf(p){
  return new Promise((resolve,reject)=>{
    const doc=new PDFDocument({margin:0,size:"A4"});
    const chunks=[];
    doc.on("data",d=>chunks.push(d));
    doc.on("end",()=>resolve(Buffer.concat(chunks)));
    doc.on("error",reject);

    const pageW=595.28;
    const pageH=841.89;
    const margin=42;

    // Background
    doc.rect(0,0,pageW,pageH).fill("#F5F7FB");

    // Header card
    doc.roundedRect(margin,32,pageW-margin*2,112,22).fillAndStroke("#FFFFFF","#E5E7EB");

    // Logo mark
    doc.roundedRect(margin+22,54,58,58,16).fill("#2563EB");
    doc.fillColor("#FFFFFF").fontSize(34).font("Helvetica-Bold").text("P",margin+39,66);
    doc.font("Helvetica");

    doc.fillColor("#111827").fontSize(24).font("Helvetica-Bold").text("Pengedag",margin+96,58);
    doc.fillColor("#6B7280").fontSize(10).font("Helvetica").text("Lønseddel og lønoverblik",margin+98,88);
    doc.fillColor("#2563EB").fontSize(9).text("Digital hjælper til timer, løn og rapporter",margin+98,106);

    doc.fillColor("#111827").fontSize(18).font("Helvetica-Bold").text("LØNSEDDEL",pageW-margin-170,59,{width:150,align:"right"});
    doc.fillColor("#6B7280").fontSize(9).font("Helvetica").text(`Periode: ${p.periodStart} - ${p.periodEnd}`,pageW-margin-220,86,{width:200,align:"right"});
    doc.text(`Oprettet: ${new Date().toISOString().slice(0,10)}`,pageW-margin-220,103,{width:200,align:"right"});

    // Employee info
    doc.roundedRect(margin,164,pageW-margin*2,70,18).fillAndStroke("#FFFFFF","#E5E7EB");
    doc.fillColor("#6B7280").fontSize(9).text("Medarbejder",margin+20,182);
    doc.fillColor("#111827").fontSize(14).font("Helvetica-Bold").text(p.employeeName||p.employeeId,margin+20,199);
    doc.font("Helvetica").fillColor("#6B7280").fontSize(9).text(`Medarbejder-ID: ${p.employeeId}`,margin+20,216);
    doc.fillColor("#16A34A").fontSize(10).font("Helvetica-Bold").text("Godkendt løngrundlag",pageW-margin-190,190,{width:170,align:"right"});
    doc.font("Helvetica").fillColor("#6B7280").fontSize(9).text(`${p.approvedEntries||0} godkendte poster`,pageW-margin-190,209,{width:170,align:"right"});

    // KPI boxes
    const boxY=254, boxW=(pageW-margin*2-24)/3;
    drawBox(doc,margin,boxY,boxW,62,"Timer i alt",Number(p.totalHours||0).toFixed(2),"#2563EB");
    drawBox(doc,margin+boxW+12,boxY,boxW,62,"Bruttoløn",`${Number(p.grossSalary||0).toFixed(2)} kr.`,"#111827");
    drawBox(doc,margin+(boxW+12)*2,boxY,boxW,62,"Netto udbetaling",`${Number(p.netSalary||0).toFixed(2)} kr.`,"#16A34A");

    // Salary details
    const leftX=margin, rightX=pageW/2+10, cardY=342;
    doc.roundedRect(leftX,cardY,245,230,18).fillAndStroke("#FFFFFF","#E5E7EB");
    doc.roundedRect(rightX,cardY,245,230,18).fillAndStroke("#FFFFFF","#E5E7EB");

    doc.fillColor("#111827").fontSize(14).font("Helvetica-Bold").text("Lønberegning",leftX+18,cardY+18);
    doc.font("Helvetica");
    let y=cardY+48;
    [
      ["Normal timer", Number(p.normalHours||0).toFixed(2)],
      ["Overtid timer", Number(p.overtimeHours||0).toFixed(2)],
      ["Normal sats", `${Number(p.normalRate||0).toFixed(2)} kr.`],
      ["Overtidssats", `${Number(p.overtimeRate||0).toFixed(2)} kr.`],
      ["Bruttoløn", `${Number(p.grossSalary||0).toFixed(2)} kr.`]
    ].forEach(([a,b])=>{ drawRow(doc,a,b,leftX+18,y,209); y+=28; });

    doc.fillColor("#111827").fontSize(14).font("Helvetica-Bold").text("Fradrag og pension",rightX+18,cardY+18);
    doc.font("Helvetica");
    y=cardY+48;
    [
      ["Pension medarbejder", `${Number(p.pensionEmployee||0).toFixed(2)} kr.`],
      ["Pension arbejdsgiver", `${Number(p.pensionEmployer||0).toFixed(2)} kr.`],
      ["AM-bidrag", `${Number(p.amBidrag||0).toFixed(2)} kr.`],
      ["Skat", `${Number(p.taxAmount||0).toFixed(2)} kr.`],
      ["Netto", `${Number(p.netSalary||0).toFixed(2)} kr.`]
    ].forEach(([a,b],i)=>{ drawRow(doc,a,b,rightX+18,y,209); y+=28; });

    // Business summary
    doc.roundedRect(margin,594,pageW-margin*2,86,18).fillAndStroke("#FFFFFF","#E5E7EB");
    doc.fillColor("#111827").fontSize(14).font("Helvetica-Bold").text("Virksomhedsoverblik",margin+18,613);
    doc.font("Helvetica");
    drawRow(doc,"Kundeomsætning",`${Number(p.revenue||0).toFixed(2)} kr.`,margin+18,642,220);
    drawRow(doc,"Margin",`${Number(p.margin||0).toFixed(2)} kr.`,pageW-margin-238,642,220);

    // Footer / disclaimer
    doc.fillColor("#6B7280").fontSize(8).text(
      "Pengedag er en digital hjælper til timer, godkendelse, lønsedler og regnskabsforberedelse. Lokal regnskabshjælper – ikke godkendt bogføringssystem.",
      margin, pageH-78, {width:pageW-margin*2,align:"center"}
    );
    doc.fillColor("#9CA3AF").fontSize(8).text("pengedag.dk",margin,pageH-50,{width:pageW-margin*2,align:"center"});

    doc.end();
  });
}

app.post("/api/admin/payslip/pdf",auth("admin"),async(req,res)=>{
  try{
    const c=req.body.calculation||await calculatePayroll(String(req.body.employeeId||"TEST001"),String(req.body.period||new Date().toISOString().slice(0,7)));
    const pdf=await createPdf(c);
    res.setHeader("Content-Type","application/pdf");
    res.setHeader("Content-Disposition",`attachment; filename="loenseddel-${c.employeeId}-${c.period}.pdf"`);
    res.send(pdf);
  }catch(e){ res.status(500).json({ok:false,error:"Kunne ikke lave PDF",details:e.message}); }
});



function resendReady(){
  return !!process.env.RESEND_API_KEY;
}

function smtpReady(){
  return !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

function emailMode(){
  if (resendReady()) return "resend";
  if (smtpReady()) return "smtp";
  return "simulated";
}

function smtpConfigPublic(){
  return {
    smtpHostSet: !!process.env.SMTP_HOST,
    smtpPort: Number(process.env.SMTP_PORT || 587),
    smtpUserSet: !!process.env.SMTP_USER,
    smtpPassSet: !!process.env.SMTP_PASS,
    smtpFrom: process.env.SMTP_FROM || process.env.SMTP_USER || "",
    smtpSecure: String(process.env.SMTP_SECURE || "false") === "true"
  };
}

function createTransporter(){
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || "false") === "true",
    connectionTimeout: Number(process.env.SMTP_CONNECTION_TIMEOUT || 12000),
    greetingTimeout: Number(process.env.SMTP_GREETING_TIMEOUT || 12000),
    socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT || 20000),
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    tls: { rejectUnauthorized: String(process.env.SMTP_REJECT_UNAUTHORIZED || "true") !== "false" }
  });
}

async function sendWithResend({ to, subject, html, text, filename, pdfBuffer, from }) {
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: from || process.env.RESEND_FROM || "Pengedag <onboarding@resend.dev>",
      to: [to],
      subject,
      html,
      text,
      attachments: [{ filename, content: pdfBuffer.toString("base64") }]
    })
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || data.error || `Resend fejl ${response.status}`);
  return data;
}

function emailText(calculation) {
  return `Hej ${calculation.employeeName || ""}

Din lønseddel for perioden ${calculation.periodStart} - ${calculation.periodEnd} er vedhæftet som PDF.

Venlig hilsen
Pengedag`;
}

function emailHtml(calculation) {
  return `
    <div style="font-family:Segoe UI,Arial,sans-serif;color:#111827;line-height:1.5">
      <h2 style="color:#2563EB;margin-bottom:8px">Pengedag</h2>
      <p>Hej ${calculation.employeeName || ""}</p>
      <p>Din lønseddel for perioden <strong>${calculation.periodStart} - ${calculation.periodEnd}</strong> er vedhæftet som PDF.</p>
      <div style="background:#F5F7FB;border:1px solid #E5E7EB;border-radius:14px;padding:14px;margin:14px 0">
        <p><strong>Timer:</strong> ${Number(calculation.totalHours || 0).toFixed(2)}</p>
        <p><strong>Bruttoløn:</strong> ${Number(calculation.grossSalary || 0).toFixed(2)} kr.</p>
        <p><strong>Netto:</strong> ${Number(calculation.netSalary || 0).toFixed(2)} kr.</p>
      </div>
      <p>Venlig hilsen<br><strong>Pengedag</strong></p>
    </div>
  `;
}

app.post("/api/admin/payslip/email", auth("admin"), async (req,res) => {
  try {
    const employeeId = String(req.body.employeeId || req.body.calculation?.employeeId || "TEST001");
    const period = String(req.body.period || req.body.calculation?.period || new Date().toISOString().slice(0,7));
    const to = String(req.body.to || req.body.email || "medarbejder@pengedag.dk").trim();

    if (!to || !to.includes("@")) {
      return res.status(400).json({ ok:false, error:"Mangler gyldig email-modtager" });
    }

    const calculation = req.body.calculation || await calculatePayroll(employeeId, period);
    const pdfBuffer = await createPdf(calculation);
    const filename = `loenseddel-${calculation.employeeId}-${calculation.period}.pdf`;
    const subject = req.body.subject || `Din lønseddel fra Pengedag - ${calculation.period}`;
    const text = req.body.text || emailText(calculation);
    const html = req.body.html || emailHtml(calculation);
    const from = process.env.RESEND_FROM || process.env.SMTP_FROM || process.env.SMTP_USER || "Pengedag <onboarding@resend.dev>";

    if (resendReady()) {
      const info = await sendWithResend({ to, subject, html, text, filename, pdfBuffer, from });
      await audit(req.user, "SEND_PAYSLIP_EMAIL_RESEND", "payslip", `${employeeId}-${period}`, {
        to, employeeId, period, filename, resendId: info.id || ""
      });
      return res.json({
        ok:true,
        provider:"resend",
        simulated:false,
        message:"Email sendt med Resend og lønseddel som PDF",
        to,
        attachment:{ filename, bytes:pdfBuffer.length },
        resendId: info.id || null
      });
    }

    if (smtpReady()) {
      const transporter = createTransporter();
      await transporter.verify();
      const info = await transporter.sendMail({
        from, to, subject, text, html,
        attachments: [{ filename, content: pdfBuffer, contentType: "application/pdf" }]
      });
      await audit(req.user, "SEND_PAYSLIP_EMAIL_SMTP", "payslip", `${employeeId}-${period}`, {
        to, employeeId, period, filename, messageId: info.messageId || "", accepted: info.accepted || [], rejected: info.rejected || []
      });
      return res.json({
        ok:true,
        provider:"smtp",
        simulated:false,
        message:"Email sendt med SMTP og lønseddel som PDF",
        to,
        attachment:{ filename, bytes:pdfBuffer.length },
        messageId: info.messageId || null,
        accepted: info.accepted || [],
        rejected: info.rejected || []
      });
    }

    await audit(req.user, "SIMULATE_PAYSLIP_EMAIL", "payslip", `${employeeId}-${period}`, {
      to, employeeId, period, filename, mode:emailMode(), smtp:smtpConfigPublic(), resendReady:resendReady()
    });
    return res.json({
      ok:true,
      provider:"simulated",
      simulated:true,
      message:"Email simuleret. RESEND_API_KEY eller SMTP mangler.",
      attachment:{ filename, bytes:pdfBuffer.length },
      mode:emailMode(),
      smtp:smtpConfigPublic(),
      resendReady:resendReady()
    });
  } catch(e) {
    console.error("PAYSLIP_EMAIL_ERROR", e);
    res.status(500).json({
      ok:false,
      error:"Kunne ikke sende email",
      details:e.message,
      mode:emailMode(),
      smtp:smtpConfigPublic(),
      resendReady:resendReady()
    });
  }
});

app.get("/api/admin/email/status", auth("admin"), async (req,res) => {
  try {
    res.json({
      ok:true,
      ready:resendReady() || smtpReady(),
      mode:emailMode(),
      version:VERSION,
      marker:"AUDIT_SAFE_FIX_2_2_6",
      resendReady:resendReady(),
      smtp:smtpConfigPublic()
    });
  } catch(e) {
    res.status(500).json({ ok:false, error:"Kunne ikke hente email-status", details:e.message });
  }
});

app.post("/api/admin/email/test", auth("admin"), async (req,res) => {
  try {
    const to = String(req.body.to || process.env.SMTP_TEST_TO || "medarbejder@pengedag.dk").trim();
    const subject = "Pengedag email-test";
    const text = "Dette er en test fra Pengedag backend.";

    if (resendReady()) {
      const info = await sendWithResend({
        to,
        subject,
        text,
        html:`<p>${text}</p>`,
        filename:"pengedag-test.txt",
        pdfBuffer:Buffer.from("Pengedag test"),
        from:process.env.RESEND_FROM || "Pengedag <onboarding@resend.dev>"
      });
      await audit(req.user, "SEND_TEST_EMAIL_RESEND", "email", to, { resendId:info.id || "" });
      return res.json({ ok:true, provider:"resend", simulated:false, message:"Test-email sendt med Resend", resendId:info.id || null });
    }

    if (!smtpReady()) {
      return res.json({ ok:true, provider:"simulated", simulated:true, message:"Email test simuleret. RESEND_API_KEY eller SMTP mangler.", mode:emailMode() });
    }

    const transporter = createTransporter();
    await transporter.verify();
    const info = await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to, subject, text
    });
    await audit(req.user, "SEND_TEST_EMAIL_SMTP", "email", to, { messageId:info.messageId || "" });
    res.json({ ok:true, provider:"smtp", simulated:false, message:"Test-email sendt med SMTP", messageId:info.messageId || null });
  } catch(e) {
    console.error("TEST_EMAIL_ERROR", e);
    res.status(500).json({ ok:false, error:"Kunne ikke sende test-email", details:e.message, mode:emailMode(), smtp:smtpConfigPublic(), resendReady:resendReady() });
  }
});

app.get("/api/debug/email-status", auth("admin"), async (req,res) => {
  res.json({
    ok:true,
    version:VERSION,
    marker:"AUDIT_SAFE_FIX_2_2_6",
    ready:resendReady() || smtpReady(),
    mode:emailMode(),
    resendReady:resendReady(),
    smtp:smtpConfigPublic()
  });
});


app.get("/api/admin/reports/summary",auth("admin"),async(req,res)=>{
  try{
    const c=await calculatePayroll(String(req.query.employeeId||"TEST001"),String(req.query.period||new Date().toISOString().slice(0,7)));
    res.json({ok:true,report:{totalHours:c.totalHours,approvedEntries:c.approvedEntries,grossSalary:c.grossSalary,netSalary:c.netSalary,revenue:c.revenue,margin:c.margin}});
  }catch(e){ res.status(500).json({ok:false,error:"Kunne ikke hente rapport",details:e.message}); }
});

app.get("/api/debug/salary-settings",auth("admin"),async(req,res)=>{
  try{ await ensure(); const r=await q(`SELECT * FROM pd_salary_settings ORDER BY updated_at DESC LIMIT 50`); res.json({ok:true,version:VERSION,marker:"AUDIT_SAFE_FIX_2_2_6",source:"pd_salary_settings",count:r.rows.length,rows:r.rows}); }
  catch(e){ res.status(500).json({ok:false,error:e.message,code:e.code||null}); }
});

seed().then(()=>app.listen(PORT,()=>console.log(`Pengedag backend ${VERSION} on port ${PORT}`))).catch(err=>{
  console.error("Startup error",err);
  app.listen(PORT,()=>console.log(`Pengedag backend ${VERSION} on port ${PORT} - started with warning`));
});
