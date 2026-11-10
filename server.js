'use strict';

// Same-origin local application server. Health payloads and uploaded files are
// AES-256-GCM encrypted before they reach SQLite. Set CLINIC_DATA_KEY to a
// protected secret-store value before starting; never commit it or store real
// patient data in an unreviewed deployment.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const ROOT = __dirname;
const MAX_BODY = 16 * 1024 * 1024;
const KEY_TEXT = process.env.CLINIC_DATA_KEY || '';
if (!/^[A-Za-z0-9+/]{43}=$/.test(KEY_TEXT) || Buffer.from(KEY_TEXT, 'base64').length !== 32) {
  console.error('CLINIC_DATA_KEY must be a base64-encoded 32-byte secret. Generate one with: node -e "console.log(require(\'node:crypto\').randomBytes(32).toString(\'base64\'))"');
  process.exit(1);
}
const DATA_KEY = Buffer.from(KEY_TEXT, 'base64');
const defaultDataDir = process.env.CLINIC_DATA_DIR || path.join(process.env.LOCALAPPDATA || ROOT, 'TabbyClinicData');
const dbPath = process.env.CLINIC_DB_PATH || path.join(defaultDataDir, 'clinic.sqlite');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new DatabaseSync(dbPath);
const loginFailures = new Map();
db.exec(`PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, email_lookup TEXT NOT NULL UNIQUE, email_cipher BLOB NOT NULL, phone_cipher BLOB NOT NULL,
 password_salt BLOB NOT NULL, password_hash BLOB NOT NULL, password_change_required INTEGER NOT NULL DEFAULT 0, role TEXT NOT NULL DEFAULT 'patient', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS patient_profiles (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
 profile_cipher BLOB NOT NULL, consent_at TEXT NOT NULL, consent_version TEXT NOT NULL,
 medical_record_number TEXT UNIQUE,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS medical_records (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 record_cipher BLOB NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,
 event_type TEXT NOT NULL, record_id TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS branches (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, area TEXT NOT NULL, address TEXT NOT NULL,
 phone TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 0, verification_reference TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS doctors (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, specialty TEXT NOT NULL, credentials TEXT NOT NULL,
 years_experience INTEGER NOT NULL CHECK(years_experience >= 11), license_cipher BLOB NOT NULL,
 branch_id TEXT NOT NULL REFERENCES branches(id), consultation_fee INTEGER NOT NULL CHECK(consultation_fee >= 0),
 account_user_id TEXT REFERENCES users(id), license_verified INTEGER NOT NULL DEFAULT 0, verification_reference TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', bio TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, verified_at TEXT, verified_by TEXT REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS branch_staff (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
 branch_id TEXT NOT NULL REFERENCES branches(id), department TEXT NOT NULL,
 name_cipher BLOB, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS doctor_hours (
 id TEXT PRIMARY KEY, doctor_id TEXT NOT NULL REFERENCES doctors(id) ON DELETE CASCADE,
 weekday INTEGER NOT NULL CHECK(weekday BETWEEN 0 AND 6), start_time TEXT NOT NULL, end_time TEXT NOT NULL,
 slot_minutes INTEGER NOT NULL CHECK(slot_minutes BETWEEN 10 AND 120), active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS appointments (
 id TEXT PRIMARY KEY, patient_user_id TEXT NOT NULL REFERENCES users(id), doctor_id TEXT NOT NULL REFERENCES doctors(id),
 branch_id TEXT NOT NULL REFERENCES branches(id), starts_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'booked',
 created_at TEXT NOT NULL, cancelled_at TEXT, is_follow_up INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS service_requests (
 id TEXT PRIMARY KEY, patient_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 branch_id TEXT REFERENCES branches(id), service_type TEXT NOT NULL, details_cipher BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'pending_provider_confirmation',
 admin_note_cipher BLOB, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS patient_branch_access (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 branch_id TEXT NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
 created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
 PRIMARY KEY(user_id,branch_id)
);
CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS medical_records_user_created ON medical_records(user_id, created_at);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS doctors_directory ON doctors(branch_id,specialty,status,license_verified);
CREATE INDEX IF NOT EXISTS appointments_patient ON appointments(patient_user_id,starts_at);
CREATE INDEX IF NOT EXISTS appointments_doctor ON appointments(doctor_id,starts_at);
CREATE INDEX IF NOT EXISTS service_requests_patient ON service_requests(patient_user_id,created_at);
CREATE INDEX IF NOT EXISTS service_requests_status ON service_requests(status,created_at);
CREATE INDEX IF NOT EXISTS branch_staff_lookup ON branch_staff(branch_id,department,active);
CREATE UNIQUE INDEX IF NOT EXISTS branch_one_manager ON branch_staff(branch_id) WHERE department='manager' AND active=1;
CREATE UNIQUE INDEX IF NOT EXISTS branch_staff_department ON branch_staff(branch_id,department) WHERE department<>'manager' AND active=1;
CREATE UNIQUE INDEX IF NOT EXISTS appointments_one_booked_slot ON appointments(doctor_id,starts_at) WHERE status='booked';`);
const userColumns = db.prepare('PRAGMA table_info(users)').all().map(column => column.name);
if (!userColumns.includes('role')) db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'patient'");
if (!userColumns.includes('password_change_required')) db.exec('ALTER TABLE users ADD COLUMN password_change_required INTEGER NOT NULL DEFAULT 0');
const branchColumns=db.prepare('PRAGMA table_info(branches)').all().map(column=>column.name);
if(!branchColumns.includes('verification_reference'))db.exec("ALTER TABLE branches ADD COLUMN verification_reference TEXT NOT NULL DEFAULT ''");
const doctorColumns=db.prepare('PRAGMA table_info(doctors)').all().map(column=>column.name);
const patientProfileColumns=db.prepare('PRAGMA table_info(patient_profiles)').all().map(column=>column.name);
if(!patientProfileColumns.includes('medical_record_number'))db.exec('ALTER TABLE patient_profiles ADD COLUMN medical_record_number TEXT');
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS patient_medical_record_number ON patient_profiles(medical_record_number) WHERE medical_record_number IS NOT NULL');
let nextPatientNumber=db.prepare("SELECT COALESCE(MAX(CAST(substr(medical_record_number,5) AS INTEGER)),0)+1 AS n FROM patient_profiles WHERE medical_record_number LIKE 'TBY-%'").get().n;
for(const existing of db.prepare('SELECT id FROM patient_profiles WHERE medical_record_number IS NULL ORDER BY created_at,id').all())db.prepare('UPDATE patient_profiles SET medical_record_number=? WHERE id=?').run(`TBY-${String(nextPatientNumber++).padStart(8,'0')}`,existing.id);
const appointmentColumns=db.prepare('PRAGMA table_info(appointments)').all().map(column=>column.name);
if(!appointmentColumns.includes('is_follow_up'))db.exec('ALTER TABLE appointments ADD COLUMN is_follow_up INTEGER NOT NULL DEFAULT 0');
if(!doctorColumns.includes('verification_reference'))db.exec("ALTER TABLE doctors ADD COLUMN verification_reference TEXT NOT NULL DEFAULT ''");
if(!doctorColumns.includes('account_user_id'))db.exec('ALTER TABLE doctors ADD COLUMN account_user_id TEXT REFERENCES users(id)');
const branchStaffColumns=db.prepare('PRAGMA table_info(branch_staff)').all().map(column=>column.name);
if(!branchStaffColumns.includes('name_cipher'))db.exec('ALTER TABLE branch_staff ADD COLUMN name_cipher BLOB');
const serviceRequestColumns=db.prepare('PRAGMA table_info(service_requests)').all().map(column=>column.name);
if(!serviceRequestColumns.includes('branch_id'))db.exec('ALTER TABLE service_requests ADD COLUMN branch_id TEXT REFERENCES branches(id)');
const plannedBranches=[
  ['00000000-0000-4000-8000-000000000001','المعادي','المعادي'],
  ['00000000-0000-4000-8000-000000000002','التجمع الخامس','التجمع الخامس'],
  ['00000000-0000-4000-8000-000000000003','مدينة نصر','مدينة نصر'],
  ['00000000-0000-4000-8000-000000000004','مصر الجديدة','مصر الجديدة'],
  ['00000000-0000-4000-8000-000000000005','الجيزة','الجيزة']
];
const seedBranch=db.prepare("INSERT OR IGNORE INTO branches(id,name,area,address,phone,active,created_at) VALUES(?,?,?,'عنوان الفرع الفعلي مطلوب قبل التفعيل','',0,?)");
for(const [id,name,area] of plannedBranches)seedBranch.run(id,name,area,new Date().toISOString());
db.prepare('INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,?)').run(new Date().toISOString());

const pbkdf2 = promisify(crypto.pbkdf2);
const dummyPasswordSalt=crypto.randomBytes(16),dummyPasswordHash=crypto.randomBytes(32);
const STAFF_DEPARTMENTS=['reception','appointments','follow_up','laboratory','radiology','pharmacy','billing','medical_records','operations'];
const nowIso = () => new Date().toISOString();
const uuid = () => crypto.randomUUID();
function newMedicalRecordNumber(){let next=db.prepare("SELECT COALESCE(MAX(CAST(substr(medical_record_number,5) AS INTEGER)),0)+1 AS n FROM patient_profiles WHERE medical_record_number LIKE 'TBY-%'").get().n;while(db.prepare('SELECT 1 FROM patient_profiles WHERE medical_record_number=?').get(`TBY-${String(next).padStart(8,'0')}`))next++;return `TBY-${String(next).padStart(8,'0')}`;}
function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', DATA_KEY, iv);
  const body = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(value))), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}
function decrypt(value) {
  const input = Buffer.from(value);
  const decipher = crypto.createDecipheriv('aes-256-gcm', DATA_KEY, input.subarray(0, 12));
  decipher.setAuthTag(input.subarray(12, 28));
  return JSON.parse(Buffer.concat([decipher.update(input.subarray(28)), decipher.final()]).toString('utf8'));
}
function json(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}
function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
}
function readBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', chunk => { size += chunk.length; if (size > limit) { reject(Object.assign(new Error('حجم الطلب أكبر من الحد المسموح'), { status: 413 })); req.destroy(); } else chunks.push(chunk); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req) {
  const body = await readBody(req);
  try { return JSON.parse(body.toString('utf8')); } catch { throw Object.assign(new Error('بيانات الطلب غير صالحة'), { status: 400 }); }
}
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  const expectedProtocol = req.socket.encrypted || process.env.TRUST_HTTPS_PROXY === '1' ? 'https:' : 'http:';
  try { const parsed = new URL(origin); return parsed.host === req.headers.host && parsed.protocol === expectedProtocol; } catch { return false; }
}
function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(v => v.trim()).filter(Boolean).map(v => { const at = v.indexOf('='); return [v.slice(0, at), decodeURIComponent(v.slice(at + 1))]; }));
}
function currentUser(req) {
  const token = parseCookies(req).clinic_session;
  if (!token) return null;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const row = db.prepare('SELECT users.id,users.role,users.password_change_required AS mustChangePassword FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires_at>?').get(tokenHash, Date.now());
  return row || null;
}
function setSession(res, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expires = Date.now() + 12 * 60 * 60 * 1000;
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').run(crypto.createHash('sha256').update(token).digest('hex'), userId, expires, nowIso());
  const secure = process.env.COOKIE_SECURE === '1' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `clinic_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200${secure}`);
}
function clearSession(req, res) {
  const token = parseCookies(req).clinic_session;
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(crypto.createHash('sha256').update(token).digest('hex'));
  const secure = process.env.COOKIE_SECURE === '1' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `clinic_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
}
function audit(userId, type, recordId = null) {
  db.prepare('INSERT INTO audit_events(user_id,event_type,record_id,created_at) VALUES(?,?,?,?)').run(userId, type, recordId, nowIso());
}
function emailLookup(email) { return crypto.createHmac('sha256', DATA_KEY).update(email).digest('hex'); }
function authLocked(key) { const entry=loginFailures.get(key); if(!entry)return false; if(entry.until<Date.now()){loginFailures.delete(key);return false;} return entry.count>=5; }
function authFailed(key) {
  const now=Date.now();
  if(loginFailures.size>=10000){for(const [candidate,state] of loginFailures)if(state.until<now)loginFailures.delete(candidate);if(loginFailures.size>=10000)loginFailures.delete(loginFailures.keys().next().value);}
  const entry=loginFailures.get(key);if(!entry||entry.until<now)loginFailures.set(key,{count:1,until:now+10*60*1000});else entry.count++;
}
function authSucceeded(key) { loginFailures.delete(key); }
function parseMultipart(buffer, boundary) {
  const delimiter = Buffer.from(`--${boundary}`); const items = []; let pos = buffer.indexOf(delimiter);
  while (pos >= 0) {
    pos += delimiter.length;
    if (buffer.subarray(pos, pos + 2).toString() === '--') break;
    if (buffer.subarray(pos, pos + 2).toString() === '\r\n') pos += 2;
    const headEnd = buffer.indexOf(Buffer.from('\r\n\r\n'), pos); if (headEnd < 0) break;
    const headers = buffer.subarray(pos, headEnd).toString('latin1');
    const next = buffer.indexOf(delimiter, headEnd + 4); if (next < 0) break;
    let dataEnd = next; if (buffer.subarray(dataEnd - 2, dataEnd).toString() === '\r\n') dataEnd -= 2;
    const disposition = headers.match(/content-disposition:\s*form-data;([^\r\n]+)/i)?.[1] || '';
    const name = disposition.match(/name="([^"]*)"/i)?.[1];
    const filename = disposition.match(/filename="([^"]*)"/i)?.[1];
    const contentType = headers.match(/content-type:\s*([^\r\n]+)/i)?.[1]?.trim().toLowerCase() || 'application/octet-stream';
    if (name) items.push({ name, filename, contentType, data: buffer.subarray(headEnd + 4, dataEnd) });
    pos = next;
  }
  return items;
}
function textPart(parts, name) { return parts.find(p => p.name === name && !p.filename)?.data.toString('utf8').trim() || ''; }
function boundedFields(source,limits){const fields={};for(const [key,max] of Object.entries(limits)){const value=String(source[key]||'').trim();if(value.length>max)return {error:true,key};if(value)fields[key]=value;}return {fields};}
const CLINICAL_FIELD_LIMITS={symptoms:2000,historyReviewed:1500,vitals:1000,assessment:2000,differential:1500,plan:2000,instructions:1500,warnings:1000,referral:1000,followUp:500,icdCode:50};
const REPORT_FIELD_LIMITS={result:2000,units:80,referenceRange:120,resultStatus:40,providerName:160,collectionDate:30,modality:60,bodyRegion:120,findings:2500,impression:1500,studyId:120,contrast:120,critical:20,notifiedTo:160,notifiedAt:30};
function verifyFile(file) {
  const b = file.data;
  if (file.contentType === 'application/pdf' && b.subarray(0, 5).toString() === '%PDF-') return true;
  if (file.contentType === 'image/jpeg' && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return true;
  if (file.contentType === 'image/png' && b.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return true;
  if ((file.contentType === 'application/dicom' || file.filename?.toLowerCase().endsWith('.dcm')) && b.length >= 132 && b.subarray(128, 132).toString() === 'DICM') return true;
  return false;
}
function requireAdmin(req, res) {
  const user=currentUser(req);
  if (!user) { json(res,401,{error:'سجّل الدخول بحساب الإدارة.'}); return null; }
  if (user.role!=='admin') { json(res,403,{error:'هذا الإجراء متاح لإدارة المركز فقط.'}); return null; }
  return user;
}
function requireBranchMember(req,res,departments=[]){
  const user=currentUser(req);if(!user){json(res,401,{error:'سجّل الدخول أولًا.'});return null;}
  if(user.role==='admin')return {...user,branchId:'*',department:'owner'};
  const membership=db.prepare('SELECT branch_id AS branchId,department FROM branch_staff WHERE user_id=? AND active=1').get(user.id);
  if(!membership){json(res,403,{error:'هذا المسار لموظفي الفروع فقط.'});return null;}
  if(departments.length&&!departments.includes(membership.department)){json(res,403,{error:'صلاحية هذا الدور لا تسمح بالإجراء.'});return null;}
  return {...user,...membership};
}
function requireMedicalAdmin(req,res){
  const user=currentUser(req);if(!user){json(res,401,{error:'سجّل الدخول أولًا.'});return null;}
  if(user.role==='admin')return {user,branchId:null,allPatients:true};
  if(user.role==='doctor')return {user,branchId:null,doctor:true,allPatients:false};
  const membership=db.prepare('SELECT branch_id AS branchId,department FROM branch_staff WHERE user_id=? AND active=1').get(user.id);
  if(!membership){json(res,403,{error:'إدارة ملفات المرضى متاحة للطبيب وموظفي الفروع والإدارة فقط.'});return null;}
  return {user,...membership,allPatients:false};
}
function patientInMedicalScope(userId,scope){
  if(scope.allPatients)return Boolean(db.prepare("SELECT 1 FROM users u JOIN patient_profiles p ON p.user_id=u.id WHERE u.id=? AND u.role='patient'").get(userId));
  if(scope.doctor)return Boolean(db.prepare("SELECT 1 FROM appointments a JOIN doctors d ON d.id=a.doctor_id JOIN users u ON u.id=a.patient_user_id JOIN patient_profiles p ON p.user_id=u.id WHERE u.id=? AND u.role='patient' AND d.account_user_id=? AND a.status IN ('booked','confirmed','in_progress','completed')").get(userId,scope.user.id));
  return Boolean(db.prepare("SELECT 1 FROM users u JOIN patient_profiles p ON p.user_id=u.id WHERE u.id=? AND u.role='patient' AND (EXISTS(SELECT 1 FROM patient_branch_access x WHERE x.user_id=u.id AND x.branch_id=?) OR EXISTS(SELECT 1 FROM appointments a WHERE a.patient_user_id=u.id AND a.branch_id=?) OR EXISTS(SELECT 1 FROM service_requests r WHERE r.patient_user_id=u.id AND r.branch_id=?))").get(userId,scope.branchId,scope.branchId,scope.branchId));
}
async function createBranchAccount({branchId,department,name,email,phone=''}){
  name=String(name||'').trim();email=String(email||'').trim().toLowerCase();phone=String(phone||'').replace(/\s/g,'');
  if(name.length<3||name.length>120||email.length>254||!/^\S+@\S+\.\S+$/.test(email)||phone&&!/^01[0-2,5][0-9]{8}$/.test(phone))throw Object.assign(new Error('أدخل اسمًا وبريدًا صحيحًا ورقم هاتف مصريًا صالحًا.'),{status:400});
  if(!db.prepare('SELECT 1 FROM branches WHERE id=?').get(branchId))throw Object.assign(new Error('الفرع غير موجود.'),{status:404});
  if(!['manager',...STAFF_DEPARTMENTS].includes(department))throw Object.assign(new Error('الدور الوظيفي غير صالح.'),{status:400});
  if(db.prepare('SELECT 1 FROM users WHERE email_lookup=?').get(emailLookup(email)))throw Object.assign(new Error('البريد مسجل بالفعل.'),{status:409});
  if(department!=='manager'&&db.prepare('SELECT 1 FROM branch_staff WHERE branch_id=? AND department=? AND active=1').get(branchId,department))throw Object.assign(new Error('يوجد مستخدم نشط لهذا الدور في الفرع بالفعل.'),{status:409});
  if(department==='manager'&&db.prepare("SELECT 1 FROM branch_staff WHERE branch_id=? AND department='manager' AND active=1").get(branchId))throw Object.assign(new Error('يوجد مدير نشط لهذا الفرع بالفعل.'),{status:409});
  const userId=uuid(),membershipId=uuid(),password=crypto.randomBytes(24).toString('base64url'),salt=crypto.randomBytes(16),hash=await pbkdf2(password,salt,310000,32,'sha256'),role=department==='manager'?'branch_manager':'branch_staff';
  db.exec('BEGIN IMMEDIATE');try{db.prepare('INSERT INTO users(id,email_lookup,email_cipher,phone_cipher,password_salt,password_hash,password_change_required,role,created_at) VALUES(?,?,?,?,?,?,1,?,?)').run(userId,emailLookup(email),encrypt({email}),encrypt({phone}),salt,hash,role,nowIso());db.prepare('INSERT INTO branch_staff(id,user_id,branch_id,department,name_cipher,created_at) VALUES(?,?,?,?,?,?)').run(membershipId,userId,branchId,department,encrypt({name}),nowIso());db.exec('COMMIT');}catch(error){db.exec('ROLLBACK');if(String(error.message).includes('UNIQUE'))throw Object.assign(new Error('الحساب أو الدور موجود بالفعل.'),{status:409});throw error;}
  return {userId,membershipId,name,email,phone,department,role,temporaryPassword:password};
}
function validDate(date) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return false;
  const parsed=new Date(`${date}T12:00:00Z`);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString().slice(0,10)===date;
}
function cairoNow() {
  const parts=new Intl.DateTimeFormat('en-CA',{timeZone:'Africa/Cairo',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(new Date());
  const v=Object.fromEntries(parts.map(p=>[p.type,p.value])); return `${v.year}-${v.month}-${v.day}T${v.hour}:${v.minute}`;
}
function availableSlots(doctorId,date) {
  if (!validDate(date)) return [];
  const dateMs=Date.parse(`${date}T12:00:00Z`), today=Date.parse(`${cairoNow().slice(0,10)}T12:00:00Z`);
  if (dateMs<today || dateMs>today+180*86400000) return [];
  const weekday=new Date(dateMs).getUTCDay();
  const doctor=db.prepare("SELECT id FROM doctors WHERE id=? AND status='active' AND license_verified=1").get(doctorId);
  if (!doctor) return [];
  const hours=db.prepare('SELECT start_time,end_time,slot_minutes FROM doctor_hours WHERE doctor_id=? AND weekday=? AND active=1').all(doctorId,weekday);
  const occupied=new Set(db.prepare("SELECT substr(starts_at,12,5) AS t FROM appointments WHERE doctor_id=? AND substr(starts_at,1,10)=? AND status='booked'").all(doctorId,date).map(x=>x.t));
  const now=cairoNow(); const result=[];
  for (const h of hours) {
    const [sh,sm]=h.start_time.split(':').map(Number),[eh,em]=h.end_time.split(':').map(Number);
    for (let minute=sh*60+sm; minute+h.slot_minutes<=eh*60+em; minute+=h.slot_minutes) {
      const time=`${String(Math.floor(minute/60)).padStart(2,'0')}:${String(minute%60).padStart(2,'0')}`;
      if ((date+'T'+time)>now && !occupied.has(time)) result.push(time);
    }
  }
  return [...new Set(result)].sort();
}

const server = http.createServer(async (req, res) => {
  securityHeaders(res);
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { ok: true });
    if (url.pathname.startsWith('/api/') && req.method !== 'GET' && !sameOrigin(req)) return json(res, 403, { error: 'مصدر الطلب غير مسموح' });
     const passwordChangeAllowed=['/api/login','/api/me','/api/password/change','/api/logout'];if(url.pathname.startsWith('/api/')&&!url.pathname.startsWith('/api/public/')&&!passwordChangeAllowed.includes(url.pathname)){const signedIn=currentUser(req);if(signedIn?.mustChangePassword)return json(res,428,{error:'يجب تغيير كلمة المرور المؤقتة قبل استخدام الحساب.',mustChangePassword:true});}

    if (req.method==='GET' && url.pathname==='/api/public/branches') return json(res,200,{branches:db.prepare('SELECT id,name,area,address,phone FROM branches WHERE active=1 ORDER BY name').all()});
    if (req.method==='GET' && url.pathname==='/api/public/doctors') {
      const q=url.searchParams.get('q')||'', branchId=url.searchParams.get('branchId')||'',pattern=`%${q.slice(0,100)}%`;
      const doctors=db.prepare("SELECT d.id,d.name,d.specialty,d.credentials,d.years_experience AS yearsExperience,d.consultation_fee AS consultationFee,d.bio,b.id AS branchId,b.name AS branch,b.area,b.address FROM doctors d JOIN branches b ON b.id=d.branch_id WHERE d.status='active' AND d.license_verified=1 AND b.active=1 AND (?='' OR d.specialty LIKE ? OR d.name LIKE ?) AND (?='' OR b.id=?) ORDER BY d.years_experience DESC,d.name").all(q,pattern,pattern,branchId,branchId);
      return json(res,200,{doctors});
    }
    if (req.method==='GET' && url.pathname==='/api/public/slots') {
      const doctorId=url.searchParams.get('doctorId')||'',date=url.searchParams.get('date')||'';
      return json(res,200,{date,slots:availableSlots(doctorId,date)});
    }
    if (req.method==='POST' && url.pathname==='/api/appointments') {
      const user=currentUser(req);if(!user)return json(res,401,{error:'سجّل الدخول لحجز الموعد.'});
      if(user.role!=='patient')return json(res,403,{error:'الحجز متاح لحساب المريض.'});
      const body=await readJson(req),doctorId=String(body.doctorId||''),startsAt=String(body.startsAt||'');
      if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(startsAt)||!validDate(startsAt.slice(0,10))||!availableSlots(doctorId,startsAt.slice(0,10)).includes(startsAt.slice(11)))return json(res,409,{error:'الموعد غير متاح. حدّث المواعيد واختر موعدًا آخر.'});
      const doctor=db.prepare("SELECT d.id,d.branch_id FROM doctors d JOIN branches b ON b.id=d.branch_id WHERE d.id=? AND d.status='active' AND d.license_verified=1 AND b.active=1").get(doctorId);
      const id=uuid();
      try{db.prepare("INSERT INTO appointments(id,patient_user_id,doctor_id,branch_id,starts_at,status,created_at) VALUES(?,?,?,?,?,'booked',?)").run(id,user.id,doctor.id,doctor.branch_id,startsAt,nowIso());}
      catch(e){if(String(e.message).includes('UNIQUE'))return json(res,409,{error:'حجز شخص آخر هذا الموعد للتو. اختر وقتًا آخر.'});throw e;}
      audit(user.id,'appointment_booked',id);return json(res,201,{ok:true,appointment:{id,doctorId:doctor.id,branchId:doctor.branch_id,startsAt,status:'booked'}});
    }
    if(req.method==='GET'&&url.pathname==='/api/appointments'){
      const user=currentUser(req);if(!user)return json(res,401,{error:'سجّل الدخول أولًا.'});
      if(user.role!=='patient')return json(res,403,{error:'هذه الخدمة لحساب المريض.'});
      const appointments=db.prepare('SELECT a.id,a.starts_at AS startsAt,a.status,a.created_at AS createdAt,d.name AS doctor,d.specialty,b.name AS branch,b.address FROM appointments a JOIN doctors d ON d.id=a.doctor_id JOIN branches b ON b.id=a.branch_id WHERE a.patient_user_id=? ORDER BY a.starts_at DESC').all(user.id);
      return json(res,200,{appointments});
    }
    const cancelAppointment=url.pathname.match(/^\/api\/appointments\/([0-9a-f-]+)\/cancel$/i);
    if(req.method==='POST'&&cancelAppointment){
      const user=currentUser(req);if(!user)return json(res,401,{error:'سجّل الدخول أولًا.'});
      if(user.role!=='patient')return json(res,403,{error:'هذه الخدمة لحساب المريض.'});
      const result=db.prepare("UPDATE appointments SET status='cancelled',cancelled_at=? WHERE id=? AND patient_user_id=? AND status='booked'").run(nowIso(),cancelAppointment[1],user.id);
      if(!result.changes)return json(res,404,{error:'الحجز غير موجود أو تم إلغاؤه بالفعل.'});audit(user.id,'appointment_cancelled',cancelAppointment[1]);return json(res,200,{ok:true});
    }
    if(req.method==='POST'&&url.pathname==='/api/service-requests'){
      const user=currentUser(req);if(!user)return json(res,401,{error:'سجّل الدخول لإرسال الطلب.'});if(user.role!=='patient')return json(res,403,{error:'هذه الخدمة لحساب المريض.'});
      const recent=db.prepare("SELECT COUNT(*) AS count FROM service_requests WHERE patient_user_id=? AND created_at>=?").get(user.id,new Date(Date.now()-24*60*60*1000).toISOString());if(recent.count>=25)return json(res,429,{error:'وصلت للحد اليومي للطلبات. حاول مرة أخرى غدًا.'});
      const body=await readJson(req),type=String(body.serviceType||''),allowed=['hospital','home_visit','phone_consult','video_consult','medicine_delivery','lab_booking','imaging_booking'];
      const details={specialty:String(body.specialty||'').trim().slice(0,100),serviceName:String(body.serviceName||'').trim().slice(0,180),area:String(body.area||'').trim().slice(0,100),address:String(body.address||'').trim().slice(0,300),phone:String(body.phone||'').trim().slice(0,30),preferredDate:String(body.preferredDate||'').trim(),preferredTime:String(body.preferredTime||'').trim(),notes:String(body.notes||'').trim().slice(0,1200),medicines:String(body.medicines||'').trim().slice(0,3000)};
      if(!allowed.includes(type))return json(res,400,{error:'نوع الخدمة غير معروف.'});
      if(type==='medicine_delivery'){
        if(details.medicines.length<2||details.area.length<2||details.address.length<8||!/^01[0-2,5][0-9]{8}$/.test(details.phone))return json(res,400,{error:'أدخل أسماء الأدوية والمنطقة والعنوان ورقم هاتف مصري صالح.'});
      }else if(['lab_booking','imaging_booking'].includes(type)){
        if(details.serviceName.length<2||details.area.length<2)return json(res,400,{error:'أدخل اسم التحليل أو الأشعة والمنطقة المطلوبة.'});
      }else{
        if(details.specialty.length<2||details.area.length<2)return json(res,400,{error:'اختر التخصص والمنطقة المطلوبة.'});
        if(type==='home_visit'&&details.address.length<8)return json(res,400,{error:'أدخل عنوان الزيارة المنزلية بالتفصيل.'});
        if(['phone_consult','video_consult'].includes(type)&&!/^01[0-2,5][0-9]{8}$/.test(details.phone))return json(res,400,{error:'أدخل رقم هاتف مصري صالحًا للتواصل.'});
      }
      if(details.preferredDate&&(!validDate(details.preferredDate)||details.preferredDate<cairoNow().slice(0,10)))return json(res,400,{error:'اختر تاريخًا صحيحًا اليوم أو بعده.'});
      if(details.preferredTime&&!/^([01]\d|2[0-3]):[0-5]\d$/.test(details.preferredTime))return json(res,400,{error:'صيغة الوقت غير صحيحة.'});
      const requestedBranch=String(body.branchId||'');let branchId=requestedBranch&&db.prepare('SELECT id FROM branches WHERE id=?').get(requestedBranch)?.id||null;if(!branchId&&details.area)branchId=db.prepare('SELECT id FROM branches WHERE lower(area)=lower(?) OR lower(name)=lower(?) LIMIT 1').get(details.area,details.area)?.id||null;
      const id=uuid(),created=nowIso();db.prepare('INSERT INTO service_requests(id,patient_user_id,branch_id,service_type,details_cipher,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(id,user.id,branchId,type,encrypt(details),'pending_provider_confirmation',created,created);audit(user.id,'service_request_created',id);return json(res,201,{ok:true,request:{id,serviceType:type,status:'pending_provider_confirmation',createdAt:created}});
    }
    if(req.method==='GET'&&url.pathname==='/api/service-requests'){
      const user=currentUser(req);if(!user)return json(res,401,{error:'سجّل الدخول أولًا.'});if(user.role!=='patient')return json(res,403,{error:'هذه الخدمة لحساب المريض.'});
      const requests=db.prepare('SELECT id,service_type AS serviceType,details_cipher,status,admin_note_cipher AS adminNoteCipher,created_at AS createdAt,updated_at AS updatedAt FROM service_requests WHERE patient_user_id=? ORDER BY created_at DESC').all(user.id).map(r=>({id:r.id,serviceType:r.serviceType,details:decrypt(r.details_cipher),status:r.status,adminNote:r.adminNoteCipher?decrypt(r.adminNoteCipher).note:'',createdAt:r.createdAt,updatedAt:r.updatedAt}));return json(res,200,{requests});
    }
    const cancelRequest=url.pathname.match(/^\/api\/service-requests\/([0-9a-f-]+)\/cancel$/i);
    if(req.method==='POST'&&cancelRequest){const user=currentUser(req);if(!user)return json(res,401,{error:'سجّل الدخول أولًا.'});if(user.role!=='patient')return json(res,403,{error:'هذه الخدمة لحساب المريض.'});const result=db.prepare("UPDATE service_requests SET status='cancelled',updated_at=? WHERE id=? AND patient_user_id=? AND status='pending_provider_confirmation'").run(nowIso(),cancelRequest[1],user.id);if(!result.changes)return json(res,404,{error:'الطلب غير موجود أو بدأ مقدم الخدمة مراجعته.'});audit(user.id,'service_request_cancelled',cancelRequest[1]);return json(res,200,{ok:true});}
    if(url.pathname.startsWith('/api/doctor/')){
      const doctorUser=currentUser(req);if(!doctorUser)return json(res,401,{error:'سجّل دخول الطبيب.'});if(doctorUser.role!=='doctor')return json(res,403,{error:'هذه المسارات لحساب الطبيب.'});
      if(req.method==='GET'&&url.pathname==='/api/doctor/me')return json(res,200,{doctors:db.prepare('SELECT d.id,d.name,d.specialty,d.credentials,d.years_experience AS yearsExperience,d.status,b.id AS branchId,b.name AS branch FROM doctors d JOIN branches b ON b.id=d.branch_id WHERE d.account_user_id=? ORDER BY b.name').all(doctorUser.id)});
      if(req.method==='GET'&&url.pathname==='/api/doctor/appointments'){
        const appointments=db.prepare('SELECT a.id,a.starts_at AS startsAt,a.status,a.branch_id AS branchId,d.name AS doctor,d.id AS doctorId,d.specialty,b.name AS branch,p.id AS patientId,p.profile_cipher,u.email_cipher,u.phone_cipher FROM appointments a JOIN doctors d ON d.id=a.doctor_id JOIN branches b ON b.id=a.branch_id JOIN patient_profiles p ON p.user_id=a.patient_user_id JOIN users u ON u.id=a.patient_user_id WHERE d.account_user_id=? AND a.status<>\'cancelled\' ORDER BY a.starts_at').all(doctorUser.id).map(a=>({id:a.id,startsAt:a.startsAt,status:a.status,doctor:a.doctor,doctorId:a.doctorId,specialty:a.specialty,branch:a.branch,branchId:a.branchId,patientId:a.patientId,patientName:decrypt(a.profile_cipher).name,patientEmail:decrypt(a.email_cipher).email,patientPhone:decrypt(a.phone_cipher).phone}));return json(res,200,{appointments});
      }
      const doctorFollowUp=url.pathname.match(/^\/api\/doctor\/appointments\/([0-9a-f-]+)\/follow-up$/i);
      if(req.method==='POST'&&doctorFollowUp){const body=await readJson(req),startsAt=String(body.startsAt||''),original=db.prepare("SELECT a.patient_user_id AS patientUserId,a.doctor_id AS doctorId,a.branch_id AS branchId,a.status FROM appointments a JOIN doctors d ON d.id=a.doctor_id WHERE a.id=? AND d.account_user_id=?").get(doctorFollowUp[1],doctorUser.id);if(!original||!['in_progress','completed'].includes(original.status))return json(res,409,{error:'يمكن تحديد موعد الإعادة بعد بدء الكشف أو إكماله.'});if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(startsAt)||!validDate(startsAt.slice(0,10))||!availableSlots(original.doctorId,startsAt.slice(0,10)).includes(startsAt.slice(11)))return json(res,409,{error:'موعد الإعادة غير متاح. اختر وقتًا متاحًا للطبيب.'});const id=uuid(),created=nowIso();try{db.prepare("INSERT INTO appointments(id,patient_user_id,doctor_id,branch_id,starts_at,status,created_at,is_follow_up) VALUES(?,?,?,?,?,'booked',?,1)").run(id,original.patientUserId,original.doctorId,original.branchId,startsAt,created);}catch(error){if(String(error.message).includes('UNIQUE'))return json(res,409,{error:'حُجز هذا الموعد للتو. اختر وقتًا آخر.'});throw error;}audit(doctorUser.id,'doctor_follow_up_scheduled',id);audit(original.patientUserId,'follow_up_added_to_medical_record',id);return json(res,201,{ok:true,appointment:{id,startsAt,status:'booked',isFollowUp:true}});}
      const doctorAppointmentRecords=url.pathname.match(/^\/api\/doctor\/appointments\/([0-9a-f-]+)\/records$/i);
      if(req.method==='GET'&&doctorAppointmentRecords){const appt=db.prepare("SELECT a.patient_user_id AS patientUserId,p.id AS patientId,p.medical_record_number AS medicalRecordNumber,p.profile_cipher,p.consent_at AS consentAt,p.consent_version AS consentVersion,u.email_cipher,u.phone_cipher FROM appointments a JOIN doctors d ON d.id=a.doctor_id JOIN patient_profiles p ON p.user_id=a.patient_user_id JOIN users u ON u.id=a.patient_user_id WHERE a.id=? AND d.account_user_id=? AND a.status IN ('booked','confirmed','in_progress','completed')").get(doctorAppointmentRecords[1],doctorUser.id);if(!appt)return json(res,404,{error:'الموعد غير موجود أو غير مرتبط بحساب الطبيب.'});const recordList=db.prepare('SELECT id,record_cipher,created_at AS createdAt FROM medical_records WHERE user_id=? ORDER BY created_at DESC').all(appt.patientUserId).map(r=>{const record=decrypt(r.record_cipher);const hasFile=Boolean(record.fileData);delete record.fileData;return {id:r.id,createdAt:r.createdAt,hasFile,...record};}),appointments=db.prepare('SELECT a.id,a.starts_at AS startsAt,a.created_at AS createdAt,a.status,a.is_follow_up AS isFollowUp,d.name AS doctor,d.specialty,b.name AS branch FROM appointments a JOIN doctors d ON d.id=a.doctor_id JOIN branches b ON b.id=a.branch_id WHERE a.patient_user_id=? ORDER BY a.starts_at DESC').all(appt.patientUserId).map(a=>({id:a.id,category:a.isFollowUp?'follow_up':'appointment',title:a.isFollowUp?'موعد إعادة':'حجز كشف',detail:`${a.doctor} • ${a.specialty} • ${a.branch} • ${a.status}`,serviceDate:a.startsAt,startsAt:a.startsAt,status:a.status,createdAt:a.createdAt,appointmentId:a.id})),records=[...appointments,...recordList].sort((a,b)=>String(b.createdAt||b.startsAt).localeCompare(String(a.createdAt||a.startsAt))),auditEvents=db.prepare("SELECT event_type AS eventType,record_id AS recordId,created_at AS createdAt FROM audit_events WHERE user_id=? OR record_id IN (SELECT id FROM medical_records WHERE user_id=?) OR record_id IN (SELECT id FROM appointments WHERE patient_user_id=?) ORDER BY created_at DESC LIMIT 100").all(appt.patientUserId,appt.patientUserId,appt.patientUserId);audit(doctorUser.id,'doctor_patient_record_viewed',doctorAppointmentRecords[1]);return json(res,200,{patientId:appt.patientId,medicalRecordNumber:appt.medicalRecordNumber,patientUserId:appt.patientUserId,profile:decrypt(appt.profile_cipher),email:decrypt(appt.email_cipher).email,phone:decrypt(appt.phone_cipher).phone,consentAt:appt.consentAt,consentVersion:appt.consentVersion,auditEvents,records});}
      const doctorFile=url.pathname.match(/^\/api\/doctor\/appointments\/([0-9a-f-]+)\/records\/([0-9a-f-]+)\/file$/i);
      if(req.method==='GET'&&doctorFile){const row=db.prepare("SELECT r.record_cipher FROM appointments a JOIN doctors d ON d.id=a.doctor_id JOIN medical_records r ON r.user_id=a.patient_user_id WHERE a.id=? AND d.account_user_id=? AND r.id=? AND a.status IN ('booked','confirmed','in_progress','completed')").get(doctorFile[1],doctorUser.id,doctorFile[2]);if(!row)return json(res,404,{error:'التقرير غير موجود أو خارج نطاق الموعد.'});const record=decrypt(row.record_cipher);if(!record.fileData)return json(res,404,{error:'لا يوجد ملف مرفق.'});const file=Buffer.from(record.fileData,'base64');audit(doctorUser.id,'doctor_record_file_downloaded',doctorFile[2]);res.writeHead(200,{'Content-Type':record.mimeType,'Content-Length':file.length,'Content-Disposition':`attachment; filename="medical-result-${doctorFile[2]}"`,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});return res.end(file);}
      const doctorAppointmentStatus=url.pathname.match(/^\/api\/doctor\/appointments\/([0-9a-f-]+)\/status$/i);
      if(req.method==='POST'&&doctorAppointmentStatus){const body=await readJson(req),status=String(body.status||'');if(!['in_progress','completed'].includes(status))return json(res,400,{error:'حالة الموعد غير صالحة.'});const appt=db.prepare('SELECT a.starts_at AS startsAt,a.status FROM appointments a JOIN doctors d ON d.id=a.doctor_id WHERE a.id=? AND d.account_user_id=?').get(doctorAppointmentStatus[1],doctorUser.id);if(!appt||appt.status==='cancelled')return json(res,404,{error:'الموعد غير موجود.'});if(status==='in_progress'&&appt.startsAt>cairoNow())return json(res,409,{error:'لا يمكن بدء الكشف قبل موعده.'});const result=db.prepare('UPDATE appointments SET status=? WHERE id=?').run(status,doctorAppointmentStatus[1]);audit(doctorUser.id,`doctor_appointment_${status}`,doctorAppointmentStatus[1]);return json(res,200,{ok:true});}
      const doctorClinicalRecord=url.pathname.match(/^\/api\/doctor\/appointments\/([0-9a-f-]+)\/clinical-record$/i);
      if(req.method==='POST'&&doctorClinicalRecord){const appt=db.prepare("SELECT a.patient_user_id AS patientUserId,d.id AS doctorId,d.name AS doctorName,a.status FROM appointments a JOIN doctors d ON d.id=a.doctor_id WHERE a.id=? AND d.account_user_id=?").get(doctorClinicalRecord[1],doctorUser.id);if(!appt||!['in_progress','completed'].includes(appt.status))return json(res,409,{error:'ابدأ الكشف المرتبط بحسابك قبل إضافة السجل السريري.'});const body=await readJson(req),category=String(body.category||''),title=String(body.title||'').trim(),detail=String(body.detail||'').trim(),clinical=boundedFields(body,CLINICAL_FIELD_LIMITS),allowed=['visit','diagnosis','treatment','medication','surgery','allergy'];if(clinical.error||!allowed.includes(category)||title.length<2||title.length>160||detail.length<2||detail.length>5000)return json(res,400,{error:clinical.error?'بعض تفاصيل الزيارة أطول من المسموح.':'أدخل نوع السجل وعنوانه وتفاصيله بشكل صحيح.'});const id=uuid(),created=nowIso(),record={category,title,detail,clinical:clinical.fields,serviceDate:String(body.serviceDate||'').slice(0,10),submittedBy:'doctor',status:'clinician_verified',doctorId:appt.doctorId,doctorName:appt.doctorName,appointmentId:doctorClinicalRecord[1]};db.prepare('INSERT INTO medical_records(id,user_id,record_cipher,created_at) VALUES(?,?,?,?)').run(id,appt.patientUserId,encrypt(record),created);audit(doctorUser.id,'clinician_record_created',id);audit(appt.patientUserId,'clinician_record_received',id);return json(res,201,{ok:true,record:{id,...record,createdAt:created}});}
      return json(res,404,{error:'مسار الطبيب غير موجود.'});
    }
    if(url.pathname.startsWith('/api/medical-admin/')){
      const scope=requireMedicalAdmin(req,res);if(!scope)return;
      if(req.method==='GET'&&url.pathname==='/api/medical-admin/patients'){
        const query=String(url.searchParams.get('q')||'').trim().toLocaleLowerCase('ar-EG').slice(0,100),rows=scope.allPatients?db.prepare("SELECT u.id,u.email_cipher,u.phone_cipher,p.profile_cipher,p.id AS patient_id,p.medical_record_number FROM users u JOIN patient_profiles p ON p.user_id=u.id WHERE u.role='patient' ORDER BY u.created_at DESC LIMIT 500").all():scope.doctor?db.prepare("SELECT DISTINCT u.id,u.email_cipher,u.phone_cipher,p.profile_cipher,p.id AS patient_id,p.medical_record_number FROM users u JOIN patient_profiles p ON p.user_id=u.id JOIN appointments a ON a.patient_user_id=u.id JOIN doctors d ON d.id=a.doctor_id WHERE u.role='patient' AND d.account_user_id=? AND a.status IN ('booked','confirmed','in_progress','completed') ORDER BY u.created_at DESC LIMIT 500").all(scope.user.id):db.prepare("SELECT DISTINCT u.id,u.email_cipher,u.phone_cipher,p.profile_cipher,p.id AS patient_id,p.medical_record_number FROM users u JOIN patient_profiles p ON p.user_id=u.id LEFT JOIN patient_branch_access x ON x.user_id=u.id AND x.branch_id=? LEFT JOIN appointments a ON a.patient_user_id=u.id AND a.branch_id=? LEFT JOIN service_requests r ON r.patient_user_id=u.id AND r.branch_id=? WHERE u.role='patient' AND (x.user_id IS NOT NULL OR a.id IS NOT NULL OR r.id IS NOT NULL) ORDER BY u.created_at DESC LIMIT 500").all(scope.branchId,scope.branchId,scope.branchId);
        const patients=rows.map(r=>({userId:r.id,patientId:r.patient_id,medicalRecordNumber:r.medical_record_number,profile:decrypt(r.profile_cipher),email:decrypt(r.email_cipher).email,phone:decrypt(r.phone_cipher).phone})).filter(p=>!query||`${p.profile.name} ${p.email} ${p.phone} ${p.patientId} ${p.medicalRecordNumber}`.toLocaleLowerCase('ar-EG').includes(query));
        audit(scope.user.id,'patient_directory_viewed',scope.branchId||'all');return json(res,200,{patients:patients.slice(0,100)});
      }
      if(req.method==='POST'&&url.pathname==='/api/medical-admin/patients'){
        if(scope.doctor)return json(res,403,{error:'إنشاء حساب المريض متاح للإدارة وموظفي الفرع.'});
        const b=await readJson(req),name=String(b.name||'').trim(),email=String(b.email||'').trim().toLowerCase(),phone=String(b.phone||'').replace(/\s/g,''),birthDate=String(b.birthDate||'').slice(0,10),branchId=scope.branchId||String(b.branchId||'');
        if(name.length<3||name.length>120||email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!/^01[0-2,5][0-9]{8}$/.test(phone)||!b.healthConsent||birthDate&&!validDate(birthDate))return json(res,400,{error:'أدخل بيانات المريض الصحيحة، وأكد موافقته الصريحة على إنشاء الملف الطبي.'});
        if(scope.branchId===null&&branchId&&!db.prepare('SELECT 1 FROM branches WHERE id=?').get(branchId))return json(res,400,{error:'الفرع غير موجود.'});
        if(db.prepare('SELECT 1 FROM users WHERE email_lookup=?').get(emailLookup(email)))return json(res,409,{error:'البريد مسجل بالفعل.'});
        const userId=uuid(),patientId=uuid(),password=crypto.randomBytes(24).toString('base64url'),salt=crypto.randomBytes(16),hash=await pbkdf2(password,salt,310000,32,'sha256'),created=nowIso();
        const medicalRecordNumber=newMedicalRecordNumber();db.exec('BEGIN IMMEDIATE');try{db.prepare("INSERT INTO users(id,email_lookup,email_cipher,phone_cipher,password_salt,password_hash,password_change_required,role,created_at) VALUES(?,?,?,?,?,?,1,'patient',?)").run(userId,emailLookup(email),encrypt({email}),encrypt({phone}),salt,hash,created);db.prepare('INSERT INTO patient_profiles(id,user_id,profile_cipher,consent_at,consent_version,medical_record_number,created_at) VALUES(?,?,?,?,?,?,?)').run(patientId,userId,encrypt({name,birthDate,bloodType:'',allergies:[],conditions:[],emergencyContact:''}),created,'staff-confirmed-health-consent-v1',medicalRecordNumber,created);if(branchId)db.prepare('INSERT INTO patient_branch_access(user_id,branch_id,created_by,created_at) VALUES(?,?,?,?)').run(userId,branchId,scope.user.id,created);db.exec('COMMIT');}catch(error){db.exec('ROLLBACK');if(String(error.message).includes('UNIQUE'))return json(res,409,{error:'البريد مسجل بالفعل.'});throw error;}
        audit(scope.user.id,'patient_created_by_staff',userId);audit(userId,'account_created_by_staff',patientId);return json(res,201,{ok:true,patientId,medicalRecordNumber,userId,account:{email,name,temporaryPassword:password}});
      }
      const patientFile=url.pathname.match(/^\/api\/medical-admin\/patients\/([^/]+)\/records\/([^/]+)\/file$/);
      if(req.method==='GET'&&patientFile){const userId=decodeURIComponent(patientFile[1]),recordId=decodeURIComponent(patientFile[2]);if(!patientInMedicalScope(userId,scope))return json(res,404,{error:'ملف المريض غير متاح لهذا الحساب أو الفرع.'});const row=db.prepare('SELECT record_cipher FROM medical_records WHERE user_id=? AND id=?').get(userId,recordId);if(!row)return json(res,404,{error:'التقرير غير موجود.'});const record=decrypt(row.record_cipher);if(!record.fileData)return json(res,404,{error:'لا يوجد مرفق لهذا السجل.'});const file=Buffer.from(record.fileData,'base64');audit(scope.user.id,'staff_patient_file_downloaded',recordId);res.writeHead(200,{'Content-Type':record.mimeType,'Content-Length':file.length,'Content-Disposition':`attachment; filename="medical-result-${recordId}"`,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});return res.end(file);}
      const patientProfile=url.pathname.match(/^\/api\/medical-admin\/patients\/([^/]+)\/profile$/);
      if(req.method==='PATCH'&&patientProfile){const userId=decodeURIComponent(patientProfile[1]);if(!patientInMedicalScope(userId,scope))return json(res,404,{error:'ملف المريض غير متاح لهذا الحساب أو الفرع.'});const body=await readJson(req),row=db.prepare('SELECT profile_cipher FROM patient_profiles WHERE user_id=?').get(userId),profile=decrypt(row.profile_cipher);if(body.name!==undefined){const name=String(body.name).trim();if(name.length<3||name.length>120)return json(res,400,{error:'اسم المريض غير صالح.'});profile.name=name;}if(body.birthDate!==undefined){const date=String(body.birthDate).slice(0,10);if(date&&!validDate(date))return json(res,400,{error:'تاريخ الميلاد غير صالح.'});profile.birthDate=date;}if(body.bloodType!==undefined)profile.bloodType=String(body.bloodType).slice(0,12);if(body.emergencyContact!==undefined)profile.emergencyContact=String(body.emergencyContact).slice(0,300);for(const key of ['allergies','conditions'])if(body[key]!==undefined){if(!Array.isArray(body[key])||body[key].length>100||body[key].some(v=>typeof v!=='string'||v.length>300))return json(res,400,{error:'تحقق من قائمة الحساسية والحالات الصحية.'});profile[key]=body[key];}const optionalFields={nationalId:40,sex:30,maritalStatus:50,language:60,accessibilityNeeds:300,alternatePhone:30,preferredContact:30,address:500,emergencyContactName:120,emergencyContactRelation:60,emergencyContactPhone:30,guardianName:120,guardianRelation:60,guardianPhone:30,insuranceProvider:120,insuranceNumber:100,familyHistory:2000,pastHistory:2000,hospitalizations:2000,vaccinations:2000,smokingStatus:100,pregnancyStatus:100,medicalDevices:1000};for(const [key,max] of Object.entries(optionalFields))if(body[key]!==undefined){const value=String(body[key]||'').trim();if(value.length>max)return json(res,400,{error:`القيمة المدخلة في ${key} أطول من المسموح.`});profile[key]=value;}if(body.nationalId!==undefined&&profile.nationalId&&!/^\d{14}$/.test(profile.nationalId))return json(res,400,{error:'الرقم القومي المصري يجب أن يتكون من ١٤ رقمًا، ويظل اختياريًا.'});let nextEmail,nextPhone;const currentAccount=db.prepare('SELECT email_lookup FROM users WHERE id=?').get(userId);if(body.email!==undefined){nextEmail=String(body.email).trim().toLowerCase();if(nextEmail.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(nextEmail))return json(res,400,{error:'البريد الإلكتروني غير صالح.'});if(emailLookup(nextEmail)!==currentAccount.email_lookup&&db.prepare('SELECT 1 FROM users WHERE email_lookup=?').get(emailLookup(nextEmail)))return json(res,409,{error:'البريد مستخدم في حساب آخر.'});}if(body.phone!==undefined){nextPhone=String(body.phone).replace(/\s/g,'');if(!/^01[0-2,5][0-9]{8}$/.test(nextPhone))return json(res,400,{error:'رقم الهاتف المصري غير صالح.'});}db.exec('BEGIN IMMEDIATE');try{db.prepare('UPDATE patient_profiles SET profile_cipher=? WHERE user_id=?').run(encrypt(profile),userId);if(nextEmail!==undefined)db.prepare('UPDATE users SET email_lookup=?,email_cipher=? WHERE id=?').run(emailLookup(nextEmail),encrypt({email:nextEmail}),userId);if(nextPhone!==undefined)db.prepare('UPDATE users SET phone_cipher=? WHERE id=?').run(encrypt({phone:nextPhone}),userId);db.exec('COMMIT');}catch(error){db.exec('ROLLBACK');throw error;}audit(scope.user.id,scope.doctor?'doctor_patient_profile_updated':'patient_profile_updated_by_staff',userId);return json(res,200,{ok:true,profile});}
      const patientRecords=url.pathname.match(/^\/api\/medical-admin\/patients\/([^/]+)\/records$/);
      if(req.method==='POST'&&patientRecords){const userId=decodeURIComponent(patientRecords[1]);if(!patientInMedicalScope(userId,scope))return json(res,404,{error:'ملف المريض غير متاح لهذا الحساب أو الفرع.'});const body=await readJson(req),category=String(body.category||''),title=String(body.title||'').trim(),detail=String(body.detail||'').trim(),clinical=boundedFields(body,CLINICAL_FIELD_LIMITS),allowed=['visit','diagnosis','treatment','medication','surgery','allergy','lab','imaging'];if(clinical.error||!allowed.includes(category)||title.length<2||title.length>160||detail.length<2||detail.length>5000)return json(res,400,{error:clinical.error?'بعض تفاصيل السجل أطول من المسموح.':'اختر نوع السجل واكتب العنوان والتفاصيل بشكل صحيح.'});const id=uuid(),created=nowIso(),record={category,title,detail,clinical:clinical.fields,serviceDate:String(body.serviceDate||'').slice(0,10),submittedBy:'staff',submittedByUserId:scope.user.id,status:'staff_entered_pending_clinician_review'};db.prepare('INSERT INTO medical_records(id,user_id,record_cipher,created_at) VALUES(?,?,?,?)').run(id,userId,encrypt(record),created);audit(scope.user.id,'patient_record_added_by_staff',id);audit(userId,'staff_record_received',id);return json(res,201,{ok:true,record:{id,...record,createdAt:created}});}
      const patientRecordEdit=url.pathname.match(/^\/api\/medical-admin\/patients\/([^/]+)\/records\/([^/]+)$/);
      if(req.method==='PATCH'&&patientRecordEdit){const userId=decodeURIComponent(patientRecordEdit[1]),recordId=decodeURIComponent(patientRecordEdit[2]);if(!patientInMedicalScope(userId,scope))return json(res,404,{error:'ملف المريض غير متاح لهذا الحساب أو الفرع.'});const row=db.prepare('SELECT record_cipher FROM medical_records WHERE id=? AND user_id=?').get(recordId,userId);if(!row)return json(res,404,{error:'السجل الطبي غير موجود.'});const body=await readJson(req),record=decrypt(row.record_cipher),allowed=['visit','diagnosis','treatment','medication','surgery','allergy','lab','imaging'],category=String(body.category||record.category||''),title=String(body.title??record.title??'').trim(),detail=String(body.detail??record.detail??'').trim();if(!allowed.includes(category)||title.length<2||title.length>160||detail.length<2||detail.length>5000)return json(res,400,{error:'تحقق من نوع السجل والعنوان والتفاصيل.'});record.category=category;record.title=title;record.detail=detail;record.serviceDate=String(body.serviceDate??record.serviceDate??'').slice(0,10);record.submittedBy=scope.doctor?'doctor':'staff';record.modifiedByUserId=scope.user.id;record.status=scope.doctor?'clinician_verified':'staff_updated_pending_clinician_review';db.prepare('UPDATE medical_records SET record_cipher=? WHERE id=? AND user_id=?').run(encrypt(record),recordId,userId);audit(scope.user.id,scope.doctor?'clinician_record_updated':'patient_record_updated_by_staff',recordId);audit(userId,'staff_record_updated',recordId);return json(res,200,{ok:true,record:{id:recordId,...record}});}
      const patientUpload=url.pathname.match(/^\/api\/medical-admin\/patients\/([^/]+)\/upload$/);
      if(req.method==='POST'&&patientUpload){const userId=decodeURIComponent(patientUpload[1]);if(!patientInMedicalScope(userId,scope))return json(res,404,{error:'ملف المريض غير متاح لهذا الحساب أو الفرع.'});const type=req.headers['content-type']||'',boundary=type.match(/boundary=(?:"([^"]+)"|([^;]+))/i);if(!boundary)return json(res,400,{error:'صيغة رفع الملف غير صالحة.'});const parts=parseMultipart(await readBody(req,MAX_BODY),boundary[1]||boundary[2]),file=parts.find(p=>p.name==='file'&&p.filename),category=textPart(parts,'category'),title=textPart(parts,'title'),report=boundedFields(Object.fromEntries(Object.entries(REPORT_FIELD_LIMITS).map(([k])=>[k,textPart(parts,k)])),REPORT_FIELD_LIMITS);if(!file||!file.data.length||file.data.length>15*1024*1024||!['lab','imaging'].includes(category)||title.length<2||report.error)return json(res,400,{error:report.error?'بعض تفاصيل التقرير أطول من المسموح.':'اختر نوع النتيجة وعنوانها وأرفق ملفًا حتى ١٥ ميجابايت.'});if(!verifyFile(file))return json(res,415,{error:'الصيغ المقبولة PDF أو JPG أو PNG أو DICOM صالح.'});const id=uuid(),created=nowIso(),record={category,title,fileName:path.basename(file.filename).slice(0,140),mimeType:file.contentType,size:file.data.length,fileData:file.data.toString('base64'),status:'uploaded_pending_clinician_review',note:textPart(parts,'note').slice(0,1000),report:report.fields,submittedBy:scope.doctor?'doctor':'staff',submittedByUserId:scope.user.id};db.prepare('INSERT INTO medical_records(id,user_id,record_cipher,created_at) VALUES(?,?,?,?)').run(id,userId,encrypt(record),created);audit(scope.user.id,'patient_result_uploaded_by_staff',id);audit(userId,'staff_result_received',id);return json(res,201,{ok:true,record:{id,...record,fileData:undefined,createdAt:created}});}
      const patientDetails=url.pathname.match(/^\/api\/medical-admin\/patients\/([^/]+)$/);
      if(req.method==='GET'&&patientDetails){const userId=decodeURIComponent(patientDetails[1]);if(!patientInMedicalScope(userId,scope))return json(res,404,{error:'ملف المريض غير متاح لهذا الحساب أو الفرع.'});const p=db.prepare('SELECT p.id AS patientId,p.medical_record_number AS medicalRecordNumber,p.profile_cipher,p.consent_at AS consentAt,p.consent_version AS consentVersion,u.email_cipher,u.phone_cipher FROM patient_profiles p JOIN users u ON u.id=p.user_id WHERE p.user_id=?').get(userId),records=db.prepare('SELECT id,record_cipher,created_at AS createdAt FROM medical_records WHERE user_id=? ORDER BY created_at DESC').all(userId).map(r=>{const record=decrypt(r.record_cipher),hasFile=Boolean(record.fileData);delete record.fileData;return {id:r.id,hasFile,...record,createdAt:r.createdAt};}),appointments=db.prepare('SELECT a.id,a.starts_at AS startsAt,a.created_at AS createdAt,a.status,a.is_follow_up AS isFollowUp,d.name AS doctor,d.specialty,b.name AS branch FROM appointments a JOIN doctors d ON d.id=a.doctor_id JOIN branches b ON b.id=a.branch_id WHERE a.patient_user_id=? ORDER BY a.starts_at DESC').all(userId).map(a=>({id:a.id,category:a.isFollowUp?'follow_up':'appointment',title:a.isFollowUp?'موعد إعادة':'حجز كشف',detail:`${a.doctor} • ${a.specialty} • ${a.branch} • ${a.status}`,serviceDate:a.startsAt,startsAt:a.startsAt,status:a.status,createdAt:a.createdAt,appointmentId:a.id})),auditEvents=db.prepare("SELECT event_type AS eventType,record_id AS recordId,created_at AS createdAt FROM audit_events WHERE user_id=? OR record_id IN (SELECT id FROM medical_records WHERE user_id=?) OR record_id IN (SELECT id FROM appointments WHERE patient_user_id=?) ORDER BY created_at DESC LIMIT 100").all(userId,userId,userId);audit(scope.user.id,scope.doctor?'doctor_patient_record_viewed':'staff_patient_record_viewed',userId);return json(res,200,{userId,patientId:p.patientId,medicalRecordNumber:p.medicalRecordNumber,profile:decrypt(p.profile_cipher),email:decrypt(p.email_cipher).email,phone:decrypt(p.phone_cipher).phone,consentAt:p.consentAt,consentVersion:p.consentVersion,auditEvents,records:[...appointments,...records].sort((a,b)=>String(b.createdAt||b.startsAt).localeCompare(String(a.createdAt||a.startsAt)))});}
      return json(res,404,{error:'مسار إدارة ملفات المرضى غير موجود.'});
    }
    if(url.pathname.startsWith('/api/branch/')){
      const member=requireBranchMember(req,res);if(!member)return;
      if(req.method==='GET'&&url.pathname==='/api/branch/dashboard'){
        if(member.branchId==='*')return json(res,400,{error:'اختر فرعًا من لوحة المالك.'});
        const branch=db.prepare('SELECT id,name,area,address,phone,active FROM branches WHERE id=?').get(member.branchId);if(!branch)return json(res,404,{error:'الفرع غير موجود.'});
        return json(res,200,{branch,department:member.department,counts:{staff:db.prepare('SELECT COUNT(*) AS n FROM branch_staff WHERE branch_id=? AND active=1 AND department<>\'manager\'').get(member.branchId).n,appointments:db.prepare("SELECT COUNT(*) AS n FROM appointments WHERE branch_id=? AND status IN ('booked','confirmed','in_progress')").get(member.branchId).n,requests:db.prepare("SELECT COUNT(*) AS n FROM service_requests WHERE branch_id=? AND status='pending_provider_confirmation'").get(member.branchId).n}});
      }
      if(req.method==='GET'&&url.pathname==='/api/branch/staff'){
        if(member.department!=='manager'&&member.department!=='operations')return json(res,403,{error:'قائمة موظفي الفرع للمدير أو مسؤول التشغيل.'});
        const staff=db.prepare('SELECT s.user_id AS userId,s.department,s.name_cipher,s.active,s.created_at AS createdAt,u.email_cipher,u.phone_cipher FROM branch_staff s JOIN users u ON u.id=s.user_id WHERE s.branch_id=? ORDER BY s.department').all(member.branchId).map(s=>({userId:s.userId,name:s.name_cipher?decrypt(s.name_cipher).name:'',department:s.department,active:Boolean(s.active),createdAt:s.createdAt,email:decrypt(s.email_cipher).email,phone:decrypt(s.phone_cipher).phone}));return json(res,200,{staff});
      }
      if(req.method==='POST'&&url.pathname==='/api/branch/staff')return json(res,403,{error:'إنشاء حسابات الموظفين والمديرين متاح لمسؤول المنصة فقط.'});
      if(req.method==='GET'&&url.pathname==='/api/branch/appointments'){
        if(!['manager','reception','appointments','follow_up','operations'].includes(member.department))return json(res,403,{error:'هذا الدور لا يراجع حجوزات العيادة.'});
        const appointments=db.prepare('SELECT a.id,a.patient_user_id AS patientUserId,a.starts_at AS startsAt,a.status,a.created_at AS createdAt,d.name AS doctor,d.specialty,p.profile_cipher,u.email_cipher,u.phone_cipher FROM appointments a JOIN doctors d ON d.id=a.doctor_id JOIN patient_profiles p ON p.user_id=a.patient_user_id JOIN users u ON u.id=a.patient_user_id WHERE a.branch_id=? ORDER BY a.starts_at').all(member.branchId).map(a=>({id:a.id,patientUserId:a.patientUserId,startsAt:a.startsAt,status:a.status,createdAt:a.createdAt,doctor:a.doctor,specialty:a.specialty,patientName:decrypt(a.profile_cipher).name,email:decrypt(a.email_cipher).email,phone:decrypt(a.phone_cipher).phone}));return json(res,200,{appointments});
      }
      const branchAppointmentStatus=url.pathname.match(/^\/api\/branch\/appointments\/([0-9a-f-]+)\/status$/i);
      if(req.method==='POST'&&branchAppointmentStatus){if(!['manager','reception','appointments','follow_up','operations'].includes(member.department))return json(res,403,{error:'هذا الدور لا يحدّث حالة الحجز.'});const body=await readJson(req),status=String(body.status||'');if(!['confirmed','in_progress','completed','cancelled'].includes(status))return json(res,400,{error:'حالة الحجز غير صالحة.'});const result=db.prepare('UPDATE appointments SET status=? WHERE id=? AND branch_id=? AND status NOT IN (\'cancelled\',\'completed\')').run(status,branchAppointmentStatus[1],member.branchId);if(!result.changes)return json(res,404,{error:'الحجز غير موجود أو مغلق.'});audit(member.id,'branch_appointment_status_updated',branchAppointmentStatus[1]);return json(res,200,{ok:true});}
      if(req.method==='GET'&&url.pathname==='/api/branch/service-requests'){
        const allowedDepartments=['manager','reception','appointments','follow_up','laboratory','radiology','pharmacy','operations'];if(!allowedDepartments.includes(member.department))return json(res,403,{error:'هذا الدور لا يراجع طلبات الخدمة.'});
        const typeFilter={laboratory:'lab_booking',radiology:'imaging_booking',pharmacy:'medicine_delivery'}[member.department];const rows=typeFilter?db.prepare('SELECT r.*,u.email_cipher,u.phone_cipher FROM service_requests r JOIN users u ON u.id=r.patient_user_id WHERE r.branch_id=? AND r.service_type=? ORDER BY r.created_at DESC').all(member.branchId,typeFilter):db.prepare('SELECT r.*,u.email_cipher,u.phone_cipher FROM service_requests r JOIN users u ON u.id=r.patient_user_id WHERE r.branch_id=? ORDER BY r.created_at DESC').all(member.branchId);return json(res,200,{requests:rows.map(r=>({id:r.id,serviceType:r.service_type,details:decrypt(r.details_cipher),status:r.status,adminNote:r.admin_note_cipher?decrypt(r.admin_note_cipher).note:'',createdAt:r.created_at,patientEmail:decrypt(r.email_cipher).email,patientPhone:decrypt(r.phone_cipher).phone}))});
      }
      const branchRequestStatus=url.pathname.match(/^\/api\/branch\/service-requests\/([0-9a-f-]+)\/status$/i);
      if(req.method==='POST'&&branchRequestStatus){const body=await readJson(req),status=String(body.status||''),note=String(body.note||'').trim().slice(0,1000),allowed=['pending_provider_confirmation','accepted','rejected','completed'];if(!allowed.includes(status))return json(res,400,{error:'حالة الطلب غير صالحة.'});const result=db.prepare('UPDATE service_requests SET status=?,admin_note_cipher=?,updated_at=? WHERE id=? AND branch_id=?').run(status,note?encrypt({note}):null,nowIso(),branchRequestStatus[1],member.branchId);if(!result.changes)return json(res,404,{error:'الطلب غير موجود في هذا الفرع.'});audit(member.id,'branch_service_request_updated',branchRequestStatus[1]);return json(res,200,{ok:true});}
      return json(res,404,{error:'مسار الفرع غير موجود.'});
    }
    if(url.pathname.startsWith('/api/admin/')){
      const admin=requireAdmin(req,res);if(!admin)return;
      if(req.method==='GET'&&url.pathname==='/api/admin/staff')return json(res,200,{staff:db.prepare('SELECT s.user_id AS userId,s.branch_id AS branchId,s.department,s.name_cipher,s.active,s.created_at AS createdAt,b.name AS branch,u.email_cipher,u.phone_cipher FROM branch_staff s JOIN branches b ON b.id=s.branch_id JOIN users u ON u.id=s.user_id ORDER BY b.name,s.department').all().map(s=>({userId:s.userId,branchId:s.branchId,branch:s.branch,name:s.name_cipher?decrypt(s.name_cipher).name:'',department:s.department,active:Boolean(s.active),createdAt:s.createdAt,email:decrypt(s.email_cipher).email,phone:decrypt(s.phone_cipher).phone}))});
      if(req.method==='POST'&&url.pathname==='/api/admin/staff'){const b=await readJson(req),account=await createBranchAccount({branchId:String(b.branchId||''),department:String(b.department||''),name:b.name,email:b.email,phone:b.phone});audit(admin.id,'branch_account_created',account.userId);return json(res,201,{ok:true,account});}
      const deactivateStaff=url.pathname.match(/^\/api\/admin\/staff\/([0-9a-f-]+)\/deactivate$/i);
      if(req.method==='POST'&&deactivateStaff){const result=db.prepare('UPDATE branch_staff SET active=0 WHERE user_id=? AND active=1').run(deactivateStaff[1]);if(!result.changes)return json(res,404,{error:'حساب الموظف غير موجود أو موقوف.'});db.prepare("UPDATE users SET role='disabled' WHERE id=?").run(deactivateStaff[1]);db.prepare('DELETE FROM sessions WHERE user_id=?').run(deactivateStaff[1]);audit(admin.id,'branch_account_deactivated',deactivateStaff[1]);return json(res,200,{ok:true});}
      if(req.method==='GET'&&url.pathname==='/api/admin/branches')return json(res,200,{branches:db.prepare('SELECT * FROM branches ORDER BY name').all()});
      if(req.method==='GET'&&url.pathname==='/api/admin/doctors')return json(res,200,{doctors:db.prepare('SELECT d.*,b.name AS branch FROM doctors d JOIN branches b ON b.id=d.branch_id ORDER BY d.created_at DESC').all().map(d=>({...d,licenseNumber:decrypt(d.license_cipher).licenseNumber}))});
      if(req.method==='POST'&&url.pathname==='/api/admin/branches'){
        const b=await readJson(req),name=String(b.name||'').trim(),area=String(b.area||'').trim(),address=String(b.address||'').trim(),phone=String(b.phone||'').trim();
        if(name.length<2||name.length>100||area.length<2||area.length>100||address.length<5||address.length>240||phone.length>30)return json(res,400,{error:'أدخل اسم الفرع والمنطقة والعنوان ورقم تواصل صحيحًا.'});
        const id=uuid();db.prepare('INSERT INTO branches(id,name,area,address,phone,active,created_at) VALUES(?,?,?,?,?,0,?)').run(id,name,area,address,phone,nowIso());audit(admin.id,'branch_created',id);return json(res,201,{ok:true,id});
      }
      const activateBranch=url.pathname.match(/^\/api\/admin\/branches\/([0-9a-f-]+)\/activate$/i);
      if(req.method==='POST'&&activateBranch){const b=await readJson(req),reference=String(b.verificationReference||'').trim().slice(0,160);if(reference.length<4)return json(res,400,{error:'سجّل مرجع التحقق من التشغيل والترخيص.'});const result=db.prepare('UPDATE branches SET active=1,verification_reference=? WHERE id=?').run(reference,activateBranch[1]);if(!result.changes)return json(res,404,{error:'الفرع غير موجود.'});audit(admin.id,'branch_activated',activateBranch[1]);return json(res,200,{ok:true});}
      const updateBranch=url.pathname.match(/^\/api\/admin\/branches\/([0-9a-f-]+)\/update$/i);
      if(req.method==='POST'&&updateBranch){const b=await readJson(req),name=String(b.name||'').trim(),area=String(b.area||'').trim(),address=String(b.address||'').trim(),phone=String(b.phone||'').trim();if(name.length<2||name.length>100||area.length<2||area.length>100||address.length<5||address.length>240||phone.length>30)return json(res,400,{error:'أدخل اسم الفرع والمنطقة والعنوان الفعلي ورقم التواصل.'});const result=db.prepare('UPDATE branches SET name=?,area=?,address=?,phone=? WHERE id=?').run(name,area,address,phone,updateBranch[1]);if(!result.changes)return json(res,404,{error:'الفرع غير موجود.'});audit(admin.id,'branch_updated',updateBranch[1]);return json(res,200,{ok:true});}
      if(req.method==='POST'&&url.pathname==='/api/admin/doctors'){
        const d=await readJson(req),name=String(d.name||'').trim(),specialty=String(d.specialty||'').trim(),credentials=String(d.credentials||'').trim(),license=String(d.licenseNumber||'').trim(),bio=String(d.bio||'').trim(),experience=Number(d.yearsExperience),fee=Number(d.consultationFee),branchId=String(d.branchId||'');
        if(name.length<3||name.length>120||specialty.length<2||credentials.length<3||license.length<3||!Number.isInteger(experience)||experience<11||experience>60||!Number.isInteger(fee)||fee<0||fee>100000||!db.prepare('SELECT 1 FROM branches WHERE id=?').get(branchId))return json(res,400,{error:'تحقق من الاسم والتخصص والمؤهلات ورقم الترخيص والخبرة (١١ سنة على الأقل) والسعر والفرع.'});
        const id=uuid();db.prepare('INSERT INTO doctors(id,name,specialty,credentials,years_experience,license_cipher,branch_id,consultation_fee,bio,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,name,specialty,credentials,experience,encrypt({licenseNumber:license}),branchId,fee,bio,nowIso());audit(admin.id,'doctor_created',id);return json(res,201,{ok:true,id,status:'pending_verification'});
      }
      const verifyDoctor=url.pathname.match(/^\/api\/admin\/doctors\/([0-9a-f-]+)\/verify$/i);
      if(req.method==='POST'&&verifyDoctor){const b=await readJson(req),reference=String(b.verificationReference||'').trim().slice(0,160);if(reference.length<4)return json(res,400,{error:'سجّل مرجع مراجعة الترخيص والمؤهلات قبل التفعيل.'});const result=db.prepare("UPDATE doctors SET license_verified=1,verification_reference=?,status='active',verified_at=?,verified_by=? WHERE id=?").run(reference,nowIso(),admin.id,verifyDoctor[1]);if(!result.changes)return json(res,404,{error:'الطبيب غير موجود.'});audit(admin.id,'doctor_verified',verifyDoctor[1]);return json(res,200,{ok:true});}
      const doctorAccount=url.pathname.match(/^\/api\/admin\/doctors\/([0-9a-f-]+)\/account$/i);
      if(req.method==='POST'&&doctorAccount){const d=db.prepare('SELECT id,name,status,license_verified,account_user_id FROM doctors WHERE id=?').get(doctorAccount[1]);if(!d)return json(res,404,{error:'الطبيب غير موجود.'});if(!d.license_verified||d.status!=='active')return json(res,409,{error:'أنشئ حساب الطبيب بعد مراجعة ترخيصه وتفعيله.'});if(d.account_user_id)return json(res,409,{error:'للطبيب حساب بالفعل.'});const b=await readJson(req),email=String(b.email||'').trim().toLowerCase(),phone=String(b.phone||'').replace(/\s/g,'');if(!/^\S+@\S+\.\S+$/.test(email)||email.length>254||phone&&!/^01[0-2,5][0-9]{8}$/.test(phone))return json(res,400,{error:'أدخل بريد الطبيب ورقم هاتف صالحًا.'});if(db.prepare('SELECT 1 FROM users WHERE email_lookup=?').get(emailLookup(email)))return json(res,409,{error:'البريد مسجل بحساب آخر.'});const userId=uuid(),password=crypto.randomBytes(24).toString('base64url'),salt=crypto.randomBytes(16),hash=await pbkdf2(password,salt,310000,32,'sha256');db.exec('BEGIN IMMEDIATE');try{db.prepare("INSERT INTO users(id,email_lookup,email_cipher,phone_cipher,password_salt,password_hash,password_change_required,role,created_at) VALUES(?,?,?,?,?,?,1,'doctor',?)").run(userId,emailLookup(email),encrypt({email}),encrypt({phone}),salt,hash,nowIso());db.prepare('UPDATE doctors SET account_user_id=? WHERE id=? AND account_user_id IS NULL').run(userId,d.id);db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');if(String(e.message).includes('UNIQUE'))return json(res,409,{error:'البريد أو الحساب مرتبط بالفعل.'});throw e;}audit(admin.id,'doctor_account_created',d.id);return json(res,201,{ok:true,account:{email,name:d.name,temporaryPassword:password}});}
      if(req.method==='POST'&&url.pathname==='/api/admin/doctor-hours'){
        const h=await readJson(req),doctorId=String(h.doctorId||''),weekday=Number(h.weekday),start=String(h.startTime||''),end=String(h.endTime||''),slot=Number(h.slotMinutes);
        const doctor=db.prepare('SELECT id FROM doctors WHERE id=?').get(doctorId);
        if(!doctor||!Number.isInteger(weekday)||weekday<0||weekday>6||!/^([01]\d|2[0-3]):[0-5]\d$/.test(start)||!/^([01]\d|2[0-3]):[0-5]\d$/.test(end)||end<=start||!Number.isInteger(slot)||slot<10||slot>120)return json(res,400,{error:'تحقق من الطبيب واليوم وساعات العمل ومدة الموعد.'});
        if(db.prepare('SELECT 1 FROM doctor_hours WHERE doctor_id=? AND weekday=? AND active=1 AND start_time<? AND end_time>?').get(doctorId,weekday,end,start))return json(res,409,{error:'تتداخل هذه الفترة مع جدول موجود للطبيب.'});
        const id=uuid();db.prepare('INSERT INTO doctor_hours(id,doctor_id,weekday,start_time,end_time,slot_minutes) VALUES(?,?,?,?,?,?)').run(id,doctorId,weekday,start,end,slot);audit(admin.id,'doctor_hours_created',doctorId);return json(res,201,{ok:true,id});
      }
      if(req.method==='GET'&&url.pathname==='/api/admin/appointments')return json(res,200,{appointments:db.prepare('SELECT a.id,a.starts_at AS startsAt,a.status,d.name AS doctor,b.name AS branch,u.email_cipher FROM appointments a JOIN doctors d ON d.id=a.doctor_id JOIN branches b ON b.id=a.branch_id JOIN users u ON u.id=a.patient_user_id ORDER BY a.starts_at DESC').all().map(a=>({id:a.id,startsAt:a.startsAt,status:a.status,doctor:a.doctor,branch:a.branch,patientEmail:decrypt(a.email_cipher).email}))});
      if(req.method==='GET'&&url.pathname==='/api/admin/service-requests')return json(res,200,{requests:db.prepare('SELECT r.*,u.email_cipher,u.phone_cipher,b.name AS branch FROM service_requests r JOIN users u ON u.id=r.patient_user_id LEFT JOIN branches b ON b.id=r.branch_id ORDER BY r.created_at DESC').all().map(r=>({id:r.id,branchId:r.branch_id,branch:r.branch||'',serviceType:r.service_type,details:decrypt(r.details_cipher),status:r.status,adminNote:r.admin_note_cipher?decrypt(r.admin_note_cipher).note:'',createdAt:r.created_at,patientEmail:decrypt(r.email_cipher).email,patientPhone:decrypt(r.phone_cipher).phone}))});
      const serviceRequestStatus=url.pathname.match(/^\/api\/admin\/service-requests\/([0-9a-f-]+)\/status$/i);
      if(req.method==='POST'&&serviceRequestStatus){const body=await readJson(req),status=String(body.status||''),note=String(body.note||'').trim().slice(0,1000),branchId=String(body.branchId||''),allowed=['pending_provider_confirmation','accepted','rejected','completed'];if(!allowed.includes(status))return json(res,400,{error:'حالة الطلب غير صالحة.'});if(branchId&&!db.prepare('SELECT 1 FROM branches WHERE id=?').get(branchId))return json(res,400,{error:'الفرع غير موجود.'});const result=db.prepare("UPDATE service_requests SET status=?,admin_note_cipher=?,updated_at=?,branch_id=CASE WHEN ?='' THEN branch_id ELSE ? END WHERE id=?").run(status,note?encrypt({note}):null,nowIso(),branchId,branchId,serviceRequestStatus[1]);if(!result.changes)return json(res,404,{error:'الطلب غير موجود.'});audit(admin.id,'service_request_status_updated',serviceRequestStatus[1]);return json(res,200,{ok:true});}
      return json(res,404,{error:'مسار الإدارة غير موجود.'});
    }

    if (req.method === 'POST' && url.pathname === '/api/register') {
      const body = await readJson(req);
      const email = String(body.email || '').trim().toLowerCase();
      const phone = String(body.phone || '').replace(/\s/g, '');
      const password = String(body.password || '');
      const name = String(body.name || '').trim();
      if (name.length < 3 || name.length > 120 || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^01[0-2,5][0-9]{8}$/.test(phone) || password.length < 12 || password.length > 128 || !body.healthConsent) return json(res, 400, { error: 'أكمل الاسم والبريد ورقم الهاتف وكلمة مرور من ١٢ إلى ١٢٨ حرفًا، ووافق صراحة على معالجة الملف الطبي.' });
      const userId = uuid(), patientId = uuid(), salt = crypto.randomBytes(16);
      const hash = await pbkdf2(password, salt, 310000, 32, 'sha256');
      let medicalRecordNumber;try {
        db.exec('BEGIN IMMEDIATE');
        medicalRecordNumber=newMedicalRecordNumber();
        db.prepare('INSERT INTO users(id,email_lookup,email_cipher,phone_cipher,password_salt,password_hash,created_at) VALUES(?,?,?,?,?,?,?)').run(userId, emailLookup(email), encrypt({ email }), encrypt({ phone }), salt, hash, nowIso());
        db.prepare('INSERT INTO patient_profiles(id,user_id,profile_cipher,consent_at,consent_version,medical_record_number,created_at) VALUES(?,?,?,?,?,?,?)').run(patientId, userId, encrypt({ name, birthDate: body.birthDate || '', bloodType: '', allergies: [], conditions: [], emergencyContact: '' }), nowIso(), 'health-data-consent-v1',medicalRecordNumber, nowIso());
        db.exec('COMMIT');
      } catch (e) { db.exec('ROLLBACK'); if (String(e.message).includes('UNIQUE')) return json(res, 409, { error: 'هذا البريد مسجل بالفعل.' }); throw e; }
      audit(userId, 'account_created'); setSession(res, userId); return json(res, 201, { ok: true, patientId,medicalRecordNumber });
    }
    if (req.method === 'POST' && url.pathname === '/api/login') {
      const body = await readJson(req); const email = String(body.email || '').trim().toLowerCase();
      const attemptKey = crypto.createHash('sha256').update(`${req.socket.remoteAddress || ''}:${email}`).digest('hex');
      if (authLocked(attemptKey)) return json(res, 429, { error: 'محاولات كثيرة. انتظر ١٠ دقائق ثم حاول مرة أخرى.' });
      const row = db.prepare('SELECT * FROM users WHERE email_lookup=?').get(emailLookup(email));
      const hash = await pbkdf2(String(body.password || ''), row?.password_salt||dummyPasswordSalt, 310000, 32, 'sha256');
      if (!row||!crypto.timingSafeEqual(hash, row?.password_hash||dummyPasswordHash)) { authFailed(attemptKey); return json(res, 401, { error: 'البريد أو كلمة المرور غير صحيحة.' }); }
      authSucceeded(attemptKey);
      setSession(res, row.id); audit(row.id, 'login'); return json(res, 200, { ok: true });
    }
    if(req.method==='POST'&&url.pathname==='/api/password/change'){
      const user=currentUser(req);if(!user)return json(res,401,{error:'سجّل الدخول أولًا.'});const body=await readJson(req),currentPassword=String(body.currentPassword||''),newPassword=String(body.newPassword||'');if(newPassword.length<12||newPassword.length>200)return json(res,400,{error:'كلمة المرور الجديدة يجب أن تكون من ١٢ إلى ٢٠٠ حرفًا.'});if(newPassword===currentPassword)return json(res,400,{error:'اختر كلمة مرور مختلفة عن المؤقتة.'});const row=db.prepare('SELECT password_salt,password_hash FROM users WHERE id=?').get(user.id),candidate=await pbkdf2(currentPassword,row.password_salt,310000,32,'sha256');if(!crypto.timingSafeEqual(candidate,row.password_hash))return json(res,401,{error:'كلمة المرور الحالية غير صحيحة.'});const salt=crypto.randomBytes(16),hash=await pbkdf2(newPassword,salt,310000,32,'sha256');db.prepare('UPDATE users SET password_salt=?,password_hash=?,password_change_required=0 WHERE id=?').run(salt,hash,user.id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(user.id);setSession(res,user.id);audit(user.id,'password_changed');return json(res,200,{ok:true});
    }
    if (req.method === 'POST' && url.pathname === '/api/logout') { const user = currentUser(req); if (user) audit(user.id, 'logout'); clearSession(req, res); return json(res, 200, { ok: true }); }
    if (req.method === 'GET' && url.pathname === '/api/me') {
      const user = currentUser(req); if (!user) return json(res, 200, { user: null });
      const patient = db.prepare('SELECT id,profile_cipher,consent_at FROM patient_profiles WHERE user_id=?').get(user.id);
      const account = db.prepare('SELECT email_cipher FROM users WHERE id=?').get(user.id);
      const patientNumber=patient?db.prepare('SELECT medical_record_number FROM patient_profiles WHERE user_id=?').get(user.id)?.medical_record_number:null;
      return json(res, 200, { user: { email: decrypt(account.email_cipher).email, role:user.role,mustChangePassword:Boolean(user.mustChangePassword) }, patient: patient ? { id: patient.id, medicalRecordNumber:patientNumber,profile: decrypt(patient.profile_cipher), consentAt: patient.consent_at } : null });
    }
    if (req.method === 'GET' && url.pathname === '/api/medical-record') {
      const user = currentUser(req); if (!user) return json(res, 401, { error: 'سجّل الدخول أولًا.' });
      if(user.role!=='patient')return json(res,403,{error:'الملف الطبي متاح لحساب المريض فقط.'});
      const patient = db.prepare('SELECT id,medical_record_number AS medicalRecordNumber,profile_cipher,consent_at,consent_version AS consentVersion FROM patient_profiles WHERE user_id=?').get(user.id);
      const patientAccount=db.prepare('SELECT phone_cipher FROM users WHERE id=?').get(user.id);
      const records = db.prepare('SELECT id,record_cipher,created_at FROM medical_records WHERE user_id=? ORDER BY created_at DESC').all(user.id).map(row => { const record=decrypt(row.record_cipher); delete record.fileData; return { id: row.id, createdAt: row.created_at, ...record }; });
      const appointments=db.prepare('SELECT a.id,a.starts_at AS startsAt,a.created_at AS createdAt,a.status,a.is_follow_up AS isFollowUp,d.name AS doctor,d.specialty,b.name AS branch FROM appointments a JOIN doctors d ON d.id=a.doctor_id JOIN branches b ON b.id=a.branch_id WHERE a.patient_user_id=? ORDER BY a.starts_at DESC').all(user.id).map(a=>({id:a.id,category:a.isFollowUp?'follow_up':'appointment',title:a.isFollowUp?'موعد إعادة':'حجز كشف',detail:`${a.doctor} • ${a.specialty} • ${a.branch} • ${a.status}`,serviceDate:a.startsAt,startsAt:a.startsAt,status:a.status,createdAt:a.createdAt,appointmentId:a.id}));
      const auditEvents=db.prepare("SELECT event_type AS eventType,record_id AS recordId,created_at AS createdAt FROM audit_events WHERE user_id=? OR record_id IN (SELECT id FROM medical_records WHERE user_id=?) OR record_id IN (SELECT id FROM appointments WHERE patient_user_id=?) ORDER BY created_at DESC LIMIT 100").all(user.id,user.id,user.id);
      audit(user.id, 'record_viewed'); return json(res, 200, { patientId: patient.id,medicalRecordNumber:patient.medicalRecordNumber,profile: decrypt(patient.profile_cipher),phone:decrypt(patientAccount.phone_cipher).phone,consentAt:patient.consent_at,consentVersion:patient.consentVersion,records:[...appointments,...records].sort((a,b)=>String(b.createdAt||b.startsAt).localeCompare(String(a.createdAt||a.startsAt))),auditEvents });
    }
    if (req.method === 'POST' && ['/api/record-entry','/api/upload'].includes(url.pathname)) {
      const user=currentUser(req);if(!user)return json(res,401,{error:'سجّل الدخول أولًا.'});
      return json(res,403,{error:'الملف الطبي للقراءة فقط للمريض. يضيف الطبيب أو موظفو المركز السجلات والنتائج.'});
    }
    const download = url.pathname.match(/^\/api\/medical-record\/([0-9a-f-]+)\/file$/i);
    if (req.method === 'GET' && download) {
      const user = currentUser(req); if (!user) return json(res, 401, { error: 'سجّل الدخول أولًا.' });
      if(user.role!=='patient')return json(res,403,{error:'تنزيل النتيجة متاح لحساب المريض فقط.'});
      const row = db.prepare('SELECT id,record_cipher FROM medical_records WHERE id=? AND user_id=?').get(download[1], user.id);
      if (!row) return json(res, 404, { error: 'الملف غير موجود.' });
      const record = decrypt(row.record_cipher); const file = Buffer.from(record.fileData, 'base64'); audit(user.id, 'result_file_downloaded', row.id);
      res.writeHead(200, { 'Content-Type': record.mimeType, 'Content-Length': file.length, 'Content-Disposition': `attachment; filename="result-${row.id}"`, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); return res.end(file);
    }
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return fs.createReadStream(path.join(ROOT, 'index.html')).pipe(res);
    }
    if(req.method==='GET'&&['/login','/register'].includes(url.pathname)){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});return fs.createReadStream(path.join(ROOT,'login.html')).pipe(res);}
    if (req.method === 'GET' && url.pathname === '/privacy') {
      res.writeHead(200, { 'Content-Type': 'text/markdown; charset=utf-8', 'Cache-Control': 'no-store' }); return fs.createReadStream(path.join(ROOT, 'PRIVACY.md')).pipe(res);
    }
    if (req.method === 'GET' && ['/app.js','/data.js','/auth-page.js'].includes(url.pathname)) {
      res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-cache' }); return fs.createReadStream(path.join(ROOT, url.pathname.slice(1))).pipe(res);
    }
    if(req.method==='GET'&&url.pathname==='/patient-record.css'){
      res.writeHead(200,{'Content-Type':'text/css; charset=utf-8','Cache-Control':'no-cache'});return fs.createReadStream(path.join(ROOT,'patient-record.css')).pipe(res);
    }
    return json(res, 404, { error: 'المسار غير موجود.' });
  } catch (error) {
    if(!error.status||error.status>=500)console.error(error);
    if (!res.headersSent) json(res, error.status || 500, { error: error.status ? error.message : 'حدث خطأ داخلي.' }); else res.destroy();
  }
});

if (require.main === module) server.listen(PORT, HOST, () => console.log(`Clinic app listening on http://${HOST}:${PORT}`));
module.exports = { server, db, encrypt, decrypt, emailLookup, uuid };
