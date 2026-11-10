const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');

process.env.CLINIC_DATA_KEY = crypto.randomBytes(32).toString('base64');
process.env.CLINIC_DB_PATH = ':memory:';
const { server, db, encrypt, emailLookup } = require('../server');
const handler = server.listeners('request')[0];

async function request(method, url, body, cookie = '') {
  const raw = body === undefined ? '' : JSON.stringify(body);
  const req = Readable.from(raw ? [Buffer.from(raw)] : []);
  req.method = method; req.url = url;
  req.headers = { host: '127.0.0.1:3000', origin: 'http://127.0.0.1:3000', ...(raw ? { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(raw)) } : {}), ...(cookie ? { cookie } : {}) };
  req.socket = { encrypted: false, remoteAddress: 'test' };
  const headers = {};
  const response = { headersSent: false, setHeader(k,v){headers[k]=v;}, writeHead(status, h={}){this.status=status;Object.assign(headers,h);this.headersSent=true;}, end(data=''){this.data=data;}, destroy(){this.destroyed=true;} };
  await handler(req,response);
  return { status: response.status, headers, body: response.data ? JSON.parse(response.data) : null };
}
async function rawRequest(method,url,raw,contentType,cookie='') {
  const req=Readable.from([raw]);req.method=method;req.url=url;req.headers={host:'127.0.0.1:3000',origin:'http://127.0.0.1:3000','content-type':contentType,'content-length':String(raw.length),...(cookie?{cookie}:{})};req.socket={encrypted:false,remoteAddress:'test'};
  const headers={},response={headersSent:false,setHeader(k,v){headers[k]=v;},writeHead(status,h={}){this.status=status;Object.assign(headers,h);this.headersSent=true;},end(data=''){this.data=data;},destroy(){this.destroyed=true;}};
  await handler(req,response);return {status:response.status,headers,raw:response.data};
}

let patientCookie, adminCookie, doctorCookie, branchId, doctorId, patientId;
before(async () => {
  const salt = crypto.randomBytes(16), password = 'AdminStrongPass!2026';
  const hash = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
  const adminId = crypto.randomUUID();
  db.prepare('INSERT INTO users(id,email_lookup,email_cipher,phone_cipher,password_salt,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?,?)').run(adminId,emailLookup('admin@example.test'),encrypt({email:'admin@example.test'}),encrypt({phone:''}),salt,hash,'admin',new Date().toISOString());
  const adminLogin = await request('POST','/api/login',{email:'admin@example.test',password});
  adminCookie = adminLogin.headers['Set-Cookie'].split(';')[0];
  const register = await request('POST','/api/register',{name:'مريض تجريبي',email:'patient@example.test',phone:'01012345678',password:'PatientStrongPass!2026',healthConsent:true,role:'admin'});
  assert.equal(register.status,201); patientId=register.body.patientId;assert.match(register.body.medicalRecordNumber,/^TBY-\d{8}$/);
  patientCookie = register.headers['Set-Cookie'].split(';')[0];
});
after(() => { db.close(); });

test('signup creates a patient file and role separation is enforced', async () => {
  const me=await request('GET','/api/me',undefined,patientCookie);
  assert.equal(me.body.patient.id,patientId); assert.equal(me.body.user.role,'patient');
  assert.equal((await request('GET','/api/admin/branches',undefined,patientCookie)).status,403);
  assert.equal((await request('GET','/api/medical-record',undefined,adminCookie)).status,403);
  const planned=await request('GET','/api/admin/branches',undefined,adminCookie);
  assert.deepEqual(planned.body.branches.map(b=>b.name).sort(),['التجمع الخامس','الجيزة','المعادي','مدينة نصر','مصر الجديدة'].sort());
  assert.ok(planned.body.branches.every(b=>b.active===0));
});

test('admin can publish verified branch and doctor, schedule real slots, and book once', async () => {
  assert.equal((await request('GET','/api/public/doctors')).body.doctors.length,0);
  const branch=await request('POST','/api/admin/branches',{name:'المعادي',area:'المعادي',address:'عنوان تجريبي غير حقيقي',phone:''},adminCookie);
  assert.equal(branch.status,201); branchId=branch.body.id;
  assert.equal((await request('POST',`/api/admin/branches/${branchId}/activate`,{verificationReference:'TEST-REF-1'},adminCookie)).status,200);
  const doctor=await request('POST','/api/admin/doctors',{name:'طبيب تجريبي',specialty:'باطنة',credentials:'مؤهل تجريبي',licenseNumber:'TEST-LICENSE',yearsExperience:11,consultationFee:500,branchId},adminCookie);
  assert.equal(doctor.status,201); doctorId=doctor.body.id;
  assert.equal((await request('POST',`/api/admin/doctors/${doctorId}/verify`,{verificationReference:'TEST-VERIFY-1'},adminCookie)).status,200);
  assert.equal((await request('GET','/api/public/doctors')).body.doctors.length,1);
  const date=new Date(Date.now()+14*86400000).toISOString().slice(0,10), weekday=new Date(`${date}T12:00:00Z`).getUTCDay();
  assert.equal((await request('POST','/api/admin/doctor-hours',{doctorId,weekday,startTime:'23:00',endTime:'23:30',slotMinutes:30},adminCookie)).status,201);
  const slots=(await request('GET',`/api/public/slots?doctorId=${doctorId}&date=${date}`)).body.slots;
  assert.deepEqual(slots,['23:00']);
  const booking={doctorId,startsAt:`${date}T23:00`};
  assert.equal((await request('POST','/api/appointments',booking,patientCookie)).status,201);
  assert.equal((await request('POST','/api/appointments',booking,patientCookie)).status,409);
  const appointments=(await request('GET','/api/appointments',undefined,patientCookie)).body.appointments;
  assert.equal(appointments.length,1); assert.equal(appointments[0].status,'booked');
  const bookedChart=await request('GET','/api/medical-record',undefined,patientCookie);assert.equal(bookedChart.body.medicalRecordNumber,'TBY-00000001');assert.ok(bookedChart.body.records.some(r=>r.category==='appointment'&&r.appointmentId===appointments[0].id));
  const doctorAccount=await request('POST',`/api/admin/doctors/${doctorId}/account`,{email:'doctor@example.test',phone:'01012345678'},adminCookie);
  assert.equal(doctorAccount.status,201);assert.ok(doctorAccount.body.account.temporaryPassword);
  const doctorLogin=await request('POST','/api/login',{email:'doctor@example.test',password:doctorAccount.body.account.temporaryPassword});
  assert.equal(doctorLogin.status,200);doctorCookie=doctorLogin.headers['Set-Cookie'].split(';')[0];
  assert.equal((await request('GET','/api/doctor/appointments',undefined,doctorCookie)).status,428);
  const doctorPassword=await request('POST','/api/password/change',{currentPassword:doctorAccount.body.account.temporaryPassword,newPassword:'DoctorNewStrongPass!2026'},doctorCookie);assert.equal(doctorPassword.status,200);doctorCookie=doctorPassword.headers['Set-Cookie'].split(';')[0];
  assert.equal((await request('GET','/api/doctor/me',undefined,doctorCookie)).body.doctors[0].id,doctorId);
  assert.equal((await request('GET','/api/doctor/appointments',undefined,doctorCookie)).body.appointments.length,1);
  assert.equal((await request('GET','/api/medical-record',undefined,doctorCookie)).status,403);
  const appointment=(await request('GET','/api/doctor/appointments',undefined,doctorCookie)).body.appointments[0];
  const chart=await request('GET',`/api/doctor/appointments/${appointment.id}/records`,undefined,doctorCookie);assert.equal(chart.status,200);assert.equal(chart.body.patientId,patientId);
  assert.equal((await request('PATCH',`/api/medical-admin/patients/${chart.body.patientUserId}/profile`,{bloodType:'A+'},doctorCookie)).status,200);
  db.prepare("UPDATE appointments SET starts_at=?,status='completed' WHERE id=?").run(`${new Date(Date.now()-86400000).toISOString().slice(0,10)}T10:00`,appointment.id);
  const followDate=new Date(Date.now()+21*86400000).toISOString().slice(0,10);
  const follow=await request('POST',`/api/doctor/appointments/${appointment.id}/follow-up`,{startsAt:`${followDate}T23:00`},doctorCookie);assert.equal(follow.status,201);
  const afterFollow=await request('GET','/api/medical-record',undefined,patientCookie);assert.ok(afterFollow.body.records.some(r=>r.category==='follow_up'&&r.appointmentId===follow.body.appointment.id));
  const boundary='doctor-report-boundary',pdf=Buffer.from('%PDF-1.4\nverified report\n%%EOF'),parts=[Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="category"\r\n\r\nlab\r\n--${boundary}\r\nContent-Disposition: form-data; name="title"\r\n\r\nتحليل موثق\r\n--${boundary}\r\nContent-Disposition: form-data; name="note"\r\n\r\nملخص التقرير\r\n--${boundary}\r\nContent-Disposition: form-data; name="result"\r\n\r\nنتيجة افتراضية للاختبار\r\n--${boundary}\r\nContent-Disposition: form-data; name="units"\r\n\r\nmg/dL\r\n--${boundary}\r\nContent-Disposition: form-data; name="referenceRange"\r\n\r\n0-10\r\n--${boundary}\r\nContent-Disposition: form-data; name="resultStatus"\r\n\r\nfinal\r\n--${boundary}\r\nContent-Disposition: form-data; name="providerName"\r\n\r\nمعمل تجريبي\r\n--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="lab.pdf"\r\nContent-Type: application/pdf\r\n\r\n`),pdf,Buffer.from(`\r\n--${boundary}--\r\n`)];
  const resultUpload=await rawRequest('POST',`/api/medical-admin/patients/${chart.body.patientUserId}/upload`,Buffer.concat(parts),`multipart/form-data; boundary=${boundary}`,doctorCookie);assert.equal(resultUpload.status,201);
  const report=JSON.parse(resultUpload.raw.toString()).record,withReport=await request('GET','/api/medical-record',undefined,patientCookie),visibleReport=withReport.body.records.find(r=>r.id===report.id);assert.ok(visibleReport&&visibleReport.title==='تحليل موثق'&&visibleReport.fileName==='lab.pdf');assert.equal(visibleReport.report.result,'نتيجة افتراضية للاختبار');assert.equal(visibleReport.report.units,'mg/dL');
});

test('security headers are returned on API responses', async () => {
  const res=await request('GET','/health');
  assert.equal(res.status,200);
  assert.ok(res.headers['Content-Security-Policy']);
  assert.equal(res.headers['X-Content-Type-Options'],'nosniff');
});

test('patient medical file is read-only and lab uploads require staff workflow', async()=>{
  assert.equal((await request('POST','/api/record-entry',{category:'visit',title:'إدخال مريض',detail:'يجب رفضه'},patientCookie)).status,403);
  const boundary='test-boundary-45',pdf=Buffer.from('%PDF-1.4\nclinic report\n%%EOF'),parts=[];
  parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="category"\r\n\r\nlab\r\n--${boundary}\r\nContent-Disposition: form-data; name="title"\r\n\r\nتحليل\r\n--${boundary}--\r\n`));
  const uploaded=await rawRequest('POST','/api/upload',Buffer.concat(parts),`multipart/form-data; boundary=${boundary}`,patientCookie);
  assert.equal(uploaded.status,403);
});

test('all non-clinic services create tracked requests for patients and admins',async()=>{
  const requests=[
    {serviceType:'hospital',specialty:'قلب',area:'مدينة نصر'},
    {serviceType:'home_visit',specialty:'باطنة',area:'المعادي',address:'شارع تجريبي ١٠، المعادي'},
    {serviceType:'phone_consult',specialty:'أطفال',area:'الجيزة',phone:'01012345678'},
    {serviceType:'video_consult',specialty:'جلدية',area:'مصر الجديدة',phone:'01012345678'},
    {serviceType:'medicine_delivery',medicines:'دواء موصوف من الطبيب',area:'المعادي',address:'شارع تجريبي ١٠، المعادي',phone:'01012345678'},
    {serviceType:'lab_booking',serviceName:'صورة دم كاملة',area:'المعادي',preferredDate:new Date(Date.now()+86400000).toISOString().slice(0,10)},
    {serviceType:'imaging_booking',serviceName:'أشعة عادية على الصدر',area:'مدينة نصر'}
  ];
  const created=[];for(const body of requests){const result=await request('POST','/api/service-requests',body,patientCookie);assert.equal(result.status,201);assert.equal(result.body.request.status,'pending_provider_confirmation');created.push(result.body.request);}
  const patientList=await request('GET','/api/service-requests',undefined,patientCookie);assert.equal(patientList.body.requests.length,7);
  assert.equal((await request('POST','/api/service-requests',{serviceType:'lab_booking',serviceName:'تحليل',area:'القاهرة'},adminCookie)).status,403);
  const queue=await request('GET','/api/admin/service-requests',undefined,adminCookie);assert.equal(queue.body.requests.length,7);
  assert.equal((await request('POST',`/api/admin/service-requests/${created[5].id}/status`,{status:'accepted',note:'تم تأكيد التوفر مبدئيًا'},adminCookie)).status,200);
  const updated=await request('GET','/api/service-requests',undefined,patientCookie);assert.equal(updated.body.requests.find(r=>r.id===created[5].id).status,'accepted');
});

test('only the platform admin provisions branch staff; branch roles stay scoped',async()=>{
  const manager=await request('POST','/api/admin/staff',{branchId,department:'manager',name:'مدير فرع تجريبي',email:'manager@example.test',phone:'01012345678'},adminCookie);
  assert.equal(manager.status,201);assert.ok(manager.body.account.temporaryPassword);
  const login=await request('POST','/api/login',{email:'manager@example.test',password:manager.body.account.temporaryPassword});assert.equal(login.status,200);let managerCookie=login.headers['Set-Cookie'].split(';')[0];
  assert.equal((await request('GET','/api/branch/dashboard',undefined,managerCookie)).status,428);
  const managerPassword=await request('POST','/api/password/change',{currentPassword:manager.body.account.temporaryPassword,newPassword:'ManagerNewStrongPass!2026'},managerCookie);assert.equal(managerPassword.status,200);managerCookie=managerPassword.headers['Set-Cookie'].split(';')[0];
  const roles=['reception','appointments','follow_up','laboratory','radiology','pharmacy','billing','medical_records','operations'];
  const staffPasswords={};for(const [i,department] of roles.entries()){const result=await request('POST','/api/admin/staff',{branchId,department,name:`موظف فرع ${i+1}`,email:`branch${i+1}@example.test`},adminCookie);assert.equal(result.status,201);assert.ok(result.body.account.temporaryPassword);staffPasswords[department]=result.body.account.temporaryPassword;}
  assert.equal((await request('POST','/api/branch/staff',{department:'reception',name:'موظف مكرر',email:'duplicate@example.test'},managerCookie)).status,403);
  assert.equal((await request('POST','/api/admin/staff',{branchId,department:'reception',name:'موظف مكرر',email:'duplicate@example.test'},adminCookie)).status,409);
  const roster=await request('GET','/api/branch/staff',undefined,managerCookie);assert.equal(roster.body.staff.length,10);assert.equal(roster.body.staff.find(s=>s.department==='manager').name,'مدير فرع تجريبي');
  const dashboard=await request('GET','/api/branch/dashboard',undefined,managerCookie);assert.equal(dashboard.body.branch.id,branchId);assert.equal(dashboard.body.counts.staff,9);
  assert.equal((await request('GET','/api/branch/appointments',undefined,managerCookie)).body.appointments.length,2);
  const patientUserId=db.prepare('SELECT user_id FROM patient_profiles WHERE id=?').get(patientId).user_id;
  const scopedList=await request('GET','/api/medical-admin/patients',undefined,managerCookie);assert.equal(scopedList.status,200);assert.ok(scopedList.body.patients.some(p=>p.userId===patientUserId));
  const patientFile=await request('GET',`/api/medical-admin/patients/${patientUserId}`,undefined,managerCookie);assert.equal(patientFile.status,200);assert.equal(patientFile.body.profile.name,'مريض تجريبي');
  const profileUpdate=await request('PATCH',`/api/medical-admin/patients/${patientUserId}/profile`,{nationalId:'29901011234567',address:'عنوان اختباري ١٠، المعادي',maritalStatus:'متزوج',email:'patient.updated@example.test',phone:'01011112222'},managerCookie);assert.equal(profileUpdate.status,200);assert.equal(profileUpdate.body.profile.nationalId,'29901011234567');assert.equal((await request('GET','/api/me',undefined,patientCookie)).body.user.email,'patient.updated@example.test');
  const staffRecord=await request('POST',`/api/medical-admin/patients/${patientUserId}/records`,{category:'visit',title:'ملاحظة استقبال',detail:'معلومة أضافها موظف الفرع'},managerCookie);assert.equal(staffRecord.status,201);assert.equal(staffRecord.body.record.status,'staff_entered_pending_clinician_review');
  assert.ok((await request('GET',`/api/medical-admin/patients/${patientUserId}`,undefined,adminCookie)).body.records.some(r=>r.id===staffRecord.body.record.id));
  const provisioned=await request('POST','/api/medical-admin/patients',{name:'مريض أنشأه الفرع',email:'frontdesk.patient@example.test',phone:'01098765432',healthConsent:true},managerCookie);assert.equal(provisioned.status,201);assert.ok(provisioned.body.account.temporaryPassword);assert.equal((await request('GET',`/api/medical-admin/patients/${provisioned.body.userId}`,undefined,managerCookie)).status,200);
  assert.equal((await request('GET','/api/medical-record',undefined,managerCookie)).status,403);
  const labRequest=await request('POST','/api/service-requests',{serviceType:'lab_booking',serviceName:'تحليل تجريبي',area:'المعادي',branchId},patientCookie);assert.equal(labRequest.status,201);
  assert.equal((await request('GET','/api/branch/service-requests',undefined,managerCookie)).body.requests.length,1);
  const otherBranch=await request('POST','/api/admin/branches',{name:'فرع نطاق آخر',area:'منطقة أخرى',address:'عنوان فرع اختباري آخر',phone:''},adminCookie);assert.equal(otherBranch.status,201);
  const otherManager=await request('POST','/api/admin/staff',{branchId:otherBranch.body.id,department:'manager',name:'مدير آخر',email:'other.manager@example.test'},adminCookie);assert.equal(otherManager.status,201);
  const otherLogin=await request('POST','/api/login',{email:'other.manager@example.test',password:otherManager.body.account.temporaryPassword});assert.equal(otherLogin.status,200);let otherCookie=otherLogin.headers['Set-Cookie'].split(';')[0];
  const otherPassword=await request('POST','/api/password/change',{currentPassword:otherManager.body.account.temporaryPassword,newPassword:'OtherManagerStrongPass!2026'},otherCookie);assert.equal(otherPassword.status,200);otherCookie=otherPassword.headers['Set-Cookie'].split(';')[0];
  assert.equal((await request('GET',`/api/medical-admin/patients/${provisioned.body.userId}`,undefined,otherCookie)).status,404);
  assert.equal((await request('GET','/api/branch/appointments',undefined,otherCookie)).body.appointments.length,0);
  assert.equal((await request('GET','/api/branch/service-requests',undefined,otherCookie)).body.requests.length,0);
  const labLogin=await request('POST','/api/login',{email:'branch4@example.test',password:staffPasswords.laboratory});assert.equal(labLogin.status,200);let labCookie=labLogin.headers['Set-Cookie'].split(';')[0];
  assert.equal((await request('GET','/api/branch/service-requests',undefined,labCookie)).status,428);
  const labPassword=await request('POST','/api/password/change',{currentPassword:staffPasswords.laboratory,newPassword:'LabNewStrongPass!2026'},labCookie);assert.equal(labPassword.status,200);labCookie=labPassword.headers['Set-Cookie'].split(';')[0];
  assert.equal((await request('GET','/api/branch/appointments',undefined,labCookie)).status,403);
  assert.equal((await request('GET','/api/branch/service-requests',undefined,labCookie)).status,200);
});
