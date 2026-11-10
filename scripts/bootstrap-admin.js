'use strict';
const crypto=require('node:crypto');
const {promisify}=require('node:util');
const {db,encrypt,emailLookup,uuid}=require('../server');
(async()=>{
  const email=String(process.env.CLINIC_ADMIN_EMAIL||'').trim().toLowerCase();
  const password=String(process.env.CLINIC_ADMIN_PASSWORD||'');
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<16||password.length>128)throw new Error('أدخل بريدًا صحيحًا وكلمة مرور من ١٦ إلى ١٢٨ حرفًا باستخدام create-admin.ps1.');
  if(db.prepare("SELECT 1 FROM users WHERE role='admin' LIMIT 1").get())throw new Error('يوجد حساب إدارة بالفعل.');
  const salt=crypto.randomBytes(16),hash=await promisify(crypto.pbkdf2)(password,salt,310000,32,'sha256');
  db.prepare("INSERT INTO users(id,email_lookup,email_cipher,phone_cipher,password_salt,password_hash,role,created_at) VALUES(?,?,?,?,?,?,'admin',?)").run(uuid(),emailLookup(email),encrypt({email}),encrypt({phone:''}),salt,hash,new Date().toISOString());
  console.log('تم إنشاء حساب الإدارة. احفظ بيانات الدخول في مخزن آمن.');
})().catch(error=>{console.error(error.message);process.exitCode=1;});
