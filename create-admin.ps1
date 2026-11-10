$ErrorActionPreference = 'Stop'
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node.js 24 أو أحدث مطلوب.' }
$dataDir = Join-Path $env:LOCALAPPDATA 'TabbyClinicData'
$keyPath = Join-Path $dataDir 'clinic-data-key.dpapi'
$databasePath = Join-Path $dataDir 'clinic.sqlite'
if (-not (Test-Path -LiteralPath $keyPath) -or -not (Test-Path -LiteralPath $databasePath)) { throw 'شغّل run-local.ps1 مرة واحدة أولًا لإنشاء مفتاح وقاعدة البيانات.' }
$email = (Read-Host 'بريد حساب الإدارة').Trim()
$passwordSecure = Read-Host 'كلمة مرور الإدارة (١٦ حرفًا على الأقل)' -AsSecureString
$password = [System.Net.NetworkCredential]::new('', $passwordSecure).Password
try {
    $secureKey = ConvertTo-SecureString -String (Get-Content -Raw -LiteralPath $keyPath)
    $env:CLINIC_DATA_KEY = [System.Net.NetworkCredential]::new('', $secureKey).Password
    $env:CLINIC_DB_PATH = $databasePath
    $env:CLINIC_ADMIN_EMAIL = $email
    $env:CLINIC_ADMIN_PASSWORD = $password
    Push-Location $PSScriptRoot
    try { node scripts/bootstrap-admin.js; if ($LASTEXITCODE -ne 0) { throw 'تعذر إنشاء حساب الإدارة.' } }
    finally { Pop-Location }
} finally {
    Remove-Item Env:CLINIC_DATA_KEY,Env:CLINIC_DB_PATH,Env:CLINIC_ADMIN_EMAIL,Env:CLINIC_ADMIN_PASSWORD -ErrorAction SilentlyContinue
    $password=$null;$passwordSecure=$null;$secureKey=$null
}
