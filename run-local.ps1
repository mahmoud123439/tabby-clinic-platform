$ErrorActionPreference = 'Stop'

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'Node.js 24 أو أحدث مطلوب. ثبّت Node.js ثم أعد المحاولة.'
}
if ([int](node -p "process.versions.node.split('.')[0]") -lt 24) {
    throw 'هذا المشروع يحتاج Node.js 24 أو أحدث.'
}

$dataDir = Join-Path $env:LOCALAPPDATA 'TabbyClinicData'
$keyPath = Join-Path $dataDir 'clinic-data-key.dpapi'
$databasePath = Join-Path $dataDir 'clinic.sqlite'
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

if (-not (Test-Path -LiteralPath $keyPath)) {
    if (Test-Path -LiteralPath $databasePath) {
        throw 'قاعدة بيانات موجودة دون مفتاح DPAPI المحفوظ. لن أُنشئ مفتاحًا جديدًا كي لا أفقد الوصول إلى البيانات القديمة. أعد CLINIC_DATA_KEY الأصلي في الجلسة أو استرجع المفتاح من مخزن الأسرار.'
    }
    $keyText = (node -p "require('node:crypto').randomBytes(32).toString('base64')").Trim()
    if ($LASTEXITCODE -ne 0 -or $keyText.Length -ne 44) { throw 'تعذر إنشاء مفتاح التشفير.' }
    $secureKey = ConvertTo-SecureString -String $keyText -AsPlainText -Force
    ConvertFrom-SecureString -SecureString $secureKey | Set-Content -LiteralPath $keyPath -NoNewline
}

try {
    $protectedKey = Get-Content -Raw -LiteralPath $keyPath
    $secureKey = ConvertTo-SecureString -String $protectedKey
    $env:CLINIC_DATA_KEY = [System.Net.NetworkCredential]::new('', $secureKey).Password
} catch {
    throw 'تعذر فك حماية مفتاح البيانات. افتح المشروع من حساب Windows نفسه الذي أنشأ المفتاح.'
}

$env:CLINIC_DB_PATH = $databasePath
$env:HOST = '127.0.0.1'
$env:PORT = '3000'
Push-Location $PSScriptRoot
try {
    Write-Host 'الخادم يعمل على http://127.0.0.1:3000. اترك هذه النافذة مفتوحة.' -ForegroundColor Cyan
    npm start
} finally {
    Remove-Item Env:CLINIC_DATA_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:CLINIC_DB_PATH -ErrorAction SilentlyContinue
    Remove-Item Env:HOST -ErrorAction SilentlyContinue
    Remove-Item Env:PORT -ErrorAction SilentlyContinue
    Pop-Location
}
