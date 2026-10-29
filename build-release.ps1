# build-release.ps1 - signed release APK for GuardPulse.
#
# Safe to commit: no secrets live here. The keystore sits OUTSIDE the repo and
# both passwords are prompted on every run.
#
# One-time setup (creates the GuardPulse release key - back it up, losing it
# means installed copies can never be updated):
#   .\build-release.ps1 -NewKey
#
# Every release:
#   .\build-release.ps1              # build at pyproject's version
#   .\build-release.ps1 -Clean       # wipe build\ + stale Gradle first
#   .\build-release.ps1 -Version 0.4.0

param(
    [string]$Version,       # defaults to the version in pyproject.toml
    [int]$BuildNumber,      # defaults to auto-increment (.build-number, gitignored)
    [switch]$Clean,
    [switch]$NewKey         # create the release keystore, then stop
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# -- Signing config ------------------------------------------------------------
$KeyStore = Join-Path $env:USERPROFILE "Keystores\guardpulse-release.jks"
$KeyAlias = "guardpulse"
# -------------------------------------------------------------------------------

$jdk = Get-ChildItem "C:\Program Files\Java\jdk-*" -Directory -ErrorAction SilentlyContinue |
       Sort-Object Name | Select-Object -Last 1
if ($jdk) { $env:JAVA_HOME = $jdk.FullName }

if ($NewKey) {
    if (Test-Path $KeyStore) { throw "A keystore already exists at '$KeyStore' - refusing to overwrite it." }
    New-Item -ItemType Directory -Force (Split-Path $KeyStore) | Out-Null
    $keytool = if ($jdk) { Join-Path $jdk.FullName "bin\keytool.exe" } else { "keytool" }
    Write-Host "Creating $KeyStore - keytool will ask for a password and your name." -ForegroundColor Cyan
    & $keytool -genkeypair -v -keystore $KeyStore -storetype PKCS12 -keyalg RSA -keysize 4096 `
        -validity 10000 -alias $KeyAlias
    if ($LASTEXITCODE -ne 0) { throw "keytool failed (exit $LASTEXITCODE)" }
    Write-Host "`nDone. BACK UP '$KeyStore' and its password somewhere safe (password manager + offline copy)." -ForegroundColor Green
    return
}

if (-not (Test-Path $KeyStore)) {
    throw "Keystore not found at '$KeyStore' - run .\build-release.ps1 -NewKey first."
}

if (-not $Version) {
    $m = Select-String -Path ".\pyproject.toml" -Pattern '^\s*version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($m) { $Version = $m.Matches[0].Groups[1].Value }
    else { throw "Couldn't read version from pyproject.toml - pass -Version x.y.z" }
}

# versionCode must INCREASE for Android to accept an update.
$counterFile = Join-Path $PSScriptRoot ".build-number"
if ($PSBoundParameters.ContainsKey('BuildNumber')) {
    $buildNo = $BuildNumber
} else {
    $prev = 1  # the debug test builds all used versionCode 1
    if (Test-Path $counterFile) { $prev = [int]((Get-Content $counterFile -Raw).Trim()) }
    $buildNo = $prev + 1
}

if ($Clean) {
    Write-Host "Clearing stale Gradle/Java daemons and build\ ..." -ForegroundColor Yellow
    taskkill /F /IM java.exe 2>$null | Out-Null
    if (Test-Path ".\build") { Remove-Item -Recurse -Force ".\build" }
}

# PKCS12 keystores use one password for the store and the key.
$Pass = [System.Net.NetworkCredential]::new("", (Read-Host "Keystore password" -AsSecureString)).Password
if (-not $Pass) { throw "Keystore password is required." }

Write-Host "Building signed APK  v$Version  (versionCode $buildNo) ..." -ForegroundColor Cyan
& ".\.venv\Scripts\flet.exe" build apk --yes `
    --android-signing-key-store $KeyStore `
    --android-signing-key-store-password $Pass `
    --android-signing-key-alias $KeyAlias `
    --android-signing-key-password $Pass `
    --build-version $Version --build-number $buildNo
$Pass = $null
if ($LASTEXITCODE -ne 0) { throw "flet build failed (exit $LASTEXITCODE)" }
Set-Content -Path $counterFile -Value "$buildNo" -NoNewline  # only count successful builds

$apk = ".\build\apk\guardpulse.apk"
$named = ".\build\apk\GuardPulse-$Version.apk"
Copy-Item $apk $named -Force
Write-Host "`nBuilt: $named" -ForegroundColor Green

# Verify the signer: want your own name, NOT 'CN=Android Debug'.
$apksigner = Get-ChildItem @("$env:LOCALAPPDATA\Android\Sdk\build-tools\*\apksigner.bat",
                             "$env:USERPROFILE\Android\build-tools\*\apksigner.bat") `
             -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
if ($apksigner) {
    $out = & $apksigner.FullName verify --print-certs $named 2>&1
    $out | Select-String "certificate DN|certificate SHA-256" | ForEach-Object { $_.Line.Trim() }
    if ($out | Select-String "CN=Android Debug") {
        Write-Host "WARNING: signed with the DEBUG key - do NOT release this APK." -ForegroundColor Red
    }
} else {
    Write-Host "apksigner not found - skipped the signer check." -ForegroundColor DarkYellow
}
