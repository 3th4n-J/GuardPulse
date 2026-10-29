# create-release.ps1 - publish a signed APK as a GitHub release.
#
# The in-app updater installs the newest release's GuardPulse-<version>.apk,
# but ONLY if it is signed with the GuardPulse release key - so this script
# refuses anything else. Run .\build-release.ps1 first.
#
#   .\create-release.ps1                    # notes from commits since the last tag
#   .\create-release.ps1 -NotesFile notes.md
#   .\create-release.ps1 -Draft             # check it on GitHub before publishing

param(
    [string]$Version,
    [string]$NotesFile,
    [switch]$Draft
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# SHA-256 of the GuardPulse release certificate (CN=Ethan Johnston, OU=GuardPulse)
$ReleaseSigner = "6aba3b6c14d4f19c9373ec672320ce6724499a94e34a7ad489d1b3f08b0e6db8"

if (-not $Version) {
    $m = Select-String -Path ".\pyproject.toml" -Pattern '^\s*version\s*=\s*"([^"]+)"' | Select-Object -First 1
    $Version = $m.Matches[0].Groups[1].Value
}
$tag = "v$Version"
$apk = ".\build\apk\GuardPulse-$Version.apk"
if (-not (Test-Path $apk)) { throw "Missing $apk - run .\build-release.ps1 first." }

# 1. Signed with the release key? (anything else would force users to uninstall = data loss)
$jdk = Get-ChildItem "C:\Program Files\Java\jdk-*" -Directory -ErrorAction SilentlyContinue |
       Sort-Object Name | Select-Object -Last 1
if ($jdk) { $env:JAVA_HOME = $jdk.FullName }
$apksigner = Get-ChildItem @("$env:LOCALAPPDATA\Android\Sdk\build-tools\*\apksigner.bat",
                             "$env:USERPROFILE\Android\build-tools\*\apksigner.bat") `
             -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
if (-not $apksigner) { throw "apksigner not found - can't confirm the signature." }
$certs = & $apksigner.FullName verify --print-certs $apk 2>&1 | Out-String
if ($certs -notmatch "certificate SHA-256 digest: $ReleaseSigner") {
    throw "$apk is NOT signed with the GuardPulse release key. Refusing to publish."
}
Write-Host "Signature OK (GuardPulse release key)." -ForegroundColor Green

# 2. Code committed and pushed, tag not used yet
if (git status --porcelain) { throw "Uncommitted changes - commit and push before releasing." }
git fetch --tags --quiet
if (git tag --list $tag) { throw "Tag $tag already exists - bump the version in pyproject.toml." }

# 3. Checksum file next to the APK
$hash = (Get-FileHash $apk -Algorithm SHA256).Hash.ToLower()
$sumFile = "$apk.sha256"
Set-Content -Path $sumFile -Value "$hash  GuardPulse-$Version.apk" -NoNewline

# 4. Tag + release
git tag -a $tag -m "GuardPulse $Version"
git -c credential.helper= -c "credential.helper=!gh auth git-credential" push origin $tag
$ghArgs = @("release", "create", $tag, $apk, $sumFile, "--title", "GuardPulse $Version")
if ($NotesFile) { $ghArgs += @("--notes-file", $NotesFile) } else { $ghArgs += "--generate-notes" }
if ($Draft) { $ghArgs += "--draft" }
gh @ghArgs
if ($LASTEXITCODE -ne 0) { throw "gh release create failed (exit $LASTEXITCODE)" }
Write-Host "Released $tag - phones will see it at their next daily check (or About > Check for updates)." -ForegroundColor Green
