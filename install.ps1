<#
.SYNOPSIS
Installs bordercheck on Windows and sets it up to report to your organisation
every hour (a per-user scheduled task; no administrator rights).

.DESCRIPTION
Downloads the latest release for this PC, checks it against SHA256SUMS before
running it, has the binary check the ed25519 signature on SHA256SUMS with the
key pinned below, then runs `bordercheck install <policies URL or invite link>`. Any mismatch
stops the install. Windows PowerShell 5.1 has no ed25519, so unlike install.sh
with OpenSSL 3 the signature is always checked by the downloaded binary; see
docs/install.md, "What the install script proves".

.EXAMPLE
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.ps1))) https://bordercheck.acme.com/policies.json

.EXAMPLE
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.ps1))) https://bordercheck.acme.com/policies.json -Email an@acme.com

.EXAMPLE
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.ps1))) https://bordercheck.acme.com/i/<code>
#>
param(
    # The policies URL, or an invite link https://<host>/i/<code> from IT.
    [Parameter(Position = 0)][string]$PolicyUrl = $env:BORDERCHECK_POLICY_URL,
    [string]$Email,                  # don't ask for the work email (scripted rollouts; not with an invite link)
    [string]$Version,                # install this release (vX.Y.Z) instead of the latest
    # With an invite link, the installed copy also takes its updates from -Repo and -Key when given.
    [string]$Repo = $(if ($env:BORDERCHECK_REPO) { $env:BORDERCHECK_REPO } else { 'ptrinh/bordercheck' }),
    [string]$Key,                    # ed25519 public key (base64) that must sign SHA256SUMS; forks set it
    [switch]$DryRun                  # download and verify, then stop before installing
)
# Whether the update source was named (option or environment), before defaults fill it in.
$RepoSet = $PSBoundParameters.ContainsKey('Repo') -or [bool]$env:BORDERCHECK_REPO
$KeySet = [bool]$Key -or [bool]$env:BORDERCHECK_PUBLIC_KEY

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # Invoke-WebRequest is very slow with the progress bar

# Keep equal to OfficialKey in internal/update/update.go (a test checks).
$OfficialKey = 'Q5Mw8yJQUgKSEtPNBVNnEP7HiSvhwT2y9Te4mEPOlcs='

function Say([string]$msg) { Write-Host "bordercheck-install: $msg" }
# Throw rather than exit: run as a script block, exit would close the user's window.
function Fail([string]$msg) { throw "bordercheck-install: $msg Nothing was installed." }

if (-not $Key) { $Key = if ($env:BORDERCHECK_PUBLIC_KEY) { $env:BORDERCHECK_PUBLIC_KEY } else { $OfficialKey } }
$GitHub = if ($env:BORDERCHECK_GITHUB) { $env:BORDERCHECK_GITHUB } else { 'https://github.com' }

if (-not $PolicyUrl) { Fail "Give your invite link or your organisation's policies URL, e.g. https://bordercheck.acme.com/policies.json." }
if (-not $PolicyUrl.StartsWith('https://')) { Fail 'The URL must start with https://.' }
# An invite link: keep in step with ParseInvite in internal/agent/enroll.go.
$Invite = $PolicyUrl -cmatch '^https://[^/?#@]+/i/[A-Za-z0-9._~-]+/?$'
if ($Invite -and $Email) { Fail '-Email cannot be used with an invite link: IT set your email when they created the invite.' }
if ($Repo -notmatch '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$') { Fail '-Repo must be owner/name.' }
if ($Version -and $Version -notmatch '^v\d+\.\d+\.\d+(-[A-Za-z0-9.]+)?$') { Fail '-Version must look like v1.2.3.' }

# Windows PowerShell 5.1 may not offer TLS 1.2 by default.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# The OS architecture, not this process's: x64 PowerShell on an Arm PC is emulated.
$arch = $null
try { $arch = [string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture } catch { }
if (-not $arch) { $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE } }
switch -Regex ($arch) {
    '^(X64|AMD64)$' { $arch = 'amd64'; break }
    '^(Arm64|ARM64)$' { $arch = 'arm64'; break }
    default { Fail "There is no bordercheck build for $arch." }
}

function Fetch([string]$url, [string]$file) {
    if ($GitHub.StartsWith('https://') -and -not $url.StartsWith('https://')) { Fail "Refusing to download over plain HTTP: $url" }
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $file
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('bordercheck-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $releases = "$GitHub/$Repo/releases"
    # releases/latest/download is GitHub's CDN, not the rate-limited API, as the updater uses.
    $sumsBase = if ($Version) { "$releases/download/$Version" } else { "$releases/latest/download" }
    $sums = Join-Path $tmp 'SHA256SUMS'
    $sig = Join-Path $tmp 'SHA256SUMS.sig'
    Say "bordercheck - (c) Phil Trinh - SENPRINTS"
    Say "Fetching the release list for windows/$arch from github.com/$Repo ..."
    try { Fetch "$sumsBase/SHA256SUMS" $sums } catch { Fail "Could not download SHA256SUMS from $sumsBase ($($_.Exception.Message))." }
    try { Fetch "$sumsBase/SHA256SUMS.sig" $sig } catch { Fail 'The release has no SHA256SUMS.sig, so it cannot be verified.' }

    $pattern = '^([0-9a-fA-F]{64}) [ *]?(bordercheck-(v\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)-windows-' + $arch + '\.exe)$'
    $match = Get-Content -LiteralPath $sums | ForEach-Object { if ($_.TrimEnd() -match $pattern) { $Matches } } | Select-Object -First 1
    if (-not $match) { Fail "The release has no binary for windows/$arch." }
    $want, $asset, $tag = $match[1].ToLower(), $match[2], $match[3]
    if ($Version -and $tag -ne $Version) { Fail "SHA256SUMS of $Version lists $asset." }

    $exe = Join-Path $tmp $asset
    Say "Downloading $asset ..."
    try { Fetch "$releases/download/$tag/$asset" $exe } catch { Fail "Could not download $asset ($($_.Exception.Message))." }

    # The checksum, before the binary runs.
    $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLower()
    if ($got -ne $want) { Fail "$asset does NOT match SHA256SUMS (expected $want, got $got). Do not install it; tell your IT team." }
    Say "$asset matches SHA256SUMS."

    # The signature, checked by the binary with the key this script pins.
    & $exe verify -key $Key $sums $sig $exe | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'SHA256SUMS is NOT signed by the bordercheck release key. Do not install this release; tell your IT team.' }
    Say 'SHA256SUMS is signed by the release key (checked by the downloaded binary).'
    if (-not ((& $exe -version) -match [regex]::Escape($tag))) { Fail "$asset does not report version $tag." }

    $installArgs = @('install', $PolicyUrl)
    if ($Email) { $installArgs += @('-email', $Email) }
    if ($Invite) {
        if ($RepoSet) { $installArgs += @('-update-repo', $Repo) }
        if ($KeySet) { $installArgs += @('-update-key', $Key) }
    }
    if ($DryRun) {
        Say "Verified $tag. Dry run: would now run: bordercheck $($installArgs -join ' ')"
        return
    }
    # Run from the console, so bordercheck can ask for the work email itself (not with an invite link).
    & $exe @installArgs
    if ($LASTEXITCODE -ne 0) { throw "bordercheck-install: bordercheck install failed (exit $LASTEXITCODE)." }
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
