<#
.SYNOPSIS
Installs bordercheck on Windows and sets it up to report to your organisation
every hour (a per-user scheduled task; no administrator rights).

.DESCRIPTION
Uses OpenSSL with Ed25519 support, when available, to verify the signed
checksum manifest before executing the downloaded binary. Otherwise an
install warns and uses the downloaded binary to check its own signature.
Dry runs never execute the binary and warn when only the checksum was checked.

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

# SubjectPublicKeyInfo prefix for a raw 32-byte Ed25519 public key.
function Test-ReleaseSignature([string]$OpenSSL, [string]$Message, [byte[]]$PublicKey, [byte[]]$Signature) {
    if ($PublicKey.Length -ne 32 -or $Signature.Length -ne 64) { return $false }
    $derPath = Join-Path $tmp 'key.der'
    $sigPath = Join-Path $tmp 'sig.bin'
    [byte[]]$der = @(0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00) + $PublicKey
    [IO.File]::WriteAllBytes($derPath, $der)
    [IO.File]::WriteAllBytes($sigPath, $Signature)
    # Windows PowerShell can turn native stderr into an error record.
    $ErrorActionPreference = 'Continue'
    & $OpenSSL pkeyutl -verify -pubin -inkey $derPath -keyform DER -rawin -in $Message -sigfile $sigPath 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
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

    $sigChecked = $false
    $openssl = Get-Command openssl.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($openssl) {
        # RFC 8032 test vector 2. A failed release signature must never trigger fallback.
        $probe = Join-Path $tmp 'probe.msg'
        [IO.File]::WriteAllBytes($probe, [byte[]]@(0x72))
        $probeKey = [Convert]::FromBase64String('PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=')
        $probeSig = [Convert]::FromBase64String('kqAJqfDUyrhyDoILX2QlQKKye1QWUD+Ps3YiI+vbadoIWsHkPhWZbkWPNhPQ8R2MOHsurrQwKu6wDSkWErsMAA==')
        if (Test-ReleaseSignature $openssl.Source $probe $probeKey $probeSig) {
            try {
                $keyBytes = [Convert]::FromBase64String($Key)
                $signature = [Convert]::FromBase64String([IO.File]::ReadAllText($sig))
            } catch { Fail 'The release key or signature is not base64.' }
            if (-not (Test-ReleaseSignature $openssl.Source $sums $keyBytes $signature)) {
                Fail 'OpenSSL could not verify SHA256SUMS with the trusted release key.'
            }
            $sigChecked = $true
            Say 'SHA256SUMS is signed by the release key (checked with OpenSSL).'
        }
    }

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

    $installArgs = @('install', $PolicyUrl)
    if ($Email) { $installArgs += @('-email', $Email) }
    if ($Invite) {
        if ($RepoSet) { $installArgs += @('-update-repo', $Repo) }
        if ($KeySet) { $installArgs += @('-update-key', $Key) }
    }
    if ($DryRun) {
        if (-not $sigChecked) { Write-Warning 'No capable OpenSSL; only the checksum was checked. The release signature was not verified.' }
        Say "Dry run ($tag): would now run: bordercheck $($installArgs -join ' ')"
        return
    }
    if (-not $sigChecked) {
        Write-Warning 'No capable OpenSSL; running the downloaded binary to check its own release signature. This is not independent verification.'
        & $exe verify -key $Key $sums $sig $exe | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'SHA256SUMS is NOT signed by the bordercheck release key.' }
    }
    if (-not ((& $exe -version) -match [regex]::Escape($tag))) { Fail "$asset does not report version $tag." }

    # Run from the console, so bordercheck can ask for the work email itself (not with an invite link).
    & $exe @installArgs
    if ($LASTEXITCODE -ne 0) { throw "bordercheck-install: bordercheck install failed (exit $LASTEXITCODE)." }
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
