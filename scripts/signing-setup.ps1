# One time only: makes Kestryl's code-signing certificate, protected by a password you choose,
# optionally trusts it on this PC, then signs Kestryl.exe.
#   powershell -ExecutionPolicy Bypass -File scripts\signing-setup.ps1      (as administrator to trust it)
#
# Where things end up (outside the project, never in git):
#   Documents\Kestryl signing\kestryl-signing.pfx  certificate + private key, encrypted with your password
#   Documents\Kestryl signing\kestryl-signing.cer  public certificate only (safe to share)
# The private key is removed from Windows' certificate store right after the export, so the
# password-protected .pfx is its only copy. Keep a backup of it: a lost .pfx or password means a
# new certificate, and PCs that trusted the old one must trust the new one.
param(
  [string]$Dir = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Kestryl signing')
)
$ErrorActionPreference = 'Stop'
$pfx = Join-Path $Dir 'kestryl-signing.pfx'
$cer = Join-Path $Dir 'kestryl-signing.cer'
if (Test-Path -LiteralPath $pfx) { throw "$pfx already exists. Sign with scripts\sign.ps1, or move that file away to make a new certificate." }

function Plain([securestring]$s) {
  $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

Write-Host 'Kestryl code-signing certificate' -ForegroundColor Cyan
Write-Host "It will be saved, encrypted with your password, to:`n  $pfx`n"
Write-Host 'Choose a password (at least 12 characters). Nobody can sign as Kestryl without it, you included.'
while ($true) {
  $p1 = Read-Host 'Password' -AsSecureString
  $p2 = Read-Host 'Same password again' -AsSecureString
  $a = Plain $p1; $b = Plain $p2
  $same = $a -ceq $b; $long = $a.Length -ge 12
  $a = $null; $b = $null
  if (-not $same) { Write-Host 'The two passwords are not the same. Try again.' -ForegroundColor Yellow; continue }
  if (-not $long) { Write-Host 'Use at least 12 characters. Try again.' -ForegroundColor Yellow; continue }
  break
}

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Kestryl' -FriendlyName 'Kestryl code signing' `
  -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy Exportable `
  -NotAfter (Get-Date).AddYears(5) -CertStoreLocation 'Cert:\CurrentUser\My'
try {
  Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $p1 -CryptoAlgorithmOption AES256_SHA256 | Out-Null
  Export-Certificate -Cert $cert -FilePath $cer -Type CERT | Out-Null
} finally {
  Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $cert.Thumbprint) -DeleteKey
}
Write-Host "`nCertificate made: CN=Kestryl, valid until $($cert.NotAfter.ToString('d MMM yyyy')), thumbprint $($cert.Thumbprint)" -ForegroundColor Green

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "`nTrust it on this PC? Then Windows shows 'Kestryl' as a verified publisher (for example in the"
Write-Host 'administrator prompt) instead of "Unknown publisher". Only files signed with your .pfx get that trust.'
if ($admin) {
  $ans = Read-Host 'Trust the Kestryl certificate on this PC? (y/N)'
  if ($ans -match '^(y|yes)$') {
    Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
    Write-Host 'Trusted on this PC.' -ForegroundColor Green
  }
} else {
  Write-Host 'Skipped: needs administrator rights. Run this from an administrator PowerShell to trust it:' -ForegroundColor Yellow
  Write-Host "  Import-Certificate -FilePath '$cer' -CertStoreLocation Cert:\LocalMachine\Root"
  Write-Host "  Import-Certificate -FilePath '$cer' -CertStoreLocation Cert:\LocalMachine\TrustedPublisher"
}

Write-Host "`nSigning Kestryl.exe..."
& (Join-Path $PSScriptRoot 'sign.ps1') -Pfx $pfx -Password $p1
