# Signs Kestryl.exe with the Kestryl code-signing certificate (made once by signing-setup.ps1).
# Asks for the certificate's password; the private key is only loaded for this run and is
# never left in Windows' certificate store. Run it after every release build:
#   powershell -ExecutionPolicy Bypass -File scripts\sign.ps1
param(
  [string]$Exe = (Join-Path $PSScriptRoot '..\src-tauri\target\release\Kestryl.exe'),
  [string]$Pfx = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Kestryl signing\kestryl-signing.pfx'),
  [securestring]$Password
)
$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path -LiteralPath $Exe).Path
if (-not (Test-Path -LiteralPath $Pfx)) { throw "No signing certificate at $Pfx. Run scripts\signing-setup.ps1 once first." }
if (-not $Password) { $Password = Read-Host "Password of $Pfx" -AsSecureString }

# Without PersistKeySet the key goes into a temporary container that Reset() deletes.
try {
  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Pfx, $Password)
} catch {
  throw 'Wrong password, or the .pfx file is damaged.'
}
try {
  if (-not $cert.HasPrivateKey) { throw 'The .pfx file has no private key.' }
  # A timestamp keeps the signature valid after the certificate expires.
  $sig = $null
  foreach ($ts in 'http://timestamp.digicert.com', 'http://timestamp.sectigo.com', 'http://timestamp.globalsign.com/tsa/r6advanced1') {
    try {
      $sig = Set-AuthenticodeSignature -LiteralPath $Exe -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $ts -ErrorAction Stop
      if ($sig.SignerCertificate -and $sig.TimeStamperCertificate) { break }
    } catch { Write-Warning "Timestamp server $ts did not answer: $($_.Exception.Message)" }
    $sig = $null
  }
  if (-not $sig) {
    Write-Warning 'No timestamp server answered: signing without a timestamp (the signature stops being valid when the certificate expires).'
    $sig = Set-AuthenticodeSignature -LiteralPath $Exe -Certificate $cert -HashAlgorithm SHA256 -ErrorAction Stop
  }
} finally {
  if ($cert) { $cert.Reset() }
}

$v = Get-AuthenticodeSignature -LiteralPath $Exe
if (-not $v.SignerCertificate -or $v.SignerCertificate.Thumbprint -ne $sig.SignerCertificate.Thumbprint) { throw "Signing failed: $($v.StatusMessage)" }
Write-Host ''
Write-Host "Signed: $Exe" -ForegroundColor Green
Write-Host "  Publisher:  $($v.SignerCertificate.Subject)"
Write-Host "  Thumbprint: $($v.SignerCertificate.Thumbprint)"
Write-Host "  Timestamp:  $(if ($v.TimeStamperCertificate) { $v.TimeStamperCertificate.Subject } else { 'none' })"
if ($v.Status -eq 'Valid') {
  Write-Host '  Windows trusts this signature on this PC.' -ForegroundColor Green
} else {
  Write-Host "  Windows says: $($v.StatusMessage)" -ForegroundColor Yellow
  Write-Host '  The file is signed, but this PC does not trust the Kestryl certificate yet (signing-setup.ps1 can add it).'
}
