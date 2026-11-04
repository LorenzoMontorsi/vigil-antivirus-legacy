<#
.SYNOPSIS
  Scarica ClamAV per Windows "legacy" (port di Gianluigi Tiesi / ClamWin, gira da Windows NT4/XP)
  e lo estrae in third_party\clamav, da dove la build dell'app lo copia accanto a Vigil.exe.
.DESCRIPTION
  Versione fissata e SHA-256 verificato: il sito non pubblica checksum, quindi l'hash qui
  sotto è quello del pacchetto scaricato e controllato quando la versione è stata adottata.
  Per aggiornare: cambiare $Version e $Sha256 insieme, dopo aver verificato il nuovo pacchetto.
  Sorgenti del port: https://github.com/clamwin/clamav-win32 (GPL-2.0).
#>
param([string]$Dest = (Join-Path $PSScriptRoot '..\third_party\clamav'))
$ErrorActionPreference = 'Stop'

$Version = '1.5.2'
$Sha256 = '669a0cce7ad10ebc9c1e91f5151b426a49a7a777c8d2af2cbc58076a39bbedeb'
$Url = "https://oss.netfarm.it/clamav/files/clamav-$Version-legacy-x86.7z"

$tmp = Join-Path $env:TEMP "vigil-legacy-clamav-$Version"
New-Item -ItemType Directory -Force $tmp | Out-Null
$archive = Join-Path $tmp "clamav-$Version-legacy-x86.7z"
if (-not (Test-Path $archive)) {
    Write-Host "Download di $Url"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing $Url -OutFile $archive
}
$actual = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $Sha256) {
    Remove-Item $archive
    throw "SHA-256 non corrispondente: atteso $Sha256, ottenuto $actual"
}

# Il tar di Windows 10/11 (libarchive) legge anche i .7z; in alternativa 7-Zip.
$out = Join-Path $tmp 'x'
Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out | Out-Null
$seven = @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($seven) { & $seven x -y "-o$out" $archive | Out-Null } else { & "$env:SystemRoot\System32\tar.exe" -xf $archive -C $out }
if ($LASTEXITCODE -ne 0) { throw "estrazione non riuscita" }

$src = Join-Path $out "clamav-$Version-legacy-x86"
Remove-Item -Recurse -Force $Dest -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Dest | Out-Null
# Solo ciò che serve a Vigil: demone, aggiornamento, librerie, certificati e licenze.
$keep = 'clamd.exe', 'freshclam.exe', 'clamscan.exe', 'sigtool.exe', 'libclamav.dll', 'libclamunrar.dll', 'libclamunrar_iface.dll', 'libfreshclam.dll', 'curl-ca-bundle.crt', 'README.md'
foreach ($f in $keep) { Copy-Item (Join-Path $src $f) $Dest }
Copy-Item -Recurse (Join-Path $src 'certs') $Dest
Copy-Item -Recurse (Join-Path $src 'copyright') $Dest
Set-Content -Encoding ascii (Join-Path $Dest 'VERSION') $Version
Write-Host "ClamAV $Version legacy pronto in $((Resolve-Path $Dest).Path)"
