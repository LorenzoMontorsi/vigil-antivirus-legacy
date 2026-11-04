<#
.SYNOPSIS
  Firma i driver vigilflt.sys (x86 e x64) con un certificato di test autofirmato ed esporta
  il certificato pubblico. Serve soprattutto al driver a 64 bit: Windows x64 carica solo driver
  firmati, e con un certificato di test il sistema va messo in "test-signing".

.NOTES
  Firma SHA-1 (le versioni legacy di Windows non capiscono i cataloghi SHA-256).
  Il certificato è di PROVA: non è un'autorità riconosciuta, va importato a mano dall'utente.
  Non committare il .pfx/chiave; nel repo non finisce nulla di segreto.
#>
param(
    [string]$Name = 'Vigil Legacy Test Certificate',
    [string]$Store = 'VigilLegacyTestStore'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$drvDir = Join-Path $root 'dist\driver'

$makecert = 'C:\WinDDK\7600.16385.win7_wdk.100208-1538\bin\x86\MakeCert.exe'
$signtool = (Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1).FullName
if (-not (Test-Path $makecert)) { throw "MakeCert non trovato: $makecert" }
if (-not $signtool) { throw 'signtool.exe (x64) non trovato nel Windows Kit 10' }

$cer = Join-Path $drvDir 'VigilLegacyTest.cer'
New-Item -ItemType Directory -Force $drvDir | Out-Null

# Rimuove eventuali certificati di prova precedenti con lo stesso nome (evita doppioni nello store).
Get-ChildItem "Cert:\CurrentUser\$Store" -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq "CN=$Name" } | Remove-Item -Force -ErrorAction SilentlyContinue

# Crea un certificato di test per la firma del codice, nello store dell'utente.
& $makecert -r -pe -n "CN=$Name" -eku 1.3.6.1.5.5.7.3.3 -ss $Store -sr currentUser -a sha1 $cer
if ($LASTEXITCODE) { throw 'makecert non riuscito' }
$thumb = (Get-ChildItem "Cert:\CurrentUser\$Store" | Where-Object { $_.Subject -eq "CN=$Name" } | Select-Object -First 1).Thumbprint
Write-Host "Certificato di test ($thumb) esportato: $cer"

foreach ($arch in 'x86', 'x64') {
    $sys = Join-Path $drvDir "$arch\vigilflt.sys"
    if (-not (Test-Path $sys)) { Write-Warning "${arch}: vigilflt.sys assente (compilalo con build-driver.ps1 -Arch $arch)"; continue }
    & $signtool sign /v /s $Store /sha1 $thumb /fd sha1 $sys
    if ($LASTEXITCODE) { throw "firma del driver $arch non riuscita" }
    Copy-Item $cer (Split-Path $sys) -Force
}
Write-Host 'Fatto. Il certificato e il driver firmato vanno distribuiti insieme (solo per i 64 bit).'
