<#
.SYNOPSIS
  Compila il minifilter vigilflt.sys con il WDK 7.1.0, a 32 bit (per XP/7 x86) o a 64 bit
  (per XP x64 / 7 x64). Il WDK 7.1 è l'ultimo che targettizza Windows XP; i WDK moderni no.

.PARAMETER Arch
  x86 (predefinito) oppure x64.

.NOTES
  Richiede il WDK 7.1.0 (GRMWDK_EN_7600_1.ISO) con "Build Environments", header e librerie
  x86 e x64 installati. Il driver a 64 bit, per caricarsi su Windows x64, va firmato e il
  sistema messo in test-signing: vedi scripts\sign-driver.ps1.
#>
param(
    [ValidateSet('x86', 'x64')] [string]$Arch = 'x86',
    [string]$Wdk = 'C:\WinDDK\7600.16385.win7_wdk.100208-1538',
    [switch]$Checked
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $root 'src\Vigil.Driver'
$flavor = if ($Checked) { 'chk' } else { 'fre' }

if (-not (Test-Path (Join-Path $Wdk 'bin\setenv.bat'))) { throw "WDK 7.1 non trovato in $Wdk" }

# Argomenti di setenv e cartella di output per architettura.
#   x86 -> target Windows XP (WXP), oggetti in objXXX_wxp_x86\i386
#   x64 -> target Server 2003/XP x64 (WNET), oggetti in objXXX_wnet_amd64\amd64
if ($Arch -eq 'x64') {
    $setArgs = "$flavor x64 WNET no_oacr"
    $objRel = "obj${flavor}_wnet_amd64\amd64\vigilflt.sys"
} else {
    $setArgs = "$flavor WXP no_oacr"
    $objRel = "obj${flavor}_wxp_x86\i386\vigilflt.sys"
}

# setenv.bat del WDK 7.1 va in errore se il PATH contiene parentesi ("Program Files (x86)")
# o se il percorso del WDK è tra virgolette: si ripulisce il PATH e si passa il percorso nudo.
$bat = Join-Path $env:TEMP "vigil-build-driver-$Arch.cmd"
@"
@echo off
set "PATH=%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem"
call "$Wdk\bin\setenv.bat" $Wdk $setArgs
cd /d "$proj"
build -cZ
exit /b %errorlevel%
"@ | Set-Content -Path $bat -Encoding ascii
$out = Join-Path $env:TEMP "vigil-driver-$Arch.log"
$p = Start-Process cmd.exe -ArgumentList "/c `"$bat`"" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError "$out.err"
Get-Content $out, "$out.err" -ErrorAction SilentlyContinue | Select-Object -Last 20
if ($p.ExitCode -ne 0) { throw "build del driver ($Arch) non riuscita (codice $($p.ExitCode)); vedi $out" }

$sys = Join-Path $proj $objRel
if (-not (Test-Path $sys)) { throw "vigilflt.sys non prodotto ($sys)" }

$outDir = Join-Path $root "dist\driver\$Arch"
New-Item -ItemType Directory -Force $outDir | Out-Null
Copy-Item $sys $outDir -Force
Copy-Item (Join-Path $proj 'vigilflt.inf') $outDir -Force
Write-Host "Driver $Arch pronto: $(Join-Path $outDir 'vigilflt.sys') ($((Get-Item $sys).Length) byte)"
