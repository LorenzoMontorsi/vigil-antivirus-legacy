<#
.SYNOPSIS
  Compila il minifilter vigilflt.sys (a 32 bit, per Windows XP/7) con il WDK 7.1.0.
  Il WDK 7.1 è l'ultimo che targettizza Windows XP; i WDK moderni no.

.NOTES
  Scarica il WDK 7.1.0 (GRMWDK_EN_7600_1.ISO) dal sito Microsoft e installane
  "Build Environments", "Tools", gli header e le librerie x86. Poi imposta -Wdk al
  percorso di installazione (di solito C:\WinDDK\7600.16385.1 o simile).
#>
param(
    [string]$Wdk = 'C:\WinDDK\7600.16385.win7_wdk.100208-1538',
    [switch]$Checked
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $root 'src\Vigil.Driver'
$flavor = if ($Checked) { 'chk' } else { 'fre' }

if (-not (Test-Path (Join-Path $Wdk 'bin\setenv.bat'))) { throw "WDK 7.1 non trovato in $Wdk" }

# setenv imposta l'ambiente del WDK (WXP = Windows XP), poi build compila nella cartella del progetto.
# Passo per un file .cmd: così le virgolette e i && non vengono rovinati dal parsing di PowerShell.
$bat = Join-Path $env:TEMP 'vigil-build-driver.cmd'
# Nota: setenv.bat del WDK 7.1 va in errore se il PATH contiene parentesi ("Program Files (x86)"),
# cosa normale su Windows a 64 bit. Lo si ripulisce prima: il WDK 7.1 porta il proprio compilatore.
@"
@echo off
set "PATH=%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem"
call "$Wdk\bin\setenv.bat" $Wdk $flavor WXP no_oacr
cd /d "$proj"
build -cZ
exit /b %errorlevel%
"@ | Set-Content -Path $bat -Encoding ascii
$out = Join-Path $env:TEMP 'vigil-driver-build.log'
$p = Start-Process cmd.exe -ArgumentList "/c `"$bat`"" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError "$out.err"
Get-Content $out, "$out.err" -ErrorAction SilentlyContinue | Select-Object -Last 25
if ($p.ExitCode -ne 0) { throw "build del driver non riuscita (codice $($p.ExitCode)); vedi $out" }

$sys = Join-Path $proj ("obj{0}_wxp_x86\i386\vigilflt.sys" -f $flavor)
if (-not (Test-Path $sys)) { throw "vigilflt.sys non prodotto ($sys)" }

$outDir = Join-Path $root 'dist\driver'
New-Item -ItemType Directory -Force $outDir | Out-Null
Copy-Item $sys $outDir -Force
Copy-Item (Join-Path $proj 'vigilflt.inf') $outDir -Force
Write-Host "Driver pronto: $(Join-Path $outDir 'vigilflt.sys') ($((Get-Item $sys).Length) byte)"
