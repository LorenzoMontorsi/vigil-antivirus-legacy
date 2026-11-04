<#
.SYNOPSIS
  Compila in Release e raccoglie in dist\VigilLegacy tutto ciò che va installato:
  app, servizio, motore e ClamAV legacy (se scaricato con fetch-clamav.ps1).
#>
param([string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'dist\VigilLegacy'

dotnet build (Join-Path $root 'VigilLegacy.sln') -c $Configuration -v q -nologo
if ($LASTEXITCODE -ne 0) { throw 'compilazione non riuscita' }

Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out | Out-Null
$app = Join-Path $root "src\Vigil.App\bin\$Configuration\net40"
$svc = Join-Path $root "src\Vigil.Service\bin\$Configuration\net40"
Copy-Item "$app\VigilLegacy.exe", "$app\VigilLegacy.exe.config", "$app\Vigil.Engine.dll" $out
Copy-Item "$svc\VigilLegacySvc.exe", "$svc\VigilLegacySvc.exe.config" $out
if (Test-Path "$app\clamav") { Copy-Item -Recurse "$app\clamav" $out } else { Write-Warning 'ClamAV assente: esegui prima scripts\fetch-clamav.ps1' }
Copy-Item (Join-Path $root 'LICENSE') $out
Write-Host "Pronto: $out"
