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
Copy-Item "$app\VigilLegacy.exe", "$app\VigilLegacy.exe.config", "$app\Vigil.Engine.dll", "$app\BouncyCastle.Crypto.dll" $out
Copy-Item "$svc\VigilLegacySvc.exe", "$svc\VigilLegacySvc.exe.config" $out
if (Test-Path "$app\clamav") { Copy-Item -Recurse "$app\clamav" $out } else { Write-Warning 'ClamAV assente: esegui prima scripts\fetch-clamav.ps1' }
# Driver di autodifesa a 32 bit (se compilato con scripts\build-driver.ps1). Facoltativo: se manca,
# Vigil funziona lo stesso, senza l'autodifesa a livello di driver.
$drv = Join-Path $root 'dist\driver'
if (Test-Path "$drv\vigilflt.sys") { Copy-Item "$drv\vigilflt.sys", "$drv\vigilflt.inf" $out } else { Write-Warning 'Driver assente: esegui prima scripts\build-driver.ps1 (serve il WDK 7.1)' }
Copy-Item (Join-Path $root 'LICENSE') $out
Write-Host "Pronto: $out"

# Programma di installazione: un solo .exe con dentro l'archivio dei file.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$payload = Join-Path $root 'dist\payload.zip'
Remove-Item $payload -ErrorAction SilentlyContinue
[IO.Compression.ZipFile]::CreateFromDirectory($out, $payload, [IO.Compression.CompressionLevel]::Optimal, $false)
dotnet build (Join-Path $root 'src\Vigil.Setup\Vigil.Setup.csproj') -c $Configuration -v q -nologo
if ($LASTEXITCODE -ne 0) { throw 'compilazione del setup non riuscita' }
$version = ([xml](Get-Content (Join-Path $root 'Directory.Build.props'))).Project.PropertyGroup.Version
$setup = Join-Path $root "dist\VigilLegacySetup-$version.exe"
Copy-Item (Join-Path $root "src\Vigil.Setup\bin\$Configuration\net40\VigilLegacySetup.exe") $setup -Force
Write-Host "Installer: $setup ($([int]((Get-Item $setup).Length / 1MB)) MB)"
