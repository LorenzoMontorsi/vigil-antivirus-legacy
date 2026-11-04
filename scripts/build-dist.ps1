<#
.SYNOPSIS
  Compila in Release e crea il programma di installazione per un'architettura (x86 o x64):
  app, servizio, motore, ClamAV legacy e il driver di autodifesa della stessa architettura.

.PARAMETER Arch
  x86 (predefinito, per XP/7 a 32 bit) oppure x64 (per XP x64 / 7 a 64 bit).

.NOTES
  I binari gestiti sono x86 e girano su entrambi i sistemi (via WOW64 sui 64 bit); cambia solo il
  driver (vigilflt.sys), che deve avere i bit del kernel. Per l'edizione a 64 bit servono il driver
  a 64 bit firmato e il certificato di prova: compilali con build-driver.ps1 -Arch x64 e sign-driver.ps1.
#>
param(
    [ValidateSet('x86', 'x64')] [string]$Arch = 'x86',
    [string]$Configuration = 'Release'
)
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

# Driver di autodifesa dell'architettura scelta (facoltativo: senza, Vigil funziona ugualmente).
$drv = Join-Path $root "dist\driver\$Arch"
if (Test-Path "$drv\vigilflt.sys") {
    Copy-Item "$drv\vigilflt.sys" $out
    if ($Arch -eq 'x64') {
        # Sui 64 bit servono il certificato di prova e lo script che abilita il test-signing.
        Copy-Item "$drv\VigilLegacyTest.cer" $out
        Copy-Item (Join-Path $root 'src\Vigil.Driver\abilita-driver-64bit.cmd') $out
    }
} else {
    Write-Warning "Driver $Arch assente: esegui prima scripts\build-driver.ps1 -Arch $Arch (e sign-driver.ps1 per x64)"
}
Copy-Item (Join-Path $root 'LICENSE') $out
Write-Host "Pronto ($Arch): $out"

# Programma di installazione: un solo .exe con dentro l'archivio dei file.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$payload = Join-Path $root 'dist\payload.zip'
Remove-Item $payload -ErrorAction SilentlyContinue
[IO.Compression.ZipFile]::CreateFromDirectory($out, $payload, [IO.Compression.CompressionLevel]::Optimal, $false)
dotnet build (Join-Path $root 'src\Vigil.Setup\Vigil.Setup.csproj') -c $Configuration -v q -nologo
if ($LASTEXITCODE -ne 0) { throw 'compilazione del setup non riuscita' }
$version = ([xml](Get-Content (Join-Path $root 'Directory.Build.props'))).Project.PropertyGroup.Version
$setup = Join-Path $root "dist\VigilLegacySetup-$version-$Arch.exe"
Copy-Item (Join-Path $root "src\Vigil.Setup\bin\$Configuration\net40\VigilLegacySetup.exe") $setup -Force
Write-Host "Installer ($Arch): $setup ($([int]((Get-Item $setup).Length / 1MB)) MB)"
