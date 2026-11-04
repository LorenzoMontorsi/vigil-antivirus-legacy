# Crea sull'host una VM VMware con Windows XP SP3 installato senza intervento, .NET 4.0 e
# l'agente di prova (xp-agent), poi la avvia. Servono: l'ISO originale di XP SP3 x86, il proprio
# product key, VMware Player/Workstation, Python e dotNetFx40_Full_x86_x64.exe (scaricato dal
# sito Microsoft se manca). Il product key resta fuori dal repository (parametro o key.txt).
#
#   tests\vm\xp-create.ps1 -Iso <xp.iso> [-ProductKey XXXXX-...] [-VmDir C:\VM\vigil-xp]
param(
    [Parameter(Mandatory)] [string] $Iso,
    [string] $ProductKey,
    [string] $VmDir = 'C:\VM\vigil-xp',
    [int] $DiskGB = 20,
    [int] $MemoryMB = 2048
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$vmware = 'C:\Program Files (x86)\VMware\VMware Player'
if (-not (Test-Path "$vmware\vmrun.exe")) { $vmware = 'C:\Program Files (x86)\VMware\VMware Workstation' }

New-Item -ItemType Directory -Force $VmDir, "$VmDir\cd", "$VmDir\dl" | Out-Null
if (-not $ProductKey) { $ProductKey = (Get-Content "$VmDir\key.txt" -ErrorAction Stop).Trim() }
Set-Content -Path "$VmDir\key.txt" -Value $ProductKey

# 1. CD degli strumenti: .NET 4.0, agente, token e script del primo avvio.
$net = "$VmDir\dl\dotNetFx40_Full_x86_x64.exe"
if (-not (Test-Path $net)) {
    Invoke-WebRequest -UseBasicParsing -OutFile $net 'https://download.microsoft.com/download/9/5/A/95A9616B-7A37-4AF6-BC36-D6EA96C8DAAE/dotNetFx40_Full_x86_x64.exe'
}
if ((Get-AuthenticodeSignature $net).Status -ne 'Valid') { throw "firma di $net non valida" }
Copy-Item $net "$VmDir\cd\dotnet40.exe"
dotnet build "$here\xp-agent\VmAgent.csproj" -c Release -o "$VmDir\cd\agent" | Out-Null
$token = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
Set-Content -Path "$VmDir\token.txt" -Value $token -Encoding ascii
Set-Content -Path "$VmDir\cd\agent\token.txt" -Value $token -Encoding ascii
@'
@echo off
rem Primo avvio della VM di prova: niente firewall (rete NAT), .NET 4.0, agente all'avvio.
set CD=%~d0
netsh firewall set opmode mode=disable
xcopy /e /i /y %CD%\agent C:\VmAgent
start /wait %CD%\dotnet40.exe /q /norestart
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v VmAgent /d "C:\VmAgent\VmAgent.exe" /f
echo fatto > C:\VmAgent\firstboot.done
start "" C:\VmAgent\VmAgent.exe
'@ | Set-Content -Path "$VmDir\cd\FIRSTBOOT.CMD" -Encoding ascii
& "$vmware\mkisofs.exe" -quiet -J -r -V VIGILTOOLS -o "$VmDir\tools.iso" "$VmDir\cd"
if ($LASTEXITCODE) { throw 'mkisofs non riuscito' }

# 2. Dischetto con WINNT.SIF (risposte per l'installazione senza intervento).
@"
[Data]
AutoPartition=1
MsDosInitiated="0"
UnattendedInstall="Yes"

[Unattended]
UnattendMode=FullUnattended
OemSkipEula=Yes
OemPreinstall=No
TargetPath=\WINDOWS
Repartition=Yes
UnattendSwitch="Yes"
WaitForReboot="No"
DriverSigningPolicy=Ignore

[GuiUnattended]
AdminPassword="vigil"
EncryptedAdminPassword=NO
AutoLogon=Yes
AutoLogonCount=9999
OEMSkipRegional=1
OemSkipWelcome=1
TimeZone=110

[UserData]
ProductKey="$ProductKey"
FullName="Vigil"
OrgName="Vigil"
ComputerName=VIGIL-XP

[Display]
BitsPerPel=32
Xresolution=1024
YResolution=768

[Identification]
JoinWorkgroup=WORKGROUP

[Networking]
InstallDefaultComponents=Yes

[GuiRunOnce]
Command0="cmd /c for %d in (D E F G H) do if exist %d:\FIRSTBOOT.CMD %d:\FIRSTBOOT.CMD"
"@ | Set-Content -Path "$VmDir\WINNT.SIF" -Encoding ascii
python -I "$here\make-floppy.py" "$VmDir\winnt.flp" "$VmDir\WINNT.SIF"
if ($LASTEXITCODE) { throw 'dischetto non creato' }

# 3. Disco IDE (XP non ha driver SATA/SAS) e configurazione.
$sectors = [long]$DiskGB * 1024 * 1024 * 2
if (-not (Test-Path "$VmDir\xp-flat.vmdk")) {
    fsutil file createnew "$VmDir\xp-flat.vmdk" ($sectors * 512) | Out-Null
}
$cyl = [Math]::Min(16383, [long]($sectors / (16 * 63)))
@"
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicFlat"

RW $sectors FLAT "xp-flat.vmdk" 0

ddb.adapterType = "ide"
ddb.geometry.cylinders = "$cyl"
ddb.geometry.heads = "16"
ddb.geometry.sectors = "63"
ddb.virtualHWVersion = "14"
"@ | Set-Content -Path "$VmDir\xp.vmdk" -Encoding ascii

@"
.encoding = "windows-1252"
config.version = "8"
virtualHW.version = "14"
displayName = "Vigil-XP"
guestOS = "winxppro"
memsize = "$MemoryMB"
numvcpus = "1"
ide0:0.present = "TRUE"
ide0:0.fileName = "xp.vmdk"
ide1:0.present = "TRUE"
ide1:0.deviceType = "cdrom-image"
ide1:0.fileName = "$Iso"
ide1:1.present = "TRUE"
ide1:1.deviceType = "cdrom-image"
ide1:1.fileName = "tools.iso"
floppy0.present = "TRUE"
floppy0.fileType = "file"
floppy0.fileName = "winnt.flp"
bios.bootOrder = "hdd,cdrom"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "vlance"
ethernet0.addressType = "generated"
usb.present = "TRUE"
svga.present = "TRUE"
sound.present = "FALSE"
tools.syncTime = "FALSE"
"@ | Set-Content -Path "$VmDir\Vigil-XP.vmx" -Encoding ascii

& "$vmware\vmrun.exe" -T player start "$VmDir\Vigil-XP.vmx" gui
"VM avviata: l'installazione dura 20-40 minuti; poi tests\vm\xp.ps1 -Exec 'ver'"
