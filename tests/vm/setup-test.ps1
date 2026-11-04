# Eseguito NELLA VM (amministratore, via SSH): prova installazione e disinstallazione silenziose
# del programma di installazione C:\VigilLegacyTest\setup.exe.
$ErrorActionPreference = 'Continue'
$setup = 'C:\VigilLegacyTest\setup.exe'

# Pulizia delle prove precedenti (rt-test.ps1 installa a mano in Program Files).
foreach ($old in 'C:\Program Files\Vigil Legacy', 'C:\Program Files (x86)\Vigil Legacy') {
    if (Test-Path "$old\VigilLegacySvc.exe") { & "$old\VigilLegacySvc.exe" --uninstall | Out-Null }
}
Get-Process VigilLegacy, VigilLegacySetup -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -Filter "Name='clamd.exe'" | Where-Object { $_.CommandLine -like '*Vigil Legacy*' } | Invoke-CimMethod -MethodName Terminate | Out-Null
Start-Sleep 2
Remove-Item -Recurse -Force 'C:\Program Files\Vigil Legacy', 'C:\Program Files (x86)\Vigil Legacy' -ErrorAction SilentlyContinue

'== installazione silenziosa'
$p = Start-Process $setup -ArgumentList '/silent' -PassThru -Wait
'codice di uscita: ' + $p.ExitCode
$key = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VigilLegacy' -ErrorAction SilentlyContinue
'Programmi e funzionalità: ' + $key.DisplayName + ' ' + $key.DisplayVersion + ' in ' + $key.InstallLocation
'disinstallazione: ' + $key.UninstallString
'file: ' + (Get-ChildItem $key.InstallLocation -Name) -join ', '
'servizio: ' + (Get-Service VigilLegacy -ErrorAction SilentlyContinue).Status
'menu Start: ' + ((Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Vigil Legacy" -Name) -join ', ')
'desktop: ' + (Test-Path "$env:PUBLIC\Desktop\Vigil Legacy.lnk")

'== disinstallazione silenziosa'
$p = Start-Process "$($key.InstallLocation)\VigilLegacySetup.exe" -ArgumentList '/uninstall', '/silent' -PassThru -Wait
'codice di uscita: ' + $p.ExitCode
'servizio ancora presente: ' + [bool](Get-Service VigilLegacy -ErrorAction SilentlyContinue)
'voce in Programmi e funzionalità: ' + (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VigilLegacy')
'file rimasti: ' + ((Get-ChildItem $key.InstallLocation -Recurse -Name -ErrorAction SilentlyContinue) -join ', ')
'collegamento sul desktop: ' + (Test-Path "$env:PUBLIC\Desktop\Vigil Legacy.lnk")
if (Test-Path "$env:TEMP\VigilLegacySetup.log") { Get-Content "$env:TEMP\VigilLegacySetup.log" }
Start-Sleep 6
'cartella rimasta dopo qualche secondo: ' + (Test-Path $key.InstallLocation)
