# Eseguito NELLA VM: apre l'installazione guidata nella sessione dell'utente (elevata tramite
# attività pianificata, senza richiesta UAC) e ne fa una foto con screenshot.ps1.
$action = New-ScheduledTaskAction -Execute 'C:\VigilLegacyTest\setup.exe'
$principal = New-ScheduledTaskPrincipal -UserId 'vigil' -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName VigilLegacySetupGui -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName VigilLegacySetupGui
Start-Sleep 6
& C:\Vigil\screenshot.ps1
Get-Process VigilLegacySetup -ErrorAction SilentlyContinue | Stop-Process -Force
