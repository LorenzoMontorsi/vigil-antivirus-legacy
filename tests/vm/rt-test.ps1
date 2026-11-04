# Eseguito NELLA VM (amministratore, via SSH): installa Vigil Legacy da C:\VigilLegacyTest e prova
# la protezione in tempo reale con "malware" finti e innocui, riconosciuti tramite il loro hash.
$ErrorActionPreference = 'Continue'
$src = 'C:\VigilLegacyTest'
$dst = 'C:\Program Files\Vigil Legacy'
$data = 'C:\ProgramData\VigilLegacy'
$log = "$data\logs\realtime.log"

# Vigil (Rust), se presente nella VM, interverrebbe per primo: lo si ferma per la prova.
Stop-Service VigilRtd -ErrorAction SilentlyContinue

# 0. Pulizia di un'eventuale prova precedente.
if (Get-Service VigilLegacy -ErrorAction SilentlyContinue) { & "$dst\VigilLegacySvc.exe" --uninstall | Out-Null }
Get-Process VigilLegacy, vigil-test-proc -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -Filter "Name='clamd.exe'" | Where-Object { $_.CommandLine -like '*Vigil Legacy*' } | Invoke-CimMethod -MethodName Terminate | Out-Null
Start-Sleep 2
Remove-Item -Recurse -Force C:\Users\vigil\AppData\Roaming\VigilLegacy -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $dst, "$data\logs", "$data\signatures", "$data\quarantine", "$data\service.json" -ErrorAction SilentlyContinue

# 1. Programma di prova (dorme 60 s) e firme finte.
New-Item -ItemType Directory -Force C:\T, "$data\signatures" | Out-Null
$code = 'public static class P { public static void Main() { System.Threading.Thread.Sleep(60000); } }'
Add-Type -TypeDefinition $code -OutputAssembly C:\T\vigil-test-proc.exe -OutputType ConsoleApplication
$jsContent = '// file innocuo usato come finto malware per provare Vigil Legacy'
$jsHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($jsContent))).Replace('-', '').ToLower()
$exeHash = (Get-FileHash C:\T\vigil-test-proc.exe -Algorithm SHA256).Hash.ToLower()
Set-Content -Encoding ascii "$data\signatures\test.txt" "$jsHash Vigil.Test.FintoScript`r`n$exeHash Vigil.Test.FintoProgramma"

# 2. Installazione.
New-Item -ItemType Directory -Force $dst | Out-Null
Copy-Item -Recurse "$src\*" $dst
& "$dst\VigilLegacySvc.exe" --install | Select-Object -Last 2
for ($i = 0; $i -lt 30 -and -not (Test-Path $log); $i++) { Start-Sleep 1 }
Start-Sleep 5
'servizio: ' + (Get-Service VigilLegacy).Status

# 3. App nella sessione interattiva dell'utente "vigil" (per vedere gli avvisi).
$action = New-ScheduledTaskAction -Execute "$dst\VigilLegacy.exe"
$principal = New-ScheduledTaskPrincipal -UserId 'vigil' -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName VigilLegacyApp -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName VigilLegacyApp
Start-Sleep 8

# 4. File: finto script sul Desktop.
$js = 'C:\Users\vigil\Desktop\finto-malware.js'
Set-Content -Encoding ascii -NoNewline -Path $js -Value $jsContent
for ($i = 0; $i -lt 15 -and (Test-Path $js); $i++) { Start-Sleep 1 }
'file ancora presente dopo la scrittura: ' + (Test-Path $js)

# 5. Programma: avvio del finto malware.
$p = Start-Process C:\T\vigil-test-proc.exe -PassThru -WindowStyle Hidden
for ($i = 0; $i -lt 15 -and -not $p.HasExited; $i++) { Start-Sleep 1 }
'programma terminato da Vigil: ' + $p.HasExited
Start-Sleep 2
'eseguibile ancora presente: ' + (Test-Path C:\T\vigil-test-proc.exe)
# Gli avvisi restano visibili ~12 s: foto dello schermo (script di Vigil, driver\vm\screenshot.ps1), se c'è.
if (Test-Path C:\Vigil\screenshot.ps1) { & C:\Vigil\screenshot.ps1 }

# 6. Elementi in quarantena e registro.
'in quarantena: ' + @(Get-ChildItem "$data\quarantine" -Filter *.vq -ErrorAction SilentlyContinue).Count
'--- realtime.log'
Get-Content $log
'--- clamd di Vigil Legacy (deve essere uno solo, del servizio)'
Get-CimInstance Win32_Process -Filter "Name='clamd.exe'" | Where-Object { $_.CommandLine -like '*Vigil Legacy*' } | ForEach-Object { $_.CommandLine }
