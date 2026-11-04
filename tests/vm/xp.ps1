# Client dell'agente della VM XP (xp-agent): esegue comandi e copia file nella VM.
#   xp.ps1 -Exec 'ver'                    comando cmd.exe nella VM (come amministratore)
#   xp.ps1 -Put locale -To 'C:\percorso'  copia un file (o una cartella) nella VM
#   xp.ps1 -Get 'C:\percorso' -To locale  copia un file dalla VM
#   xp.ps1 -Ip                            indirizzo della VM
param([string] $Exec, [string] $Put, [string] $Get, [string] $To, [switch] $Ip, [string] $VmDir = 'C:\VM\vigil-xp')
$ErrorActionPreference = 'Stop'
$token = (Get-Content "$VmDir\token.txt").Trim()

function Find-Ip {
    $mac = (Select-String -Path "$VmDir\Vigil-XP.vmx" -Pattern 'ethernet0.generatedAddress = "(.*)"').Matches[0].Groups[1].Value
    $leases = Get-Content 'C:\ProgramData\VMware\vmnetdhcp.leases' -Raw
    $last = $null
    foreach ($m in [regex]::Matches($leases, '(?s)lease ([\d.]+) \{(.*?)\}')) {
        if ($m.Groups[2].Value -match [regex]::Escape($mac)) { $last = $m.Groups[1].Value }
    }
    if (-not $last) { throw "indirizzo della VM non trovato ($mac)" }
    $last
}

function Open-Agent([string] $op, [string[]] $lines) {
    $c = New-Object Net.Sockets.TcpClient
    $c.Connect((Find-Ip), 7799)
    $s = $c.GetStream()
    $b = [Text.Encoding]::UTF8.GetBytes((@($token, $op) + $lines | ForEach-Object { "$_`n" }) -join '')
    $s.Write($b, 0, $b.Length)
    @($c, $s)
}

function Read-All($s) {
    $ms = New-Object IO.MemoryStream
    $s.CopyTo($ms)
    $ms.ToArray()
}

function Send-File([string] $local, [string] $remote) {
    $data = [IO.File]::ReadAllBytes($local)
    $c, $s = Open-Agent 'PUT' @($remote, $data.Length)
    $s.Write($data, 0, $data.Length)
    $r = [Text.Encoding]::UTF8.GetString((Read-All $s))
    $c.Close()
    if ($r -ne 'ok') { throw "copia di $local non riuscita: $r" }
}

if ($Ip) { Find-Ip; return }
if ($Exec) {
    $c, $s = Open-Agent 'EXEC' @($Exec)
    $text = [Text.Encoding]::UTF8.GetString((Read-All $s))
    $c.Close()
    $nl = $text.IndexOf("`n")
    $text.Substring($nl + 1)
    $global:LASTEXITCODE = [int]$text.Substring(0, $nl)
    return
}
if ($Put) {
    $item = Get-Item $Put
    if ($item.PSIsContainer) {
        foreach ($f in Get-ChildItem $Put -Recurse -File) {
            Send-File $f.FullName (Join-Path $To $f.FullName.Substring($item.FullName.Length).TrimStart('\'))
        }
    } else { Send-File $item.FullName $To }
    return
}
if ($Get) {
    $c, $s = Open-Agent 'GET' @($Get)
    $all = Read-All $s
    $c.Close()
    $nl = [Array]::IndexOf($all, [byte]10)
    $n = [int][Text.Encoding]::ASCII.GetString($all, 0, $nl)
    if ($n -lt 0) { throw [Text.Encoding]::UTF8.GetString($all, $nl + 1, $all.Length - $nl - 1) }
    [IO.File]::WriteAllBytes($To, $all[($nl + 1)..($all.Length - 1)])
}
