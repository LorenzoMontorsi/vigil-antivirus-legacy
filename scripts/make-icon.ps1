<#
.SYNOPSIS
  Disegna l'icona di Vigil Legacy (scudo su quadrato con gradiente viola/ciano/lime)
  con WPF e produce src\Vigil.App\Assets\vigil.ico (16-256 px, leggibile anche da XP)
  e logo.png (256 px).
#>
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase
$assets = Join-Path $PSScriptRoot '..\src\Vigil.App\Assets'

function Render([int]$size) {
    $dv = New-Object System.Windows.Media.DrawingVisual
    $dc = $dv.RenderOpen()
    $s = $size / 256.0
    $grad = New-Object System.Windows.Media.LinearGradientBrush
    $grad.StartPoint = '0,0'; $grad.EndPoint = '1,1'
    $grad.GradientStops.Add((New-Object System.Windows.Media.GradientStop ([System.Windows.Media.ColorConverter]::ConvertFromString('#8B5CF6')), 0))
    $grad.GradientStops.Add((New-Object System.Windows.Media.GradientStop ([System.Windows.Media.ColorConverter]::ConvertFromString('#22D3EE')), 0.55))
    $grad.GradientStops.Add((New-Object System.Windows.Media.GradientStop ([System.Windows.Media.ColorConverter]::ConvertFromString('#A3E635')), 1))
    $r = 56 * $s
    $dc.DrawRoundedRectangle($grad, $null, (New-Object System.Windows.Rect (8 * $s), (8 * $s), (240 * $s), (240 * $s)), $r, $r)
    # Scudo scuro al centro, con bordo chiaro.
    $shield = [System.Windows.Media.Geometry]::Parse('M128,44 L196,70 V124 C196,170 166,204 128,218 C90,204 60,170 60,124 V70 Z')
    $ink = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#0A0B14'))
    # Le geometrie analizzate sono congelate: si scala il disegno, con spessori in unità a 256 px.
    $dc.PushTransform((New-Object System.Windows.Media.ScaleTransform $s, $s))
    $pen = New-Object System.Windows.Media.Pen ([System.Windows.Media.Brushes]::White), ([Math]::Max(1.0, 10 * $s) / $s)
    $dc.DrawGeometry($ink, $pen, $shield)
    # Segno di spunta (solo dove si vede: da 24 px in su).
    if ($size -ge 24) {
        $tick = [System.Windows.Media.Geometry]::Parse('M98,128 L120,150 L160,108')
        $tp = New-Object System.Windows.Media.Pen ($grad), ([Math]::Max(1.5, 16 * $s) / $s)
        $tp.StartLineCap = 'Round'; $tp.EndLineCap = 'Round'; $tp.LineJoin = 'Round'
        $dc.DrawGeometry($null, $tp, $tick)
    }
    $dc.Pop()
    $dc.Close()
    $bmp = New-Object System.Windows.Media.Imaging.RenderTargetBitmap $size, $size, 96, 96, ([System.Windows.Media.PixelFormats]::Pbgra32)
    $bmp.Render($dv)
    $enc = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bmp))
    $ms = New-Object System.IO.MemoryStream
    $enc.Save($ms)
    return , $ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 256
$pngs = @{}
foreach ($z in $sizes) { $pngs[$z] = Render $z }
[IO.File]::WriteAllBytes((Join-Path $assets 'logo.png'), $pngs[256])

# ICO con immagini PNG, poi ico-xp.py converte le piccole in bitmap (XP non legge le PNG).
$ms = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter $ms
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
foreach ($z in $sizes) {
    $b = if ($z -ge 256) { 0 } else { $z }
    $w.Write([byte]$b); $w.Write([byte]$b); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32); $w.Write([uint32]$pngs[$z].Length); $w.Write([uint32]$offset)
    $offset += $pngs[$z].Length
}
foreach ($z in $sizes) { $w.Write($pngs[$z]) }
$tmp = Join-Path $env:TEMP 'vigil-png.ico'
[IO.File]::WriteAllBytes($tmp, $ms.ToArray())
python -I (Join-Path $PSScriptRoot 'ico-xp.py') $tmp (Join-Path $assets 'vigil.ico')
