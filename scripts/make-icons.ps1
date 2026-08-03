# Builds every icon Osprey ships from the one source logo.
#
#   powershell -ExecutionPolicy Bypass -File scripts/make-icons.ps1
#
# Outputs (all regenerable, so none are hand-edited):
#   branding/osprey.ico              - embedded in osprey-svc.exe by build.rs
#   branding/ios/AppIcon-1024.png    - the iOS marketing icon
#
# Two format rules drive the differences between them:
#   * A Windows icon is composited over whatever the shell paints behind it, so
#     the white plate around the mark is keyed out. Without that the taskbar
#     shows a white tile.
#   * An iOS app icon must be fully opaque with no alpha channel at all -
#     App Store Connect rejects one that has it - so the iOS output keeps the
#     white background.
#
# Every `New-Object` here passes -ArgumentList explicitly. The terser
# `New-Object Type(a, b)` form binds the parenthesised list as a single
# positional argument in Windows PowerShell and fails with the famously
# unhelpful "Parameter is not valid".

# The parameter and the loaded bitmap must not differ only by case: PowerShell
# variable names are case-insensitive, so assigning a Bitmap to `$Source` when
# the parameter is declared `[string]$Source` silently stringifies the object
# and every later property read comes back empty.
param(
    [string]$LogoPath = "$PSScriptRoot\..\branding\osprey-logo.png",
    [string]$OutDir = "$PSScriptRoot\..\branding"
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

if (-not (Test-Path $LogoPath)) { throw "source logo not found: $LogoPath" }
$logo = New-Object System.Drawing.Bitmap -ArgumentList (Resolve-Path $LogoPath).Path
Write-Host "source: $($logo.Width)x$($logo.Height)"

# Pixels at or above this luminance become fully transparent; the band below it
# fades, which keeps the mark's anti-aliased edges from turning into a jagged
# white fringe on a dark taskbar.
$opaqueBelow = 200
$clearAbove = 250

function New-TransparentBitmap {
    param($Image)

    $argb = [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
    $out = New-Object System.Drawing.Bitmap -ArgumentList $Image.Width, $Image.Height, $argb
    $rect = New-Object System.Drawing.Rectangle -ArgumentList 0, 0, $Image.Width, $Image.Height

    $src = $Image.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, $argb)
    $dst = $out.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly, $argb)
    try {
        $count = $Image.Width * $Image.Height * 4
        $bytes = New-Object byte[] $count
        [System.Runtime.InteropServices.Marshal]::Copy($src.Scan0, $bytes, 0, $count)

        for ($i = 0; $i -lt $count; $i += 4) {
            # BGRA byte order.
            $b = $bytes[$i]; $g = $bytes[$i + 1]; $r = $bytes[$i + 2]
            $luma = (0.299 * $r) + (0.587 * $g) + (0.114 * $b)
            if ($luma -ge $clearAbove) {
                $bytes[$i + 3] = 0
            } elseif ($luma -gt $opaqueBelow) {
                $t = ($luma - $opaqueBelow) / ($clearAbove - $opaqueBelow)
                $bytes[$i + 3] = [byte][math]::Round(255 * (1 - $t))
            } else {
                $bytes[$i + 3] = 255
            }
        }
        [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $dst.Scan0, $count)
    } finally {
        $Image.UnlockBits($src)
        $out.UnlockBits($dst)
    }
    return $out
}

function Resize-Bitmap {
    param($Image, [int]$Size)

    $argb = [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
    $out = New-Object System.Drawing.Bitmap -ArgumentList $Size, $Size, $argb
    $g = [System.Drawing.Graphics]::FromImage($out)
    try {
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)
        $target = New-Object System.Drawing.Rectangle -ArgumentList 0, 0, $Size, $Size
        $g.DrawImage($Image, $target)
    } finally {
        $g.Dispose()
    }
    return $out
}

function Get-PngBytes {
    param($Image)
    $stream = New-Object System.IO.MemoryStream
    try {
        $Image.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
        # The leading comma is load-bearing: PowerShell unrolls a returned
        # array into the pipeline element by element, and the caller then
        # re-collects an Object[] of boxed bytes rather than the byte[] the
        # BinaryWriter needs. Wrapping it keeps the array intact.
        return , $stream.ToArray()
    } finally {
        $stream.Dispose()
    }
}

# ---- Windows .ico -----------------------------------------------------------
# Written by hand because .NET cannot save a multi-resolution icon. The Vista+
# ICO container stores each entry as a whole PNG, which is what every size above
# 48px should be anyway.

$transparent = New-TransparentBitmap -Image $logo
$sizes = @(16, 24, 32, 48, 64, 128, 256)
$entries = @()
foreach ($size in $sizes) {
    $scaled = Resize-Bitmap -Image $transparent -Size $size
    try {
        $png = Get-PngBytes -Image $scaled
        if ($png.Length -lt 100) { throw "encoding the ${size}px entry produced $($png.Length) bytes" }
        $entries += , @{ Size = $size; Png = $png }
    } finally {
        $scaled.Dispose()
    }
}

$icoPath = Join-Path $OutDir 'osprey.ico'
$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter -ArgumentList $fs
try {
    $bw.Write([uint16]0)                  # reserved
    $bw.Write([uint16]1)                  # type: icon
    $bw.Write([uint16]$entries.Count)

    # Directory entries come first, so every image offset is past all of them.
    $offset = 6 + (16 * $entries.Count)
    foreach ($entry in $entries) {
        # 256 is encoded as 0 - the field is a single byte.
        $dim = if ($entry.Size -ge 256) { 0 } else { $entry.Size }
        $bw.Write([byte]$dim)             # width
        $bw.Write([byte]$dim)             # height
        $bw.Write([byte]0)                # palette size: none
        $bw.Write([byte]0)                # reserved
        $bw.Write([uint16]1)              # colour planes
        $bw.Write([uint16]32)             # bits per pixel
        $bw.Write([uint32]$entry.Png.Length)
        $bw.Write([uint32]$offset)
        $offset += $entry.Png.Length
    }
    foreach ($entry in $entries) { $bw.Write($entry.Png) }
} finally {
    $bw.Dispose()
    $fs.Dispose()
}
Write-Host "wrote $icoPath ($((Get-Item $icoPath).Length) bytes, $($entries.Count) sizes)"

# ---- iOS marketing icon -----------------------------------------------------
# Opaque on purpose: App Store Connect rejects an icon carrying an alpha
# channel, so this one is flattened onto white rather than keyed out.

$iosDir = Join-Path $OutDir 'ios'
New-Item -ItemType Directory -Path $iosDir -Force | Out-Null

$rgb = [System.Drawing.Imaging.PixelFormat]::Format24bppRgb
$ios = New-Object System.Drawing.Bitmap -ArgumentList 1024, 1024, $rgb
$g = [System.Drawing.Graphics]::FromImage($ios)
try {
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::White)
    $target = New-Object System.Drawing.Rectangle -ArgumentList 0, 0, 1024, 1024
    $g.DrawImage($logo, $target)
} finally {
    $g.Dispose()
}
$iosPath = Join-Path $iosDir 'AppIcon-1024.png'
$ios.Save($iosPath, [System.Drawing.Imaging.ImageFormat]::Png)
$ios.Dispose()
Write-Host "wrote $iosPath (1024x1024, opaque)"

$transparent.Dispose()
$logo.Dispose()

