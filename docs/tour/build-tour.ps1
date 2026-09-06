#requires -Version 5.1
# Assemble docs/tour/tour.html from tour.template.html.
#
# Each @@TOKEN@@ in the template is replaced by a base64 data: URI built from a
# git-tracked asset in this repository, so the assembled page is a single
# self-contained file with no external image references.
#
# Re-runnable and idempotent: the output is always rebuilt from the template,
# never from a previous tour.html. Fails loudly if a source asset is missing,
# if a declared token is absent from the template, if any @@TOKEN@@ survives
# substitution, or if the assembled page exceeds the page budget.
#
# ASCII-only by contract: PowerShell 5.1 decodes a no-BOM .ps1 as cp1252, so a
# stray non-ASCII byte here can silently corrupt parsing.
#
# Run:  powershell -ExecutionPolicy Bypass -File docs/tour/build-tour.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TourDir  = $PSScriptRoot
$RepoRoot = Split-Path -Parent (Split-Path -Parent $TourDir)
$Template = Join-Path $TourDir 'tour.template.html'
$Output   = Join-Path $TourDir 'tour.html'

# Assembled-page budget in bytes.
$MaxBytes = 1000000

# Asset manifest. MaxWidth is the downscale target in pixels and applies to
# raster assets only (0 = no downscale). SVG is vector: it is embedded
# byte-for-byte and MaxWidth is ignored.
$Assets = @(
    [pscustomobject]@{
        Token    = '@@SVG_FAMILY@@'
        Path     = 'assets/utility-family-dark.svg'
        MaxWidth = 0
    }
)

function Get-SvgDataUri {
    param([Parameter(Mandatory = $true)][string]$FullPath)

    $bytes = [System.IO.File]::ReadAllBytes($FullPath)
    return 'data:image/svg+xml;base64,' + [Convert]::ToBase64String($bytes)
}

function Get-RasterDataUri {
    # Downscale a raster asset to $MaxWidth and return it as a data: URI.
    # PNG/GIF sources re-encode as PNG (flat art); everything else re-encodes
    # as JPEG at quality 82 (photographic content).
    param(
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][int]$MaxWidth
    )

    Add-Type -AssemblyName System.Drawing

    $src = [System.Drawing.Image]::FromFile($FullPath)
    try {
        $w = $src.Width
        $h = $src.Height
        if ($MaxWidth -gt 0 -and $w -gt $MaxWidth) {
            $h = [int][math]::Round($h * ($MaxWidth / $w))
            $w = $MaxWidth
        }
        if ($h -lt 1) { $h = 1 }

        $bmp = New-Object -TypeName System.Drawing.Bitmap -ArgumentList $w, $h
        try {
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            try {
                $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $g.PixelOffsetMode   = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $g.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
                $g.DrawImage($src, 0, 0, $w, $h)
            }
            finally { $g.Dispose() }

            $ms = New-Object -TypeName System.IO.MemoryStream
            try {
                $ext = [System.IO.Path]::GetExtension($FullPath).ToLowerInvariant()
                if ($ext -eq '.png' -or $ext -eq '.gif') {
                    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
                    $mime = 'image/png'
                }
                else {
                    $codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() |
                        Where-Object { $_.MimeType -eq 'image/jpeg' } |
                        Select-Object -First 1
                    if ($null -eq $codec) { throw 'No JPEG encoder available on this machine.' }

                    $ep = New-Object -TypeName System.Drawing.Imaging.EncoderParameters -ArgumentList 1
                    $ep.Param[0] = New-Object -TypeName System.Drawing.Imaging.EncoderParameter `
                        -ArgumentList ([System.Drawing.Imaging.Encoder]::Quality), ([long]82)
                    $bmp.Save($ms, $codec, $ep)
                    $mime = 'image/jpeg'
                }
                return "data:$mime;base64," + [Convert]::ToBase64String($ms.ToArray())
            }
            finally { $ms.Dispose() }
        }
        finally { $bmp.Dispose() }
    }
    finally { $src.Dispose() }
}

if (-not (Test-Path -LiteralPath $Template)) {
    throw "Template not found: $Template"
}

$html = [System.IO.File]::ReadAllText($Template)

foreach ($asset in $Assets) {
    $full = Join-Path $RepoRoot $asset.Path
    if (-not (Test-Path -LiteralPath $full)) {
        throw ("Missing source asset for {0}: {1}" -f $asset.Token, $full)
    }
    if ($html.IndexOf($asset.Token) -lt 0) {
        throw ("Token {0} declared in the manifest but absent from {1}" -f $asset.Token, $Template)
    }

    $ext = [System.IO.Path]::GetExtension($full).ToLowerInvariant()
    if ($ext -eq '.svg') {
        $uri = Get-SvgDataUri -FullPath $full
    }
    else {
        $uri = Get-RasterDataUri -FullPath $full -MaxWidth $asset.MaxWidth
    }

    $html = $html.Replace($asset.Token, $uri)
    $srcKb = [math]::Round((Get-Item -LiteralPath $full).Length / 1KB, 1)
    $uriKb = [math]::Round($uri.Length / 1KB, 1)
    Write-Host ("  embedded {0,-16} {1,8} KB source -> {2,8} KB data URI  ({3})" -f `
        $asset.Token, $srcKb, $uriKb, $asset.Path)
}

$leftover = [regex]::Matches($html, '@@[A-Z0-9_]+@@')
if ($leftover.Count -gt 0) {
    $names = ($leftover | ForEach-Object { $_.Value } | Select-Object -Unique) -join ', '
    throw "Unsubstituted token(s) remain in the assembled page: $names"
}

$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
[System.IO.File]::WriteAllText($Output, $html, $utf8NoBom)

$size = (Get-Item -LiteralPath $Output).Length
Write-Host ""
Write-Host ("  wrote " + (Split-Path $Output -Leaf))
Write-Host ("  size  {0:N0} bytes  (budget {1:N0})" -f $size, $MaxBytes)

if ($size -gt $MaxBytes) {
    throw ("Assembled page is {0:N0} bytes, over the {1:N0}-byte budget. Lower MaxWidth in the asset manifest." -f $size, $MaxBytes)
}

Write-Host "  OK"
