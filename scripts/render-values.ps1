<#
.SYNOPSIS
    Prints the exact values to paste into the Render dashboard.

.DESCRIPTION
    Reads the local .env so the values printed here are the same ones the
    local application uses. Reusing them keeps the encrypted records
    readable across the local and the cloud deployment.

.EXAMPLE
    ./scripts/dev.ps1 render-values
#>

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $projectRoot ".env"

if (-not (Test-Path -LiteralPath $envFile)) {
    throw "No .env file was found. Create it from .env.example first."
}

$values = @{}

Get-Content -LiteralPath $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
        $parts = $line.Split("=", 2)
        $values[$parts[0].Trim()] = $parts[1].Trim()
    }
}

$required = @("MONGO_URI", "CAPABILITY_CODES", "AES_KEYS", "FINGERPRINT_KEY")
$missing = $required | Where-Object { -not $values.ContainsKey($_) -or -not $values[$_] }

if ($missing) {
    throw "These values are missing from .env: $($missing -join ', ')"
}

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " Paste these into the Render blueprint" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

foreach ($key in $required) {
    Write-Host ""
    Write-Host "--- $key ---" -ForegroundColor Green
    Write-Host $values[$key]
}

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " ACTIVE_KEY_ID = v1" -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Render asks for four values, plus ACTIVE_KEY_ID is already set." -ForegroundColor DarkGray
Write-Host ""
