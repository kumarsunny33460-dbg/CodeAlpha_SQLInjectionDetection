<#
.SYNOPSIS
    Developer helper for SQLShield.

.DESCRIPTION
    Wraps the common development tasks so they work the same way on Windows,
    macOS and Linux.

.EXAMPLE
    ./scripts/dev.ps1 install
    ./scripts/dev.ps1 run
    ./scripts/dev.ps1 test
    ./scripts/dev.ps1 check
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("setup", "install", "run", "serve", "test", "coverage", "lint", "format", "check", "docker", "clean")]
    [string]$Command = "run"
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$venvPath = Join-Path $projectRoot "venv"
$envFile = Join-Path $projectRoot ".env"
$envExample = Join-Path $projectRoot ".env.example"

if (Test-Path -LiteralPath $venvPath) {
    $python = Join-Path $venvPath "Scripts/python.exe"
    if (-not (Test-Path -LiteralPath $python)) {
        $python = Join-Path $venvPath "bin/python"
    }
} else {
    $python = "python"
}

function Invoke-Native {
    <#
    .SYNOPSIS
        Runs a native command and returns its exit code.

    .DESCRIPTION
        Native tools such as pip and docker write their progress to stderr.
        Calling them directly turns that output into error records, which are
        noisy and, under ErrorActionPreference = Stop, terminating. Running the
        command through Start-Process with redirected streams keeps the output
        as plain text.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [string[]]$Arguments = @(),
        [switch]$Quiet
    )

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()

    try {
        # Arguments containing spaces have to be quoted for Start-Process.
        $quoted = @(
            $Arguments | ForEach-Object {
                if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
            }
        )

        $process = Start-Process `
            -FilePath $File `
            -ArgumentList $quoted `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile

        $exitCode = $process.ExitCode

        $output = Get-Content -LiteralPath $stdoutFile -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue
    }
    finally {
        Remove-Item -LiteralPath $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
    }

    if (-not $Quiet) {
        if ($output) { $output.TrimEnd() | Out-Host }
        if ($stderr) { Write-Host $stderr.TrimEnd() -ForegroundColor DarkGray }
    }

    return $exitCode
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    Write-Host ""
    Write-Host "==> $Description" -ForegroundColor Cyan

    $exitCode = Invoke-Native -File $python -Arguments $Arguments

    if ($exitCode -ne 0) {
        throw "$Description failed with exit code $exitCode."
    }
}

Push-Location $projectRoot

try {
    switch ($Command) {
        "setup" {
            Write-Host "==> Preparing SQLShield" -ForegroundColor Cyan

            if (-not (Test-Path -LiteralPath $envFile)) {
                Copy-Item -LiteralPath $envExample -Destination $envFile
                Write-Host "    .env created from .env.example" -ForegroundColor Green
                Write-Host "    Fill in CAPABILITY_CODES and AES_KEYS before going live." -ForegroundColor Yellow
            } else {
                Write-Host "    .env already exists, keeping it" -ForegroundColor Green
            }

            if (-not (Test-Path -LiteralPath $venvPath)) {
                Write-Host "==> Creating the virtual environment" -ForegroundColor Cyan
                & python -m venv $venvPath
                $python = Join-Path $venvPath "Scripts/python.exe"
            }

            Invoke-Step "Installing the dependencies" @("-m", "pip", "install", "-r", "requirements-dev.txt")

            $hasDocker = $null -ne (Get-Command docker -ErrorAction SilentlyContinue)

            if ($hasDocker) {
                Write-Host "==> Starting the Docker stack (app + MongoDB)" -ForegroundColor Cyan
                $exitCode = Invoke-Native -File "docker" -Arguments @("compose", "up", "--build", "-d")
                if ($exitCode -ne 0) {
                    throw "The Docker stack failed to start with exit code $exitCode."
                }
                Write-Host ""
                Write-Host "    SQLShield is available at http://127.0.0.1:8000/" -ForegroundColor Green
                Write-Host "    Stop it with: docker compose down" -ForegroundColor Green
            } else {
                Write-Host ""
                Write-Host "Docker was not found." -ForegroundColor Yellow
                Write-Host "Start a local MongoDB and run './scripts/dev.ps1 run' instead:" -ForegroundColor Yellow
                Write-Host "    docker run -d --name sqlshield-mongo -p 27017:27017 mongo:7" -ForegroundColor Yellow
            }
        }

        "install" {
            if (-not (Test-Path -LiteralPath $python) -or $python -eq "python") {
                Write-Host "==> Creating the virtual environment" -ForegroundColor Cyan
                & python -m venv $venvPath
                $python = Join-Path $venvPath "Scripts/python.exe"
            }
            Invoke-Step "Upgrading pip" @("-m", "pip", "install", "--upgrade", "pip")
            Invoke-Step "Installing the dependencies" @("-m", "pip", "install", "-r", "requirements-dev.txt")
        }

        "run" {
            Invoke-Step "Starting the development server" @("-m", "flask", "--app", "app", "run", "--debug", "--port", "5000")
        }

        "serve" {
            Invoke-Step "Starting the production server" @("-m", "gunicorn", "--config", "deploy/gunicorn.conf.py", "wsgi:application")
        }

        "test" {
            Invoke-Step "Running the test suite" @("-m", "pytest")
        }

        "coverage" {
            Invoke-Step "Running the test suite with coverage" @("-m", "pytest", "--cov=sqlshield", "--cov-report=term-missing")
        }

        "lint" {
            Invoke-Step "Running the linter" @("-m", "ruff", "check", ".")
        }

        "format" {
            Invoke-Step "Formatting the code" @("-m", "ruff", "format", ".")
        }

        "check" {
            Invoke-Step "Running the linter" @("-m", "ruff", "check", ".")
            Invoke-Step "Running the type checker" @("-m", "mypy", "sqlshield")
            Invoke-Step "Running the test suite" @("-m", "pytest")
        }

        "docker" {
            Write-Host "==> Rebuilding the Docker stack" -ForegroundColor Cyan
            $exitCode = Invoke-Native -File "docker" -Arguments @("compose", "up", "--build", "-d")
            if ($exitCode -ne 0) {
                throw "The Docker stack failed to start with exit code $exitCode."
            }
            Invoke-Native -File "docker" -Arguments @("compose", "ps")
        }

        "clean" {
            Write-Host "==> Removing the caches" -ForegroundColor Cyan
            Get-ChildItem -LiteralPath $projectRoot -Directory -Recurse -Force -Filter "__pycache__" |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($folder in @(".pytest_cache", ".ruff_cache", ".mypy_cache", "htmlcov")) {
                $target = Join-Path $projectRoot $folder
                if (Test-Path -LiteralPath $target) {
                    Remove-Item -LiteralPath $target -Recurse -Force
                }
            }
        }
    }
}
finally {
    Pop-Location
}
