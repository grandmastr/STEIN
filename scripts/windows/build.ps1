[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipDesktop
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$NodeRoot = Join-Path $env:LOCALAPPDATA "Programs\DevTools\Node"
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
if (Test-Path $NodeRoot) {
    $env:Path = "$NodeRoot;$env:Path"
}

foreach ($Tool in @("cargo.exe", "pnpm.cmd")) {
    if (-not (Get-Command $Tool -ErrorAction SilentlyContinue)) {
        throw "Required build tool is unavailable: $Tool"
    }
}

Push-Location $RepoRoot
try {
    Write-Host "[STEIN] Checking dependency boundaries"
    & (Join-Path $PSScriptRoot "check-boundaries.ps1")
    if ($LASTEXITCODE -ne 0) { throw "dependency boundary checks failed" }

    Write-Host "[STEIN] Formatting Rust workspace"
    & cargo.exe fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt failed" }

    Write-Host "[STEIN] Checking Rust workspace"
    & cargo.exe check --workspace --all-targets
    if ($LASTEXITCODE -ne 0) { throw "cargo check failed" }

    Write-Host "[STEIN] Linting Rust workspace"
    & cargo.exe clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed" }

    if (-not $SkipTests) {
        Write-Host "[STEIN] Running Rust tests"
        & cargo.exe test --workspace
        if ($LASTEXITCODE -ne 0) { throw "cargo test failed" }
    }

    Write-Host "[STEIN] Building CORE and CLI release binaries"
    & cargo.exe build --release -p stein-core-daemon -p stein-cli
    if ($LASTEXITCODE -ne 0) { throw "CORE release build failed" }

    if (-not $SkipDesktop) {
        Push-Location (Join-Path $RepoRoot "apps\desktop")
        try {
            Write-Host "[STEIN] Installing locked desktop dependencies"
            if (Test-Path "pnpm-lock.yaml") {
                & pnpm.cmd install --frozen-lockfile
            } else {
                & pnpm.cmd install
            }
            if ($LASTEXITCODE -ne 0) { throw "pnpm install failed" }

            if (-not $SkipTests) {
                Write-Host "[STEIN] Type-checking, linting, and testing desktop"
                & pnpm.cmd run typecheck
                if ($LASTEXITCODE -ne 0) { throw "desktop typecheck failed" }
                & pnpm.cmd run lint
                if ($LASTEXITCODE -ne 0) { throw "desktop lint failed" }
                & pnpm.cmd test
                if ($LASTEXITCODE -ne 0) { throw "desktop tests failed" }
            }

            Write-Host "[STEIN] Building Tauri desktop executable"
            & pnpm.cmd exec tauri build --no-bundle
            if ($LASTEXITCODE -ne 0) { throw "Tauri build failed" }
        } finally {
            Pop-Location
        }
    }
} finally {
    Pop-Location
}

Write-Host "[STEIN] Build completed"
