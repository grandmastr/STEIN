[CmdletBinding()]
param(
    [string] $EvidenceRoot,

    [switch] $IncludeInteractiveNative
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..")).Path
$desktopRoot = Join-Path $repoRoot "apps\desktop"
$edgeExtensionRoot = Join-Path $repoRoot "extensions\edge"
$edgeHostManifest = Join-Path $repoRoot "apps\edge-native-host\Cargo.toml"
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

if ($env:OS -cne "Windows_NT") {
    throw "Phase 2 source verification must run with native Windows tools."
}

foreach ($tool in @("cargo.exe", "rustc.exe", "node.exe", "pnpm.cmd", "powershell.exe")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required source-verification tool is unavailable: $tool"
    }
}

if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $EvidenceRoot = Join-Path $repoRoot "artifacts\evidence\phase-2\source-$stamp"
}
$evidencePath = [IO.Path]::GetFullPath($EvidenceRoot)
$repositoryPath = [IO.Path]::GetFullPath($repoRoot)
if (-not $evidencePath.StartsWith(
        "$repositoryPath$([IO.Path]::DirectorySeparatorChar)artifacts$([IO.Path]::DirectorySeparatorChar)",
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "EvidenceRoot must be below the repository artifacts directory."
}
$null = New-Item -ItemType Directory -Path $evidencePath -Force

$checks = New-Object Collections.Generic.List[object]
$startedAt = (Get-Date).ToUniversalTime()

function ConvertTo-SteinSafeLeaf {
    param([Parameter(Mandatory = $true)][string] $Value)

    return ($Value.ToLowerInvariant() -replace "[^a-z0-9._-]", "-")
}

function Get-SteinSha256 {
    param([Parameter(Mandatory = $true)][string] $Path)

    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite)
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha256.ComputeHash($stream)
            return [BitConverter]::ToString($digest).Replace("-", "").ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-SteinLogRecord {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    $item = Get-Item -LiteralPath $Path -Force
    return [ordered]@{
        path = $item.FullName.Substring($repositoryPath.Length + 1).Replace("\", "/")
        size = $item.Length
        sha256 = Get-SteinSha256 -Path $item.FullName
    }
}

function Invoke-SteinSourceCheck {
    param(
        [Parameter(Mandatory = $true)][string] $Id,
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )

    $leaf = ConvertTo-SteinSafeLeaf -Value $Id
    $stdoutPath = Join-Path $evidencePath "$leaf.stdout.txt"
    $stderrPath = Join-Path $evidencePath "$leaf.stderr.txt"
    $begin = (Get-Date).ToUniversalTime()
    $exitCode = -1
    $launchError = $null
    Write-Host "[RUN ] $Id"
    $process = $null
    try {
        $process = Start-Process `
            -FilePath $Executable `
            -ArgumentList $Arguments `
            -WorkingDirectory $WorkingDirectory `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath
        # Windows PowerShell releases Start-Process's native process handle
        # when -Wait is absent unless it is materialized by the caller. Keep
        # that handle so ExitCode remains available after the direct process
        # exits.
        $null = $process.Handle
        # Start-Process -Wait waits for the entire descendant process tree on
        # Windows. Toolchains can leave a helper alive after the command has
        # already returned, which would prevent the remaining checks and final
        # report from being collected. WaitForExit observes the launched check
        # itself; its exit code remains the authoritative gate result.
        $process.WaitForExit()
        $exitCode = $process.ExitCode
    }
    catch {
        $launchError = "The check could not be launched."
        $launchError | Set-Content -LiteralPath $stderrPath -Encoding UTF8
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
    $finish = (Get-Date).ToUniversalTime()
    $passed = $exitCode -eq 0
    $marker = if ($passed) { "PASS" } else { "FAIL" }
    Write-Host "[$marker] $Id"
    $checks.Add([ordered]@{
        id = $Id
        status = if ($passed) { "pass" } else { "fail" }
        executable = (Split-Path -Leaf $Executable)
        arguments = @($Arguments)
        working_directory = $WorkingDirectory.Substring($repositoryPath.Length).TrimStart("\").Replace("\", "/")
        started_at = $begin.ToString("o")
        completed_at = $finish.ToString("o")
        duration_ms = [long]($finish - $begin).TotalMilliseconds
        exit_code = $exitCode
        failure_summary = $launchError
        stdout = Get-SteinLogRecord -Path $stdoutPath
        stderr = Get-SteinLogRecord -Path $stderrPath
    })
}

function Add-SteinNotRunCheck {
    param(
        [Parameter(Mandatory = $true)][string] $Id,
        [Parameter(Mandatory = $true)][string] $Reason
    )

    Write-Host "[NOT RUN] $Id"
    $checks.Add([ordered]@{
        id = $Id
        status = "not_run"
        reason = $Reason
    })
}

$originalCoreHash = $env:STEIN_CORE_EXECUTABLE_SHA256
$originalFamily = $env:STEIN_PRODUCTION_PACKAGE_FAMILY_NAME
$originalBrokerAumid = $env:STEIN_PRODUCTION_BROKER_AUMID
$originalEdgeExtensionId = $env:STEIN_EDGE_EXTENSION_ID
$originalEdgePublisher = $env:STEIN_EDGE_PUBLISHER_SHA256
$originalEdgeHostPublisher = $env:STEIN_EDGE_HOST_PUBLISHER_SHA256
try {
    # These are compile-only, production-shaped synthetic values. They are not
    # an installed identity and cannot satisfy the private-client gate.
    $env:STEIN_CORE_EXECUTABLE_SHA256 = "1111111111111111111111111111111111111111111111111111111111111111"
    $env:STEIN_PRODUCTION_PACKAGE_FAMILY_NAME = "STEIN.PersonalIntelligence_123456789abcd"
    $env:STEIN_PRODUCTION_BROKER_AUMID = "$($env:STEIN_PRODUCTION_PACKAGE_FAMILY_NAME)!PrivateBroker"
    $env:STEIN_EDGE_EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
    $env:STEIN_EDGE_PUBLISHER_SHA256 = "2222222222222222222222222222222222222222222222222222222222222222"
    $env:STEIN_EDGE_HOST_PUBLISHER_SHA256 = "3333333333333333333333333333333333333333333333333333333333333333"

    $cargo = (Get-Command "cargo.exe" -ErrorAction Stop).Source
    $pnpm = (Get-Command "pnpm.cmd" -ErrorAction Stop).Source
    $powershell = (Get-Command "powershell.exe" -ErrorAction Stop).Source

    Invoke-SteinSourceCheck -Id "rust-format" -Executable $cargo `
        -Arguments @("fmt", "--all", "--", "--check") -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck -Id "rust-check" -Executable $cargo `
        -Arguments @("check", "--workspace", "--all-targets", "--all-features") `
        -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck -Id "rust-clippy" -Executable $cargo `
        -Arguments @("clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings") `
        -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck -Id "rust-tests" -Executable $cargo `
        -Arguments @("test", "--workspace", "--all-targets", "--all-features") `
        -WorkingDirectory $repoRoot

    Invoke-SteinSourceCheck -Id "desktop-typecheck" -Executable $pnpm `
        -Arguments @("typecheck") -WorkingDirectory $desktopRoot
    Invoke-SteinSourceCheck -Id "desktop-lint" -Executable $pnpm `
        -Arguments @("lint") -WorkingDirectory $desktopRoot
    Invoke-SteinSourceCheck -Id "desktop-tests" -Executable $pnpm `
        -Arguments @("test") -WorkingDirectory $desktopRoot
    Invoke-SteinSourceCheck -Id "desktop-build" -Executable $pnpm `
        -Arguments @("build") -WorkingDirectory $desktopRoot

    Invoke-SteinSourceCheck -Id "edge-extension-tests" -Executable $pnpm `
        -Arguments @("test") -WorkingDirectory $edgeExtensionRoot
    Invoke-SteinSourceCheck -Id "edge-host-format" -Executable $cargo `
        -Arguments @("fmt", "--manifest-path", $edgeHostManifest, "--", "--check") `
        -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck -Id "edge-host-check" -Executable $cargo `
        -Arguments @(
            "check", "--manifest-path", $edgeHostManifest,
            "--all-targets", "--all-features"
        ) -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck -Id "edge-host-clippy" -Executable $cargo `
        -Arguments @(
            "clippy", "--manifest-path", $edgeHostManifest,
            "--all-targets", "--all-features", "--", "-D", "warnings"
        ) -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck -Id "edge-host-tests" -Executable $cargo `
        -Arguments @(
            "test", "--manifest-path", $edgeHostManifest,
            "--all-targets", "--all-features"
        ) -WorkingDirectory $repoRoot

    Invoke-SteinSourceCheck -Id "boundary-contract" -Executable $powershell `
        -Arguments @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", (Join-Path $repoRoot "scripts\windows\check-boundaries.ps1"),
            "-Json"
        ) -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck -Id "msix-static-contract" -Executable $powershell `
        -Arguments @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", (Join-Path $repoRoot "packaging\windows-msix\Test-Static.ps1")
        ) -WorkingDirectory $repoRoot

    Invoke-SteinSourceCheck -Id "release-workspace" -Executable $cargo `
        -Arguments @("build", "--workspace", "--release") -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck -Id "release-production-core" -Executable $cargo `
        -Arguments @(
            "build", "--release", "-p", "stein-core-daemon",
            "--features", "production-private-endpoint"
        ) -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck -Id "release-edge-host" -Executable $cargo `
        -Arguments @(
            "build", "--release", "--manifest-path", $edgeHostManifest,
            "--features", "production-edge-host"
        ) -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck -Id "release-tauri-no-bundle" -Executable $pnpm `
        -Arguments @("exec", "tauri", "build", "--no-bundle") -WorkingDirectory $desktopRoot

    if ($IncludeInteractiveNative) {
        Invoke-SteinSourceCheck -Id "windows-native-ignored-fixtures" -Executable $cargo `
            -Arguments @(
                "test", "-p", "stein-platform-windows", "--all-features",
                "--", "--ignored", "--test-threads=1"
            ) -WorkingDirectory $repoRoot
    }
    else {
        Add-SteinNotRunCheck `
            -Id "windows-native-ignored-fixtures" `
            -Reason "Requires explicit -IncludeInteractiveNative consent; may show native UI and create synthetic OS resources that tests then remove."
    }
}
finally {
    $env:STEIN_CORE_EXECUTABLE_SHA256 = $originalCoreHash
    $env:STEIN_PRODUCTION_PACKAGE_FAMILY_NAME = $originalFamily
    $env:STEIN_PRODUCTION_BROKER_AUMID = $originalBrokerAumid
    $env:STEIN_EDGE_EXTENSION_ID = $originalEdgeExtensionId
    $env:STEIN_EDGE_PUBLISHER_SHA256 = $originalEdgePublisher
    $env:STEIN_EDGE_HOST_PUBLISHER_SHA256 = $originalEdgeHostPublisher
}

$completedAt = (Get-Date).ToUniversalTime()
$failed = @($checks | Where-Object { $_.status -eq "fail" })
$notRun = @($checks | Where-Object { $_.status -eq "not_run" })
$report = [ordered]@{
    schema_version = 1
    claim = "source_verification_only"
    installed_or_signed_evidence = $false
    passed = $failed.Count -eq 0
    complete_acceptance = $false
    started_at = $startedAt.ToString("o")
    completed_at = $completedAt.ToString("o")
    host = [ordered]@{
        os_version = [Environment]::OSVersion.VersionString
        process_architecture = $env:PROCESSOR_ARCHITECTURE
        elevated = [Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    checks = @($checks | ForEach-Object { $_ })
    summary = [ordered]@{
        pass = @($checks | Where-Object { $_.status -eq "pass" }).Count
        fail = $failed.Count
        not_run = $notRun.Count
    }
}
$reportPath = Join-Path $evidencePath "source-verification.json"
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Host "Source verification report: $reportPath"

if ($failed.Count -ne 0) {
    exit 1
}
