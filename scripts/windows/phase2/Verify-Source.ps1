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
. (Join-Path $PSScriptRoot "Source-Evidence.ps1")

function Resolve-SteinSourceWindowsPowerShell {
    $systemRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($systemRoot)) {
        throw "The exact Windows PowerShell host is unavailable."
    }
    $systemRoot = [IO.Path]::GetFullPath($systemRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $candidate = [IO.Path]::GetFullPath(
        (Join-Path $systemRoot "WindowsPowerShell\v1.0\powershell.exe"))
    $prefix = "$systemRoot$([IO.Path]::DirectorySeparatorChar)"
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The exact Windows PowerShell host is unavailable."
    }
    $probe = Split-Path -Parent $candidate
    while ($probe.Length -ge $systemRoot.Length) {
        $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "The exact Windows PowerShell host is unavailable."
        }
        if ([string]::Equals($probe, $systemRoot, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            throw "The exact Windows PowerShell host is unavailable."
        }
        $probe = $parent
    }
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0) {
        throw "The exact Windows PowerShell host is unavailable."
    }
    return $item.FullName
}

function Resolve-SteinSourcePwsh {
    $command = Get-Command "pwsh.exe" -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    if ($null -eq $command -or [string]::IsNullOrWhiteSpace([string]$command.Source)) {
        throw "The required pwsh source-verification host is unavailable."
    }
    $candidate = [IO.Path]::GetFullPath([string]$command.Source)
    if ([IO.Path]::GetFileName($candidate) -cne "pwsh.exe") {
        throw "The required pwsh source-verification host is invalid."
    }
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0) {
        throw "The required pwsh source-verification host is invalid."
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $item.FullName -ErrorAction Stop
    $expectedSubject =
        "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
    if ([string]$signature.Status -cne "Valid" -or
        $null -eq $signature.SignerCertificate -or
        [string]$signature.SignerCertificate.Subject -cne $expectedSubject) {
        throw "The required pwsh source-verification host has an invalid publisher signature."
    }
    $probe = $item.Directory
    while ($null -ne $probe) {
        if (($probe.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The required pwsh source-verification host is invalid."
        }
        $probe = $probe.Parent
    }
    return $item.FullName
}

if ($env:OS -cne "Windows_NT") {
    throw "Phase 2 source verification must run with native Windows tools."
}

foreach ($tool in @("cargo.exe", "rustc.exe", "node.exe", "pnpm.cmd", "git.exe")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required source-verification tool is unavailable: $tool"
    }
}
$powershell = Resolve-SteinSourceWindowsPowerShell
$pwsh = Resolve-SteinSourcePwsh

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
$toolExecutables = [ordered]@{
    cargo = (Get-Command "cargo.exe" -ErrorAction Stop).Source
    rustc = (Get-Command "rustc.exe" -ErrorAction Stop).Source
    node = (Get-Command "node.exe" -ErrorAction Stop).Source
    pnpm = (Get-Command "pnpm.cmd" -ErrorAction Stop).Source
    git = (Get-Command "git.exe" -ErrorAction Stop).Source
    pwsh = $pwsh
}
$initialProvenance = Get-SteinSourceEvidenceProvenance `
    -RepositoryRoot $repoRoot `
    -ToolExecutables $toolExecutables
$initialProvenanceDigest = Get-SteinSourceEvidenceObjectDigest -Value $initialProvenance

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
$originalEdgeExtensionVersion = $env:STEIN_EDGE_EXTENSION_VERSION
$originalEdgePublisher = $env:STEIN_EDGE_PUBLISHER_SHA256
$originalEdgeHostPublisher = $env:STEIN_EDGE_HOST_PUBLISHER_SHA256
try {
    # These are compile-only, production-shaped synthetic values. They are not
    # an installed identity and cannot satisfy the private-client gate.
    $env:STEIN_CORE_EXECUTABLE_SHA256 = "1111111111111111111111111111111111111111111111111111111111111111"
    $env:STEIN_PRODUCTION_PACKAGE_FAMILY_NAME = "STEIN.PersonalIntelligence_123456789abcd"
    $env:STEIN_PRODUCTION_BROKER_AUMID = "$($env:STEIN_PRODUCTION_PACKAGE_FAMILY_NAME)!PrivateBroker"
    $env:STEIN_EDGE_EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
    $syntheticEdgeExtensionVersion = "0.1.0"
    if ($syntheticEdgeExtensionVersion.Length -gt 32 -or
        $syntheticEdgeExtensionVersion -notmatch `
            "^(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){0,3}$") {
        throw "The synthetic Edge extension version is outside the production build contract."
    }
    $env:STEIN_EDGE_EXTENSION_VERSION = $syntheticEdgeExtensionVersion
    $env:STEIN_EDGE_PUBLISHER_SHA256 = "2222222222222222222222222222222222222222222222222222222222222222"
    $env:STEIN_EDGE_HOST_PUBLISHER_SHA256 = "3333333333333333333333333333333333333333333333333333333333333333"

    $cargo = [string]$toolExecutables["cargo"]
    $pnpm = [string]$toolExecutables["pnpm"]
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
    Invoke-SteinSourceCheck -Id "source-evidence-contract" -Executable $powershell `
        -Arguments @(
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", (Join-Path $repoRoot "scripts\windows\phase2\Test-VerifySource.ps1")
        ) -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck -Id "installed-evidence-harness-static" -Executable $powershell `
        -Arguments @(
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", (Join-Path $repoRoot "scripts\windows\phase2\Test-VerifyInstalled.ps1")
        ) -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck `
        -Id "installed-reviewer-windows-powershell-contract" `
        -Executable $powershell `
        -Arguments @(
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", (Join-Path $repoRoot "scripts\windows\phase2\Test-ReviewInstalled.ps1")
        ) `
        -WorkingDirectory $repoRoot
    Invoke-SteinSourceCheck `
        -Id "installed-reviewer-pwsh-contract" `
        -Executable $pwsh `
        -Arguments @(
            "-NoLogo",
            "-NoProfile",
            "-File", (Join-Path $repoRoot "scripts\windows\phase2\Test-ReviewInstalled.ps1")
        ) `
        -WorkingDirectory $repoRoot
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
            "--features", "production-private-endpoint,production-edge-producer"
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
    $env:STEIN_EDGE_EXTENSION_VERSION = $originalEdgeExtensionVersion
    $env:STEIN_EDGE_PUBLISHER_SHA256 = $originalEdgePublisher
    $env:STEIN_EDGE_HOST_PUBLISHER_SHA256 = $originalEdgeHostPublisher
}

$completedProvenance = Get-SteinSourceEvidenceProvenance `
    -RepositoryRoot $repoRoot `
    -ToolExecutables $toolExecutables
$completedProvenanceDigest = Get-SteinSourceEvidenceObjectDigest -Value $completedProvenance
$provenanceStable = $initialProvenanceDigest -ceq $completedProvenanceDigest
$checks.Add([ordered]@{
    id = "source-provenance-stability"
    status = if ($provenanceStable) { "pass" } else { "fail" }
    initial_provenance_sha256 = $initialProvenanceDigest
    completed_provenance_sha256 = $completedProvenanceDigest
    failure_summary = if ($provenanceStable) {
        $null
    }
    else {
        "Repository or source-verification toolchain state changed during the run."
    }
})
$generator = Get-SteinSourceEvidenceGenerator `
    -RepositoryRoot $repoRoot `
    -Paths @(
        (Join-Path $PSScriptRoot "Verify-Source.ps1"),
        (Join-Path $PSScriptRoot "Verify-Source.cmd"),
        (Join-Path $PSScriptRoot "Source-Evidence.ps1"),
        (Join-Path $PSScriptRoot "Test-VerifySource.ps1"),
        (Join-Path $PSScriptRoot "Review-Installed.ps1"),
        (Join-Path $PSScriptRoot "Review-Installed.cmd"),
        (Join-Path $PSScriptRoot "Test-ReviewInstalled.ps1"),
        (Join-Path $PSScriptRoot "Common.ps1"),
        (Join-Path $repoRoot "packaging\windows-msix\PackageTools.ps1")
    )
$checksDigest = Get-SteinSourceEvidenceObjectDigest -Value @($checks | ForEach-Object { $_ })
$completedAt = (Get-Date).ToUniversalTime()
$failed = @($checks | Where-Object { $_.status -eq "fail" })
$notRun = @($checks | Where-Object { $_.status -eq "not_run" })
$report = [ordered]@{
    schema_version = 2
    claim = "source_verification_only"
    installed_or_signed_evidence = $false
    passed = $failed.Count -eq 0
    complete_acceptance = $false
    started_at = $startedAt.ToString("o")
    completed_at = $completedAt.ToString("o")
    host = [ordered]@{
        os_version = [Environment]::OSVersion.VersionString
        process_architecture = $env:PROCESSOR_ARCHITECTURE
        powershell_edition = [string]$PSVersionTable.PSEdition
        powershell_version = $PSVersionTable.PSVersion.ToString()
        elevated = [Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    provenance = $completedProvenance
    integrity = [ordered]@{
        semantics = "content_integrity_only_not_authentication"
        generator = $generator
        provenance_sha256 = $completedProvenanceDigest
        checks_sha256 = $checksDigest
        root_anchor_path = "root-anchor.json"
    }
    checks = @($checks | ForEach-Object { $_ })
    summary = [ordered]@{
        pass = @($checks | Where-Object { $_.status -eq "pass" }).Count
        fail = $failed.Count
        not_run = $notRun.Count
    }
}
$reportPath = Join-Path $evidencePath "source-verification.json"
Write-SteinSourceEvidenceJson -Path $reportPath -Value $report -Depth 20
$rootAnchor = New-SteinSourceEvidenceRootAnchor `
    -ReportPath $reportPath `
    -GeneratorDigest $generator.digest_sha256 `
    -ProvenanceDigest $completedProvenanceDigest `
    -ChecksDigest $checksDigest
$rootAnchorPath = Join-Path $evidencePath "root-anchor.json"
Write-SteinSourceEvidenceJson -Path $rootAnchorPath -Value $rootAnchor -Depth 8
Write-Host "Source verification report: $reportPath"
Write-Host "Source evidence root digest: $($rootAnchor.root_digest_sha256)"

if ($failed.Count -ne 0) {
    exit 1
}
