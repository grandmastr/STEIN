[CmdletBinding()]
param(
    [string] $EvidenceRoot,

    [switch] $IncludeInteractiveNative
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
if ($IncludeInteractiveNative) {
    throw "-IncludeInteractiveNative is frozen until a versioned closed native-fixture receipt validator exists."
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..")).Path
$desktopRoot = Join-Path $repoRoot "apps\desktop"
$edgeExtensionRoot = Join-Path $repoRoot "extensions\edge"
$edgeHostManifest = Join-Path $repoRoot "apps\edge-native-host\Cargo.toml"

function Get-SteinSourceBootstrapStreamSha256 {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream] $Stream,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw $FailureCode
    }
    try {
        $Stream.Position = 0
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            return [BitConverter]::ToString($sha256.ComputeHash($Stream)).
                Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
    }
    catch {
        throw $FailureCode
    }
    finally {
        if ($Stream.CanSeek) {
            $Stream.Position = 0
        }
    }
}

function Open-SteinSourceBootstrapBinding {
    param(
        [Parameter(Mandatory = $true)][string] $Role,
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $RepositoryRoot
    )

    $repository = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $prefix = "$repository$([IO.Path]::DirectorySeparatorChar)"
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'source_bootstrap_source_invalid'
    }
    $probe = Split-Path -Parent $resolved
    while ($probe.Length -ge $repository.Length) {
        $ancestor = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $ancestor.PSIsContainer -or
            (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'source_bootstrap_source_invalid'
        }
        if ([string]::Equals(
                $probe,
                $repository,
                [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $probe, [StringComparison]::OrdinalIgnoreCase) -or
            -not $parent.StartsWith($repository, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'source_bootstrap_source_invalid'
        }
        $probe = $parent
    }
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -lt 1 -or $item.Length -gt 16777216) {
        throw 'source_bootstrap_source_invalid'
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ([long]$stream.Length -ne [long]$item.Length) {
            throw 'source_bootstrap_source_invalid'
        }
        $digest = Get-SteinSourceBootstrapStreamSha256 `
            -Stream $stream `
            -FailureCode 'source_bootstrap_source_invalid'
        return [pscustomobject]@{
            record = [pscustomobject]@{
                role = $Role
                path = $item.FullName.Substring($repository.Length + 1).Replace('\', '/')
                size = [long]$item.Length
                sha256 = $digest
            }
            full_path = $item.FullName
            stream = $stream
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Assert-SteinSourceBootstrapSourcesStable {
    $bindings = @($script:SteinSourceBootstrapBindings)
    $definitions = @($script:SteinSourceBootstrapDefinitions)
    if ($bindings.Count -ne 4 -or $definitions.Count -ne 4) {
        throw 'source_bootstrap_source_changed'
    }
    for ($index = 0; $index -lt $bindings.Count; $index++) {
        $binding = $bindings[$index]
        $definition = $definitions[$index]
        $item = Get-Item -LiteralPath $binding.full_path -Force -ErrorAction Stop
        if ([string]$binding.record.role -cne [string]$definition.role -or
            [string]$binding.full_path -cne [string]$definition.path -or
            [string]$binding.record.path -cne
                [string]$definition.path.Substring(
                    $repoRoot.Length + 1).Replace('\', '/') -or
            $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            [long]$item.Length -ne [long]$binding.record.size -or
            [long]$binding.stream.Length -ne [long]$binding.record.size -or
            (Get-SteinSourceBootstrapStreamSha256 `
                -Stream $binding.stream `
                -FailureCode 'source_bootstrap_source_changed') -cne
                [string]$binding.record.sha256) {
            throw 'source_bootstrap_source_changed'
        }
    }
    return @($bindings | ForEach-Object { $_.record })
}

$script:SteinSourceBootstrapDefinitions = @(
        [pscustomobject]@{
            role = 'harness'
            path = $PSCommandPath
        },
        [pscustomobject]@{
            role = 'package-tools'
            path = (Join-Path $repoRoot 'packaging\windows-msix\PackageTools.ps1')
        },
        [pscustomobject]@{
            role = 'source-evidence'
            path = (Join-Path $PSScriptRoot 'Source-Evidence.ps1')
        },
        [pscustomobject]@{
            role = 'source-fixture-runner'
            path = (Join-Path $PSScriptRoot 'Run-Source-Fixture.ps1')
        }
) | Sort-Object role
$script:SteinSourceBootstrapBindings = @(
    $script:SteinSourceBootstrapDefinitions | ForEach-Object {
        Open-SteinSourceBootstrapBinding `
            -Role $_.role `
            -Path $_.path `
            -RepositoryRoot $repoRoot
    })
$sourceEvidenceBootstrapBinding = @($script:SteinSourceBootstrapBindings |
    Where-Object { [string]$_.record.role -ceq 'source-evidence' })
$sourceFixtureRunnerBootstrapBinding = @($script:SteinSourceBootstrapBindings |
    Where-Object { [string]$_.record.role -ceq 'source-fixture-runner' })
if ($sourceEvidenceBootstrapBinding.Count -ne 1 -or
    $sourceFixtureRunnerBootstrapBinding.Count -ne 1) {
    throw 'source_bootstrap_source_invalid'
}
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
. $sourceEvidenceBootstrapBinding[0].full_path
if ((Get-SteinSourceBootstrapStreamSha256 `
            -Stream $sourceEvidenceBootstrapBinding[0].stream `
            -FailureCode 'source_bootstrap_source_changed') -cne
        [string]$sourceEvidenceBootstrapBinding[0].record.sha256) {
    throw 'source_bootstrap_source_changed'
}
. $sourceFixtureRunnerBootstrapBinding[0].full_path -LibraryOnly
if ((Get-SteinSourceBootstrapStreamSha256 `
            -Stream $sourceFixtureRunnerBootstrapBinding[0].stream `
            -FailureCode 'source_bootstrap_source_changed') -cne
        [string]$sourceFixtureRunnerBootstrapBinding[0].record.sha256) {
    throw 'source_bootstrap_source_changed'
}

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

foreach ($tool in @(
        "cargo.exe", "rustc.exe", "rustup.exe", "node.exe", "pnpm.cmd", "git.exe")) {
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
    cargo = [string]@(Get-Command "cargo.exe" -CommandType Application -ErrorAction Stop)[0].Source
    rustc = [string]@(Get-Command "rustc.exe" -CommandType Application -ErrorAction Stop)[0].Source
    rustup = [string]@(Get-Command "rustup.exe" -CommandType Application -ErrorAction Stop)[0].Source
    node = [string]@(Get-Command "node.exe" -CommandType Application -ErrorAction Stop)[0].Source
    pnpm = [string]@(Get-Command "pnpm.cmd" -CommandType Application -ErrorAction Stop)[0].Source
    git = [string]@(Get-Command "git.exe" -CommandType Application -ErrorAction Stop)[0].Source
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

function Invoke-SteinSourceFixtureChecks {
    param(
        [Parameter(Mandatory = $true)][string] $PowerShellExecutable,
        [Parameter(Mandatory = $true)][string] $GitExecutable,
        [Parameter(Mandatory = $true)] $Provenance
    )

    $registryPath = Join-Path $PSScriptRoot "Source-Fixture-Registry.json"
    $registryRead = Read-SteinSourceFixtureLockedJson `
        -Path $registryPath `
        -MaximumBytes 1048576
    $null = Assert-SteinSourceFixtureRegistry -Registry $registryRead.value
    $fixtureGitBinding = Get-SteinSourceFixtureGitBinding `
        -LauncherExecutable $GitExecutable `
        -WorkingDirectory $repoRoot
    if ([string]$fixtureGitBinding.Record.executable_sha256 -cne
            [string]$Provenance.toolchain.git.executable_sha256 -or
        [string]$fixtureGitBinding.Record.resolved_executable_sha256 -cne
            [string]$Provenance.toolchain.git.resolved_executable_sha256 -or
        [string]$fixtureGitBinding.Record.version -cne
            [string]$Provenance.toolchain.git.version -or
        [string]$fixtureGitBinding.Record.resolved_version -cne
            [string]$Provenance.toolchain.git.resolved_version) {
        throw "source_fixture_git_provenance_mismatch"
    }
    $compilerEnvironment = Get-SteinSourceFixtureCompilerEnvironmentRecord `
        -RustupToolchain ([string]$Provenance.toolchain.cargo.rustup_toolchain) `
        -PathSha256 (Get-SteinSourceFixturePathSha256)
    $compilerEnvironmentSha256 = Get-SteinSourceEvidenceObjectDigest `
        -Value $compilerEnvironment
    $fixtureDirectory = Join-Path $evidencePath "source-fixtures"
    $fixtureRelativeDirectory = $fixtureDirectory.Substring(
        $repositoryPath.Length + 1).Replace("\", "/")
    $arguments = @(
        "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        "scripts/windows/phase2/Run-Source-Fixture.ps1", "-OutputDirectory",
        $fixtureRelativeDirectory)
    $launchArguments = @($arguments)
    $launchArguments[5] = [string]$sourceFixtureRunnerBootstrapBinding[0].full_path
    $stdoutPath = Join-Path $evidencePath "source-fixture-suite.stdout.txt"
    $stderrPath = Join-Path $evidencePath "source-fixture-suite.stderr.txt"
    $begin = (Get-Date).ToUniversalTime()
    $exitCode = -1
    $failureSummary = $null
    Write-Host "[RUN ] closed-source-fixture-suite"
    $process = $null
    try {
        $process = Start-Process `
            -FilePath $PowerShellExecutable `
            -ArgumentList $launchArguments `
            -WorkingDirectory $repoRoot `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath
        $null = $process.Handle
        $process.WaitForExit()
        $exitCode = [int]$process.ExitCode
    }
    catch {
        $failureSummary = "The closed source-fixture suite could not be launched."
        $failureSummary | Set-Content -LiteralPath $stderrPath -Encoding UTF8
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }

    $finish = (Get-Date).ToUniversalTime()
    $stdoutRecord = Get-SteinLogRecord -Path $stdoutPath
    $stderrRecord = Get-SteinLogRecord -Path $stderrPath
    $receiptReads = @{}
    $indexRead = $null
    if ($exitCode -eq 0) {
        try {
            $treeResult = Invoke-SteinSourceEvidenceProcess `
                -Executable ([string]$fixtureGitBinding.ResolvedPath) `
                -Arguments @("rev-parse", "--verify", "HEAD^{tree}") `
                -WorkingDirectory $repoRoot `
                -MaximumStandardOutputCharacters 256 `
                -MaximumStandardErrorCharacters 512
            $candidateTree = $treeResult.stdout.Trim()
            $candidateCommit = [string]$Provenance.repository.head_commit
            if ($candidateTree -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
                $candidateTree.Length -ne $candidateCommit.Length) {
                throw "source_fixture_candidate_tree_invalid"
            }
            $indexPath = Join-Path $fixtureDirectory "index.json"
            $indexRead = Read-SteinSourceFixtureLockedJson `
                -Path $indexPath `
                -MaximumBytes 1048576
            $null = Assert-SteinSourceFixtureIndex `
                -Index $indexRead.value `
                -Registry $registryRead.value `
                -ExpectedRegistrySha256 ([string]$registryRead.sha256) `
                -ExpectedCommit $candidateCommit `
                -ExpectedTree $candidateTree `
                -ExpectedGitLauncherVersion `
                    ([string]$Provenance.toolchain.git.version) `
                -ExpectedGitLauncherSha256 `
                    ([string]$Provenance.toolchain.git.executable_sha256) `
                -ExpectedGitResolvedVersion `
                    ([string]$Provenance.toolchain.git.resolved_version) `
                -ExpectedGitResolvedSha256 `
                    ([string]$Provenance.toolchain.git.resolved_executable_sha256)
            $indexByCheck = @{}
            foreach ($descriptor in @($indexRead.value.receipts)) {
                $indexByCheck[[string]$descriptor.source_check_id] = $descriptor
            }
            foreach ($fixture in @($registryRead.value.fixtures)) {
                $sourceCheckId = [string]$fixture.source_check_id
                if (-not $indexByCheck.ContainsKey($sourceCheckId)) {
                    throw "source_fixture_index_missing_receipt"
                }
                $descriptor = $indexByCheck[$sourceCheckId]
                $receiptPath = Join-Path $fixtureDirectory ([string]$descriptor.path)
                $receiptRead = Read-SteinSourceFixtureLockedJson `
                    -Path $receiptPath `
                    -MaximumBytes 4194304
                if ([long]$receiptRead.size -ne [long]$descriptor.size -or
                    [string]$receiptRead.sha256 -cne [string]$descriptor.sha256) {
                    throw "source_fixture_receipt_descriptor_mismatch"
                }
                $null = Assert-SteinSourceFixtureReceipt `
                    -Receipt $receiptRead.value `
                    -Fixture $fixture `
                    -ExpectedRegistrySha256 ([string]$registryRead.sha256) `
                    -ExpectedCommit $candidateCommit `
                    -ExpectedTree $candidateTree `
                    -ExpectedCargoLauncherSha256 `
                        ([string]$Provenance.toolchain.cargo.executable_sha256) `
                    -ExpectedCargoResolvedSha256 `
                        ([string]$Provenance.toolchain.cargo.resolved_executable_sha256) `
                    -ExpectedRustcLauncherSha256 `
                        ([string]$Provenance.toolchain.rustc.executable_sha256) `
                    -ExpectedRustcResolvedSha256 `
                        ([string]$Provenance.toolchain.rustc.resolved_executable_sha256) `
                    -ExpectedRustupToolchain `
                        ([string]$Provenance.toolchain.cargo.rustup_toolchain) `
                    -ExpectedGitLauncherVersion `
                        ([string]$Provenance.toolchain.git.version) `
                    -ExpectedGitLauncherSha256 `
                        ([string]$Provenance.toolchain.git.executable_sha256) `
                    -ExpectedGitResolvedVersion `
                        ([string]$Provenance.toolchain.git.resolved_version) `
                    -ExpectedGitResolvedSha256 `
                        ([string]$Provenance.toolchain.git.resolved_executable_sha256) `
                    -ExpectedCompilerEnvironmentSha256 $compilerEnvironmentSha256
                $receiptReads[$sourceCheckId] = [pscustomobject]@{
                    Read = $receiptRead
                    Descriptor = $descriptor
                    Path = $receiptPath
                }
            }
            $actualFixtureFiles = @(Get-ChildItem -LiteralPath $fixtureDirectory -Force)
            if ($actualFixtureFiles.Count -ne (@($registryRead.value.fixtures).Count + 1) -or
                @($actualFixtureFiles | Where-Object {
                        $_.PSIsContainer -or
                        (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
                    }).Count -ne 0) {
                throw "source_fixture_output_set_invalid"
            }
        }
        catch {
            $exitCode = 1
            $failureSummary = "The closed source-fixture receipt set is invalid."
        }
    }
    elseif ($null -eq $failureSummary) {
        $failureSummary = "The closed source-fixture suite failed."
    }

    foreach ($fixture in @($registryRead.value.fixtures)) {
        $sourceCheckId = [string]$fixture.source_check_id
        $passed = $exitCode -eq 0 -and $receiptReads.ContainsKey($sourceCheckId)
        $marker = if ($passed) { "PASS" } else { "FAIL" }
        Write-Host "[$marker] $sourceCheckId"
        $record = [ordered]@{
            id = $sourceCheckId
            status = if ($passed) { "pass" } else { "fail" }
            executable = "powershell.exe"
            arguments = $arguments
            working_directory = "."
            started_at = $begin.ToString("o")
            completed_at = $finish.ToString("o")
            duration_ms = [long]($finish - $begin).TotalMilliseconds
            exit_code = $exitCode
            failure_summary = if ($passed) { $null } else { $failureSummary }
            stdout = $stdoutRecord
            stderr = $stderrRecord
        }
        if ($passed) {
            $receipt = $receiptReads[$sourceCheckId]
            $record.source_fixture_receipt = $receipt.Read.value
            $record.source_fixture_receipt_artifact = [ordered]@{
                path = "source-fixtures/$([string]$receipt.Descriptor.path)"
                size = [long]$receipt.Read.size
                sha256 = [string]$receipt.Read.sha256
            }
            $record.source_fixture_suite_index = [ordered]@{
                path = "source-fixtures/index.json"
                size = [long]$indexRead.size
                sha256 = [string]$indexRead.sha256
            }
        }
        $checks.Add($record)
    }
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
    Invoke-SteinSourceCheck -Id "no-leaks-scanner-static" -Executable $powershell `
        -Arguments @(
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", (Join-Path $repoRoot "scripts\windows\phase2\Test-ScanNoLeaks.ps1")
        ) -WorkingDirectory $repoRoot
    Add-SteinNotRunCheck `
        -Id "no-leaks-producer-workflow" `
        -Reason "Candidate-owned installed artifact producer is not implemented."
    Add-SteinNotRunCheck `
        -Id "native-toolchain-provenance" `
        -Reason "Authenticated Rust/rustup/Git/VS/MSVC/Windows SDK/package-tool payload, runtime, sysroot, library, and linker provenance is not implemented."
    Add-SteinNotRunCheck `
        -Id "pinned-clean-build-environment" `
        -Reason "Authenticated immutable candidate input and fresh dependency, build, and output isolation are not implemented for every source check."
    Add-SteinNotRunCheck `
        -Id "portable-runner-attestation" `
        -Reason "Authenticated GitHub artifact attestation tied to repository, workflow, commit, and artifact digest is not implemented."
    Add-SteinNotRunCheck `
        -Id "source-report-command-provenance" `
        -Reason "Independent closed command/argument/working-directory provenance for every source-report check is not implemented."
    Invoke-SteinSourceFixtureChecks `
        -PowerShellExecutable $powershell `
        -GitExecutable ([string]$toolExecutables["git"]) `
        -Provenance $initialProvenance
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

    Add-SteinNotRunCheck `
        -Id "windows-native-ignored-fixtures" `
        -Reason "Requires explicit native-fixture workflow support; interactive native fixtures remain unimplemented source evidence."
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
        (Join-Path $PSScriptRoot "Source-Fixture-Registry.json"),
        (Join-Path $PSScriptRoot "Run-Source-Fixture.ps1"),
        (Join-Path $PSScriptRoot "Test-SourceFixture.ps1"),
        (Join-Path $PSScriptRoot "Test-VerifySource.ps1"),
        (Join-Path $PSScriptRoot "Review-Installed.ps1"),
        (Join-Path $PSScriptRoot "Review-Installed.cmd"),
        (Join-Path $PSScriptRoot "Test-ReviewInstalled.ps1"),
        (Join-Path $PSScriptRoot "Common.ps1"),
        (Join-Path $PSScriptRoot "Evidence-Spec.json"),
        (Join-Path $PSScriptRoot "Evidence-Contract.ps1"),
        (Join-Path $PSScriptRoot "Scan-NoLeaks.ps1"),
        (Join-Path $PSScriptRoot "Scan-NoLeaks.cmd"),
        (Join-Path $PSScriptRoot "Test-ScanNoLeaks.ps1"),
        (Join-Path $repoRoot "packaging\windows-msix\PackageTools.ps1")
    )
foreach ($binding in $script:SteinSourceBootstrapBindings) {
    $generatorRecord = @($generator.files | Where-Object {
            [string]$_.path -ceq [string]$binding.record.path
        })
    if ($generatorRecord.Count -ne 1 -or
        [long]$generatorRecord[0].size -ne [long]$binding.record.size -or
        [string]$generatorRecord[0].sha256 -cne [string]$binding.record.sha256) {
        throw 'source_generator_differs_from_loaded_bootstrap'
    }
}
$null = Assert-SteinSourceBootstrapSourcesStable
$null = Assert-SteinSourceFixtureBootstrapSourcesStable
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
$null = Assert-SteinSourceBootstrapSourcesStable
$null = Assert-SteinSourceFixtureBootstrapSourcesStable
$sourceBootstrapStreams = @(
    @($script:SteinSourceBootstrapBindings) +
    @($script:SteinSourceFixtureBootstrapBindings) |
        ForEach-Object { $_.stream })
foreach ($stream in $sourceBootstrapStreams) {
    $stream.Dispose()
}
Write-Host "Source verification report: $reportPath"
Write-Host "Source evidence root digest: $($rootAnchor.root_digest_sha256)"

if ($failed.Count -ne 0) {
    exit 1
}
