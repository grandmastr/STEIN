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
    if ($bindings.Count -ne 6 -or $definitions.Count -ne 6) {
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
            role = 'source-command-registry'
            path = (Join-Path $PSScriptRoot 'Source-Command-Registry.json')
        },
        [pscustomobject]@{
            role = 'source-command-runner'
            path = (Join-Path $PSScriptRoot 'Run-Source-Check.ps1')
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
$sourceCommandRegistryBootstrapBinding = @($script:SteinSourceBootstrapBindings |
    Where-Object { [string]$_.record.role -ceq 'source-command-registry' })
$sourceCommandRunnerBootstrapBinding = @($script:SteinSourceBootstrapBindings |
    Where-Object { [string]$_.record.role -ceq 'source-command-runner' })
if ($sourceEvidenceBootstrapBinding.Count -ne 1 -or
    $sourceFixtureRunnerBootstrapBinding.Count -ne 1 -or
    $sourceCommandRegistryBootstrapBinding.Count -ne 1 -or
    $sourceCommandRunnerBootstrapBinding.Count -ne 1) {
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
$sourceCommandRegistryRead = Read-SteinSourceEvidenceCommandRegistry `
    -RepositoryRoot $repoRoot `
    -RegistryPath ([string]$sourceCommandRegistryBootstrapBinding[0].full_path)
if ([long]$sourceCommandRegistryRead.Size -ne
        [long]$sourceCommandRegistryBootstrapBinding[0].record.size -or
    [string]$sourceCommandRegistryRead.Sha256 -cne
        [string]$sourceCommandRegistryBootstrapBinding[0].record.sha256) {
    $sourceCommandRegistryRead.Stream.Dispose()
    throw 'source_command_registry_bootstrap_mismatch'
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
$gitLauncherPath = [IO.Path]::GetFullPath([string]$toolExecutables['git'])
$gitInstallationRoot = [IO.Path]::GetFullPath((Split-Path -Parent (
            Split-Path -Parent $gitLauncherPath)))
$gitResolvedPath = [IO.Path]::GetFullPath((Join-Path `
            $gitInstallationRoot 'mingw64\bin\git.exe'))
if ([IO.Path]::GetFileName($gitLauncherPath) -cne 'git.exe' -or
    [IO.Path]::GetFileName((Split-Path -Parent $gitLauncherPath)) -cne 'cmd' -or
    -not $gitResolvedPath.StartsWith(
        "$gitInstallationRoot$([IO.Path]::DirectorySeparatorChar)",
        [StringComparison]::OrdinalIgnoreCase) -or
    (Get-SteinSourceEvidenceSha256 -Path $gitLauncherPath) -cne
        [string]$initialProvenance.toolchain.git.executable_sha256 -or
    (Get-SteinSourceEvidenceSha256 -Path $gitResolvedPath) -cne
        [string]$initialProvenance.toolchain.git.resolved_executable_sha256) {
    throw 'source_command_git_provenance_mismatch'
}
$candidateTreeResult = Invoke-SteinSourceEvidenceProcess `
    -Executable ([string]$toolExecutables['git']) `
    -Arguments @('rev-parse', '--verify', 'HEAD^{tree}') `
    -WorkingDirectory $repoRoot `
    -MaximumStandardOutputCharacters 256 `
    -MaximumStandardErrorCharacters 1024
$candidateTree = $candidateTreeResult.stdout.Trim()
if ($candidateTree -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
    $candidateTree.Length -ne
        ([string]$initialProvenance.repository.head_commit).Length) {
    throw 'source_command_candidate_tree_invalid'
}
$sourceCommandToolExecutables = [ordered]@{
    cargo = [string]$toolExecutables['cargo']
    pnpm = [string]$toolExecutables['pnpm']
    windows_powershell = $powershell
    pwsh = $pwsh
    git_launcher = $gitLauncherPath
    git_resolved = $gitResolvedPath
}
$evidenceRelativePath = $evidencePath.Substring(
    $repositoryPath.Length + 1).Replace('\', '/')

function Invoke-SteinRegisteredSourceCommand {
    param([Parameter(Mandatory = $true)][string] $Id)

    Write-Host "[RUN ] $Id"
    $result = Invoke-SteinSourceEvidenceProcess `
        -Executable $powershell `
        -Arguments @(
            '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
            [string]$sourceCommandRunnerBootstrapBinding[0].record.path,
            '-CheckId', $Id,
            '-CandidateCommit', [string]$initialProvenance.repository.head_commit,
            '-CandidateTree', $candidateTree,
            '-ExpectedRegistrySha256', [string]$sourceCommandRegistryRead.Sha256,
            '-ExpectedGitLauncherPath', $gitLauncherPath,
            '-ExpectedGitLauncherSha256',
                [string]$initialProvenance.toolchain.git.executable_sha256,
            '-ExpectedGitResolvedSha256',
                [string]$initialProvenance.toolchain.git.resolved_executable_sha256,
            '-EvidenceRoot', $evidenceRelativePath) `
        -WorkingDirectory $repoRoot `
        -AllowedExitCodes @(0, 1) `
        -MaximumStandardOutputCharacters 1048576 `
        -MaximumStandardErrorCharacters 1048576
    $marker = if ([int]$result.exit_code -eq 0) { 'PASS' } else { 'FAIL' }
    Write-Host "[$marker] $Id"
    return [int]$result.exit_code
}

function New-SteinRegisteredSourceCheckRecord {
    param([Parameter(Mandatory = $true)] $ValidatedReceipt)

    $receipt = $ValidatedReceipt.receipt
    $descriptor = $ValidatedReceipt.descriptor
    $execution = $receipt.execution
    $command = $receipt.command
    $status = [string]$receipt.status
    $failureSummary = if ($status -ceq 'pass') {
        $null
    }
    else {
        "The registered source check failed: $([string]$execution.failure_code)."
    }
    return [ordered]@{
        id = [string]$receipt.check_id
        status = $status
        executable = [string]$command.executable_name
        arguments = @($command.arguments | ForEach-Object { [string]$_ })
        working_directory = [string]$command.working_directory
        started_at = [string]$execution.started_at
        completed_at = [string]$execution.completed_at
        duration_ms = [long]$execution.duration_ms
        exit_code = [long]$execution.exit_code
        failure_summary = $failureSummary
        stdout = [ordered]@{
            path = "$evidenceRelativePath/$([string]$execution.stdout.path)"
            size = [long]$execution.stdout.size
            sha256 = [string]$execution.stdout.sha256
        }
        stderr = [ordered]@{
            path = "$evidenceRelativePath/$([string]$execution.stderr.path)"
            size = [long]$execution.stderr.size
            sha256 = [string]$execution.stderr.sha256
        }
        source_command_receipt = $receipt
        source_command_receipt_artifact = [ordered]@{
            path = "source-command-receipts/$([string]$descriptor.path)"
            size = [long]$descriptor.size
            sha256 = [string]$descriptor.sha256
        }
    }
}

function Add-SteinRegisteredSourceFixtureEvidence {
    param(
        [Parameter(Mandatory = $true)][Collections.IDictionary] $RecordsById,
        [Parameter(Mandatory = $true)] $Provenance
    )

    $registryPath = Join-Path $PSScriptRoot 'Source-Fixture-Registry.json'
    $registryRead = Read-SteinSourceFixtureLockedJson `
        -Path $registryPath `
        -MaximumBytes 1048576
    $null = Assert-SteinSourceFixtureRegistry -Registry $registryRead.value
    $fixtureGitBinding = Get-SteinSourceFixtureGitBinding `
        -LauncherExecutable ([string]$toolExecutables['git']) `
        -WorkingDirectory $repoRoot
    if ([string]$fixtureGitBinding.Record.executable_sha256 -cne
            [string]$Provenance.toolchain.git.executable_sha256 -or
        [string]$fixtureGitBinding.Record.resolved_executable_sha256 -cne
            [string]$Provenance.toolchain.git.resolved_executable_sha256 -or
        [string]$fixtureGitBinding.Record.version -cne
            [string]$Provenance.toolchain.git.version -or
        [string]$fixtureGitBinding.Record.resolved_version -cne
            [string]$Provenance.toolchain.git.resolved_version) {
        throw 'source_fixture_git_provenance_mismatch'
    }
    $compilerEnvironment = Get-SteinSourceFixtureCompilerEnvironmentRecord `
        -RustupToolchain ([string]$Provenance.toolchain.cargo.rustup_toolchain) `
        -PathSha256 (Get-SteinSourceFixturePathSha256)
    $compilerEnvironmentSha256 = Get-SteinSourceEvidenceObjectDigest `
        -Value $compilerEnvironment
    $fixtureDirectory = Join-Path $evidencePath 'source-fixtures'
    $indexRead = Read-SteinSourceFixtureLockedJson `
        -Path (Join-Path $fixtureDirectory 'index.json') `
        -MaximumBytes 1048576
    $null = Assert-SteinSourceFixtureIndex `
        -Index $indexRead.value `
        -Registry $registryRead.value `
        -ExpectedRegistrySha256 ([string]$registryRead.sha256) `
        -ExpectedCommit ([string]$Provenance.repository.head_commit) `
        -ExpectedTree $candidateTree `
        -ExpectedGitLauncherVersion ([string]$Provenance.toolchain.git.version) `
        -ExpectedGitLauncherSha256 ([string]$Provenance.toolchain.git.executable_sha256) `
        -ExpectedGitResolvedVersion ([string]$Provenance.toolchain.git.resolved_version) `
        -ExpectedGitResolvedSha256 ([string]$Provenance.toolchain.git.resolved_executable_sha256)

    $indexByCheck = @{}
    foreach ($descriptor in @($indexRead.value.receipts)) {
        $indexByCheck[[string]$descriptor.source_check_id] = $descriptor
    }
    foreach ($fixture in @($registryRead.value.fixtures)) {
        $sourceCheckId = [string]$fixture.source_check_id
        if (-not $RecordsById.Contains($sourceCheckId) -or
            [string]$RecordsById[$sourceCheckId].status -cne 'pass' -or
            -not $indexByCheck.ContainsKey($sourceCheckId)) {
            throw 'source_fixture_command_receipt_missing'
        }
        $descriptor = $indexByCheck[$sourceCheckId]
        $receiptPath = Join-Path $fixtureDirectory ([string]$descriptor.path)
        $receiptRead = Read-SteinSourceFixtureLockedJson `
            -Path $receiptPath `
            -MaximumBytes 4194304
        if ([long]$receiptRead.size -ne [long]$descriptor.size -or
            [string]$receiptRead.sha256 -cne [string]$descriptor.sha256) {
            throw 'source_fixture_receipt_descriptor_mismatch'
        }
        $null = Assert-SteinSourceFixtureReceipt `
            -Receipt $receiptRead.value `
            -Fixture $fixture `
            -ExpectedRegistrySha256 ([string]$registryRead.sha256) `
            -ExpectedCommit ([string]$Provenance.repository.head_commit) `
            -ExpectedTree $candidateTree `
            -ExpectedCargoLauncherSha256 ([string]$Provenance.toolchain.cargo.executable_sha256) `
            -ExpectedCargoResolvedSha256 ([string]$Provenance.toolchain.cargo.resolved_executable_sha256) `
            -ExpectedRustcLauncherSha256 ([string]$Provenance.toolchain.rustc.executable_sha256) `
            -ExpectedRustcResolvedSha256 ([string]$Provenance.toolchain.rustc.resolved_executable_sha256) `
            -ExpectedRustupToolchain ([string]$Provenance.toolchain.cargo.rustup_toolchain) `
            -ExpectedGitLauncherVersion ([string]$Provenance.toolchain.git.version) `
            -ExpectedGitLauncherSha256 ([string]$Provenance.toolchain.git.executable_sha256) `
            -ExpectedGitResolvedVersion ([string]$Provenance.toolchain.git.resolved_version) `
            -ExpectedGitResolvedSha256 ([string]$Provenance.toolchain.git.resolved_executable_sha256) `
            -ExpectedCompilerEnvironmentSha256 $compilerEnvironmentSha256
        $record = $RecordsById[$sourceCheckId]
        $record.source_fixture_receipt = $receiptRead.value
        $record.source_fixture_receipt_artifact = [ordered]@{
            path = "source-fixtures/$([string]$descriptor.path)"
            size = [long]$receiptRead.size
            sha256 = [string]$receiptRead.sha256
        }
        $record.source_fixture_suite_index = [ordered]@{
            path = 'source-fixtures/index.json'
            size = [long]$indexRead.size
            sha256 = [string]$indexRead.sha256
        }
    }
    $actualFixtureFiles = @(Get-ChildItem -LiteralPath $fixtureDirectory -Force)
    if ($actualFixtureFiles.Count -ne (@($registryRead.value.fixtures).Count + 1) -or
        @($actualFixtureFiles | Where-Object {
                $_.PSIsContainer -or
                (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
            }).Count -ne 0) {
        throw 'source_fixture_output_set_invalid'
    }
}

$groupExecutionStarted = $false
foreach ($definition in @($sourceCommandRegistryRead.Registry.checks)) {
    $category = [string]$definition.category
    if ($category -ceq 'direct_execution') {
        $null = Invoke-SteinRegisteredSourceCommand -Id ([string]$definition.id)
    }
    elseif ($category -ceq 'grouped_fixture_execution' -and
        -not $groupExecutionStarted) {
        $groupExecutionStarted = $true
        $null = Invoke-SteinRegisteredSourceCommand -Id ([string]$definition.id)
    }
}
if (-not $groupExecutionStarted) {
    throw 'source_command_group_execution_missing'
}
$null = Invoke-SteinRegisteredSourceCommand `
    -Id 'source-report-command-provenance'

$sourceCommandEvidence = Assert-SteinSourceEvidenceCommandReceiptIndex `
    -RegistryRead $sourceCommandRegistryRead `
    -RepositoryRoot $repoRoot `
    -EvidenceRoot $evidencePath `
    -CandidateCommit ([string]$initialProvenance.repository.head_commit) `
    -CandidateTree $candidateTree `
    -RunnerPath ([string]$sourceCommandRunnerBootstrapBinding[0].full_path) `
    -ToolExecutables $sourceCommandToolExecutables

$recordsById = @{}
foreach ($validatedReceipt in @($sourceCommandEvidence.Receipts)) {
    $record = New-SteinRegisteredSourceCheckRecord `
        -ValidatedReceipt $validatedReceipt
    $recordsById[[string]$record.id] = $record
}
$groupedRecords = @($sourceCommandRegistryRead.Contract.GroupedIds |
    ForEach-Object { $recordsById[[string]$_] })
if (@($groupedRecords | Where-Object {
            $null -eq $_ -or [string]$_.status -cne 'pass'
        }).Count -eq 0) {
    Add-SteinRegisteredSourceFixtureEvidence `
        -RecordsById $recordsById `
        -Provenance $initialProvenance
}

$notRunReasons = [ordered]@{
    'native-toolchain-provenance' = 'Authenticated Rust/rustup/Git/VS/MSVC/Windows SDK/package-tool payload, runtime, sysroot, library, and linker provenance is not implemented.'
    'no-leaks-producer-workflow' = 'Candidate-owned installed artifact producer is not implemented.'
    'pinned-clean-build-environment' = 'Authenticated immutable candidate input and fresh dependency, build, and output isolation are not implemented for every source check.'
    'portable-runner-attestation' = 'Authenticated GitHub artifact attestation tied to repository, workflow, commit, and artifact digest is not implemented.'
    'windows-native-ignored-fixtures' = 'Requires explicit native-fixture workflow support; interactive native fixtures remain unimplemented source evidence.'
}
foreach ($id in $notRunReasons.Keys) {
    Write-Host "[NOT RUN] $id"
    $recordsById[$id] = [ordered]@{
        id = $id
        status = 'not_run'
        reason = [string]$notRunReasons[$id]
    }
}
$recordsById['source-report-command-provenance'] = [ordered]@{
    id = 'source-report-command-provenance'
    status = 'pass'
    derivation = 'exact_registry_and_receipt_coverage'
    registry_sha256 = [string]$sourceCommandEvidence.RegistrySha256
    runner_sha256 = [string]$sourceCommandEvidence.RunnerSha256
    executed_check_count = [long]$sourceCommandEvidence.ExecutedCheckCount
    execution_group_count = [long]$sourceCommandEvidence.ExecutionGroupCount
    source_command_receipt_index = $sourceCommandEvidence.Index
    source_command_receipt_index_artifact = [ordered]@{
        path = 'source-command-receipts/index.json'
        size = [long]$sourceCommandEvidence.IndexSize
        sha256 = [string]$sourceCommandEvidence.IndexSha256
    }
    failure_summary = $null
}
foreach ($definition in @($sourceCommandRegistryRead.Registry.checks | Where-Object {
            [string]$_.id -cne 'source-provenance-stability'
        })) {
    $id = [string]$definition.id
    if (-not $recordsById.ContainsKey($id)) {
        throw 'source_command_report_record_missing'
    }
    $checks.Add($recordsById[$id])
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
        (Join-Path $PSScriptRoot "Source-Command-Registry.json"),
        (Join-Path $PSScriptRoot "Run-Source-Check.ps1"),
        (Join-Path $PSScriptRoot "Test-SourceCommand.ps1"),
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
        (Join-Path $repoRoot ".github\workflows\portable-semantic.yml"),
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
$null = Assert-SteinSourceEvidenceCommandEvidenceStable `
    -Evidence $sourceCommandEvidence
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
$null = Assert-SteinSourceEvidenceCommandEvidenceStable `
    -Evidence $sourceCommandEvidence
Close-SteinSourceEvidenceCommandEvidence -Evidence $sourceCommandEvidence
$sourceCommandRegistryRead.Stream.Dispose()
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
