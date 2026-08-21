[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $PackagePath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Publisher,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9A-Fa-f ]{40,59}$")]
    [string] $CertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")]
    [string] $Version,

    [string] $InstallRoot = (Join-Path (
        [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) "STEIN"),

    [string] $EvidenceRoot,

    [string] $AttachmentManifest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..")).Path
function Get-SteinInstalledLockedStreamSha256 {
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
                Replace("-", "").ToLowerInvariant()
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

function Open-SteinInstalledBootstrapFileBinding {
    param(
        [Parameter(Mandatory = $true)][string] $Role,
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $RepositoryRoot
    )

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $repository = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $prefix = "$repository$([IO.Path]::DirectorySeparatorChar)"
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "A runtime evidence source is outside the repository."
    }
    $probe = Split-Path -Parent $resolved
    while ($probe.Length -ge $repository.Length) {
        $ancestor = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $ancestor.PSIsContainer -or
            (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "A runtime evidence source has an invalid ancestor."
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
            throw "A runtime evidence source has an invalid ancestor."
        }
        $probe = $parent
    }
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0) {
        throw "A runtime evidence source is not a regular file."
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne [long]$item.Length) {
            throw "A runtime evidence source changed during capture."
        }
        $digest = Get-SteinInstalledLockedStreamSha256 `
            -Stream $stream `
            -FailureCode "runtime_source_set_changed"
        $current = Get-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
        if ($current.PSIsContainer -or
            (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            [long]$current.Length -ne [long]$item.Length) {
            throw "A runtime evidence source changed during capture."
        }
        return [pscustomobject]@{
            record = [pscustomobject]@{
                role = $Role
                path = $item.FullName.Substring($repository.Length + 1).Replace("\", "/")
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

$script:SteinInstalledRuntimeSourceDefinitions = @(
    [pscustomobject]@{ role = "harness"; path = $PSCommandPath },
    [pscustomobject]@{ role = "launcher"; path = (Join-Path $PSScriptRoot "Verify-Installed.cmd") },
    [pscustomobject]@{ role = "phase2-common"; path = (Join-Path $PSScriptRoot "Common.ps1") },
    [pscustomobject]@{
        role = "evidence-contract"
        path = (Join-Path $PSScriptRoot "Evidence-Contract.ps1")
    },
    [pscustomobject]@{
        role = "evidence-spec"
        path = (Join-Path $PSScriptRoot "Evidence-Spec.json")
    },
    [pscustomobject]@{
        role = "source-fixture-registry"
        path = (Join-Path $PSScriptRoot "Source-Fixture-Registry.json")
    },
    [pscustomobject]@{ role = "phase2-status"; path = (Join-Path $PSScriptRoot "Status.ps1") },
    [pscustomobject]@{
        role = "package-tools"
        path = (Join-Path $repoRoot "packaging\windows-msix\PackageTools.ps1")
    },
    [pscustomobject]@{
        role = "msix-verifier"
        path = (Join-Path $repoRoot "packaging\windows-msix\Verify-Msix.ps1")
    }
) | Sort-Object role
$script:SteinInstalledRuntimeSourceBindings = @(
    $script:SteinInstalledRuntimeSourceDefinitions | ForEach-Object {
        Open-SteinInstalledBootstrapFileBinding `
            -Role $_.role `
            -Path $_.path `
            -RepositoryRoot $repoRoot
    }
)
$script:SteinInstalledInitialRuntimeSources = @(
    $script:SteinInstalledRuntimeSourceBindings | ForEach-Object { $_.record })
$msixVerifierBinding = @($script:SteinInstalledRuntimeSourceBindings | Where-Object {
        [string]$_.record.role -ceq "msix-verifier"
    })
if ($msixVerifierBinding.Count -ne 1) {
    throw "runtime_source_set_changed"
}
$script:SteinPhase2MsixVerifierPath = [string]$msixVerifierBinding[0].full_path
$commonBinding = @($script:SteinInstalledRuntimeSourceBindings | Where-Object {
        [string]$_.record.role -ceq "phase2-common"
    })
if ($commonBinding.Count -ne 1) {
    throw "runtime_source_set_changed"
}
. $commonBinding[0].full_path
if ((Get-SteinInstalledLockedStreamSha256 `
            -Stream $commonBinding[0].stream `
            -FailureCode "runtime_source_set_changed") -cne
        [string]$commonBinding[0].record.sha256) {
    throw "runtime_source_set_changed"
}

$script:SteinPhase2GateIds = @(
    "P2-BUILD",
    "P2-PHASE1-REGRESSION",
    "P2-PRIVATE-CLIENT",
    "P2-PERSISTENCE",
    "P2-UPGRADE",
    "P2-SECRETS",
    "P2-IDENTITY",
    "P2-GOALS",
    "P2-GRANTS",
    "P2-CONSENT",
    "P2-PRESENCE",
    "P2-APPLICATION",
    "P2-DOCUMENT",
    "P2-BROWSER",
    "P2-UIA",
    "P2-PIXELS",
    "P2-MODEL-CONTRACT",
    "P2-MODEL-LIVE",
    "P2-SILENCE",
    "P2-INTERVENTION",
    "P2-POLICY-FAILSAFE",
    "P2-NATIVE-CONTROL",
    "P2-NOTIFICATION",
    "P2-OUTBOX-RECOVERY",
    "P2-OUTBOX-EXPIRY",
    "P2-FEEDBACK",
    "P2-REVOCATION-RACE",
    "P2-DESKTOP-CLOSED",
    "P2-DAEMON-RESTART",
    "P2-RETENTION",
    "P2-NO-LEAKS",
    "P2-PORTABLE-FIXTURE"
)
$script:SteinPhase2ExpectedPolicyProfileId = "phase2-focus-v1"
$evidenceContractBinding = @($script:SteinInstalledRuntimeSourceBindings | Where-Object {
        [string]$_.record.role -ceq "evidence-contract"
    })
if ($evidenceContractBinding.Count -ne 1) {
    throw "runtime_source_set_changed"
}
. $evidenceContractBinding[0].full_path
if ((Get-SteinInstalledLockedStreamSha256 `
            -Stream $evidenceContractBinding[0].stream `
            -FailureCode "runtime_source_set_changed") -cne
        [string]$evidenceContractBinding[0].record.sha256) {
    throw "runtime_source_set_changed"
}
$script:SteinPhase2EvidenceSpecificationPath = Join-Path $PSScriptRoot "Evidence-Spec.json"
$initialEvidenceSpecification = @($script:SteinInstalledInitialRuntimeSources | Where-Object {
        [string]$_.role -ceq "evidence-spec"
    })
if ($initialEvidenceSpecification.Count -ne 1) {
    throw "evidence_spec_runtime_source_missing"
}
$script:SteinPhase2EvidenceSpecificationSha256 =
    [string]$initialEvidenceSpecification[0].sha256
$script:SteinPhase2EvidenceSpecification = Read-SteinPhase2EvidenceSpecification `
    -Path $script:SteinPhase2EvidenceSpecificationPath `
    -ExpectedGateIds $script:SteinPhase2GateIds `
    -ExpectedSha256 $script:SteinPhase2EvidenceSpecificationSha256
$initialSourceFixtureRegistry = @(
    $script:SteinInstalledInitialRuntimeSources | Where-Object {
        [string]$_.role -ceq 'source-fixture-registry'
    })
if ($initialSourceFixtureRegistry.Count -ne 1) {
    throw 'source_fixture_registry_runtime_source_missing'
}
$script:SteinPhase2SourceFixtureRegistry = Read-SteinPhase2SourceFixtureRegistry `
    -Path (Join-Path $PSScriptRoot 'Source-Fixture-Registry.json') `
    -ExpectedSha256 ([string]$initialSourceFixtureRegistry[0].sha256)
$script:SteinInstalledChecks = New-Object Collections.Generic.List[object]
$script:SteinInstalledAttachments = @()
$script:SteinInstalledExternalEvidenceFiles = @{}
$script:SteinInstalledSourceBundle = $null
$script:SteinInstalledRelease = $null
$script:SteinInstalledStatusProjection = $null

function Get-SteinInstalledStringSha256 {
    param([Parameter(Mandatory = $true)][string] $Value)

    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString(
            $sha256.ComputeHash($bytes)).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Resolve-SteinInstalledWindowsPowerShell {
    $systemRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($systemRoot)) {
        throw "windows_powershell_host_unavailable"
    }
    $systemRoot = [IO.Path]::GetFullPath($systemRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $candidate = [IO.Path]::GetFullPath(
        (Join-Path $systemRoot "WindowsPowerShell\v1.0\powershell.exe"))
    $prefix = "$systemRoot$([IO.Path]::DirectorySeparatorChar)"
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "windows_powershell_host_unavailable"
    }

    $probe = Split-Path -Parent $candidate
    while ($probe.Length -ge $systemRoot.Length) {
        $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "windows_powershell_host_unavailable"
        }
        if ([string]::Equals($probe, $systemRoot, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            throw "windows_powershell_host_unavailable"
        }
        $probe = $parent
    }

    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0) {
        throw "windows_powershell_host_unavailable"
    }
    return $item.FullName
}

function Assert-SteinInstalledRuntimeSourcesStable {
    $bindings = @($script:SteinInstalledRuntimeSourceBindings)
    $expected = @($script:SteinInstalledInitialRuntimeSources)
    if ($bindings.Count -ne $expected.Count) {
        throw "runtime_source_set_changed"
    }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        $binding = $bindings[$index]
        foreach ($property in @("role", "path", "size", "sha256")) {
            if ([string]$binding.record.$property -cne [string]$expected[$index].$property) {
                throw "runtime_source_set_changed"
            }
        }
        $item = Get-Item -LiteralPath $binding.full_path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            [long]$item.Length -ne [long]$expected[$index].size -or
            [long]$binding.stream.Length -ne [long]$expected[$index].size -or
            (Get-SteinInstalledLockedStreamSha256 `
                -Stream $binding.stream `
                -FailureCode "runtime_source_set_changed") -cne
                [string]$expected[$index].sha256) {
            throw "runtime_source_set_changed"
        }
    }
    return @($script:SteinInstalledInitialRuntimeSources | ForEach-Object { $_ })
}

function Get-SteinInstalledPathToken {
    param([Parameter(Mandatory = $true)][string] $Path)

    $canonical = [IO.Path]::GetFullPath($Path)
    return "<local-path-sha256:$((Get-SteinInstalledStringSha256 -Value $canonical.ToLowerInvariant()))>"
}

function Assert-SteinInstalledJsonShape {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string[]] $ExpectedProperties,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if ($null -eq $Value) {
        throw $FailureCode
    }
    $actual = @($Value.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    $expected = @($ExpectedProperties | Sort-Object)
    if ($actual.Count -ne $expected.Count -or
        @(Compare-Object -ReferenceObject $expected -DifferenceObject $actual -CaseSensitive).Count -ne 0) {
        throw $FailureCode
    }
}

function Assert-SteinInstalledEvidenceBase {
    param(
        [Parameter(Mandatory = $true)][string] $Base,
        [Parameter(Mandatory = $true)][string] $RepositoryRoot
    )

    $artifactsRoot = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot "artifacts"))
    $canonical = [IO.Path]::GetFullPath($Base).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $prefix = "$artifactsRoot$([IO.Path]::DirectorySeparatorChar)"
    if (-not $canonical.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "EvidenceRoot must be below the repository artifacts directory."
    }

    $probe = $canonical
    while ($probe.Length -ge $artifactsRoot.Length) {
        if (Test-Path -LiteralPath $probe) {
            $item = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or
                (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw "The evidence path must contain only regular directories."
            }
        }
        if ([string]::Equals($probe, $artifactsRoot, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            break
        }
        $probe = $parent
    }
    return $canonical
}

function Write-SteinInstalledEvidenceJson {
    param(
        [Parameter(Mandatory = $true)][string] $RelativePath,
        [Parameter(Mandatory = $true)] $Value
    )

    $path = [IO.Path]::GetFullPath((Join-Path $script:SteinInstalledEvidencePath $RelativePath))
    $prefix = "$script:SteinInstalledEvidencePath$([IO.Path]::DirectorySeparatorChar)"
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "An evidence output escaped its timestamped directory."
    }
    $parent = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyPath -Path $parent
    }
    $Value | ConvertTo-Json -Depth 24 |
        Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
    Protect-SteinPhase2OwnerOnlyPath -Path $path
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    return [ordered]@{
        path = $item.FullName.Substring($script:SteinInstalledEvidencePath.Length + 1).Replace("\", "/")
        size = $item.Length
        sha256 = Get-SteinPhase2Sha256 -Path $item.FullName
    }
}

function New-SteinInstalledCommandRecord {
    param(
        [Parameter(Mandatory = $true)][string] $Identity,
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string[]] $Arguments
    )

    return [ordered]@{
        identity = $Identity
        executable = $Executable
        arguments = @($Arguments)
        local_path_representation = "deterministic_sha256_token"
        arguments_omitted = $false
    }
}

function Invoke-SteinInstalledCheck {
    param(
        [Parameter(Mandatory = $true)][string] $Id,
        [Parameter(Mandatory = $true)] $Command,
        [Parameter(Mandatory = $true)][string] $FailureCode,
        [Parameter(Mandatory = $true)][ValidateSet("fail", "blocked")][string] $StatusOnError,
        [Parameter(Mandatory = $true)][scriptblock] $Action
    )

    $started = [DateTime]::UtcNow
    $status = "pass"
    $payload = $null
    try {
        $payload = & $Action
    }
    catch {
        $status = $StatusOnError
        $payload = [ordered]@{
            verified = $false
            failure_code = $FailureCode
        }
    }
    $completed = [DateTime]::UtcNow
    $record = [ordered]@{
        schema_version = 1
        check_id = $Id
        status = $status
        command = $Command
        started_at_utc = $started.ToString("o")
        completed_at_utc = $completed.ToString("o")
        duration_ms = [long]($completed - $started).TotalMilliseconds
        exit_code = if ($status -ceq "pass") { 0 } else { $null }
        failure_summary = if ($status -ceq "pass") { $null } else { "content_minimized:$FailureCode" }
        result = $payload
    }
    $artifact = Write-SteinInstalledEvidenceJson `
        -RelativePath ("checks\" + ($Id.ToLowerInvariant() -replace "[^a-z0-9._-]", "-") + ".json") `
        -Value $record
    $check = [ordered]@{
        id = $Id
        status = $status
        command = $Command
        started_at_utc = $record.started_at_utc
        completed_at_utc = $record.completed_at_utc
        duration_ms = $record.duration_ms
        exit_code = $record.exit_code
        failure_summary = $record.failure_summary
        output = $artifact
    }
    $script:SteinInstalledChecks.Add($check)
    $marker = switch ($status) {
        "pass" { "PASS" }
        "fail" { "FAIL" }
        default { "BLOCKED" }
    }
    Write-Host "[$marker] $Id"
    return $check
}

function Add-SteinInstalledNotRunCheck {
    param(
        [Parameter(Mandatory = $true)][string] $Id,
        [Parameter(Mandatory = $true)] $Command,
        [Parameter(Mandatory = $true)][string] $ReasonCode,
        [Parameter(Mandatory = $true)] $Result
    )

    $now = [DateTime]::UtcNow.ToString("o")
    $record = [ordered]@{
        schema_version = 1
        check_id = $Id
        status = "not_run"
        command = $Command
        started_at_utc = $now
        completed_at_utc = $now
        duration_ms = 0
        exit_code = $null
        failure_summary = $null
        reason_code = $ReasonCode
        result = $Result
    }
    $artifact = Write-SteinInstalledEvidenceJson `
        -RelativePath ("checks\" + ($Id.ToLowerInvariant() -replace "[^a-z0-9._-]", "-") + ".json") `
        -Value $record
    $check = [ordered]@{
        id = $Id
        status = "not_run"
        command = $Command
        started_at_utc = $now
        completed_at_utc = $now
        duration_ms = 0
        exit_code = $null
        failure_summary = $null
        reason_code = $ReasonCode
        output = $artifact
    }
    $script:SteinInstalledChecks.Add($check)
    Write-Host "[NOT RUN] $Id"
    return $check
}

function Get-SteinInstalledCheck {
    param([Parameter(Mandatory = $true)][string] $Id)

    return @($script:SteinInstalledChecks | Where-Object { $_.id -ceq $Id })[0]
}

function Assert-SteinInstalledBundlesEqual {
    param(
        [Parameter(Mandatory = $true)] $Expected,
        [Parameter(Mandatory = $true)] $Actual
    )

    foreach ($property in @(
            "PackageName", "Publisher", "PackageFamilyName", "DesktopAumid", "BrokerAumid",
            "BrowserProducerAumid",
            "Version", "CertificateThumbprint", "MsixSize", "MsixSha256", "CoreSize",
            "CoreSha256", "BrowserHostSha256", "CandidateGitCommit", "CandidateGitTree",
            "SourceVerificationSha256", "SourceRootAnchorSha256", "SourceRootDigestSha256",
            "CliSize", "CliSha256", "DesktopSize", "DesktopSha256",
            "DesktopDistFileCount", "DesktopDistManifestSha256")) {
        if ([string]$Expected.$property -cne [string]$Actual.$property) {
            throw "installed_bundle_mismatch"
        }
    }
}

function ConvertTo-SteinInstalledStatusProjection {
    param([Parameter(Mandatory = $true)] $Status)

    $runtime = $Status.core.runtime
    $capabilities = @()
    if ($null -ne $Status.core -and $null -ne $Status.core.capabilities) {
        $capabilities = @($Status.core.capabilities | ForEach-Object {
            [ordered]@{
                capability = [string]$_.capability
                schema_version = if ($null -ne $_.PSObject.Properties["schema_version"]) {
                    [int]$_.schema_version
                }
                else { $null }
                state = [string]$_.state
                unavailable_reason = if ($null -ne $_.PSObject.Properties["unavailable_reason"]) {
                    $_.unavailable_reason
                }
                else { $null }
            }
        })
    }
    return [ordered]@{
        healthy = [bool]$Status.healthy
        installed = [bool]$Status.installed
        lifecycle_state = [string]$Status.lifecycle_state
        package_name = [string]$Status.package_name
        package_family_name = [string]$Status.package_family_name
        desktop_aumid = [string]$Status.desktop_aumid
        broker_aumid = [string]$Status.broker_aumid
        browser_producer_aumid = [string]$Status.browser_producer_aumid
        version = [string]$Status.version
        package_count = [int]$Status.package_count
        task_count = [int]$Status.task_count
        task_state = [string]$Status.task_state
        core_process_count = [int]$Status.core_process_count
        files_verified = [bool]$Status.files_verified
        owner_acl_verified = [bool]$Status.owner_acl_verified
        migration_readiness_verified = [bool]$Status.migration_readiness_verified
        migration_readiness_signal = [string]$Status.migration_readiness_signal
        numeric_schema_version_reported = [bool]$Status.numeric_schema_version_reported
        recovery_required = [bool]$Status.recovery_required
        runtime = [ordered]@{
            health = [string]$runtime.health
            state = [string]$runtime.state
            build_id = [string]$runtime.buildId
            protocol_version = $runtime.protocolVersion
        }
        capabilities = $capabilities
        authenticated_actor_retained = $false
        daemon_instance_id_retained = $false
    }
}

function Register-SteinInstalledExternalEvidenceFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][long] $Size,
        [Parameter(Mandatory = $true)][string] $Sha256
    )

    $key = [IO.Path]::GetFullPath($Path).ToLowerInvariant()
    if ($script:SteinInstalledExternalEvidenceFiles.ContainsKey($key)) {
        $existing = $script:SteinInstalledExternalEvidenceFiles[$key]
        if ([long]$existing.size -ne $Size -or [string]$existing.sha256 -cne $Sha256) {
            throw "external_evidence_descriptor_conflict"
        }
        return
    }
    $script:SteinInstalledExternalEvidenceFiles[$key] = [pscustomobject]@{
        path = [IO.Path]::GetFullPath($Path)
        size = $Size
        sha256 = $Sha256
    }
}

function Assert-SteinInstalledExternalEvidenceFilesStable {
    foreach ($record in @($script:SteinInstalledExternalEvidenceFiles.Values)) {
        $item = Get-Item -LiteralPath $record.path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            [long]$item.Length -ne [long]$record.size -or
            (Get-SteinPhase2Sha256 -Path $item.FullName) -cne [string]$record.sha256) {
            throw "external_evidence_changed_during_collection"
        }
    }
}

function Read-SteinInstalledLockedJsonFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][long] $MaximumBytes,
        [Parameter(Mandatory = $true)][string] $FailureCode,
        [string] $ExpectedSha256,
        [long] $ExpectedSize = -1
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes -or
        ($ExpectedSize -ge 0 -and $item.Length -ne $ExpectedSize) -or
        (-not [string]::IsNullOrWhiteSpace($ExpectedSha256) -and
            $ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$')) {
        throw $FailureCode
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $item.Length -or
            $stream.Length -le 0 -or $stream.Length -gt $MaximumBytes -or
            ($ExpectedSize -ge 0 -and $stream.Length -ne $ExpectedSize)) {
            throw 'json_artifact_hash_or_size_mismatch'
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw 'json_artifact_hash_or_size_mismatch'
            }
            $offset += $read
        }
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $actualSha256 = [BitConverter]::ToString($sha256.ComputeHash($bytes)).
                Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256) -and
            $actualSha256 -cne $ExpectedSha256) {
            throw 'json_artifact_hash_or_size_mismatch'
        }
        try {
            $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
            $jsonText = $strictUtf8.GetString($bytes)
            if ($jsonText.Length -gt 0 -and [int][char]$jsonText[0] -eq 0xFEFF) {
                $jsonText = $jsonText.Substring(1)
            }
        }
        catch {
            throw $FailureCode
        }
    }
    finally {
        $stream.Dispose()
    }
    try {
        $value = $jsonText | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw $FailureCode
    }
    return [pscustomobject]@{
        value = $value
        sha256 = $actualSha256
        size = [long]$bytes.Length
    }
}

function Read-SteinInstalledAttachments {
    param([Parameter(Mandatory = $true)][string] $ManifestPath)

    $resolvedManifest = Resolve-SteinPhase2RegularFile -Path $ManifestPath
    if ((Get-Item -LiteralPath $resolvedManifest -Force -ErrorAction Stop).Length -gt 1MB) {
        throw "attachment_manifest_size_invalid"
    }
    $manifestRead = Read-SteinInstalledLockedJsonFile `
        -Path $resolvedManifest `
        -MaximumBytes 1MB `
        -FailureCode 'attachment_manifest_invalid'
    $manifestHash = [string]$manifestRead.sha256
    Register-SteinInstalledExternalEvidenceFile `
        -Path $resolvedManifest `
        -Size ([long]$manifestRead.size) `
        -Sha256 $manifestHash
    $manifest = $manifestRead.value
    Assert-SteinInstalledJsonShape -Value $manifest `
        -ExpectedProperties @("schema_version", "attachments") `
        -FailureCode "attachment_manifest_schema_invalid"
    if (($manifest.schema_version -isnot [int] -and $manifest.schema_version -isnot [long]) -or
        [long]$manifest.schema_version -ne 2) {
        throw "attachment_manifest_schema_invalid"
    }
    $entries = @($manifest.attachments)
    if ($entries.Count -lt 1 -or $entries.Count -gt 64) {
        throw "attachment_manifest_count_invalid"
    }

    $seen = @{}
    $sanitized = New-Object Collections.Generic.List[object]
    foreach ($entry in $entries) {
        Assert-SteinInstalledJsonShape -Value $entry `
            -ExpectedProperties @(
                "attachment_id", "gate_id", "kind", "path", "sha256",
                "declared_result", "privacy_reviewed", "synthetic_only", "recorded_at_utc",
                "artifacts") `
            -FailureCode "attachment_entry_schema_invalid"
        $attachmentId = [string]$entry.attachment_id
        $gateId = [string]$entry.gate_id
        $kind = [string]$entry.kind
        $declaredResult = [string]$entry.declared_result
        if ($attachmentId -cnotmatch "^[a-z0-9][a-z0-9._-]{0,63}$" -or $seen.ContainsKey($attachmentId)) {
            throw "attachment_id_invalid"
        }
        $seen[$attachmentId] = $true
        if ($gateId -cnotin $script:SteinPhase2GateIds) {
            throw "attachment_gate_invalid"
        }
        if ($kind -cnotin @("redacted_screenshot", "native_fixture_result") -or
            $declaredResult -cnotin @("pass", "fail", "blocked", "not_run")) {
            throw "attachment_classification_invalid"
        }
        if ($entry.privacy_reviewed -isnot [bool] -or -not [bool]$entry.privacy_reviewed -or
            $entry.synthetic_only -isnot [bool] -or -not [bool]$entry.synthetic_only) {
            throw "attachment_privacy_review_missing"
        }
        $recordedAt = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse(
                [string]$entry.recorded_at_utc,
                [Globalization.CultureInfo]::InvariantCulture,
                ([Globalization.DateTimeStyles]::AssumeUniversal -bor
                    [Globalization.DateTimeStyles]::AdjustToUniversal),
                [ref]$recordedAt) -or
            $recordedAt -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
            throw "attachment_timestamp_invalid"
        }
        $path = Resolve-SteinPhase2RegularFile -Path ([string]$entry.path)
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        $extension = [IO.Path]::GetExtension($path)
        if (($kind -ceq "redacted_screenshot" -and $extension -ine ".png") -or
            ($kind -ceq "native_fixture_result" -and $extension -ine ".json")) {
            throw "attachment_format_invalid"
        }
        $maximumSize = if ($kind -ceq "redacted_screenshot") { 32MB } else { 4MB }
        if ($item.Length -gt $maximumSize) {
            throw "attachment_size_invalid"
        }
        $expectedHash = ([string]$entry.sha256).ToLowerInvariant()
        if ($expectedHash -cnotmatch "^[0-9a-f]{64}$") {
            throw "attachment_hash_invalid"
        }
        $actualHash = Get-SteinPhase2Sha256 -Path $path
        if ($actualHash -cne $expectedHash) {
            throw "attachment_hash_mismatch"
        }
        Register-SteinInstalledExternalEvidenceFile `
            -Path $path `
            -Size ([long]$item.Length) `
            -Sha256 $actualHash
        $underlyingArtifacts = New-Object Collections.Generic.List[object]
        $underlyingArtifactPaths = @{}
        $underlyingArtifactsById = @{}
        $underlyingArtifactIds = @{}
        foreach ($artifactEntry in @($entry.artifacts)) {
            Assert-SteinInstalledJsonShape -Value $artifactEntry `
                -ExpectedProperties @("artifact_id", "path", "sha256", "size") `
                -FailureCode "underlying_artifact_entry_schema_invalid"
            $artifactId = [string]$artifactEntry.artifact_id
            if ($artifactId -cnotmatch "^[a-z0-9][a-z0-9._-]{2,95}$" -or
                $underlyingArtifactIds.ContainsKey($artifactId) -or
                ($artifactEntry.size -isnot [int] -and $artifactEntry.size -isnot [long]) -or
                [long]$artifactEntry.size -lt 1 -or [long]$artifactEntry.size -gt 67108864) {
                throw "underlying_artifact_entry_invalid"
            }
            $artifactHash = ([string]$artifactEntry.sha256).ToLowerInvariant()
            if ($artifactHash -cnotmatch "^[0-9a-f]{64}$") {
                throw "underlying_artifact_hash_invalid"
            }
            $artifactPath = Resolve-SteinPhase2RegularFile -Path ([string]$artifactEntry.path)
            $artifactItem = Get-Item -LiteralPath $artifactPath -Force -ErrorAction Stop
            if ([long]$artifactItem.Length -ne [long]$artifactEntry.size -or
                (Get-SteinPhase2Sha256 -Path $artifactPath) -cne $artifactHash) {
                throw "underlying_artifact_hash_or_size_mismatch"
            }
            Register-SteinInstalledExternalEvidenceFile `
                -Path $artifactPath `
                -Size ([long]$artifactItem.Length) `
                -Sha256 $artifactHash
            $underlyingArtifactIds[$artifactId] = $true
            $underlyingArtifactPaths[$artifactId] = $artifactPath
            $underlyingArtifactRecord = [pscustomobject]@{
                artifact_id = $artifactId
                sha256 = $artifactHash
                size = [long]$artifactItem.Length
            }
            $underlyingArtifacts.Add($underlyingArtifactRecord)
            $underlyingArtifactsById[$artifactId] = $underlyingArtifactRecord
        }
        if ($kind -ceq "redacted_screenshot" -and $underlyingArtifacts.Count -ne 0) {
            throw "screenshot_underlying_artifact_unexpected"
        }
        $nativeFixture = $null
        if ($kind -ceq "native_fixture_result") {
            if ($underlyingArtifacts.Count -lt 1 -or $underlyingArtifacts.Count -gt 64) {
                throw "native_fixture_underlying_artifact_count_invalid"
            }
            $nativeRead = Read-SteinInstalledLockedJsonFile `
                -Path $path `
                -MaximumBytes 4MB `
                -FailureCode 'native_fixture_result_invalid' `
                -ExpectedSha256 $expectedHash `
                -ExpectedSize ([long]$item.Length)
            $nativeResult = $nativeRead.value
            $gateSpecification = $script:SteinPhase2EvidenceSpecification.gates_by_id[$gateId]
            $expectedPackage = [pscustomobject]@{
                package_family_name = [string]$script:SteinInstalledSourceBundle.PackageFamilyName
                version = [string]$script:SteinInstalledSourceBundle.Version
                msix_sha256 = [string]$script:SteinInstalledSourceBundle.MsixSha256
                core_sha256 = [string]$script:SteinInstalledSourceBundle.CoreSha256
                browser_host_sha256 = [string]$script:SteinInstalledSourceBundle.BrowserHostSha256
                cli_executable_size = [long]$script:SteinInstalledSourceBundle.CliSize
                cli_executable_sha256 = [string]$script:SteinInstalledSourceBundle.CliSha256
                desktop_executable_size = [long]$script:SteinInstalledSourceBundle.DesktopSize
                desktop_executable_sha256 = [string]$script:SteinInstalledSourceBundle.DesktopSha256
                desktop_dist_file_count = [int]$script:SteinInstalledSourceBundle.DesktopDistFileCount
                desktop_dist_manifest_sha256 = [string]$script:SteinInstalledSourceBundle.DesktopDistManifestSha256
                candidate_git_commit = [string]$script:SteinInstalledSourceBundle.CandidateGitCommit
                candidate_git_tree = [string]$script:SteinInstalledSourceBundle.CandidateGitTree
                source_verification_sha256 = [string]$script:SteinInstalledSourceBundle.SourceVerificationSha256
                source_root_anchor_sha256 = [string]$script:SteinInstalledSourceBundle.SourceRootAnchorSha256
                source_root_digest_sha256 = [string]$script:SteinInstalledSourceBundle.SourceRootDigestSha256
            }
            $null = Assert-SteinPhase2GateEvidenceResult `
                -Value $nativeResult `
                -Specification $script:SteinPhase2EvidenceSpecification.specification `
                -Gate $gateSpecification `
                -SpecificationSha256 $script:SteinPhase2EvidenceSpecificationSha256 `
                -ExpectedPackage $expectedPackage `
                -ExpectedCollector $hostRecord `
                -UnderlyingArtifacts @($underlyingArtifacts | ForEach-Object { $_ })
            if ([string]$nativeResult.result -cne $declaredResult) {
                throw "native_fixture_result_identity_invalid"
            }
            $nativeRecordedAt = [DateTimeOffset]::MinValue
            if (-not [DateTimeOffset]::TryParse(
                    [string]$nativeResult.recorded_at_utc,
                    [Globalization.CultureInfo]::InvariantCulture,
                    ([Globalization.DateTimeStyles]::AssumeUniversal -bor
                        [Globalization.DateTimeStyles]::AdjustToUniversal),
                    [ref]$nativeRecordedAt) -or
                $nativeRecordedAt -ne $recordedAt) {
                throw "native_fixture_result_timestamp_invalid"
            }
            $nativeExitCode = $nativeResult.exit_code
            $sourceBinding = $nativeResult.bindings.source_report
            $sourceReportPath = $underlyingArtifactPaths[[string]$sourceBinding.report_artifact_id]
            $sourceRootPath = $underlyingArtifactPaths[[string]$sourceBinding.root_anchor_artifact_id]
            $sourceReportDescriptor =
                $underlyingArtifactsById[[string]$sourceBinding.report_artifact_id]
            $sourceRootDescriptor =
                $underlyingArtifactsById[[string]$sourceBinding.root_anchor_artifact_id]
            if ([string]::IsNullOrWhiteSpace($sourceReportPath) -or
                [string]::IsNullOrWhiteSpace($sourceRootPath) -or
                $null -eq $sourceReportDescriptor -or $null -eq $sourceRootDescriptor) {
                throw "source_evidence_artifact_missing"
            }
            $sourceReport = (Read-SteinInstalledLockedJsonFile `
                    -Path $sourceReportPath `
                    -MaximumBytes 16MB `
                    -FailureCode 'source_evidence_report_invalid' `
                    -ExpectedSha256 ([string]$sourceReportDescriptor.sha256) `
                    -ExpectedSize ([long]$sourceReportDescriptor.size)).value
            $sourceRoot = (Read-SteinInstalledLockedJsonFile `
                    -Path $sourceRootPath `
                    -MaximumBytes 1MB `
                    -FailureCode 'source_evidence_root_invalid' `
                    -ExpectedSha256 ([string]$sourceRootDescriptor.sha256) `
                    -ExpectedSize ([long]$sourceRootDescriptor.size)).value
            $null = Assert-SteinPhase2SourceEvidenceBinding `
                -EvidenceResult $nativeResult `
                -SourceReport $sourceReport `
                -SourceRootAnchor $sourceRoot `
                -EvidenceSpecification $script:SteinPhase2EvidenceSpecification.specification `
                -SourceFixtureRegistry $script:SteinPhase2SourceFixtureRegistry.value `
                -SourceFixtureRegistrySha256 `
                    ([string]$script:SteinPhase2SourceFixtureRegistry.sha256)
            if ($gateId -ceq "P2-PORTABLE-FIXTURE") {
                $linuxPath = $underlyingArtifactPaths[
                    [string]$nativeResult.bindings.linux_artifact.artifact_id]
                if ([string]::IsNullOrWhiteSpace($linuxPath)) {
                    throw "linux_artifact_missing"
                }
                $linuxDescriptor = $underlyingArtifactsById[
                    [string]$nativeResult.bindings.linux_artifact.artifact_id]
                if ($null -eq $linuxDescriptor) {
                    throw "linux_artifact_missing"
                }
                $linuxArtifact = (Read-SteinInstalledLockedJsonFile `
                        -Path $linuxPath `
                        -MaximumBytes 4MB `
                        -FailureCode 'linux_artifact_invalid' `
                        -ExpectedSha256 ([string]$linuxDescriptor.sha256) `
                        -ExpectedSize ([long]$linuxDescriptor.size)).value
                $null = Assert-SteinPhase2LinuxPortableArtifact `
                    -Artifact $linuxArtifact `
                    -Gate $gateSpecification `
                    -ExpectedCommit ([string]$nativeResult.bindings.commit.object_id) `
                    -ExpectedTree ([string]$nativeResult.bindings.commit.tree_id) `
                    -SourceReport $sourceReport `
                    -EvidenceResult $nativeResult `
                    -UnderlyingArtifacts @($underlyingArtifacts | ForEach-Object { $_ })
            }
            $noLeaksScannerArtifact = $null
            $noLeaksProducerArtifact = $null
            foreach ($runnerBinding in @($nativeResult.bindings.runner_artifacts)) {
                $runnerSpecification = @($gateSpecification.runner_artifacts | Where-Object {
                    [string]$_.artifact_role -ceq [string]$runnerBinding.artifact_role
                })[0]
                $runnerPath = $underlyingArtifactPaths[[string]$runnerBinding.artifact_id]
                $runnerDescriptor =
                    $underlyingArtifactsById[[string]$runnerBinding.artifact_id]
                if ($null -eq $runnerSpecification -or
                    [string]::IsNullOrWhiteSpace($runnerPath) -or
                    $null -eq $runnerDescriptor) {
                    throw "runner_artifact_missing"
                }
                $runnerArtifact = (Read-SteinInstalledLockedJsonFile `
                        -Path $runnerPath `
                        -MaximumBytes 4MB `
                        -FailureCode 'runner_artifact_invalid' `
                        -ExpectedSha256 ([string]$runnerDescriptor.sha256) `
                        -ExpectedSize ([long]$runnerDescriptor.size)).value
                if ([string]$runnerBinding.artifact_role -ceq
                    "private_diagnostic_denial") {
                    $null = Assert-SteinPhase2PrivateDiagnosticArtifact `
                        -Artifact $runnerArtifact `
                        -RunnerArtifact $runnerSpecification
                }
                elseif ([string]$runnerBinding.artifact_role -ceq "toast_com_denial") {
                    $null = Assert-SteinPhase2ToastComDenialArtifact `
                        -Artifact $runnerArtifact `
                        -RunnerArtifact $runnerSpecification
                }
                elseif ([string]$runnerBinding.artifact_role -ceq "no_leaks_scan") {
                    $null = Assert-SteinPhase2NoLeaksArtifact `
                        -Artifact $runnerArtifact `
                        -RunnerArtifact $runnerSpecification `
                        -EvidenceResult $nativeResult
                    $noLeaksScannerArtifact = $runnerArtifact
                }
                elseif ([string]$runnerBinding.artifact_role -ceq
                    "no_leaks_sentinel_producer") {
                    $null = Assert-SteinPhase2NoLeaksProducerArtifact `
                        -Artifact $runnerArtifact `
                        -RunnerArtifact $runnerSpecification `
                        -EvidenceResult $nativeResult
                    $noLeaksProducerArtifact = $runnerArtifact
                }
                else {
                    throw "runner_artifact_role_unsupported"
                }
            }
            if ($gateId -ceq "P2-NO-LEAKS") {
                if ($null -eq $noLeaksScannerArtifact -or
                    $null -eq $noLeaksProducerArtifact) {
                    throw "no_leaks_receipt_pair_missing"
                }
                $null = Assert-SteinPhase2NoLeaksReceiptPair `
                    -ScannerArtifact $noLeaksScannerArtifact `
                    -ProducerArtifact $noLeaksProducerArtifact
            }
            $nativeFixture = [ordered]@{
                schema_version = 2
                contract_id = [string]$nativeResult.contract_id
                contract_sha256 = [string]$nativeResult.contract_sha256
                fixture_id = [string]$nativeResult.fixture_id
                runner_id = [string]$nativeResult.runner_id
                exit_code = $nativeExitCode
                closed_content_free_schema_verified = $true
                proof_classes = @($nativeResult.proof_classes)
                subchecks = @($nativeResult.subchecks)
                bindings = $nativeResult.bindings
                artifacts = @($nativeResult.artifacts)
            }
        }
        $sanitized.Add([ordered]@{
            attachment_id = $attachmentId
            gate_id = $gateId
            kind = $kind
            declared_result = $declaredResult
            recorded_at_utc = $recordedAt.ToString("o")
            sha256 = $actualHash
            size = $item.Length
            privacy_reviewed = $true
            synthetic_only = $true
            source_path_retained = $false
            file_copied = $false
            semantic_result_verified_by_harness = $false
            native_fixture = $nativeFixture
        })
    }
    Assert-SteinInstalledExternalEvidenceFilesStable
    return @($sanitized | ForEach-Object { $_ })
}

Assert-SteinPhase2WindowsHost
$InstallRoot = Assert-SteinPhase2InstallRoot -InstallRoot $InstallRoot
$normalizedThumbprint = ConvertTo-SteinCertificateThumbprint -Thumbprint $CertificateThumbprint
$null = ConvertTo-SteinPhase2Version -Version $Version

if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    $EvidenceRoot = Join-Path $repoRoot "artifacts\evidence\phase-2"
}
$evidenceBase = Assert-SteinInstalledEvidenceBase -Base $EvidenceRoot -RepositoryRoot $repoRoot
if (-not (Test-Path -LiteralPath $evidenceBase -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $evidenceBase -Force -ErrorAction Stop
}
$stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
$runId = [Guid]::NewGuid().ToString("N")
$script:SteinInstalledEvidencePath = Join-Path $evidenceBase "installed-$stamp-$($runId.Substring(0, 8))"
$null = New-Item -ItemType Directory -Path $script:SteinInstalledEvidencePath -ErrorAction Stop
Protect-SteinPhase2OwnerOnlyPath -Path $script:SteinInstalledEvidencePath
$startedAt = [DateTime]::UtcNow

$generatorRecord = [ordered]@{
    schema_version = 1
    harness_identity = "phase2-installed-evidence-v1"
    runtime_source_files = @($script:SteinInstalledInitialRuntimeSources | ForEach-Object { $_ })
    source_paths = "repository_relative_only"
    source_stability = "required_before_ledger"
    trust_scope = "content_integrity_only_not_authentication"
}
$generatorArtifact = Write-SteinInstalledEvidenceJson `
    -RelativePath "generator.json" `
    -Value $generatorRecord

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$hostIdentityHash = Get-SteinInstalledStringSha256 -Value (
    "$env:COMPUTERNAME`0$($identity.User.Value)")
$windowsVersion = Get-ItemProperty `
    -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
    -ErrorAction Stop
$hostRecord = [ordered]@{
    schema_version = 1
    host_identity_sha256 = $hostIdentityHash
    computer_name_retained = $false
    user_name_retained = $false
    user_sid_retained = $false
    os = [ordered]@{
        product_name = [string]$windowsVersion.ProductName
        display_version = [string]$windowsVersion.DisplayVersion
        build_number = [string]$windowsVersion.CurrentBuildNumber
        update_build_revision = [int]$windowsVersion.UBR
        process_architecture = [string]$env:PROCESSOR_ARCHITECTURE
        operating_system_64_bit = [Environment]::Is64BitOperatingSystem
        process_64_bit = [Environment]::Is64BitProcess
    }
    powershell = [ordered]@{
        edition = [string]$PSVersionTable.PSEdition
        version = [string]$PSVersionTable.PSVersion
    }
    elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    evidence_owner_sid_only = $true
}
$hostArtifact = Write-SteinInstalledEvidenceJson -RelativePath "host.json" -Value $hostRecord

$packagePathToken = Get-SteinInstalledPathToken -Path $PackagePath
$installRootToken = Get-SteinInstalledPathToken -Path $InstallRoot
$statusBinding = @($script:SteinInstalledRuntimeSourceBindings | Where-Object {
        [string]$_.record.role -ceq "phase2-status"
    })
if ($statusBinding.Count -ne 1) {
    throw "runtime_source_set_changed"
}
$statusScript = [string]$statusBinding[0].full_path
$statusScriptToken = Get-SteinInstalledPathToken -Path $statusScript

$preflightCommand = New-SteinInstalledCommandRecord `
    -Identity "Verify-Installed.ps1::host-and-tool-preflight" `
    -Executable "powershell-host" `
    -Arguments @("-PackagePath", $packagePathToken, "-InstallRoot", $installRootToken)
$preflight = Invoke-SteinInstalledCheck `
    -Id "installed-host-preflight" `
    -Command $preflightCommand `
    -FailureCode "installed_preflight_unavailable" `
    -StatusOnError "blocked" `
    -Action {
        $powershellExecutable = Resolve-SteinInstalledWindowsPowerShell
        $makeAppx = Resolve-WindowsSdkTool -Name "makeappx.exe"
        if (-not (Test-Path -LiteralPath $statusScript -PathType Leaf)) {
            throw "installed_preflight_unavailable"
        }
        [ordered]@{
            verified = $true
            native_windows = $true
            non_elevated = $true
            powershell_executable = Split-Path -Leaf $powershellExecutable
            makeappx_executable = Split-Path -Leaf $makeAppx
            status_script_sha256 = Get-SteinPhase2Sha256 -Path $statusScript
        }
    }

$bundleCommand = New-SteinInstalledCommandRecord `
    -Identity "Verify-Installed.ps1::verify-signed-release-bundle" `
    -Executable "powershell-host" `
    -Arguments @(
        "-PackagePath", $packagePathToken,
        "-Publisher", $Publisher,
        "-CertificateThumbprint", $normalizedThumbprint,
        "-Version", $Version)
if ($preflight.status -ceq "pass") {
    $bundleCheck = Invoke-SteinInstalledCheck `
        -Id "signed-release-bundle" `
        -Command $bundleCommand `
        -FailureCode "signed_release_bundle_invalid" `
        -StatusOnError "fail" `
        -Action {
            $script:SteinInstalledSourceBundle = Get-SteinPhase2ReleaseBundle `
                -PackagePath $PackagePath `
                -Publisher $Publisher `
                -CertificateThumbprint $normalizedThumbprint `
                -Version $Version
            [ordered]@{
                verified = $true
                package_source_path_retained = $false
                identity_source_path_retained = $false
                package_name = $script:SteinInstalledSourceBundle.PackageName
                publisher = $script:SteinInstalledSourceBundle.Publisher
                package_family_name = $script:SteinInstalledSourceBundle.PackageFamilyName
                desktop_aumid = $script:SteinInstalledSourceBundle.DesktopAumid
                broker_aumid = $script:SteinInstalledSourceBundle.BrokerAumid
                browser_producer_aumid = $script:SteinInstalledSourceBundle.BrowserProducerAumid
                version = $script:SteinInstalledSourceBundle.Version
                signing_certificate_thumbprint = $script:SteinInstalledSourceBundle.CertificateThumbprint
                msix = [ordered]@{
                    size = $script:SteinInstalledSourceBundle.MsixSize
                    sha256 = $script:SteinInstalledSourceBundle.MsixSha256
                }
                core = [ordered]@{
                    size = $script:SteinInstalledSourceBundle.CoreSize
                    sha256 = $script:SteinInstalledSourceBundle.CoreSha256
                }
                browser_host = [ordered]@{
                    sha256 = $script:SteinInstalledSourceBundle.BrowserHostSha256
                    installed_payload_file_count = @(
                        $script:SteinInstalledSourceBundle.InstalledPayloadFiles).Count
                }
                diagnostic_cli = [ordered]@{
                    size = $script:SteinInstalledSourceBundle.CliSize
                    sha256 = $script:SteinInstalledSourceBundle.CliSha256
                }
                closed_msix_layout_and_core_binding_verified = $true
            }
        }
}
else {
    $bundleCheck = Invoke-SteinInstalledCheck `
        -Id "signed-release-bundle" `
        -Command $bundleCommand `
        -FailureCode "signed_release_bundle_preflight_blocked" `
        -StatusOnError "blocked" `
        -Action { throw "signed_release_bundle_preflight_blocked" }
}

$installedCommand = New-SteinInstalledCommandRecord `
    -Identity "Verify-Installed.ps1::verify-protected-installed-bundle-and-private-identity-pins" `
    -Executable "powershell-host" `
    -Arguments @(
        "-InstallRoot", $installRootToken,
        "-Publisher", $Publisher,
        "-CertificateThumbprint", $normalizedThumbprint,
        "-Version", $Version)
if ($bundleCheck.status -ceq "pass") {
    $installedCheck = Invoke-SteinInstalledCheck `
        -Id "installed-bundle-and-private-identity-pins" `
        -Command $installedCommand `
        -FailureCode "installed_bundle_or_identity_invalid" `
        -StatusOnError "fail" `
        -Action {
            $script:SteinInstalledRelease = Get-SteinPhase2InstalledBundle `
                -InstallRoot $InstallRoot `
                -Publisher $Publisher `
                -CertificateThumbprint $normalizedThumbprint `
                -Version $Version
            Assert-SteinInstalledBundlesEqual `
                -Expected $script:SteinInstalledSourceBundle `
                -Actual $script:SteinInstalledRelease.Bundle
            $package = Assert-SteinPhase2InstalledPackage `
                -Bundle $script:SteinInstalledRelease.Bundle
            if ([string]$package.PackageFullName -cne
                [string]$script:SteinInstalledRelease.Record.package_full_name) {
                throw "installed_package_record_mismatch"
            }
            [ordered]@{
                verified = $true
                source_and_protected_installed_bundle_equal = $true
                package_full_name = [string]$package.PackageFullName
                package_family_name = $script:SteinInstalledRelease.Bundle.PackageFamilyName
                desktop_aumid = $script:SteinInstalledRelease.Bundle.DesktopAumid
                broker_aumid = $script:SteinInstalledRelease.Bundle.BrokerAumid
                browser_producer_aumid = $script:SteinInstalledRelease.Bundle.BrowserProducerAumid
                version = $script:SteinInstalledRelease.Bundle.Version
                msix_sha256 = $script:SteinInstalledRelease.Bundle.MsixSha256
                broker_pinned_core_sha256 = $script:SteinInstalledRelease.Bundle.CoreSha256
                browser_host_sha256 = $script:SteinInstalledRelease.Bundle.BrowserHostSha256
                installed_payload_files_verified = @(
                    $script:SteinInstalledRelease.Bundle.InstalledPayloadFiles).Count
                private_session_positive_fixture_executed = $false
                private_session_adversarial_fixture_executed = $false
            }
        }
}
else {
    $installedCheck = Invoke-SteinInstalledCheck `
        -Id "installed-bundle-and-private-identity-pins" `
        -Command $installedCommand `
        -FailureCode "installed_bundle_source_prerequisite_blocked" `
        -StatusOnError "blocked" `
        -Action { throw "installed_bundle_source_prerequisite_blocked" }
}

$statusCommand = New-SteinInstalledCommandRecord `
    -Identity "Status.ps1::exact-installed-lifecycle-readiness" `
    -Executable "System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Arguments @(
        "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $statusScriptToken,
        "-Publisher", $Publisher,
        "-CertificateThumbprint", $normalizedThumbprint,
        "-Version", $Version,
        "-InstallRoot", $installRootToken,
        "-Json")
if ($installedCheck.status -ceq "pass") {
    $statusCheck = Invoke-SteinInstalledCheck `
        -Id "installed-lifecycle-status" `
        -Command $statusCommand `
        -FailureCode "installed_lifecycle_status_unhealthy" `
        -StatusOnError "fail" `
        -Action {
            $powershellExecutable = Resolve-SteinInstalledWindowsPowerShell
            $statusOutput = @(& $powershellExecutable `
                -NoLogo `
                -NoProfile `
                -ExecutionPolicy Bypass `
                -File $statusScript `
                -Publisher $Publisher `
                -CertificateThumbprint $normalizedThumbprint `
                -Version $Version `
                -InstallRoot $InstallRoot `
                -Json 2>&1)
            $statusExitCode = $LASTEXITCODE
            $statusLines = @($statusOutput | ForEach-Object { [string]$_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            if ($statusLines.Count -eq 0) {
                throw "installed_status_output_missing"
            }
            $status = $statusLines[$statusLines.Count - 1] | ConvertFrom-Json -ErrorAction Stop
            if ($statusExitCode -ne 0 -or -not [bool]$status.healthy -or
                -not [bool]$status.installed -or
                [string]$status.package_family_name -cne
                    $script:SteinInstalledRelease.Bundle.PackageFamilyName -or
                [string]$status.desktop_aumid -cne $script:SteinInstalledRelease.Bundle.DesktopAumid -or
                [string]$status.broker_aumid -cne $script:SteinInstalledRelease.Bundle.BrokerAumid -or
                [string]$status.browser_producer_aumid -cne $script:SteinInstalledRelease.Bundle.BrowserProducerAumid -or
                [string]$status.version -cne $Version) {
                throw "installed_lifecycle_status_unhealthy"
            }
            $script:SteinInstalledStatusProjection = ConvertTo-SteinInstalledStatusProjection `
                -Status $status
            $script:SteinInstalledStatusProjection | Add-Member `
                -NotePropertyName status_command_exit_code `
                -NotePropertyValue $statusExitCode
            return $script:SteinInstalledStatusProjection
        }
}
else {
    $statusCheck = Invoke-SteinInstalledCheck `
        -Id "installed-lifecycle-status" `
        -Command $statusCommand `
        -FailureCode "installed_lifecycle_identity_prerequisite_blocked" `
        -StatusOnError "blocked" `
        -Action { throw "installed_lifecycle_identity_prerequisite_blocked" }
}

$templateGate = $script:SteinPhase2EvidenceSpecification.gates_by_id["P2-NOTIFICATION"]
$templateProofArtifacts = New-Object Collections.Generic.List[object]
$templateProofArtifactIds = New-Object Collections.Generic.List[string]
foreach ($proofClass in @($templateGate.required_proof_classes)) {
    $artifactId = "proof-$($proofClass.Replace('_', '-'))"
    $templateProofArtifactIds.Add($artifactId)
    $templateProofArtifacts.Add([ordered]@{
        artifact_id = $artifactId
        proof_class = [string]$proofClass
        origin = "installed_native"
        sha256 = "<sha256>"
        size = "<positive-byte-count>"
    })
}
$templateSubchecks = New-Object Collections.Generic.List[object]
for ($templateIndex = 0; $templateIndex -lt @($templateGate.required_subchecks).Count;
    $templateIndex++) {
    $templateSubchecks.Add([ordered]@{
        id = [string]@($templateGate.required_subchecks)[$templateIndex]
        origin = "installed_native"
        result = "pass"
        artifact_ids = @($templateProofArtifactIds[$templateIndex % $templateProofArtifactIds.Count])
        source_check_ids = @()
    })
}
$attachmentTemplateArtifacts = @(
    [ordered]@{
        artifact_id = "source-verification-report"
        path = "C:\synthetic-evidence\source-verification.json"
        sha256 = "<sha256>"
        size = "<positive-byte-count>"
    },
    [ordered]@{
        artifact_id = "source-root-anchor"
        path = "C:\synthetic-evidence\source-root-anchor.json"
        sha256 = "<sha256>"
        size = "<positive-byte-count>"
    }
)
foreach ($artifact in @($templateProofArtifacts)) {
    $attachmentTemplateArtifacts += [ordered]@{
        artifact_id = [string]$artifact.artifact_id
        path = "C:\synthetic-evidence\$($artifact.artifact_id).json"
        sha256 = "<sha256>"
        size = "<positive-byte-count>"
    }
}
$attachmentTemplate = [ordered]@{
    schema_version = 2
    attachments = @(
        [ordered]@{
            attachment_id = "notification-screenshot-01"
            gate_id = "P2-NOTIFICATION"
            kind = "redacted_screenshot"
            path = "C:\synthetic-evidence\notification.png"
            sha256 = "<64 lowercase hexadecimal characters>"
            declared_result = "pass"
            privacy_reviewed = $true
            synthetic_only = $true
            recorded_at_utc = "2026-08-20T12:00:00Z"
            artifacts = @()
        },
        [ordered]@{
            attachment_id = "native-notification-fixture-01"
            gate_id = "P2-NOTIFICATION"
            kind = "native_fixture_result"
            path = "C:\synthetic-evidence\native-notification-result.json"
            sha256 = "<64 lowercase hexadecimal characters>"
            declared_result = "pass"
            privacy_reviewed = $true
            synthetic_only = $true
            recorded_at_utc = "2026-08-20T12:00:00Z"
            artifacts = $attachmentTemplateArtifacts
        }
    )
    rules = @(
        "Paths are used only for read-only hash validation and are never retained.",
        "Attachment files are never copied into evidence.",
        "A screenshot never changes a ledger result.",
        "Every underlying artifact is rehashed and its source path is never retained.",
        "A native result must satisfy the checked-in exact gate evidence contract.",
        "A hash-validated native pass remains not_run until independently reviewed."
    )
}
$attachmentTemplateArtifact = Write-SteinInstalledEvidenceJson `
    -RelativePath "attachments-template.json" `
    -Value $attachmentTemplate
$nativeFixtureResultTemplate = [ordered]@{
    schema_version = 2
    contract_id = [string]$script:SteinPhase2EvidenceSpecification.specification.contract_id
    contract_sha256 = $script:SteinPhase2EvidenceSpecificationSha256
    gate_id = "P2-NOTIFICATION"
    fixture_id = [string]$templateGate.fixture_id
    runner_id = [string]$templateGate.runner_id
    result = "pass"
    recorded_at_utc = "2026-08-20T12:00:00Z"
    exit_code = 0
    runner = [ordered]@{
        platform = "windows"
        architecture = "x86_64"
        non_elevated = $true
        installed_package = $true
    }
    proof_classes = @($templateGate.required_proof_classes)
    subchecks = @($templateSubchecks | ForEach-Object { $_ })
    bindings = [ordered]@{
        package = [ordered]@{
            package_family_name = "<exact-installed-pfn>"
            version = $Version
            msix_sha256 = "<sha256>"
            core_sha256 = "<sha256>"
            browser_host_sha256 = "<sha256>"
            cli_executable_size = 1
            cli_executable_sha256 = "<sha256>"
            desktop_executable_size = 1
            desktop_executable_sha256 = "<sha256>"
            desktop_dist_file_count = 1
            desktop_dist_manifest_sha256 = "<sha256>"
            candidate_git_commit = "<signed-candidate-commit>"
            candidate_git_tree = "<signed-candidate-tree>"
            source_verification_sha256 = "<sha256>"
            source_root_anchor_sha256 = "<sha256>"
            source_root_digest_sha256 = "<sha256>"
        }
        commit = [ordered]@{
            object_id = "<signed-candidate-commit>"
            tree_id = "<signed-candidate-tree>"
        }
        collector = [ordered]@{
            host_identity_sha256 = $hostIdentityHash
            evidence_owner_sid_only = $true
        }
        source_report = [ordered]@{
            report_artifact_id = "source-verification-report"
            root_anchor_artifact_id = "source-root-anchor"
            report_sha256 = "<sha256>"
            root_anchor_sha256 = "<sha256>"
            root_digest_sha256 = "<sha256>"
        }
        linux_artifact = $null
        runner_artifacts = @()
    }
    artifacts = @(
        [ordered]@{
            artifact_id = "source-verification-report"
            proof_class = "source_provenance"
            origin = "source_verification"
            sha256 = "<sha256>"
            size = "<positive-byte-count>"
        },
        [ordered]@{
            artifact_id = "source-root-anchor"
            proof_class = "source_provenance"
            origin = "source_verification"
            sha256 = "<sha256>"
            size = "<positive-byte-count>"
        }
    ) + @($templateProofArtifacts | ForEach-Object { $_ })
}
$nativeFixtureResultTemplateArtifact = Write-SteinInstalledEvidenceJson `
    -RelativePath "native-fixture-result-template.json" `
    -Value $nativeFixtureResultTemplate

$attachmentCommandArguments = if ([string]::IsNullOrWhiteSpace($AttachmentManifest)) {
    @("-AttachmentManifest", "<not-supplied>")
}
else {
    @("-AttachmentManifest", (Get-SteinInstalledPathToken -Path $AttachmentManifest))
}
$attachmentCommand = New-SteinInstalledCommandRecord `
    -Identity "Verify-Installed.ps1::validate-operator-attachments" `
    -Executable "powershell-host" `
    -Arguments $attachmentCommandArguments
if ([string]::IsNullOrWhiteSpace($AttachmentManifest)) {
    $attachmentCheck = Add-SteinInstalledNotRunCheck `
        -Id "operator-attachments" `
        -Command $attachmentCommand `
        -ReasonCode "operator_attachment_manifest_not_supplied" `
        -Result ([ordered]@{
            attachments = @()
            template = $attachmentTemplateArtifact
            native_fixture_result_template = $nativeFixtureResultTemplateArtifact
            attachment_files_copied = $false
        })
}
else {
    $attachmentCheck = Invoke-SteinInstalledCheck `
        -Id "operator-attachments" `
        -Command $attachmentCommand `
        -FailureCode "operator_attachment_validation_failed" `
        -StatusOnError "fail" `
        -Action {
            $script:SteinInstalledAttachments = @(Read-SteinInstalledAttachments `
                -ManifestPath $AttachmentManifest)
            [ordered]@{
                verified = $true
                attachments = $script:SteinInstalledAttachments
                template = $attachmentTemplateArtifact
                native_fixture_result_template = $nativeFixtureResultTemplateArtifact
                source_manifest_path_retained = $false
                attachment_files_copied = $false
                pass_results_promoted_to_ledger_pass = $false
            }
        }
}

$generatorCommand = New-SteinInstalledCommandRecord `
    -Identity "Verify-Installed.ps1::reverify-runtime-source-digests" `
    -Executable "powershell-host" `
    -Arguments @("-GeneratorArtifact", $generatorArtifact.sha256)
$generatorCheck = Invoke-SteinInstalledCheck `
    -Id "evidence-generator-stability" `
    -Command $generatorCommand `
    -FailureCode "runtime_evidence_source_changed" `
    -StatusOnError "fail" `
    -Action {
        $stableSources = @(Assert-SteinInstalledRuntimeSourcesStable)
        [ordered]@{
            verified = $true
            generator = $generatorArtifact
            runtime_source_file_count = $stableSources.Count
            source_paths = "repository_relative_only"
        }
    }

$rowState = @{}
foreach ($gateId in $script:SteinPhase2GateIds) {
    $rowState[$gateId] = [ordered]@{
        status = "not_run"
        reason_code = "required_installed_fixture_not_executed_by_read_only_harness"
    }
}

function Set-SteinInstalledGateState {
    param(
        [Parameter(Mandatory = $true)][string] $GateId,
        [Parameter(Mandatory = $true)][ValidateSet("fail", "blocked", "not_run")][string] $Status,
        [Parameter(Mandatory = $true)][string] $ReasonCode
    )

    $priority = @{ not_run = 1; blocked = 2; fail = 3 }
    if ($priority[$Status] -ge $priority[[string]$rowState[$GateId].status]) {
        $rowState[$GateId] = [ordered]@{
            status = $Status
            reason_code = $ReasonCode
        }
    }
}

if ($bundleCheck.status -ceq "fail") {
    Set-SteinInstalledGateState -GateId "P2-BUILD" -Status "fail" `
        -ReasonCode "exact_signed_release_bundle_verification_failed"
}
elseif ($bundleCheck.status -ceq "blocked") {
    Set-SteinInstalledGateState -GateId "P2-BUILD" -Status "blocked" `
        -ReasonCode "exact_signed_release_bundle_verification_blocked"
}
if ($generatorCheck.status -ceq "fail") {
    Set-SteinInstalledGateState -GateId "P2-BUILD" -Status "fail" `
        -ReasonCode "runtime_evidence_source_changed_during_collection"
}
if ($installedCheck.status -ceq "fail") {
    Set-SteinInstalledGateState -GateId "P2-PRIVATE-CLIENT" -Status "fail" `
        -ReasonCode "installed_private_identity_prerequisite_failed"
}
elseif ($installedCheck.status -ceq "blocked") {
    Set-SteinInstalledGateState -GateId "P2-PRIVATE-CLIENT" -Status "blocked" `
        -ReasonCode "installed_private_identity_prerequisite_blocked"
}
if ($statusCheck.status -ceq "fail") {
    Set-SteinInstalledGateState -GateId "P2-PERSISTENCE" -Status "fail" `
        -ReasonCode "installed_persistence_readiness_failed"
}
elseif ($statusCheck.status -ceq "blocked") {
    Set-SteinInstalledGateState -GateId "P2-PERSISTENCE" -Status "blocked" `
        -ReasonCode "installed_persistence_readiness_blocked"
}
if ($attachmentCheck.status -ceq "fail") {
    Set-SteinInstalledGateState -GateId "P2-NO-LEAKS" -Status "blocked" `
        -ReasonCode "operator_attachment_privacy_or_hash_validation_failed"
}

if ($attachmentCheck.status -ceq "pass") {
    foreach ($attachment in $script:SteinInstalledAttachments) {
        if ($attachment.kind -cne "native_fixture_result") {
            continue
        }
        switch ([string]$attachment.declared_result) {
            "fail" {
                Set-SteinInstalledGateState -GateId $attachment.gate_id -Status "fail" `
                    -ReasonCode "hash_validated_native_fixture_declares_failure"
            }
            "blocked" {
                Set-SteinInstalledGateState -GateId $attachment.gate_id -Status "blocked" `
                    -ReasonCode "hash_validated_native_fixture_declares_blocked"
            }
            "pass" {
                Set-SteinInstalledGateState -GateId $attachment.gate_id -Status "not_run" `
                    -ReasonCode "hash_validated_native_pass_requires_independent_semantic_review"
            }
        }
    }
}

$supportingCheckIds = @{
    "P2-BUILD" = @(
        "installed-host-preflight", "signed-release-bundle", "evidence-generator-stability")
    "P2-PRIVATE-CLIENT" = @(
        "installed-host-preflight", "signed-release-bundle",
        "installed-bundle-and-private-identity-pins")
    "P2-PERSISTENCE" = @(
        "installed-bundle-and-private-identity-pins", "installed-lifecycle-status")
    "P2-UPGRADE" = @("installed-bundle-and-private-identity-pins", "installed-lifecycle-status")
    "P2-DAEMON-RESTART" = @("installed-lifecycle-status")
    "P2-NO-LEAKS" = @("operator-attachments")
}

$packageProvenance = [ordered]@{
    publisher = $Publisher
    signing_certificate_thumbprint = $normalizedThumbprint
    version = $Version
    package_path = $packagePathToken
    release_identity_schema_version = $script:SteinPhase2IdentitySchemaVersion
    install_record_schema_version = $script:SteinPhase2InstallSchemaVersion
    package_family_name = $null
    desktop_aumid = $null
    broker_aumid = $null
    browser_producer_aumid = $null
    msix_sha256 = $null
    core_sha256 = $null
    browser_host_sha256 = $null
    candidate_git_commit = $null
    candidate_git_tree = $null
    source_verification_sha256 = $null
    source_root_anchor_sha256 = $null
    source_root_digest_sha256 = $null
    installed_payload_file_count = 0
    cli_executable_size = 0
    cli_executable_sha256 = $null
    desktop_executable_size = 0
    desktop_executable_sha256 = $null
    desktop_dist_file_count = 0
    desktop_dist_manifest_sha256 = $null
}
if ($null -ne $script:SteinInstalledSourceBundle) {
    $packageProvenance.package_family_name = $script:SteinInstalledSourceBundle.PackageFamilyName
    $packageProvenance.desktop_aumid = $script:SteinInstalledSourceBundle.DesktopAumid
    $packageProvenance.broker_aumid = $script:SteinInstalledSourceBundle.BrokerAumid
    $packageProvenance.browser_producer_aumid = $script:SteinInstalledSourceBundle.BrowserProducerAumid
    $packageProvenance.msix_sha256 = $script:SteinInstalledSourceBundle.MsixSha256
    $packageProvenance.core_sha256 = $script:SteinInstalledSourceBundle.CoreSha256
    $packageProvenance.browser_host_sha256 = $script:SteinInstalledSourceBundle.BrowserHostSha256
    $packageProvenance.candidate_git_commit = $script:SteinInstalledSourceBundle.CandidateGitCommit
    $packageProvenance.candidate_git_tree = $script:SteinInstalledSourceBundle.CandidateGitTree
    $packageProvenance.source_verification_sha256 =
        $script:SteinInstalledSourceBundle.SourceVerificationSha256
    $packageProvenance.source_root_anchor_sha256 =
        $script:SteinInstalledSourceBundle.SourceRootAnchorSha256
    $packageProvenance.source_root_digest_sha256 =
        $script:SteinInstalledSourceBundle.SourceRootDigestSha256
    $packageProvenance.installed_payload_file_count = @(
        $script:SteinInstalledSourceBundle.InstalledPayloadFiles).Count
    $packageProvenance.cli_executable_size = $script:SteinInstalledSourceBundle.CliSize
    $packageProvenance.cli_executable_sha256 = $script:SteinInstalledSourceBundle.CliSha256
    $packageProvenance.desktop_executable_size = $script:SteinInstalledSourceBundle.DesktopSize
    $packageProvenance.desktop_executable_sha256 = $script:SteinInstalledSourceBundle.DesktopSha256
    $packageProvenance.desktop_dist_file_count =
        $script:SteinInstalledSourceBundle.DesktopDistFileCount
    $packageProvenance.desktop_dist_manifest_sha256 =
        $script:SteinInstalledSourceBundle.DesktopDistManifestSha256
}
$runtimeBuildId = $null
$runtimeProtocolVersion = $null
if ($null -ne $script:SteinInstalledStatusProjection) {
    $runtimeBuildId = $script:SteinInstalledStatusProjection.runtime.build_id
    $runtimeProtocolVersion = $script:SteinInstalledStatusProjection.runtime.protocol_version
}
$versionProvenance = [ordered]@{
    package_version = $Version
    runtime_build_id = $runtimeBuildId
    protocol_version = $runtimeProtocolVersion
    release_identity_schema_version = $script:SteinPhase2IdentitySchemaVersion
    install_record_schema_version = $script:SteinPhase2InstallSchemaVersion
    durable_persistence_capability_schema_version = 1
    numeric_database_schema_reported = $false
    expected_policy_profile_id = $script:SteinPhase2ExpectedPolicyProfileId
    policy_profile_reported_by_installed_runtime = $false
}

$ledgerRows = New-Object Collections.Generic.List[object]
$rowsRoot = Join-Path $script:SteinInstalledEvidencePath "ledger-rows"
$null = New-Item -ItemType Directory -Path $rowsRoot -ErrorAction Stop
Protect-SteinPhase2OwnerOnlyPath -Path $rowsRoot
foreach ($gateId in $script:SteinPhase2GateIds) {
    $checkIds = if ($supportingCheckIds.ContainsKey($gateId)) {
        @($supportingCheckIds[$gateId])
    }
    else { @() }
    $commands = @($checkIds | ForEach-Object {
        $check = Get-SteinInstalledCheck -Id $_
        [ordered]@{
            check_id = $check.id
            status = $check.status
            command = $check.command
            exit_code = $check.exit_code
            output = $check.output
        }
    })
    $attachments = @($script:SteinInstalledAttachments | Where-Object { $_.gate_id -ceq $gateId })
    $rowPayload = [ordered]@{
        schema_version = 1
        gate_id = $gateId
        status = [string]$rowState[$gateId].status
        reason_code = [string]$rowState[$gateId].reason_code
        harness_identity = "phase2-installed-evidence-v1"
        generator_provenance = $generatorArtifact
        host_provenance = $hostArtifact
        package = $packageProvenance
        versions = $versionProvenance
        policy_profile = [ordered]@{
            expected_id = $script:SteinPhase2ExpectedPolicyProfileId
            reported_by_installed_runtime = $false
            accepted_as_installed_policy_evidence = $false
        }
        commands = $commands
        attachments = $attachments
        screenshot_can_prove_gate = $false
        attached_pass_promoted_by_harness = $false
    }
    $rowLeaf = ($gateId.ToLowerInvariant() -replace "[^a-z0-9._-]", "-") + ".json"
    $rowArtifact = Write-SteinInstalledEvidenceJson `
        -RelativePath ("ledger-rows\$rowLeaf") `
        -Value $rowPayload
    $outputArtifacts = @($commands | ForEach-Object { $_.output }) + @($rowArtifact)
    $ledgerRows.Add([ordered]@{
        gate_id = $gateId
        status = $rowPayload.status
        reason_code = $rowPayload.reason_code
        harness_identity = $rowPayload.harness_identity
        versions = $versionProvenance
        commands = $commands
        output_artifacts = $outputArtifacts
        attachments = $attachments
        generator_provenance = $generatorArtifact
        host_provenance = $hostArtifact
        row_artifact = $rowArtifact
    })
}

Assert-SteinInstalledExternalEvidenceFilesStable
$completedAt = [DateTime]::UtcNow
$checkFailures = @($script:SteinInstalledChecks | Where-Object { $_.status -ceq "fail" })
$checkBlocked = @($script:SteinInstalledChecks | Where-Object { $_.status -ceq "blocked" })
$rowFailures = @($ledgerRows | Where-Object { $_.status -ceq "fail" })
$rowBlocked = @($ledgerRows | Where-Object { $_.status -ceq "blocked" })
$baselineChecks = @($preflight, $bundleCheck, $installedCheck, $statusCheck, $generatorCheck)
$machineVerificationPassed = @(
    $baselineChecks | Where-Object { $_.status -cne "pass" }).Count -eq 0
$completeAcceptance = @($ledgerRows | Where-Object { $_.status -cne "pass" }).Count -eq 0
$ledger = [ordered]@{
    schema_version = 1
    run_id = $runId
    claim = "installed_machine_verification_only"
    installed_or_signed_evidence = (
        $bundleCheck.status -ceq "pass" -and $installedCheck.status -ceq "pass")
    machine_verification_passed = $machineVerificationPassed
    complete_acceptance = $completeAcceptance
    started_at_utc = $startedAt.ToString("o")
    completed_at_utc = $completedAt.ToString("o")
    duration_ms = [long]($completedAt - $startedAt).TotalMilliseconds
    generator_provenance = $generatorArtifact
    host_provenance = $hostArtifact
    package = $packageProvenance
    schema_versions = [ordered]@{
        ledger = 1
        release_identity = $script:SteinPhase2IdentitySchemaVersion
        install_record = $script:SteinPhase2InstallSchemaVersion
        durable_persistence_capability = 1
    }
    policy_profile = [ordered]@{
        expected_id = $script:SteinPhase2ExpectedPolicyProfileId
        reported_by_installed_runtime = $false
        policy_dependent_rows_may_pass = $false
    }
    privacy = [ordered]@{
        provider_credentials_accessed = $false
        private_protocol_snapshot_requested = $false
        private_source_payload_retained = $false
        local_paths_replaced_with_sha256_tokens = $true
        attachment_source_paths_retained = $false
        attachment_files_copied = $false
        operator_privacy_review_required = $true
    }
    mutation = [ordered]@{
        package_install_or_remove = $false
        task_start_stop_or_registration = $false
        daemon_start_stop_or_restart = $false
        credential_read_write_or_delete = $false
        installed_state_mutated = $false
        temporary_msix_verification_unpack = $true
        persistent_outputs_evidence_directory_only = $true
    }
    checks = @($script:SteinInstalledChecks | ForEach-Object { $_ })
    rows = @($ledgerRows | ForEach-Object { $_ })
    summary = [ordered]@{
        checks = [ordered]@{
            pass = @($script:SteinInstalledChecks | Where-Object { $_.status -ceq "pass" }).Count
            fail = $checkFailures.Count
            blocked = $checkBlocked.Count
            not_run = @($script:SteinInstalledChecks | Where-Object { $_.status -ceq "not_run" }).Count
        }
        rows = [ordered]@{
            pass = @($ledgerRows | Where-Object { $_.status -ceq "pass" }).Count
            fail = $rowFailures.Count
            blocked = $rowBlocked.Count
            not_run = @($ledgerRows | Where-Object { $_.status -ceq "not_run" }).Count
        }
    }
}
$ledgerArtifact = Write-SteinInstalledEvidenceJson -RelativePath "ledger.json" -Value $ledger
$rootMaterial = @(
    "phase2-installed-evidence-root-v1",
    $runId,
    $generatorArtifact.sha256,
    $hostArtifact.sha256,
    $ledgerArtifact.sha256
) -join "`0"
$rootDigest = Get-SteinInstalledStringSha256 -Value $rootMaterial
$rootAnchor = [ordered]@{
    schema_version = 1
    run_id = $runId
    harness_identity = "phase2-installed-evidence-v1"
    digest_algorithm = "sha256"
    root_digest_sha256 = $rootDigest
    digest_material = "identity_nul_run_nul_generator_nul_host_nul_ledger"
    generator = $generatorArtifact
    host = $hostArtifact
    ledger = $ledgerArtifact
    trust_scope = "content_integrity_only_not_authentication"
}
$rootAnchorArtifact = Write-SteinInstalledEvidenceJson `
    -RelativePath "root-anchor.json" `
    -Value $rootAnchor
Assert-SteinInstalledExternalEvidenceFilesStable
Protect-SteinPhase2OwnerOnlyTree -Root $script:SteinInstalledEvidencePath
$null = Assert-SteinInstalledRuntimeSourcesStable

$evidenceDisplayPath = $script:SteinInstalledEvidencePath.Substring($repoRoot.Length + 1)
$evidenceDisplayPath = $evidenceDisplayPath.Replace("\", "/")
Write-Host "Installed evidence directory (repository-relative): $evidenceDisplayPath"
Write-Host "Ledger SHA-256: $($ledgerArtifact.sha256)"
Write-Host "Evidence root SHA-256: $rootDigest"
Write-Host "Root anchor artifact SHA-256: $($rootAnchorArtifact.sha256)"
Write-Host "Complete Phase 2 acceptance: $completeAcceptance"

if ($checkFailures.Count -ne 0 -or $rowFailures.Count -ne 0) {
    exit 1
}
if ($checkBlocked.Count -ne 0 -or $rowBlocked.Count -ne 0) {
    exit 2
}
exit 0
