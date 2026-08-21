[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $EvidenceDirectory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $ExpectedRootAnchorSha256,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ReviewManifest,

    [string] $OutputRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

# Keep validation failures content-minimized. Unhandled PowerShell errors normally
# include absolute script/input paths and source excerpts in the error stream.
trap {
    $message = [string]$_.Exception.Message
    $failureCode = if ($message -cmatch '^[a-z][a-z0-9_]{2,127}$') {
        $message
    }
    else {
        "review_validation_failed"
    }
    [Console]::Error.WriteLine($failureCode)
    exit 1
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..")).Path
$commonPath = Join-Path $PSScriptRoot "Common.ps1"

function Get-SteinReviewLockedStreamSha256 {
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

function Open-SteinReviewBootstrapFileBinding {
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
        throw "reviewer_runtime_source_outside_repository"
    }
    $probe = Split-Path -Parent $resolved
    while ($probe.Length -ge $repository.Length) {
        $ancestor = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $ancestor.PSIsContainer -or
            (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "reviewer_runtime_source_invalid"
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
            throw "reviewer_runtime_source_invalid"
        }
        $probe = $parent
    }
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0) {
        throw "reviewer_runtime_source_invalid"
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne [long]$item.Length) {
            throw "reviewer_runtime_source_invalid"
        }
        $digest = Get-SteinReviewLockedStreamSha256 `
            -Stream $stream `
            -FailureCode "reviewer_runtime_source_invalid"
        $current = Get-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
        if ($current.PSIsContainer -or
            (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            [long]$current.Length -ne [long]$item.Length) {
            throw "reviewer_runtime_source_invalid"
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

$script:SteinReviewRuntimeSourceDefinitions = @(
    [pscustomobject]@{ role = "reviewer"; path = $PSCommandPath },
    [pscustomobject]@{ role = "launcher"; path = (Join-Path $PSScriptRoot "Review-Installed.cmd") },
    [pscustomobject]@{ role = "phase2-common"; path = $commonPath },
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
    [pscustomobject]@{
        role = "package-tools"
        path = (Join-Path $repoRoot "packaging\windows-msix\PackageTools.ps1")
    }
) | Sort-Object role
$script:SteinReviewRuntimeSourceBindings = @(
    $script:SteinReviewRuntimeSourceDefinitions | ForEach-Object {
        Open-SteinReviewBootstrapFileBinding `
            -Role $_.role `
            -Path $_.path `
            -RepositoryRoot $repoRoot
    }
)
$script:SteinReviewInitialRuntimeSources = @(
    $script:SteinReviewRuntimeSourceBindings | ForEach-Object { $_.record })

$commonBinding = @($script:SteinReviewRuntimeSourceBindings | Where-Object {
        [string]$_.record.role -ceq "phase2-common"
    })
if ($commonBinding.Count -ne 1) {
    throw "reviewer_runtime_source_invalid"
}
. $commonBinding[0].full_path
if ((Get-SteinReviewLockedStreamSha256 `
            -Stream $commonBinding[0].stream `
            -FailureCode "reviewer_runtime_source_changed") -cne
        [string]$commonBinding[0].record.sha256) {
    throw "reviewer_runtime_source_changed"
}

$script:SteinPhase2ReviewGateIds = @(
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
$evidenceContractBinding = @($script:SteinReviewRuntimeSourceBindings | Where-Object {
        [string]$_.record.role -ceq "evidence-contract"
    })
if ($evidenceContractBinding.Count -ne 1) {
    throw "reviewer_runtime_source_invalid"
}
$evidenceContractPath = [string]$evidenceContractBinding[0].full_path
$evidenceSpecificationPath = Join-Path $PSScriptRoot "Evidence-Spec.json"
. $evidenceContractPath
if ((Get-SteinReviewLockedStreamSha256 `
            -Stream $evidenceContractBinding[0].stream `
            -FailureCode "reviewer_runtime_source_changed") -cne
        [string]$evidenceContractBinding[0].record.sha256) {
    throw "reviewer_runtime_source_changed"
}
$initialEvidenceSpecification = @($script:SteinReviewInitialRuntimeSources | Where-Object {
        [string]$_.role -ceq "evidence-spec"
    })
if ($initialEvidenceSpecification.Count -ne 1) {
    throw "evidence_spec_runtime_source_missing"
}
$script:SteinPhase2ReviewEvidenceSpecificationSha256 =
    [string]$initialEvidenceSpecification[0].sha256
$script:SteinPhase2ReviewEvidenceSpecification = Read-SteinPhase2EvidenceSpecification `
    -Path $evidenceSpecificationPath `
    -ExpectedGateIds $script:SteinPhase2ReviewGateIds `
    -ExpectedSha256 $script:SteinPhase2ReviewEvidenceSpecificationSha256
$initialSourceFixtureRegistry = @(
    $script:SteinReviewInitialRuntimeSources | Where-Object {
        [string]$_.role -ceq 'source-fixture-registry'
    })
if ($initialSourceFixtureRegistry.Count -ne 1) {
    throw 'source_fixture_registry_runtime_source_missing'
}
$script:SteinPhase2ReviewSourceFixtureRegistry =
    Read-SteinPhase2SourceFixtureRegistry `
        -Path (Join-Path $PSScriptRoot 'Source-Fixture-Registry.json') `
        -ExpectedSha256 ([string]$initialSourceFixtureRegistry[0].sha256)
$script:SteinReviewArtifactCache = @{}
$script:SteinReviewAttachmentFiles = @{}
$script:SteinReviewCollectorRuntimeSourceFiles = @{}
$script:SteinReviewCollectorHostRecord = $null

function Assert-SteinReviewJsonShape {
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
        @(Compare-Object `
            -ReferenceObject $expected `
            -DifferenceObject $actual `
            -CaseSensitive).Count -ne 0) {
        throw $FailureCode
    }
}

function Assert-SteinReviewSchemaVersion {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if (($Value -isnot [int] -and $Value -isnot [long]) -or [long]$Value -ne 1) {
        throw $FailureCode
    }
}

function Assert-SteinReviewBoolean {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if ($Value -isnot [bool]) {
        throw $FailureCode
    }
}

function Assert-SteinReviewHash {
    param(
        [AllowNull()] $Value,
        [Parameter(Mandatory = $true)][string] $FailureCode,
        [switch] $AllowNull
    )

    if ($null -eq $Value -and $AllowNull) {
        return
    }
    if ($Value -isnot [string] -or [string]$Value -cnotmatch "^[0-9a-f]{64}$") {
        throw $FailureCode
    }
}

function Assert-SteinReviewInteger {
    param(
        [AllowNull()] $Value,
        [Parameter(Mandatory = $true)][string] $FailureCode,
        [switch] $AllowNull,
        [long] $Minimum = 0
    )

    if ($null -eq $Value -and $AllowNull) {
        return
    }
    if (($Value -isnot [int] -and $Value -isnot [long]) -or [long]$Value -lt $Minimum) {
        throw $FailureCode
    }
}

function Assert-SteinReviewTimestamp {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    $parsed = [DateTimeOffset]::MinValue
    if ($Value -is [DateTimeOffset]) {
        $parsed = ([DateTimeOffset]$Value).ToUniversalTime()
    }
    elseif ($Value -is [DateTime]) {
        $parsed = ([DateTimeOffset]([DateTime]$Value)).ToUniversalTime()
    }
    elseif ($Value -is [string]) {
        if (-not [DateTimeOffset]::TryParse(
                [string]$Value,
                [Globalization.CultureInfo]::InvariantCulture,
                ([Globalization.DateTimeStyles]::AssumeUniversal -bor
                    [Globalization.DateTimeStyles]::AdjustToUniversal),
                [ref]$parsed)) {
            throw $FailureCode
        }
    }
    else {
        throw $FailureCode
    }
    if ($parsed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        throw $FailureCode
    }
    return $parsed
}

function ConvertTo-SteinReviewTimestampString {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    $parsed = Assert-SteinReviewTimestamp -Value $Value -FailureCode $FailureCode
    if ($null -eq $parsed -or
        $parsed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        throw $FailureCode
    }
    return ([DateTimeOffset]$parsed).ToUniversalTime().ToString("o")
}

function Get-SteinReviewStringSha256 {
    param([Parameter(Mandatory = $true)][string] $Value)

    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha256.ComputeHash($bytes)).
            Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Test-SteinReviewJsonEqual {
    param(
        [AllowNull()] $Left,
        [AllowNull()] $Right
    )

    $leftJson = $Left | ConvertTo-Json -Compress -Depth 32
    $rightJson = $Right | ConvertTo-Json -Compress -Depth 32
    return $leftJson -ceq $rightJson
}

function Assert-SteinReviewNoPrivateValues {
    param(
        [AllowNull()] $Value,
        [string] $Context = "evidence"
    )

    if ($null -eq $Value) {
        return
    }
    if ($Value -is [string]) {
        $text = [string]$Value
        if ($text -match '(?i)(?:^|[\s"''=])(?:[a-z]:[\\/]|\\\\|\\\\\?\\|\\\\\.\\)' -or
            $text -match '(?i)(?:^|[\\/])(?:users|home)[\\/][^\\/\s]+' -or
            $text -match '(?i)(?:^|[^a-z0-9])S-1-[0-9]+(?:-[0-9]+){2,}(?:[^a-z0-9]|$)') {
            throw "private_value_leak_detected"
        }
        if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME) -and
            $env:COMPUTERNAME.Length -ge 3 -and
            $text.IndexOf($env:COMPUTERNAME, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "raw_host_name_leak_detected"
        }
        return
    }
    if ($Value -is [ValueType]) {
        return
    }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            Assert-SteinReviewNoPrivateValues -Value $Value[$key] -Context "$Context.$key"
        }
        return
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($entry in $Value) {
            Assert-SteinReviewNoPrivateValues -Value $entry -Context $Context
        }
        return
    }
    foreach ($property in @($Value.PSObject.Properties)) {
        Assert-SteinReviewNoPrivateValues `
            -Value $property.Value `
            -Context "$Context.$($property.Name)"
    }
}

function Assert-SteinReviewNoReparseAncestors {
    param([Parameter(Mandatory = $true)][string] $Path)

    $probe = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrWhiteSpace($probe)) {
        if (Test-Path -LiteralPath $probe) {
            $item = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "reparse_path_rejected"
            }
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            break
        }
        $probe = $parent
    }
}

function Assert-SteinReviewArtifactsPath {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Description,
        [switch] $RequireDirectory
    )

    $artifactsRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot "artifacts")).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $canonical = [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $prefix = "$artifactsRoot$([IO.Path]::DirectorySeparatorChar)"
    if (-not $canonical.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "${Description}_outside_repository_artifacts"
    }
    Assert-SteinReviewNoReparseAncestors -Path $canonical
    if ($RequireDirectory) {
        $item = Get-Item -LiteralPath $canonical -Force -ErrorAction Stop
        if (-not $item.PSIsContainer) {
            throw "${Description}_not_directory"
        }
    }
    return $canonical
}

function Resolve-SteinReviewContainedFile {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)] $RelativePath,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if ($RelativePath -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$RelativePath) -or
        ([string]$RelativePath).Length -gt 512 -or
        [IO.Path]::IsPathRooted([string]$RelativePath) -or
        [string]$RelativePath -cmatch '\\' -or
        [string]$RelativePath -cnotmatch '^[A-Za-z0-9._/-]+$') {
        throw $FailureCode
    }
    $segments = @(([string]$RelativePath).Split('/'))
    if ($segments.Count -eq 0 -or
        @($segments | Where-Object {
            [string]::IsNullOrWhiteSpace($_) -or $_ -ceq "." -or $_ -ceq ".."
        }).Count -ne 0) {
        throw $FailureCode
    }
    $canonicalRoot = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $candidate = [IO.Path]::GetFullPath((Join-Path $canonicalRoot ([string]$RelativePath)))
    $prefix = "$canonicalRoot$([IO.Path]::DirectorySeparatorChar)"
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw $FailureCode
    }
    $probe = $canonicalRoot
    foreach ($segment in $segments) {
        $probe = Join-Path $probe $segment
        $item = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "reparse_path_rejected"
        }
    }
    $file = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -le 0) {
        throw $FailureCode
    }
    return $file.FullName
}

function Read-SteinReviewJsonFile {
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
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw $FailureCode
    }
    if ($ExpectedSize -ge 0 -and $item.Length -ne $ExpectedSize) {
        throw "json_artifact_hash_or_size_mismatch"
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256) -and
        $ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw $FailureCode
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $item.Length -or
            $stream.Length -le 0 -or
            $stream.Length -gt $MaximumBytes -or
            ($ExpectedSize -ge 0 -and $stream.Length -ne $ExpectedSize)) {
            throw "json_artifact_hash_or_size_mismatch"
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "json_artifact_hash_or_size_mismatch"
            }
            $offset += $read
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
            $sha256 = [Security.Cryptography.SHA256]::Create()
            try {
                $digest = [BitConverter]::ToString($sha256.ComputeHash($bytes)).
                    Replace("-", "").ToLowerInvariant()
            }
            finally {
                $sha256.Dispose()
            }
            if ($digest -cne $ExpectedSha256) {
                throw "json_artifact_hash_or_size_mismatch"
            }
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
        return $jsonText | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw $FailureCode
    }
}

function Assert-SteinReviewArtifactDescriptor {
    param(
        [Parameter(Mandatory = $true)] $Descriptor,
        [Parameter(Mandatory = $true)][string] $EvidenceRoot,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    Assert-SteinReviewJsonShape -Value $Descriptor `
        -ExpectedProperties @("path", "size", "sha256") `
        -FailureCode $FailureCode
    Assert-SteinReviewHash -Value $Descriptor.sha256 -FailureCode $FailureCode
    Assert-SteinReviewInteger -Value $Descriptor.size -Minimum 1 -FailureCode $FailureCode
    $path = Resolve-SteinReviewContainedFile `
        -Root $EvidenceRoot `
        -RelativePath $Descriptor.path `
        -FailureCode $FailureCode
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.Length -ne [long]$Descriptor.size -or
        (Get-SteinPhase2Sha256 -Path $path) -cne [string]$Descriptor.sha256) {
        throw "evidence_artifact_hash_or_size_mismatch"
    }
    $cacheKey = ([string]$Descriptor.path).ToLowerInvariant()
    if ($script:SteinReviewArtifactCache.ContainsKey($cacheKey)) {
        $existing = $script:SteinReviewArtifactCache[$cacheKey]
        if ([long]$existing.size -ne [long]$Descriptor.size -or
            [string]$existing.sha256 -cne [string]$Descriptor.sha256) {
            throw "evidence_artifact_descriptor_conflict"
        }
    }
    else {
        $script:SteinReviewArtifactCache[$cacheKey] = [pscustomobject]@{
            path = $path
            size = [long]$item.Length
            sha256 = [string]$Descriptor.sha256
        }
    }
    return $path
}

function Assert-SteinReviewArtifactCacheStable {
    foreach ($entry in $script:SteinReviewArtifactCache.Values) {
        $item = Get-Item -LiteralPath $entry.path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $item.Length -ne [long]$entry.size -or
            (Get-SteinPhase2Sha256 -Path $entry.path) -cne [string]$entry.sha256) {
            throw "evidence_changed_during_review"
        }
    }
}

function Register-SteinReviewNestedArtifactDescriptors {
    param(
        [AllowNull()] $Value,
        [Parameter(Mandatory = $true)][string] $EvidenceRoot,
        [int] $Depth = 0
    )

    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {
        return
    }
    if ($Depth -gt 32) {
        throw "collector_nested_artifact_depth_invalid"
    }
    if ($Value -is [Collections.IDictionary]) {
        $keys = @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)
        if ($keys.Count -eq 3 -and
            @(Compare-Object `
                -ReferenceObject @("path", "sha256", "size") `
                -DifferenceObject $keys `
                -CaseSensitive).Count -eq 0) {
            $descriptor = [pscustomobject]@{
                path = $Value["path"]
                size = $Value["size"]
                sha256 = $Value["sha256"]
            }
            $null = Assert-SteinReviewArtifactDescriptor `
                -Descriptor $descriptor `
                -EvidenceRoot $EvidenceRoot `
                -FailureCode "collector_nested_artifact_invalid"
            return
        }
        foreach ($key in $Value.Keys) {
            Register-SteinReviewNestedArtifactDescriptors `
                -Value $Value[$key] `
                -EvidenceRoot $EvidenceRoot `
                -Depth ($Depth + 1)
        }
        return
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($entry in $Value) {
            Register-SteinReviewNestedArtifactDescriptors `
                -Value $entry `
                -EvidenceRoot $EvidenceRoot `
                -Depth ($Depth + 1)
        }
        return
    }
    $properties = @($Value.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    if ($properties.Count -eq 3 -and
        @(Compare-Object `
            -ReferenceObject @("path", "sha256", "size") `
            -DifferenceObject $properties `
            -CaseSensitive).Count -eq 0) {
        $null = Assert-SteinReviewArtifactDescriptor `
            -Descriptor $Value `
            -EvidenceRoot $EvidenceRoot `
            -FailureCode "collector_nested_artifact_invalid"
        return
    }
    foreach ($property in @($Value.PSObject.Properties)) {
        Register-SteinReviewNestedArtifactDescriptors `
            -Value $property.Value `
            -EvidenceRoot $EvidenceRoot `
            -Depth ($Depth + 1)
    }
}

function Assert-SteinReviewExactFileTree {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string[]] $ExpectedFiles,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    $canonicalRoot = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $prefix = "$canonicalRoot$([IO.Path]::DirectorySeparatorChar)"
    $expectedFileSet = @{}
    $expectedDirectorySet = @{}
    foreach ($expectedFile in $ExpectedFiles) {
        $canonicalFile = [IO.Path]::GetFullPath($expectedFile)
        if (-not $canonicalFile.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw $FailureCode
        }
        $fileKey = $canonicalFile.ToLowerInvariant()
        if ($expectedFileSet.ContainsKey($fileKey)) {
            continue
        }
        $expectedFileSet[$fileKey] = $true
        $parent = Split-Path -Parent $canonicalFile
        while (-not [string]::IsNullOrWhiteSpace($parent) -and
            -not [string]::Equals(
                $parent,
                $canonicalRoot,
                [StringComparison]::OrdinalIgnoreCase)) {
            if (-not $parent.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw $FailureCode
            }
            $expectedDirectorySet[$parent.ToLowerInvariant()] = $true
            $next = Split-Path -Parent $parent
            if ($next -ceq $parent) {
                throw $FailureCode
            }
            $parent = $next
        }
    }

    $actualFileSet = @{}
    $actualDirectorySet = @{}
    $pending = New-Object Collections.Generic.Queue[string]
    $pending.Enqueue($canonicalRoot)
    while ($pending.Count -ne 0) {
        $directory = $pending.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "reparse_path_rejected"
            }
            $key = $item.FullName.ToLowerInvariant()
            if ($item.PSIsContainer) {
                if ($actualDirectorySet.ContainsKey($key)) {
                    throw $FailureCode
                }
                $actualDirectorySet[$key] = $true
                $pending.Enqueue($item.FullName)
            }
            else {
                if ($actualFileSet.ContainsKey($key)) {
                    throw $FailureCode
                }
                $actualFileSet[$key] = $true
            }
        }
    }
    if ($actualFileSet.Count -ne $expectedFileSet.Count -or
        $actualDirectorySet.Count -ne $expectedDirectorySet.Count -or
        @($actualFileSet.Keys | Where-Object {
            -not $expectedFileSet.ContainsKey($_)
        }).Count -ne 0 -or
        @($actualDirectorySet.Keys | Where-Object {
            -not $expectedDirectorySet.ContainsKey($_)
        }).Count -ne 0) {
        throw $FailureCode
    }
}

function Assert-SteinReviewCollectorRuntimeSourcesStable {
    foreach ($entry in $script:SteinReviewCollectorRuntimeSourceFiles.Values) {
        $item = Get-Item -LiteralPath $entry.path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $item.Length -ne [long]$entry.size -or
            (Get-SteinPhase2Sha256 -Path $entry.path) -cne [string]$entry.sha256) {
            throw "collector_runtime_source_changed_during_review"
        }
    }
}

function Assert-SteinReviewRuntimeSourcesStable {
    $bindings = @($script:SteinReviewRuntimeSourceBindings)
    if ($bindings.Count -ne $script:SteinReviewInitialRuntimeSources.Count) {
        throw "reviewer_runtime_source_changed"
    }
    for ($index = 0; $index -lt $bindings.Count; $index++) {
        $binding = $bindings[$index]
        $expected = $script:SteinReviewInitialRuntimeSources[$index]
        foreach ($property in @("role", "path", "size", "sha256")) {
            if ([string]$binding.record.$property -cne [string]$expected.$property) {
                throw "reviewer_runtime_source_changed"
            }
        }
        $item = Get-Item -LiteralPath $binding.full_path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            [long]$item.Length -ne [long]$expected.size -or
            [long]$binding.stream.Length -ne [long]$expected.size -or
            (Get-SteinReviewLockedStreamSha256 `
                -Stream $binding.stream `
                -FailureCode "reviewer_runtime_source_changed") -cne
                [string]$expected.sha256) {
            throw "reviewer_runtime_source_changed"
        }
    }
    return @($script:SteinReviewInitialRuntimeSources | ForEach-Object { $_ })
}

function Assert-SteinReviewGenerator {
    param([Parameter(Mandatory = $true)] $Generator)

    Assert-SteinReviewJsonShape -Value $Generator `
        -ExpectedProperties @(
            "schema_version", "harness_identity", "runtime_source_files",
            "source_paths", "source_stability", "trust_scope") `
        -FailureCode "collector_generator_schema_invalid"
    Assert-SteinReviewSchemaVersion -Value $Generator.schema_version `
        -FailureCode "collector_generator_schema_invalid"
    if ([string]$Generator.harness_identity -cne "phase2-installed-evidence-v1" -or
        [string]$Generator.source_paths -cne "repository_relative_only" -or
        [string]$Generator.source_stability -cne "required_before_ledger" -or
        [string]$Generator.trust_scope -cne "content_integrity_only_not_authentication") {
        throw "collector_generator_identity_invalid"
    }
    $expectedSources = @(
        [pscustomobject]@{
            role = "harness"
            path = "scripts/windows/phase2/Verify-Installed.ps1"
        },
        [pscustomobject]@{
            role = "launcher"
            path = "scripts/windows/phase2/Verify-Installed.cmd"
        },
        [pscustomobject]@{
            role = "msix-verifier"
            path = "packaging/windows-msix/Verify-Msix.ps1"
        },
        [pscustomobject]@{
            role = "package-tools"
            path = "packaging/windows-msix/PackageTools.ps1"
        },
        [pscustomobject]@{
            role = "phase2-common"
            path = "scripts/windows/phase2/Common.ps1"
        },
        [pscustomobject]@{
            role = "evidence-contract"
            path = "scripts/windows/phase2/Evidence-Contract.ps1"
        },
        [pscustomobject]@{
            role = "evidence-spec"
            path = "scripts/windows/phase2/Evidence-Spec.json"
        },
        [pscustomobject]@{
            role = "source-fixture-registry"
            path = "scripts/windows/phase2/Source-Fixture-Registry.json"
        },
        [pscustomobject]@{
            role = "phase2-status"
            path = "scripts/windows/phase2/Status.ps1"
        }
    ) | Sort-Object role
    $sources = @($Generator.runtime_source_files)
    if ($sources.Count -ne $expectedSources.Count) {
        throw "collector_generator_source_set_invalid"
    }
    $roles = @{}
    $paths = @{}
    foreach ($source in $sources) {
        Assert-SteinReviewJsonShape -Value $source `
            -ExpectedProperties @("role", "path", "size", "sha256") `
            -FailureCode "collector_generator_source_schema_invalid"
        if ([string]$source.role -cnotmatch "^[a-z][a-z0-9-]{0,63}$" -or
            $roles.ContainsKey([string]$source.role) -or
            [string]$source.path -cnotmatch "^[A-Za-z0-9._/-]+$" -or
            [IO.Path]::IsPathRooted([string]$source.path) -or
            [string]$source.path -cmatch "(?:^|/)\.\.?(/|$)" -or
            $paths.ContainsKey(([string]$source.path).ToLowerInvariant())) {
            throw "collector_generator_source_identity_invalid"
        }
        Assert-SteinReviewInteger -Value $source.size -Minimum 1 `
            -FailureCode "collector_generator_source_identity_invalid"
        Assert-SteinReviewHash -Value $source.sha256 `
            -FailureCode "collector_generator_source_identity_invalid"
        $expected = @($expectedSources | Where-Object {
            [string]$_.role -ceq [string]$source.role
        })
        if ($expected.Count -ne 1 -or
            [string]$source.path -cne [string]$expected[0].path) {
            throw "collector_generator_source_set_invalid"
        }
        $sourcePath = Resolve-SteinReviewContainedFile `
            -Root $repoRoot `
            -RelativePath $source.path `
            -FailureCode "collector_generator_source_unavailable"
        $sourceItem = Get-Item -LiteralPath $sourcePath -Force -ErrorAction Stop
        if ($sourceItem.Length -ne [long]$source.size -or
            (Get-SteinPhase2Sha256 -Path $sourcePath) -cne [string]$source.sha256) {
            throw "collector_generator_source_digest_mismatch"
        }
        $roles[[string]$source.role] = $true
        $paths[([string]$source.path).ToLowerInvariant()] = $true
        $script:SteinReviewCollectorRuntimeSourceFiles[[string]$source.role] =
            [pscustomobject]@{
                path = $sourcePath
                size = [long]$sourceItem.Length
                sha256 = [string]$source.sha256
            }
    }
    if (@($expectedSources | Where-Object {
        -not $roles.ContainsKey([string]$_.role)
    }).Count -ne 0) {
        throw "collector_generator_source_set_invalid"
    }
}

function Assert-SteinReviewHost {
    param([Parameter(Mandatory = $true)] $HostRecord)

    Assert-SteinReviewJsonShape -Value $HostRecord `
        -ExpectedProperties @(
            "schema_version", "host_identity_sha256", "computer_name_retained",
            "user_name_retained", "user_sid_retained", "os", "powershell",
            "elevated", "evidence_owner_sid_only") `
        -FailureCode "collector_host_schema_invalid"
    Assert-SteinReviewSchemaVersion -Value $HostRecord.schema_version `
        -FailureCode "collector_host_schema_invalid"
    Assert-SteinReviewHash -Value $HostRecord.host_identity_sha256 `
        -FailureCode "collector_host_identity_invalid"
    foreach ($property in @(
            "computer_name_retained", "user_name_retained", "user_sid_retained",
            "elevated", "evidence_owner_sid_only")) {
        Assert-SteinReviewBoolean -Value $HostRecord.$property `
            -FailureCode "collector_host_privacy_invalid"
    }
    if ([bool]$HostRecord.computer_name_retained -or
        [bool]$HostRecord.user_name_retained -or
        [bool]$HostRecord.user_sid_retained -or
        [bool]$HostRecord.elevated -or
        -not [bool]$HostRecord.evidence_owner_sid_only) {
        throw "collector_host_privacy_invalid"
    }
    Assert-SteinReviewJsonShape -Value $HostRecord.os `
        -ExpectedProperties @(
            "product_name", "display_version", "build_number", "update_build_revision",
            "process_architecture", "operating_system_64_bit", "process_64_bit") `
        -FailureCode "collector_host_os_schema_invalid"
    Assert-SteinReviewJsonShape -Value $HostRecord.powershell `
        -ExpectedProperties @("edition", "version") `
        -FailureCode "collector_host_powershell_schema_invalid"
    if ([string]$HostRecord.os.product_name -cnotmatch '^Windows [A-Za-z0-9 .()_-]{1,63}$' -or
        [string]$HostRecord.os.display_version -cnotmatch '^[A-Za-z0-9._-]{1,32}$' -or
        [string]$HostRecord.os.build_number -cnotmatch '^[0-9]{4,10}$' -or
        [string]$HostRecord.os.process_architecture -cnotin @("AMD64", "ARM64") -or
        [string]$HostRecord.powershell.edition -cnotin @("Desktop", "Core") -or
        [string]$HostRecord.powershell.version -cnotmatch '^[0-9]+(?:\.[0-9]+){1,3}$') {
        throw "collector_host_metadata_invalid"
    }
    Assert-SteinReviewInteger -Value $HostRecord.os.update_build_revision `
        -FailureCode "collector_host_metadata_invalid"
    Assert-SteinReviewBoolean -Value $HostRecord.os.operating_system_64_bit `
        -FailureCode "collector_host_metadata_invalid"
    Assert-SteinReviewBoolean -Value $HostRecord.os.process_64_bit `
        -FailureCode "collector_host_metadata_invalid"
    if (-not [bool]$HostRecord.os.operating_system_64_bit -or
        -not [bool]$HostRecord.os.process_64_bit) {
        throw "collector_host_metadata_invalid"
    }
}

function Assert-SteinReviewCommand {
    param([Parameter(Mandatory = $true)] $Command)

    Assert-SteinReviewJsonShape -Value $Command `
        -ExpectedProperties @(
            "identity", "executable", "arguments", "local_path_representation",
            "arguments_omitted") `
        -FailureCode "collector_command_schema_invalid"
    if ([string]$Command.identity -cnotmatch '^[A-Za-z0-9._:-]{1,128}$' -or
        [string]::IsNullOrWhiteSpace([string]$Command.executable) -or
        [string]$Command.local_path_representation -cne "deterministic_sha256_token") {
        throw "collector_command_identity_invalid"
    }
    Assert-SteinReviewBoolean -Value $Command.arguments_omitted `
        -FailureCode "collector_command_identity_invalid"
    if ([bool]$Command.arguments_omitted) {
        throw "collector_command_identity_invalid"
    }
    foreach ($argument in @($Command.arguments)) {
        if ($argument -isnot [string]) {
            throw "collector_command_argument_invalid"
        }
    }
}

function Assert-SteinReviewAttachmentMetadata {
    param(
        [Parameter(Mandatory = $true)] $Attachment,
        [Parameter(Mandatory = $true)][string] $ExpectedGate
    )

    Assert-SteinReviewJsonShape -Value $Attachment `
        -ExpectedProperties @(
            "attachment_id", "gate_id", "kind", "declared_result", "recorded_at_utc",
            "sha256", "size", "privacy_reviewed", "synthetic_only",
            "source_path_retained", "file_copied",
            "semantic_result_verified_by_harness", "native_fixture") `
        -FailureCode "collector_attachment_schema_invalid"
    if ([string]$Attachment.attachment_id -cnotmatch '^[a-z0-9][a-z0-9._-]{0,63}$' -or
        [string]$Attachment.gate_id -cne $ExpectedGate -or
        [string]$Attachment.kind -cnotin @("redacted_screenshot", "native_fixture_result") -or
        [string]$Attachment.declared_result -cnotin @("pass", "fail", "blocked", "not_run")) {
        throw "collector_attachment_identity_invalid"
    }
    $null = Assert-SteinReviewTimestamp -Value $Attachment.recorded_at_utc `
        -FailureCode "collector_attachment_timestamp_invalid"
    Assert-SteinReviewHash -Value $Attachment.sha256 `
        -FailureCode "collector_attachment_hash_invalid"
    Assert-SteinReviewInteger -Value $Attachment.size -Minimum 1 `
        -FailureCode "collector_attachment_size_invalid"
    foreach ($property in @(
            "privacy_reviewed", "synthetic_only", "source_path_retained", "file_copied",
            "semantic_result_verified_by_harness")) {
        Assert-SteinReviewBoolean -Value $Attachment.$property `
            -FailureCode "collector_attachment_classification_invalid"
    }
    if (-not [bool]$Attachment.privacy_reviewed -or
        -not [bool]$Attachment.synthetic_only -or
        [bool]$Attachment.source_path_retained -or
        [bool]$Attachment.file_copied -or
        [bool]$Attachment.semantic_result_verified_by_harness) {
        throw "collector_attachment_classification_invalid"
    }
    if ([string]$Attachment.kind -ceq "native_fixture_result") {
        Assert-SteinReviewJsonShape -Value $Attachment.native_fixture `
            -ExpectedProperties @(
                "schema_version", "contract_id", "contract_sha256", "fixture_id",
                "runner_id", "exit_code", "closed_content_free_schema_verified",
                "proof_classes", "subchecks", "bindings", "artifacts") `
            -FailureCode "collector_native_fixture_metadata_invalid"
        $gateSpecification = $script:SteinPhase2ReviewEvidenceSpecification.gates_by_id[$ExpectedGate]
        if (($Attachment.native_fixture.schema_version -isnot [int] -and
                $Attachment.native_fixture.schema_version -isnot [long]) -or
            [long]$Attachment.native_fixture.schema_version -ne 2 -or
            [string]$Attachment.native_fixture.contract_id -cne
                [string]$script:SteinPhase2ReviewEvidenceSpecification.specification.contract_id -or
            [string]$Attachment.native_fixture.contract_sha256 -cne
                $script:SteinPhase2ReviewEvidenceSpecificationSha256 -or
            [string]$Attachment.native_fixture.fixture_id -cne
                [string]$gateSpecification.fixture_id -or
            [string]$Attachment.native_fixture.runner_id -cne
                [string]$gateSpecification.runner_id) {
            throw "collector_native_fixture_metadata_invalid"
        }
        Assert-SteinReviewBoolean `
            -Value $Attachment.native_fixture.closed_content_free_schema_verified `
            -FailureCode "collector_native_fixture_metadata_invalid"
        if (-not [bool]$Attachment.native_fixture.closed_content_free_schema_verified) {
            throw "collector_native_fixture_metadata_invalid"
        }
    }
    elseif ($null -ne $Attachment.native_fixture) {
        throw "collector_screenshot_native_metadata_invalid"
    }
}

function Assert-SteinReviewLedgerEnvelope {
    param([Parameter(Mandatory = $true)] $Ledger)

    Assert-SteinReviewJsonShape -Value $Ledger `
        -ExpectedProperties @(
            "schema_version", "run_id", "claim", "installed_or_signed_evidence",
            "machine_verification_passed", "complete_acceptance", "started_at_utc",
            "completed_at_utc", "duration_ms", "generator_provenance",
            "host_provenance", "package", "schema_versions", "policy_profile",
            "privacy", "mutation", "checks", "rows", "summary") `
        -FailureCode "collector_ledger_schema_invalid"
    Assert-SteinReviewSchemaVersion -Value $Ledger.schema_version `
        -FailureCode "collector_ledger_schema_invalid"
    if ([string]$Ledger.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Ledger.claim -cne "installed_machine_verification_only") {
        throw "collector_ledger_identity_invalid"
    }
    foreach ($property in @(
            "installed_or_signed_evidence", "machine_verification_passed",
            "complete_acceptance")) {
        Assert-SteinReviewBoolean -Value $Ledger.$property `
            -FailureCode "collector_ledger_state_invalid"
    }
    $null = Assert-SteinReviewTimestamp -Value $Ledger.started_at_utc `
        -FailureCode "collector_ledger_timestamp_invalid"
    $null = Assert-SteinReviewTimestamp -Value $Ledger.completed_at_utc `
        -FailureCode "collector_ledger_timestamp_invalid"
    Assert-SteinReviewInteger -Value $Ledger.duration_ms `
        -FailureCode "collector_ledger_duration_invalid"

    Assert-SteinReviewJsonShape -Value $Ledger.privacy `
        -ExpectedProperties @(
            "provider_credentials_accessed", "private_protocol_snapshot_requested",
            "private_source_payload_retained", "local_paths_replaced_with_sha256_tokens",
            "attachment_source_paths_retained", "attachment_files_copied",
            "operator_privacy_review_required") `
        -FailureCode "collector_ledger_privacy_schema_invalid"
    foreach ($property in @($Ledger.privacy.PSObject.Properties | ForEach-Object { $_.Name })) {
        Assert-SteinReviewBoolean -Value $Ledger.privacy.$property `
            -FailureCode "collector_ledger_privacy_invalid"
    }
    if ([bool]$Ledger.privacy.provider_credentials_accessed -or
        [bool]$Ledger.privacy.private_protocol_snapshot_requested -or
        [bool]$Ledger.privacy.private_source_payload_retained -or
        -not [bool]$Ledger.privacy.local_paths_replaced_with_sha256_tokens -or
        [bool]$Ledger.privacy.attachment_source_paths_retained -or
        [bool]$Ledger.privacy.attachment_files_copied -or
        -not [bool]$Ledger.privacy.operator_privacy_review_required) {
        throw "collector_ledger_privacy_invalid"
    }
    Assert-SteinReviewJsonShape -Value $Ledger.mutation `
        -ExpectedProperties @(
            "package_install_or_remove", "task_start_stop_or_registration",
            "daemon_start_stop_or_restart", "credential_read_write_or_delete",
            "installed_state_mutated", "temporary_msix_verification_unpack",
            "persistent_outputs_evidence_directory_only") `
        -FailureCode "collector_ledger_mutation_schema_invalid"
    foreach ($property in @($Ledger.mutation.PSObject.Properties | ForEach-Object { $_.Name })) {
        Assert-SteinReviewBoolean -Value $Ledger.mutation.$property `
            -FailureCode "collector_ledger_mutation_invalid"
    }
    if ([bool]$Ledger.mutation.package_install_or_remove -or
        [bool]$Ledger.mutation.task_start_stop_or_registration -or
        [bool]$Ledger.mutation.daemon_start_stop_or_restart -or
        [bool]$Ledger.mutation.credential_read_write_or_delete -or
        [bool]$Ledger.mutation.installed_state_mutated -or
        -not [bool]$Ledger.mutation.persistent_outputs_evidence_directory_only) {
        throw "collector_ledger_mutation_invalid"
    }

    Assert-SteinReviewJsonShape -Value $Ledger.package `
        -ExpectedProperties @(
            "publisher", "signing_certificate_thumbprint", "version", "package_path",
            "release_identity_schema_version", "install_record_schema_version",
            "package_family_name", "desktop_aumid", "broker_aumid",
            "browser_producer_aumid", "msix_sha256", "core_sha256",
            "browser_host_sha256", "candidate_git_commit", "candidate_git_tree",
            "source_verification_sha256", "source_root_anchor_sha256",
            "source_root_digest_sha256", "installed_payload_file_count",
            "cli_executable_size", "cli_executable_sha256",
            "desktop_executable_size", "desktop_executable_sha256",
            "desktop_dist_file_count", "desktop_dist_manifest_sha256") `
        -FailureCode "collector_package_provenance_schema_invalid"
    if ([string]$Ledger.package.package_path -cnotmatch
            '^<local-path-sha256:[0-9a-f]{64}>$' -or
        [string]$Ledger.package.version -cnotmatch '^[0-9]+(?:\.[0-9]+){3}$') {
        throw "collector_package_provenance_invalid"
    }
    foreach ($property in @(
            "release_identity_schema_version", "install_record_schema_version",
            "installed_payload_file_count", "cli_executable_size",
            "desktop_executable_size", "desktop_dist_file_count")) {
        Assert-SteinReviewInteger -Value $Ledger.package.$property `
            -FailureCode "collector_package_provenance_invalid"
    }
    if ([long]$Ledger.package.release_identity_schema_version -ne 3 -or
        [long]$Ledger.package.install_record_schema_version -ne 2 -or
        [long]$Ledger.package.cli_executable_size -lt 0 -or
        [long]$Ledger.package.desktop_executable_size -lt 0 -or
        [long]$Ledger.package.desktop_dist_file_count -lt 0 -or
        [long]$Ledger.package.desktop_dist_file_count -gt 10000) {
        throw "collector_package_provenance_invalid"
    }
    foreach ($property in @(
            "msix_sha256", "core_sha256", "browser_host_sha256",
            "cli_executable_sha256", "desktop_executable_sha256",
            "desktop_dist_manifest_sha256",
            "source_verification_sha256", "source_root_anchor_sha256",
            "source_root_digest_sha256")) {
        Assert-SteinReviewHash -Value $Ledger.package.$property `
            -AllowNull `
            -FailureCode "collector_package_provenance_invalid"
    }
    $boundPackageHashes = @(
        $Ledger.package.core_sha256,
        $Ledger.package.browser_host_sha256,
        $Ledger.package.cli_executable_sha256,
        $Ledger.package.desktop_executable_sha256,
        $Ledger.package.desktop_dist_manifest_sha256)
    if ($null -ne $Ledger.package.msix_sha256) {
        if (@($boundPackageHashes | Where-Object { $null -eq $_ }).Count -ne 0 -or
            [long]$Ledger.package.cli_executable_size -le 0 -or
            [long]$Ledger.package.desktop_executable_size -le 0 -or
            [long]$Ledger.package.desktop_dist_file_count -le 0) {
            throw "collector_package_provenance_invalid"
        }
    }
    elseif (@($boundPackageHashes | Where-Object { $null -ne $_ }).Count -ne 0 -or
        [long]$Ledger.package.cli_executable_size -ne 0 -or
        [long]$Ledger.package.desktop_executable_size -ne 0 -or
        [long]$Ledger.package.desktop_dist_file_count -ne 0) {
        throw "collector_package_provenance_invalid"
    }
    if ($null -ne $Ledger.package.candidate_git_commit -and
        ([string]$Ledger.package.candidate_git_commit -cnotmatch
                '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
            [string]$Ledger.package.candidate_git_tree -cnotmatch
                '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
            ([string]$Ledger.package.candidate_git_commit).Length -ne
                ([string]$Ledger.package.candidate_git_tree).Length)) {
        throw "collector_package_provenance_invalid"
    }

    Assert-SteinReviewJsonShape -Value $Ledger.schema_versions `
        -ExpectedProperties @(
            "ledger", "release_identity", "install_record",
            "durable_persistence_capability") `
        -FailureCode "collector_schema_versions_invalid"
    foreach ($property in @($Ledger.schema_versions.PSObject.Properties | ForEach-Object { $_.Name })) {
        Assert-SteinReviewInteger -Value $Ledger.schema_versions.$property `
            -Minimum 1 `
            -FailureCode "collector_schema_versions_invalid"
    }
    Assert-SteinReviewJsonShape -Value $Ledger.policy_profile `
        -ExpectedProperties @(
            "expected_id", "reported_by_installed_runtime",
            "policy_dependent_rows_may_pass") `
        -FailureCode "collector_policy_profile_schema_invalid"
    foreach ($property in @(
            "reported_by_installed_runtime", "policy_dependent_rows_may_pass")) {
        Assert-SteinReviewBoolean -Value $Ledger.policy_profile.$property `
            -FailureCode "collector_policy_profile_invalid"
    }
    if ([string]$Ledger.policy_profile.expected_id -cne "phase2-focus-v1" -or
        [bool]$Ledger.policy_profile.reported_by_installed_runtime -or
        [bool]$Ledger.policy_profile.policy_dependent_rows_may_pass) {
        throw "collector_policy_profile_invalid"
    }
    Assert-SteinReviewJsonShape -Value $Ledger.summary `
        -ExpectedProperties @("checks", "rows") `
        -FailureCode "collector_summary_schema_invalid"
    foreach ($summaryGroup in @($Ledger.summary.checks, $Ledger.summary.rows)) {
        Assert-SteinReviewJsonShape -Value $summaryGroup `
            -ExpectedProperties @("pass", "fail", "blocked", "not_run") `
            -FailureCode "collector_summary_schema_invalid"
        foreach ($property in @("pass", "fail", "blocked", "not_run")) {
            Assert-SteinReviewInteger -Value $summaryGroup.$property `
                -FailureCode "collector_summary_invalid"
        }
    }
}

function Assert-SteinReviewVersionProvenance {
    param([Parameter(Mandatory = $true)] $Versions)

    Assert-SteinReviewJsonShape -Value $Versions `
        -ExpectedProperties @(
            "package_version", "runtime_build_id", "protocol_version",
            "release_identity_schema_version", "install_record_schema_version",
            "durable_persistence_capability_schema_version",
            "numeric_database_schema_reported", "expected_policy_profile_id",
            "policy_profile_reported_by_installed_runtime") `
        -FailureCode "collector_version_provenance_schema_invalid"
    foreach ($property in @(
            "numeric_database_schema_reported",
            "policy_profile_reported_by_installed_runtime")) {
        Assert-SteinReviewBoolean -Value $Versions.$property `
            -FailureCode "collector_version_provenance_invalid"
    }
    if ([string]$Versions.package_version -cnotmatch '^[0-9]+(?:\.[0-9]+){3}$' -or
        [string]$Versions.expected_policy_profile_id -cne "phase2-focus-v1") {
        throw "collector_version_provenance_invalid"
    }
    foreach ($property in @(
            "release_identity_schema_version", "install_record_schema_version",
            "durable_persistence_capability_schema_version")) {
        Assert-SteinReviewInteger -Value $Versions.$property `
            -Minimum 1 `
            -FailureCode "collector_version_provenance_invalid"
    }
    if ([long]$Versions.release_identity_schema_version -ne 3 -or
        [long]$Versions.install_record_schema_version -ne 2) {
        throw "collector_version_provenance_invalid"
    }
    if ($null -ne $Versions.protocol_version) {
        Assert-SteinReviewInteger -Value $Versions.protocol_version `
            -Minimum 1 `
            -FailureCode "collector_version_provenance_invalid"
    }
    if ($null -ne $Versions.runtime_build_id -and
        ($Versions.runtime_build_id -isnot [string] -or
            [string]$Versions.runtime_build_id -cnotmatch '^[A-Za-z0-9._-]{1,128}$')) {
        throw "collector_version_provenance_invalid"
    }
}

function Read-SteinReviewNativeFixture {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $Metadata,
        [Parameter(Mandatory = $true)][object[]] $UnderlyingArtifacts,
        [Parameter(Mandatory = $true)] $UnderlyingPaths,
        [Parameter(Mandatory = $true)] $ExpectedPackage
    )

    $underlyingById = @{}
    foreach ($underlyingArtifact in @($UnderlyingArtifacts)) {
        $underlyingById[[string]$underlyingArtifact.artifact_id] = $underlyingArtifact
    }
    $fixture = Read-SteinReviewJsonFile `
        -Path $Path `
        -MaximumBytes 4MB `
        -FailureCode "native_fixture_result_invalid" `
        -ExpectedSha256 ([string]$Metadata.sha256) `
        -ExpectedSize ([long]$Metadata.size)
    Assert-SteinReviewJsonShape -Value $fixture `
        -ExpectedProperties @(
            "schema_version", "contract_id", "contract_sha256", "gate_id",
            "fixture_id", "runner_id", "result", "recorded_at_utc", "exit_code",
            "runner", "proof_classes", "subchecks", "bindings", "artifacts") `
        -FailureCode "native_fixture_result_schema_invalid"
    $gateSpecification =
        $script:SteinPhase2ReviewEvidenceSpecification.gates_by_id[[string]$Metadata.gate_id]
    try {
        $null = Assert-SteinPhase2GateEvidenceResult `
            -Value $fixture `
            -Specification $script:SteinPhase2ReviewEvidenceSpecification.specification `
            -Gate $gateSpecification `
            -SpecificationSha256 $script:SteinPhase2ReviewEvidenceSpecificationSha256 `
            -ExpectedPackage $ExpectedPackage `
            -ExpectedCollector $script:SteinReviewCollectorHostRecord `
            -UnderlyingArtifacts $UnderlyingArtifacts
    }
    catch {
        throw $_.Exception.Message
    }
    if ([string]$fixture.contract_id -cne [string]$Metadata.native_fixture.contract_id -or
        [string]$fixture.contract_sha256 -cne [string]$Metadata.native_fixture.contract_sha256 -or
        [string]$fixture.fixture_id -cne [string]$Metadata.native_fixture.fixture_id -or
        [string]$fixture.runner_id -cne [string]$Metadata.native_fixture.runner_id -or
        [string]$fixture.gate_id -cne [string]$Metadata.gate_id -or
        [string]$fixture.result -cne [string]$Metadata.declared_result -or
        (ConvertTo-SteinReviewTimestampString `
            -Value $fixture.recorded_at_utc `
            -FailureCode "native_fixture_result_timestamp_invalid") -cne
        (ConvertTo-SteinReviewTimestampString `
            -Value $Metadata.recorded_at_utc `
            -FailureCode "native_fixture_result_timestamp_invalid")) {
        throw "native_fixture_result_binding_invalid"
    }
    $exitCode = $fixture.exit_code
    if (($fixture.result -ceq "pass" -and
            (($exitCode -isnot [int] -and $exitCode -isnot [long]) -or
                [long]$exitCode -ne 0)) -or
        ($fixture.result -ceq "fail" -and
            (($exitCode -isnot [int] -and $exitCode -isnot [long]) -or
                [long]$exitCode -eq 0)) -or
        ($fixture.result -cin @("blocked", "not_run") -and $null -ne $exitCode)) {
        throw "native_fixture_result_exit_invalid"
    }
    if ($null -eq $exitCode) {
        if ($null -ne $Metadata.native_fixture.exit_code) {
            throw "native_fixture_result_exit_binding_invalid"
        }
    }
    elseif ([long]$exitCode -ne [long]$Metadata.native_fixture.exit_code) {
        throw "native_fixture_result_exit_binding_invalid"
    }
    foreach ($binding in @(
            [pscustomobject]@{ left = $fixture.proof_classes; right = $Metadata.native_fixture.proof_classes },
            [pscustomobject]@{ left = $fixture.subchecks; right = $Metadata.native_fixture.subchecks },
            [pscustomobject]@{ left = $fixture.bindings; right = $Metadata.native_fixture.bindings },
            [pscustomobject]@{ left = $fixture.artifacts; right = $Metadata.native_fixture.artifacts })) {
        if (-not (Test-SteinReviewJsonEqual -Left $binding.left -Right $binding.right)) {
            throw "native_fixture_result_metadata_binding_invalid"
        }
    }
    $sourceBinding = $fixture.bindings.source_report
    $sourceReportPath = $UnderlyingPaths[[string]$sourceBinding.report_artifact_id]
    $sourceRootPath = $UnderlyingPaths[[string]$sourceBinding.root_anchor_artifact_id]
    $sourceReportDescriptor = $underlyingById[[string]$sourceBinding.report_artifact_id]
    $sourceRootDescriptor = $underlyingById[[string]$sourceBinding.root_anchor_artifact_id]
    if ([string]::IsNullOrWhiteSpace($sourceReportPath) -or
        [string]::IsNullOrWhiteSpace($sourceRootPath) -or
        $null -eq $sourceReportDescriptor -or $null -eq $sourceRootDescriptor) {
        throw "source_evidence_artifact_missing"
    }
    $sourceReport = Read-SteinReviewJsonFile `
        -Path $sourceReportPath `
        -MaximumBytes 16MB `
        -FailureCode "source_evidence_report_invalid" `
        -ExpectedSha256 ([string]$sourceReportDescriptor.sha256) `
        -ExpectedSize ([long]$sourceReportDescriptor.size)
    $sourceRoot = Read-SteinReviewJsonFile `
        -Path $sourceRootPath `
        -MaximumBytes 1MB `
        -FailureCode "source_evidence_root_invalid" `
        -ExpectedSha256 ([string]$sourceRootDescriptor.sha256) `
        -ExpectedSize ([long]$sourceRootDescriptor.size)
    $null = Assert-SteinPhase2SourceEvidenceBinding `
        -EvidenceResult $fixture `
        -SourceReport $sourceReport `
        -SourceRootAnchor $sourceRoot `
        -EvidenceSpecification $script:SteinPhase2ReviewEvidenceSpecification.specification `
        -SourceFixtureRegistry $script:SteinPhase2ReviewSourceFixtureRegistry.value `
        -SourceFixtureRegistrySha256 `
            ([string]$script:SteinPhase2ReviewSourceFixtureRegistry.sha256)
    if ([string]$Metadata.gate_id -ceq "P2-PORTABLE-FIXTURE") {
        $linuxPath = $UnderlyingPaths[[string]$fixture.bindings.linux_artifact.artifact_id]
        if ([string]::IsNullOrWhiteSpace($linuxPath)) {
            throw "linux_artifact_missing"
        }
        $linuxDescriptor = $underlyingById[
            [string]$fixture.bindings.linux_artifact.artifact_id]
        if ($null -eq $linuxDescriptor) {
            throw "linux_artifact_missing"
        }
        $linuxArtifact = Read-SteinReviewJsonFile `
            -Path $linuxPath `
            -MaximumBytes 4MB `
            -FailureCode "linux_artifact_invalid" `
            -ExpectedSha256 ([string]$linuxDescriptor.sha256) `
            -ExpectedSize ([long]$linuxDescriptor.size)
        $null = Assert-SteinPhase2LinuxPortableArtifact `
            -Artifact $linuxArtifact `
            -Gate $gateSpecification `
            -ExpectedCommit ([string]$fixture.bindings.commit.object_id) `
            -ExpectedTree ([string]$fixture.bindings.commit.tree_id) `
            -SourceReport $sourceReport `
            -EvidenceResult $fixture `
            -UnderlyingArtifacts $UnderlyingArtifacts
    }
    $noLeaksScannerArtifact = $null
    $noLeaksProducerArtifact = $null
    foreach ($runnerBinding in @($fixture.bindings.runner_artifacts)) {
        $runnerSpecification = @($gateSpecification.runner_artifacts | Where-Object {
            [string]$_.artifact_role -ceq [string]$runnerBinding.artifact_role
        })[0]
        $runnerPath = $UnderlyingPaths[[string]$runnerBinding.artifact_id]
        $runnerDescriptor = $underlyingById[[string]$runnerBinding.artifact_id]
        if ($null -eq $runnerSpecification -or
            [string]::IsNullOrWhiteSpace($runnerPath) -or
            $null -eq $runnerDescriptor) {
            throw "runner_artifact_missing"
        }
        $runnerArtifact = Read-SteinReviewJsonFile `
            -Path $runnerPath `
            -MaximumBytes 4MB `
            -FailureCode "runner_artifact_invalid" `
            -ExpectedSha256 ([string]$runnerDescriptor.sha256) `
            -ExpectedSize ([long]$runnerDescriptor.size)
        if ([string]$runnerBinding.artifact_role -ceq "private_diagnostic_denial") {
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
                -EvidenceResult $fixture
            $noLeaksScannerArtifact = $runnerArtifact
        }
        elseif ([string]$runnerBinding.artifact_role -ceq
            "no_leaks_sentinel_producer") {
            $null = Assert-SteinPhase2NoLeaksProducerArtifact `
                -Artifact $runnerArtifact `
                -RunnerArtifact $runnerSpecification `
                -EvidenceResult $fixture
            $noLeaksProducerArtifact = $runnerArtifact
        }
        else {
            throw "runner_artifact_role_unsupported"
        }
    }
    if ([string]$Metadata.gate_id -ceq "P2-NO-LEAKS") {
        if ($null -eq $noLeaksScannerArtifact -or $null -eq $noLeaksProducerArtifact) {
            throw "no_leaks_receipt_pair_missing"
        }
        $null = Assert-SteinPhase2NoLeaksReceiptPair `
            -ScannerArtifact $noLeaksScannerArtifact `
            -ProducerArtifact $noLeaksProducerArtifact
    }
    Assert-SteinReviewNoPrivateValues -Value $fixture -Context "native_fixture"
    return $fixture
}

function Write-SteinReviewEvidenceJson {
    param(
        [Parameter(Mandatory = $true)][string] $RelativePath,
        [Parameter(Mandatory = $true)] $Value
    )

    $path = [IO.Path]::GetFullPath((Join-Path $script:SteinReviewOutputPath $RelativePath))
    $prefix = "$script:SteinReviewOutputPath$([IO.Path]::DirectorySeparatorChar)"
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "review_output_path_escape"
    }
    $parent = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyPath -Path $parent
    }
    $Value | ConvertTo-Json -Depth 32 |
        Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
    Protect-SteinPhase2OwnerOnlyPath -Path $path
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    return [ordered]@{
        path = $item.FullName.Substring($script:SteinReviewOutputPath.Length + 1).Replace("\", "/")
        size = [long]$item.Length
        sha256 = Get-SteinPhase2Sha256 -Path $item.FullName
    }
}

Assert-SteinPhase2WindowsHost

$evidenceRoot = Assert-SteinReviewArtifactsPath `
    -Path $EvidenceDirectory `
    -Description "evidence_directory" `
    -RequireDirectory
Assert-SteinPhase2OwnerOnlyTree -Root $evidenceRoot

$rootAnchorPath = Resolve-SteinReviewContainedFile `
    -Root $evidenceRoot `
    -RelativePath "root-anchor.json" `
    -FailureCode "collector_root_anchor_missing"
$rootAnchorItem = Get-Item -LiteralPath $rootAnchorPath -Force -ErrorAction Stop
$rootAnchorFileHash = Get-SteinPhase2Sha256 -Path $rootAnchorPath
if ($rootAnchorFileHash -cne $ExpectedRootAnchorSha256) {
    throw "collector_root_anchor_hash_mismatch"
}
$rootAnchor = Read-SteinReviewJsonFile `
    -Path $rootAnchorPath `
    -MaximumBytes 1MB `
    -FailureCode "collector_root_anchor_invalid" `
    -ExpectedSha256 $ExpectedRootAnchorSha256 `
    -ExpectedSize ([long]$rootAnchorItem.Length)
Assert-SteinReviewJsonShape -Value $rootAnchor `
    -ExpectedProperties @(
        "schema_version", "run_id", "harness_identity", "digest_algorithm",
        "root_digest_sha256", "digest_material", "generator", "host", "ledger",
        "trust_scope") `
    -FailureCode "collector_root_anchor_schema_invalid"
Assert-SteinReviewSchemaVersion -Value $rootAnchor.schema_version `
    -FailureCode "collector_root_anchor_schema_invalid"
Assert-SteinReviewHash -Value $rootAnchor.root_digest_sha256 `
    -FailureCode "collector_root_digest_invalid"
if ([string]$rootAnchor.run_id -cnotmatch '^[0-9a-f]{32}$' -or
    [string]$rootAnchor.harness_identity -cne "phase2-installed-evidence-v1" -or
    [string]$rootAnchor.digest_algorithm -cne "sha256" -or
    [string]$rootAnchor.digest_material -cne
        "identity_nul_run_nul_generator_nul_host_nul_ledger" -or
    [string]$rootAnchor.trust_scope -cne "content_integrity_only_not_authentication") {
    throw "collector_root_anchor_identity_invalid"
}
foreach ($binding in @(
        [pscustomobject]@{ descriptor = $rootAnchor.generator; expected = "generator.json" },
        [pscustomobject]@{ descriptor = $rootAnchor.host; expected = "host.json" },
        [pscustomobject]@{ descriptor = $rootAnchor.ledger; expected = "ledger.json" })) {
    if ([string]$binding.descriptor.path -cne [string]$binding.expected) {
        throw "collector_root_anchor_path_invalid"
    }
}
$generatorPath = Assert-SteinReviewArtifactDescriptor `
    -Descriptor $rootAnchor.generator `
    -EvidenceRoot $evidenceRoot `
    -FailureCode "collector_generator_artifact_invalid"
$hostPath = Assert-SteinReviewArtifactDescriptor `
    -Descriptor $rootAnchor.host `
    -EvidenceRoot $evidenceRoot `
    -FailureCode "collector_host_artifact_invalid"
$ledgerPath = Assert-SteinReviewArtifactDescriptor `
    -Descriptor $rootAnchor.ledger `
    -EvidenceRoot $evidenceRoot `
    -FailureCode "collector_ledger_artifact_invalid"
$expectedRootMaterial = @(
    "phase2-installed-evidence-root-v1",
    [string]$rootAnchor.run_id,
    [string]$rootAnchor.generator.sha256,
    [string]$rootAnchor.host.sha256,
    [string]$rootAnchor.ledger.sha256
) -join "`0"
if ((Get-SteinReviewStringSha256 -Value $expectedRootMaterial) -cne
    [string]$rootAnchor.root_digest_sha256) {
    throw "collector_root_digest_mismatch"
}

$generator = Read-SteinReviewJsonFile `
    -Path $generatorPath `
    -MaximumBytes 1MB `
    -FailureCode "collector_generator_invalid" `
    -ExpectedSha256 ([string]$rootAnchor.generator.sha256) `
    -ExpectedSize ([long]$rootAnchor.generator.size)
$hostRecord = Read-SteinReviewJsonFile `
    -Path $hostPath `
    -MaximumBytes 1MB `
    -FailureCode "collector_host_invalid" `
    -ExpectedSha256 ([string]$rootAnchor.host.sha256) `
    -ExpectedSize ([long]$rootAnchor.host.size)
$script:SteinReviewCollectorHostRecord = $hostRecord
$ledger = Read-SteinReviewJsonFile `
    -Path $ledgerPath `
    -MaximumBytes 16MB `
    -FailureCode "collector_ledger_invalid" `
    -ExpectedSha256 ([string]$rootAnchor.ledger.sha256) `
    -ExpectedSize ([long]$rootAnchor.ledger.size)
Assert-SteinReviewGenerator -Generator $generator
Assert-SteinReviewHost -HostRecord $hostRecord
Assert-SteinReviewLedgerEnvelope -Ledger $ledger
$ledgerStartedAt = Assert-SteinReviewTimestamp `
    -Value $ledger.started_at_utc `
    -FailureCode "collector_ledger_timestamp_invalid"
$ledgerCompletedAt = Assert-SteinReviewTimestamp `
    -Value $ledger.completed_at_utc `
    -FailureCode "collector_ledger_timestamp_invalid"
if ($ledgerCompletedAt -lt $ledgerStartedAt) {
    throw "collector_ledger_timestamp_invalid"
}
if ([string]$ledger.run_id -cne [string]$rootAnchor.run_id -or
    -not (Test-SteinReviewJsonEqual -Left $ledger.generator_provenance -Right $rootAnchor.generator) -or
    -not (Test-SteinReviewJsonEqual -Left $ledger.host_provenance -Right $rootAnchor.host)) {
    throw "collector_ledger_root_binding_invalid"
}

$collectorChecks = @($ledger.checks)
$collectorCheckIds = @{}
foreach ($check in $collectorChecks) {
    $expectedCheckProperties = if ($null -ne $check.PSObject.Properties["reason_code"]) {
        @(
            "id", "status", "command", "started_at_utc", "completed_at_utc",
            "duration_ms", "exit_code", "failure_summary", "reason_code", "output")
    }
    else {
        @(
            "id", "status", "command", "started_at_utc", "completed_at_utc",
            "duration_ms", "exit_code", "failure_summary", "output")
    }
    Assert-SteinReviewJsonShape -Value $check `
        -ExpectedProperties $expectedCheckProperties `
        -FailureCode "collector_check_schema_invalid"
    if ([string]$check.id -cnotmatch '^[a-z0-9][a-z0-9._-]{0,127}$' -or
        $collectorCheckIds.ContainsKey([string]$check.id) -or
        [string]$check.status -cnotin @("pass", "fail", "blocked", "not_run")) {
        throw "collector_check_identity_invalid"
    }
    $collectorCheckIds[[string]$check.id] = $check
    Assert-SteinReviewCommand -Command $check.command
    $checkOutputPath = Assert-SteinReviewArtifactDescriptor `
        -Descriptor $check.output `
        -EvidenceRoot $evidenceRoot `
        -FailureCode "collector_check_artifact_invalid"
    $checkOutput = Read-SteinReviewJsonFile `
        -Path $checkOutputPath `
        -MaximumBytes 8MB `
        -FailureCode "collector_check_output_invalid" `
        -ExpectedSha256 ([string]$check.output.sha256) `
        -ExpectedSize ([long]$check.output.size)
    $expectedCheckOutputProperties = if ($null -ne $check.PSObject.Properties["reason_code"]) {
        @(
            "schema_version", "check_id", "status", "command", "started_at_utc",
            "completed_at_utc", "duration_ms", "exit_code", "failure_summary",
            "reason_code", "result")
    }
    else {
        @(
            "schema_version", "check_id", "status", "command", "started_at_utc",
            "completed_at_utc", "duration_ms", "exit_code", "failure_summary", "result")
    }
    Assert-SteinReviewJsonShape `
        -Value $checkOutput `
        -ExpectedProperties $expectedCheckOutputProperties `
        -FailureCode "collector_check_output_schema_invalid"
    Assert-SteinReviewSchemaVersion `
        -Value $checkOutput.schema_version `
        -FailureCode "collector_check_output_schema_invalid"
    Assert-SteinReviewInteger `
        -Value $check.duration_ms `
        -FailureCode "collector_check_state_invalid"
    Assert-SteinReviewInteger `
        -Value $checkOutput.duration_ms `
        -FailureCode "collector_check_output_schema_invalid"
    $checkStartedAt = Assert-SteinReviewTimestamp `
        -Value $check.started_at_utc `
        -FailureCode "collector_check_timestamp_invalid"
    $checkCompletedAt = Assert-SteinReviewTimestamp `
        -Value $check.completed_at_utc `
        -FailureCode "collector_check_timestamp_invalid"
    if ($checkCompletedAt -lt $checkStartedAt -or
        $checkStartedAt -lt $ledgerStartedAt -or
        $checkCompletedAt -gt $ledgerCompletedAt -or
        [string]$checkOutput.check_id -cne [string]$check.id -or
        [string]$checkOutput.status -cne [string]$check.status -or
        -not (Test-SteinReviewJsonEqual -Left $checkOutput.command -Right $check.command) -or
        [string]$checkOutput.started_at_utc -cne [string]$check.started_at_utc -or
        [string]$checkOutput.completed_at_utc -cne [string]$check.completed_at_utc -or
        [long]$checkOutput.duration_ms -ne [long]$check.duration_ms -or
        -not (Test-SteinReviewJsonEqual -Left $checkOutput.exit_code -Right $check.exit_code) -or
        -not (Test-SteinReviewJsonEqual `
            -Left $checkOutput.failure_summary `
            -Right $check.failure_summary)) {
        throw "collector_check_output_binding_invalid"
    }
    $summaryHasReason = $null -ne $check.PSObject.Properties["reason_code"]
    $outputHasReason = $null -ne $checkOutput.PSObject.Properties["reason_code"]
    if ($summaryHasReason -ne $outputHasReason -or
        ($summaryHasReason -and
            [string]$checkOutput.reason_code -cne [string]$check.reason_code)) {
        throw "collector_check_output_binding_invalid"
    }
    if ([string]$check.status -ceq "pass") {
        if (($check.exit_code -isnot [int] -and $check.exit_code -isnot [long]) -or
            [long]$check.exit_code -ne 0 -or
            $null -ne $check.failure_summary -or
            $summaryHasReason) {
            throw "collector_check_state_invalid"
        }
    }
    elseif ([string]$check.status -ceq "not_run") {
        if ($null -ne $check.exit_code -or
            $null -ne $check.failure_summary -or
            -not $summaryHasReason -or
            [string]$check.reason_code -cnotmatch '^[a-z][a-z0-9_]{2,127}$') {
            throw "collector_check_state_invalid"
        }
    }
    elseif ($null -ne $check.exit_code -or
        $check.failure_summary -isnot [string] -or
        [string]$check.failure_summary -cnotmatch
            '^content_minimized:[a-z][a-z0-9_]{2,127}$' -or
        $summaryHasReason) {
        throw "collector_check_state_invalid"
    }
    Assert-SteinReviewNoPrivateValues -Value $checkOutput -Context "collector_check"
    Register-SteinReviewNestedArtifactDescriptors `
        -Value $checkOutput `
        -EvidenceRoot $evidenceRoot
}
foreach ($status in @("pass", "fail", "blocked", "not_run")) {
    $actualCount = @($collectorChecks | Where-Object {
        [string]$_.status -ceq $status
    }).Count
    if ([long]$ledger.summary.checks.$status -ne $actualCount) {
        throw "collector_check_summary_mismatch"
    }
}

$sourceRows = @($ledger.rows)
if ($sourceRows.Count -ne 32) {
    throw "collector_gate_count_invalid"
}
$sourceRowsByGate = @{}
$sourceAttachmentsById = @{}
$sourceAttachmentGateById = @{}
foreach ($row in $sourceRows) {
    Assert-SteinReviewJsonShape -Value $row `
        -ExpectedProperties @(
            "gate_id", "status", "reason_code", "harness_identity", "versions",
            "commands", "output_artifacts", "attachments", "generator_provenance",
            "host_provenance", "row_artifact") `
        -FailureCode "collector_row_schema_invalid"
    $gateId = [string]$row.gate_id
    if ($gateId -cnotin $script:SteinPhase2ReviewGateIds -or
        $sourceRowsByGate.ContainsKey($gateId)) {
        throw "collector_gate_set_invalid"
    }
    if ([string]$row.status -cnotin @("pass", "fail", "blocked", "not_run") -or
        [string]$row.reason_code -cnotmatch '^[a-z][a-z0-9_]{2,127}$' -or
        [string]$row.harness_identity -cne "phase2-installed-evidence-v1") {
        throw "collector_row_state_invalid"
    }
    if (-not (Test-SteinReviewJsonEqual -Left $row.generator_provenance -Right $rootAnchor.generator) -or
        -not (Test-SteinReviewJsonEqual -Left $row.host_provenance -Right $rootAnchor.host)) {
        throw "collector_row_provenance_invalid"
    }
    Assert-SteinReviewVersionProvenance -Versions $row.versions
    $rowPath = Assert-SteinReviewArtifactDescriptor `
        -Descriptor $row.row_artifact `
        -EvidenceRoot $evidenceRoot `
        -FailureCode "collector_row_artifact_invalid"
    $expectedRowPath = "ledger-rows/" +
        ($gateId.ToLowerInvariant() -replace "[^a-z0-9._-]", "-") + ".json"
    if ([string]$row.row_artifact.path -cne $expectedRowPath) {
        throw "collector_row_artifact_path_invalid"
    }
    $rowPayload = Read-SteinReviewJsonFile `
        -Path $rowPath `
        -MaximumBytes 8MB `
        -FailureCode "collector_row_artifact_payload_invalid" `
        -ExpectedSha256 ([string]$row.row_artifact.sha256) `
        -ExpectedSize ([long]$row.row_artifact.size)
    Assert-SteinReviewJsonShape -Value $rowPayload `
        -ExpectedProperties @(
            "schema_version", "gate_id", "status", "reason_code", "harness_identity",
            "generator_provenance", "host_provenance", "package", "versions",
            "policy_profile", "commands", "attachments", "screenshot_can_prove_gate",
            "attached_pass_promoted_by_harness") `
        -FailureCode "collector_row_artifact_schema_invalid"
    Assert-SteinReviewSchemaVersion -Value $rowPayload.schema_version `
        -FailureCode "collector_row_artifact_schema_invalid"
    foreach ($property in @("screenshot_can_prove_gate", "attached_pass_promoted_by_harness")) {
        Assert-SteinReviewBoolean -Value $rowPayload.$property `
            -FailureCode "collector_row_promotion_invariant_invalid"
        if ([bool]$rowPayload.$property) {
            throw "collector_row_promotion_invariant_invalid"
        }
    }
    Assert-SteinReviewJsonShape -Value $rowPayload.policy_profile `
        -ExpectedProperties @(
            "expected_id", "reported_by_installed_runtime",
            "accepted_as_installed_policy_evidence") `
        -FailureCode "collector_row_policy_profile_schema_invalid"
    foreach ($property in @(
            "reported_by_installed_runtime", "accepted_as_installed_policy_evidence")) {
        Assert-SteinReviewBoolean -Value $rowPayload.policy_profile.$property `
            -FailureCode "collector_row_policy_profile_invalid"
    }
    if ([string]$rowPayload.policy_profile.expected_id -cne "phase2-focus-v1" -or
        [bool]$rowPayload.policy_profile.reported_by_installed_runtime -or
        [bool]$rowPayload.policy_profile.accepted_as_installed_policy_evidence) {
        throw "collector_row_policy_profile_invalid"
    }
    if ([string]$rowPayload.gate_id -cne $gateId -or
        [string]$rowPayload.status -cne [string]$row.status -or
        [string]$rowPayload.reason_code -cne [string]$row.reason_code -or
        [string]$rowPayload.harness_identity -cne [string]$row.harness_identity -or
        -not (Test-SteinReviewJsonEqual -Left $rowPayload.generator_provenance -Right $rootAnchor.generator) -or
        -not (Test-SteinReviewJsonEqual -Left $rowPayload.host_provenance -Right $rootAnchor.host) -or
        -not (Test-SteinReviewJsonEqual -Left $rowPayload.package -Right $ledger.package) -or
        -not (Test-SteinReviewJsonEqual -Left $rowPayload.versions -Right $row.versions) -or
        -not (Test-SteinReviewJsonEqual -Left $rowPayload.commands -Right $row.commands) -or
        -not (Test-SteinReviewJsonEqual -Left $rowPayload.attachments -Right $row.attachments)) {
        throw "collector_row_artifact_binding_invalid"
    }

    $rowCommandIds = @{}
    foreach ($commandRecord in @($row.commands)) {
        Assert-SteinReviewJsonShape -Value $commandRecord `
            -ExpectedProperties @("check_id", "status", "command", "exit_code", "output") `
            -FailureCode "collector_row_command_schema_invalid"
        if ([string]$commandRecord.check_id -cnotmatch '^[a-z0-9][a-z0-9._-]{0,127}$' -or
            $rowCommandIds.ContainsKey([string]$commandRecord.check_id) -or
            -not $collectorCheckIds.ContainsKey([string]$commandRecord.check_id) -or
            [string]$commandRecord.status -cnotin @("pass", "fail", "blocked", "not_run")) {
            throw "collector_row_command_invalid"
        }
        $rowCommandIds[[string]$commandRecord.check_id] = $true
        Assert-SteinReviewCommand -Command $commandRecord.command
        $sourceCheck = $collectorCheckIds[[string]$commandRecord.check_id]
        if ([string]$commandRecord.status -cne [string]$sourceCheck.status -or
            -not (Test-SteinReviewJsonEqual `
                -Left $commandRecord.command `
                -Right $sourceCheck.command) -or
            -not (Test-SteinReviewJsonEqual `
                -Left $commandRecord.exit_code `
                -Right $sourceCheck.exit_code) -or
            -not (Test-SteinReviewJsonEqual `
                -Left $commandRecord.output `
                -Right $sourceCheck.output)) {
            throw "collector_row_command_binding_invalid"
        }
        $null = Assert-SteinReviewArtifactDescriptor `
            -Descriptor $commandRecord.output `
            -EvidenceRoot $evidenceRoot `
            -FailureCode "collector_row_command_artifact_invalid"
    }
    $outputPaths = @{}
    $expectedOutputPaths = @{}
    $expectedOutputPaths[([string]$row.row_artifact.path).ToLowerInvariant()] = $true
    foreach ($commandRecord in @($row.commands)) {
        $commandOutputKey = ([string]$commandRecord.output.path).ToLowerInvariant()
        if ($expectedOutputPaths.ContainsKey($commandOutputKey)) {
            throw "collector_row_command_artifact_duplicate"
        }
        $expectedOutputPaths[$commandOutputKey] = $true
    }
    foreach ($outputArtifact in @($row.output_artifacts)) {
        $null = Assert-SteinReviewArtifactDescriptor `
            -Descriptor $outputArtifact `
            -EvidenceRoot $evidenceRoot `
            -FailureCode "collector_row_output_artifact_invalid"
        $outputKey = ([string]$outputArtifact.path).ToLowerInvariant()
        if ($outputPaths.ContainsKey($outputKey)) {
            throw "collector_row_output_artifact_duplicate"
        }
        if (-not $expectedOutputPaths.ContainsKey($outputKey)) {
            throw "collector_row_output_artifact_unexpected"
        }
        $outputPaths[$outputKey] = $true
    }
    if ($outputPaths.Count -ne $expectedOutputPaths.Count) {
        throw "collector_row_output_artifact_set_invalid"
    }
    if (-not $outputPaths.ContainsKey(([string]$row.row_artifact.path).ToLowerInvariant())) {
        throw "collector_row_artifact_not_in_output_set"
    }
    foreach ($commandRecord in @($row.commands)) {
        if (-not $outputPaths.ContainsKey(
                ([string]$commandRecord.output.path).ToLowerInvariant())) {
            throw "collector_row_command_artifact_not_in_output_set"
        }
    }

    foreach ($attachment in @($row.attachments)) {
        Assert-SteinReviewAttachmentMetadata `
            -Attachment $attachment `
            -ExpectedGate $gateId
        $attachmentId = [string]$attachment.attachment_id
        if ($sourceAttachmentsById.ContainsKey($attachmentId)) {
            throw "collector_attachment_duplicate"
        }
        $sourceAttachmentsById[$attachmentId] = $attachment
        $sourceAttachmentGateById[$attachmentId] = $gateId
    }
    Assert-SteinReviewNoPrivateValues -Value $rowPayload -Context "collector_row"
    $sourceRowsByGate[$gateId] = [pscustomobject]@{
        summary = $row
        payload = $rowPayload
        path = $rowPath
    }
}
if (@($script:SteinPhase2ReviewGateIds | Where-Object {
            -not $sourceRowsByGate.ContainsKey($_)
        }).Count -ne 0) {
    throw "collector_gate_set_invalid"
}
foreach ($status in @("pass", "fail", "blocked", "not_run")) {
    $actualCount = @($sourceRows | Where-Object {
        [string]$_.status -ceq $status
    }).Count
    if ([long]$ledger.summary.rows.$status -ne $actualCount) {
        throw "collector_row_summary_mismatch"
    }
}
$collectorExpectedFiles = @($script:SteinReviewArtifactCache.Values | ForEach-Object {
    [string]$_.path
}) + @($rootAnchorPath)
Assert-SteinReviewExactFileTree `
    -Root $evidenceRoot `
    -ExpectedFiles $collectorExpectedFiles `
    -FailureCode "collector_evidence_file_set_invalid"
Assert-SteinReviewCollectorRuntimeSourcesStable

Assert-SteinReviewNoPrivateValues -Value $rootAnchor -Context "collector_root_anchor"
Assert-SteinReviewNoPrivateValues -Value $generator -Context "collector_generator"
Assert-SteinReviewNoPrivateValues -Value $hostRecord -Context "collector_host"
Assert-SteinReviewNoPrivateValues -Value $ledger -Context "collector_ledger"

$manifestPath = Resolve-SteinPhase2RegularFile -Path $ReviewManifest
Assert-SteinReviewNoReparseAncestors -Path $manifestPath
$manifestItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
if ($manifestItem.Length -gt 8MB) {
    throw "review_manifest_size_invalid"
}
$manifestInitialHash = Get-SteinPhase2Sha256 -Path $manifestPath
$manifest = Read-SteinReviewJsonFile `
    -Path $manifestPath `
    -MaximumBytes 8MB `
    -FailureCode "review_manifest_invalid" `
    -ExpectedSha256 $manifestInitialHash `
    -ExpectedSize ([long]$manifestItem.Length)
Assert-SteinReviewJsonShape -Value $manifest `
    -ExpectedProperties @(
        "schema_version", "review_identity", "source_root_anchor_sha256",
        "source_root_digest_sha256", "source_ledger_sha256", "attachments", "reviews") `
    -FailureCode "review_manifest_schema_invalid"
Assert-SteinReviewSchemaVersion -Value $manifest.schema_version `
    -FailureCode "review_manifest_schema_invalid"
if ([string]$manifest.review_identity -cne "phase2-installed-independent-review-v1") {
    throw "review_manifest_identity_invalid"
}
foreach ($binding in @(
        [pscustomobject]@{
            actual = $manifest.source_root_anchor_sha256
            expected = $ExpectedRootAnchorSha256
        },
        [pscustomobject]@{
            actual = $manifest.source_root_digest_sha256
            expected = $rootAnchor.root_digest_sha256
        },
        [pscustomobject]@{
            actual = $manifest.source_ledger_sha256
            expected = $rootAnchor.ledger.sha256
        })) {
    Assert-SteinReviewHash -Value $binding.actual `
        -FailureCode "review_manifest_source_binding_invalid"
    if ([string]$binding.actual -cne [string]$binding.expected) {
        throw "review_manifest_source_binding_invalid"
    }
}

$manifestBase = Split-Path -Parent $manifestPath
$attachmentMappings = @($manifest.attachments)
if ($attachmentMappings.Count -ne $sourceAttachmentsById.Count) {
    throw "review_attachment_set_invalid"
}
$mappingsById = @{}
foreach ($mapping in $attachmentMappings) {
    Assert-SteinReviewJsonShape -Value $mapping `
        -ExpectedProperties @(
            "attachment_id", "gate_id", "kind", "path", "sha256", "artifacts") `
        -FailureCode "review_attachment_schema_invalid"
    $attachmentId = [string]$mapping.attachment_id
    if ($attachmentId -cnotmatch '^[a-z0-9][a-z0-9._-]{0,63}$' -or
        $mappingsById.ContainsKey($attachmentId) -or
        -not $sourceAttachmentsById.ContainsKey($attachmentId)) {
        throw "review_attachment_set_invalid"
    }
    $metadata = $sourceAttachmentsById[$attachmentId]
    Assert-SteinReviewHash -Value $mapping.sha256 `
        -FailureCode "review_attachment_hash_invalid"
    if ([string]$mapping.gate_id -cne [string]$metadata.gate_id -or
        [string]$mapping.kind -cne [string]$metadata.kind -or
        [string]$mapping.sha256 -cne [string]$metadata.sha256) {
        throw "review_attachment_binding_invalid"
    }
    $attachmentPath = Resolve-SteinReviewContainedFile `
        -Root $manifestBase `
        -RelativePath $mapping.path `
        -FailureCode "review_attachment_path_invalid"
    $attachmentItem = Get-Item -LiteralPath $attachmentPath -Force -ErrorAction Stop
    $expectedExtension = if ([string]$metadata.kind -ceq "native_fixture_result") {
        ".json"
    }
    else { ".png" }
    $maximumSize = if ([string]$metadata.kind -ceq "native_fixture_result") {
        4MB
    }
    else { 32MB }
    if ([IO.Path]::GetExtension($attachmentPath) -ine $expectedExtension -or
        $attachmentItem.Length -gt $maximumSize -or
        $attachmentItem.Length -ne [long]$metadata.size -or
        (Get-SteinPhase2Sha256 -Path $attachmentPath) -cne [string]$metadata.sha256) {
        throw "review_attachment_hash_or_size_mismatch"
    }
    $underlyingArtifacts = New-Object Collections.Generic.List[object]
    $underlyingPaths = @{}
    $expectedUnderlying = if ([string]$metadata.kind -ceq "native_fixture_result") {
        @($metadata.native_fixture.artifacts)
    }
    else { @() }
    $expectedUnderlyingById = @{}
    foreach ($descriptor in $expectedUnderlying) {
        $expectedUnderlyingById[[string]$descriptor.artifact_id] = $descriptor
    }
    $underlyingMappings = @($mapping.artifacts)
    if ($underlyingMappings.Count -ne $expectedUnderlyingById.Count) {
        throw "review_underlying_artifact_set_invalid"
    }
    foreach ($artifactMapping in $underlyingMappings) {
        Assert-SteinReviewJsonShape -Value $artifactMapping `
            -ExpectedProperties @("artifact_id", "path", "sha256", "size") `
            -FailureCode "review_underlying_artifact_schema_invalid"
        $artifactId = [string]$artifactMapping.artifact_id
        if ($artifactId -cnotmatch '^[a-z0-9][a-z0-9._-]{2,95}$' -or
            $underlyingPaths.ContainsKey($artifactId) -or
            -not $expectedUnderlyingById.ContainsKey($artifactId)) {
            throw "review_underlying_artifact_set_invalid"
        }
        Assert-SteinReviewHash -Value $artifactMapping.sha256 `
            -FailureCode "review_underlying_artifact_invalid"
        Assert-SteinReviewInteger -Value $artifactMapping.size -Minimum 1 `
            -FailureCode "review_underlying_artifact_invalid"
        $expectedDescriptor = $expectedUnderlyingById[$artifactId]
        if ([string]$artifactMapping.sha256 -cne [string]$expectedDescriptor.sha256 -or
            [long]$artifactMapping.size -ne [long]$expectedDescriptor.size) {
            throw "review_underlying_artifact_binding_invalid"
        }
        $artifactPath = Resolve-SteinReviewContainedFile `
            -Root $manifestBase `
            -RelativePath $artifactMapping.path `
            -FailureCode "review_underlying_artifact_path_invalid"
        $artifactItem = Get-Item -LiteralPath $artifactPath -Force -ErrorAction Stop
        if ($artifactItem.Length -ne [long]$artifactMapping.size -or
            $artifactItem.Length -gt 64MB -or
            (Get-SteinPhase2Sha256 -Path $artifactPath) -cne
                [string]$artifactMapping.sha256) {
            throw "review_underlying_artifact_hash_or_size_mismatch"
        }
        $underlyingArtifacts.Add([pscustomobject]@{
            artifact_id = $artifactId
            sha256 = [string]$artifactMapping.sha256
            size = [long]$artifactMapping.size
        })
        $underlyingPaths[$artifactId] = $artifactPath
        $script:SteinReviewAttachmentFiles["artifact:$attachmentId`:$artifactId"] =
            [pscustomobject]@{
                path = $artifactPath
                size = [long]$artifactItem.Length
                sha256 = [string]$artifactMapping.sha256
            }
    }
    $fixture = $null
    if ([string]$metadata.kind -ceq "native_fixture_result") {
        $fixture = Read-SteinReviewNativeFixture `
            -Path $attachmentPath `
            -Metadata $metadata `
            -UnderlyingArtifacts @($underlyingArtifacts | ForEach-Object { $_ }) `
            -UnderlyingPaths $underlyingPaths `
            -ExpectedPackage $ledger.package
    }
    $mappingsById[$attachmentId] = [pscustomobject]@{
        mapping = $mapping
        metadata = $metadata
        path = $attachmentPath
        fixture = $fixture
        size = [long]$attachmentItem.Length
        sha256 = [string]$metadata.sha256
    }
    $script:SteinReviewAttachmentFiles["attachment:$attachmentId"] =
        $mappingsById[$attachmentId]
}

$reviews = @($manifest.reviews)
if ($reviews.Count -ne 32) {
    throw "review_gate_count_invalid"
}
$reviewsByGate = @{}
$reviewRecordIds = @{}
foreach ($review in $reviews) {
    Assert-SteinReviewJsonShape -Value $review `
        -ExpectedProperties @(
            "review_record_id", "gate_id", "disposition", "reason_code",
            "source_row_sha256", "native_fixture_attachment_id",
            "native_fixture_sha256", "independent_review", "semantic_review_completed",
            "privacy_review_completed", "synthetic_only", "reviewed_at_utc") `
        -FailureCode "review_record_schema_invalid"
    $gateId = [string]$review.gate_id
    $recordId = [string]$review.review_record_id
    if ($gateId -cnotin $script:SteinPhase2ReviewGateIds -or
        $reviewsByGate.ContainsKey($gateId) -or
        $recordId -cnotmatch '^[a-z0-9][a-z0-9._-]{0,63}$' -or
        $reviewRecordIds.ContainsKey($recordId) -or
        [string]$review.disposition -cnotin @("pass", "fail", "blocked", "not_run") -or
        [string]$review.reason_code -cnotmatch '^[a-z][a-z0-9_]{2,127}$') {
        throw "review_record_identity_invalid"
    }
    $reviewRecordIds[$recordId] = $true
    Assert-SteinReviewHash -Value $review.source_row_sha256 `
        -FailureCode "review_record_row_hash_invalid"
    $sourceRow = $sourceRowsByGate[$gateId].summary
    if ([string]$review.source_row_sha256 -cne [string]$sourceRow.row_artifact.sha256) {
        throw "review_record_row_hash_mismatch"
    }
    foreach ($property in @(
            "independent_review", "semantic_review_completed",
            "privacy_review_completed", "synthetic_only")) {
        Assert-SteinReviewBoolean -Value $review.$property `
            -FailureCode "review_record_declaration_invalid"
    }
    $reviewedAt = Assert-SteinReviewTimestamp -Value $review.reviewed_at_utc `
        -FailureCode "review_record_timestamp_invalid"
    if ($reviewedAt -lt $ledgerCompletedAt) {
        throw "review_record_timestamp_invalid"
    }

    $fixtureIdIsNull = $null -eq $review.native_fixture_attachment_id
    $fixtureHashIsNull = $null -eq $review.native_fixture_sha256
    if ($fixtureIdIsNull -ne $fixtureHashIsNull) {
        throw "review_record_fixture_binding_invalid"
    }
    $fixtureBinding = $null
    if (-not $fixtureIdIsNull) {
        if ($review.native_fixture_attachment_id -isnot [string] -or
            [string]$review.native_fixture_attachment_id -cnotmatch
                '^[a-z0-9][a-z0-9._-]{0,63}$' -or
            -not $mappingsById.ContainsKey([string]$review.native_fixture_attachment_id)) {
            throw "review_record_fixture_binding_invalid"
        }
        Assert-SteinReviewHash -Value $review.native_fixture_sha256 `
            -FailureCode "review_record_fixture_binding_invalid"
        $fixtureBinding = $mappingsById[[string]$review.native_fixture_attachment_id]
        if ([string]$fixtureBinding.metadata.gate_id -cne $gateId -or
            [string]$fixtureBinding.sha256 -cne [string]$review.native_fixture_sha256 -or
            [string]$fixtureBinding.metadata.kind -cne "native_fixture_result" -or
            $null -eq $fixtureBinding.fixture) {
            throw "review_record_fixture_binding_invalid"
        }
        $fixtureRecordedAt = Assert-SteinReviewTimestamp `
            -Value $fixtureBinding.fixture.recorded_at_utc `
            -FailureCode "review_record_timestamp_invalid"
        if ($reviewedAt -lt $fixtureRecordedAt) {
            throw "review_record_timestamp_invalid"
        }
    }

    if ([string]$review.disposition -ceq "pass") {
        if ([string]$sourceRow.status -cin @("fail", "blocked", "not_run")) {
            # The row is retained conservatively below; it cannot be promoted.
        }
        elseif ($null -eq $fixtureBinding -or
            [string]$fixtureBinding.metadata.kind -cne "native_fixture_result" -or
            [string]$fixtureBinding.metadata.declared_result -cne "pass" -or
            $null -eq $fixtureBinding.fixture -or
            [string]$fixtureBinding.fixture.result -cne "pass" -or
            [long]$fixtureBinding.fixture.exit_code -ne 0 -or
            -not [bool]$review.independent_review -or
            -not [bool]$review.semantic_review_completed -or
            -not [bool]$review.privacy_review_completed -or
            -not [bool]$review.synthetic_only) {
            throw "review_pass_requirements_not_satisfied"
        }
    }
    $reviewsByGate[$gateId] = [pscustomobject]@{
        record = $review
        fixture = $fixtureBinding
    }
}
if (@($script:SteinPhase2ReviewGateIds | Where-Object {
            -not $reviewsByGate.ContainsKey($_)
        }).Count -ne 0) {
    throw "review_gate_set_invalid"
}

Assert-SteinReviewNoPrivateValues -Value $manifest -Context "review_manifest"

$promotedRows = New-Object Collections.Generic.List[object]
foreach ($gateId in $script:SteinPhase2ReviewGateIds) {
    $sourceRow = $sourceRowsByGate[$gateId].summary
    $review = $reviewsByGate[$gateId].record
    $fixtureBinding = $reviewsByGate[$gateId].fixture
    $status = "not_run"
    $reasonCode = "independent_review_not_complete"
    if ([string]$sourceRow.status -ceq "fail" -or
        [string]$review.disposition -ceq "fail") {
        $status = "fail"
        $reasonCode = if ([string]$sourceRow.status -ceq "fail") {
            "source_collector_declared_fail"
        }
        else { "independent_review_declared_fail" }
    }
    elseif ([string]$sourceRow.status -ceq "blocked" -or
        [string]$review.disposition -ceq "blocked") {
        $status = "blocked"
        $reasonCode = if ([string]$sourceRow.status -ceq "blocked") {
            "source_collector_declared_blocked"
        }
        else { "independent_review_declared_blocked" }
    }
    elseif ([string]$sourceRow.status -ceq "pass" -and
        [string]$review.disposition -ceq "pass") {
        $status = "pass"
        $reasonCode = "independently_reviewed_native_fixture_pass"
    }
    elseif ([string]$sourceRow.status -ceq "not_run") {
        $reasonCode = "source_collector_declared_not_run"
    }
    $fixtureHash = $null
    if ($null -ne $fixtureBinding) {
        $fixtureHash = [string]$fixtureBinding.sha256
    }
    $promotedRows.Add([ordered]@{
        gate_id = $gateId
        status = $status
        reason_code = $reasonCode
        source_row_sha256 = [string]$sourceRow.row_artifact.sha256
        native_fixture_sha256 = $fixtureHash
        review_record_id = [string]$review.review_record_id
        reviewed_at_utc = ConvertTo-SteinReviewTimestampString `
            -Value $review.reviewed_at_utc `
            -FailureCode "review_record_timestamp_invalid"
        independent_review = [bool]$review.independent_review
        semantic_review_completed = [bool]$review.semantic_review_completed
        privacy_review_completed = [bool]$review.privacy_review_completed
        synthetic_only = [bool]$review.synthetic_only
        native_fixture_result_bound = (
            $null -ne $fixtureBinding -and
            [string]$fixtureBinding.metadata.kind -ceq "native_fixture_result")
        screenshot_can_prove_gate = $false
    })
}

$manifestFinalItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
if ($manifestFinalItem.Length -ne $manifestItem.Length -or
    (Get-SteinPhase2Sha256 -Path $manifestPath) -cne $manifestInitialHash) {
    throw "review_manifest_changed_during_validation"
}
foreach ($attachment in $script:SteinReviewAttachmentFiles.Values) {
    $item = Get-Item -LiteralPath $attachment.path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -ne [long]$attachment.size -or
        (Get-SteinPhase2Sha256 -Path $attachment.path) -cne [string]$attachment.sha256) {
        throw "review_attachment_changed_during_validation"
    }
}
Assert-SteinReviewArtifactCacheStable
$rootAnchorFinalItem = Get-Item -LiteralPath $rootAnchorPath -Force -ErrorAction Stop
if ($rootAnchorFinalItem.Length -ne $rootAnchorItem.Length -or
    (Get-SteinPhase2Sha256 -Path $rootAnchorPath) -cne $ExpectedRootAnchorSha256) {
    throw "collector_root_anchor_changed_during_review"
}
$reviewerSources = @(Assert-SteinReviewRuntimeSourcesStable)

$completed = [DateTime]::UtcNow
$failCount = @($promotedRows | Where-Object { $_.status -ceq "fail" }).Count
$blockedCount = @($promotedRows | Where-Object { $_.status -ceq "blocked" }).Count
$notRunCount = @($promotedRows | Where-Object { $_.status -ceq "not_run" }).Count
$passCount = @($promotedRows | Where-Object { $_.status -ceq "pass" }).Count
$completeAcceptance = (
    $promotedRows.Count -eq 32 -and
    $passCount -eq 32 -and
    $failCount -eq 0 -and
    $blockedCount -eq 0 -and
    $notRunCount -eq 0)

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Split-Path -Parent $evidenceRoot
}
$outputBase = Assert-SteinReviewArtifactsPath `
    -Path $OutputRoot `
    -Description "review_output_root" `
    -RequireDirectory
$stamp = $completed.ToUniversalTime().ToString("yyyyMMddTHHmmssfffZ")
$reviewRunId = [Guid]::NewGuid().ToString("N")
$script:SteinReviewOutputPath = Join-Path $outputBase (
    "reviewed-$stamp-$($reviewRunId.Substring(0, 8))")
$null = New-Item -ItemType Directory -Path $script:SteinReviewOutputPath -ErrorAction Stop
Protect-SteinPhase2OwnerOnlyPath -Path $script:SteinReviewOutputPath

$reviewerGenerator = [ordered]@{
    schema_version = 1
    harness_identity = "phase2-installed-review-v1"
    runtime_source_files = @($reviewerSources | ForEach-Object { $_ })
    source_paths = "repository_relative_only"
    source_stability = "required_before_final_ledger"
    trust_scope = "content_integrity_only_not_authentication"
}
$reviewerGeneratorArtifact = Write-SteinReviewEvidenceJson `
    -RelativePath "reviewer-generator.json" `
    -Value $reviewerGenerator

$finalLedger = [ordered]@{
    schema_version = 1
    run_id = $reviewRunId
    claim = "independently_reviewed_installed_acceptance"
    complete_acceptance = $completeAcceptance
    completed_at_utc = $completed.ToString("o")
    source_integrity = [ordered]@{
        collector_run_id = [string]$ledger.run_id
        collector_root_anchor_sha256 = $ExpectedRootAnchorSha256
        collector_root_digest_sha256 = [string]$rootAnchor.root_digest_sha256
        collector_generator_sha256 = [string]$rootAnchor.generator.sha256
        collector_host_sha256 = [string]$rootAnchor.host.sha256
        collector_ledger_sha256 = [string]$rootAnchor.ledger.sha256
        collector_rows_rehashed = 32
        collector_attachments_rehashed = $sourceAttachmentsById.Count
        changed_evidence_rejected = $true
    }
    review_provenance = [ordered]@{
        review_identity = "phase2-installed-independent-review-v1"
        review_manifest_sha256 = $manifestInitialHash
        exact_gate_set_verified = $true
        exact_attachment_set_verified = $true
        source_paths_retained = $false
    }
    privacy = [ordered]@{
        content_minimized = $true
        raw_host_retained = $false
        user_sid_retained = $false
        local_paths_retained = $false
        attachment_files_copied = $false
        provider_credentials_accessed = $false
        private_protocol_snapshot_requested = $false
    }
    mutation = [ordered]@{
        installed_state_mutated = $false
        package_task_process_or_daemon_changed = $false
        credential_store_accessed = $false
        persistent_outputs_review_directory_only = $true
    }
    rows = @($promotedRows | ForEach-Object { $_ })
    summary = [ordered]@{
        pass = $passCount
        fail = $failCount
        blocked = $blockedCount
        not_run = $notRunCount
    }
}
Assert-SteinReviewNoPrivateValues -Value $finalLedger -Context "final_ledger"
$finalLedgerArtifact = Write-SteinReviewEvidenceJson `
    -RelativePath "ledger.json" `
    -Value $finalLedger
$finalRootMaterial = @(
    "phase2-installed-review-root-v1",
    $reviewRunId,
    $reviewerGeneratorArtifact.sha256,
    $ExpectedRootAnchorSha256,
    $manifestInitialHash,
    $finalLedgerArtifact.sha256
) -join "`0"
$finalRootDigest = Get-SteinReviewStringSha256 -Value $finalRootMaterial
$finalRootAnchor = [ordered]@{
    schema_version = 1
    run_id = $reviewRunId
    harness_identity = "phase2-installed-review-v1"
    digest_algorithm = "sha256"
    root_digest_sha256 = $finalRootDigest
    digest_material =
        "identity_nul_run_nul_generator_nul_source_anchor_nul_review_manifest_nul_ledger"
    reviewer_generator = $reviewerGeneratorArtifact
    source_root_anchor_sha256 = $ExpectedRootAnchorSha256
    review_manifest_sha256 = $manifestInitialHash
    ledger = $finalLedgerArtifact
    trust_scope = "content_integrity_only_not_authentication"
}
Assert-SteinReviewNoPrivateValues -Value $finalRootAnchor -Context "final_root_anchor"
$finalRootAnchorArtifact = Write-SteinReviewEvidenceJson `
    -RelativePath "root-anchor.json" `
    -Value $finalRootAnchor
Protect-SteinPhase2OwnerOnlyTree -Root $script:SteinReviewOutputPath
Assert-SteinPhase2OwnerOnlyTree -Root $script:SteinReviewOutputPath
$reviewOutputArtifacts = @(
    $reviewerGeneratorArtifact,
    $finalLedgerArtifact,
    $finalRootAnchorArtifact)
$reviewOutputFiles = @($reviewOutputArtifacts | ForEach-Object {
    Join-Path $script:SteinReviewOutputPath ([string]$_.path)
})
Assert-SteinReviewExactFileTree `
    -Root $script:SteinReviewOutputPath `
    -ExpectedFiles $reviewOutputFiles `
    -FailureCode "review_output_file_set_invalid"
for ($index = 0; $index -lt $reviewOutputArtifacts.Count; $index++) {
    $item = Get-Item -LiteralPath $reviewOutputFiles[$index] -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -ne [long]$reviewOutputArtifacts[$index].size -or
        (Get-SteinPhase2Sha256 -Path $item.FullName) -cne
            [string]$reviewOutputArtifacts[$index].sha256) {
        throw "review_output_changed_during_finalization"
    }
}

# Recheck all external inputs and executable sources after final output is sealed.
$manifestPostOutputItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
if ($manifestPostOutputItem.Length -ne $manifestItem.Length -or
    (Get-SteinPhase2Sha256 -Path $manifestPath) -cne $manifestInitialHash) {
    throw "review_manifest_changed_during_finalization"
}
foreach ($attachment in $script:SteinReviewAttachmentFiles.Values) {
    $item = Get-Item -LiteralPath $attachment.path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -ne [long]$attachment.size -or
        (Get-SteinPhase2Sha256 -Path $attachment.path) -cne [string]$attachment.sha256) {
        throw "review_attachment_changed_during_finalization"
    }
}
Assert-SteinReviewArtifactCacheStable
Assert-SteinReviewCollectorRuntimeSourcesStable
$null = Assert-SteinReviewRuntimeSourcesStable
$rootAnchorPostOutputItem = Get-Item -LiteralPath $rootAnchorPath -Force -ErrorAction Stop
if ($rootAnchorPostOutputItem.Length -ne $rootAnchorItem.Length -or
    (Get-SteinPhase2Sha256 -Path $rootAnchorPath) -cne $ExpectedRootAnchorSha256) {
    throw "collector_root_anchor_changed_during_finalization"
}
Assert-SteinReviewExactFileTree `
    -Root $evidenceRoot `
    -ExpectedFiles $collectorExpectedFiles `
    -FailureCode "collector_evidence_file_set_invalid"
Assert-SteinReviewExactFileTree `
    -Root $script:SteinReviewOutputPath `
    -ExpectedFiles $reviewOutputFiles `
    -FailureCode "review_output_file_set_invalid"
for ($index = 0; $index -lt $reviewOutputArtifacts.Count; $index++) {
    $item = Get-Item -LiteralPath $reviewOutputFiles[$index] -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -ne [long]$reviewOutputArtifacts[$index].size -or
        (Get-SteinPhase2Sha256 -Path $item.FullName) -cne
            [string]$reviewOutputArtifacts[$index].sha256) {
        throw "review_output_changed_during_finalization"
    }
}
$null = Assert-SteinReviewRuntimeSourcesStable

$displayPath = $script:SteinReviewOutputPath.Substring($repoRoot.Length + 1).Replace("\", "/")
Write-Host "Reviewed evidence directory (repository-relative): $displayPath"
Write-Host "Final ledger SHA-256: $($finalLedgerArtifact.sha256)"
Write-Host "Final evidence root SHA-256: $finalRootDigest"
Write-Host "Final root anchor artifact SHA-256: $($finalRootAnchorArtifact.sha256)"
Write-Host "Complete Phase 2 acceptance: $completeAcceptance"

if ($failCount -ne 0) {
    exit 1
}
if ($blockedCount -ne 0) {
    exit 2
}
if (-not $completeAcceptance) {
    exit 3
}
exit 0
