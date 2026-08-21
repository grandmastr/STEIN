[CmdletBinding(DefaultParameterSetName = "Installed")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Installed")]
    [ValidateNotNullOrEmpty()]
    [string] $Publisher,

    [Parameter(Mandatory = $true, ParameterSetName = "Installed")]
    [ValidatePattern("^[0-9A-Fa-f ]{40,59}$")]
    [string] $CertificateThumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = "Installed")]
    [ValidatePattern("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")]
    [string] $Version,

    [Parameter(Mandatory = $true, ParameterSetName = "Installed")]
    [ValidateNotNullOrEmpty()]
    [string] $EvidenceDirectory,

    [Parameter(ParameterSetName = "Installed")]
    [string] $InstallRoot = (Join-Path (
        [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) "STEIN"),

    [Parameter(Mandatory = $true, ParameterSetName = "Synthetic")]
    [ValidateNotNullOrEmpty()]
    [string] $SyntheticFixtureRoot,

    [Parameter(Mandatory = $true, ParameterSetName = "Synthetic")]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $PackageMsixSha256,

    [Parameter(Mandatory = $true, ParameterSetName = "Synthetic")]
    [ValidatePattern("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]
    [string] $CandidateGitCommit,

    [Parameter(Mandatory = $true, ParameterSetName = "Synthetic")]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $SourceVerificationSha256
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version 3.0

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..")).Path
. (Join-Path $PSScriptRoot "Common.ps1")

$script:NoLeaksGateId = "P2-NO-LEAKS"
$script:NoLeaksFixtureId = "phase2-no-leaks-sentinel-scan-v1"
$script:NoLeaksRunnerId = "stein-phase2-no-leaks-scan-v1"
$script:NoLeaksProducerId = "stein-phase2-no-leaks-artifact-producer-v1"
$script:NoLeaksProducerCommandId = "collect-closed-installed-artifacts-v1"
$script:NoLeaksProducerFixtureId = "phase2-no-leaks-sentinel-producer-v1"
$script:NoLeaksProducerRunnerId = "stein-phase2-no-leaks-producer-v1"

# This is intentionally public synthetic test data. It is never accepted as a
# caller parameter and is never written to scanner output.
$script:NoLeaksSentinel = "STEIN_PHASE2_PUBLIC_NO_LEAKS_SENTINEL_V1_7F4C2A91"
$script:NoLeaksPatterns = @(
    [Text.Encoding]::UTF8.GetBytes($script:NoLeaksSentinel),
    [Text.Encoding]::Unicode.GetBytes($script:NoLeaksSentinel)
)
$script:NoLeaksStableFiles =
    [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase)
$script:NoLeaksStableTrees =
    [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase)
$script:NoLeaksInstalledCredentialBaseline = $null

$script:NoLeaksSubcheckIds = @(
    "audit_clean",
    "crash_output_clean",
    "credential_metadata_clean",
    "database_clean",
    "errors_clean",
    "evidence_clean",
    "logs_clean",
    "outbox_clean",
    "package_clean",
    "protocol_clean",
    "recovery_copy_clean",
    "traces_clean"
)

$script:NoLeaksProducerSubcheckIds = @(
    "audit_sentinel_roundtrip",
    "crash_output_sentinel_roundtrip",
    "credential_metadata_sentinel_roundtrip",
    "database_sentinel_roundtrip",
    "errors_sentinel_roundtrip",
    "evidence_sentinel_roundtrip",
    "logs_sentinel_roundtrip",
    "outbox_sentinel_roundtrip",
    "package_sentinel_roundtrip",
    "protocol_sentinel_roundtrip",
    "recovery_copy_sentinel_roundtrip",
    "traces_sentinel_roundtrip"
)

$script:NoLeaksProducerSlots = @(
    [pscustomobject]@{
        id = "crash_output"
        relative_path = "artifacts\crash-output.bin"
        subcheck_id = "crash_output_clean"
        artifact_class = "crash_output"
    },
    [pscustomobject]@{
        id = "errors"
        relative_path = "artifacts\errors.bin"
        subcheck_id = "errors_clean"
        artifact_class = "errors"
    },
    [pscustomobject]@{
        id = "evidence_receipt"
        relative_path = "artifacts\evidence-receipt.json"
        subcheck_id = "evidence_clean"
        artifact_class = "evidence"
    },
    [pscustomobject]@{
        id = "logs"
        relative_path = "artifacts\logs.bin"
        subcheck_id = "logs_clean"
        artifact_class = "logs"
    },
    [pscustomobject]@{
        id = "protocol_receipt"
        relative_path = "artifacts\protocol-receipt.json"
        subcheck_id = "protocol_clean"
        artifact_class = "protocol"
    },
    [pscustomobject]@{
        id = "recovery_copy"
        relative_path = "artifacts\recovery-copy.db"
        subcheck_id = "recovery_copy_clean"
        artifact_class = "recovery_copy"
    },
    [pscustomobject]@{
        id = "traces"
        relative_path = "artifacts\traces.bin"
        subcheck_id = "traces_clean"
        artifact_class = "traces"
    }
)

function Assert-NoLeaksJsonShape {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string[]] $ExpectedProperties
    )

    if ($null -eq $Value) {
        throw "closed_schema_invalid"
    }
    $actual = @($Value.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    $expected = @($ExpectedProperties | Sort-Object)
    if ($actual.Count -ne $expected.Count -or
        @(Compare-Object `
            -ReferenceObject $expected `
            -DifferenceObject $actual `
            -CaseSensitive).Count -ne 0) {
        throw "closed_schema_invalid"
    }
}

function Get-NoLeaksCanonicalPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    return [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
}

function Assert-NoLeaksDirectoryAncestors {
    param([Parameter(Mandatory = $true)][string] $Path)

    $probe = [IO.Path]::GetFullPath($Path)
    while ($true) {
        $item = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "directory_ancestor_invalid"
        }
        $parent = [IO.Directory]::GetParent($probe)
        if ($null -eq $parent) {
            break
        }
        $next = $parent.FullName
        if ([string]::IsNullOrWhiteSpace($next) -or $next -ceq $probe) {
            throw "directory_ancestor_invalid"
        }
        $probe = $next
    }
}

function Get-NoLeaksRelativePath {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $Path
    )

    $canonicalRoot = Get-NoLeaksCanonicalPath -Path $Root
    $canonicalPath = [IO.Path]::GetFullPath($Path)
    $prefix = "$canonicalRoot$([IO.Path]::DirectorySeparatorChar)"
    if (-not $canonicalPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "path_containment_invalid"
    }
    return $canonicalPath.Substring($prefix.Length).Replace("/", "\")
}

function Register-NoLeaksStableTree {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]] $Files,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]] $Directories
    )

    $canonical = Get-NoLeaksCanonicalPath -Path $Root
    $fileSet = @($Files | Sort-Object)
    $directorySet = @($Directories | Sort-Object)
    if ($script:NoLeaksStableTrees.ContainsKey($canonical)) {
        $existing = $script:NoLeaksStableTrees[$canonical]
        if (@(Compare-Object `
                    -ReferenceObject @($existing.files) `
                    -DifferenceObject $fileSet `
                    -CaseSensitive).Count -ne 0 -or
            @(Compare-Object `
                    -ReferenceObject @($existing.directories) `
                    -DifferenceObject $directorySet `
                    -CaseSensitive).Count -ne 0) {
            throw "artifact_tree_changed"
        }
        return
    }
    $script:NoLeaksStableTrees.Add(
        $canonical,
        [pscustomobject]@{
            root = $canonical
            files = $fileSet
            directories = $directorySet
        })
}

function Assert-NoLeaksClosedTree {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string[]] $ExpectedFiles,
        [Parameter(Mandatory = $true)][string[]] $ExpectedDirectories
    )

    $canonicalRoot = Get-NoLeaksCanonicalPath -Path $Root
    $rootItem = Get-Item -LiteralPath $canonicalRoot -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "closed_tree_invalid"
    }

    $items = @(Get-ChildItem -LiteralPath $canonicalRoot -Force -Recurse -ErrorAction Stop)
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "closed_tree_invalid"
        }
    }
    $actualFiles = @(
        $items |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object { Get-NoLeaksRelativePath -Root $canonicalRoot -Path $_.FullName } |
            Sort-Object
    )
    $actualDirectories = @(
        $items |
            Where-Object { $_.PSIsContainer } |
            ForEach-Object { Get-NoLeaksRelativePath -Root $canonicalRoot -Path $_.FullName } |
            Sort-Object
    )
    $expectedFileSet = @($ExpectedFiles | Sort-Object)
    $expectedDirectorySet = @($ExpectedDirectories | Sort-Object)
    if ($actualFiles.Count -ne $expectedFileSet.Count -or
        $actualDirectories.Count -ne $expectedDirectorySet.Count -or
        @(Compare-Object `
            -ReferenceObject $expectedFileSet `
            -DifferenceObject $actualFiles `
            -CaseSensitive).Count -ne 0 -or
        @(Compare-Object `
            -ReferenceObject $expectedDirectorySet `
            -DifferenceObject $actualDirectories `
            -CaseSensitive).Count -ne 0) {
        throw "closed_tree_invalid"
    }
    Register-NoLeaksStableTree `
        -Root $canonicalRoot `
        -Files $actualFiles `
        -Directories $actualDirectories
    return $canonicalRoot
}

function Get-NoLeaksSha256Bytes {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha256.ComputeHash($Bytes)).Replace(
            "-",
            "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-NoLeaksPatternMatchCount {
    param(
        [Parameter(Mandatory = $true)][byte[]] $Bytes,
        [Parameter(Mandatory = $true)][byte[]] $Pattern,
        [Parameter(Mandatory = $true)][int] $PriorByteCount
    )

    if ($Pattern.Length -eq 0 -or $Bytes.Length -lt $Pattern.Length) {
        return 0
    }
    $matches = 0
    $lastStart = $Bytes.Length - $Pattern.Length
    for ($start = 0; $start -le $lastStart; $start++) {
        if (($start + $Pattern.Length) -le $PriorByteCount) {
            continue
        }
        $equal = $true
        for ($offset = 0; $offset -lt $Pattern.Length; $offset++) {
            if ($Bytes[$start + $offset] -ne $Pattern[$offset]) {
                $equal = $false
                break
            }
        }
        if ($equal) {
            $matches++
        }
    }
    return $matches
}

function Get-NoLeaksByteMatchCount {
    param([Parameter(Mandatory = $true)][byte[]] $Bytes)

    $matches = 0
    foreach ($pattern in $script:NoLeaksPatterns) {
        $matches += Get-NoLeaksPatternMatchCount `
            -Bytes $Bytes `
            -Pattern $pattern `
            -PriorByteCount 0
    }
    return $matches
}

function Register-NoLeaksStableFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $Inspection,
        [Parameter(Mandatory = $true)][bool] $AllowEmpty
    )

    $canonical = [IO.Path]::GetFullPath($Path)
    if ($script:NoLeaksStableFiles.ContainsKey($canonical)) {
        $existing = $script:NoLeaksStableFiles[$canonical]
        if ([long]$existing.size_bytes -ne [long]$Inspection.size_bytes -or
            [string]$existing.sha256 -cne [string]$Inspection.sha256 -or
            [bool]$existing.allow_empty -ne $AllowEmpty) {
            throw "artifact_file_changed"
        }
        return
    }
    $script:NoLeaksStableFiles.Add(
        $canonical,
        [pscustomobject]@{
            path = $canonical
            size_bytes = [long]$Inspection.size_bytes
            sha256 = [string]$Inspection.sha256
            allow_empty = $AllowEmpty
        })
}

function Get-NoLeaksFileInspection {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [switch] $AllowEmpty,
        [switch] $SkipStabilityTracking,
        [ValidateRange(0, 1048576)]
        [int] $MaximumCaptureBytes = 0
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -lt 0 -or
        ($item.Length -eq 0 -and -not $AllowEmpty) -or
        ($MaximumCaptureBytes -gt 0 -and $item.Length -gt $MaximumCaptureBytes)) {
        throw "artifact_file_invalid"
    }

    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $initialLength = [long]$stream.Length
        if ($initialLength -lt 0 -or
            ($initialLength -eq 0 -and -not $AllowEmpty) -or
            $initialLength -ne [long]$item.Length) {
            throw "artifact_file_invalid"
        }
        $sha256 = [Security.Cryptography.SHA256]::Create()
        $capture = $null
        try {
            if ($MaximumCaptureBytes -gt 0) {
                $capture = [IO.MemoryStream]::new([int]$initialLength)
            }
            $buffer = New-Object byte[] 65536
            $tail = New-Object byte[] 0
            $maximumPatternLength = @(
                $script:NoLeaksPatterns | ForEach-Object { $_.Length } |
                    Measure-Object -Maximum).Maximum
            $matches = 0
            $total = 0L
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $null = $sha256.TransformBlock($buffer, 0, $read, $buffer, 0)
                if ($null -ne $capture) {
                    $capture.Write($buffer, 0, $read)
                }
                $combined = New-Object byte[] ($tail.Length + $read)
                if ($tail.Length -gt 0) {
                    [Buffer]::BlockCopy($tail, 0, $combined, 0, $tail.Length)
                }
                [Buffer]::BlockCopy($buffer, 0, $combined, $tail.Length, $read)
                foreach ($pattern in $script:NoLeaksPatterns) {
                    $matches += Get-NoLeaksPatternMatchCount `
                        -Bytes $combined `
                        -Pattern $pattern `
                        -PriorByteCount $tail.Length
                }
                $keep = [Math]::Min(
                    [Math]::Max(0, [int]$maximumPatternLength - 1),
                    $combined.Length)
                $nextTail = New-Object byte[] $keep
                if ($keep -gt 0) {
                    [Buffer]::BlockCopy(
                        $combined,
                        $combined.Length - $keep,
                        $nextTail,
                        0,
                        $keep)
                }
                $tail = $nextTail
                $total += $read
            }
            $empty = New-Object byte[] 0
            $null = $sha256.TransformFinalBlock($empty, 0, 0)
            if ($total -ne $initialLength -or $stream.Length -ne $initialLength) {
                throw "artifact_file_changed"
            }
            $digest = [BitConverter]::ToString($sha256.Hash).Replace(
                "-",
                "").ToLowerInvariant()
            $inspection = [pscustomobject]@{
                size_bytes = $total
                sha256 = $digest
                matches_found = [int]$matches
                captured_bytes = if ($null -eq $capture) { $null } else { $capture.ToArray() }
            }
            if (-not $SkipStabilityTracking) {
                Register-NoLeaksStableFile `
                    -Path $item.FullName `
                    -Inspection $inspection `
                    -AllowEmpty ([bool]$AllowEmpty)
            }
            return $inspection
        }
        finally {
            if ($null -ne $capture) {
                $capture.Dispose()
            }
            $sha256.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-NoLeaksStableArtifactSet {
    foreach ($tree in @($script:NoLeaksStableTrees.Values | Sort-Object root)) {
        $rootItem = Get-Item -LiteralPath $tree.root -Force -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or
            (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "artifact_tree_changed"
        }
        $items = @(Get-ChildItem `
                -LiteralPath $tree.root `
                -Force `
                -Recurse `
                -ErrorAction Stop)
        foreach ($item in $items) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "artifact_tree_changed"
            }
        }
        $files = @(
            $items |
                Where-Object { -not $_.PSIsContainer } |
                ForEach-Object { Get-NoLeaksRelativePath -Root $tree.root -Path $_.FullName } |
                Sort-Object)
        $directories = @(
            $items |
                Where-Object { $_.PSIsContainer } |
                ForEach-Object { Get-NoLeaksRelativePath -Root $tree.root -Path $_.FullName } |
                Sort-Object)
        if (@(Compare-Object `
                    -ReferenceObject @($tree.files) `
                    -DifferenceObject $files `
                    -CaseSensitive).Count -ne 0 -or
            @(Compare-Object `
                    -ReferenceObject @($tree.directories) `
                    -DifferenceObject $directories `
                    -CaseSensitive).Count -ne 0) {
            throw "artifact_tree_changed"
        }
    }

    foreach ($baseline in @($script:NoLeaksStableFiles.Values | Sort-Object path)) {
        $current = Get-NoLeaksFileInspection `
            -Path $baseline.path `
            -AllowEmpty:([bool]$baseline.allow_empty) `
            -SkipStabilityTracking
        if ([long]$current.size_bytes -ne [long]$baseline.size_bytes -or
            [string]$current.sha256 -cne [string]$baseline.sha256) {
            throw "artifact_file_changed"
        }
    }

    if ($null -ne $script:NoLeaksInstalledCredentialBaseline) {
        $currentCredential = Get-NoLeaksInstalledCredentialInspection
        if ([long]$currentCredential.size_bytes -ne
                [long]$script:NoLeaksInstalledCredentialBaseline.size_bytes -or
            [string]$currentCredential.sha256 -cne
                [string]$script:NoLeaksInstalledCredentialBaseline.sha256 -or
            [int]$currentCredential.matches_found -ne
                [int]$script:NoLeaksInstalledCredentialBaseline.matches_found) {
            throw "credential_metadata_changed"
        }
    }
}

function Read-NoLeaksBoundedJsonFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][ValidateRange(1, 1048576)][int] $MaximumBytes
    )

    $inspection = Get-NoLeaksFileInspection `
        -Path $Path `
        -MaximumCaptureBytes $MaximumBytes
    [byte[]]$bytes = $inspection.captured_bytes
    if ($bytes.Length -gt $MaximumBytes -or
        ($bytes.Length -ge 3 -and
            $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) {
        throw "bounded_json_invalid"
    }
    try {
        $encoding = New-Object Text.UTF8Encoding($false, $true)
        $text = $encoding.GetString($bytes)
        $document = $text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "bounded_json_invalid"
    }
    return [pscustomobject]@{
        document = $document
        inspection = $inspection
    }
}

function New-NoLeaksCatalogRecord {
    param(
        [Parameter(Mandatory = $true)][string] $Class,
        [Parameter(Mandatory = $true)][string] $Id,
        [Parameter(Mandatory = $true)] $Inspection
    )

    if ($Class -cnotmatch "^[a-z][a-z0-9_]*$" -or
        $Id -cnotmatch "^[a-z0-9][a-z0-9_.\/-]*$") {
        throw "artifact_identity_invalid"
    }
    return [pscustomobject]@{
        artifact_class = $Class
        artifact_id = $Id
        size_bytes = [long]$Inspection.size_bytes
        sha256 = [string]$Inspection.sha256
        matches_found = [int]$Inspection.matches_found
    }
}

function New-NoLeaksMemoryInspection {
    param([Parameter(Mandatory = $true)][string[]] $Values)

    $lines = New-Object "Collections.Generic.List[string]"
    foreach ($value in $Values) {
        $lines.Add("$($value.Length):$value")
    }
    $lines.Sort([StringComparer]::Ordinal)
    $canonical = [string]::Join("`n", $lines.ToArray())
    $utf8 = [Text.Encoding]::UTF8.GetBytes($canonical)
    $utf16 = [Text.Encoding]::Unicode.GetBytes($canonical)
    $bytes = New-Object byte[] ($utf8.Length + 1 + $utf16.Length)
    [Buffer]::BlockCopy($utf8, 0, $bytes, 0, $utf8.Length)
    $bytes[$utf8.Length] = 10
    [Buffer]::BlockCopy($utf16, 0, $bytes, $utf8.Length + 1, $utf16.Length)
    return [pscustomobject]@{
        size_bytes = [long]$bytes.Length
        sha256 = Get-NoLeaksSha256Bytes -Bytes $bytes
        matches_found = Get-NoLeaksByteMatchCount -Bytes $bytes
    }
}

function Get-NoLeaksProducerInspections {
    param(
        [Parameter(Mandatory = $true)][string] $InputRoot,
        [Parameter(Mandatory = $true)][string] $PackageBinding,
        [Parameter(Mandatory = $true)][string] $CommitBinding,
        [Parameter(Mandatory = $true)][string] $SourceBinding
    )

    $manifestRelativePath = "producer-manifest.json"
    $receiptRelativePath = "producer-receipt.json"
    $expectedFiles = @($manifestRelativePath, $receiptRelativePath) + @(
        $script:NoLeaksProducerSlots | ForEach-Object { $_.relative_path })
    $null = Assert-NoLeaksClosedTree `
        -Root $InputRoot `
        -ExpectedFiles $expectedFiles `
        -ExpectedDirectories @("artifacts")

    $manifestPath = Join-Path $InputRoot $manifestRelativePath
    $manifestRead = Read-NoLeaksBoundedJsonFile `
        -Path $manifestPath `
        -MaximumBytes 262144
    $manifest = $manifestRead.document
    Assert-NoLeaksJsonShape `
        -Value $manifest `
        -ExpectedProperties @("schema_version", "producer_id", "command_id", "artifacts")
    if ([int]$manifest.schema_version -ne 1 -or
        [string]$manifest.producer_id -cne $script:NoLeaksProducerId -or
        [string]$manifest.command_id -cne $script:NoLeaksProducerCommandId) {
        throw "producer_manifest_invalid"
    }

    $entries = @($manifest.artifacts)
    if ($entries.Count -ne $script:NoLeaksProducerSlots.Count) {
        throw "producer_manifest_invalid"
    }
    $inspections = @{}
    for ($index = 0; $index -lt $script:NoLeaksProducerSlots.Count; $index++) {
        $slot = $script:NoLeaksProducerSlots[$index]
        $entry = $entries[$index]
        Assert-NoLeaksJsonShape `
            -Value $entry `
            -ExpectedProperties @("id", "expected_present", "size_bytes", "sha256")
        $size = 0L
        if ([string]$entry.id -cne [string]$slot.id -or
            -not ($entry.expected_present -is [bool]) -or
            -not [bool]$entry.expected_present -or
            -not [long]::TryParse(
                [string]$entry.size_bytes,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$size) -or
            $size -le 0 -or
            [string]$entry.sha256 -cnotmatch "^[0-9a-f]{64}$") {
            throw "producer_manifest_invalid"
        }
        $inspection = Get-NoLeaksFileInspection -Path (Join-Path $InputRoot $slot.relative_path)
        if ($inspection.size_bytes -ne $size -or
            $inspection.sha256 -cne [string]$entry.sha256) {
            throw "producer_manifest_binding_invalid"
        }
        $inspections[[string]$slot.id] = $inspection
    }

    $receiptRead = Read-NoLeaksBoundedJsonFile `
        -Path (Join-Path $InputRoot $receiptRelativePath) `
        -MaximumBytes 131072
    $receipt = $receiptRead.document
    Assert-NoLeaksJsonShape `
        -Value $receipt `
        -ExpectedProperties @(
            "schema_version", "gate_id", "fixture_id", "runner_id", "result",
            "bindings", "summary", "subchecks")
    Assert-NoLeaksJsonShape `
        -Value $receipt.bindings `
        -ExpectedProperties @(
            "package_msix_sha256", "candidate_git_commit", "source_verification_sha256",
            "producer_manifest_sha256", "producer_source_sha256",
            "artifact_catalog_sha256", "artifact_count")
    Assert-NoLeaksJsonShape `
        -Value $receipt.summary `
        -ExpectedProperties @("required", "passed", "failed", "not_run", "artifacts_produced")
    if ([int]$receipt.schema_version -ne 1 -or
        [string]$receipt.gate_id -cne $script:NoLeaksGateId -or
        [string]$receipt.fixture_id -cne $script:NoLeaksProducerFixtureId -or
        [string]$receipt.runner_id -cne $script:NoLeaksProducerRunnerId -or
        [string]$receipt.result -cne "pass" -or
        [string]$receipt.bindings.package_msix_sha256 -cne $PackageBinding -or
        [string]$receipt.bindings.candidate_git_commit -cne $CommitBinding -or
        [string]$receipt.bindings.source_verification_sha256 -cne $SourceBinding -or
        [string]$receipt.bindings.producer_manifest_sha256 -cne
            [string]$manifestRead.inspection.sha256 -or
        [string]$receipt.bindings.producer_source_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
        [string]$receipt.bindings.producer_source_sha256 -ceq ("0" * 64) -or
        [string]$receipt.bindings.artifact_catalog_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
        [int]$receipt.bindings.artifact_count -le 0 -or
        [int]$receipt.summary.required -ne $script:NoLeaksProducerSubcheckIds.Count -or
        [int]$receipt.summary.passed -ne $script:NoLeaksProducerSubcheckIds.Count -or
        [int]$receipt.summary.failed -ne 0 -or
        [int]$receipt.summary.not_run -ne 0 -or
        [int]$receipt.summary.artifacts_produced -ne [int]$receipt.bindings.artifact_count) {
        throw "producer_receipt_invalid"
    }
    $producerSubchecks = @($receipt.subchecks)
    if ($producerSubchecks.Count -ne $script:NoLeaksProducerSubcheckIds.Count) {
        throw "producer_receipt_invalid"
    }
    $produced = 0
    for ($index = 0; $index -lt $producerSubchecks.Count; $index++) {
        $subcheck = $producerSubchecks[$index]
        Assert-NoLeaksJsonShape `
            -Value $subcheck `
            -ExpectedProperties @("id", "result", "artifacts_produced")
        if ([string]$subcheck.id -cne $script:NoLeaksProducerSubcheckIds[$index] -or
            [string]$subcheck.result -cne "pass" -or
            [int]$subcheck.artifacts_produced -lt 1) {
            throw "producer_receipt_invalid"
        }
        $produced += [int]$subcheck.artifacts_produced
    }
    if ($produced -ne [int]$receipt.summary.artifacts_produced) {
        throw "producer_receipt_invalid"
    }
    return [pscustomobject]@{
        manifest = $manifestRead.inspection
        artifacts = $inspections
        receipt = $receipt
    }
}

function Initialize-NoLeaksCredentialMetadataApi {
    if ($null -ne ("Stein.Phase2NoLeaksCredentialMetadataNative" -as [type])) {
        return
    }
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Stein {
    public sealed class Phase2NoLeaksCredentialMetadata {
        public string TargetName { get; set; }
        public string UserName { get; set; }
        public UInt32 Type { get; set; }
        public UInt32 Persist { get; set; }
    }

    public static class Phase2NoLeaksCredentialMetadataNative {
        [StructLayout(LayoutKind.Sequential)]
        private struct Credential {
            public UInt32 Flags;
            public UInt32 Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public UInt32 CredentialBlobSize;
            public IntPtr CredentialBlob;
            public UInt32 Persist;
            public UInt32 AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredEnumerateW(
            string filter, UInt32 flags, out UInt32 count, out IntPtr credentials);

        [DllImport("advapi32.dll")]
        private static extern void CredFree(IntPtr buffer);

        public static Phase2NoLeaksCredentialMetadata[] Enumerate(string prefix) {
            UInt32 count;
            IntPtr array;
            if (!CredEnumerateW(prefix + "*", 0, out count, out array)) {
                int error = Marshal.GetLastWin32Error();
                if (error == 1168) return new Phase2NoLeaksCredentialMetadata[0];
                throw new Win32Exception(error, "Credential metadata enumeration failed.");
            }
            if (count > 256) {
                CredFree(array);
                throw new InvalidOperationException("Credential metadata set is not bounded.");
            }
            Phase2NoLeaksCredentialMetadata[] result =
                new Phase2NoLeaksCredentialMetadata[count];
            try {
                for (int index = 0; index < count; index++) {
                    IntPtr pointer = Marshal.ReadIntPtr(array, index * IntPtr.Size);
                    Credential credential = (Credential)Marshal.PtrToStructure(
                        pointer, typeof(Credential));
                    string target = credential.TargetName == IntPtr.Zero
                        ? null
                        : Marshal.PtrToStringUni(credential.TargetName);
                    string user = credential.UserName == IntPtr.Zero
                        ? String.Empty
                        : Marshal.PtrToStringUni(credential.UserName);
                    result[index] = new Phase2NoLeaksCredentialMetadata {
                        TargetName = target,
                        UserName = user,
                        Type = credential.Type,
                        Persist = credential.Persist
                    };
                }
            }
            finally {
                CredFree(array);
            }
            return result;
        }
    }
}
"@
}

function ConvertTo-NoLeaksCredentialInspection {
    param([Parameter(Mandatory = $true)] $Entries)

    $entryArray = @($Entries)
    if ($entryArray.Count -lt 1 -or $entryArray.Count -gt 256) {
        throw "credential_metadata_set_invalid"
    }
    $values = New-Object "Collections.Generic.List[string]"
    $seen = New-Object "Collections.Generic.HashSet[string]" ([StringComparer]::Ordinal)
    foreach ($entry in $entryArray) {
        $target = [string]$entry.TargetName
        $userName = [string]$entry.UserName
        $type = [uint32]$entry.Type
        $persist = [uint32]$entry.Persist
        if ($type -ne 1 -or
            -not $target.StartsWith("STEIN:model-route:", [StringComparison]::Ordinal) -or
            $target.Substring("STEIN:model-route:".Length) -cnotmatch "^[A-Za-z0-9._-]{1,128}$" -or
            $userName.Length -gt 512 -or
            -not $seen.Add($target)) {
            throw "credential_metadata_set_invalid"
        }
        $values.Add("target=$target`nusername=$userName`ntype=$type`npersist=$persist")
    }
    return New-NoLeaksMemoryInspection -Values $values.ToArray()
}

function Get-NoLeaksInstalledCredentialInspection {
    Initialize-NoLeaksCredentialMetadataApi
    $entries = [Stein.Phase2NoLeaksCredentialMetadataNative]::Enumerate(
        "STEIN:model-route:")
    return ConvertTo-NoLeaksCredentialInspection -Entries $entries
}

function Get-NoLeaksSyntheticCredentialInspection {
    param([Parameter(Mandatory = $true)][string] $Path)

    $read = Read-NoLeaksBoundedJsonFile -Path $Path -MaximumBytes 65536
    $document = $read.document
    Assert-NoLeaksJsonShape `
        -Value $document `
        -ExpectedProperties @("schema_version", "entries")
    if ([int]$document.schema_version -ne 1) {
        throw "credential_metadata_fixture_invalid"
    }
    $converted = @(
        @($document.entries) | ForEach-Object {
            Assert-NoLeaksJsonShape `
                -Value $_ `
                -ExpectedProperties @("target_name", "user_name", "type", "persist")
            [pscustomobject]@{
                TargetName = [string]$_.target_name
                UserName = [string]$_.user_name
                Type = [uint32]$_.type
                Persist = [uint32]$_.persist
            }
        }
    )
    return [pscustomobject]@{
        metadata = ConvertTo-NoLeaksCredentialInspection -Entries $converted
        document = $read.inspection
    }
}

function Get-NoLeaksDataFileInspections {
    param(
        [Parameter(Mandatory = $true)][string] $DataRoot,
        [Parameter(Mandatory = $true)][bool] $RequireSidecars
    )

    $required = @("stein.db")
    $sidecars = @("stein.db-journal", "stein.db-shm", "stein.db-wal")
    if ($RequireSidecars) {
        $required += $sidecars
    }
    $actualFiles = @(
        Get-ChildItem -LiteralPath $DataRoot -File -Force -ErrorAction Stop |
            ForEach-Object { $_.Name } |
            Sort-Object
    )
    $allowed = @($required)
    if (-not $RequireSidecars) {
        $allowed += $sidecars
    }
    $unexpected = @($actualFiles | Where-Object { $_ -cnotin $allowed })
    $missing = @($required | Where-Object { $_ -cnotin $actualFiles })
    $directories = @(Get-ChildItem -LiteralPath $DataRoot -Directory -Force -ErrorAction Stop)
    if ($unexpected.Count -ne 0 -or $missing.Count -ne 0 -or $directories.Count -ne 0) {
        throw "database_file_set_invalid"
    }
    Assert-SteinPhase2NoReparseTree -Root $DataRoot
    Register-NoLeaksStableTree `
        -Root $DataRoot `
        -Files $actualFiles `
        -Directories @()

    $records = @()
    foreach ($leaf in $actualFiles) {
        $id = switch -CaseSensitive ($leaf) {
            "stein.db" { "main"; break }
            "stein.db-journal" { "journal"; break }
            "stein.db-shm" { "shm"; break }
            "stein.db-wal" { "wal"; break }
            default { throw "database_file_set_invalid" }
        }
        $records += [pscustomobject]@{
            id = $id
            inspection = Get-NoLeaksFileInspection `
                -Path (Join-Path $DataRoot $leaf) `
                -AllowEmpty:($leaf -cne "stein.db")
        }
    }
    return $records
}

function Get-NoLeaksLogFileInspections {
    param(
        [Parameter(Mandatory = $true)][string] $LogRoot,
        [Parameter(Mandatory = $true)][bool] $RequireFiles
    )

    $allowed = @("core.stderr.log", "core.stdout.log")
    $actualFiles = @(
        Get-ChildItem -LiteralPath $LogRoot -File -Force -ErrorAction Stop |
            ForEach-Object { $_.Name } |
            Sort-Object
    )
    $directories = @(Get-ChildItem -LiteralPath $LogRoot -Directory -Force -ErrorAction Stop)
    if (@($actualFiles | Where-Object { $_ -cnotin $allowed }).Count -ne 0 -or
        $directories.Count -ne 0 -or
        ($RequireFiles -and
            @(Compare-Object `
                -ReferenceObject ($allowed | Sort-Object) `
                -DifferenceObject $actualFiles `
                -CaseSensitive).Count -ne 0)) {
        throw "log_file_set_invalid"
    }
    Assert-SteinPhase2NoReparseTree -Root $LogRoot
    Register-NoLeaksStableTree `
        -Root $LogRoot `
        -Files $actualFiles `
        -Directories @()
    return @(
        $actualFiles | ForEach-Object {
            [pscustomobject]@{
                id = if ($_ -ceq "core.stderr.log") { "installed_stderr" } else { "installed_stdout" }
                inspection = Get-NoLeaksFileInspection `
                    -Path (Join-Path $LogRoot $_) `
                    -AllowEmpty
            }
        }
    )
}

function Get-NoLeaksSyntheticPackageRecords {
    param([Parameter(Mandatory = $true)][string] $PackageRoot)

    $unpackedRoot = Join-Path $PackageRoot "unpacked"
    $unpackedFiles = @(Assert-SteinClosedUnpackedPackageLayout -PackageRoot $unpackedRoot)
    $topFiles = @(
        "candidate.identity.json",
        "candidate.msix",
        "release-cli.exe",
        "release-core.exe"
    )
    $expectedFiles = @($topFiles) + @($unpackedFiles | ForEach-Object { "unpacked\$_" })
    $expectedDirectories = New-Object "Collections.Generic.HashSet[string]" ([StringComparer]::Ordinal)
    $null = $expectedDirectories.Add("unpacked")
    foreach ($relativePath in $unpackedFiles) {
        $parent = Split-Path -Parent $relativePath
        while (-not [string]::IsNullOrWhiteSpace($parent)) {
            $null = $expectedDirectories.Add("unpacked\$parent")
            $parent = Split-Path -Parent $parent
        }
    }
    $null = Assert-NoLeaksClosedTree `
        -Root $PackageRoot `
        -ExpectedFiles $expectedFiles `
        -ExpectedDirectories @($expectedDirectories)

    $records = @(
        New-NoLeaksCatalogRecord `
            -Class "package" `
            -Id "msix" `
            -Inspection (Get-NoLeaksFileInspection -Path (Join-Path $PackageRoot "candidate.msix"))
        New-NoLeaksCatalogRecord `
            -Class "package" `
            -Id "release_identity" `
            -Inspection (Get-NoLeaksFileInspection -Path (Join-Path $PackageRoot "candidate.identity.json"))
        New-NoLeaksCatalogRecord `
            -Class "package" `
            -Id "release_core" `
            -Inspection (Get-NoLeaksFileInspection -Path (Join-Path $PackageRoot "release-core.exe"))
        New-NoLeaksCatalogRecord `
            -Class "package" `
            -Id "release_cli" `
            -Inspection (Get-NoLeaksFileInspection -Path (Join-Path $PackageRoot "release-cli.exe"))
    )
    foreach ($relativePath in @($unpackedFiles | Sort-Object)) {
        $id = "payload/" + $relativePath.Replace("\", "/").ToLowerInvariant()
        $records += New-NoLeaksCatalogRecord `
            -Class "package" `
            -Id $id `
            -Inspection (Get-NoLeaksFileInspection -Path (Join-Path $unpackedRoot $relativePath))
    }
    return $records
}

function New-NoLeaksUnpackDirectory {
    $temporaryRoot = Get-NoLeaksCanonicalPath -Path ([IO.Path]::GetTempPath())
    $leaf = "STEIN-phase2-no-leaks-unpack-$([Guid]::NewGuid().ToString('N'))"
    $path = [IO.Path]::GetFullPath((Join-Path $temporaryRoot $leaf))
    $prefix = "$temporaryRoot$([IO.Path]::DirectorySeparatorChar)"
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $path) -cnotmatch "^STEIN-phase2-no-leaks-unpack-[0-9a-f]{32}$" -or
        (Test-Path -LiteralPath $path)) {
        throw "unpack_directory_invalid"
    }
    Assert-NoLeaksDirectoryAncestors -Path $temporaryRoot
    $null = New-Item -ItemType Directory -Path $path -ErrorAction Stop
    $null = Protect-SteinPhase2OwnerOnlyPath -Path $path
    return $path
}

function Remove-NoLeaksUnpackDirectory {
    param([Parameter(Mandatory = $true)][string] $Path)

    $temporaryRoot = Get-NoLeaksCanonicalPath -Path ([IO.Path]::GetTempPath())
    $canonical = Get-NoLeaksCanonicalPath -Path $Path
    $prefix = "$temporaryRoot$([IO.Path]::DirectorySeparatorChar)"
    if (-not $canonical.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $canonical) -cnotmatch
            "^STEIN-phase2-no-leaks-unpack-[0-9a-f]{32}$") {
        throw "package_unpack_cleanup_failed"
    }
    Assert-NoLeaksDirectoryAncestors -Path $temporaryRoot
    Assert-NoLeaksDirectoryAncestors -Path $canonical
    Assert-SteinPhase2NoReparseTree -Root $canonical
    Remove-Item -LiteralPath $canonical -Recurse -Force -ErrorAction Stop
}

function Get-NoLeaksInstalledPackageRecords {
    param([Parameter(Mandatory = $true)] $Installed)

    $bundle = $Installed.Bundle
    $null = Assert-SteinPhase2InstalledPackage -Bundle $bundle
    $unpackedRoot = New-NoLeaksUnpackDirectory
    try {
        $makeAppx = Resolve-WindowsSdkTool -Name "makeappx.exe"
        & $makeAppx unpack /p $bundle.PackagePath /d $unpackedRoot /o *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "package_unpack_failed"
        }
        $unpackedFiles = @(Assert-SteinClosedUnpackedPackageLayout -PackageRoot $unpackedRoot)
        $records = @(
            New-NoLeaksCatalogRecord `
                -Class "package" `
                -Id "msix" `
                -Inspection (Get-NoLeaksFileInspection -Path $bundle.PackagePath)
            New-NoLeaksCatalogRecord `
                -Class "package" `
                -Id "release_identity" `
                -Inspection (Get-NoLeaksFileInspection -Path $bundle.IdentityPath)
            New-NoLeaksCatalogRecord `
                -Class "package" `
                -Id "release_core" `
                -Inspection (Get-NoLeaksFileInspection -Path $bundle.CorePath)
            New-NoLeaksCatalogRecord `
                -Class "package" `
                -Id "release_cli" `
                -Inspection (Get-NoLeaksFileInspection -Path $bundle.CliPath)
        )
        foreach ($relativePath in @($unpackedFiles | Sort-Object)) {
            $id = "payload/" + $relativePath.Replace("\", "/").ToLowerInvariant()
            $records += New-NoLeaksCatalogRecord `
                -Class "package" `
                -Id $id `
                -Inspection (Get-NoLeaksFileInspection `
                    -Path (Join-Path $unpackedRoot $relativePath) `
                    -SkipStabilityTracking)
        }
        return $records
    }
    finally {
        if (Test-Path -LiteralPath $unpackedRoot) {
            try {
                Remove-NoLeaksUnpackDirectory -Path $unpackedRoot
            }
            catch {
                # Never traverse or describe a suspicious temporary tree. The
                # directory is owner-only and contains only the signed public
                # package, but residue still invalidates the acceptance scan.
                throw "package_unpack_cleanup_failed"
            }
        }
    }
}

function Assert-NoLeaksInstalledEvidenceDirectory {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $RepositoryRoot
    )

    $base = Get-NoLeaksCanonicalPath -Path (
        Join-Path $RepositoryRoot "artifacts\evidence\phase-2")
    $canonical = Get-NoLeaksCanonicalPath -Path $Path
    $prefix = "$base$([IO.Path]::DirectorySeparatorChar)"
    if (-not $canonical.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $canonical) -cnotmatch "^installed-[0-9]{8}T[0-9]{9}Z-[0-9a-f]{8}$") {
        throw "evidence_directory_invalid"
    }
    $probe = $canonical
    while ($probe.Length -ge $base.Length) {
        $item = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "evidence_directory_invalid"
        }
        if ([string]::Equals($probe, $base, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            throw "evidence_directory_invalid"
        }
        $probe = $parent
    }
    Assert-SteinPhase2OwnerOnlyTree -Root $canonical
    return $canonical
}

function Assert-NoLeaksSyntheticRoot {
    param([Parameter(Mandatory = $true)][string] $Path)

    $temporaryRoot = Get-NoLeaksCanonicalPath -Path ([IO.Path]::GetTempPath())
    $base = [IO.Path]::GetFullPath((Join-Path $temporaryRoot "STEIN-phase2-no-leaks-selftest"))
    $canonical = Get-NoLeaksCanonicalPath -Path $Path
    $prefix = "$base$([IO.Path]::DirectorySeparatorChar)"
    if (-not $canonical.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $canonical) -cnotmatch "^[0-9a-f]{32}$") {
        throw "synthetic_fixture_root_invalid"
    }
    foreach ($probe in @($base, $canonical)) {
        $item = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "synthetic_fixture_root_invalid"
        }
    }
    return $canonical
}

function Assert-NoLeaksSyntheticFixtureLayout {
    param([Parameter(Mandatory = $true)][string] $Root)

    $payload = @(Get-SteinFixedApplicationPayloadRelativePaths) + @("AppxBlockMap.xml")
    $files = @(
        "credential-metadata.json",
        "evidence\no-leaks-input\producer-manifest.json",
        "evidence\no-leaks-input\producer-receipt.json",
        "evidence\no-leaks-input\artifacts\crash-output.bin",
        "evidence\no-leaks-input\artifacts\errors.bin",
        "evidence\no-leaks-input\artifacts\evidence-receipt.json",
        "evidence\no-leaks-input\artifacts\logs.bin",
        "evidence\no-leaks-input\artifacts\protocol-receipt.json",
        "evidence\no-leaks-input\artifacts\recovery-copy.db",
        "evidence\no-leaks-input\artifacts\traces.bin",
        "install\data\stein.db",
        "install\data\stein.db-journal",
        "install\data\stein.db-shm",
        "install\data\stein.db-wal",
        "install\logs\core.stderr.log",
        "install\logs\core.stdout.log",
        "package\candidate.identity.json",
        "package\candidate.msix",
        "package\release-cli.exe",
        "package\release-core.exe"
    ) + @($payload | ForEach-Object { "package\unpacked\$_" })
    $directories = New-Object "Collections.Generic.HashSet[string]" ([StringComparer]::Ordinal)
    foreach ($relativePath in $files) {
        $parent = Split-Path -Parent $relativePath
        while (-not [string]::IsNullOrWhiteSpace($parent)) {
            $null = $directories.Add($parent)
            $parent = Split-Path -Parent $parent
        }
    }
    $null = Assert-NoLeaksClosedTree `
        -Root $Root `
        -ExpectedFiles $files `
        -ExpectedDirectories @($directories)
}

function Assert-NoLeaksBindingValue {
    param(
        [Parameter(Mandatory = $true)][string] $Value,
        [Parameter(Mandatory = $true)][ValidateSet("sha256", "git")][string] $Kind
    )

    $valid = if ($Kind -ceq "sha256") {
        $Value -cmatch "^[0-9a-f]{64}$" -and $Value -cne ("0" * 64)
    }
    else {
        $Value -cmatch "^(?:[0-9a-f]{40}|[0-9a-f]{64})$" -and
            $Value -cne ("0" * $Value.Length)
    }
    if (-not $valid) {
        throw "provenance_binding_invalid"
    }
}

function Get-NoLeaksCatalogSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        $Records
    )

    $lines = New-Object "Collections.Generic.List[string]"
    foreach ($record in @($Records)) {
        $lines.Add(
            "$($record.artifact_class)|$($record.artifact_id)|$($record.size_bytes)|$($record.sha256)")
    }
    $lines.Sort([StringComparer]::Ordinal)
    $bytes = [Text.Encoding]::UTF8.GetBytes([string]::Join("`n", $lines.ToArray()))
    return Get-NoLeaksSha256Bytes -Bytes $bytes
}

$results = @{}
foreach ($id in $script:NoLeaksSubcheckIds) {
    $results[$id] = [ordered]@{
        id = $id
        result = "not_run"
        files_inspected = 0
        matches_found = 0
    }
}
$catalog = New-Object "Collections.Generic.List[object]"
$catalogKeys = New-Object "Collections.Generic.HashSet[string]" ([StringComparer]::Ordinal)

function Complete-NoLeaksSubcheck {
    param(
        [Parameter(Mandatory = $true)][string] $Id,
        [Parameter(Mandatory = $true)] $Records
    )

    $recordArray = @($Records)
    if ($recordArray.Count -eq 0) {
        throw "subcheck_artifact_set_empty"
    }
    $matches = 0
    foreach ($record in $recordArray) {
        $key = "$($record.artifact_class)`0$($record.artifact_id)"
        if (-not $catalogKeys.Add($key)) {
            throw "artifact_catalog_duplicate"
        }
        $catalog.Add($record)
        $matches += [int]$record.matches_found
    }
    $results[$Id].files_inspected = $recordArray.Count
    $results[$Id].matches_found = $matches
    $results[$Id].result = if ($matches -eq 0) { "pass" } else { "fail" }
}

function Fail-NoLeaksSubcheck {
    param([Parameter(Mandatory = $true)][string] $Id)

    $results[$Id].result = "fail"
    $results[$Id].files_inspected = 0
    $results[$Id].matches_found = 0
}

function Invalidate-NoLeaksSubchecks {
    foreach ($id in $script:NoLeaksSubcheckIds) {
        $results[$id].result = "fail"
    }
}

try {
    $installed = $null
    if ($PSCmdlet.ParameterSetName -ceq "Installed") {
        Assert-SteinPhase2WindowsHost
        $canonicalInstallRoot = Assert-SteinPhase2InstallRoot -InstallRoot $InstallRoot
        Assert-SteinPhase2OwnerOnlyTree -Root $canonicalInstallRoot
        $installed = Get-SteinPhase2InstalledBundle `
            -InstallRoot $canonicalInstallRoot `
            -Publisher $Publisher `
            -CertificateThumbprint $CertificateThumbprint `
            -Version $Version
        $canonicalEvidenceDirectory = Assert-NoLeaksInstalledEvidenceDirectory `
            -Path $EvidenceDirectory `
            -RepositoryRoot $repoRoot
        $producerInputRoot = Join-Path $canonicalEvidenceDirectory "no-leaks-input"
        $dataRoot = Join-Path $canonicalInstallRoot "data"
        $logRoot = Join-Path $canonicalInstallRoot "logs"
        $packageBinding = [string]$installed.Bundle.MsixSha256
        $commitBinding = [string]$installed.Bundle.CandidateGitCommit
        $sourceBinding = [string]$installed.Bundle.SourceVerificationSha256
    }
    else {
        $canonicalSyntheticRoot = Assert-NoLeaksSyntheticRoot -Path $SyntheticFixtureRoot
        $producerInputRoot = Join-Path $canonicalSyntheticRoot "evidence\no-leaks-input"
        $dataRoot = Join-Path $canonicalSyntheticRoot "install\data"
        $logRoot = Join-Path $canonicalSyntheticRoot "install\logs"
        $packageBinding = $PackageMsixSha256
        $commitBinding = $CandidateGitCommit
        $sourceBinding = $SourceVerificationSha256
    }
    Assert-NoLeaksBindingValue -Value $packageBinding -Kind "sha256"
    Assert-NoLeaksBindingValue -Value $commitBinding -Kind "git"
    Assert-NoLeaksBindingValue -Value $sourceBinding -Kind "sha256"

    $fixtureLayoutValid = $true
    if ($PSCmdlet.ParameterSetName -ceq "Synthetic") {
        try {
            Assert-NoLeaksSyntheticFixtureLayout -Root $canonicalSyntheticRoot
        }
        catch {
            $fixtureLayoutValid = $false
            foreach ($id in $script:NoLeaksSubcheckIds) {
                Fail-NoLeaksSubcheck -Id $id
            }
        }
    }

    $producerReceipt = $null
    if ($fixtureLayoutValid) {
      try {
        $databaseInspections = @(Get-NoLeaksDataFileInspections `
            -DataRoot $dataRoot `
            -RequireSidecars ($PSCmdlet.ParameterSetName -ceq "Synthetic"))
        foreach ($role in @("audit", "database", "outbox")) {
            $roleRecords = @(
                $databaseInspections | ForEach-Object {
                    New-NoLeaksCatalogRecord `
                        -Class $role `
                        -Id $_.id `
                        -Inspection $_.inspection
                }
            )
            Complete-NoLeaksSubcheck -Id "${role}_clean" -Records $roleRecords
        }
    }
      catch {
        foreach ($id in @("audit_clean", "database_clean", "outbox_clean")) {
            Fail-NoLeaksSubcheck -Id $id
        }
      }

      try {
        $producer = Get-NoLeaksProducerInspections `
            -InputRoot $producerInputRoot `
            -PackageBinding $packageBinding `
            -CommitBinding $commitBinding `
            -SourceBinding $sourceBinding
        $producerReceipt = $producer.receipt
        foreach ($slot in $script:NoLeaksProducerSlots) {
            $records = @(
                New-NoLeaksCatalogRecord `
                    -Class $slot.artifact_class `
                    -Id $slot.id `
                    -Inspection $producer.artifacts[[string]$slot.id]
            )
            if ([string]$slot.id -ceq "evidence_receipt") {
                $records += New-NoLeaksCatalogRecord `
                    -Class "evidence" `
                    -Id "producer_manifest" `
                    -Inspection $producer.manifest
            }
            if ([string]$slot.id -ceq "logs") {
                $installedLogs = @(Get-NoLeaksLogFileInspections `
                    -LogRoot $logRoot `
                    -RequireFiles ($PSCmdlet.ParameterSetName -ceq "Synthetic"))
                foreach ($installedLog in $installedLogs) {
                    $records += New-NoLeaksCatalogRecord `
                        -Class "logs" `
                        -Id $installedLog.id `
                        -Inspection $installedLog.inspection
                }
            }
            Complete-NoLeaksSubcheck -Id $slot.subcheck_id -Records $records
        }
    }
      catch {
        foreach ($slot in $script:NoLeaksProducerSlots) {
            if ($results[$slot.subcheck_id].result -ceq "not_run") {
                Fail-NoLeaksSubcheck -Id $slot.subcheck_id
            }
        }
      }

      try {
        $credentialRecords = if ($PSCmdlet.ParameterSetName -ceq "Installed") {
            $script:NoLeaksInstalledCredentialBaseline =
                Get-NoLeaksInstalledCredentialInspection
            @(
                New-NoLeaksCatalogRecord `
                    -Class "credential_metadata" `
                    -Id "metadata_set" `
                    -Inspection $script:NoLeaksInstalledCredentialBaseline
            )
        }
        else {
            $syntheticCredential = Get-NoLeaksSyntheticCredentialInspection `
                -Path (Join-Path $canonicalSyntheticRoot "credential-metadata.json")
            @(
                New-NoLeaksCatalogRecord `
                    -Class "credential_metadata" `
                    -Id "metadata_set" `
                    -Inspection $syntheticCredential.metadata
                New-NoLeaksCatalogRecord `
                    -Class "credential_metadata" `
                    -Id "synthetic_fixture_document" `
                    -Inspection $syntheticCredential.document
            )
        }
        Complete-NoLeaksSubcheck `
            -Id "credential_metadata_clean" `
            -Records $credentialRecords
    }
      catch {
        Fail-NoLeaksSubcheck -Id "credential_metadata_clean"
      }

      try {
        $packageRecords = if ($PSCmdlet.ParameterSetName -ceq "Installed") {
            @(Get-NoLeaksInstalledPackageRecords -Installed $installed)
        }
        else {
            @(Get-NoLeaksSyntheticPackageRecords `
                -PackageRoot (Join-Path $canonicalSyntheticRoot "package"))
        }
        Complete-NoLeaksSubcheck -Id "package_clean" -Records $packageRecords
    }
      catch {
        Fail-NoLeaksSubcheck -Id "package_clean"
      }
    }

    try {
        Assert-NoLeaksStableArtifactSet
    }
    catch {
        Invalidate-NoLeaksSubchecks
    }

    $orderedSubchecks = @($script:NoLeaksSubcheckIds | ForEach-Object { $results[$_] })
    $passed = @($orderedSubchecks | Where-Object { $_.result -ceq "pass" }).Count
    $failed = @($orderedSubchecks | Where-Object { $_.result -ceq "fail" }).Count
    $notRun = @($orderedSubchecks | Where-Object { $_.result -ceq "not_run" }).Count
    $filesInspected = 0
    foreach ($subcheck in $orderedSubchecks) {
        $filesInspected += [int]$subcheck.files_inspected
    }
    $catalogRecords = @($catalog | ForEach-Object { $_ })
    $catalogDigest = Get-NoLeaksCatalogSha256 -Records $catalogRecords
    if ($null -eq $producerReceipt -or
        [string]$producerReceipt.bindings.artifact_catalog_sha256 -cne $catalogDigest -or
        [int]$producerReceipt.bindings.artifact_count -ne $catalog.Count) {
        Invalidate-NoLeaksSubchecks
    }
    $orderedSubchecks = @($script:NoLeaksSubcheckIds | ForEach-Object { $results[$_] })
    $passed = @($orderedSubchecks | Where-Object { $_.result -ceq "pass" }).Count
    $failed = @($orderedSubchecks | Where-Object { $_.result -ceq "fail" }).Count
    $notRun = @($orderedSubchecks | Where-Object { $_.result -ceq "not_run" }).Count
    $overall = if ($passed -eq $script:NoLeaksSubcheckIds.Count -and
        $failed -eq 0 -and
        $notRun -eq 0 -and
        $filesInspected -gt 0) { "pass" } else { "fail" }

    $receipt = [ordered]@{
        schema_version = 1
        gate_id = $script:NoLeaksGateId
        fixture_id = $script:NoLeaksFixtureId
        runner_id = $script:NoLeaksRunnerId
        result = $overall
        bindings = [ordered]@{
            package_msix_sha256 = $packageBinding
            candidate_git_commit = $commitBinding
            source_verification_sha256 = $sourceBinding
            artifact_catalog_sha256 = $catalogDigest
            artifact_count = $catalog.Count
        }
        summary = [ordered]@{
            required = $script:NoLeaksSubcheckIds.Count
            passed = $passed
            failed = $failed
            not_run = $notRun
            files_inspected = $filesInspected
        }
        subchecks = $orderedSubchecks
    }
    [Console]::Out.WriteLine(($receipt | ConvertTo-Json -Depth 8 -Compress))
    if ($overall -ceq "pass") {
        exit 0
    }
    exit 1
}
catch {
    [Console]::Error.WriteLine("P2-NO-LEAKS scanner failed closed.")
    exit 2
}
