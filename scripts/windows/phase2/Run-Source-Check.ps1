[CmdletBinding()]
param(
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{2,95}$')]
    [string] $CheckId,

    [ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')]
    [string] $CandidateCommit,

    [ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')]
    [string] $CandidateTree,

    [ValidatePattern('^[0-9a-f]{64}$')]
    [string] $ExpectedRegistrySha256,

    [string] $ExpectedGitLauncherPath,

    [ValidatePattern('^[0-9a-f]{64}$')]
    [string] $ExpectedGitLauncherSha256,

    [ValidatePattern('^[0-9a-f]{64}$')]
    [string] $ExpectedGitResolvedSha256,

    [string] $EvidenceRoot,

    [switch] $LibraryOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

if ($env:OS -cne 'Windows_NT') {
    throw 'source_command_windows_host_required'
}
$script:SourceCommandRepositoryRoot = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..\..')).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
$script:SourceCommandRegistryPath = Join-Path $PSScriptRoot 'Source-Command-Registry.json'
$script:SourceCommandMaximumLogBytes = 16777216L

function Get-SteinSourceCommandStreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream] $Stream)

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw 'source_command_stream_invalid'
    }
    $Stream.Position = 0
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($algorithm.ComputeHash($Stream)).Replace(
            '-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
        $Stream.Position = 0
    }
}

function Get-SteinSourceCommandTextSha256 {
    param([AllowEmptyString()][Parameter(Mandatory = $true)][string] $Value)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace(
            '-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Get-SteinSourceCommandObjectSha256 {
    param([Parameter(Mandatory = $true)] $Value)

    return Get-SteinSourceCommandTextSha256 -Value (
        $Value | ConvertTo-Json -Depth 20 -Compress)
}

function Assert-SteinSourceCommandExactProperties {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string[]] $Expected,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if ($null -eq $Value -or $Value -is [string] -or
        $null -eq $Value.PSObject) {
        throw $FailureCode
    }
    $actual = @($Value.PSObject.Properties | ForEach-Object { [string]$_.Name })
    if ($actual.Count -ne $Expected.Count) {
        throw $FailureCode
    }
    foreach ($name in $Expected) {
        if ($name -cnotin $actual) {
            throw $FailureCode
        }
    }
}

function Test-SteinSourceCommandSafeRelativePath {
    param([Parameter(Mandatory = $true)][string] $Value)

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 512 -or
        [IO.Path]::IsPathRooted($Value) -or
        $Value -match '^[A-Za-z]:' -or $Value -match '[\x00-\x1f<>:"|?*]' -or
        $Value.Contains('\') -or $Value.StartsWith('/') -or $Value.EndsWith('/')) {
        return $false
    }
    if ($Value -ceq '.') {
        return $true
    }
    foreach ($segment in $Value.Split('/')) {
        if ([string]::IsNullOrWhiteSpace($segment) -or
            $segment -cin @('.', '..') -or $segment.EndsWith('.') -or
            $segment.EndsWith(' ') -or
            $segment -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') {
            return $false
        }
    }
    return $true
}

function Test-SteinSourceCommandToken {
    param([AllowNull()] $Value)

    if ($Value -isnot [string] -or $Value.Length -lt 1 -or
        $Value.Length -gt 512 -or
        $Value -cnotmatch '^[A-Za-z0-9._/,+@=-]+$' -or
        $Value -match '[\s"''&|;<>`$(){}\[\]!?*\\:]' -or
        $Value.StartsWith('/')) {
        return $false
    }
    foreach ($segment in $Value.Split('/')) {
        if ($segment -cin @('.', '..')) {
            return $false
        }
    }
    return $true
}

function Resolve-SteinSourceCommandPathUnderRoot {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $RelativePath,
        [Parameter(Mandatory = $true)][ValidateSet('Leaf', 'Container')][string] $Kind
    )

    if (-not (Test-SteinSourceCommandSafeRelativePath -Value $RelativePath)) {
        throw 'source_command_relative_path_invalid'
    }
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $candidate = if ($RelativePath -ceq '.') {
        $rootPath
    }
    else {
        [IO.Path]::GetFullPath((Join-Path $rootPath (
                    $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar))))
    }
    if ($candidate -cne $rootPath -and -not $candidate.StartsWith(
            "$rootPath$([IO.Path]::DirectorySeparatorChar)",
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'source_command_relative_path_invalid'
    }
    $probe = if ($Kind -ceq 'Leaf') { Split-Path -Parent $candidate } else { $candidate }
    while ($probe.Length -ge $rootPath.Length) {
        $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'source_command_path_unsafe'
        }
        if ([string]::Equals(
                $probe, $rootPath, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            throw 'source_command_path_unsafe'
        }
        $probe = $parent
    }
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($Kind -ceq 'Leaf' -and $item.PSIsContainer) -or
        ($Kind -ceq 'Container' -and -not $item.PSIsContainer)) {
        throw 'source_command_path_unsafe'
    }
    return $item.FullName
}

function Open-SteinSourceCommandFileLock {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [long] $MinimumBytes = 1L,
        [long] $MaximumBytes = 16777216L
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -lt $MinimumBytes -or $item.Length -gt $MaximumBytes) {
        throw 'source_command_locked_file_invalid'
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ([long]$stream.Length -ne [long]$item.Length -or
            [long]$stream.Length -lt $MinimumBytes -or
            [long]$stream.Length -gt $MaximumBytes) {
            throw 'source_command_locked_file_invalid'
        }
        $digest = Get-SteinSourceCommandStreamSha256 -Stream $stream
        return [pscustomobject]@{
            Path = $item.FullName
            Size = [long]$stream.Length
            Sha256 = $digest
            Stream = $stream
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Read-SteinSourceCommandLockedJson {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [long] $MaximumBytes = 1048576L
    )

    $lock = Open-SteinSourceCommandFileLock -Path $Path -MaximumBytes $MaximumBytes
    try {
        $bytes = New-Object byte[] $lock.Size
        $read = 0
        while ($read -lt $bytes.Length) {
            $count = $lock.Stream.Read($bytes, $read, $bytes.Length - $read)
            if ($count -le 0) {
                throw 'source_command_json_read_invalid'
            }
            $read += $count
        }
        $lock.Stream.Position = 0
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $converter = Get-Command ConvertFrom-Json -CommandType Cmdlet `
            -ErrorAction Stop
        $value = if ($converter.Parameters.ContainsKey('DateKind')) {
            $text | ConvertFrom-Json -DateKind String -ErrorAction Stop
        }
        else {
            $text | ConvertFrom-Json -ErrorAction Stop
        }
        return [pscustomobject]@{ Lock = $lock; Value = $value }
    }
    catch {
        $lock.Stream.Dispose()
        throw
    }
    finally {
        if ($null -ne $bytes) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
}

function Assert-SteinSourceCommandRegistry {
    param([Parameter(Mandatory = $true)] $Registry)

    $directIds = @(
        'rust-format', 'rust-check', 'rust-clippy', 'rust-tests',
        'desktop-typecheck', 'desktop-lint', 'desktop-tests', 'desktop-build',
        'edge-extension-tests', 'edge-host-format', 'edge-host-check',
        'edge-host-clippy', 'edge-host-tests', 'boundary-contract',
        'source-evidence-contract', 'installed-evidence-harness-static',
        'no-leaks-scanner-static',
        'installed-reviewer-windows-powershell-contract',
        'installed-reviewer-pwsh-contract', 'msix-static-contract',
        'release-workspace', 'release-production-core', 'release-edge-host',
        'release-tauri-no-bundle')
    $retainedIds = @(
        'no-leaks-producer-workflow', 'native-toolchain-provenance',
        'pinned-clean-build-environment', 'portable-runner-attestation',
        'windows-native-ignored-fixtures')
    $groupedIds = @(
        'phase2-source-fixture-upgrade', 'phase2-source-fixture-secrets',
        'phase2-source-fixture-identity',
        'phase2-source-fixture-phase1-regression',
        'phase2-source-fixture-goals', 'phase2-source-fixture-pixels',
        'phase2-source-fixture-model-contract',
        'phase2-source-fixture-intervention',
        'phase2-source-fixture-policy-failsafe',
        'phase2-source-fixture-notification',
        'phase2-source-fixture-outbox-recovery',
        'phase2-source-fixture-revocation-race',
        'phase2-source-fixture-retention')
    $derivedIds = @(
        'source-report-command-provenance', 'source-provenance-stability')
    $expectedIds = @(
        'rust-format', 'rust-check', 'rust-clippy', 'rust-tests',
        'desktop-typecheck', 'desktop-lint', 'desktop-tests', 'desktop-build',
        'edge-extension-tests', 'edge-host-format', 'edge-host-check',
        'edge-host-clippy', 'edge-host-tests', 'boundary-contract',
        'source-evidence-contract', 'installed-evidence-harness-static',
        'no-leaks-scanner-static', 'no-leaks-producer-workflow',
        'native-toolchain-provenance', 'pinned-clean-build-environment',
        'portable-runner-attestation', 'source-report-command-provenance') +
        $groupedIds + @(
        'installed-reviewer-windows-powershell-contract',
        'installed-reviewer-pwsh-contract', 'msix-static-contract',
        'release-workspace', 'release-production-core', 'release-edge-host',
        'release-tauri-no-bundle', 'windows-native-ignored-fixtures',
        'source-provenance-stability')

    Assert-SteinSourceCommandExactProperties -Value $Registry `
        -Expected @('schema_version', 'registry_id', 'checks') `
        -FailureCode 'source_command_registry_invalid'
    if (($Registry.schema_version -isnot [int] -and
            $Registry.schema_version -isnot [long]) -or
        [long]$Registry.schema_version -ne 1 -or
        [string]$Registry.registry_id -cne
            'stein.phase2.source-command-registry.v1') {
        throw 'source_command_registry_invalid'
    }
    $checks = @($Registry.checks)
    if ($checks.Count -ne 44) {
        throw 'source_command_registry_coverage_invalid'
    }
    for ($index = 0; $index -lt $expectedIds.Count; $index++) {
        if ([string]$checks[$index].id -cne [string]$expectedIds[$index]) {
            throw 'source_command_registry_coverage_invalid'
        }
    }
    $ids = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $groupMaterial = $null
    $executionGroups = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $expectedReasons = @{
        'no-leaks-producer-workflow' =
            'candidate_owned_installed_artifact_producer_unimplemented'
        'native-toolchain-provenance' =
            'authenticated_native_toolchain_provenance_unimplemented'
        'pinned-clean-build-environment' =
            'immutable_candidate_and_fresh_build_isolation_unimplemented'
        'portable-runner-attestation' =
            'authenticated_portable_artifact_attestation_unimplemented'
        'windows-native-ignored-fixtures' =
            'versioned_closed_native_fixture_receipts_unimplemented'
    }
    foreach ($check in $checks) {
        $id = [string]$check.id
        if ($id -cnotmatch '^[a-z0-9][a-z0-9._-]{2,95}$' -or -not $ids.Add($id)) {
            throw 'source_command_registry_check_invalid'
        }
        $category = [string]$check.category
        if ($id -cin $directIds -and $category -cne 'direct_execution') {
            throw 'source_command_registry_category_invalid'
        }
        if ($id -cin $groupedIds -and
            $category -cne 'grouped_fixture_execution') {
            throw 'source_command_registry_category_invalid'
        }
        if ($id -cin $retainedIds -and $category -cne 'retained_obligation') {
            throw 'source_command_registry_category_invalid'
        }
        if ($id -cin $derivedIds -and $category -cne 'derived') {
            throw 'source_command_registry_category_invalid'
        }
        if ($category -ceq 'retained_obligation') {
            Assert-SteinSourceCommandExactProperties -Value $check `
                -Expected @('id', 'category', 'reason_code') `
                -FailureCode 'source_command_registry_check_invalid'
            if ([string]$check.reason_code -cne [string]$expectedReasons[$id]) {
                throw 'source_command_registry_check_invalid'
            }
            continue
        }
        if ($category -ceq 'derived') {
            Assert-SteinSourceCommandExactProperties -Value $check `
                -Expected @('id', 'category', 'derivation') `
                -FailureCode 'source_command_registry_check_invalid'
            $expectedDerivation = if ($id -ceq 'source-report-command-provenance') {
                'exact_registry_and_receipt_coverage'
            }
            else {
                'candidate_and_registry_streams_stable'
            }
            if ([string]$check.derivation -cne $expectedDerivation) {
                throw 'source_command_registry_check_invalid'
            }
            continue
        }

        $expectedProperties = @(
            'id', 'category', 'executable_role', 'arguments',
            'working_directory', 'environment_profile', 'timeout_seconds')
        if ($category -ceq 'grouped_fixture_execution') {
            $expectedProperties = @(
                'id', 'category', 'group_id', 'executable_role', 'arguments',
                'working_directory', 'environment_profile', 'timeout_seconds',
                'fixture_receipt_path')
        }
        Assert-SteinSourceCommandExactProperties -Value $check `
            -Expected $expectedProperties `
            -FailureCode 'source_command_registry_check_invalid'
        if ([string]$check.executable_role -cnotin @(
                'cargo', 'pnpm', 'windows_powershell', 'pwsh') -or
            [string]$check.environment_profile -cnotin @(
                'phase2_synthetic_compile_v1', 'phase2_source_fixture_v1') -or
            ($check.timeout_seconds -isnot [int] -and
                $check.timeout_seconds -isnot [long]) -or
            [long]$check.timeout_seconds -lt 30 -or
            [long]$check.timeout_seconds -gt 14400 -or
            -not (Test-SteinSourceCommandSafeRelativePath `
                -Value ([string]$check.working_directory))) {
            throw 'source_command_registry_check_invalid'
        }
        if (($category -ceq 'direct_execution' -and
                [string]$check.environment_profile -cne
                    'phase2_synthetic_compile_v1') -or
            ($category -ceq 'grouped_fixture_execution' -and
                [string]$check.environment_profile -cne
                    'phase2_source_fixture_v1')) {
            throw 'source_command_registry_check_invalid'
        }
        $arguments = @($check.arguments)
        if ($arguments.Count -lt 1 -or $arguments.Count -gt 24) {
            throw 'source_command_registry_arguments_invalid'
        }
        foreach ($argument in $arguments) {
            Assert-SteinSourceCommandExactProperties -Value $argument `
                -Expected @('kind', 'value') `
                -FailureCode 'source_command_registry_arguments_invalid'
            $kind = [string]$argument.kind
            $value = [string]$argument.value
            if ($kind -cnotin @(
                    'literal', 'repository_relative_path',
                    'evidence_relative_path') -or
                -not (Test-SteinSourceCommandToken -Value $value) -or
                [IO.Path]::IsPathRooted($value) -or $value -match '^[A-Za-z]:') {
                throw 'source_command_registry_arguments_invalid'
            }
            if ($kind -ceq 'literal') {
                if ($value -cin @('-Command', '-EncodedCommand', '/c', '/k')) {
                    throw 'source_command_registry_shell_argument_invalid'
                }
            }
            elseif (-not (Test-SteinSourceCommandSafeRelativePath -Value $value)) {
                throw 'source_command_registry_arguments_invalid'
            }
            if ($kind -ceq 'evidence_relative_path' -and
                $value -cne 'source-fixtures') {
                throw 'source_command_registry_arguments_invalid'
            }
        }
        if ($category -ceq 'grouped_fixture_execution') {
            if ([string]$check.group_id -cne 'closed-source-fixture-suite' -or
                [string]$check.fixture_receipt_path -cne
                    "source-fixtures/$id.receipt.json") {
                throw 'source_command_registry_group_invalid'
            }
            $material = [ordered]@{
                role = [string]$check.executable_role
                arguments = @($check.arguments)
                working_directory = [string]$check.working_directory
                environment_profile = [string]$check.environment_profile
                timeout_seconds = [long]$check.timeout_seconds
            } | ConvertTo-Json -Depth 8 -Compress
            if ($null -eq $groupMaterial) {
                $groupMaterial = $material
            }
            elseif ([string]$groupMaterial -cne [string]$material) {
                throw 'source_command_registry_group_invalid'
            }
            $null = $executionGroups.Add('closed-source-fixture-suite')
        }
        else {
            $null = $executionGroups.Add("direct:$id")
        }
    }
    if ($executionGroups.Count -ne 25) {
        throw 'source_command_registry_execution_group_count_invalid'
    }
    return [pscustomobject]@{
        DirectIds = $directIds
        GroupedIds = $groupedIds
        RetainedIds = $retainedIds
        DerivedIds = $derivedIds
        ExecutionGroupCount = 25
    }
}

function Invoke-SteinSourceCommandGit {
    param(
        [Parameter(Mandatory = $true)][string] $GitExecutable,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [int[]] $AllowedExitCodes = @(0),
        [long] $MaximumCharacters = 1048576L
    )

    Push-Location -LiteralPath $script:SourceCommandRepositoryRoot
    try {
        $output = @(& $GitExecutable `
                -c core.fsmonitor=false `
                -c core.untrackedCache=false `
                @Arguments 2>&1)
        $exitCode = [int]$LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    $text = ($output | ForEach-Object { [string]$_ }) -join "`n"
    if ($exitCode -notin $AllowedExitCodes -or $text.Length -gt $MaximumCharacters) {
        throw 'source_command_git_operation_failed'
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Text = $text.Trim() }
}

function New-SteinSourceCommandGitBlobHashAlgorithm {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(40, 64)]
        [int] $ObjectIdLength
    )

    if ($ObjectIdLength -eq 40) {
        return [Security.Cryptography.SHA1]::Create()
    }
    return [Security.Cryptography.SHA256]::Create()
}

function New-SteinSourceCommandGitBlobHeader {
    param([Parameter(Mandatory = $true)][long] $ContentLength)

    if ($ContentLength -lt 0) {
        throw 'source_command_stream_invalid'
    }
    $lengthText = $ContentLength.ToString(
        [Globalization.CultureInfo]::InvariantCulture)
    $prefix = [Text.Encoding]::ASCII.GetBytes("blob $lengthText")
    $header = New-Object byte[] ($prefix.Length + 1)
    try {
        [Buffer]::BlockCopy($prefix, 0, $header, 0, $prefix.Length)
        return ,$header
    }
    finally {
        [Array]::Clear($prefix, 0, $prefix.Length)
    }
}

function Get-SteinSourceCommandGitBlobRawState {
    param(
        [Parameter(Mandatory = $true)][IO.Stream] $Stream,
        [Parameter(Mandatory = $true)][ValidateSet(40, 64)][int] $ObjectIdLength
    )

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw 'source_command_stream_invalid'
    }
    $algorithm = New-SteinSourceCommandGitBlobHashAlgorithm `
        -ObjectIdLength $ObjectIdLength
    $header = New-SteinSourceCommandGitBlobHeader `
        -ContentLength ([long]$Stream.Length)
    $buffer = New-Object byte[] 65536
    $crLfPairCount = 0L
    $pendingCarriageReturn = $false
    $Stream.Position = 0
    try {
        $null = $algorithm.TransformBlock(
            $header, 0, $header.Length, $header, 0)
        while (($read = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            for ($index = 0; $index -lt $read; $index++) {
                $value = $buffer[$index]
                if ($pendingCarriageReturn -and $value -eq 10) {
                    $crLfPairCount++
                }
                $pendingCarriageReturn = $value -eq 13
            }
            $null = $algorithm.TransformBlock($buffer, 0, $read, $buffer, 0)
        }
        $null = $algorithm.TransformFinalBlock($buffer, 0, 0)
        return [pscustomobject]@{
            ObjectId = [BitConverter]::ToString($algorithm.Hash).Replace(
                '-', '').ToLowerInvariant()
            CrLfPairCount = [long]$crLfPairCount
        }
    }
    finally {
        $algorithm.Dispose()
        $Stream.Position = 0
        [Array]::Clear($header, 0, $header.Length)
        [Array]::Clear($buffer, 0, $buffer.Length)
    }
}

function Get-SteinSourceCommandCrLfNormalizedGitBlobObjectId {
    param(
        [Parameter(Mandatory = $true)][IO.Stream] $Stream,
        [Parameter(Mandatory = $true)][ValidateSet(40, 64)][int] $ObjectIdLength,
        [Parameter(Mandatory = $true)][long] $CrLfPairCount
    )

    if (-not $Stream.CanRead -or -not $Stream.CanSeek -or
        $CrLfPairCount -lt 1 -or $CrLfPairCount -gt [long]$Stream.Length) {
        throw 'source_command_stream_invalid'
    }
    $normalizedLength = [long]$Stream.Length - $CrLfPairCount
    $algorithm = New-SteinSourceCommandGitBlobHashAlgorithm `
        -ObjectIdLength $ObjectIdLength
    $header = New-SteinSourceCommandGitBlobHeader `
        -ContentLength $normalizedLength
    $readBuffer = New-Object byte[] 65536
    $writeBuffer = New-Object byte[] 65536
    $writeCount = 0
    $normalizedByteCount = 0L
    $pendingCarriageReturn = $false
    $Stream.Position = 0
    try {
        $null = $algorithm.TransformBlock(
            $header, 0, $header.Length, $header, 0)
        while (($readCount = $Stream.Read(
                    $readBuffer, 0, $readBuffer.Length)) -gt 0) {
            for ($index = 0; $index -lt $readCount; $index++) {
                $value = $readBuffer[$index]
                if ($pendingCarriageReturn) {
                    if ($value -eq 10) {
                        $writeBuffer[$writeCount] = 10
                        $writeCount++
                        $pendingCarriageReturn = $false
                        if ($writeCount -eq $writeBuffer.Length) {
                            $null = $algorithm.TransformBlock(
                                $writeBuffer, 0, $writeCount, $writeBuffer, 0)
                            $normalizedByteCount += $writeCount
                            $writeCount = 0
                        }
                        continue
                    }
                    $writeBuffer[$writeCount] = 13
                    $writeCount++
                    $pendingCarriageReturn = $false
                    if ($writeCount -eq $writeBuffer.Length) {
                        $null = $algorithm.TransformBlock(
                            $writeBuffer, 0, $writeCount, $writeBuffer, 0)
                        $normalizedByteCount += $writeCount
                        $writeCount = 0
                    }
                }
                if ($value -eq 13) {
                    $pendingCarriageReturn = $true
                }
                else {
                    $writeBuffer[$writeCount] = $value
                    $writeCount++
                    if ($writeCount -eq $writeBuffer.Length) {
                        $null = $algorithm.TransformBlock(
                            $writeBuffer, 0, $writeCount, $writeBuffer, 0)
                        $normalizedByteCount += $writeCount
                        $writeCount = 0
                    }
                }
            }
        }
        if ($pendingCarriageReturn) {
            $writeBuffer[$writeCount] = 13
            $writeCount++
        }
        $null = $algorithm.TransformFinalBlock($writeBuffer, 0, $writeCount)
        $normalizedByteCount += $writeCount
        if ($normalizedByteCount -ne $normalizedLength) {
            throw 'source_command_stream_invalid'
        }
        return [BitConverter]::ToString($algorithm.Hash).Replace(
            '-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
        $Stream.Position = 0
        [Array]::Clear($header, 0, $header.Length)
        [Array]::Clear($readBuffer, 0, $readBuffer.Length)
        [Array]::Clear($writeBuffer, 0, $writeBuffer.Length)
    }
}

function Assert-SteinSourceCommandSafeAttributes {
    param(
        [Parameter(Mandatory = $true)][string] $GitExecutable,
        [Parameter(Mandatory = $true)][string[]] $Paths
    )

    if ($Paths.Count -lt 1 -or $Paths.Count -gt 100000) {
        throw 'source_command_candidate_attributes_invalid'
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $GitExecutable
    $startInfo.Arguments = '-c core.quotepath=false -c core.fsmonitor=false ' +
        '-c core.untrackedCache=false check-attr --stdin filter ident ' +
        'working-tree-encoding'
    $startInfo.WorkingDirectory = $script:SourceCommandRepositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'source_command_candidate_attributes_invalid'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $encoding = [Text.UTF8Encoding]::new($false)
        foreach ($path in $Paths) {
            if (-not (Test-SteinSourceCommandSafeRelativePath -Value $path)) {
                throw 'source_command_candidate_attributes_invalid'
            }
            $bytes = $encoding.GetBytes("$path`n")
            try {
                $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
            }
            finally {
                [Array]::Clear($bytes, 0, $bytes.Length)
            }
        }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(60000)) {
            try { $process.Kill() } catch { }
            throw 'source_command_candidate_attributes_invalid'
        }
        $process.WaitForExit()
        $stdout = [string]$stdoutTask.Result
        $stderr = [string]$stderrTask.Result
        if ($process.ExitCode -ne 0 -or
            -not [string]::IsNullOrEmpty($stderr) -or
            $stdout.Length -gt 67108864) {
            throw 'source_command_candidate_attributes_invalid'
        }
        $expectedPaths = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        foreach ($path in $Paths) {
            $null = $expectedPaths.Add($path)
        }
        $seen = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $lineCount = 0
        foreach ($line in @($stdout -split "`r?`n" | Where-Object {
                    -not [string]::IsNullOrEmpty([string]$_)
                })) {
            if ([string]$line -cnotmatch
                '^(?<path>[^:]+): (?<attribute>filter|ident|working-tree-encoding): (?<value>.+)$') {
                throw 'source_command_candidate_attributes_invalid'
            }
            $path = [string]$Matches['path']
            $attribute = [string]$Matches['attribute']
            $value = [string]$Matches['value']
            if (-not $expectedPaths.Contains($path) -or
                $value -cnotin @('unspecified', 'unset') -or
                -not $seen.Add("$path`n$attribute")) {
                throw 'source_command_candidate_attributes_invalid'
            }
            $lineCount++
        }
        if ($lineCount -ne ($Paths.Count * 3) -or
            $seen.Count -ne ($Paths.Count * 3)) {
            throw 'source_command_candidate_attributes_invalid'
        }
        return $true
    }
    finally {
        try { $process.StandardInput.Close() } catch { }
        $process.Dispose()
    }
}

function Resolve-SteinSourceCommandExecutable {
    param([Parameter(Mandatory = $true)][string] $Role)

    $path = if ($Role -ceq 'windows_powershell') {
        $system = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
        if ([string]::IsNullOrWhiteSpace($system)) {
            throw 'source_command_executable_unavailable'
        }
        Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe'
    }
    else {
        $name = switch ($Role) {
            'cargo' { 'cargo.exe' }
            'pnpm' { 'pnpm.cmd' }
            'pwsh' { 'pwsh.exe' }
            default { throw 'source_command_executable_role_invalid' }
        }
        $command = Get-Command $name -CommandType Application -ErrorAction Stop |
            Select-Object -First 1
        [string]$command.Source
    }
    $item = Get-Item -LiteralPath ([IO.Path]::GetFullPath($path)) `
        -Force -ErrorAction Stop
    $expectedLeaf = switch ($Role) {
        'windows_powershell' { 'powershell.exe' }
        'cargo' { 'cargo.exe' }
        'pnpm' { 'pnpm.cmd' }
        'pwsh' { 'pwsh.exe' }
    }
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -lt 1 -or [IO.Path]::GetFileName($item.FullName) -cne $expectedLeaf) {
        throw 'source_command_executable_invalid'
    }
    if ($Role -ceq 'pwsh') {
        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $item.FullName `
            -ErrorAction Stop
        $subject = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
        if ([string]$signature.Status -cne 'Valid' -or
            $null -eq $signature.SignerCertificate -or
            [string]$signature.SignerCertificate.Subject -cne $subject) {
            throw 'source_command_pwsh_publisher_invalid'
        }
    }
    $lock = Open-SteinSourceCommandFileLock `
        -Path $item.FullName `
        -MaximumBytes 268435456
    return [pscustomobject]@{
        Role = $Role
        Path = $item.FullName
        Name = $expectedLeaf
        Size = $lock.Size
        Sha256 = $lock.Sha256
        Stream = $lock.Stream
    }
}

function Open-SteinSourceCommandGitBinding {
    param(
        [Parameter(Mandatory = $true)][string] $LauncherPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string] $ExpectedLauncherSha256,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string] $ExpectedResolvedSha256
    )

    if (-not [IO.Path]::IsPathRooted($LauncherPath) -or
        $LauncherPath.Contains("`r") -or $LauncherPath.Contains("`n")) {
        throw 'source_command_git_binding_invalid'
    }
    $launcherFullPath = [IO.Path]::GetFullPath($LauncherPath)
    $launcherDirectory = Split-Path -Parent $launcherFullPath
    if ([IO.Path]::GetFileName($launcherFullPath) -cne 'git.exe' -or
        [IO.Path]::GetFileName($launcherDirectory) -cne 'cmd') {
        throw 'source_command_git_binding_invalid'
    }
    $installationRoot = [IO.Path]::GetFullPath(
        (Split-Path -Parent $launcherDirectory)).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
    $resolvedFullPath = [IO.Path]::GetFullPath((Join-Path `
                $installationRoot 'mingw64\bin\git.exe'))
    if (-not $resolvedFullPath.StartsWith(
            "$installationRoot$([IO.Path]::DirectorySeparatorChar)",
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'source_command_git_binding_invalid'
    }

    foreach ($path in @($launcherFullPath, $resolvedFullPath)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -lt 1 -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'source_command_git_binding_invalid'
        }
        $probe = Split-Path -Parent $item.FullName
        while (-not [string]::IsNullOrWhiteSpace($probe)) {
            $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
            if (-not $directory.PSIsContainer -or
                (($directory.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw 'source_command_git_binding_invalid'
            }
            $parent = Split-Path -Parent $probe
            if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
                break
            }
            $probe = $parent
        }
    }

    $launcherLock = $null
    $resolvedLock = $null
    try {
        $launcherLock = Open-SteinSourceCommandFileLock `
            -Path $launcherFullPath `
            -MaximumBytes 268435456
        $resolvedLock = Open-SteinSourceCommandFileLock `
            -Path $resolvedFullPath `
            -MaximumBytes 268435456
        if ([string]$launcherLock.Sha256 -cne $ExpectedLauncherSha256 -or
            [string]$resolvedLock.Sha256 -cne $ExpectedResolvedSha256) {
            throw 'source_command_git_binding_invalid'
        }
        return [pscustomobject]@{
            Launcher = $launcherLock
            Resolved = $resolvedLock
        }
    }
    catch {
        if ($null -ne $resolvedLock) {
            $resolvedLock.Stream.Dispose()
        }
        if ($null -ne $launcherLock) {
            $launcherLock.Stream.Dispose()
        }
        throw
    }
}

function Get-SteinSourceCommandCandidateInventory {
    param(
        [Parameter(Mandatory = $true)][string] $GitExecutable,
        [Parameter(Mandatory = $true)][string] $ExpectedCommit,
        [Parameter(Mandatory = $true)][string] $ExpectedTree
    )

    $commit = Invoke-SteinSourceCommandGit -GitExecutable $GitExecutable `
        -Arguments @('rev-parse', '--verify', 'HEAD^{commit}') `
        -MaximumCharacters 128
    $tree = Invoke-SteinSourceCommandGit -GitExecutable $GitExecutable `
        -Arguments @('rev-parse', '--verify', 'HEAD^{tree}') `
        -MaximumCharacters 128
    if ([string]$commit.Text -cne $ExpectedCommit -or
        [string]$tree.Text -cne $ExpectedTree) {
        throw 'source_command_candidate_identity_mismatch'
    }
    $objectFormat = Invoke-SteinSourceCommandGit -GitExecutable $GitExecutable `
        -Arguments @('rev-parse', '--show-object-format') `
        -MaximumCharacters 32
    $expectedObjectFormat = if ($ExpectedCommit.Length -eq 40) { 'sha1' } else { 'sha256' }
    if ([string]$objectFormat.Text -cne $expectedObjectFormat) {
        throw 'source_command_candidate_identity_mismatch'
    }

    $listing = Invoke-SteinSourceCommandGit -GitExecutable $GitExecutable `
        -Arguments @(
            '-c', 'core.quotepath=false', 'ls-tree', '-r', '--full-tree',
            $ExpectedCommit) `
        -MaximumCharacters 33554432
    $files = New-Object Collections.Generic.List[object]
    $records = New-Object Collections.Generic.List[string]
    $fileByPath = [Collections.Generic.Dictionary[string,object]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($line in @($listing.Text -split "`n" | Where-Object {
                -not [string]::IsNullOrEmpty([string]$_)
            })) {
        if ([string]$line -cnotmatch
            '^(?<mode>[0-9]{6}) (?<type>[a-z]+) (?<oid>[0-9a-f]+)\t(?<path>.+)$') {
            throw 'source_command_candidate_file_set_invalid'
        }
        $mode = [string]$Matches['mode']
        $type = [string]$Matches['type']
        $objectId = [string]$Matches['oid']
        $relative = [string]$Matches['path']
        if ($mode -cnotin @('100644', '100755') -or $type -cne 'blob' -or
            $objectId -cnotmatch "^[0-9a-f]{$($ExpectedCommit.Length)}$" -or
            -not (Test-SteinSourceCommandSafeRelativePath -Value $relative) -or
            $fileByPath.ContainsKey($relative)) {
            throw 'source_command_candidate_file_set_invalid'
        }
        $file = [pscustomobject]@{
            RelativePath = $relative
            Mode = $mode
            ObjectId = $objectId
        }
        $fileByPath.Add($relative, $file)
        $files.Add($file)
        $pathBytes = [Text.UTF8Encoding]::new($false).GetByteCount($relative)
        $records.Add("$pathBytes`:$relative|$mode|$objectId")
        if ($files.Count -gt 100000) {
            throw 'source_command_candidate_file_set_invalid'
        }
    }
    if ($files.Count -lt 1) {
        throw 'source_command_candidate_file_set_invalid'
    }

    $indexListing = Invoke-SteinSourceCommandGit -GitExecutable $GitExecutable `
        -Arguments @('-c', 'core.quotepath=false', 'ls-files', '--stage') `
        -MaximumCharacters 33554432
    $indexPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($line in @($indexListing.Text -split "`n" | Where-Object {
                -not [string]::IsNullOrEmpty([string]$_)
            })) {
        if ([string]$line -cnotmatch
            '^(?<mode>[0-9]{6}) (?<oid>[0-9a-f]+) (?<stage>[0-3])\t(?<path>.+)$') {
            throw 'source_command_candidate_index_invalid'
        }
        $relative = [string]$Matches['path']
        if (-not $fileByPath.ContainsKey($relative) -or
            -not $indexPaths.Add($relative) -or
            [string]$Matches['stage'] -cne '0' -or
            [string]$Matches['mode'] -cne [string]$fileByPath[$relative].Mode -or
            [string]$Matches['oid'] -cne [string]$fileByPath[$relative].ObjectId) {
            throw 'source_command_candidate_index_invalid'
        }
    }
    if ($indexPaths.Count -ne $files.Count) {
        throw 'source_command_candidate_index_invalid'
    }

    $flagListing = Invoke-SteinSourceCommandGit -GitExecutable $GitExecutable `
        -Arguments @('-c', 'core.quotepath=false', 'ls-files', '-v') `
        -MaximumCharacters 33554432
    $flagPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($line in @($flagListing.Text -split "`n" | Where-Object {
                -not [string]::IsNullOrEmpty([string]$_)
            })) {
        if ([string]$line -cnotmatch '^(?<tag>.) (?<path>.+)$') {
            throw 'source_command_candidate_index_flags_invalid'
        }
        $relative = [string]$Matches['path']
        if ([string]$Matches['tag'] -cne 'H' -or
            -not $fileByPath.ContainsKey($relative) -or
            -not $flagPaths.Add($relative)) {
            throw 'source_command_candidate_index_flags_invalid'
        }
    }
    if ($flagPaths.Count -ne $files.Count) {
        throw 'source_command_candidate_index_flags_invalid'
    }

    $relativePaths = @($files.ToArray() | ForEach-Object {
            [string]$_.RelativePath
        })
    $null = Assert-SteinSourceCommandSafeAttributes `
        -GitExecutable $GitExecutable `
        -Paths $relativePaths
    $diff = Invoke-SteinSourceCommandGit -GitExecutable $GitExecutable `
        -Arguments @('diff-index', '--quiet', $ExpectedCommit, '--') `
        -AllowedExitCodes @(0, 1) `
        -MaximumCharacters 4096
    $status = Invoke-SteinSourceCommandGit -GitExecutable $GitExecutable `
        -Arguments @(
            '-c', 'core.quotepath=false', 'status', '--porcelain=v1',
            '--untracked-files=all') `
        -MaximumCharacters 16777216
    if ($diff.ExitCode -ne 0 -or -not [string]::IsNullOrEmpty($diff.Text) -or
        -not [string]::IsNullOrEmpty($status.Text)) {
        throw 'source_command_candidate_tracked_changes_present'
    }

    $recordArray = $records.ToArray()
    [Array]::Sort($recordArray, [StringComparer]::Ordinal)
    return [pscustomobject]@{
        Commit = $ExpectedCommit
        Tree = $ExpectedTree
        FileCount = $files.Count
        ManifestSha256 = Get-SteinSourceCommandTextSha256 `
            -Value ($recordArray -join "`n")
        Files = $files.ToArray()
    }
}

function Open-SteinSourceCommandCandidate {
    param(
        [Parameter(Mandatory = $true)][string] $GitExecutable,
        [Parameter(Mandatory = $true)][string] $ExpectedCommit,
        [Parameter(Mandatory = $true)][string] $ExpectedTree
    )

    $inventory = Get-SteinSourceCommandCandidateInventory `
        -GitExecutable $GitExecutable `
        -ExpectedCommit $ExpectedCommit `
        -ExpectedTree $ExpectedTree
    $locks = New-Object Collections.Generic.List[object]
    $eolConvertedFileCount = 0
    try {
        foreach ($file in @($inventory.Files)) {
            $relative = [string]$file.RelativePath
            $fullPath = Resolve-SteinSourceCommandPathUnderRoot `
                -Root $script:SourceCommandRepositoryRoot `
                -RelativePath $relative `
                -Kind Leaf
            $lock = Open-SteinSourceCommandFileLock `
                -Path $fullPath `
                -MinimumBytes 0 `
                -MaximumBytes 2147483648
            $locks.Add($lock)
            $blobState = Get-SteinSourceCommandGitBlobRawState `
                -Stream $lock.Stream `
                -ObjectIdLength $ExpectedCommit.Length
            if ([string]$blobState.ObjectId -cne [string]$file.ObjectId) {
                if ([long]$blobState.CrLfPairCount -lt 1) {
                    throw 'source_command_candidate_content_invalid'
                }
                $normalizedObjectId =
                    Get-SteinSourceCommandCrLfNormalizedGitBlobObjectId `
                        -Stream $lock.Stream `
                        -ObjectIdLength $ExpectedCommit.Length `
                        -CrLfPairCount ([long]$blobState.CrLfPairCount)
                if ($normalizedObjectId -cne [string]$file.ObjectId) {
                    throw 'source_command_candidate_content_invalid'
                }
                $eolConvertedFileCount++
            }
        }
        return [pscustomobject]@{
            Commit = [string]$inventory.Commit
            Tree = [string]$inventory.Tree
            FileCount = [long]$inventory.FileCount
            ManifestSha256 = [string]$inventory.ManifestSha256
            EolConvertedFileCount = $eolConvertedFileCount
            Locks = $locks
        }
    }
    catch {
        foreach ($lock in $locks) {
            $lock.Stream.Dispose()
        }
        throw
    }
}

function Assert-SteinSourceCommandCandidateStable {
    param(
        [Parameter(Mandatory = $true)] $Candidate,
        [Parameter(Mandatory = $true)][string] $GitExecutable
    )

    foreach ($lock in $Candidate.Locks.ToArray()) {
        if ([long]$lock.Stream.Length -ne [long]$lock.Size -or
            (Get-SteinSourceCommandStreamSha256 -Stream $lock.Stream) -cne
                [string]$lock.Sha256) {
            throw 'source_command_candidate_changed'
        }
    }
    try {
        $inventory = Get-SteinSourceCommandCandidateInventory `
            -GitExecutable $GitExecutable `
            -ExpectedCommit ([string]$Candidate.Commit) `
            -ExpectedTree ([string]$Candidate.Tree)
    }
    catch {
        throw 'source_command_candidate_changed'
    }
    if ([long]$inventory.FileCount -ne [long]$Candidate.FileCount -or
        [string]$inventory.ManifestSha256 -cne
            [string]$Candidate.ManifestSha256) {
        throw 'source_command_candidate_changed'
    }
    return $true
}

function Resolve-SteinSourceCommandEvidenceRoot {
    param([Parameter(Mandatory = $true)][string] $Path)

    $allowedRoot = [IO.Path]::GetFullPath((Join-Path `
            $script:SourceCommandRepositoryRoot 'artifacts\evidence\phase-2')).TrimEnd(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar)
    $candidate = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    }
    else {
        [IO.Path]::GetFullPath((Join-Path $script:SourceCommandRepositoryRoot $Path))
    }
    if (-not $candidate.StartsWith(
            "$allowedRoot$([IO.Path]::DirectorySeparatorChar)",
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'source_command_evidence_root_invalid'
    }
    $relative = $candidate.Substring($allowedRoot.Length + 1).Replace('\', '/')
    if (-not (Test-SteinSourceCommandSafeRelativePath -Value $relative) -or
        $relative -cnotmatch '^[A-Za-z0-9._/-]+$') {
        throw 'source_command_evidence_root_invalid'
    }
    $current = $script:SourceCommandRepositoryRoot
    foreach ($segment in @('artifacts', 'evidence', 'phase-2') + $relative.Split('/')) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            $null = New-Item -ItemType Directory -Path $current -ErrorAction Stop
        }
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'source_command_evidence_root_invalid'
        }
    }
    return [IO.Path]::GetFullPath($candidate)
}

function New-SteinSourceCommandDirectory {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $Leaf
    )

    if ($Leaf -cnotmatch '^[a-z][a-z0-9-]{2,63}$') {
        throw 'source_command_output_directory_invalid'
    }
    $path = Join-Path $Root $Leaf
    if (-not (Test-Path -LiteralPath $path)) {
        $null = New-Item -ItemType Directory -Path $path -ErrorAction Stop
    }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'source_command_output_directory_invalid'
    }
    return $item.FullName
}

function ConvertTo-SteinSourceCommandArgumentVector {
    param(
        [Parameter(Mandatory = $true)] $Check,
        [Parameter(Mandatory = $true)][string] $ResolvedEvidenceRoot
    )

    $arguments = New-Object Collections.Generic.List[string]
    foreach ($argument in @($Check.arguments)) {
        $kind = [string]$argument.kind
        $value = [string]$argument.value
        if ($kind -ceq 'literal' -or $kind -ceq 'repository_relative_path') {
            $arguments.Add($value)
            continue
        }
        if ($kind -ceq 'evidence_relative_path') {
            $full = [IO.Path]::GetFullPath((Join-Path $ResolvedEvidenceRoot (
                        $value.Replace('/', [IO.Path]::DirectorySeparatorChar))))
            $prefix = "$script:SourceCommandRepositoryRoot$([IO.Path]::DirectorySeparatorChar)"
            if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'source_command_evidence_argument_invalid'
            }
            $arguments.Add($full.Substring($prefix.Length).Replace('\', '/'))
            continue
        }
        throw 'source_command_argument_kind_invalid'
    }
    $result = $arguments.ToArray()
    foreach ($token in $result) {
        if ([string]::IsNullOrEmpty([string]$token) -or
            [string]$token -cnotmatch '^[A-Za-z0-9._,=!:/-]+$') {
            throw 'source_command_launch_token_invalid'
        }
    }
    return $result
}

function Get-SteinSourceCommandArgumentDigest {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)

    $records = New-Object Collections.Generic.List[string]
    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        $value = [string]$Arguments[$index]
        $length = [Text.UTF8Encoding]::new($false).GetByteCount($value)
        $records.Add("$index|$length`:$value")
    }
    return Get-SteinSourceCommandTextSha256 -Value ($records.ToArray() -join "`n")
}

function Set-SteinSourceCommandEnvironmentProfile {
    param([Parameter(Mandatory = $true)][string] $Profile)

    $values = [ordered]@{
        STEIN_CORE_EXECUTABLE_SHA256 = '1111111111111111111111111111111111111111111111111111111111111111'
        STEIN_PRODUCTION_PACKAGE_FAMILY_NAME = 'STEIN.PersonalIntelligence_123456789abcd'
        STEIN_PRODUCTION_BROKER_AUMID = 'STEIN.PersonalIntelligence_123456789abcd!PrivateBroker'
        STEIN_EDGE_EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop'
        STEIN_EDGE_EXTENSION_VERSION = '0.1.0'
        STEIN_EDGE_PUBLISHER_SHA256 = '2222222222222222222222222222222222222222222222222222222222222222'
        STEIN_EDGE_HOST_PUBLISHER_SHA256 = '3333333333333333333333333333333333333333333333333333333333333333'
    }
    if ($Profile -cnotin @(
            'phase2_synthetic_compile_v1', 'phase2_source_fixture_v1')) {
        throw 'source_command_environment_profile_invalid'
    }
    $original = @{}
    foreach ($name in $values.Keys) {
        $original[$name] = [Environment]::GetEnvironmentVariable(
            $name, [EnvironmentVariableTarget]::Process)
        [Environment]::SetEnvironmentVariable(
            $name, [string]$values[$name], [EnvironmentVariableTarget]::Process)
    }
    return [pscustomobject]@{
        Original = $original
        Digest = Get-SteinSourceCommandObjectSha256 -Value ([ordered]@{
                profile = $Profile
                values = $values
            })
    }
}

function Restore-SteinSourceCommandEnvironmentProfile {
    param([Parameter(Mandatory = $true)] $Original)

    foreach ($name in @($Original.Keys)) {
        [Environment]::SetEnvironmentVariable(
            [string]$name,
            $Original[$name],
            [EnvironmentVariableTarget]::Process)
    }
}

function Stop-SteinSourceCommandProcessTree {
    param([Parameter(Mandatory = $true)][int] $ProcessId)

    try {
        $children = @(Get-CimInstance -ClassName Win32_Process `
                -Filter ("ParentProcessId = {0}" -f $ProcessId) `
                -ErrorAction SilentlyContinue)
        foreach ($child in $children) {
            Stop-SteinSourceCommandProcessTree -ProcessId ([int]$child.ProcessId)
        }
    }
    catch { }
    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

function New-SteinSourceCommandEmptyFile {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (Test-Path -LiteralPath $Path) {
        return
    }
    $stream = [IO.FileStream]::new(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    $stream.Dispose()
}

function Reset-SteinSourceCommandOversizedLog {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][long] $MaximumBytes
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'source_command_log_invalid'
    }
    if ([long]$item.Length -le $MaximumBytes) {
        return $false
    }
    $message = "source_command_log_limit_exceeded:$MaximumBytes`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($message)
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Create,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    return $true
}

function Get-SteinSourceCommandLogRecord {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $RelativePath
    )

    $lock = Open-SteinSourceCommandFileLock `
        -Path $Path `
        -MinimumBytes 0 `
        -MaximumBytes $script:SourceCommandMaximumLogBytes
    try {
        return [ordered]@{
            path = $RelativePath
            size = [long]$lock.Size
            sha256 = [string]$lock.Sha256
        }
    }
    finally {
        $lock.Stream.Dispose()
    }
}

function Invoke-SteinSourceCommandProcess {
    param(
        [Parameter(Mandatory = $true)] $Executable,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory,
        [Parameter(Mandatory = $true)][long] $TimeoutSeconds,
        [Parameter(Mandatory = $true)][string] $LogLeaf,
        [Parameter(Mandatory = $true)][string] $LogDirectory,
        [Parameter(Mandatory = $true)][string] $CancellationPath
    )

    $stdoutPath = Join-Path $LogDirectory "$LogLeaf.stdout.txt"
    $stderrPath = Join-Path $LogDirectory "$LogLeaf.stderr.txt"
    if ((Test-Path -LiteralPath $stdoutPath) -or
        (Test-Path -LiteralPath $stderrPath)) {
        throw 'source_command_log_already_exists'
    }
    $started = (Get-Date).ToUniversalTime()
    $exitCode = -1
    $failureCode = $null
    $process = $null
    try {
        $process = Start-Process `
            -FilePath ([string]$Executable.Path) `
            -ArgumentList $Arguments `
            -WorkingDirectory $WorkingDirectory `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath
        $null = $process.Handle
        while (-not $process.WaitForExit(250)) {
            if ((Get-Date).ToUniversalTime() -ge $started.AddSeconds($TimeoutSeconds)) {
                $failureCode = 'timeout'
                break
            }
            if (Test-Path -LiteralPath $CancellationPath -PathType Leaf) {
                $failureCode = 'cancelled'
                break
            }
            foreach ($path in @($stdoutPath, $stderrPath)) {
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    if ($item.Length -gt $script:SourceCommandMaximumLogBytes) {
                        $failureCode = 'log_limit_exceeded'
                        break
                    }
                }
            }
            if ($null -ne $failureCode) {
                break
            }
        }
        if ($null -ne $failureCode -and -not $process.HasExited) {
            Stop-SteinSourceCommandProcessTree -ProcessId ([int]$process.Id)
            $null = $process.WaitForExit(30000)
        }
        if ($process.HasExited) {
            $exitCode = [int]$process.ExitCode
        }
    }
    catch [Management.Automation.PipelineStoppedException] {
        $failureCode = 'cancelled'
        throw
    }
    catch {
        $failureCode = 'launch_failed'
    }
    finally {
        if ($null -ne $process) {
            if (-not $process.HasExited) {
                Stop-SteinSourceCommandProcessTree -ProcessId ([int]$process.Id)
                $null = $process.WaitForExit(30000)
            }
            $process.Dispose()
        }
    }
    New-SteinSourceCommandEmptyFile -Path $stdoutPath
    New-SteinSourceCommandEmptyFile -Path $stderrPath
    $logLimitExceeded = $false
    foreach ($path in @($stdoutPath, $stderrPath)) {
        if (Reset-SteinSourceCommandOversizedLog `
                -Path $path `
                -MaximumBytes $script:SourceCommandMaximumLogBytes) {
            $logLimitExceeded = $true
        }
    }
    if ($logLimitExceeded) {
        $failureCode = 'log_limit_exceeded'
    }
    $completed = (Get-Date).ToUniversalTime()
    if ($null -eq $failureCode -and $exitCode -ne 0) {
        $failureCode = 'nonzero_exit'
    }
    return [pscustomobject]@{
        Status = if ($null -eq $failureCode -and $exitCode -eq 0) {
            'pass'
        }
        else {
            'fail'
        }
        StartedAt = $started
        CompletedAt = $completed
        ExitCode = $exitCode
        FailureCode = $failureCode
        Stdout = Get-SteinSourceCommandLogRecord `
            -Path $stdoutPath `
            -RelativePath "source-command-logs/$LogLeaf.stdout.txt"
        Stderr = Get-SteinSourceCommandLogRecord `
            -Path $stderrPath `
            -RelativePath "source-command-logs/$LogLeaf.stderr.txt"
    }
}

function Read-SteinSourceCommandGroupArtifacts {
    param(
        [Parameter(Mandatory = $true)][string] $EvidencePath,
        [Parameter(Mandatory = $true)][string[]] $GroupedIds,
        [Parameter(Mandatory = $true)][string] $ExpectedCommit,
        [Parameter(Mandatory = $true)][string] $ExpectedTree,
        [Parameter(Mandatory = $true)][string] $ExpectedFixtureRegistrySha256
    )

    $fixtureRoot = Join-Path $EvidencePath 'source-fixtures'
    $indexPath = Join-Path $fixtureRoot 'index.json'
    $indexRead = Read-SteinSourceCommandLockedJson `
        -Path $indexPath `
        -MaximumBytes 1048576
    $locks = New-Object Collections.Generic.List[object]
    $locks.Add($indexRead.Lock)
    try {
        $index = $indexRead.Value
        Assert-SteinSourceCommandExactProperties -Value $index `
            -Expected @(
                'schema_version', 'suite_id', 'result', 'candidate_git_commit',
                'candidate_git_tree', 'registry_sha256', 'git', 'rustup', 'receipts') `
            -FailureCode 'source_command_group_output_invalid'
        if (($index.schema_version -isnot [int] -and
                $index.schema_version -isnot [long]) -or
            [long]$index.schema_version -ne 1 -or
            [string]$index.suite_id -cne 'stein.phase2.source-fixture-suite.v1' -or
            [string]$index.result -cne 'pass' -or
            [string]$index.candidate_git_commit -cne $ExpectedCommit -or
            [string]$index.candidate_git_tree -cne $ExpectedTree -or
            [string]$index.registry_sha256 -cne $ExpectedFixtureRegistrySha256) {
            throw 'source_command_group_output_invalid'
        }
        $descriptors = @($index.receipts)
        if ($descriptors.Count -ne $GroupedIds.Count) {
            throw 'source_command_group_output_invalid'
        }
        $artifacts = @{}
        for ($position = 0; $position -lt $GroupedIds.Count; $position++) {
            $id = [string]$GroupedIds[$position]
            $descriptor = $descriptors[$position]
            Assert-SteinSourceCommandExactProperties -Value $descriptor `
                -Expected @(
                    'source_check_id', 'source_fixture_id', 'source_runner_id',
                    'gate_id', 'gate_fixture_id', 'gate_runner_id', 'path',
                    'size', 'sha256') `
                -FailureCode 'source_command_group_output_invalid'
            $expectedLeaf = "$id.receipt.json"
            if ([string]$descriptor.source_check_id -cne $id -or
                [string]$descriptor.path -cne $expectedLeaf -or
                ($descriptor.size -isnot [int] -and
                    $descriptor.size -isnot [long]) -or
                [long]$descriptor.size -lt 1 -or
                [long]$descriptor.size -gt 4194304 -or
                [string]$descriptor.sha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw 'source_command_group_output_invalid'
            }
            $receiptPath = Resolve-SteinSourceCommandPathUnderRoot `
                -Root $fixtureRoot `
                -RelativePath $expectedLeaf `
                -Kind Leaf
            $receiptLock = Open-SteinSourceCommandFileLock `
                -Path $receiptPath `
                -MaximumBytes 4194304
            $locks.Add($receiptLock)
            if ([long]$receiptLock.Size -ne [long]$descriptor.size -or
                [string]$receiptLock.Sha256 -cne [string]$descriptor.sha256) {
                throw 'source_command_group_output_invalid'
            }
            $artifacts[$id] = @(
                [ordered]@{
                    role = 'source_fixture_suite_index'
                    size = [long]$indexRead.Lock.Size
                    sha256 = [string]$indexRead.Lock.Sha256
                },
                [ordered]@{
                    role = 'source_fixture_receipt'
                    size = [long]$receiptLock.Size
                    sha256 = [string]$receiptLock.Sha256
                })
        }
        $actual = @(Get-ChildItem -LiteralPath $fixtureRoot -Force -ErrorAction Stop)
        if ($actual.Count -ne ($GroupedIds.Count + 1) -or
            @($actual | Where-Object {
                    $_.PSIsContainer -or
                    (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
                }).Count -ne 0) {
            throw 'source_command_group_output_invalid'
        }
        return [pscustomobject]@{ Artifacts = $artifacts; Locks = $locks }
    }
    catch {
        foreach ($lock in $locks) {
            $lock.Stream.Dispose()
        }
        throw
    }
}

function Write-SteinSourceCommandJsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $Value
    )

    if (Test-Path -LiteralPath $Path) {
        throw 'source_command_receipt_already_exists'
    }
    $json = ($Value | ConvertTo-Json -Depth 16) + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $stream = [IO.FileStream]::new(
        $temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    [IO.File]::Move($temporary, $Path)
}

function New-SteinSourceCommandReceipt {
    param(
        [Parameter(Mandatory = $true)] $Check,
        [Parameter(Mandatory = $true)][string] $Status,
        [Parameter(Mandatory = $true)] $Bindings,
        $Command,
        $Execution,
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)][object[]] $Artifacts,
        [AllowNull()] $ObligationCode,
        [AllowNull()] $Derivation
    )

    return [ordered]@{
        schema_version = 1
        claim = 'closed_source_command_execution_only'
        check_id = [string]$Check.id
        category = [string]$Check.category
        status = $Status
        bindings = $Bindings
        command = $Command
        execution = $Execution
        artifacts = @($Artifacts)
        obligation_code = $ObligationCode
        derivation = $Derivation
    }
}

function Get-SteinSourceCommandReceiptCoverage {
    param(
        [Parameter(Mandatory = $true)] $Registry,
        [Parameter(Mandatory = $true)][string] $ReceiptDirectory,
        [Parameter(Mandatory = $true)] $Bindings
    )

    $expected = @($Registry.checks | Where-Object {
            [string]$_.category -cin @(
                'direct_execution', 'grouped_fixture_execution')
        })
    $actual = @(Get-ChildItem -LiteralPath $ReceiptDirectory -Filter '*.receipt.json' `
            -File -Force -ErrorAction Stop)
    if ($actual.Count -ne $expected.Count) {
        throw 'source_command_receipt_coverage_invalid'
    }
    $evidencePath = Split-Path -Parent $ReceiptDirectory
    $descriptors = New-Object Collections.Generic.List[object]
    $executionGroups = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $executionIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $groupedExecutionId = $null
    foreach ($check in $expected) {
        $path = Join-Path $ReceiptDirectory "$([string]$check.id).receipt.json"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'source_command_receipt_coverage_invalid'
        }
        $read = $null
        try {
            $read = Read-SteinSourceCommandLockedJson -Path $path -MaximumBytes 1048576
            $receipt = $read.Value
            Assert-SteinSourceCommandExactProperties -Value $receipt `
                -Expected @(
                    'schema_version', 'claim', 'check_id', 'category', 'status',
                    'bindings', 'command', 'execution', 'artifacts',
                    'obligation_code', 'derivation') `
                -FailureCode 'source_command_receipt_coverage_invalid'
            Assert-SteinSourceCommandExactProperties -Value $receipt.bindings `
                -Expected @(
                    'candidate_commit', 'candidate_tree', 'candidate_file_count',
                    'candidate_manifest_sha256', 'git_launcher_sha256',
                    'git_resolved_sha256', 'registry_sha256', 'runner_sha256',
                    'evidence_root_sha256', 'check_definition_sha256',
                    'execution_group_count') `
                -FailureCode 'source_command_receipt_coverage_invalid'
            Assert-SteinSourceCommandExactProperties -Value $receipt.command `
                -Expected @(
                    'executable_role', 'executable_name', 'executable_size',
                    'executable_sha256', 'arguments', 'arguments_sha256',
                    'working_directory', 'environment_profile',
                    'environment_profile_sha256', 'timeout_seconds') `
                -FailureCode 'source_command_receipt_coverage_invalid'
            Assert-SteinSourceCommandExactProperties -Value $receipt.execution `
                -Expected @(
                    'execution_group_id', 'execution_id', 'started_at',
                    'completed_at', 'duration_ms', 'exit_code', 'failure_code',
                    'stdout', 'stderr') `
                -FailureCode 'source_command_receipt_coverage_invalid'
            foreach ($streamName in @('stdout', 'stderr')) {
                Assert-SteinSourceCommandExactProperties `
                    -Value $receipt.execution.$streamName `
                    -Expected @('path', 'size', 'sha256') `
                    -FailureCode 'source_command_receipt_coverage_invalid'
            }
            $expectedArguments = ConvertTo-SteinSourceCommandArgumentVector `
                -Check $check `
                -ResolvedEvidenceRoot $evidencePath
            $actualArguments = @($receipt.command.arguments | ForEach-Object {
                    [string]$_
                })
            if ($actualArguments.Count -ne $expectedArguments.Count) {
                throw 'source_command_receipt_coverage_invalid'
            }
            for ($argumentIndex = 0;
                    $argumentIndex -lt $expectedArguments.Count;
                    $argumentIndex++) {
                if ([string]$actualArguments[$argumentIndex] -cne
                    [string]$expectedArguments[$argumentIndex]) {
                    throw 'source_command_receipt_coverage_invalid'
                }
            }
            $expectedGroupId = if ([string]$check.category -ceq
                    'grouped_fixture_execution') {
                'closed-source-fixture-suite'
            }
            else {
                "direct:$([string]$check.id)"
            }
            $expectedLogLeaf = if ([string]$check.category -ceq
                    'grouped_fixture_execution') {
                'closed-source-fixture-suite'
            }
            else {
                [string]$check.id
            }
            if ([long]$receipt.schema_version -ne 1 -or
                [string]$receipt.claim -cne 'closed_source_command_execution_only' -or
                [string]$receipt.check_id -cne [string]$check.id -or
                [string]$receipt.category -cne [string]$check.category -or
                [string]$receipt.bindings.candidate_commit -cne
                    [string]$Bindings.candidate_commit -or
                [string]$receipt.bindings.candidate_tree -cne
                    [string]$Bindings.candidate_tree -or
                [long]$receipt.bindings.candidate_file_count -ne
                    [long]$Bindings.candidate_file_count -or
                [string]$receipt.bindings.candidate_manifest_sha256 -cne
                    [string]$Bindings.candidate_manifest_sha256 -or
                [string]$receipt.bindings.git_launcher_sha256 -cne
                    [string]$Bindings.git_launcher_sha256 -or
                [string]$receipt.bindings.git_resolved_sha256 -cne
                    [string]$Bindings.git_resolved_sha256 -or
                [string]$receipt.bindings.registry_sha256 -cne
                    [string]$Bindings.registry_sha256 -or
                [string]$receipt.bindings.runner_sha256 -cne
                    [string]$Bindings.runner_sha256 -or
                [string]$receipt.bindings.evidence_root_sha256 -cne
                    [string]$Bindings.evidence_root_sha256 -or
                [string]$receipt.bindings.check_definition_sha256 -cne
                    (Get-SteinSourceCommandObjectSha256 -Value $check) -or
                [long]$receipt.bindings.execution_group_count -ne 25 -or
                [string]$receipt.command.executable_role -cne
                    [string]$check.executable_role -or
                [string]$receipt.command.arguments_sha256 -cne
                    (Get-SteinSourceCommandArgumentDigest `
                        -Arguments $expectedArguments) -or
                [string]$receipt.command.working_directory -cne
                    [string]$check.working_directory -or
                [string]$receipt.command.environment_profile -cne
                    [string]$check.environment_profile -or
                [long]$receipt.command.timeout_seconds -ne
                    [long]$check.timeout_seconds -or
                [string]$receipt.command.executable_sha256 -cnotmatch
                    '^[0-9a-f]{64}$' -or
                [string]$receipt.command.environment_profile_sha256 -cnotmatch
                    '^[0-9a-f]{64}$' -or
                [string]$receipt.execution.execution_group_id -cne
                    $expectedGroupId -or
                [string]$receipt.execution.execution_id -cnotmatch
                    '^[0-9a-f]{64}$' -or
                [string]$receipt.execution.stdout.path -cne
                    "source-command-logs/$expectedLogLeaf.stdout.txt" -or
                [string]$receipt.execution.stderr.path -cne
                    "source-command-logs/$expectedLogLeaf.stderr.txt" -or
                $null -ne $receipt.obligation_code -or
                $null -ne $receipt.derivation) {
                throw 'source_command_receipt_coverage_invalid'
            }
            if ([string]$receipt.status -cnotin @('pass', 'fail')) {
                throw 'source_command_receipt_coverage_invalid'
            }
            foreach ($streamName in @('stdout', 'stderr')) {
                $streamDescriptor = $receipt.execution.$streamName
                if (($streamDescriptor.size -isnot [int] -and
                        $streamDescriptor.size -isnot [long]) -or
                    [long]$streamDescriptor.size -lt 0 -or
                    [long]$streamDescriptor.size -gt
                        $script:SourceCommandMaximumLogBytes -or
                    [string]$streamDescriptor.sha256 -cnotmatch
                        '^[0-9a-f]{64}$') {
                    throw 'source_command_receipt_coverage_invalid'
                }
                $logPath = Resolve-SteinSourceCommandPathUnderRoot `
                    -Root $evidencePath `
                    -RelativePath ([string]$streamDescriptor.path) `
                    -Kind Leaf
                $logLock = Open-SteinSourceCommandFileLock `
                    -Path $logPath `
                    -MinimumBytes 0 `
                    -MaximumBytes $script:SourceCommandMaximumLogBytes
                try {
                    if ([long]$logLock.Size -ne [long]$streamDescriptor.size -or
                        [string]$logLock.Sha256 -cne
                            [string]$streamDescriptor.sha256) {
                        throw 'source_command_receipt_coverage_invalid'
                    }
                }
                finally {
                    $logLock.Stream.Dispose()
                }
            }
            $executionMaterial = [ordered]@{
                execution_group_id = $expectedGroupId
                executable_role = [string]$receipt.command.executable_role
                executable_sha256 = [string]$receipt.command.executable_sha256
                arguments_sha256 = [string]$receipt.command.arguments_sha256
                working_directory = [string]$receipt.command.working_directory
                environment_profile_sha256 =
                    [string]$receipt.command.environment_profile_sha256
                started_at = [string]$receipt.execution.started_at
                completed_at = [string]$receipt.execution.completed_at
                exit_code = [long]$receipt.execution.exit_code
                failure_code = $receipt.execution.failure_code
                stdout = $receipt.execution.stdout
                stderr = $receipt.execution.stderr
            }
            if ([string]$receipt.execution.execution_id -cne
                (Get-SteinSourceCommandObjectSha256 -Value $executionMaterial)) {
                throw 'source_command_receipt_coverage_invalid'
            }
            $null = $executionGroups.Add($expectedGroupId)
            if ([string]$check.category -ceq 'grouped_fixture_execution') {
                if ($null -eq $groupedExecutionId) {
                    $groupedExecutionId = [string]$receipt.execution.execution_id
                }
                elseif ([string]$receipt.execution.execution_id -cne
                    $groupedExecutionId) {
                    throw 'source_command_receipt_coverage_invalid'
                }
            }
            elseif (-not $executionIds.Add(
                    [string]$receipt.execution.execution_id)) {
                throw 'source_command_receipt_coverage_invalid'
            }
            $descriptors.Add([ordered]@{
                    check_id = [string]$check.id
                    category = [string]$check.category
                    path = "$([string]$check.id).receipt.json"
                    size = [long]$read.Lock.Size
                    sha256 = [string]$read.Lock.Sha256
                })
        }
        catch {
            throw 'source_command_receipt_coverage_invalid'
        }
        finally {
            if ($null -ne $read) {
                $read.Lock.Stream.Dispose()
            }
        }
    }
    if ($executionGroups.Count -ne 25 -or $null -eq $groupedExecutionId) {
        throw 'source_command_receipt_coverage_invalid'
    }
    return [pscustomobject]@{
        ExecutedCheckCount = $expected.Count
        Receipts = $descriptors.ToArray()
    }
}

function Initialize-SteinSourceCommandSecurityModule {
    if ($PSVersionTable.PSEdition -cne 'Desktop' -or
        -not [Environment]::Is64BitProcess) {
        throw 'source_command_windows_powershell_host_invalid'
    }

    $expectedDesktopHome = [IO.Path]::GetFullPath((Join-Path (
                [Environment]::GetFolderPath(
                    [Environment+SpecialFolder]::System)) `
            'WindowsPowerShell\v1.0')).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $desktopHome = [IO.Path]::GetFullPath([string]$PSHOME).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    if (-not [string]::Equals(
            $desktopHome,
            $expectedDesktopHome,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'source_command_windows_powershell_host_invalid'
    }

    $desktopModuleRoot = [IO.Path]::GetFullPath((
            Join-Path $desktopHome 'Modules'))
    $desktopSecurityModuleRoot = [IO.Path]::GetFullPath((
            Join-Path $desktopModuleRoot 'Microsoft.PowerShell.Security'))
    $desktopSecurityModuleManifest = [IO.Path]::GetFullPath((
            Join-Path $desktopModuleRoot `
                'Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'))
    foreach ($binding in @(
            [pscustomobject]@{ Path = $desktopHome; Container = $true },
            [pscustomobject]@{ Path = $desktopModuleRoot; Container = $true },
            [pscustomobject]@{
                Path = $desktopSecurityModuleRoot
                Container = $true
            },
            [pscustomobject]@{
                Path = $desktopSecurityModuleManifest
                Container = $false
            })) {
        $item = Get-Item -LiteralPath ([string]$binding.Path) `
            -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ([bool]$binding.Container -and -not $item.PSIsContainer) -or
            (-not [bool]$binding.Container -and $item.PSIsContainer) -or
            (-not [bool]$binding.Container -and $item.Length -lt 1) -or
            -not [string]::Equals(
                $item.FullName,
                [string]$binding.Path,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'source_command_security_module_path_unsafe'
        }
    }

    foreach ($loadedModule in @(Get-Module `
                -Name 'Microsoft.PowerShell.Security' -ErrorAction Stop)) {
        if (-not [string]::Equals(
                [string]$loadedModule.Path,
                $desktopSecurityModuleManifest,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'source_command_security_module_binding_invalid'
        }
    }

    $env:PSModulePath = $desktopModuleRoot
    Import-Module -Name $desktopSecurityModuleManifest `
        -Force -ErrorAction Stop
    $boundModules = @(Get-Module `
            -Name 'Microsoft.PowerShell.Security' -ErrorAction Stop)
    $signatureCommands = @(Get-Command `
            -Name 'Get-AuthenticodeSignature' `
            -All `
            -ErrorAction Stop)
    if ($boundModules.Count -ne 1 -or
        $signatureCommands.Count -ne 1 -or
        -not [string]::Equals(
            [string]$boundModules[0].Path,
            $desktopSecurityModuleManifest,
            [StringComparison]::OrdinalIgnoreCase) -or
        [string]$signatureCommands[0].ModuleName -cne
            'Microsoft.PowerShell.Security' -or
        [string]$signatureCommands[0].CommandType -cne 'Cmdlet' -or
        $null -eq $signatureCommands[0].Module -or
        -not [string]::Equals(
            [string]$signatureCommands[0].Module.Path,
            $desktopSecurityModuleManifest,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'source_command_security_module_binding_invalid'
    }
}

if ($LibraryOnly) {
    return
}
Initialize-SteinSourceCommandSecurityModule
if ($CheckId -cnotmatch '^[a-z0-9][a-z0-9._-]{2,95}$' -or
    $CandidateCommit -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
    $CandidateTree -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
    $CandidateCommit.Length -ne $CandidateTree.Length -or
    $ExpectedRegistrySha256 -cnotmatch '^[0-9a-f]{64}$' -or
    -not [IO.Path]::IsPathRooted($ExpectedGitLauncherPath) -or
    $ExpectedGitLauncherSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $ExpectedGitResolvedSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    throw 'source_command_cli_binding_invalid'
}

$registryRead = $null
$runnerLock = $null
$gitBinding = $null
$gitTool = $null
$commandTool = $null
$candidate = $null
$groupArtifacts = $null
$environment = $null
$scriptExitCode = 1
try {
    $registryRead = Read-SteinSourceCommandLockedJson `
        -Path $script:SourceCommandRegistryPath `
        -MaximumBytes 1048576
    if ([string]$registryRead.Lock.Sha256 -cne $ExpectedRegistrySha256) {
        throw 'source_command_registry_digest_mismatch'
    }
    $contract = Assert-SteinSourceCommandRegistry -Registry $registryRead.Value
    $checks = @($registryRead.Value.checks | Where-Object {
            [string]$_.id -ceq $CheckId
        })
    if ($checks.Count -ne 1) {
        throw 'source_command_check_unknown'
    }
    $check = $checks[0]
    if ([string]$check.category -ceq 'retained_obligation' -or
        [string]$check.id -ceq 'source-provenance-stability') {
        throw 'source_command_check_not_executable'
    }

    $runnerLock = Open-SteinSourceCommandFileLock `
        -Path $PSCommandPath `
        -MaximumBytes 4194304
    $gitBinding = Open-SteinSourceCommandGitBinding `
        -LauncherPath $ExpectedGitLauncherPath `
        -ExpectedLauncherSha256 $ExpectedGitLauncherSha256 `
        -ExpectedResolvedSha256 $ExpectedGitResolvedSha256
    $gitTool = $gitBinding.Resolved
    $candidate = Open-SteinSourceCommandCandidate `
        -GitExecutable $gitTool.Path `
        -ExpectedCommit $CandidateCommit `
        -ExpectedTree $CandidateTree
    $evidencePath = Resolve-SteinSourceCommandEvidenceRoot -Path $EvidenceRoot
    $receiptDirectory = New-SteinSourceCommandDirectory `
        -Root $evidencePath `
        -Leaf 'source-command-receipts'
    $logDirectory = New-SteinSourceCommandDirectory `
        -Root $evidencePath `
        -Leaf 'source-command-logs'
    $evidenceRelative = $evidencePath.Substring(
        $script:SourceCommandRepositoryRoot.Length + 1).Replace('\', '/')
    $baseBindings = [ordered]@{
        candidate_commit = [string]$candidate.Commit
        candidate_tree = [string]$candidate.Tree
        candidate_file_count = [long]$candidate.FileCount
        candidate_manifest_sha256 = [string]$candidate.ManifestSha256
        git_launcher_sha256 = [string]$gitBinding.Launcher.Sha256
        git_resolved_sha256 = [string]$gitBinding.Resolved.Sha256
        registry_sha256 = [string]$registryRead.Lock.Sha256
        runner_sha256 = [string]$runnerLock.Sha256
        evidence_root_sha256 = Get-SteinSourceCommandTextSha256 `
            -Value $evidenceRelative
        check_definition_sha256 = Get-SteinSourceCommandObjectSha256 -Value $check
        execution_group_count = [long]$contract.ExecutionGroupCount
    }

    if ([string]$check.category -ceq 'retained_obligation') {
        $null = Assert-SteinSourceCommandCandidateStable `
            -Candidate $candidate `
            -GitExecutable $gitTool.Path
        $scriptExitCode = 2
    }
    elseif ([string]$check.category -ceq 'derived') {
        if ([string]$check.derivation -ceq 'exact_registry_and_receipt_coverage') {
            $coverage = Get-SteinSourceCommandReceiptCoverage `
                -Registry $registryRead.Value `
                -ReceiptDirectory $receiptDirectory `
                -Bindings $baseBindings
            $indexBindings = [ordered]@{
                candidate_commit = [string]$baseBindings.candidate_commit
                candidate_tree = [string]$baseBindings.candidate_tree
                candidate_file_count = [long]$baseBindings.candidate_file_count
                candidate_manifest_sha256 =
                    [string]$baseBindings.candidate_manifest_sha256
                git_launcher_sha256 =
                    [string]$baseBindings.git_launcher_sha256
                git_resolved_sha256 =
                    [string]$baseBindings.git_resolved_sha256
                registry_sha256 = [string]$baseBindings.registry_sha256
                runner_sha256 = [string]$baseBindings.runner_sha256
                evidence_root_sha256 =
                    [string]$baseBindings.evidence_root_sha256
            }
            $index = [ordered]@{
                schema_version = 1
                claim = 'closed_source_command_receipt_index'
                registry_id = [string]$registryRead.Value.registry_id
                bindings = $indexBindings
                executed_check_count = [long]$coverage.ExecutedCheckCount
                execution_group_count = [long]$contract.ExecutionGroupCount
                receipts = @($coverage.Receipts)
            }
            Write-SteinSourceCommandJsonAtomic `
                -Path (Join-Path $receiptDirectory 'index.json') `
                -Value $index
        }
        $null = Assert-SteinSourceCommandCandidateStable `
            -Candidate $candidate `
            -GitExecutable $gitTool.Path
        $scriptExitCode = 0
    }
    else {
        $commandTool = Resolve-SteinSourceCommandExecutable `
            -Role ([string]$check.executable_role)
        $arguments = ConvertTo-SteinSourceCommandArgumentVector `
            -Check $check `
            -ResolvedEvidenceRoot $evidencePath
        $workingDirectory = Resolve-SteinSourceCommandPathUnderRoot `
            -Root $script:SourceCommandRepositoryRoot `
            -RelativePath ([string]$check.working_directory) `
            -Kind Container
        if ([string]$check.category -ceq 'grouped_fixture_execution' -and
            (Test-Path -LiteralPath (Join-Path $evidencePath 'source-fixtures'))) {
            throw 'source_command_group_output_already_exists'
        }
        $environment = Set-SteinSourceCommandEnvironmentProfile `
            -Profile ([string]$check.environment_profile)
        $environmentDigest = [string]$environment.Digest
        try {
            $logLeaf = if ([string]$check.category -ceq
                    'grouped_fixture_execution') {
                'closed-source-fixture-suite'
            }
            else {
                [string]$check.id
            }
            $processResult = Invoke-SteinSourceCommandProcess `
                -Executable $commandTool `
                -Arguments $arguments `
                -WorkingDirectory $workingDirectory `
                -TimeoutSeconds ([long]$check.timeout_seconds) `
                -LogLeaf $logLeaf `
                -LogDirectory $logDirectory `
                -CancellationPath (Join-Path $evidencePath 'cancel.request')
        }
        finally {
            Restore-SteinSourceCommandEnvironmentProfile `
                -Original $environment.Original
            $environment = $null
        }
        try {
            $null = Assert-SteinSourceCommandCandidateStable `
                -Candidate $candidate `
                -GitExecutable $gitTool.Path
        }
        catch {
            $processResult.Status = 'fail'
            $processResult.FailureCode = 'candidate_changed'
        }
        $commandRecord = [ordered]@{
            executable_role = [string]$check.executable_role
            executable_name = [string]$commandTool.Name
            executable_size = [long]$commandTool.Size
            executable_sha256 = [string]$commandTool.Sha256
            arguments = @($arguments)
            arguments_sha256 = Get-SteinSourceCommandArgumentDigest `
                -Arguments $arguments
            working_directory = [string]$check.working_directory
            environment_profile = [string]$check.environment_profile
            environment_profile_sha256 = [string]$environmentDigest
            timeout_seconds = [long]$check.timeout_seconds
        }
        $executionGroupId = if ([string]$check.category -ceq
                'grouped_fixture_execution') {
            'closed-source-fixture-suite'
        }
        else {
            "direct:$([string]$check.id)"
        }
        $startedAtText = $processResult.StartedAt.ToString('o')
        $completedAtText = $processResult.CompletedAt.ToString('o')
        $executionIdMaterial = [ordered]@{
            execution_group_id = $executionGroupId
            executable_role = [string]$commandRecord.executable_role
            executable_sha256 = [string]$commandRecord.executable_sha256
            arguments_sha256 = [string]$commandRecord.arguments_sha256
            working_directory = [string]$commandRecord.working_directory
            environment_profile_sha256 =
                [string]$commandRecord.environment_profile_sha256
            started_at = $startedAtText
            completed_at = $completedAtText
            exit_code = [long]$processResult.ExitCode
            failure_code = $processResult.FailureCode
            stdout = $processResult.Stdout
            stderr = $processResult.Stderr
        }
        $executionRecord = [ordered]@{
            execution_group_id = $executionGroupId
            execution_id = Get-SteinSourceCommandObjectSha256 `
                -Value $executionIdMaterial
            started_at = $startedAtText
            completed_at = $completedAtText
            duration_ms = [long]($processResult.CompletedAt -
                $processResult.StartedAt).TotalMilliseconds
            exit_code = [long]$processResult.ExitCode
            failure_code = $processResult.FailureCode
            stdout = $processResult.Stdout
            stderr = $processResult.Stderr
        }

        if ([string]$check.category -ceq 'grouped_fixture_execution') {
            $artifactMap = @{}
            if ([string]$processResult.Status -ceq 'pass') {
                try {
                    $fixtureRegistryLock = @($candidate.Locks | Where-Object {
                            $_.Path.EndsWith(
                                'scripts\windows\phase2\Source-Fixture-Registry.json',
                                [StringComparison]::OrdinalIgnoreCase)
                        })
                    if ($fixtureRegistryLock.Count -ne 1) {
                        throw 'source_command_fixture_registry_binding_missing'
                    }
                    $groupArtifacts = Read-SteinSourceCommandGroupArtifacts `
                        -EvidencePath $evidencePath `
                        -GroupedIds @($contract.GroupedIds) `
                        -ExpectedCommit $CandidateCommit `
                        -ExpectedTree $CandidateTree `
                        -ExpectedFixtureRegistrySha256 `
                            ([string]$fixtureRegistryLock[0].Sha256)
                    $artifactMap = $groupArtifacts.Artifacts
                }
                catch {
                    $processResult.Status = 'fail'
                    $processResult.FailureCode = 'group_output_invalid'
                    $executionRecord.failure_code = 'group_output_invalid'
                    $executionIdMaterial.failure_code = 'group_output_invalid'
                    $executionRecord.execution_id =
                        Get-SteinSourceCommandObjectSha256 `
                            -Value $executionIdMaterial
                }
            }
            foreach ($groupId in @($contract.GroupedIds)) {
                $groupCheck = @($registryRead.Value.checks | Where-Object {
                        [string]$_.id -ceq [string]$groupId
                    })[0]
                $bindings = [ordered]@{}
                foreach ($property in $baseBindings.Keys) {
                    $bindings[$property] = $baseBindings[$property]
                }
                $bindings.check_definition_sha256 =
                    Get-SteinSourceCommandObjectSha256 -Value $groupCheck
                $artifacts = if ($artifactMap.ContainsKey([string]$groupId)) {
                    @($artifactMap[[string]$groupId])
                }
                else {
                    @()
                }
                $receipt = New-SteinSourceCommandReceipt `
                    -Check $groupCheck `
                    -Status ([string]$processResult.Status) `
                    -Bindings $bindings `
                    -Command $commandRecord `
                    -Execution $executionRecord `
                    -Artifacts $artifacts `
                    -ObligationCode $null `
                    -Derivation $null
                Write-SteinSourceCommandJsonAtomic `
                    -Path (Join-Path $receiptDirectory `
                        "$([string]$groupId).receipt.json") `
                    -Value $receipt
            }
        }
        else {
            $receipt = New-SteinSourceCommandReceipt `
                -Check $check `
                -Status ([string]$processResult.Status) `
                -Bindings $baseBindings `
                -Command $commandRecord `
                -Execution $executionRecord `
                -Artifacts @() `
                -ObligationCode $null `
                -Derivation $null
            Write-SteinSourceCommandJsonAtomic `
                -Path (Join-Path $receiptDirectory "$CheckId.receipt.json") `
                -Value $receipt
        }
        $scriptExitCode = if ([string]$processResult.Status -ceq 'pass') {
            0
        }
        else {
            1
        }
    }
}
finally {
    if ($null -ne $environment) {
        Restore-SteinSourceCommandEnvironmentProfile -Original $environment.Original
    }
    if ($null -ne $groupArtifacts) {
        foreach ($lock in $groupArtifacts.Locks.ToArray()) {
            $lock.Stream.Dispose()
        }
    }
    if ($null -ne $candidate) {
        foreach ($lock in $candidate.Locks.ToArray()) {
            $lock.Stream.Dispose()
        }
    }
    foreach ($tool in @($commandTool)) {
        if ($null -ne $tool) {
            $tool.Stream.Dispose()
        }
    }
    if ($null -ne $gitBinding) {
        foreach ($tool in @($gitBinding.Resolved, $gitBinding.Launcher)) {
            if ($null -ne $tool) {
                $tool.Stream.Dispose()
            }
        }
    }
    if ($null -ne $runnerLock) {
        $runnerLock.Stream.Dispose()
    }
    if ($null -ne $registryRead) {
        $registryRead.Lock.Stream.Dispose()
    }
}

exit $scriptExitCode
