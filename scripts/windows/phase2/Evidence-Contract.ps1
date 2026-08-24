Set-StrictMode -Version 3.0

function Assert-SteinPhase2EvidenceShape {
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

function Assert-SteinPhase2EvidenceExactSet {
    param(
        [AllowEmptyCollection()][object[]] $Actual,
        [AllowEmptyCollection()][object[]] $Expected,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    $actualValues = @($Actual | ForEach-Object { [string]$_ })
    $expectedValues = @($Expected | ForEach-Object { [string]$_ })
    if ($actualValues.Count -ne $expectedValues.Count -or
        @($actualValues | Select-Object -Unique).Count -ne $actualValues.Count) {
        throw $FailureCode
    }
    if ($actualValues.Count -eq 0) {
        return
    }
    if (@(Compare-Object `
            -ReferenceObject ($expectedValues | Sort-Object) `
            -DifferenceObject ($actualValues | Sort-Object) `
            -CaseSensitive).Count -ne 0) {
        throw $FailureCode
    }
}

function Assert-SteinPhase2EvidenceHash {
    param(
        [AllowNull()] $Value,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if ($Value -isnot [string] -or [string]$Value -cnotmatch '^[0-9a-f]{64}$') {
        throw $FailureCode
    }
}

function Get-SteinPhase2EvidenceTextSha256 {
    param([Parameter(Mandatory = $true)][string] $Value)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString(
            $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).
            Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Read-SteinPhase2SourceFixtureRegistry {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $ExpectedSha256
    )

    Assert-SteinPhase2EvidenceHash `
        -Value $ExpectedSha256 `
        -FailureCode 'source_fixture_registry_hash_invalid'
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0 -or $item.Length -gt 1MB) {
        throw 'source_fixture_registry_file_invalid'
    }
    $bytes = $null
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw 'source_fixture_registry_file_invalid' }
            $offset += $read
        }
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $actualSha256 = [BitConverter]::ToString(
                $sha256.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
        }
        finally { $sha256.Dispose() }
        if ($actualSha256 -cne $ExpectedSha256) {
            throw 'source_fixture_registry_hash_mismatch'
        }
        try {
            $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) |
                ConvertFrom-Json -ErrorAction Stop
        }
        catch { throw 'source_fixture_registry_json_invalid' }
    }
    finally {
        $stream.Dispose()
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    }
    return [pscustomobject]@{
        value = $json
        sha256 = $actualSha256
    }
}

function Get-SteinPhase2EvidenceObjectSha256 {
    param([Parameter(Mandatory = $true)] $Value)

    return Get-SteinPhase2EvidenceTextSha256 `
        -Value ($Value | ConvertTo-Json -Depth 40 -Compress)
}

function Test-SteinPhase2SourceCommandRelativePath {
    param(
        [AllowNull()] $Value,
        [switch] $AllowRepositoryRoot
    )

    if ($Value -is [string] -and $Value -ceq '.') {
        return [bool]$AllowRepositoryRoot
    }
    if ($Value -isnot [string] -or $Value.Length -lt 1 -or
        $Value.Length -gt 512 -or [IO.Path]::IsPathRooted($Value) -or
        $Value -match '^[A-Za-z]:' -or $Value.Contains('\\') -or
        $Value.StartsWith('/') -or $Value.EndsWith('/') -or
        $Value -cnotmatch '^[A-Za-z0-9._/-]+$') {
        return $false
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

function Get-SteinPhase2SourceCommandCatalog {
    $direct = @(
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
    $grouped = @(
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
    $retained = @(
        'no-leaks-producer-workflow', 'native-toolchain-provenance',
        'pinned-clean-build-environment', 'portable-runner-attestation',
        'windows-native-ignored-fixtures')
    $derived = @(
        'source-report-command-provenance', 'source-provenance-stability')
    $ordered = @(
        'rust-format', 'rust-check', 'rust-clippy', 'rust-tests',
        'desktop-typecheck', 'desktop-lint', 'desktop-tests', 'desktop-build',
        'edge-extension-tests', 'edge-host-format', 'edge-host-check',
        'edge-host-clippy', 'edge-host-tests', 'boundary-contract',
        'source-evidence-contract', 'installed-evidence-harness-static',
        'no-leaks-scanner-static', 'no-leaks-producer-workflow',
        'native-toolchain-provenance', 'pinned-clean-build-environment',
        'portable-runner-attestation', 'source-report-command-provenance') +
        $grouped + @(
        'installed-reviewer-windows-powershell-contract',
        'installed-reviewer-pwsh-contract', 'msix-static-contract',
        'release-workspace', 'release-production-core', 'release-edge-host',
        'release-tauri-no-bundle', 'windows-native-ignored-fixtures',
        'source-provenance-stability')
    return [pscustomobject]@{
        Direct = $direct
        Grouped = $grouped
        Retained = $retained
        Derived = $derived
        Ordered = $ordered
    }
}

function Assert-SteinPhase2SourceCommandRegistry {
    param([Parameter(Mandatory = $true)] $Registry)

    $failureCode = 'source_command_registry_invalid'
    $catalog = Get-SteinPhase2SourceCommandCatalog
    Assert-SteinPhase2EvidenceShape -Value $Registry `
        -ExpectedProperties @('schema_version', 'registry_id', 'checks') `
        -FailureCode $failureCode
    if (($Registry.schema_version -isnot [int] -and
            $Registry.schema_version -isnot [long]) -or
        [long]$Registry.schema_version -ne 1 -or
        [string]$Registry.registry_id -cne
            'stein.phase2.source-command-registry.v1' -or
        $catalog.Direct.Count -ne 24 -or $catalog.Grouped.Count -ne 13 -or
        $catalog.Derived.Count -ne 2 -or $catalog.Retained.Count -ne 5 -or
        $catalog.Ordered.Count -ne 44) {
        throw $failureCode
    }
    $checks = @($Registry.checks)
    if ($checks.Count -ne 44) {
        throw $failureCode
    }
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $executionGroups = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $groupMaterial = $null
    $reasonCodes = @{
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
    for ($index = 0; $index -lt $checks.Count; $index++) {
        $check = $checks[$index]
        $id = [string]$check.id
        if ($id -cne [string]$catalog.Ordered[$index] -or
            $id -cnotmatch '^[a-z0-9][a-z0-9._-]{2,95}$' -or
            -not $seen.Add($id)) {
            throw $failureCode
        }
        $category = if ($catalog.Direct -ccontains $id) {
            'direct_execution'
        }
        elseif ($catalog.Grouped -ccontains $id) {
            'grouped_fixture_execution'
        }
        elseif ($catalog.Derived -ccontains $id) {
            'derived'
        }
        elseif ($catalog.Retained -ccontains $id) {
            'retained_obligation'
        }
        else {
            throw $failureCode
        }
        if ([string]$check.category -cne $category) {
            throw $failureCode
        }
        if ($category -ceq 'retained_obligation') {
            Assert-SteinPhase2EvidenceShape -Value $check `
                -ExpectedProperties @('id', 'category', 'reason_code') `
                -FailureCode $failureCode
            if ([string]$check.reason_code -cne [string]$reasonCodes[$id]) {
                throw $failureCode
            }
            continue
        }
        if ($category -ceq 'derived') {
            Assert-SteinPhase2EvidenceShape -Value $check `
                -ExpectedProperties @('id', 'category', 'derivation') `
                -FailureCode $failureCode
            $expectedDerivation = if ($id -ceq
                    'source-report-command-provenance') {
                'exact_registry_and_receipt_coverage'
            }
            else {
                'candidate_and_registry_streams_stable'
            }
            if ([string]$check.derivation -cne $expectedDerivation) {
                throw $failureCode
            }
            continue
        }
        $properties = @(
            'id', 'category', 'executable_role', 'arguments',
            'working_directory', 'environment_profile', 'timeout_seconds')
        if ($category -ceq 'grouped_fixture_execution') {
            $properties = @(
                'id', 'category', 'group_id', 'executable_role', 'arguments',
                'working_directory', 'environment_profile', 'timeout_seconds',
                'fixture_receipt_path')
        }
        Assert-SteinPhase2EvidenceShape -Value $check `
            -ExpectedProperties $properties `
            -FailureCode $failureCode
        if ([string]$check.executable_role -cnotin @(
                'cargo', 'pnpm', 'windows_powershell', 'pwsh') -or
            -not (Test-SteinPhase2SourceCommandRelativePath `
                -Value $check.working_directory `
                -AllowRepositoryRoot) -or
            ($check.timeout_seconds -isnot [int] -and
                $check.timeout_seconds -isnot [long]) -or
            [long]$check.timeout_seconds -lt 30 -or
            [long]$check.timeout_seconds -gt 14400) {
            throw $failureCode
        }
        $expectedProfile = if ($category -ceq
                'grouped_fixture_execution') {
            'phase2_source_fixture_v1'
        }
        else {
            'phase2_synthetic_compile_v1'
        }
        if ([string]$check.environment_profile -cne $expectedProfile) {
            throw $failureCode
        }
        $arguments = @($check.arguments)
        if ($arguments.Count -lt 1 -or $arguments.Count -gt 24) {
            throw $failureCode
        }
        foreach ($argument in $arguments) {
            Assert-SteinPhase2EvidenceShape -Value $argument `
                -ExpectedProperties @('kind', 'value') `
                -FailureCode $failureCode
            $kind = [string]$argument.kind
            $value = [string]$argument.value
            if ($kind -cnotin @(
                    'literal', 'repository_relative_path',
                    'evidence_relative_path') -or
                [string]::IsNullOrEmpty($value) -or $value.Length -gt 512 -or
                $value -cnotmatch '^[A-Za-z0-9._,=!:/-]+$' -or
                $value -match '[\x00-\x1f&|;<>`"]' -or
                [IO.Path]::IsPathRooted($value) -or $value -match '^[A-Za-z]:') {
                throw $failureCode
            }
            if ($kind -ceq 'literal' -and
                $value -cin @('-Command', '-EncodedCommand', '/c', '/k')) {
                throw $failureCode
            }
            if ($kind -cne 'literal' -and
                -not (Test-SteinPhase2SourceCommandRelativePath -Value $value)) {
                throw $failureCode
            }
            if ($kind -ceq 'evidence_relative_path' -and
                $value -cne 'source-fixtures') {
                throw $failureCode
            }
        }
        if ($category -ceq 'grouped_fixture_execution') {
            if ([string]$check.group_id -cne 'closed-source-fixture-suite' -or
                [string]$check.fixture_receipt_path -cne
                    "source-fixtures/$id.receipt.json") {
                throw $failureCode
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
                throw $failureCode
            }
            $null = $executionGroups.Add('closed-source-fixture-suite')
        }
        else {
            $null = $executionGroups.Add("direct:$id")
        }
    }
    if ($executionGroups.Count -ne 25) {
        throw $failureCode
    }
    return [pscustomobject]@{
        catalog = $catalog
        checks = $checks
        execution_group_count = 25
    }
}

function Read-SteinPhase2SourceCommandRegistry {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $ExpectedSha256
    )

    $failureCode = 'source_command_registry_file_invalid'
    Assert-SteinPhase2EvidenceHash `
        -Value $ExpectedSha256 `
        -FailureCode 'source_command_registry_hash_invalid'
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0 -or $item.Length -gt 1MB) {
        throw $failureCode
    }
    $bytes = $null
    $stream = [IO.FileStream]::new(
        $item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $item.Length) {
            throw $failureCode
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw $failureCode }
            $offset += $read
        }
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $actualSha256 = [BitConverter]::ToString(
                $sha256.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
        }
        finally { $sha256.Dispose() }
        if ($actualSha256 -cne $ExpectedSha256) {
            throw 'source_command_registry_hash_mismatch'
        }
        try {
            $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
            if ($text.Length -lt 2 -or [int][char]$text[0] -eq 0xFEFF) {
                throw 'source_command_registry_json_invalid'
            }
            $registry = $text | ConvertFrom-Json -ErrorAction Stop
        }
        catch { throw 'source_command_registry_json_invalid' }
        $null = Assert-SteinPhase2SourceCommandRegistry -Registry $registry
    }
    finally {
        $stream.Dispose()
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    }
    return [pscustomobject]@{
        value = $registry
        sha256 = $actualSha256
    }
}

function Read-SteinPhase2EvidenceSpecification {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string[]] $ExpectedGateIds,
        [Parameter(Mandatory = $true)][string] $ExpectedSha256
    )

    Assert-SteinPhase2EvidenceHash `
        -Value $ExpectedSha256 `
        -FailureCode 'evidence_spec_hash_invalid'
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0 -or $item.Length -gt 1MB) {
        throw 'evidence_spec_file_invalid'
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $item.Length -or
            $stream.Length -le 0 -or $stream.Length -gt 1MB) {
            throw 'evidence_spec_file_invalid'
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw 'evidence_spec_file_invalid'
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
        if ($actualSha256 -cne $ExpectedSha256) {
            throw 'evidence_spec_hash_mismatch'
        }
        try {
            $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
            $jsonText = $strictUtf8.GetString($bytes)
            if ($jsonText.Length -gt 0 -and [int][char]$jsonText[0] -eq 0xFEFF) {
                $jsonText = $jsonText.Substring(1)
            }
        }
        catch {
            throw 'evidence_spec_encoding_invalid'
        }
    }
    finally {
        $stream.Dispose()
    }
    try {
        $specification = $jsonText | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw 'evidence_spec_json_invalid'
    }
    Assert-SteinPhase2EvidenceShape -Value $specification `
        -ExpectedProperties @(
            'schema_version', 'contract_id', 'evidence_result_schema_version',
            'default_subcheck_origin', 'binding_requirements',
            'source_report_contract', 'gates') `
        -FailureCode 'evidence_spec_schema_invalid'
    if (($specification.schema_version -isnot [int] -and
            $specification.schema_version -isnot [long]) -or
        [long]$specification.schema_version -ne 1 -or
        [string]$specification.contract_id -cne 'stein-phase2-gate-evidence-v1' -or
        ($specification.evidence_result_schema_version -isnot [int] -and
            $specification.evidence_result_schema_version -isnot [long]) -or
        [long]$specification.evidence_result_schema_version -ne 2 -or
        [string]$specification.default_subcheck_origin -cne 'installed_native') {
        throw 'evidence_spec_identity_invalid'
    }
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($specification.binding_requirements) `
        -Expected @('package', 'commit', 'source_report') `
        -FailureCode 'evidence_spec_binding_set_invalid'
    Assert-SteinPhase2EvidenceShape -Value $specification.source_report_contract `
        -ExpectedProperties @(
            'source_fixture_registry_sha256', 'source_command_registry_sha256',
            'required_pass_check_ids', 'allowed_not_run_check_ids',
            'required_generator_paths') `
        -FailureCode 'evidence_spec_source_report_contract_invalid'
    $expectedSourceFixtureRegistrySha256 =
        'd2414e552dfbc00b3ecf5837cfc431c64f670508ae4e8696b9fce4f85a75c5c5'
    if ([string]$specification.source_report_contract.source_fixture_registry_sha256 `
            -cne $expectedSourceFixtureRegistrySha256) {
        throw 'evidence_spec_source_fixture_registry_invalid'
    }
    $expectedSourceCommandRegistrySha256 =
        '9a1bb265a11a3b7ca18d1e8b67a2b1c47f9cb090910a458ca3d41fb221b50cbc'
    if ([string]$specification.source_report_contract.source_command_registry_sha256 `
            -cne $expectedSourceCommandRegistrySha256) {
        throw 'evidence_spec_source_command_registry_invalid'
    }
    $expectedSourcePassCheckIds = @(
        'boundary-contract',
        'desktop-build',
        'desktop-lint',
        'desktop-tests',
        'desktop-typecheck',
        'edge-extension-tests',
        'edge-host-check',
        'edge-host-clippy',
        'edge-host-format',
        'edge-host-tests',
        'installed-evidence-harness-static',
        'installed-reviewer-pwsh-contract',
        'installed-reviewer-windows-powershell-contract',
        'msix-static-contract',
        'no-leaks-scanner-static',
        'phase2-source-fixture-goals',
        'phase2-source-fixture-identity',
        'phase2-source-fixture-intervention',
        'phase2-source-fixture-model-contract',
        'phase2-source-fixture-notification',
        'phase2-source-fixture-outbox-recovery',
        'phase2-source-fixture-phase1-regression',
        'phase2-source-fixture-pixels',
        'phase2-source-fixture-policy-failsafe',
        'phase2-source-fixture-revocation-race',
        'phase2-source-fixture-retention',
        'phase2-source-fixture-secrets',
        'phase2-source-fixture-upgrade',
        'release-edge-host',
        'release-production-core',
        'release-tauri-no-bundle',
        'release-workspace',
        'rust-check',
        'rust-clippy',
        'rust-format',
        'rust-tests',
        'source-evidence-contract',
        'source-report-command-provenance',
        'source-provenance-stability'
    )
    $expectedAllowedNotRunCheckIds = @(
        'native-toolchain-provenance',
        'no-leaks-producer-workflow',
        'pinned-clean-build-environment',
        'portable-runner-attestation',
        'windows-native-ignored-fixtures'
    )
    $expectedSourceGeneratorPaths = @(
        'scripts/windows/phase2/Verify-Source.ps1',
        'scripts/windows/phase2/Verify-Source.cmd',
        'scripts/windows/phase2/Source-Evidence.ps1',
        'scripts/windows/phase2/Source-Command-Registry.json',
        'scripts/windows/phase2/Run-Source-Check.ps1',
        'scripts/windows/phase2/Test-SourceCommand.ps1',
        'scripts/windows/phase2/Source-Fixture-Registry.json',
        'scripts/windows/phase2/Run-Source-Fixture.ps1',
        'scripts/windows/phase2/Test-SourceFixture.ps1',
        'scripts/windows/phase2/Test-VerifySource.ps1',
        'scripts/windows/phase2/Review-Installed.ps1',
        'scripts/windows/phase2/Review-Installed.cmd',
        'scripts/windows/phase2/Test-ReviewInstalled.ps1',
        'scripts/windows/phase2/Common.ps1',
        'scripts/windows/phase2/Evidence-Spec.json',
        'scripts/windows/phase2/Evidence-Contract.ps1',
        'scripts/windows/phase2/Scan-NoLeaks.ps1',
        'scripts/windows/phase2/Scan-NoLeaks.cmd',
        'scripts/windows/phase2/Test-ScanNoLeaks.ps1',
        'packaging/windows-msix/PackageTools.ps1'
    )
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($specification.source_report_contract.required_pass_check_ids) `
        -Expected $expectedSourcePassCheckIds `
        -FailureCode 'evidence_spec_source_report_contract_invalid'
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($specification.source_report_contract.allowed_not_run_check_ids) `
        -Expected $expectedAllowedNotRunCheckIds `
        -FailureCode 'evidence_spec_source_report_contract_invalid'
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($specification.source_report_contract.required_generator_paths) `
        -Expected $expectedSourceGeneratorPaths `
        -FailureCode 'evidence_spec_source_report_contract_invalid'

    $gates = @($specification.gates)
    if ($gates.Count -ne 32) {
        throw 'evidence_spec_gate_count_invalid'
    }
    $byGate = @{}
    $fixtureIds = @{}
    $runnerIds = @{}
    foreach ($gate in $gates) {
        $gateId = [string]$gate.gate_id
        $hasLinuxArtifact = $null -ne $gate.PSObject.Properties['linux_artifact']
        $hasSourceSubchecks = $null -ne $gate.PSObject.Properties['source_subchecks']
        $hasLinuxSubchecks = $null -ne $gate.PSObject.Properties['linux_subchecks']
        $hasSourceSubcheckCheckIds =
            $null -ne $gate.PSObject.Properties['source_subcheck_check_ids']
        $hasSourceReportCheckIds =
            $null -ne $gate.PSObject.Properties['source_report_check_ids']
        $hasRunnerArtifacts = $null -ne $gate.PSObject.Properties['runner_artifacts']
        $expectedProperties = @(
            'gate_id', 'fixture_id', 'runner_id', 'required_proof_classes',
            'required_subchecks', 'required_bindings')
        if ($hasLinuxArtifact) {
            $expectedProperties += 'linux_artifact'
        }
        if ($hasSourceSubchecks) {
            $expectedProperties += 'source_subchecks'
        }
        if ($hasSourceSubcheckCheckIds) {
            $expectedProperties += 'source_subcheck_check_ids'
        }
        if ($hasLinuxSubchecks) {
            $expectedProperties += 'linux_subchecks'
        }
        if ($hasSourceReportCheckIds) {
            $expectedProperties += 'source_report_check_ids'
        }
        if ($hasRunnerArtifacts) {
            $expectedProperties += 'runner_artifacts'
        }
        Assert-SteinPhase2EvidenceShape -Value $gate `
            -ExpectedProperties $expectedProperties `
            -FailureCode 'evidence_spec_gate_schema_invalid'
        if ($gateId -cnotmatch '^P2-[A-Z0-9-]+$' -or
            $gateId -cnotin $ExpectedGateIds -or
            $byGate.ContainsKey($gateId) -or
            [string]$gate.fixture_id -cnotmatch '^[a-z0-9][a-z0-9.-]{2,95}$' -or
            [string]$gate.runner_id -cnotmatch '^[a-z0-9][a-z0-9.-]{2,127}$' -or
            $fixtureIds.ContainsKey([string]$gate.fixture_id) -or
            $runnerIds.ContainsKey([string]$gate.runner_id)) {
            throw 'evidence_spec_gate_identity_invalid'
        }
        $proofClasses = @($gate.required_proof_classes)
        $subchecks = @($gate.required_subchecks)
        if ($proofClasses.Count -lt 1 -or $subchecks.Count -lt 1) {
            throw 'evidence_spec_gate_requirements_invalid'
        }
        foreach ($proofClass in $proofClasses) {
            if ($proofClass -isnot [string] -or
                [string]$proofClass -cnotmatch '^[a-z][a-z0-9_]{2,63}$') {
                throw 'evidence_spec_proof_class_invalid'
            }
        }
        foreach ($subcheck in $subchecks) {
            if ($subcheck -isnot [string] -or
                [string]$subcheck -cnotmatch '^[a-z][a-z0-9_]{2,95}$') {
                throw 'evidence_spec_subcheck_invalid'
            }
        }
        Assert-SteinPhase2EvidenceExactSet -Actual $proofClasses -Expected $proofClasses `
            -FailureCode 'evidence_spec_proof_class_invalid'
        Assert-SteinPhase2EvidenceExactSet -Actual $subchecks -Expected $subchecks `
            -FailureCode 'evidence_spec_subcheck_invalid'
        $sourceSubchecks = @(if ($hasSourceSubchecks) { @($gate.source_subchecks) })
        $linuxSubchecks = @(if ($hasLinuxSubchecks) { @($gate.linux_subchecks) })
        foreach ($specialSubcheck in @($sourceSubchecks) + @($linuxSubchecks)) {
            if ([string]$specialSubcheck -cnotin $subchecks) {
                throw 'evidence_spec_subcheck_origin_invalid'
            }
        }
        if (@($sourceSubchecks | Where-Object { [string]$_ -cin $linuxSubchecks }).Count -ne 0) {
            throw 'evidence_spec_subcheck_origin_invalid'
        }
        Assert-SteinPhase2EvidenceExactSet -Actual $sourceSubchecks -Expected $sourceSubchecks `
            -FailureCode 'evidence_spec_subcheck_origin_invalid'
        Assert-SteinPhase2EvidenceExactSet -Actual $linuxSubchecks -Expected $linuxSubchecks `
            -FailureCode 'evidence_spec_subcheck_origin_invalid'
        if (($sourceSubchecks.Count -gt 0) -ne $hasSourceReportCheckIds -or
            ($sourceSubchecks.Count -gt 0) -ne $hasSourceSubcheckCheckIds) {
            throw 'evidence_spec_source_check_binding_invalid'
        }
        if ($hasSourceReportCheckIds) {
            $sourceCheckIds = @($gate.source_report_check_ids)
            if ($sourceCheckIds.Count -lt 1) {
                throw 'evidence_spec_source_check_binding_invalid'
            }
            foreach ($sourceCheckId in $sourceCheckIds) {
                if ($sourceCheckId -isnot [string] -or
                    [string]$sourceCheckId -cnotmatch '^[a-z][a-z0-9-]{2,95}$') {
                    throw 'evidence_spec_source_check_binding_invalid'
                }
            }
            Assert-SteinPhase2EvidenceExactSet `
                -Actual $sourceCheckIds `
                -Expected $sourceCheckIds `
                -FailureCode 'evidence_spec_source_check_binding_invalid'
            Assert-SteinPhase2EvidenceShape `
                -Value $gate.source_subcheck_check_ids `
                -ExpectedProperties $sourceSubchecks `
                -FailureCode 'evidence_spec_source_check_binding_invalid'
            $mappedSourceCheckIds = New-Object Collections.Generic.List[string]
            foreach ($sourceSubcheck in $sourceSubchecks) {
                $mappingProperty =
                    $gate.source_subcheck_check_ids.PSObject.Properties[
                        [string]$sourceSubcheck]
                $subcheckSourceCheckIds = @($mappingProperty.Value)
                if ($subcheckSourceCheckIds.Count -lt 1) {
                    throw 'evidence_spec_source_check_binding_invalid'
                }
                foreach ($sourceCheckId in $subcheckSourceCheckIds) {
                    if ($sourceCheckId -isnot [string] -or
                        [string]$sourceCheckId -cnotmatch '^[a-z][a-z0-9-]{2,95}$' -or
                        [string]$sourceCheckId -cnotin $sourceCheckIds) {
                        throw 'evidence_spec_source_check_binding_invalid'
                    }
                    $mappedSourceCheckIds.Add([string]$sourceCheckId)
                }
                Assert-SteinPhase2EvidenceExactSet `
                    -Actual $subcheckSourceCheckIds `
                    -Expected $subcheckSourceCheckIds `
                    -FailureCode 'evidence_spec_source_check_binding_invalid'
            }
            Assert-SteinPhase2EvidenceExactSet `
                -Actual @($mappedSourceCheckIds | Sort-Object -Unique) `
                -Expected $sourceCheckIds `
                -FailureCode 'evidence_spec_source_check_binding_invalid'
        }
        if ($hasRunnerArtifacts) {
            $runnerArtifacts = @($gate.runner_artifacts)
            if ($runnerArtifacts.Count -lt 1 -or $runnerArtifacts.Count -gt 8) {
                throw 'evidence_spec_runner_artifact_invalid'
            }
            $runnerArtifactRoles = @{}
            foreach ($runnerArtifact in $runnerArtifacts) {
                $runnerArtifactProperties = @(
                    'artifact_role', 'proof_class', 'origin', 'fixture_id',
                    'runner_id', 'required_subchecks')
                if ([string]$runnerArtifact.artifact_role -ceq
                    'no_leaks_sentinel_producer') {
                    $runnerArtifactProperties += @(
                        'producer_source_artifact_id',
                        'producer_manifest_artifact_id',
                        'source_report_check_id')
                }
                Assert-SteinPhase2EvidenceShape -Value $runnerArtifact `
                    -ExpectedProperties $runnerArtifactProperties `
                    -FailureCode 'evidence_spec_runner_artifact_invalid'
                if ([string]$runnerArtifact.artifact_role -cnotmatch
                        '^[a-z][a-z0-9_]{2,63}$' -or
                    $runnerArtifactRoles.ContainsKey([string]$runnerArtifact.artifact_role) -or
                    [string]$runnerArtifact.proof_class -cnotin $proofClasses -or
                    [string]$runnerArtifact.origin -cnotin @(
                        'source_verification', 'installed_native', 'linux_ci') -or
                    [string]$runnerArtifact.fixture_id -cnotmatch
                        '^[a-z0-9][a-z0-9.-]{2,95}$' -or
                    [string]$runnerArtifact.runner_id -cnotmatch
                        '^[a-z0-9][a-z0-9.-]{2,127}$') {
                    throw 'evidence_spec_runner_artifact_invalid'
                }
                if ([string]$runnerArtifact.artifact_role -ceq
                        'no_leaks_sentinel_producer' -and
                    ([string]$runnerArtifact.producer_source_artifact_id -cne
                            'no-leaks-producer-source' -or
                        [string]$runnerArtifact.producer_manifest_artifact_id -cne
                            'no-leaks-producer-manifest' -or
                        [string]$runnerArtifact.source_report_check_id -cne
                            'no-leaks-producer-workflow' -or
                        [string]$runnerArtifact.source_report_check_id -cnotin
                            @($gate.source_report_check_ids))) {
                    throw 'evidence_spec_runner_artifact_invalid'
                }
                if (@($runnerArtifact.required_subchecks).Count -lt 1) {
                    throw 'evidence_spec_runner_artifact_subcheck_invalid'
                }
                foreach ($runnerSubcheck in @($runnerArtifact.required_subchecks)) {
                    if ([string]$runnerSubcheck -cnotin $subchecks -or
                        (Get-SteinPhase2GateSubcheckOrigin `
                            -Gate $gate `
                            -SubcheckId ([string]$runnerSubcheck)) -cne
                            [string]$runnerArtifact.origin) {
                        throw 'evidence_spec_runner_artifact_subcheck_invalid'
                    }
                }
                Assert-SteinPhase2EvidenceExactSet `
                    -Actual @($runnerArtifact.required_subchecks) `
                    -Expected @($runnerArtifact.required_subchecks) `
                    -FailureCode 'evidence_spec_runner_artifact_subcheck_invalid'
                $runnerArtifactRoles[[string]$runnerArtifact.artifact_role] = $true
            }
        }
        $requiredBindings = @('package', 'commit', 'source_report')
        if ($gateId -ceq 'P2-PORTABLE-FIXTURE') {
            $requiredBindings += 'linux_artifact'
        }
        Assert-SteinPhase2EvidenceExactSet `
            -Actual @($gate.required_bindings) `
            -Expected $requiredBindings `
            -FailureCode 'evidence_spec_gate_binding_set_invalid'
        if ($gateId -ceq 'P2-PORTABLE-FIXTURE') {
            if (-not $hasLinuxArtifact) {
                throw 'evidence_spec_linux_artifact_missing'
            }
            Assert-SteinPhase2EvidenceShape -Value $gate.linux_artifact `
                -ExpectedProperties @(
                    'schema_version', 'fixture_id', 'runner_id', 'artifact_id_prefix',
                    'required_subchecks') `
                -FailureCode 'evidence_spec_linux_artifact_invalid'
            if (($gate.linux_artifact.schema_version -isnot [int] -and
                    $gate.linux_artifact.schema_version -isnot [long]) -or
                [long]$gate.linux_artifact.schema_version -ne 1 -or
                [string]$gate.linux_artifact.fixture_id -cne 'phase2-portable-semantic-v1' -or
                [string]$gate.linux_artifact.runner_id -cne 'github-actions-ubuntu-portable-v1' -or
                [string]$gate.linux_artifact.artifact_id_prefix -cne 'linux-log-') {
                throw 'evidence_spec_linux_artifact_invalid'
            }
            Assert-SteinPhase2EvidenceExactSet `
                -Actual @($gate.linux_artifact.required_subchecks) `
                -Expected $linuxSubchecks `
                -FailureCode 'evidence_spec_linux_subcheck_set_invalid'
        }
        elseif ($hasLinuxArtifact -or $hasLinuxSubchecks) {
            throw 'evidence_spec_linux_artifact_unexpected'
        }
        $byGate[$gateId] = $gate
        $fixtureIds[[string]$gate.fixture_id] = $true
        $runnerIds[[string]$gate.runner_id] = $true
    }
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($gates | ForEach-Object { $_.gate_id }) `
        -Expected $ExpectedGateIds `
        -FailureCode 'evidence_spec_gate_set_invalid'
    return [pscustomobject]@{
        specification = $specification
        gates_by_id = $byGate
        sha256 = $actualSha256
    }
}

function Get-SteinPhase2GateSubcheckOrigin {
    param(
        [Parameter(Mandatory = $true)] $Gate,
        [Parameter(Mandatory = $true)][string] $SubcheckId
    )

    if ($null -ne $Gate.PSObject.Properties['source_subchecks'] -and
        $SubcheckId -cin @($Gate.source_subchecks)) {
        return 'source_verification'
    }
    if ($null -ne $Gate.PSObject.Properties['linux_subchecks'] -and
        $SubcheckId -cin @($Gate.linux_subchecks)) {
        return 'linux_ci'
    }
    return 'installed_native'
}

function Assert-SteinPhase2EvidencePackageBinding {
    param(
        [Parameter(Mandatory = $true)] $Binding,
        [Parameter(Mandatory = $true)] $ExpectedPackage
    )

    Assert-SteinPhase2EvidenceShape -Value $Binding `
        -ExpectedProperties @(
            'package_family_name', 'version', 'msix_sha256', 'core_sha256',
            'browser_host_sha256', 'cli_executable_size',
            'cli_executable_sha256', 'desktop_executable_size',
            'desktop_executable_sha256', 'desktop_dist_file_count',
            'desktop_dist_manifest_sha256', 'candidate_git_commit',
            'candidate_git_tree', 'source_verification_sha256',
            'source_root_anchor_sha256', 'source_root_digest_sha256') `
        -FailureCode 'gate_evidence_package_binding_invalid'
    foreach ($property in @(
            'msix_sha256', 'core_sha256', 'browser_host_sha256',
            'cli_executable_sha256', 'desktop_executable_sha256',
            'desktop_dist_manifest_sha256',
            'source_verification_sha256', 'source_root_anchor_sha256',
            'source_root_digest_sha256')) {
        Assert-SteinPhase2EvidenceHash -Value $Binding.$property `
            -FailureCode 'gate_evidence_package_binding_invalid'
    }
    foreach ($property in @(
            'cli_executable_size', 'desktop_executable_size',
            'desktop_dist_file_count')) {
        if (($Binding.$property -isnot [int] -and
                $Binding.$property -isnot [long]) -or
            [long]$Binding.$property -le 0 -or
            ($property -ceq 'desktop_dist_file_count' -and
                [long]$Binding.$property -gt 10000)) {
            throw 'gate_evidence_package_binding_invalid'
        }
        if ([long]$Binding.$property -ne [long]$ExpectedPackage.$property) {
            throw 'gate_evidence_package_binding_mismatch'
        }
    }
    foreach ($property in @(
            'package_family_name', 'version', 'msix_sha256', 'core_sha256',
            'browser_host_sha256', 'cli_executable_sha256',
            'desktop_executable_sha256', 'desktop_dist_manifest_sha256',
            'candidate_git_commit',
            'candidate_git_tree', 'source_verification_sha256',
            'source_root_anchor_sha256', 'source_root_digest_sha256')) {
        if ([string]$Binding.$property -cne [string]$ExpectedPackage.$property) {
            throw 'gate_evidence_package_binding_mismatch'
        }
    }
    if ([string]$Binding.candidate_git_commit -cnotmatch
            '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        [string]$Binding.candidate_git_tree -cnotmatch
            '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        ([string]$Binding.candidate_git_commit).Length -ne
            ([string]$Binding.candidate_git_tree).Length) {
        throw 'gate_evidence_package_binding_invalid'
    }
}

function Assert-SteinPhase2GateEvidenceResult {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)] $Specification,
        [Parameter(Mandatory = $true)] $Gate,
        [Parameter(Mandatory = $true)][string] $SpecificationSha256,
        [Parameter(Mandatory = $true)] $ExpectedPackage,
        [Parameter(Mandatory = $true)] $ExpectedCollector,
        [Parameter(Mandatory = $true)][object[]] $UnderlyingArtifacts
    )

    Assert-SteinPhase2EvidenceShape -Value $Value `
        -ExpectedProperties @(
            'schema_version', 'contract_id', 'contract_sha256', 'gate_id',
            'fixture_id', 'runner_id', 'result', 'recorded_at_utc', 'exit_code',
            'runner', 'proof_classes', 'subchecks', 'bindings', 'artifacts') `
        -FailureCode 'gate_evidence_result_schema_invalid'
    if (($Value.schema_version -isnot [int] -and $Value.schema_version -isnot [long]) -or
        [long]$Value.schema_version -ne [long]$Specification.evidence_result_schema_version -or
        [string]$Value.contract_id -cne [string]$Specification.contract_id -or
        [string]$Value.contract_sha256 -cne $SpecificationSha256 -or
        [string]$Value.gate_id -cne [string]$Gate.gate_id -or
        [string]$Value.fixture_id -cne [string]$Gate.fixture_id -or
        [string]$Value.runner_id -cne [string]$Gate.runner_id -or
        [string]$Value.result -cnotin @('pass', 'fail', 'blocked', 'not_run')) {
        throw 'gate_evidence_result_identity_invalid'
    }
    Assert-SteinPhase2EvidenceShape -Value $Value.runner `
        -ExpectedProperties @('platform', 'architecture', 'non_elevated', 'installed_package') `
        -FailureCode 'gate_evidence_runner_schema_invalid'
    if ([string]$Value.runner.platform -cne 'windows' -or
        [string]$Value.runner.architecture -cnotmatch '^[A-Za-z0-9_.-]{2,32}$' -or
        $Value.runner.non_elevated -isnot [bool] -or
        -not [bool]$Value.runner.non_elevated -or
        $Value.runner.installed_package -isnot [bool] -or
        -not [bool]$Value.runner.installed_package) {
        throw 'gate_evidence_runner_invalid'
    }
    $exitCode = $Value.exit_code
    if (([string]$Value.result -ceq 'pass' -and
            (($exitCode -isnot [int] -and $exitCode -isnot [long]) -or [long]$exitCode -ne 0)) -or
        ([string]$Value.result -ceq 'fail' -and
            (($exitCode -isnot [int] -and $exitCode -isnot [long]) -or [long]$exitCode -eq 0)) -or
        ([string]$Value.result -cin @('blocked', 'not_run') -and $null -ne $exitCode)) {
        throw 'gate_evidence_result_exit_invalid'
    }
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($Value.proof_classes) `
        -Expected @($Gate.required_proof_classes) `
        -FailureCode 'gate_evidence_proof_class_set_invalid'

    Assert-SteinPhase2EvidenceShape -Value $Value.bindings `
        -ExpectedProperties @(
            'package', 'commit', 'source_report', 'linux_artifact', 'collector',
            'runner_artifacts') `
        -FailureCode 'gate_evidence_bindings_schema_invalid'
    Assert-SteinPhase2EvidencePackageBinding `
        -Binding $Value.bindings.package `
        -ExpectedPackage $ExpectedPackage
    Assert-SteinPhase2EvidenceShape -Value $Value.bindings.commit `
        -ExpectedProperties @('object_id', 'tree_id') `
        -FailureCode 'gate_evidence_commit_binding_invalid'
    if ([string]$Value.bindings.commit.object_id -cnotmatch
            '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        [string]$Value.bindings.commit.tree_id -cnotmatch
            '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        [string]$Value.bindings.commit.object_id -cne
            [string]$Value.bindings.package.candidate_git_commit -or
        [string]$Value.bindings.commit.tree_id -cne
            [string]$Value.bindings.package.candidate_git_tree) {
        throw 'gate_evidence_commit_binding_invalid'
    }
    Assert-SteinPhase2EvidenceShape -Value $Value.bindings.collector `
        -ExpectedProperties @('host_identity_sha256', 'evidence_owner_sid_only') `
        -FailureCode 'gate_evidence_collector_binding_invalid'
    Assert-SteinPhase2EvidenceHash -Value $Value.bindings.collector.host_identity_sha256 `
        -FailureCode 'gate_evidence_collector_binding_invalid'
    if ([string]$Value.bindings.collector.host_identity_sha256 -cne
            [string]$ExpectedCollector.host_identity_sha256 -or
        $Value.bindings.collector.evidence_owner_sid_only -isnot [bool] -or
        -not [bool]$Value.bindings.collector.evidence_owner_sid_only -or
        -not [bool]$ExpectedCollector.evidence_owner_sid_only) {
        throw 'gate_evidence_collector_binding_mismatch'
    }
    Assert-SteinPhase2EvidenceShape -Value $Value.bindings.source_report `
        -ExpectedProperties @(
            'report_artifact_id', 'root_anchor_artifact_id', 'report_sha256',
            'root_anchor_sha256', 'root_digest_sha256') `
        -FailureCode 'gate_evidence_source_binding_invalid'
    foreach ($property in @('report_sha256', 'root_anchor_sha256', 'root_digest_sha256')) {
        Assert-SteinPhase2EvidenceHash -Value $Value.bindings.source_report.$property `
            -FailureCode 'gate_evidence_source_binding_invalid'
    }
    if ([string]$Value.bindings.source_report.report_sha256 -cne
            [string]$Value.bindings.package.source_verification_sha256 -or
        [string]$Value.bindings.source_report.root_anchor_sha256 -cne
            [string]$Value.bindings.package.source_root_anchor_sha256 -or
        [string]$Value.bindings.source_report.root_digest_sha256 -cne
            [string]$Value.bindings.package.source_root_digest_sha256) {
        throw 'gate_evidence_signed_source_binding_mismatch'
    }
    foreach ($property in @('report_artifact_id', 'root_anchor_artifact_id')) {
        if ([string]$Value.bindings.source_report.$property -cnotmatch
            '^[a-z0-9][a-z0-9._-]{2,95}$') {
            throw 'gate_evidence_source_binding_invalid'
        }
    }
    $requiresLinux = [string]$Gate.gate_id -ceq 'P2-PORTABLE-FIXTURE'
    if ($requiresLinux) {
        Assert-SteinPhase2EvidenceShape -Value $Value.bindings.linux_artifact `
            -ExpectedProperties @('artifact_id', 'sha256', 'fixture_id', 'runner_id') `
            -FailureCode 'gate_evidence_linux_binding_invalid'
        Assert-SteinPhase2EvidenceHash -Value $Value.bindings.linux_artifact.sha256 `
            -FailureCode 'gate_evidence_linux_binding_invalid'
        if ([string]$Value.bindings.linux_artifact.artifact_id -cnotmatch
                '^[a-z0-9][a-z0-9._-]{2,95}$' -or
            [string]$Value.bindings.linux_artifact.fixture_id -cne
                [string]$Gate.linux_artifact.fixture_id -or
            [string]$Value.bindings.linux_artifact.runner_id -cne
                [string]$Gate.linux_artifact.runner_id) {
            throw 'gate_evidence_linux_binding_invalid'
        }
    }
    elseif ($null -ne $Value.bindings.linux_artifact) {
        throw 'gate_evidence_linux_binding_unexpected'
    }

    $artifacts = @($Value.artifacts)
    $artifactsById = @{}
    foreach ($artifact in $artifacts) {
        Assert-SteinPhase2EvidenceShape -Value $artifact `
            -ExpectedProperties @('artifact_id', 'proof_class', 'origin', 'sha256', 'size') `
            -FailureCode 'gate_evidence_artifact_schema_invalid'
        $artifactId = [string]$artifact.artifact_id
        if ($artifactId -cnotmatch '^[a-z0-9][a-z0-9._-]{2,95}$' -or
            $artifactsById.ContainsKey($artifactId) -or
            ([string]$artifact.proof_class -cnotin @($Gate.required_proof_classes) -and
                [string]$artifact.proof_class -cne 'source_provenance') -or
            [string]$artifact.origin -cnotin @(
                'source_verification', 'installed_native', 'linux_ci') -or
            ($artifact.size -isnot [int] -and $artifact.size -isnot [long]) -or
            [long]$artifact.size -lt 1 -or [long]$artifact.size -gt 67108864) {
            throw 'gate_evidence_artifact_identity_invalid'
        }
        Assert-SteinPhase2EvidenceHash -Value $artifact.sha256 `
            -FailureCode 'gate_evidence_artifact_identity_invalid'
        $artifactsById[$artifactId] = $artifact
    }
    if ($artifactsById.Count -lt (@($Gate.required_proof_classes).Count + 2)) {
        throw 'gate_evidence_artifact_set_invalid'
    }
    $underlyingById = @{}
    foreach ($underlying in @($UnderlyingArtifacts)) {
        Assert-SteinPhase2EvidenceShape -Value $underlying `
            -ExpectedProperties @('artifact_id', 'sha256', 'size') `
            -FailureCode 'gate_evidence_underlying_artifact_schema_invalid'
        $underlyingId = [string]$underlying.artifact_id
        if ($underlyingId -cnotmatch '^[a-z0-9][a-z0-9._-]{2,95}$' -or
            $underlyingById.ContainsKey($underlyingId) -or
            -not $artifactsById.ContainsKey($underlyingId)) {
            throw 'gate_evidence_underlying_artifact_set_invalid'
        }
        Assert-SteinPhase2EvidenceHash -Value $underlying.sha256 `
            -FailureCode 'gate_evidence_underlying_artifact_invalid'
        if ([string]$underlying.sha256 -cne [string]$artifactsById[$underlyingId].sha256 -or
            [long]$underlying.size -ne [long]$artifactsById[$underlyingId].size) {
            throw 'gate_evidence_underlying_artifact_mismatch'
        }
        $underlyingById[$underlyingId] = $underlying
    }
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($underlyingById.Keys) `
        -Expected @($artifactsById.Keys) `
        -FailureCode 'gate_evidence_underlying_artifact_set_invalid'

    $subchecks = @($Value.subchecks)
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($subchecks | ForEach-Object { $_.id }) `
        -Expected @($Gate.required_subchecks) `
        -FailureCode 'gate_evidence_subcheck_set_invalid'
    $referencedArtifacts = @{}
    foreach ($subcheck in $subchecks) {
        Assert-SteinPhase2EvidenceShape -Value $subcheck `
            -ExpectedProperties @(
                'id', 'origin', 'result', 'artifact_ids', 'source_check_ids') `
            -FailureCode 'gate_evidence_subcheck_schema_invalid'
        $expectedOrigin = Get-SteinPhase2GateSubcheckOrigin `
            -Gate $Gate `
            -SubcheckId ([string]$subcheck.id)
        if ([string]$subcheck.origin -cne $expectedOrigin -or
            [string]$subcheck.result -cnotin @('pass', 'fail', 'blocked', 'not_run') -or
            ([string]$Value.result -ceq 'pass' -and [string]$subcheck.result -cne 'pass')) {
            throw 'gate_evidence_subcheck_result_invalid'
        }
        $expectedSourceCheckIds = if ($expectedOrigin -ceq 'source_verification') {
            $sourceMappingProperty =
                $Gate.source_subcheck_check_ids.PSObject.Properties[
                    [string]$subcheck.id]
            @(
                @($sourceMappingProperty.Value) +
                    @(
                        'native-toolchain-provenance',
                        'pinned-clean-build-environment',
                        'source-report-command-provenance') |
                    Sort-Object -Unique)
        }
        else { @() }
        Assert-SteinPhase2EvidenceExactSet `
            -Actual @($subcheck.source_check_ids) `
            -Expected $expectedSourceCheckIds `
            -FailureCode 'gate_evidence_source_check_binding_invalid'
        $artifactIds = @($subcheck.artifact_ids)
        if ($artifactIds.Count -lt 1) {
            throw 'gate_evidence_subcheck_artifact_set_invalid'
        }
        foreach ($artifactId in $artifactIds) {
            if ($artifactId -isnot [string] -or
                -not $artifactsById.ContainsKey([string]$artifactId) -or
                [string]$artifactsById[[string]$artifactId].origin -cne $expectedOrigin) {
                throw 'gate_evidence_subcheck_artifact_set_invalid'
            }
            $referencedArtifacts[[string]$artifactId] = $true
        }
    }
    foreach ($proofClass in @($Gate.required_proof_classes)) {
        if (@($artifacts | Where-Object {
                    [string]$_.proof_class -ceq [string]$proofClass -and
                    $referencedArtifacts.ContainsKey([string]$_.artifact_id)
                }).Count -lt 1) {
            throw 'gate_evidence_proof_class_unsubstantiated'
        }
    }
    $sourceBinding = $Value.bindings.source_report
    foreach ($binding in @(
            [pscustomobject]@{
                id = [string]$sourceBinding.report_artifact_id
                hash = [string]$sourceBinding.report_sha256
            },
            [pscustomobject]@{
                id = [string]$sourceBinding.root_anchor_artifact_id
                hash = [string]$sourceBinding.root_anchor_sha256
            })) {
        if (-not $artifactsById.ContainsKey($binding.id) -or
            [string]$artifactsById[$binding.id].sha256 -cne $binding.hash -or
            [string]$artifactsById[$binding.id].proof_class -cne 'source_provenance' -or
            [string]$artifactsById[$binding.id].origin -cne 'source_verification') {
            throw 'gate_evidence_source_binding_artifact_mismatch'
        }
    }
    if ($requiresLinux) {
        $linuxBinding = $Value.bindings.linux_artifact
        if (-not $artifactsById.ContainsKey([string]$linuxBinding.artifact_id) -or
            [string]$artifactsById[[string]$linuxBinding.artifact_id].sha256 -cne
                [string]$linuxBinding.sha256 -or
            [string]$artifactsById[[string]$linuxBinding.artifact_id].proof_class -cne
                'portable_linux' -or
            [string]$artifactsById[[string]$linuxBinding.artifact_id].origin -cne
                'linux_ci') {
            throw 'gate_evidence_linux_binding_artifact_mismatch'
        }
        foreach ($linuxSubcheckId in @($Gate.linux_artifact.required_subchecks)) {
            $linuxLogArtifactId =
                [string]$Gate.linux_artifact.artifact_id_prefix + [string]$linuxSubcheckId
            $linuxSubcheck = @($subchecks | Where-Object {
                    [string]$_.id -ceq [string]$linuxSubcheckId
                })
            if ($linuxSubcheck.Count -ne 1 -or
                -not $artifactsById.ContainsKey($linuxLogArtifactId) -or
                [string]$artifactsById[$linuxLogArtifactId].proof_class -cne
                    'portable_linux' -or
                [string]$artifactsById[$linuxLogArtifactId].origin -cne 'linux_ci' -or
                $linuxLogArtifactId -cnotin @($linuxSubcheck[0].artifact_ids)) {
                throw 'gate_evidence_linux_log_artifact_missing'
            }
        }
    }
    $expectedRunnerArtifacts = @(if (
            $null -ne $Gate.PSObject.Properties['runner_artifacts']) {
            @($Gate.runner_artifacts)
        })
    $runnerArtifactBindings = @($Value.bindings.runner_artifacts)
    if ($runnerArtifactBindings.Count -ne @($expectedRunnerArtifacts).Count) {
        throw 'gate_evidence_runner_artifact_set_invalid'
    }
    $runnerArtifactRoles = @{}
    foreach ($runnerBinding in $runnerArtifactBindings) {
        Assert-SteinPhase2EvidenceShape -Value $runnerBinding `
            -ExpectedProperties @(
                'artifact_role', 'artifact_id', 'fixture_id', 'runner_id', 'sha256') `
            -FailureCode 'gate_evidence_runner_artifact_binding_invalid'
        $expectedRunner = @($expectedRunnerArtifacts | Where-Object {
                [string]$_.artifact_role -ceq [string]$runnerBinding.artifact_role
            })
        Assert-SteinPhase2EvidenceHash -Value $runnerBinding.sha256 `
            -FailureCode 'gate_evidence_runner_artifact_binding_invalid'
        if ($expectedRunner.Count -ne 1 -or
            $runnerArtifactRoles.ContainsKey([string]$runnerBinding.artifact_role) -or
            [string]$runnerBinding.artifact_id -cnotmatch
                '^[a-z0-9][a-z0-9._-]{2,95}$' -or
            [string]$runnerBinding.fixture_id -cne [string]$expectedRunner[0].fixture_id -or
            [string]$runnerBinding.runner_id -cne [string]$expectedRunner[0].runner_id -or
            -not $artifactsById.ContainsKey([string]$runnerBinding.artifact_id) -or
            [string]$artifactsById[[string]$runnerBinding.artifact_id].sha256 -cne
                [string]$runnerBinding.sha256 -or
            [string]$artifactsById[[string]$runnerBinding.artifact_id].proof_class -cne
                [string]$expectedRunner[0].proof_class -or
            [string]$artifactsById[[string]$runnerBinding.artifact_id].origin -cne
                [string]$expectedRunner[0].origin) {
            throw 'gate_evidence_runner_artifact_binding_invalid'
        }
        foreach ($runnerSubcheckId in @($expectedRunner[0].required_subchecks)) {
            $runnerSubcheck = @($subchecks | Where-Object {
                    [string]$_.id -ceq [string]$runnerSubcheckId
                })
            if ($runnerSubcheck.Count -ne 1 -or
                [string]$runnerBinding.artifact_id -cnotin
                    @($runnerSubcheck[0].artifact_ids)) {
                throw 'gate_evidence_runner_artifact_not_referenced'
            }
        }
        $runnerArtifactRoles[[string]$runnerBinding.artifact_role] = $true
    }
    if ([string]$Gate.gate_id -ceq 'P2-NO-LEAKS') {
        $producerRunner = @($Gate.runner_artifacts | Where-Object {
                [string]$_.artifact_role -ceq 'no_leaks_sentinel_producer'
            })
        if ($producerRunner.Count -ne 1) {
            throw 'gate_evidence_no_leaks_producer_binding_missing'
        }
        $producerSourceId = [string]$producerRunner[0].producer_source_artifact_id
        $producerManifestId = [string]$producerRunner[0].producer_manifest_artifact_id
        $producerContractSubcheck = @($subchecks | Where-Object {
                [string]$_.id -ceq 'sentinel_producer_contract'
            })
        if (-not $artifactsById.ContainsKey($producerSourceId) -or
            [string]$artifactsById[$producerSourceId].proof_class -cne 'privacy_scan' -or
            [string]$artifactsById[$producerSourceId].origin -cne 'source_verification' -or
            -not $artifactsById.ContainsKey($producerManifestId) -or
            [string]$artifactsById[$producerManifestId].proof_class -cne 'privacy_scan' -or
            [string]$artifactsById[$producerManifestId].origin -cne 'installed_native' -or
            $producerContractSubcheck.Count -ne 1 -or
            $producerSourceId -cnotin @($producerContractSubcheck[0].artifact_ids)) {
            throw 'gate_evidence_no_leaks_producer_binding_missing'
        }
    }
    return $true
}

function Assert-SteinPhase2FixedPassReceipt {
    param(
        [Parameter(Mandatory = $true)] $Artifact,
        [Parameter(Mandatory = $true)] $RunnerArtifact,
        [Parameter(Mandatory = $true)][string] $FailurePrefix
    )

    Assert-SteinPhase2EvidenceShape -Value $Artifact `
        -ExpectedProperties @(
            'schema_version', 'fixture_id', 'runner_id', 'result', 'summary', 'subchecks') `
        -FailureCode ($FailurePrefix + '_artifact_schema_invalid')
    if (($Artifact.schema_version -isnot [int] -and $Artifact.schema_version -isnot [long]) -or
        [long]$Artifact.schema_version -ne 1 -or
        [string]$Artifact.fixture_id -cne [string]$RunnerArtifact.fixture_id -or
        [string]$Artifact.runner_id -cne [string]$RunnerArtifact.runner_id -or
        [string]$Artifact.result -cne 'pass') {
        throw ($FailurePrefix + '_artifact_identity_invalid')
    }
    Assert-SteinPhase2EvidenceShape -Value $Artifact.summary `
        -ExpectedProperties @('required', 'passed', 'failed', 'not_run') `
        -FailureCode ($FailurePrefix + '_artifact_summary_invalid')
    foreach ($property in @('required', 'passed', 'failed', 'not_run')) {
        if (($Artifact.summary.$property -isnot [int] -and
                $Artifact.summary.$property -isnot [long]) -or
            [long]$Artifact.summary.$property -lt 0) {
            throw ($FailurePrefix + '_artifact_summary_invalid')
        }
    }
    $requiredSubchecks = @($RunnerArtifact.required_subchecks)
    if ([long]$Artifact.summary.required -ne $requiredSubchecks.Count -or
        [long]$Artifact.summary.passed -ne $requiredSubchecks.Count -or
        [long]$Artifact.summary.failed -ne 0 -or
        [long]$Artifact.summary.not_run -ne 0) {
        throw ($FailurePrefix + '_artifact_summary_invalid')
    }
    $subchecks = @($Artifact.subchecks)
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($subchecks | ForEach-Object { $_.id }) `
        -Expected $requiredSubchecks `
        -FailureCode ($FailurePrefix + '_artifact_subcheck_set_invalid')
    for ($subcheckIndex = 0; $subcheckIndex -lt $subchecks.Count; $subcheckIndex++) {
        $subcheck = $subchecks[$subcheckIndex]
        Assert-SteinPhase2EvidenceShape -Value $subcheck `
            -ExpectedProperties @('id', 'result') `
            -FailureCode ($FailurePrefix + '_artifact_subcheck_invalid')
        if ([string]$subcheck.id -cne [string]$requiredSubchecks[$subcheckIndex] -or
            [string]$subcheck.result -cne 'pass') {
            throw ($FailurePrefix + '_artifact_subcheck_invalid')
        }
    }
    return $true
}

function Assert-SteinPhase2PrivateDiagnosticArtifact {
    param(
        [Parameter(Mandatory = $true)] $Artifact,
        [Parameter(Mandatory = $true)] $RunnerArtifact
    )

    return Assert-SteinPhase2FixedPassReceipt `
        -Artifact $Artifact `
        -RunnerArtifact $RunnerArtifact `
        -FailurePrefix 'private_diagnostic'
}

function Assert-SteinPhase2ToastComDenialArtifact {
    param(
        [Parameter(Mandatory = $true)] $Artifact,
        [Parameter(Mandatory = $true)] $RunnerArtifact
    )

    return Assert-SteinPhase2FixedPassReceipt `
        -Artifact $Artifact `
        -RunnerArtifact $RunnerArtifact `
        -FailurePrefix 'toast_com_denial'
}

function Assert-SteinPhase2NoLeaksArtifact {
    param(
        [Parameter(Mandatory = $true)] $Artifact,
        [Parameter(Mandatory = $true)] $RunnerArtifact,
        [Parameter(Mandatory = $true)] $EvidenceResult
    )

    Assert-SteinPhase2EvidenceShape -Value $Artifact `
        -ExpectedProperties @(
            'schema_version', 'gate_id', 'fixture_id', 'runner_id', 'result',
            'bindings', 'summary', 'subchecks') `
        -FailureCode 'no_leaks_artifact_schema_invalid'
    if (($Artifact.schema_version -isnot [int] -and $Artifact.schema_version -isnot [long]) -or
        [long]$Artifact.schema_version -ne 1 -or
        [string]$Artifact.gate_id -cne 'P2-NO-LEAKS' -or
        [string]$Artifact.fixture_id -cne [string]$RunnerArtifact.fixture_id -or
        [string]$Artifact.runner_id -cne [string]$RunnerArtifact.runner_id -or
        [string]$Artifact.result -cne 'pass') {
        throw 'no_leaks_artifact_identity_invalid'
    }
    Assert-SteinPhase2EvidenceShape -Value $Artifact.bindings `
        -ExpectedProperties @(
            'package_msix_sha256', 'candidate_git_commit',
            'source_verification_sha256', 'artifact_catalog_sha256', 'artifact_count') `
        -FailureCode 'no_leaks_artifact_binding_invalid'
    foreach ($property in @(
            'package_msix_sha256', 'source_verification_sha256',
            'artifact_catalog_sha256')) {
        Assert-SteinPhase2EvidenceHash -Value $Artifact.bindings.$property `
            -FailureCode 'no_leaks_artifact_binding_invalid'
        if ([string]$Artifact.bindings.$property -ceq ('0' * 64)) {
            throw 'no_leaks_artifact_binding_invalid'
        }
    }
    if ([string]$Artifact.bindings.candidate_git_commit -cnotmatch
            '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        [string]$Artifact.bindings.package_msix_sha256 -cne
            [string]$EvidenceResult.bindings.package.msix_sha256 -or
        [string]$Artifact.bindings.candidate_git_commit -cne
            [string]$EvidenceResult.bindings.commit.object_id -or
        [string]$Artifact.bindings.source_verification_sha256 -cne
            [string]$EvidenceResult.bindings.source_report.report_sha256 -or
        ($Artifact.bindings.artifact_count -isnot [int] -and
            $Artifact.bindings.artifact_count -isnot [long]) -or
        [long]$Artifact.bindings.artifact_count -lt 1 -or
        [long]$Artifact.bindings.artifact_count -gt 4096) {
        throw 'no_leaks_artifact_binding_invalid'
    }
    Assert-SteinPhase2EvidenceShape -Value $Artifact.summary `
        -ExpectedProperties @('required', 'passed', 'failed', 'not_run', 'files_inspected') `
        -FailureCode 'no_leaks_artifact_summary_invalid'
    foreach ($property in @('required', 'passed', 'failed', 'not_run', 'files_inspected')) {
        if (($Artifact.summary.$property -isnot [int] -and
                $Artifact.summary.$property -isnot [long]) -or
            [long]$Artifact.summary.$property -lt 0) {
            throw 'no_leaks_artifact_summary_invalid'
        }
    }
    $requiredSubchecks = @($RunnerArtifact.required_subchecks)
    if ([long]$Artifact.summary.required -ne $requiredSubchecks.Count -or
        [long]$Artifact.summary.passed -ne $requiredSubchecks.Count -or
        [long]$Artifact.summary.failed -ne 0 -or
        [long]$Artifact.summary.not_run -ne 0 -or
        [long]$Artifact.summary.files_inspected -lt $requiredSubchecks.Count -or
        [long]$Artifact.bindings.artifact_count -ne
            [long]$Artifact.summary.files_inspected) {
        throw 'no_leaks_artifact_summary_invalid'
    }
    $subchecks = @($Artifact.subchecks)
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($subchecks | ForEach-Object { $_.id }) `
        -Expected $requiredSubchecks `
        -FailureCode 'no_leaks_artifact_subcheck_set_invalid'
    $filesInspected = 0L
    for ($subcheckIndex = 0; $subcheckIndex -lt $subchecks.Count; $subcheckIndex++) {
        $subcheck = $subchecks[$subcheckIndex]
        Assert-SteinPhase2EvidenceShape -Value $subcheck `
            -ExpectedProperties @('id', 'result', 'files_inspected', 'matches_found') `
            -FailureCode 'no_leaks_artifact_subcheck_invalid'
        if ([string]$subcheck.id -cne [string]$requiredSubchecks[$subcheckIndex] -or
            [string]$subcheck.result -cne 'pass' -or
            ($subcheck.files_inspected -isnot [int] -and
                $subcheck.files_inspected -isnot [long]) -or
            [long]$subcheck.files_inspected -lt 1 -or
            ($subcheck.matches_found -isnot [int] -and
                $subcheck.matches_found -isnot [long]) -or
            [long]$subcheck.matches_found -ne 0) {
            throw 'no_leaks_artifact_subcheck_invalid'
        }
        $filesInspected += [long]$subcheck.files_inspected
    }
    if ($filesInspected -ne [long]$Artifact.summary.files_inspected) {
        throw 'no_leaks_artifact_summary_invalid'
    }
    return $true
}

function Assert-SteinPhase2NoLeaksProducerArtifact {
    param(
        [Parameter(Mandatory = $true)] $Artifact,
        [Parameter(Mandatory = $true)] $RunnerArtifact,
        [Parameter(Mandatory = $true)] $EvidenceResult
    )

    Assert-SteinPhase2EvidenceShape -Value $Artifact `
        -ExpectedProperties @(
            'schema_version', 'gate_id', 'fixture_id', 'runner_id', 'result',
            'bindings', 'summary', 'subchecks') `
        -FailureCode 'no_leaks_producer_artifact_schema_invalid'
    if (($Artifact.schema_version -isnot [int] -and $Artifact.schema_version -isnot [long]) -or
        [long]$Artifact.schema_version -ne 1 -or
        [string]$Artifact.gate_id -cne 'P2-NO-LEAKS' -or
        [string]$Artifact.fixture_id -cne [string]$RunnerArtifact.fixture_id -or
        [string]$Artifact.runner_id -cne [string]$RunnerArtifact.runner_id -or
        [string]$Artifact.result -cne 'pass') {
        throw 'no_leaks_producer_artifact_identity_invalid'
    }
    Assert-SteinPhase2EvidenceShape -Value $Artifact.bindings `
        -ExpectedProperties @(
            'package_msix_sha256', 'candidate_git_commit',
            'source_verification_sha256', 'producer_manifest_sha256',
            'producer_source_sha256', 'artifact_catalog_sha256', 'artifact_count') `
        -FailureCode 'no_leaks_producer_artifact_binding_invalid'
    foreach ($property in @(
            'package_msix_sha256', 'source_verification_sha256',
            'producer_manifest_sha256', 'producer_source_sha256',
            'artifact_catalog_sha256')) {
        Assert-SteinPhase2EvidenceHash -Value $Artifact.bindings.$property `
            -FailureCode 'no_leaks_producer_artifact_binding_invalid'
        if ([string]$Artifact.bindings.$property -ceq ('0' * 64)) {
            throw 'no_leaks_producer_artifact_binding_invalid'
        }
    }
    $producerSource = @($EvidenceResult.artifacts | Where-Object {
            [string]$_.artifact_id -ceq [string]$RunnerArtifact.producer_source_artifact_id
        })
    $producerManifest = @($EvidenceResult.artifacts | Where-Object {
            [string]$_.artifact_id -ceq [string]$RunnerArtifact.producer_manifest_artifact_id
        })
    if ([string]$Artifact.bindings.candidate_git_commit -cnotmatch
            '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        [string]$Artifact.bindings.package_msix_sha256 -cne
            [string]$EvidenceResult.bindings.package.msix_sha256 -or
        [string]$Artifact.bindings.candidate_git_commit -cne
            [string]$EvidenceResult.bindings.commit.object_id -or
        [string]$Artifact.bindings.source_verification_sha256 -cne
            [string]$EvidenceResult.bindings.source_report.report_sha256 -or
        $producerSource.Count -ne 1 -or $producerManifest.Count -ne 1 -or
        [string]$Artifact.bindings.producer_source_sha256 -cne
            [string]$producerSource[0].sha256 -or
        [string]$Artifact.bindings.producer_manifest_sha256 -cne
            [string]$producerManifest[0].sha256 -or
        ($Artifact.bindings.artifact_count -isnot [int] -and
            $Artifact.bindings.artifact_count -isnot [long]) -or
        [long]$Artifact.bindings.artifact_count -lt 1 -or
        [long]$Artifact.bindings.artifact_count -gt 4096) {
        throw 'no_leaks_producer_artifact_binding_invalid'
    }
    Assert-SteinPhase2EvidenceShape -Value $Artifact.summary `
        -ExpectedProperties @('required', 'passed', 'failed', 'not_run', 'artifacts_produced') `
        -FailureCode 'no_leaks_producer_artifact_summary_invalid'
    foreach ($property in @('required', 'passed', 'failed', 'not_run', 'artifacts_produced')) {
        if (($Artifact.summary.$property -isnot [int] -and
                $Artifact.summary.$property -isnot [long]) -or
            [long]$Artifact.summary.$property -lt 0) {
            throw 'no_leaks_producer_artifact_summary_invalid'
        }
    }
    $requiredSubchecks = @($RunnerArtifact.required_subchecks)
    if ([long]$Artifact.summary.required -ne $requiredSubchecks.Count -or
        [long]$Artifact.summary.passed -ne $requiredSubchecks.Count -or
        [long]$Artifact.summary.failed -ne 0 -or
        [long]$Artifact.summary.not_run -ne 0 -or
        [long]$Artifact.summary.artifacts_produced -lt $requiredSubchecks.Count -or
        [long]$Artifact.bindings.artifact_count -ne
            [long]$Artifact.summary.artifacts_produced) {
        throw 'no_leaks_producer_artifact_summary_invalid'
    }
    $subchecks = @($Artifact.subchecks)
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($subchecks | ForEach-Object { $_.id }) `
        -Expected $requiredSubchecks `
        -FailureCode 'no_leaks_producer_artifact_subcheck_set_invalid'
    $artifactsProduced = 0L
    for ($subcheckIndex = 0; $subcheckIndex -lt $subchecks.Count; $subcheckIndex++) {
        $subcheck = $subchecks[$subcheckIndex]
        Assert-SteinPhase2EvidenceShape -Value $subcheck `
            -ExpectedProperties @('id', 'result', 'artifacts_produced') `
            -FailureCode 'no_leaks_producer_artifact_subcheck_invalid'
        if ([string]$subcheck.id -cne [string]$requiredSubchecks[$subcheckIndex] -or
            [string]$subcheck.result -cne 'pass' -or
            ($subcheck.artifacts_produced -isnot [int] -and
                $subcheck.artifacts_produced -isnot [long]) -or
            [long]$subcheck.artifacts_produced -lt 1) {
            throw 'no_leaks_producer_artifact_subcheck_invalid'
        }
        $artifactsProduced += [long]$subcheck.artifacts_produced
    }
    if ($artifactsProduced -ne [long]$Artifact.summary.artifacts_produced) {
        throw 'no_leaks_producer_artifact_summary_invalid'
    }
    return $true
}

function Assert-SteinPhase2NoLeaksReceiptPair {
    param(
        [Parameter(Mandatory = $true)] $ScannerArtifact,
        [Parameter(Mandatory = $true)] $ProducerArtifact
    )

    foreach ($property in @(
            'package_msix_sha256', 'candidate_git_commit',
            'source_verification_sha256', 'artifact_catalog_sha256', 'artifact_count')) {
        if ([string]$ScannerArtifact.bindings.$property -cne
            [string]$ProducerArtifact.bindings.$property) {
            throw 'no_leaks_receipt_pair_binding_mismatch'
        }
    }
    return $true
}

function Get-SteinPhase2SourceFixtureInvocationId {
    param([Parameter(Mandatory = $true)] $Invocation)

    $material = @(
        'stein-source-fixture-invocation-v1',
        "kind=$([string]$Invocation.kind)",
        "module=$([string]$Invocation.module)",
        "test=$([string]$Invocation.test)") -join "`n"
    $digest = Get-SteinPhase2EvidenceTextSha256 -Value $material
    return "source-invocation-$($digest.Substring(0, 24))"
}

function Get-SteinPhase2SourceFixtureCommandDefinition {
    param([Parameter(Mandatory = $true)] $Invocation)

    $kind = [string]$Invocation.kind
    $module = [string]$Invocation.module
    $test = [string]$Invocation.test
    switch ($kind) {
        'core' { $qualified = "$module`::tests::$test"; $package = 'stein-core'; $target = @('--lib') }
        'store' { $qualified = $test; $package = 'stein-store-sqlite'; $target = @('--test', 'repository') }
        'windows' { $qualified = "$module`::tests::$test"; $package = 'stein-platform-windows'; $target = @('--lib') }
        'model' { $qualified = "tests::$test"; $package = 'stein-model-openai'; $target = @('--lib') }
        'desktop' {
            $qualified = if ($module -ceq 'toast_activation') {
                "toast_activation::tests::$test"
            }
            else { "$module`::$test" }
            $package = 'stein-desktop'; $target = @('--lib')
        }
        'cli' { $qualified = "tests::$test"; $package = 'stein-cli'; $target = @('--bin', 'stein-cli') }
        'protocol' { $qualified = $test; $package = 'stein-protocol'; $target = @('--test', 'protocol_contract') }
        'ipc' { $qualified = "$module`::tests::$test"; $package = 'stein-ipc'; $target = @('--lib') }
        'boundary' {
            return [pscustomobject]@{
                qualified_name = 'boundary_contract'
                arguments = @(
                    '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                    '-File', 'scripts/windows/check-boundaries.ps1', '-Json')
                harness = $null
            }
        }
        default { throw 'source_fixture_receipt_invalid' }
    }
    $targetKind = if ($target[0] -ceq '--lib') { 'lib' }
        elseif ($target[0] -ceq '--test') { 'test' }
        else { 'bin' }
    $targetName = switch ($package) {
        'stein-core' { 'stein_core' }
        'stein-store-sqlite' { 'repository' }
        'stein-platform-windows' { 'stein_platform_windows' }
        'stein-model-openai' { 'stein_model_openai' }
        'stein-desktop' { 'stein_desktop_lib' }
        'stein-cli' { 'stein-cli' }
        'stein-protocol' { 'protocol_contract' }
        'stein-ipc' { 'stein_ipc' }
    }
    $manifestPath = switch ($package) {
        'stein-core' { 'crates/stein-core/Cargo.toml' }
        'stein-store-sqlite' { 'crates/stein-store-sqlite/Cargo.toml' }
        'stein-platform-windows' { 'crates/stein-platform-windows/Cargo.toml' }
        'stein-model-openai' { 'crates/stein-model-openai/Cargo.toml' }
        'stein-desktop' { 'apps/desktop/src-tauri/Cargo.toml' }
        'stein-cli' { 'apps/core-cli/Cargo.toml' }
        'stein-protocol' { 'crates/stein-protocol/Cargo.toml' }
        'stein-ipc' { 'crates/stein-ipc/Cargo.toml' }
    }
    $prefix = @(
        'test', '--locked', '--manifest-path', 'Cargo.toml', '-p', $package) +
        $target
    return [pscustomobject]@{
        qualified_name = $qualified
        arguments = @($prefix + @(
                '--', $qualified, '--exact', '--test-threads=1'))
        harness = [pscustomobject]@{
            harness_id = ("cargo-harness-$package-$targetKind-$targetName" -replace '_', '-')
            package = $package
            target_kind = $targetKind
            target_name = $targetName
            manifest_path = $manifestPath
            compile_arguments = @($prefix + @(
                    '--no-run', '--message-format=json-render-diagnostics'))
        }
    }
}

function Assert-SteinPhase2SourceFixtureReceiptCheck {
    param(
        [Parameter(Mandatory = $true)] $Check,
        [Parameter(Mandatory = $true)] $Gate,
        [Parameter(Mandatory = $true)] $SourceReport,
        [Parameter(Mandatory = $true)] $EvidenceResult,
        [Parameter(Mandatory = $true)][string] $RegistrySha256,
        [Parameter(Mandatory = $true)] $Fixture
    )

    $failureCode = 'source_fixture_receipt_invalid'
    Assert-SteinPhase2EvidenceShape -Value $Check `
        -ExpectedProperties @(
            'id', 'status', 'executable', 'arguments', 'working_directory',
            'started_at', 'completed_at', 'duration_ms', 'exit_code',
            'failure_summary', 'stdout', 'stderr', 'source_fixture_receipt',
            'source_fixture_receipt_artifact', 'source_fixture_suite_index',
            'source_command_receipt', 'source_command_receipt_artifact') `
        -FailureCode $failureCode
    $checkId = [string]$Check.id
    if ([string]$Check.status -cne 'pass' -or
        [string]$Check.executable -cne 'powershell.exe' -or
        [string]$Check.working_directory -cne '.' -or
        [long]$Check.exit_code -ne 0 -or $null -ne $Check.failure_summary) {
        throw $failureCode
    }
    $arguments = @($Check.arguments | ForEach-Object { [string]$_ })
    if ($arguments.Count -ne 8 -or
        [string]$arguments[0] -cne '-NoLogo' -or
        [string]$arguments[1] -cne '-NoProfile' -or
        [string]$arguments[2] -cne '-ExecutionPolicy' -or
        [string]$arguments[3] -cne 'Bypass' -or
        [string]$arguments[4] -cne '-File' -or
        [string]$arguments[5] -cne
            'scripts/windows/phase2/Run-Source-Fixture.ps1' -or
        [string]$arguments[6] -cne '-OutputDirectory' -or
        [string]$arguments[7] -cnotmatch
            '^artifacts/evidence/phase-2/source-[A-Za-z0-9._-]{1,96}/source-fixtures$') {
        throw $failureCode
    }

    $receipt = $Check.source_fixture_receipt
    Assert-SteinPhase2EvidenceShape -Value $receipt `
        -ExpectedProperties @(
            'schema_version', 'claim', 'source_check_id', 'source_fixture_id',
            'source_runner_id', 'gate_id', 'gate_fixture_id', 'gate_runner_id',
            'result', 'bindings', 'environment', 'semantic_sources', 'harnesses',
            'executions', 'subchecks', 'summary') `
        -FailureCode $failureCode
    $sourceSlug = $checkId.Substring('phase2-source-fixture-'.Length)
    if ([long]$receipt.schema_version -ne 1 -or
        [string]$receipt.claim -cne 'closed_source_fixture_only' -or
        [string]$receipt.source_check_id -cne $checkId -or
        [string]$receipt.source_fixture_id -cne "$checkId-v1" -or
        [string]$receipt.source_runner_id -cne
            "stein.phase2.source-fixture.$sourceSlug.v1" -or
        [string]$receipt.gate_id -cne [string]$Gate.gate_id -or
        [string]$receipt.gate_fixture_id -cne [string]$Gate.fixture_id -or
        [string]$receipt.gate_runner_id -cne [string]$Gate.runner_id -or
        [string]$receipt.result -cne 'pass') {
        throw $failureCode
    }
    Assert-SteinPhase2EvidenceShape -Value $Fixture `
        -ExpectedProperties @(
            'source_check_id', 'source_fixture_id', 'source_runner_id',
            'gate_id', 'gate_fixture_id', 'gate_runner_id',
            'semantic_source_paths', 'subchecks') `
        -FailureCode $failureCode
    if ([string]$Fixture.source_check_id -cne $checkId -or
        [string]$Fixture.source_fixture_id -cne [string]$receipt.source_fixture_id -or
        [string]$Fixture.source_runner_id -cne [string]$receipt.source_runner_id -or
        [string]$Fixture.gate_id -cne [string]$receipt.gate_id -or
        [string]$Fixture.gate_fixture_id -cne [string]$receipt.gate_fixture_id -or
        [string]$Fixture.gate_runner_id -cne [string]$receipt.gate_runner_id) {
        throw $failureCode
    }
    Assert-SteinPhase2EvidenceShape -Value $receipt.bindings `
        -ExpectedProperties @(
            'candidate_git_commit', 'candidate_git_tree',
            'candidate_tree_file_count', 'candidate_tree_manifest_sha256',
            'registry_sha256', 'fixture_definition_sha256',
            'semantic_source_manifest_sha256', 'rustup_toolchain',
            'rustup_version', 'rustup_sha256',
            'cargo_launcher_sha256', 'cargo_resolved_sha256',
            'rustc_launcher_sha256', 'rustc_resolved_sha256',
            'git_launcher_version', 'git_launcher_sha256',
            'git_resolved_version', 'git_resolved_sha256',
            'compiler_environment_sha256', 'git_environment_sha256') `
        -FailureCode $failureCode
    foreach ($property in @(
            'candidate_tree_manifest_sha256', 'registry_sha256',
            'fixture_definition_sha256', 'semantic_source_manifest_sha256',
            'cargo_launcher_sha256', 'cargo_resolved_sha256',
            'rustc_launcher_sha256', 'rustc_resolved_sha256',
            'rustup_sha256',
            'git_launcher_sha256', 'git_resolved_sha256',
            'compiler_environment_sha256', 'git_environment_sha256')) {
        Assert-SteinPhase2EvidenceHash `
            -Value $receipt.bindings.$property `
            -FailureCode $failureCode
    }
    if ([string]$receipt.bindings.candidate_git_commit -cne
            [string]$EvidenceResult.bindings.commit.object_id -or
        [string]$receipt.bindings.candidate_git_tree -cne
            [string]$EvidenceResult.bindings.commit.tree_id -or
        [string]$receipt.bindings.registry_sha256 -cne $RegistrySha256 -or
        [string]$receipt.bindings.cargo_launcher_sha256 -cne
            [string]$SourceReport.provenance.toolchain.cargo.executable_sha256 -or
        [string]$receipt.bindings.cargo_resolved_sha256 -cne
            [string]$SourceReport.provenance.toolchain.cargo.resolved_executable_sha256 -or
        [string]$receipt.bindings.rustc_launcher_sha256 -cne
            [string]$SourceReport.provenance.toolchain.rustc.executable_sha256 -or
        [string]$receipt.bindings.rustc_resolved_sha256 -cne
            [string]$SourceReport.provenance.toolchain.rustc.resolved_executable_sha256 -or
        [string]$receipt.bindings.rustup_toolchain -cne
            [string]$SourceReport.provenance.toolchain.cargo.rustup_toolchain -or
        [string]$receipt.bindings.rustup_version -cne
            [string]$SourceReport.provenance.toolchain.rustup.version -or
        [string]$receipt.bindings.rustup_sha256 -cne
            [string]$SourceReport.provenance.toolchain.rustup.executable_sha256 -or
        [string]$receipt.bindings.git_launcher_version -cne
            [string]$SourceReport.provenance.toolchain.git.version -or
        [string]$receipt.bindings.git_launcher_sha256 -cne
            [string]$SourceReport.provenance.toolchain.git.executable_sha256 -or
        [string]$receipt.bindings.git_resolved_version -cne
            [string]$SourceReport.provenance.toolchain.git.resolved_version -or
        [string]$receipt.bindings.git_resolved_sha256 -cne
            [string]$SourceReport.provenance.toolchain.git.resolved_executable_sha256 -or
        [long]$receipt.bindings.candidate_tree_file_count -lt 1 -or
        [long]$receipt.bindings.candidate_tree_file_count -gt 100000) {
        throw $failureCode
    }
    $fixtureDefinitionDigest = Get-SteinPhase2EvidenceTextSha256 `
        -Value ($Fixture | ConvertTo-Json -Depth 32 -Compress)
    if ([string]$receipt.bindings.fixture_definition_sha256 -cne
        $fixtureDefinitionDigest) {
        throw $failureCode
    }
    Assert-SteinPhase2EvidenceShape -Value $receipt.environment `
        -ExpectedProperties @(
            'source', 'target', 'tracked_source_lock', 'working_directory',
            'cargo_home_precondition', 'cargo_home_initial_entry_count',
            'cargo_config_precondition', 'cargo_config_postcondition',
            'effective_compiler_environment', 'effective_git_environment') `
        -FailureCode $failureCode
    if ([string]$receipt.environment.source -cne 'private_exact_git_snapshot' -or
        [string]$receipt.environment.target -cne
            'fresh_private_shared_suite_target' -or
        [string]$receipt.environment.tracked_source_lock -cne
            'all_candidate_files_held_read_only' -or
        [string]$receipt.environment.working_directory -cne '.' -or
        [string]$receipt.environment.cargo_home_precondition -cne
            'fresh_private_owner_only_empty' -or
        [string]$receipt.environment.cargo_config_precondition -cne
            'execution_and_snapshot_ancestor_configs_absent' -or
        [string]$receipt.environment.cargo_config_postcondition -cne
            'execution_and_snapshot_ancestor_configs_absent' -or
        [long]$receipt.environment.cargo_home_initial_entry_count -ne 0) {
        throw $failureCode
    }
    $expectedCompilerEnvironment = [ordered]@{
        CARGO_HOME = 'fresh_private_owner_only_empty_at_suite_start'
        CARGO_INCREMENTAL = '0'
        CARGO_TARGET_DIR = 'fresh_private_shared_suite_target'
        CARGO_BUILD_TARGET_DIR = 'cleared'
        CARGO_TERM_COLOR = 'never'
        CARGO_BUILD_RUSTC = 'resolved_rustc_payload'
        CARGO_BUILD_RUSTC_WRAPPER = 'cleared'
        CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER = 'cleared'
        RUSTC = 'resolved_rustc_payload'
        RUSTC_WRAPPER = 'cleared'
        RUSTC_WORKSPACE_WRAPPER = 'cleared'
        RUSTFLAGS = 'cleared'
        CARGO_ENCODED_RUSTFLAGS = 'cleared'
        RUSTUP_TOOLCHAIN = [string]$receipt.bindings.rustup_toolchain
        UNREGISTERED_TOOL_OVERRIDE_PREFIXES = 'cleared'
        PATH_SHA256 = [string]$receipt.environment.effective_compiler_environment.PATH_SHA256
    }
    Assert-SteinPhase2EvidenceShape `
        -Value $receipt.environment.effective_compiler_environment `
        -ExpectedProperties @($expectedCompilerEnvironment.Keys) `
        -FailureCode $failureCode
    foreach ($environmentName in $expectedCompilerEnvironment.Keys) {
        if ([string]$receipt.environment.effective_compiler_environment.$environmentName -cne
            [string]$expectedCompilerEnvironment[$environmentName]) {
            throw $failureCode
        }
    }
    if ((Get-SteinPhase2EvidenceTextSha256 -Value (
                $receipt.environment.effective_compiler_environment |
                    ConvertTo-Json -Depth 8 -Compress)) -cne
        [string]$receipt.bindings.compiler_environment_sha256) {
        throw $failureCode
    }
    Assert-SteinPhase2EvidenceHash `
        -Value $receipt.environment.effective_compiler_environment.PATH_SHA256 `
        -FailureCode $failureCode
    $expectedGitEnvironment = [ordered]@{
        GIT_CONFIG_NOSYSTEM = '1'
        GIT_CONFIG_GLOBAL = 'NUL'
        GIT_CONFIG_COUNT = '0'
        GIT_NO_REPLACE_OBJECTS = '1'
        GIT_TERMINAL_PROMPT = '0'
        GIT_OPTIONAL_LOCKS = '0'
        OTHER_GIT_ENVIRONMENT = 'cleared'
        PATH_SHA256 = [string]$receipt.environment.effective_compiler_environment.PATH_SHA256
    }
    Assert-SteinPhase2EvidenceShape `
        -Value $receipt.environment.effective_git_environment `
        -ExpectedProperties @($expectedGitEnvironment.Keys) `
        -FailureCode $failureCode
    foreach ($environmentName in $expectedGitEnvironment.Keys) {
        if ([string]$receipt.environment.effective_git_environment.$environmentName -cne
            [string]$expectedGitEnvironment[$environmentName]) {
            throw $failureCode
        }
    }
    if ((Get-SteinPhase2EvidenceTextSha256 -Value (
                $receipt.environment.effective_git_environment |
                    ConvertTo-Json -Depth 8 -Compress)) -cne
        [string]$receipt.bindings.git_environment_sha256) {
        throw $failureCode
    }

    $semanticSources = @($receipt.semantic_sources)
    $expectedSemanticPaths = @(
        $Fixture.semantic_source_paths | ForEach-Object { [string]$_ })
    if ($semanticSources.Count -ne $expectedSemanticPaths.Count) {
        throw $failureCode
    }
    $semanticPaths = New-Object Collections.Generic.List[string]
    for ($sourceIndex = 0; $sourceIndex -lt $semanticSources.Count; $sourceIndex++) {
        $source = $semanticSources[$sourceIndex]
        Assert-SteinPhase2EvidenceShape -Value $source `
            -ExpectedProperties @('path', 'size', 'sha256', 'git_blob_object_id') `
            -FailureCode $failureCode
        if ([string]$source.path -cne $expectedSemanticPaths[$sourceIndex] -or
            [string]$source.path -cnotmatch
                '^(?!.*(?:^|/)\.\.?/)[A-Za-z0-9._/-]{1,512}$' -or
            [IO.Path]::IsPathRooted([string]$source.path) -or
            ($source.size -isnot [int] -and $source.size -isnot [long]) -or
            [long]$source.size -lt 1 -or
            [string]$source.git_blob_object_id -cnotmatch
                '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
            throw $failureCode
        }
        Assert-SteinPhase2EvidenceHash -Value $source.sha256 -FailureCode $failureCode
        $semanticPaths.Add([string]$source.path)
    }
    if ($semanticPaths.Count -lt 2 -or
        @($semanticPaths | Select-Object -Unique).Count -ne $semanticPaths.Count -or
        (Get-SteinPhase2EvidenceTextSha256 -Value (
                $semanticSources | ConvertTo-Json -Depth 16 -Compress)) -cne
            [string]$receipt.bindings.semantic_source_manifest_sha256) {
        throw $failureCode
    }

    $expectedHarnesses = New-Object Collections.Generic.List[object]
    $expectedHarnessIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($fixtureSubcheck in @($Fixture.subchecks)) {
        foreach ($fixtureInvocation in @($fixtureSubcheck.invocations)) {
            $fixtureCommand = Get-SteinPhase2SourceFixtureCommandDefinition `
                -Invocation $fixtureInvocation
            if ($null -ne $fixtureCommand.harness -and
                $expectedHarnessIds.Add([string]$fixtureCommand.harness.harness_id)) {
                $expectedHarnesses.Add($fixtureCommand.harness)
            }
        }
    }
    $harnesses = @($receipt.harnesses)
    if ($harnesses.Count -ne $expectedHarnesses.Count) {
        throw $failureCode
    }
    $harnessById = @{}
    for ($harnessIndex = 0; $harnessIndex -lt $harnesses.Count; $harnessIndex++) {
        $harness = $harnesses[$harnessIndex]
        $expectedHarness = $expectedHarnesses[$harnessIndex]
        Assert-SteinPhase2EvidenceShape -Value $harness `
            -ExpectedProperties @(
                'harness_id', 'package', 'target_kind', 'target_name',
                'manifest_path', 'binary', 'compile') `
            -FailureCode $failureCode
        $harnessId = [string]$harness.harness_id
        if ($harnessId -cnotmatch '^cargo-harness-[a-z0-9-]{8,127}$' -or
            $harnessById.ContainsKey($harnessId) -or
            [string]$harness.package -cnotmatch '^[a-z][a-z0-9-]{2,63}$' -or
            [string]$harness.target_kind -cnotin @('lib', 'test', 'bin') -or
            [string]$harness.target_name -cnotmatch '^[A-Za-z0-9_-]{1,96}$' -or
            [string]$harness.manifest_path -cnotmatch
                '^[A-Za-z0-9._/-]{1,256}/Cargo\.toml$' -or
            [IO.Path]::IsPathRooted([string]$harness.manifest_path)) {
            throw $failureCode
        }
        if ($harnessId -cne [string]$expectedHarness.harness_id -or
            [string]$harness.package -cne [string]$expectedHarness.package -or
            [string]$harness.target_kind -cne [string]$expectedHarness.target_kind -or
            [string]$harness.target_name -cne [string]$expectedHarness.target_name -or
            [string]$harness.manifest_path -cne [string]$expectedHarness.manifest_path) {
            throw $failureCode
        }
        Assert-SteinPhase2EvidenceShape -Value $harness.binary `
            -ExpectedProperties @('size', 'sha256') `
            -FailureCode $failureCode
        Assert-SteinPhase2EvidenceHash -Value $harness.binary.sha256 `
            -FailureCode $failureCode
        if ([long]$harness.binary.size -lt 1 -or
            [long]$harness.binary.size -gt 2147483648) {
            throw $failureCode
        }
        Assert-SteinPhase2EvidenceShape -Value $harness.compile `
            -ExpectedProperties @(
                'executable', 'arguments', 'working_directory', 'exit_code',
                'stdout', 'stderr', 'compiler_artifact_matches') `
            -FailureCode $failureCode
        $compileArguments = @($harness.compile.arguments | ForEach-Object { [string]$_ })
        if ([string]$harness.compile.executable -cne 'cargo.exe' -or
            [string]$harness.compile.working_directory -cne '.' -or
            [long]$harness.compile.exit_code -ne 0 -or
            [long]$harness.compile.compiler_artifact_matches -ne 1 -or
            $compileArguments.Count -ne @($expectedHarness.compile_arguments).Count -or
            @(Compare-Object `
                    -ReferenceObject @($expectedHarness.compile_arguments) `
                    -DifferenceObject $compileArguments `
                    -CaseSensitive `
                    -SyncWindow 0).Count -ne 0) {
            throw $failureCode
        }
        foreach ($output in @($harness.compile.stdout, $harness.compile.stderr)) {
            Assert-SteinPhase2EvidenceShape -Value $output `
                -ExpectedProperties @('size', 'sha256') `
                -FailureCode $failureCode
            Assert-SteinPhase2EvidenceHash -Value $output.sha256 -FailureCode $failureCode
            if ([long]$output.size -lt 0 -or [long]$output.size -gt 16777216) {
                throw $failureCode
            }
        }
        $harnessById[$harnessId] = $harness
    }
    if ($harnesses.Count -lt 1 -or $harnesses.Count -gt 8) {
        throw $failureCode
    }

    $expectedExecutionOrder = New-Object Collections.Generic.List[string]
    $expectedInvocationById = @{}
    $expectedSubcheckExecutionIds = New-Object Collections.Generic.List[object]
    foreach ($fixtureSubcheck in @($Fixture.subchecks)) {
        $subcheckExecutionIds = New-Object Collections.Generic.List[string]
        foreach ($fixtureInvocation in @($fixtureSubcheck.invocations)) {
            $executionId = Get-SteinPhase2SourceFixtureInvocationId `
                -Invocation $fixtureInvocation
            $subcheckExecutionIds.Add($executionId)
            if (-not $expectedInvocationById.ContainsKey($executionId)) {
                $expectedInvocationById[$executionId] = $fixtureInvocation
                $expectedExecutionOrder.Add($executionId)
            }
        }
        $expectedSubcheckExecutionIds.Add(
            @($subcheckExecutionIds | ForEach-Object { $_ }))
    }
    $executions = @($receipt.executions)
    if ($executions.Count -ne $expectedExecutionOrder.Count) {
        throw $failureCode
    }
    $executionById = @{}
    $cargoExecutionCount = 0
    $boundaryExecutionCount = 0
    for ($executionIndex = 0; $executionIndex -lt $executions.Count; $executionIndex++) {
        $execution = $executions[$executionIndex]
        $expectedExecutionId = [string]$expectedExecutionOrder[$executionIndex]
        $expectedInvocation = $expectedInvocationById[$expectedExecutionId]
        $expectedCommand = Get-SteinPhase2SourceFixtureCommandDefinition `
            -Invocation $expectedInvocation
        $isBoundary = [string]$expectedInvocation.kind -ceq 'boundary'
        $properties = @(
            'execution_id', 'sequence', 'kind', 'qualified_test_name',
            'executable', 'arguments', 'working_directory', 'execution')
        if (-not $isBoundary) {
            $properties += @('harness_id', 'registered_cargo_arguments', 'preflight')
        }
        else {
            $properties += @('nested_tool')
        }
        Assert-SteinPhase2EvidenceShape -Value $execution `
            -ExpectedProperties $properties `
            -FailureCode $failureCode
        $executionId = [string]$execution.execution_id
        if ($executionId -cne $expectedExecutionId -or
            $executionId -cnotmatch '^source-invocation-[0-9a-f]{24}$' -or
            $executionById.ContainsKey($executionId) -or
            [long]$execution.sequence -ne ($executionIndex + 1) -or
            [string]$execution.working_directory -cne '.' -or
            [string]$execution.qualified_test_name -cne
                [string]$expectedCommand.qualified_name) {
            throw $failureCode
        }
        if ($isBoundary) {
            Assert-SteinPhase2EvidenceShape -Value $execution.execution `
                -ExpectedProperties @(
                    'exit_code', 'stdout', 'stderr', 'passed_checks',
                    'failed_checks') `
                -FailureCode $failureCode
            $boundaryArguments = @($execution.arguments | ForEach-Object { [string]$_ })
            $expectedBoundaryArguments = @($expectedCommand.arguments)
            if ([string]$execution.executable -cne 'powershell.exe' -or
                [string]$receipt.gate_id -cne 'P2-MODEL-CONTRACT' -or
                [string]$execution.qualified_test_name -cne 'boundary_contract' -or
                @(Compare-Object `
                        -ReferenceObject $expectedBoundaryArguments `
                        -DifferenceObject $boundaryArguments `
                        -CaseSensitive `
                        -SyncWindow 0).Count -ne 0 -or
                [long]$execution.execution.exit_code -ne 0 -or
                [long]$execution.execution.passed_checks -ne 4 -or
                [long]$execution.execution.failed_checks -ne 0) {
                throw $failureCode
            }
            Assert-SteinPhase2EvidenceShape -Value $execution.nested_tool `
                -ExpectedProperties @(
                    'executable', 'sha256', 'arguments', 'working_directory') `
                -FailureCode $failureCode
            Assert-SteinPhase2EvidenceHash `
                -Value $execution.nested_tool.sha256 `
                -FailureCode $failureCode
            $expectedNestedArguments = @(
                'metadata', '--locked', '--no-deps', '--format-version', '1',
                '--manifest-path', 'Cargo.toml')
            if ([string]$execution.nested_tool.executable -cne
                    'resolved_cargo_payload' -or
                [string]$execution.nested_tool.sha256 -cne
                    [string]$receipt.bindings.cargo_resolved_sha256 -or
                [string]$execution.nested_tool.working_directory -cne
                    'validated_config_free_system_directory' -or
                @(Compare-Object `
                        -ReferenceObject $expectedNestedArguments `
                        -DifferenceObject @($execution.nested_tool.arguments) `
                        -CaseSensitive `
                        -SyncWindow 0).Count -ne 0 -or
                [long]$execution.execution.stderr.size -ne 0) {
                throw $failureCode
            }
            $boundaryExecutionCount++
        }
        else {
            $harnessId = [string]$execution.harness_id
            $directArguments = @($execution.arguments | ForEach-Object { [string]$_ })
            $registeredArguments = @(
                $execution.registered_cargo_arguments | ForEach-Object { [string]$_ })
            $preflightArguments = @(
                $execution.preflight.arguments | ForEach-Object { [string]$_ })
            Assert-SteinPhase2EvidenceShape -Value $execution.preflight `
                -ExpectedProperties @(
                    'exit_code', 'arguments', 'stdout', 'stderr',
                    'exact_test_matches') `
                -FailureCode $failureCode
            Assert-SteinPhase2EvidenceShape -Value $execution.execution `
                -ExpectedProperties @(
                    'exit_code', 'stdout', 'stderr', 'passed_tests', 'failed_tests') `
                -FailureCode $failureCode
            if (-not $harnessById.ContainsKey($harnessId)) {
                throw $failureCode
            }
            $harness = $harnessById[$harnessId]
            $registeredTargetArguments = @(switch ([string]$harness.target_kind) {
                    'lib' { '--lib' }
                    'test' { '--test'; [string]$harness.target_name }
                    'bin' { '--bin'; [string]$harness.target_name }
                    default { }
                })
            $expectedRegisteredArguments = @($expectedCommand.arguments)
            if ([string]$execution.executable -cne 'locked_test_binary' -or
                [string]$execution.harness_id -cne
                    [string]$expectedCommand.harness.harness_id -or
                $directArguments.Count -ne 3 -or
                $directArguments[0] -cne [string]$execution.qualified_test_name -or
                $directArguments[1] -cne '--exact' -or
                $directArguments[2] -cne '--test-threads=1' -or
                $preflightArguments.Count -ne 3 -or
                $preflightArguments[0] -cne [string]$execution.qualified_test_name -or
                $preflightArguments[1] -cne '--exact' -or
                $preflightArguments[2] -cne '--list' -or
                @(Compare-Object `
                        -ReferenceObject $expectedRegisteredArguments `
                        -DifferenceObject $registeredArguments `
                        -CaseSensitive `
                        -SyncWindow 0).Count -ne 0 -or
                [long]$execution.preflight.exit_code -ne 0 -or
                [long]$execution.preflight.exact_test_matches -ne 1 -or
                [long]$execution.execution.exit_code -ne 0 -or
                [long]$execution.execution.passed_tests -ne 1 -or
                [long]$execution.execution.failed_tests -ne 0 -or
                [long]$execution.preflight.stderr.size -ne 0 -or
                [long]$execution.execution.stderr.size -ne 0) {
                throw $failureCode
            }
            $cargoExecutionCount++
        }
        foreach ($output in @(
                $execution.execution.stdout, $execution.execution.stderr) +
            $(if ($isBoundary) { @() } else {
                    @($execution.preflight.stdout, $execution.preflight.stderr)
                })) {
            Assert-SteinPhase2EvidenceShape -Value $output `
                -ExpectedProperties @('size', 'sha256') `
                -FailureCode $failureCode
            Assert-SteinPhase2EvidenceHash -Value $output.sha256 -FailureCode $failureCode
            if ([long]$output.size -lt 0 -or [long]$output.size -gt 16777216) {
                throw $failureCode
            }
        }
        $executionById[$executionId] = $execution
    }
    if ($executions.Count -lt 1 -or $executions.Count -gt 128) {
        throw $failureCode
    }

    $expectedSourceSubchecks = New-Object Collections.Generic.List[string]
    foreach ($sourceSubcheckId in @($Gate.source_subchecks)) {
        $mapping = $Gate.source_subcheck_check_ids.PSObject.Properties[
            [string]$sourceSubcheckId]
        if ($null -ne $mapping -and $checkId -cin @($mapping.Value)) {
            $expectedSourceSubchecks.Add([string]$sourceSubcheckId)
        }
    }
    $subchecks = @($receipt.subchecks)
    $fixtureSubchecks = @($Fixture.subchecks)
    if ($subchecks.Count -ne $expectedSourceSubchecks.Count -or
        $fixtureSubchecks.Count -ne $expectedSourceSubchecks.Count) {
        throw $failureCode
    }
    $referencedExecutions = @{}
    $mappingCount = 0
    for ($subcheckIndex = 0; $subcheckIndex -lt $subchecks.Count; $subcheckIndex++) {
        $subcheck = $subchecks[$subcheckIndex]
        Assert-SteinPhase2EvidenceShape -Value $subcheck `
            -ExpectedProperties @('id', 'result', 'execution_ids') `
            -FailureCode $failureCode
        $executionIds = @($subcheck.execution_ids | ForEach-Object { [string]$_ })
        if ([string]$subcheck.id -cne
                [string]$expectedSourceSubchecks[$subcheckIndex] -or
            [string]$subcheck.id -cne
                [string]$fixtureSubchecks[$subcheckIndex].id -or
            [string]$subcheck.result -cne 'pass' -or
            $executionIds.Count -lt 1 -or
            @($executionIds | Select-Object -Unique).Count -ne $executionIds.Count -or
            @(Compare-Object `
                    -ReferenceObject @($expectedSubcheckExecutionIds[$subcheckIndex]) `
                    -DifferenceObject $executionIds `
                    -CaseSensitive `
                    -SyncWindow 0).Count -ne 0) {
            throw $failureCode
        }
        foreach ($executionId in $executionIds) {
            if (-not $executionById.ContainsKey($executionId)) {
                throw $failureCode
            }
            $referencedExecutions[$executionId] = $true
            $mappingCount++
        }
    }
    if ($referencedExecutions.Count -ne $executionById.Count) {
        throw $failureCode
    }
    Assert-SteinPhase2EvidenceShape -Value $receipt.summary `
        -ExpectedProperties @(
            'subcheck_count', 'harness_count', 'invocation_mapping_count',
            'unique_execution_count', 'cargo_test_execution_count',
            'boundary_execution_count') `
        -FailureCode $failureCode
    if ([long]$receipt.summary.subcheck_count -ne $subchecks.Count -or
        [long]$receipt.summary.harness_count -ne $harnesses.Count -or
        [long]$receipt.summary.invocation_mapping_count -ne $mappingCount -or
        [long]$receipt.summary.unique_execution_count -ne $executions.Count -or
        [long]$receipt.summary.cargo_test_execution_count -ne $cargoExecutionCount -or
        [long]$receipt.summary.boundary_execution_count -ne $boundaryExecutionCount) {
        throw $failureCode
    }

    foreach ($descriptorCase in @(
            [pscustomobject]@{
                value = $Check.source_fixture_receipt_artifact
                path = "source-fixtures/$checkId.receipt.json"
                maximum = 4194304
            },
            [pscustomobject]@{
                value = $Check.source_fixture_suite_index
                path = 'source-fixtures/index.json'
                maximum = 1048576
            })) {
        Assert-SteinPhase2EvidenceShape -Value $descriptorCase.value `
            -ExpectedProperties @('path', 'size', 'sha256') `
            -FailureCode $failureCode
        Assert-SteinPhase2EvidenceHash -Value $descriptorCase.value.sha256 `
            -FailureCode $failureCode
        if ([string]$descriptorCase.value.path -cne $descriptorCase.path -or
            [long]$descriptorCase.value.size -lt 1 -or
            [long]$descriptorCase.value.size -gt $descriptorCase.maximum) {
            throw $failureCode
        }
    }
    return $true
}

function Get-SteinPhase2SourceCommandArgumentSha256 {
    param(
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)][string[]] $Arguments
    )

    $records = New-Object Collections.Generic.List[string]
    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        $value = [string]$Arguments[$index]
        if ($value.Length -lt 1 -or $value.Length -gt 512 -or
            $value -match '[\x00-\x1f\s"''&|;<>`$(){}\[\]!?*\\:]' -or
            $value.StartsWith('/')) {
            throw 'source_command_argument_invalid'
        }
        $length = [Text.UTF8Encoding]::new($false).GetByteCount($value)
        $records.Add("$index|$length`:$value")
    }
    return Get-SteinPhase2EvidenceTextSha256 `
        -Value ($records.ToArray() -join "`n")
}

function Get-SteinPhase2SourceCommandEnvironmentSha256 {
    param([Parameter(Mandatory = $true)][string] $Profile)

    if ($Profile -cnotin @(
            'phase2_synthetic_compile_v1', 'phase2_source_fixture_v1')) {
        throw 'source_command_environment_invalid'
    }
    $values = [ordered]@{
        STEIN_CORE_EXECUTABLE_SHA256 =
            '1111111111111111111111111111111111111111111111111111111111111111'
        STEIN_PRODUCTION_PACKAGE_FAMILY_NAME =
            'STEIN.PersonalIntelligence_123456789abcd'
        STEIN_PRODUCTION_BROKER_AUMID =
            'STEIN.PersonalIntelligence_123456789abcd!PrivateBroker'
        STEIN_EDGE_EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop'
        STEIN_EDGE_EXTENSION_VERSION = '0.1.0'
        STEIN_EDGE_PUBLISHER_SHA256 =
            '2222222222222222222222222222222222222222222222222222222222222222'
        STEIN_EDGE_HOST_PUBLISHER_SHA256 =
            '3333333333333333333333333333333333333333333333333333333333333333'
    }
    return Get-SteinPhase2EvidenceObjectSha256 -Value ([ordered]@{
            profile = $Profile
            values = $values
        })
}

function ConvertFrom-SteinPhase2SourceCommandTimestamp {
    param([AllowNull()] $Value)

    if ($Value -isnot [string] -or
        $Value -cnotmatch
            '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$') {
        throw 'source_command_timestamp_invalid'
    }
    $parsed = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$Value,
            "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            $styles,
            [ref]$parsed)) {
        throw 'source_command_timestamp_invalid'
    }
    return $parsed
}

function Get-SteinPhase2SourceCommandExpectedArguments {
    param(
        [Parameter(Mandatory = $true)] $RegistryCheck,
        [Parameter(Mandatory = $true)][string] $EvidenceRootRelative
    )

    $result = New-Object Collections.Generic.List[string]
    foreach ($argument in @($RegistryCheck.arguments)) {
        $kind = [string]$argument.kind
        $value = [string]$argument.value
        if ($kind -ceq 'literal' -or $kind -ceq 'repository_relative_path') {
            $result.Add($value)
        }
        elseif ($kind -ceq 'evidence_relative_path') {
            $combined = "$EvidenceRootRelative/$value"
            if (-not (Test-SteinPhase2SourceCommandRelativePath `
                    -Value $combined)) {
                throw 'source_command_argument_invalid'
            }
            $result.Add($combined)
        }
        else {
            throw 'source_command_argument_invalid'
        }
    }
    return $result.ToArray()
}

function Assert-SteinPhase2SourceCommandDescriptor {
    param(
        [Parameter(Mandatory = $true)] $Descriptor,
        [Parameter(Mandatory = $true)][string] $ExpectedPath,
        [long] $MinimumSize = 0,
        [long] $MaximumSize = 16777216,
        [string] $FailureCode = 'source_command_evidence_invalid'
    )

    Assert-SteinPhase2EvidenceShape -Value $Descriptor `
        -ExpectedProperties @('path', 'size', 'sha256') `
        -FailureCode $FailureCode
    Assert-SteinPhase2EvidenceHash `
        -Value $Descriptor.sha256 `
        -FailureCode $FailureCode
    if ([string]$Descriptor.path -cne $ExpectedPath -or
        ($Descriptor.size -isnot [int] -and
            $Descriptor.size -isnot [long]) -or
        [long]$Descriptor.size -lt $MinimumSize -or
        [long]$Descriptor.size -gt $MaximumSize) {
        throw $FailureCode
    }
}

function Assert-SteinPhase2SourceCommandEvidence {
    param(
        [Parameter(Mandatory = $true)] $EvidenceResult,
        [Parameter(Mandatory = $true)] $SourceReport,
        [Parameter(Mandatory = $true)] $EvidenceSpecification,
        [Parameter(Mandatory = $true)] $SourceCommandRegistry,
        [Parameter(Mandatory = $true)][string] $SourceCommandRegistrySha256,
        [Parameter(Mandatory = $true)] $SourceGeneratorByPath
    )

    $failureCode = 'source_command_evidence_invalid'
    $registryContract = Assert-SteinPhase2SourceCommandRegistry `
        -Registry $SourceCommandRegistry
    $catalog = $registryContract.catalog
    $registryPath = 'scripts/windows/phase2/Source-Command-Registry.json'
    $runnerPath = 'scripts/windows/phase2/Run-Source-Check.ps1'
    if (-not $SourceGeneratorByPath.ContainsKey($registryPath) -or
        -not $SourceGeneratorByPath.ContainsKey($runnerPath) -or
        [string]$SourceCommandRegistrySha256 -cne
            [string]$EvidenceSpecification.source_report_contract.source_command_registry_sha256 -or
        [string]$SourceGeneratorByPath[$registryPath].sha256 -cne
            $SourceCommandRegistrySha256) {
        throw $failureCode
    }
    $runnerSha256 = [string]$SourceGeneratorByPath[$runnerPath].sha256
    Assert-SteinPhase2EvidenceHash -Value $runnerSha256 `
        -FailureCode $failureCode
    try {
        $reportStartedAt = ConvertFrom-SteinPhase2SourceCommandTimestamp `
            -Value $SourceReport.started_at
        $reportCompletedAt = ConvertFrom-SteinPhase2SourceCommandTimestamp `
            -Value $SourceReport.completed_at
    }
    catch {
        throw $failureCode
    }
    if ($reportCompletedAt -lt $reportStartedAt) {
        throw $failureCode
    }

    $reportChecks = @($SourceReport.checks)
    if ($reportChecks.Count -ne 44) {
        throw $failureCode
    }
    $reportById = @{}
    for ($index = 0; $index -lt $reportChecks.Count; $index++) {
        $id = [string]$reportChecks[$index].id
        if ($id -cne [string]$catalog.Ordered[$index] -or
            $reportById.ContainsKey($id)) {
            throw $failureCode
        }
        $reportById[$id] = $reportChecks[$index]
    }

    $provenanceRow = $reportById['source-report-command-provenance']
    Assert-SteinPhase2EvidenceShape -Value $provenanceRow `
        -ExpectedProperties @(
            'id', 'status', 'derivation', 'registry_sha256', 'runner_sha256',
            'executed_check_count', 'execution_group_count',
            'source_command_receipt_index',
            'source_command_receipt_index_artifact', 'failure_summary') `
        -FailureCode $failureCode
    if ([string]$provenanceRow.status -cne 'pass' -or
        [string]$provenanceRow.derivation -cne
            'exact_registry_and_receipt_coverage' -or
        [string]$provenanceRow.registry_sha256 -cne
            $SourceCommandRegistrySha256 -or
        [string]$provenanceRow.runner_sha256 -cne $runnerSha256 -or
        ($provenanceRow.executed_check_count -isnot [int] -and
            $provenanceRow.executed_check_count -isnot [long]) -or
        [long]$provenanceRow.executed_check_count -ne 37 -or
        ($provenanceRow.execution_group_count -isnot [int] -and
            $provenanceRow.execution_group_count -isnot [long]) -or
        [long]$provenanceRow.execution_group_count -ne 25 -or
        $null -ne $provenanceRow.failure_summary -or
        $null -ne $provenanceRow.PSObject.Properties['source_command_receipt'] -or
        $null -ne $provenanceRow.PSObject.Properties['source_command_receipt_artifact']) {
        throw $failureCode
    }
    Assert-SteinPhase2SourceCommandDescriptor `
        -Descriptor $provenanceRow.source_command_receipt_index_artifact `
        -ExpectedPath 'source-command-receipts/index.json' `
        -MinimumSize 1 `
        -MaximumSize 1048576 `
        -FailureCode $failureCode

    foreach ($nonExecutableId in @(
            @($catalog.Retained) + @('source-provenance-stability'))) {
        $row = $reportById[[string]$nonExecutableId]
        foreach ($propertyName in @(
                'source_command_receipt', 'source_command_receipt_artifact',
                'source_command_receipt_index',
                'source_command_receipt_index_artifact')) {
            if ($null -ne $row.PSObject.Properties[$propertyName]) {
                throw $failureCode
            }
        }
    }

    $indexValue = $provenanceRow.source_command_receipt_index
    Assert-SteinPhase2EvidenceShape -Value $indexValue `
        -ExpectedProperties @(
            'schema_version', 'claim', 'registry_id', 'bindings',
            'executed_check_count', 'execution_group_count', 'receipts') `
        -FailureCode $failureCode
    Assert-SteinPhase2EvidenceShape -Value $indexValue.bindings `
        -ExpectedProperties @(
            'candidate_commit', 'candidate_tree', 'candidate_file_count',
            'candidate_manifest_sha256', 'git_launcher_sha256',
            'git_resolved_sha256', 'registry_sha256', 'runner_sha256',
            'evidence_root_sha256') `
        -FailureCode $failureCode
    $common = $indexValue.bindings
    $reportGit = $SourceReport.provenance.toolchain.git
    if (($indexValue.schema_version -isnot [int] -and
            $indexValue.schema_version -isnot [long]) -or
        [long]$indexValue.schema_version -ne 1 -or
        [string]$indexValue.claim -cne
            'closed_source_command_receipt_index' -or
        [string]$indexValue.registry_id -cne
            'stein.phase2.source-command-registry.v1' -or
        ($indexValue.executed_check_count -isnot [int] -and
            $indexValue.executed_check_count -isnot [long]) -or
        [long]$indexValue.executed_check_count -ne 37 -or
        ($indexValue.execution_group_count -isnot [int] -and
            $indexValue.execution_group_count -isnot [long]) -or
        [long]$indexValue.execution_group_count -ne 25 -or
        [string]$common.candidate_commit -cne
            [string]$EvidenceResult.bindings.commit.object_id -or
        [string]$common.candidate_tree -cne
            [string]$EvidenceResult.bindings.commit.tree_id -or
        ($common.candidate_file_count -isnot [int] -and
            $common.candidate_file_count -isnot [long]) -or
        [long]$common.candidate_file_count -lt 1 -or
        [long]$common.candidate_file_count -gt 1000000 -or
        [string]$common.git_launcher_sha256 -cne
            [string]$reportGit.executable_sha256 -or
        [string]$common.git_resolved_sha256 -cne
            [string]$reportGit.resolved_executable_sha256 -or
        [string]$common.registry_sha256 -cne $SourceCommandRegistrySha256 -or
        [string]$common.runner_sha256 -cne $runnerSha256) {
        throw $failureCode
    }
    foreach ($propertyName in @(
            'candidate_manifest_sha256', 'git_launcher_sha256',
            'git_resolved_sha256', 'evidence_root_sha256')) {
        Assert-SteinPhase2EvidenceHash -Value $common.$propertyName `
            -FailureCode $failureCode
    }

    $firstGrouped = $reportById[[string]$catalog.Grouped[0]]
    $firstGroupedArguments = @(
        $firstGrouped.source_command_receipt.command.arguments |
            ForEach-Object { [string]$_ })
    if ($firstGroupedArguments.Count -lt 1) {
        throw $failureCode
    }
    $fixtureArgument = [string]$firstGroupedArguments[
        $firstGroupedArguments.Count - 1]
    $fixtureSuffix = '/source-fixtures'
    if (-not $fixtureArgument.EndsWith(
            $fixtureSuffix, [StringComparison]::Ordinal) -or
        $fixtureArgument.Length -le $fixtureSuffix.Length) {
        throw $failureCode
    }
    $evidenceRootRelative = $fixtureArgument.Substring(
        0, $fixtureArgument.Length - $fixtureSuffix.Length)
    if (-not (Test-SteinPhase2SourceCommandRelativePath `
            -Value $evidenceRootRelative) -or
        -not $evidenceRootRelative.StartsWith(
            'artifacts/evidence/phase-2/', [StringComparison]::Ordinal) -or
        (Get-SteinPhase2EvidenceTextSha256 -Value $evidenceRootRelative) -cne
            [string]$common.evidence_root_sha256) {
        throw $failureCode
    }

    $indexDescriptors = @($indexValue.receipts)
    $executedChecks = @($SourceCommandRegistry.checks | Where-Object {
            [string]$_.category -cin @(
                'direct_execution', 'grouped_fixture_execution')
        })
    if ($executedChecks.Count -ne 37 -or
        $indexDescriptors.Count -ne 37) {
        throw $failureCode
    }
    $executionGroups = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $directExecutionIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $expectedLogPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $toolByRole = @{}
    $groupedIdentity = $null
    $groupedExecutionId = $null

    for ($position = 0; $position -lt $executedChecks.Count; $position++) {
        $definition = $executedChecks[$position]
        $id = [string]$definition.id
        $category = [string]$definition.category
        $row = $reportById[$id]
        $rowProperties = @(
            'id', 'status', 'executable', 'arguments', 'working_directory',
            'started_at', 'completed_at', 'duration_ms', 'exit_code',
            'failure_summary', 'stdout', 'stderr', 'source_command_receipt',
            'source_command_receipt_artifact')
        if ($category -ceq 'grouped_fixture_execution') {
            $rowProperties += @(
                'source_fixture_receipt', 'source_fixture_receipt_artifact',
                'source_fixture_suite_index')
        }
        Assert-SteinPhase2EvidenceShape -Value $row `
            -ExpectedProperties $rowProperties `
            -FailureCode $failureCode
        $receipt = $row.source_command_receipt
        $artifact = $row.source_command_receipt_artifact
        Assert-SteinPhase2SourceCommandDescriptor `
            -Descriptor $artifact `
            -ExpectedPath "source-command-receipts/$id.receipt.json" `
            -MinimumSize 1 `
            -MaximumSize 1048576 `
            -FailureCode $failureCode
        $descriptor = $indexDescriptors[$position]
        Assert-SteinPhase2EvidenceShape -Value $descriptor `
            -ExpectedProperties @('check_id', 'category', 'path', 'size', 'sha256') `
            -FailureCode $failureCode
        if ([string]$descriptor.check_id -cne $id -or
            [string]$descriptor.category -cne $category -or
            [string]$descriptor.path -cne "$id.receipt.json" -or
            ($descriptor.size -isnot [int] -and
                $descriptor.size -isnot [long]) -or
            [long]$descriptor.size -lt 1 -or
            [long]$descriptor.size -gt 1048576 -or
            [long]$descriptor.size -ne [long]$artifact.size -or
            [string]$descriptor.sha256 -cne [string]$artifact.sha256) {
            throw $failureCode
        }
        Assert-SteinPhase2EvidenceHash -Value $descriptor.sha256 `
            -FailureCode $failureCode

        Assert-SteinPhase2EvidenceShape -Value $receipt `
            -ExpectedProperties @(
                'schema_version', 'claim', 'check_id', 'category', 'status',
                'bindings', 'command', 'execution', 'artifacts',
                'obligation_code', 'derivation') `
            -FailureCode $failureCode
        Assert-SteinPhase2EvidenceShape -Value $receipt.bindings `
            -ExpectedProperties @(
                'candidate_commit', 'candidate_tree', 'candidate_file_count',
                'candidate_manifest_sha256', 'git_launcher_sha256',
                'git_resolved_sha256', 'registry_sha256', 'runner_sha256',
                'evidence_root_sha256', 'check_definition_sha256',
                'execution_group_count') `
            -FailureCode $failureCode
        $bindings = $receipt.bindings
        if (($receipt.schema_version -isnot [int] -and
                $receipt.schema_version -isnot [long]) -or
            [long]$receipt.schema_version -ne 1 -or
            [string]$receipt.claim -cne
                'closed_source_command_execution_only' -or
            [string]$receipt.check_id -cne $id -or
            [string]$receipt.category -cne $category -or
            [string]$receipt.status -cne 'pass' -or
            [string]$row.status -cne 'pass' -or
            $null -ne $receipt.obligation_code -or
            $null -ne $receipt.derivation -or
            [string]$bindings.candidate_commit -cne
                [string]$common.candidate_commit -or
            [string]$bindings.candidate_tree -cne
                [string]$common.candidate_tree -or
            ($bindings.candidate_file_count -isnot [int] -and
                $bindings.candidate_file_count -isnot [long]) -or
            [long]$bindings.candidate_file_count -ne
                [long]$common.candidate_file_count -or
            [string]$bindings.candidate_manifest_sha256 -cne
                [string]$common.candidate_manifest_sha256 -or
            [string]$bindings.git_launcher_sha256 -cne
                [string]$common.git_launcher_sha256 -or
            [string]$bindings.git_resolved_sha256 -cne
                [string]$common.git_resolved_sha256 -or
            [string]$bindings.registry_sha256 -cne
                [string]$common.registry_sha256 -or
            [string]$bindings.runner_sha256 -cne
                [string]$common.runner_sha256 -or
            [string]$bindings.evidence_root_sha256 -cne
                [string]$common.evidence_root_sha256 -or
            [string]$bindings.check_definition_sha256 -cne
                (Get-SteinPhase2EvidenceObjectSha256 -Value $definition) -or
            ($bindings.execution_group_count -isnot [int] -and
                $bindings.execution_group_count -isnot [long]) -or
            [long]$bindings.execution_group_count -ne 25) {
            throw $failureCode
        }

        Assert-SteinPhase2EvidenceShape -Value $receipt.command `
            -ExpectedProperties @(
                'executable_role', 'executable_name', 'executable_size',
                'executable_sha256', 'arguments', 'arguments_sha256',
                'working_directory', 'environment_profile',
                'environment_profile_sha256', 'timeout_seconds') `
            -FailureCode $failureCode
        $command = $receipt.command
        $expectedArguments = @(Get-SteinPhase2SourceCommandExpectedArguments `
                -RegistryCheck $definition `
                -EvidenceRootRelative $evidenceRootRelative)
        $actualArguments = @($command.arguments | ForEach-Object { [string]$_ })
        if ($actualArguments.Count -ne $expectedArguments.Count -or
            @(Compare-Object `
                    -ReferenceObject $expectedArguments `
                    -DifferenceObject $actualArguments `
                    -CaseSensitive `
                    -SyncWindow 0).Count -ne 0) {
            throw $failureCode
        }
        $expectedExecutableName = switch ([string]$definition.executable_role) {
            'cargo' { 'cargo.exe' }
            'pnpm' { 'pnpm.cmd' }
            'windows_powershell' { 'powershell.exe' }
            'pwsh' { 'pwsh.exe' }
            default { throw $failureCode }
        }
        if ([string]$command.executable_role -cne
                [string]$definition.executable_role -or
            [string]$command.executable_name -cne $expectedExecutableName -or
            ($command.executable_size -isnot [int] -and
                $command.executable_size -isnot [long]) -or
            [long]$command.executable_size -lt 1 -or
            [long]$command.executable_size -gt 268435456 -or
            [string]$command.arguments_sha256 -cne
                (Get-SteinPhase2SourceCommandArgumentSha256 `
                    -Arguments $actualArguments) -or
            [string]$command.working_directory -cne
                [string]$definition.working_directory -or
            [string]$command.environment_profile -cne
                [string]$definition.environment_profile -or
            [string]$command.environment_profile_sha256 -cne
                (Get-SteinPhase2SourceCommandEnvironmentSha256 `
                    -Profile ([string]$definition.environment_profile)) -or
            [long]$command.timeout_seconds -ne
                [long]$definition.timeout_seconds) {
            throw $failureCode
        }
        Assert-SteinPhase2EvidenceHash -Value $command.executable_sha256 `
            -FailureCode $failureCode
        $role = [string]$command.executable_role
        $toolIdentity = "$([string]$command.executable_name)|$([long]$command.executable_size)|$([string]$command.executable_sha256)"
        if ($toolByRole.ContainsKey($role)) {
            if ([string]$toolByRole[$role] -cne $toolIdentity) {
                throw $failureCode
            }
        }
        else {
            $toolByRole[$role] = $toolIdentity
        }
        $provenanceTool = switch ($role) {
            'cargo' { $SourceReport.provenance.toolchain.cargo }
            'pnpm' { $SourceReport.provenance.toolchain.pnpm }
            'pwsh' { $SourceReport.provenance.toolchain.pwsh }
            default { $null }
        }
        if ($null -ne $provenanceTool -and
            [string]$command.executable_sha256 -cne
                [string]$provenanceTool.executable_sha256) {
            throw $failureCode
        }

        Assert-SteinPhase2EvidenceShape -Value $receipt.execution `
            -ExpectedProperties @(
                'execution_group_id', 'execution_id', 'started_at',
                'completed_at', 'duration_ms', 'exit_code', 'failure_code',
                'stdout', 'stderr') `
            -FailureCode $failureCode
        $execution = $receipt.execution
        $expectedGroupId = if ($category -ceq
                'grouped_fixture_execution') {
            'closed-source-fixture-suite'
        }
        else {
            "direct:$id"
        }
        $logLeaf = if ($category -ceq 'grouped_fixture_execution') {
            'closed-source-fixture-suite'
        }
        else {
            $id
        }
        $startedAt = ConvertFrom-SteinPhase2SourceCommandTimestamp `
            -Value $execution.started_at
        $completedAt = ConvertFrom-SteinPhase2SourceCommandTimestamp `
            -Value $execution.completed_at
        if ([string]$execution.execution_group_id -cne $expectedGroupId -or
            [string]$execution.execution_id -cnotmatch '^[0-9a-f]{64}$' -or
            $completedAt -lt $startedAt -or
            $startedAt -lt $reportStartedAt -or
            $completedAt -gt $reportCompletedAt -or
            ($execution.duration_ms -isnot [int] -and
                $execution.duration_ms -isnot [long]) -or
            [long]$execution.duration_ms -ne
                [long]($completedAt - $startedAt).TotalMilliseconds -or
            [long]$execution.duration_ms -lt 0 -or
            [long]$execution.duration_ms -gt
                ([long]$definition.timeout_seconds * 1000L + 60000L) -or
            ($execution.exit_code -isnot [int] -and
                $execution.exit_code -isnot [long]) -or
            [long]$execution.exit_code -ne 0 -or
            $null -ne $execution.failure_code) {
            throw $failureCode
        }
        foreach ($streamName in @('stdout', 'stderr')) {
            $expectedLogPath =
                "source-command-logs/$logLeaf.$streamName.txt"
            Assert-SteinPhase2SourceCommandDescriptor `
                -Descriptor $execution.$streamName `
                -ExpectedPath $expectedLogPath `
                -MinimumSize 0 `
                -MaximumSize 16777216 `
                -FailureCode $failureCode
            $null = $expectedLogPaths.Add($expectedLogPath)
        }
        $executionMaterial = [ordered]@{
            execution_group_id = $expectedGroupId
            executable_role = [string]$command.executable_role
            executable_sha256 = [string]$command.executable_sha256
            arguments_sha256 = [string]$command.arguments_sha256
            working_directory = [string]$command.working_directory
            environment_profile_sha256 =
                [string]$command.environment_profile_sha256
            started_at = [string]$execution.started_at
            completed_at = [string]$execution.completed_at
            exit_code = [long]$execution.exit_code
            failure_code = $execution.failure_code
            stdout = $execution.stdout
            stderr = $execution.stderr
        }
        if ([string]$execution.execution_id -cne
            (Get-SteinPhase2EvidenceObjectSha256 -Value $executionMaterial)) {
            throw $failureCode
        }
        $null = $executionGroups.Add($expectedGroupId)
        if ($category -ceq 'grouped_fixture_execution') {
            $identity = Get-SteinPhase2EvidenceObjectSha256 -Value ([ordered]@{
                    command = $command
                    execution = $execution
                })
            if ($null -eq $groupedIdentity) {
                $groupedIdentity = $identity
                $groupedExecutionId = [string]$execution.execution_id
            }
            elseif ([string]$groupedIdentity -cne $identity -or
                [string]$groupedExecutionId -cne
                    [string]$execution.execution_id) {
                throw $failureCode
            }
        }
        elseif (-not $directExecutionIds.Add(
                [string]$execution.execution_id)) {
            throw $failureCode
        }

        if ([string]$row.executable -cne [string]$command.executable_name -or
            [string]$row.working_directory -cne
                [string]$command.working_directory -or
            [string]$row.started_at -cne [string]$execution.started_at -or
            [string]$row.completed_at -cne [string]$execution.completed_at -or
            ($row.duration_ms -isnot [int] -and
                $row.duration_ms -isnot [long]) -or
            [long]$row.duration_ms -ne [long]$execution.duration_ms -or
            ($row.exit_code -isnot [int] -and
                $row.exit_code -isnot [long]) -or
            [long]$row.exit_code -ne [long]$execution.exit_code -or
            $null -ne $row.failure_summary) {
            throw $failureCode
        }
        $rowArguments = @($row.arguments | ForEach-Object { [string]$_ })
        if ($rowArguments.Count -ne $actualArguments.Count -or
            @(Compare-Object `
                    -ReferenceObject $actualArguments `
                    -DifferenceObject $rowArguments `
                    -CaseSensitive `
                    -SyncWindow 0).Count -ne 0) {
            throw $failureCode
        }
        foreach ($streamName in @('stdout', 'stderr')) {
            $outerStream = $row.$streamName
            $executionStream = $execution.$streamName
            Assert-SteinPhase2SourceCommandDescriptor `
                -Descriptor $outerStream `
                -ExpectedPath "$evidenceRootRelative/$([string]$executionStream.path)" `
                -MinimumSize 0 `
                -MaximumSize 16777216 `
                -FailureCode $failureCode
            if ([long]$outerStream.size -ne [long]$executionStream.size -or
                [string]$outerStream.sha256 -cne
                    [string]$executionStream.sha256) {
                throw $failureCode
            }
        }

        $receiptArtifacts = @($receipt.artifacts)
        if ($category -ceq 'direct_execution') {
            if ($receiptArtifacts.Count -ne 0) {
                throw $failureCode
            }
        }
        else {
            if ($receiptArtifacts.Count -ne 2) {
                throw $failureCode
            }
            Assert-SteinPhase2EvidenceShape -Value $receiptArtifacts[0] `
                -ExpectedProperties @('role', 'size', 'sha256') `
                -FailureCode $failureCode
            Assert-SteinPhase2EvidenceShape -Value $receiptArtifacts[1] `
                -ExpectedProperties @('role', 'size', 'sha256') `
                -FailureCode $failureCode
            foreach ($receiptArtifact in $receiptArtifacts) {
                Assert-SteinPhase2EvidenceHash -Value $receiptArtifact.sha256 `
                    -FailureCode $failureCode
                if (($receiptArtifact.size -isnot [int] -and
                        $receiptArtifact.size -isnot [long]) -or
                    [long]$receiptArtifact.size -lt 1 -or
                    [long]$receiptArtifact.size -gt 4194304) {
                    throw $failureCode
                }
            }
            Assert-SteinPhase2SourceCommandDescriptor `
                -Descriptor $row.source_fixture_suite_index `
                -ExpectedPath 'source-fixtures/index.json' `
                -MinimumSize 1 `
                -MaximumSize 1048576 `
                -FailureCode $failureCode
            Assert-SteinPhase2SourceCommandDescriptor `
                -Descriptor $row.source_fixture_receipt_artifact `
                -ExpectedPath ([string]$definition.fixture_receipt_path) `
                -MinimumSize 1 `
                -MaximumSize 4194304 `
                -FailureCode $failureCode
            if ([string]$receiptArtifacts[0].role -cne
                    'source_fixture_suite_index' -or
                [long]$receiptArtifacts[0].size -ne
                    [long]$row.source_fixture_suite_index.size -or
                [string]$receiptArtifacts[0].sha256 -cne
                    [string]$row.source_fixture_suite_index.sha256 -or
                [string]$receiptArtifacts[1].role -cne
                    'source_fixture_receipt' -or
                [long]$receiptArtifacts[1].size -ne
                    [long]$row.source_fixture_receipt_artifact.size -or
                [string]$receiptArtifacts[1].sha256 -cne
                    [string]$row.source_fixture_receipt_artifact.sha256) {
                throw $failureCode
            }
        }
    }
    if ($executionGroups.Count -ne 25 -or
        $directExecutionIds.Count -ne 24 -or
        $expectedLogPaths.Count -ne 50 -or
        $toolByRole.Count -ne 4 -or $null -eq $groupedIdentity) {
        throw $failureCode
    }
    return $true
}

function Assert-SteinPhase2SourceEvidenceBinding {
    param(
        [Parameter(Mandatory = $true)] $EvidenceResult,
        [Parameter(Mandatory = $true)] $SourceReport,
        [Parameter(Mandatory = $true)] $SourceRootAnchor,
        [Parameter(Mandatory = $true)] $EvidenceSpecification,
        [Parameter(Mandatory = $true)] $SourceFixtureRegistry,
        [Parameter(Mandatory = $true)][string] $SourceFixtureRegistrySha256,
        [Parameter(Mandatory = $true)] $SourceCommandRegistry,
        [Parameter(Mandatory = $true)][string] $SourceCommandRegistrySha256
    )

    Assert-SteinPhase2EvidenceShape -Value $SourceRootAnchor `
        -ExpectedProperties @(
            'schema_version', 'claim', 'integrity_semantics', 'source_verification',
            'generator_sha256', 'provenance_sha256', 'checks_sha256',
            'root_digest_sha256') `
        -FailureCode 'source_evidence_root_schema_invalid'
    Assert-SteinPhase2EvidenceShape -Value $SourceRootAnchor.source_verification `
        -ExpectedProperties @('path', 'size', 'sha256') `
        -FailureCode 'source_evidence_root_schema_invalid'
    foreach ($property in @(
            'generator_sha256', 'provenance_sha256', 'checks_sha256',
            'root_digest_sha256')) {
        Assert-SteinPhase2EvidenceHash -Value $SourceRootAnchor.$property `
            -FailureCode 'source_evidence_root_invalid'
    }
    $binding = $EvidenceResult.bindings.source_report
    if (($SourceRootAnchor.schema_version -isnot [int] -and
            $SourceRootAnchor.schema_version -isnot [long]) -or
        [long]$SourceRootAnchor.schema_version -ne 1 -or
        [string]$SourceRootAnchor.claim -cne 'source_verification_only' -or
        [string]$SourceRootAnchor.integrity_semantics -cne
            'content_integrity_only_not_authentication' -or
        [string]$SourceRootAnchor.source_verification.path -cne
            'source-verification.json' -or
        [string]$SourceRootAnchor.source_verification.sha256 -cne
            [string]$binding.report_sha256 -or
        [string]$SourceRootAnchor.root_digest_sha256 -cne
            [string]$binding.root_digest_sha256) {
        throw 'source_evidence_root_binding_invalid'
    }
    $rootMaterial = @(
        'stein-phase2-source-evidence-root-v1',
        "source_verification_sha256=$($SourceRootAnchor.source_verification.sha256)",
        "generator_sha256=$($SourceRootAnchor.generator_sha256)",
        "provenance_sha256=$($SourceRootAnchor.provenance_sha256)",
        "checks_sha256=$($SourceRootAnchor.checks_sha256)"
    ) -join "`n"
    if ((Get-SteinPhase2EvidenceTextSha256 -Value $rootMaterial) -cne
        [string]$SourceRootAnchor.root_digest_sha256) {
        throw 'source_evidence_root_digest_mismatch'
    }

    foreach ($property in @(
            'schema_version', 'claim', 'installed_or_signed_evidence', 'passed',
            'complete_acceptance', 'started_at', 'completed_at', 'provenance',
            'integrity', 'checks', 'summary')) {
        if ($null -eq $SourceReport.PSObject.Properties[$property]) {
            throw 'source_evidence_report_schema_invalid'
        }
    }
    Assert-SteinPhase2EvidenceShape -Value $SourceReport.integrity.generator `
        -ExpectedProperties @('schema_version', 'files', 'digest_sha256') `
        -FailureCode 'source_evidence_generator_invalid'
    if (($SourceReport.integrity.generator.schema_version -isnot [int] -and
            $SourceReport.integrity.generator.schema_version -isnot [long]) -or
        [long]$SourceReport.integrity.generator.schema_version -ne 1) {
        throw 'source_evidence_generator_invalid'
    }
    $sourceGeneratorFiles = @($SourceReport.integrity.generator.files)
    $sourceGeneratorPaths = New-Object Collections.Generic.List[string]
    $sourceGeneratorByPath = @{}
    foreach ($generatorFile in $sourceGeneratorFiles) {
        Assert-SteinPhase2EvidenceShape -Value $generatorFile `
            -ExpectedProperties @('path', 'size', 'sha256') `
            -FailureCode 'source_evidence_generator_invalid'
        if ($generatorFile.path -isnot [string] -or
            [string]$generatorFile.path -cnotmatch
                '^(?:scripts/windows/phase2|packaging/windows-msix)/[A-Za-z0-9._/-]+$' -or
            ($generatorFile.size -isnot [int] -and
                $generatorFile.size -isnot [long]) -or
            [long]$generatorFile.size -le 0) {
            throw 'source_evidence_generator_invalid'
        }
        if ($sourceGeneratorByPath.ContainsKey([string]$generatorFile.path)) {
            throw 'source_evidence_generator_invalid'
        }
        Assert-SteinPhase2EvidenceHash -Value $generatorFile.sha256 `
            -FailureCode 'source_evidence_generator_invalid'
        $sourceGeneratorByPath[[string]$generatorFile.path] = $generatorFile
        $sourceGeneratorPaths.Add([string]$generatorFile.path)
    }
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($sourceGeneratorPaths | ForEach-Object { $_ }) `
        -Expected @($EvidenceSpecification.source_report_contract.required_generator_paths) `
        -FailureCode 'source_evidence_generator_invalid'
    $recomputedGeneratorDigest = Get-SteinPhase2EvidenceTextSha256 `
        -Value ($sourceGeneratorFiles | ConvertTo-Json -Depth 16 -Compress)
    if ([string]$SourceReport.integrity.generator.digest_sha256 -cne
            $recomputedGeneratorDigest) {
        throw 'source_evidence_generator_invalid'
    }
    if (($SourceReport.provenance.schema_version -isnot [int] -and
            $SourceReport.provenance.schema_version -isnot [long]) -or
        [long]$SourceReport.provenance.schema_version -ne 2 -or
        [string]$SourceReport.provenance.classification -cne
            'bounded_content_free_source_provenance' -or
        $null -eq $SourceReport.provenance.toolchain) {
        throw 'source_evidence_toolchain_invalid'
    }
    Assert-SteinPhase2EvidenceShape `
        -Value $SourceReport.provenance.toolchain `
        -ExpectedProperties @('cargo', 'rustc', 'rustup', 'node', 'pnpm', 'git', 'pwsh') `
        -FailureCode 'source_evidence_toolchain_invalid'
    foreach ($rustToolName in @('cargo', 'rustc')) {
        $rustTool = $SourceReport.provenance.toolchain.$rustToolName
        Assert-SteinPhase2EvidenceShape -Value $rustTool `
            -ExpectedProperties @(
                'version', 'executable_sha256', 'rustup_toolchain',
                'resolved_version', 'resolved_executable_sha256') `
            -FailureCode 'source_evidence_toolchain_invalid'
        Assert-SteinPhase2EvidenceHash -Value $rustTool.executable_sha256 `
            -FailureCode 'source_evidence_toolchain_invalid'
        Assert-SteinPhase2EvidenceHash -Value $rustTool.resolved_executable_sha256 `
            -FailureCode 'source_evidence_toolchain_invalid'
        if ($rustTool.version -isnot [string] -or
            [string]$rustTool.version -cnotmatch '^[\x20-\x7e]{1,160}$' -or
            [string]$rustTool.resolved_version -cne [string]$rustTool.version -or
            [string]$rustTool.rustup_toolchain -cnotmatch
                '^[0-9A-Za-z][0-9A-Za-z._-]{2,127}$') {
            throw 'source_evidence_toolchain_invalid'
        }
    }
    if ([string]$SourceReport.provenance.toolchain.cargo.rustup_toolchain -cne
        [string]$SourceReport.provenance.toolchain.rustc.rustup_toolchain) {
        throw 'source_evidence_toolchain_invalid'
    }
    $pnpmTool = $SourceReport.provenance.toolchain.pnpm
    Assert-SteinPhase2EvidenceShape -Value $pnpmTool `
        -ExpectedProperties @(
            'version', 'executable_sha256', 'resolved_entrypoint_sha256') `
        -FailureCode 'source_evidence_toolchain_invalid'
    Assert-SteinPhase2EvidenceHash -Value $pnpmTool.executable_sha256 `
        -FailureCode 'source_evidence_toolchain_invalid'
    Assert-SteinPhase2EvidenceHash -Value $pnpmTool.resolved_entrypoint_sha256 `
        -FailureCode 'source_evidence_toolchain_invalid'
    if ($pnpmTool.version -isnot [string] -or
        [string]$pnpmTool.version -cnotmatch '^[\x20-\x7e]{1,160}$') {
        throw 'source_evidence_toolchain_invalid'
    }
    foreach ($basicToolName in @('rustup', 'node')) {
        $basicTool = $SourceReport.provenance.toolchain.$basicToolName
        Assert-SteinPhase2EvidenceShape -Value $basicTool `
            -ExpectedProperties @('version', 'executable_sha256') `
            -FailureCode 'source_evidence_toolchain_invalid'
        Assert-SteinPhase2EvidenceHash -Value $basicTool.executable_sha256 `
            -FailureCode 'source_evidence_toolchain_invalid'
        if ($basicTool.version -isnot [string] -or
            [string]$basicTool.version -cnotmatch '^[\x20-\x7e]{1,160}$') {
            throw 'source_evidence_toolchain_invalid'
        }
    }
    $gitTool = $SourceReport.provenance.toolchain.git
    Assert-SteinPhase2EvidenceShape -Value $gitTool `
        -ExpectedProperties @(
            'version', 'executable_sha256', 'resolved_version',
            'resolved_executable_sha256') `
        -FailureCode 'source_evidence_toolchain_invalid'
    Assert-SteinPhase2EvidenceHash -Value $gitTool.executable_sha256 `
        -FailureCode 'source_evidence_toolchain_invalid'
    Assert-SteinPhase2EvidenceHash -Value $gitTool.resolved_executable_sha256 `
        -FailureCode 'source_evidence_toolchain_invalid'
    if ($gitTool.version -isnot [string] -or
        [string]$gitTool.version -cnotmatch '^[\x20-\x7e]{1,160}$' -or
        [string]$gitTool.resolved_version -cne [string]$gitTool.version) {
        throw 'source_evidence_toolchain_invalid'
    }
    $pwshTool = $SourceReport.provenance.toolchain.pwsh
    Assert-SteinPhase2EvidenceShape -Value $pwshTool `
        -ExpectedProperties @(
            'version', 'executable_sha256', 'authenticode_status',
            'signer_subject') `
        -FailureCode 'source_evidence_toolchain_invalid'
    Assert-SteinPhase2EvidenceHash -Value $pwshTool.executable_sha256 `
        -FailureCode 'source_evidence_toolchain_invalid'
    if ($pwshTool.version -isnot [string] -or
        [string]$pwshTool.version -cnotmatch '^[\x20-\x7e]{1,160}$' -or
        [string]$pwshTool.authenticode_status -cne 'valid' -or
        [string]$pwshTool.signer_subject -cne
            'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US') {
        throw 'source_evidence_toolchain_invalid'
    }
    $recomputedProvenanceDigest = Get-SteinPhase2EvidenceTextSha256 `
        -Value ($SourceReport.provenance | ConvertTo-Json -Depth 16 -Compress)
    $recomputedChecksDigest = Get-SteinPhase2EvidenceTextSha256 `
        -Value (@($SourceReport.checks) | ConvertTo-Json -Depth 40 -Compress)
    if ([string]$SourceReport.integrity.provenance_sha256 -cne
            $recomputedProvenanceDigest -or
        [string]$SourceReport.integrity.checks_sha256 -cne
            $recomputedChecksDigest) {
        throw 'source_evidence_report_digest_invalid'
    }
    if (($SourceReport.schema_version -isnot [int] -and
            $SourceReport.schema_version -isnot [long]) -or
        [long]$SourceReport.schema_version -ne 2 -or
        [string]$SourceReport.claim -cne 'source_verification_only' -or
        $SourceReport.installed_or_signed_evidence -isnot [bool] -or
        [bool]$SourceReport.installed_or_signed_evidence -or
        $SourceReport.passed -isnot [bool] -or -not [bool]$SourceReport.passed -or
        $SourceReport.complete_acceptance -isnot [bool] -or
        [bool]$SourceReport.complete_acceptance -or
        $null -eq $SourceReport.provenance.repository -or
        [string]$SourceReport.provenance.repository.head_commit -cne
            [string]$EvidenceResult.bindings.commit.object_id -or
        [string]$SourceReport.integrity.semantics -cne
            'content_integrity_only_not_authentication' -or
        [string]$SourceReport.integrity.root_anchor_path -cne 'root-anchor.json' -or
        [string]$SourceReport.integrity.generator.digest_sha256 -cne
            [string]$SourceRootAnchor.generator_sha256 -or
        [string]$SourceReport.integrity.provenance_sha256 -cne
            [string]$SourceRootAnchor.provenance_sha256 -or
        [string]$SourceReport.integrity.checks_sha256 -cne
            [string]$SourceRootAnchor.checks_sha256 -or
        [long]$SourceReport.summary.fail -ne 0) {
        throw 'source_evidence_report_binding_invalid'
    }
    $checksById = @{}
    $sourceCheckIds = New-Object Collections.Generic.List[string]
    foreach ($check in @($SourceReport.checks)) {
        if ($null -eq $check.PSObject.Properties['id'] -or
            $null -eq $check.PSObject.Properties['status'] -or
            [string]$check.id -cnotmatch '^[a-z][a-z0-9-]{2,95}$' -or
            $checksById.ContainsKey([string]$check.id)) {
            throw 'source_evidence_check_set_invalid'
        }
        $checksById[[string]$check.id] = $check
        $sourceCheckIds.Add([string]$check.id)
    }
    $contractRequiredPassIds = @(
        $EvidenceSpecification.source_report_contract.required_pass_check_ids)
    $contractAllowedNotRunIds = @(
        $EvidenceSpecification.source_report_contract.allowed_not_run_check_ids)
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($sourceCheckIds | ForEach-Object { $_ }) `
        -Expected (@($contractRequiredPassIds) + @($contractAllowedNotRunIds)) `
        -FailureCode 'source_evidence_check_set_invalid'
    foreach ($requiredPassId in $contractRequiredPassIds) {
        $requiredPassCheck = $checksById[[string]$requiredPassId]
        if ([string]$requiredPassCheck.status -cne 'pass') {
            throw 'source_evidence_required_check_not_passed'
        }
        $requiredExitProperty =
            $requiredPassCheck.PSObject.Properties['exit_code']
        if ($null -ne $requiredExitProperty -and
            (($requiredExitProperty.Value -isnot [int] -and
                    $requiredExitProperty.Value -isnot [long]) -or
                [long]$requiredExitProperty.Value -ne 0)) {
            throw 'source_evidence_required_check_not_passed'
        }
    }
    foreach ($allowedNotRunId in $contractAllowedNotRunIds) {
        $allowedCheck = $checksById[[string]$allowedNotRunId]
        $expectedNotRunReasons = [ordered]@{
            'native-toolchain-provenance' = 'Authenticated Rust/rustup/Git/VS/MSVC/Windows SDK/package-tool payload, runtime, sysroot, library, and linker provenance is not implemented.'
            'no-leaks-producer-workflow' = 'Candidate-owned installed artifact producer is not implemented.'
            'pinned-clean-build-environment' = 'Authenticated immutable candidate input and fresh dependency, build, and output isolation are not implemented for every source check.'
            'portable-runner-attestation' = 'Authenticated GitHub artifact attestation tied to repository, workflow, commit, and artifact digest is not implemented.'
            'windows-native-ignored-fixtures' = 'Requires explicit native-fixture workflow support; interactive native fixtures remain unimplemented source evidence.'
        }
        Assert-SteinPhase2EvidenceShape -Value $allowedCheck `
            -ExpectedProperties @('id', 'status', 'reason') `
            -FailureCode 'source_evidence_check_status_invalid'
        if ([string]$allowedCheck.status -cne 'not_run' -or
            [string]$allowedCheck.reason -cne
                [string]$expectedNotRunReasons[[string]$allowedNotRunId]) {
            throw 'source_evidence_check_status_invalid'
        }
    }
    $null = Assert-SteinPhase2SourceCommandEvidence `
        -EvidenceResult $EvidenceResult `
        -SourceReport $SourceReport `
        -EvidenceSpecification $EvidenceSpecification `
        -SourceCommandRegistry $SourceCommandRegistry `
        -SourceCommandRegistrySha256 $SourceCommandRegistrySha256 `
        -SourceGeneratorByPath $sourceGeneratorByPath
    $registryGeneratorPath =
        'scripts/windows/phase2/Source-Fixture-Registry.json'
    if (-not $sourceGeneratorByPath.ContainsKey($registryGeneratorPath)) {
        throw 'source_evidence_generator_invalid'
    }
    if ([string]$sourceGeneratorByPath[$registryGeneratorPath].sha256 -cne
            [string]$EvidenceSpecification.source_report_contract.source_fixture_registry_sha256 -or
        $SourceFixtureRegistrySha256 -cne
            [string]$EvidenceSpecification.source_report_contract.source_fixture_registry_sha256) {
        throw 'source_evidence_fixture_registry_invalid'
    }
    Assert-SteinPhase2EvidenceShape -Value $SourceFixtureRegistry `
        -ExpectedProperties @(
            'schema_version', 'registry_id', 'receipt_schema_version',
            'fixtures') `
        -FailureCode 'source_evidence_fixture_registry_invalid'
    $sourceFixtureByCheck = @{}
    foreach ($fixture in @($SourceFixtureRegistry.fixtures)) {
        $fixtureCheckProperty = $fixture.PSObject.Properties['source_check_id']
        if ($null -eq $fixtureCheckProperty -or
            $sourceFixtureByCheck.ContainsKey([string]$fixtureCheckProperty.Value)) {
            throw 'source_evidence_fixture_registry_invalid'
        }
        $sourceFixtureByCheck[[string]$fixtureCheckProperty.Value] = $fixture
    }
    if ([long]$SourceFixtureRegistry.schema_version -ne 1 -or
        [long]$SourceFixtureRegistry.receipt_schema_version -ne 1 -or
        [string]$SourceFixtureRegistry.registry_id -cne
            'stein.phase2.source-fixture.registry.v1' -or
        $sourceFixtureByCheck.Count -ne 13) {
        throw 'source_evidence_fixture_registry_invalid'
    }
    foreach ($fixtureCheck in @($SourceReport.checks | Where-Object {
                [string]$_.id -clike 'phase2-source-fixture-*' -and
                [string]$_.status -ceq 'pass'
            })) {
        $fixtureGates = @($EvidenceSpecification.gates | Where-Object {
                $sourceCheckProperty =
                    $_.PSObject.Properties['source_report_check_ids']
                $null -ne $sourceCheckProperty -and
                    [string]$fixtureCheck.id -cin @($sourceCheckProperty.Value)
            })
        if ($fixtureGates.Count -ne 1) {
            throw 'source_fixture_receipt_invalid'
        }
        if (-not $sourceFixtureByCheck.ContainsKey([string]$fixtureCheck.id)) {
            throw 'source_fixture_receipt_invalid'
        }
        $null = Assert-SteinPhase2SourceFixtureReceiptCheck `
            -Check $fixtureCheck `
            -Gate $fixtureGates[0] `
            -SourceReport $SourceReport `
            -EvidenceResult $EvidenceResult `
            -RegistrySha256 `
                ([string]$sourceGeneratorByPath[$registryGeneratorPath].sha256) `
            -Fixture $sourceFixtureByCheck[[string]$fixtureCheck.id]
    }
    Assert-SteinPhase2EvidenceShape -Value $SourceReport.summary `
        -ExpectedProperties @('pass', 'fail', 'not_run') `
        -FailureCode 'source_evidence_summary_invalid'
    foreach ($summaryProperty in @('pass', 'fail', 'not_run')) {
        if ($SourceReport.summary.$summaryProperty -isnot [int] -and
            $SourceReport.summary.$summaryProperty -isnot [long]) {
            throw 'source_evidence_summary_invalid'
        }
    }
    $actualSourcePassCount = @($SourceReport.checks | Where-Object {
            [string]$_.status -ceq 'pass'
        }).Count
    $actualSourceNotRunCount = @($SourceReport.checks | Where-Object {
            [string]$_.status -ceq 'not_run'
        }).Count
    if ([long]$SourceReport.summary.pass -ne $actualSourcePassCount -or
        [long]$SourceReport.summary.fail -ne 0 -or
        [long]$SourceReport.summary.not_run -ne $actualSourceNotRunCount) {
        throw 'source_evidence_summary_invalid'
    }
    $requiredCheckIds = @(
        @($EvidenceResult.subchecks | Where-Object {
                [string]$_.origin -ceq 'source_verification'
            } | ForEach-Object { @($_.source_check_ids) }) |
            ForEach-Object { $_ } |
            Sort-Object -Unique)
    $frozenDependencySeen = $false
    foreach ($requiredCheckId in $requiredCheckIds) {
        if (-not $checksById.ContainsKey([string]$requiredCheckId)) {
            throw 'source_evidence_required_check_not_passed'
        }
        $requiredCheck = $checksById[[string]$requiredCheckId]
        if ([string]$requiredCheckId -cin $contractRequiredPassIds) {
            if ([string]$requiredCheck.status -cne 'pass') {
                throw 'source_evidence_required_check_not_passed'
            }
            $exitProperty = $requiredCheck.PSObject.Properties['exit_code']
            if ($null -ne $exitProperty -and
                (($exitProperty.Value -isnot [int] -and
                        $exitProperty.Value -isnot [long]) -or
                    [long]$exitProperty.Value -ne 0)) {
                throw 'source_evidence_required_check_not_passed'
            }
        }
        elseif ([string]$requiredCheckId -cin $contractAllowedNotRunIds) {
            if ([string]$requiredCheck.status -cne 'not_run') {
                throw 'source_evidence_required_check_not_passed'
            }
            $frozenDependencySeen = $true
        }
        else {
            throw 'source_evidence_required_check_not_passed'
        }
    }
    if ($frozenDependencySeen -and
        [string]$EvidenceResult.result -ceq 'pass') {
        throw 'source_evidence_required_check_not_passed'
    }
    return $true
}

function Assert-SteinPhase2LinuxPortableArtifact {
    param(
        [Parameter(Mandatory = $true)] $Artifact,
        [Parameter(Mandatory = $true)] $Gate,
        [Parameter(Mandatory = $true)][string] $ExpectedCommit,
        [Parameter(Mandatory = $true)][string] $ExpectedTree,
        [Parameter(Mandatory = $true)] $SourceReport,
        [Parameter(Mandatory = $true)] $EvidenceResult,
        [Parameter(Mandatory = $true)][object[]] $UnderlyingArtifacts
    )

    Assert-SteinPhase2EvidenceShape -Value $Artifact `
        -ExpectedProperties @(
            'schema_version', 'gate_id', 'fixture_id', 'runner_id', 'result',
            'generated_at', 'repository', 'toolchain', 'generator', 'subchecks') `
        -FailureCode 'linux_artifact_schema_invalid'
    if (($Artifact.schema_version -isnot [int] -and $Artifact.schema_version -isnot [long]) -or
        [long]$Artifact.schema_version -ne [long]$Gate.linux_artifact.schema_version -or
        [string]$Artifact.gate_id -cne [string]$Gate.gate_id -or
        [string]$Artifact.fixture_id -cne [string]$Gate.linux_artifact.fixture_id -or
        [string]$Artifact.runner_id -cne [string]$Gate.linux_artifact.runner_id -or
        [string]$Artifact.result -cne 'pass') {
        throw 'linux_artifact_identity_invalid'
    }
    $generatedAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
            [string]$Artifact.generated_at,
            [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal),
            [ref]$generatedAt) -or
        $generatedAt -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        throw 'linux_artifact_timestamp_invalid'
    }
    Assert-SteinPhase2EvidenceShape -Value $Artifact.repository `
        -ExpectedProperties @('commit', 'tree', 'clean_before', 'clean_after') `
        -FailureCode 'linux_artifact_repository_invalid'
    if ([string]$Artifact.repository.commit -cne $ExpectedCommit -or
        [string]$Artifact.repository.tree -cne $ExpectedTree -or
        [string]$Artifact.repository.tree -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        $Artifact.repository.clean_before -isnot [bool] -or
        -not [bool]$Artifact.repository.clean_before -or
        $Artifact.repository.clean_after -isnot [bool] -or
        -not [bool]$Artifact.repository.clean_after) {
        throw 'linux_artifact_repository_invalid'
    }
    Assert-SteinPhase2EvidenceShape -Value $Artifact.toolchain `
        -ExpectedProperties @(
            'rustc_verbose', 'cargo_version', 'rust_toolchain_sha256',
            'cargo_lock_sha256') `
        -FailureCode 'linux_artifact_toolchain_invalid'
    foreach ($property in @('rust_toolchain_sha256', 'cargo_lock_sha256')) {
        Assert-SteinPhase2EvidenceHash -Value $Artifact.toolchain.$property `
            -FailureCode 'linux_artifact_toolchain_invalid'
    }
    if ($Artifact.toolchain.rustc_verbose -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Artifact.toolchain.rustc_verbose) -or
        $Artifact.toolchain.cargo_version -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Artifact.toolchain.cargo_version)) {
        throw 'linux_artifact_toolchain_invalid'
    }
    $cargoLockRecords = @($SourceReport.provenance.dependency_locks | Where-Object {
            [string]$_.path -ceq 'Cargo.lock'
        })
    if ($cargoLockRecords.Count -ne 1 -or
        [string]$cargoLockRecords[0].sha256 -cne
            [string]$Artifact.toolchain.cargo_lock_sha256) {
        throw 'linux_artifact_cargo_lock_binding_invalid'
    }
    Assert-SteinPhase2EvidenceShape -Value $Artifact.generator `
        -ExpectedProperties @('workflow_path', 'workflow_sha256') `
        -FailureCode 'linux_artifact_generator_invalid'
    Assert-SteinPhase2EvidenceHash -Value $Artifact.generator.workflow_sha256 `
        -FailureCode 'linux_artifact_generator_invalid'
    if ([string]$Artifact.generator.workflow_path -cne
        '.github/workflows/portable-semantic.yml') {
        throw 'linux_artifact_generator_invalid'
    }
    $subchecks = @($Artifact.subchecks)
    Assert-SteinPhase2EvidenceExactSet `
        -Actual @($subchecks | ForEach-Object { $_.id }) `
        -Expected @($Gate.linux_artifact.required_subchecks) `
        -FailureCode 'linux_artifact_subcheck_set_invalid'
    $resultArtifactsById = @{}
    foreach ($resultArtifact in @($EvidenceResult.artifacts)) {
        $resultArtifactsById[[string]$resultArtifact.artifact_id] = $resultArtifact
    }
    $underlyingArtifactsById = @{}
    foreach ($underlyingArtifact in @($UnderlyingArtifacts)) {
        $underlyingArtifactsById[[string]$underlyingArtifact.artifact_id] = $underlyingArtifact
    }
    for ($subcheckIndex = 0; $subcheckIndex -lt $subchecks.Count; $subcheckIndex++) {
        $subcheck = $subchecks[$subcheckIndex]
        Assert-SteinPhase2EvidenceShape -Value $subcheck `
            -ExpectedProperties @('id', 'command', 'exit_code', 'result', 'artifact') `
            -FailureCode 'linux_artifact_subcheck_schema_invalid'
        Assert-SteinPhase2EvidenceShape -Value $subcheck.artifact `
            -ExpectedProperties @('path', 'size_bytes', 'sha256') `
            -FailureCode 'linux_artifact_subcheck_artifact_invalid'
        Assert-SteinPhase2EvidenceHash -Value $subcheck.artifact.sha256 `
            -FailureCode 'linux_artifact_subcheck_artifact_invalid'
        if ([string]$subcheck.id -cne
                [string]$Gate.linux_artifact.required_subchecks[$subcheckIndex] -or
            $subcheck.command -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$subcheck.command) -or
            ($subcheck.exit_code -isnot [int] -and $subcheck.exit_code -isnot [long]) -or
            [long]$subcheck.exit_code -ne 0 -or
            [string]$subcheck.result -cne 'pass' -or
            [string]$subcheck.artifact.path -cnotmatch '^[A-Za-z0-9._/-]{1,160}$' -or
            [IO.Path]::IsPathRooted([string]$subcheck.artifact.path) -or
            [string]$subcheck.artifact.path -cmatch '(?:^|/)\.\.?(/|$)' -or
            ($subcheck.artifact.size_bytes -isnot [int] -and
                $subcheck.artifact.size_bytes -isnot [long]) -or
            [long]$subcheck.artifact.size_bytes -lt 1) {
            throw 'linux_artifact_subcheck_invalid'
        }
        $expectedArtifactId =
            [string]$Gate.linux_artifact.artifact_id_prefix + [string]$subcheck.id
        if ([string]$subcheck.artifact.path -cne "logs/$([string]$subcheck.id).log" -or
            -not $resultArtifactsById.ContainsKey($expectedArtifactId) -or
            -not $underlyingArtifactsById.ContainsKey($expectedArtifactId) -or
            [string]$resultArtifactsById[$expectedArtifactId].proof_class -cne
                'portable_linux' -or
            [string]$resultArtifactsById[$expectedArtifactId].origin -cne 'linux_ci' -or
            [string]$resultArtifactsById[$expectedArtifactId].sha256 -cne
                [string]$subcheck.artifact.sha256 -or
            [long]$resultArtifactsById[$expectedArtifactId].size -ne
                [long]$subcheck.artifact.size_bytes -or
            [string]$underlyingArtifactsById[$expectedArtifactId].sha256 -cne
                [string]$subcheck.artifact.sha256 -or
            [long]$underlyingArtifactsById[$expectedArtifactId].size -ne
                [long]$subcheck.artifact.size_bytes) {
            throw 'linux_artifact_subcheck_artifact_mismatch'
        }
    }
    return $true
}
