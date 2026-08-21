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
            'required_pass_check_ids', 'allowed_not_run_check_ids',
            'required_generator_paths') `
        -FailureCode 'evidence_spec_source_report_contract_invalid'
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
        'release-edge-host',
        'release-production-core',
        'release-tauri-no-bundle',
        'release-workspace',
        'rust-check',
        'rust-clippy',
        'rust-format',
        'rust-tests',
        'source-evidence-contract',
        'source-provenance-stability'
    )
    $expectedAllowedNotRunCheckIds = @(
        'native-toolchain-provenance',
        'no-leaks-producer-workflow',
        'phase2-source-fixture-goals',
        'phase2-source-fixture-identity',
        'phase2-source-fixture-intervention',
        'phase2-source-fixture-model-contract',
        'phase2-source-fixture-notification',
        'phase2-source-fixture-outbox-recovery',
        'phase2-source-fixture-phase1-regression',
        'phase2-source-fixture-pixels',
        'phase2-source-fixture-policy-failsafe',
        'phase2-source-fixture-retention',
        'phase2-source-fixture-revocation-race',
        'phase2-source-fixture-secrets',
        'phase2-source-fixture-upgrade',
        'pinned-clean-build-environment',
        'portable-runner-attestation',
        'source-report-command-provenance',
        'windows-native-ignored-fixtures'
    )
    $expectedSourceGeneratorPaths = @(
        'scripts/windows/phase2/Verify-Source.ps1',
        'scripts/windows/phase2/Verify-Source.cmd',
        'scripts/windows/phase2/Source-Evidence.ps1',
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

function Assert-SteinPhase2SourceEvidenceBinding {
    param(
        [Parameter(Mandatory = $true)] $EvidenceResult,
        [Parameter(Mandatory = $true)] $SourceReport,
        [Parameter(Mandatory = $true)] $SourceRootAnchor,
        [Parameter(Mandatory = $true)] $EvidenceSpecification
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
            'complete_acceptance', 'provenance', 'integrity', 'checks', 'summary')) {
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
        Assert-SteinPhase2EvidenceHash -Value $generatorFile.sha256 `
            -FailureCode 'source_evidence_generator_invalid'
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
        -Value (@($SourceReport.checks) | ConvertTo-Json -Depth 16 -Compress)
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
        $allowedStatus = [string]$allowedCheck.status
        if ($allowedStatus -cne 'pass' -and $allowedStatus -cne 'not_run') {
            throw 'source_evidence_check_status_invalid'
        }
        $allowedExitProperty = $allowedCheck.PSObject.Properties['exit_code']
        if ($allowedStatus -ceq 'pass' -and $null -ne $allowedExitProperty -and
            (($allowedExitProperty.Value -isnot [int] -and
                    $allowedExitProperty.Value -isnot [long]) -or
                [long]$allowedExitProperty.Value -ne 0)) {
            throw 'source_evidence_check_status_invalid'
        }
        if ($allowedStatus -ceq 'not_run') {
            Assert-SteinPhase2EvidenceShape -Value $allowedCheck `
                -ExpectedProperties @('id', 'status', 'reason') `
                -FailureCode 'source_evidence_check_status_invalid'
            if ($allowedCheck.reason -isnot [string] -or
                [string]::IsNullOrWhiteSpace([string]$allowedCheck.reason) -or
                ([string]$allowedCheck.reason).Length -gt 256) {
                throw 'source_evidence_check_status_invalid'
            }
        }
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
    foreach ($requiredCheckId in $requiredCheckIds) {
        if (-not $checksById.ContainsKey([string]$requiredCheckId) -or
            [string]$checksById[[string]$requiredCheckId].status -cne 'pass') {
            throw 'source_evidence_required_check_not_passed'
        }
        $exitProperty = $checksById[[string]$requiredCheckId].PSObject.Properties['exit_code']
        if ($null -ne $exitProperty -and
            (($exitProperty.Value -isnot [int] -and $exitProperty.Value -isnot [long]) -or
                [long]$exitProperty.Value -ne 0)) {
            throw 'source_evidence_required_check_not_passed'
        }
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
