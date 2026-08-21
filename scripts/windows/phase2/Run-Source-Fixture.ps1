[CmdletBinding()]
param(
    [string] $OutputDirectory,

    [switch] $LibraryOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$sourceFixtureScriptRoot = $PSScriptRoot
$sourceFixtureRepositoryRoot = [IO.Path]::GetFullPath(
    (Join-Path $sourceFixtureScriptRoot "..\..\.."))
$script:SteinSourceFixtureRegistrySha256 =
    "d2414e552dfbc00b3ecf5837cfc431c64f670508ae4e8696b9fce4f85a75c5c5"

function Get-SteinSourceFixtureBootstrapStreamSha256 {
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

function Open-SteinSourceFixtureBootstrapBinding {
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
        throw 'source_fixture_bootstrap_source_invalid'
    }
    $probe = Split-Path -Parent $resolved
    while ($probe.Length -ge $repository.Length) {
        $ancestor = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $ancestor.PSIsContainer -or
            (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'source_fixture_bootstrap_source_invalid'
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
            throw 'source_fixture_bootstrap_source_invalid'
        }
        $probe = $parent
    }
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -lt 1 -or $item.Length -gt 16777216) {
        throw 'source_fixture_bootstrap_source_invalid'
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ([long]$stream.Length -ne [long]$item.Length) {
            throw 'source_fixture_bootstrap_source_invalid'
        }
        $digest = Get-SteinSourceFixtureBootstrapStreamSha256 `
            -Stream $stream `
            -FailureCode 'source_fixture_bootstrap_source_invalid'
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

function Assert-SteinSourceFixtureBootstrapSourcesStable {
    $bindings = @($script:SteinSourceFixtureBootstrapBindings)
    $definitions = @($script:SteinSourceFixtureBootstrapDefinitions)
    if ($bindings.Count -ne 4 -or $definitions.Count -ne 4) {
        throw 'source_fixture_bootstrap_source_changed'
    }
    for ($index = 0; $index -lt $bindings.Count; $index++) {
        $binding = $bindings[$index]
        $definition = $definitions[$index]
        $item = Get-Item -LiteralPath $binding.full_path -Force -ErrorAction Stop
        if ([string]$binding.record.role -cne [string]$definition.role -or
            [string]$binding.full_path -cne [string]$definition.path -or
            [string]$binding.record.path -cne
                [string]$definition.path.Substring(
                    $sourceFixtureRepositoryRoot.Length + 1).Replace('\', '/') -or
            $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            [long]$item.Length -ne [long]$binding.record.size -or
            [long]$binding.stream.Length -ne [long]$binding.record.size -or
            (Get-SteinSourceFixtureBootstrapStreamSha256 `
                -Stream $binding.stream `
                -FailureCode 'source_fixture_bootstrap_source_changed') -cne
                [string]$binding.record.sha256) {
            throw 'source_fixture_bootstrap_source_changed'
        }
    }
    return @($bindings | ForEach-Object { $_.record })
}

$script:SteinSourceFixtureBootstrapDefinitions = @(
        [pscustomobject]@{
            role = 'evidence-contract'
            path = (Join-Path $sourceFixtureScriptRoot 'Evidence-Contract.ps1')
        },
        [pscustomobject]@{
            role = 'package-tools'
            path = (Join-Path $sourceFixtureRepositoryRoot `
                'packaging\windows-msix\PackageTools.ps1')
        },
        [pscustomobject]@{
            role = 'runner'
            path = $PSCommandPath
        },
        [pscustomobject]@{
            role = 'source-evidence'
            path = (Join-Path $sourceFixtureScriptRoot 'Source-Evidence.ps1')
        }
) | Sort-Object role
$script:SteinSourceFixtureBootstrapBindings = @(
    $script:SteinSourceFixtureBootstrapDefinitions | ForEach-Object {
        Open-SteinSourceFixtureBootstrapBinding `
            -Role $_.role `
            -Path $_.path `
            -RepositoryRoot $sourceFixtureRepositoryRoot
    })
$sourceEvidenceBootstrapBinding = @($script:SteinSourceFixtureBootstrapBindings |
    Where-Object { [string]$_.record.role -ceq 'source-evidence' })
$packageToolsBootstrapBinding = @($script:SteinSourceFixtureBootstrapBindings |
    Where-Object { [string]$_.record.role -ceq 'package-tools' })
if ($sourceEvidenceBootstrapBinding.Count -ne 1 -or
    $packageToolsBootstrapBinding.Count -ne 1) {
    throw 'source_fixture_bootstrap_source_invalid'
}
. $sourceEvidenceBootstrapBinding[0].full_path
if ((Get-SteinSourceFixtureBootstrapStreamSha256 `
            -Stream $sourceEvidenceBootstrapBinding[0].stream `
            -FailureCode 'source_fixture_bootstrap_source_changed') -cne
        [string]$sourceEvidenceBootstrapBinding[0].record.sha256) {
    throw 'source_fixture_bootstrap_source_changed'
}
. $packageToolsBootstrapBinding[0].full_path
if ((Get-SteinSourceFixtureBootstrapStreamSha256 `
            -Stream $packageToolsBootstrapBinding[0].stream `
            -FailureCode 'source_fixture_bootstrap_source_changed') -cne
        [string]$packageToolsBootstrapBinding[0].record.sha256) {
    throw 'source_fixture_bootstrap_source_changed'
}

function Assert-SteinSourceFixtureJsonShape {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string[]] $ExpectedProperties,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if ($null -eq $Value) {
        throw $FailureCode
    }
    $actual = if ($Value -is [Collections.IDictionary]) {
        @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)
    }
    else {
        @($Value.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    }
    $expected = @($ExpectedProperties | Sort-Object)
    if ($actual.Count -ne $expected.Count -or
        @(Compare-Object `
            -ReferenceObject $expected `
            -DifferenceObject $actual `
            -CaseSensitive).Count -ne 0) {
        throw $FailureCode
    }
}

function Read-SteinSourceFixtureLockedJson {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [long] $MaximumBytes = 1048576
    )

    if ($MaximumBytes -lt 1 -or $MaximumBytes -gt [int]::MaxValue) {
        throw "source_fixture_json_bound_invalid"
    }
    $capture = Read-SteinSourceEvidenceLockedUtf8File `
        -Path $Path `
        -MaximumBytes ([int]$MaximumBytes)
    try {
        $value = [string]$capture.text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "source_fixture_json_invalid"
    }
    return [pscustomobject]@{
        value = $value
        size = [long]$capture.size
        sha256 = [string]$capture.sha256
    }
}

function Get-SteinSourceFixtureExpectedDefinitions {
    return [ordered]@{
        "phase2-source-fixture-upgrade" = [ordered]@{
            source_fixture = "phase2-source-fixture-upgrade-v1"
            source_runner = "stein.phase2.source-fixture.upgrade.v1"
            gate = "P2-UPGRADE"
            gate_fixture = "phase2-upgrade-v1"
            gate_runner = "stein.phase2.upgrade.v1"
            subchecks = @("migration_atomicity_source", "migration_catalog_source")
        }
        "phase2-source-fixture-secrets" = [ordered]@{
            source_fixture = "phase2-source-fixture-secrets-v1"
            source_runner = "stein.phase2.source-fixture.secrets.v1"
            gate = "P2-SECRETS"
            gate_fixture = "phase2-secrets-v1"
            gate_runner = "stein.phase2.secrets.v1"
            subchecks = @("delete_failure_obligation", "no_client_read", "no_fallback")
        }
        "phase2-source-fixture-identity" = [ordered]@{
            source_fixture = "phase2-source-fixture-identity-v1"
            source_runner = "stein.phase2.source-fixture.identity.v1"
            gate = "P2-IDENTITY"
            gate_fixture = "phase2-identity-v1"
            gate_runner = "stein.phase2.identity.v1"
            subchecks = @("implicit_learning_denied", "revision_conflict", "stricter_policy")
        }
        "phase2-source-fixture-phase1-regression" = [ordered]@{
            source_fixture = "phase2-source-fixture-phase1-regression-v1"
            source_runner = "stein.phase2.source-fixture.phase1-regression.v1"
            gate = "P2-PHASE1-REGRESSION"
            gate_fixture = "phase2-phase1-regression-v1"
            gate_runner = "stein.phase2.phase1-regression.v1"
            subchecks = @("cancellation", "capacity", "protocol")
        }
        "phase2-source-fixture-goals" = [ordered]@{
            source_fixture = "phase2-source-fixture-goals-v1"
            source_runner = "stein.phase2.source-fixture.goals.v1"
            gate = "P2-GOALS"
            gate_fixture = "phase2-goals-v1"
            gate_runner = "stein.phase2.goals.v1"
            subchecks = @("delete_cascade", "idempotency", "revision_conflict")
        }
        "phase2-source-fixture-pixels" = [ordered]@{
            source_fixture = "phase2-source-fixture-pixels-v1"
            source_runner = "stein.phase2.source-fixture.pixels.v1"
            gate = "P2-PIXELS"
            gate_fixture = "phase2-pixels-v1"
            gate_runner = "stein.phase2.pixels.v1"
            subchecks = @("bounded_frame", "frame_destroyed", "structured_source_preferred")
        }
        "phase2-source-fixture-model-contract" = [ordered]@{
            source_fixture = "phase2-source-fixture-model-contract-v1"
            source_runner = "stein.phase2.source-fixture.model-contract.v1"
            gate = "P2-MODEL-CONTRACT"
            gate_fixture = "phase2-model-contract-v1"
            gate_runner = "stein.phase2.model-contract.v1"
            subchecks = @(
                "credential_absent", "diagnostic_minimized", "least_sensitive_packet",
                "no_provider_objects", "no_raw_response", "persistence_minimized",
                "route_intersection", "tools_absent", "unapproved_category_absent")
        }
        "phase2-source-fixture-intervention" = [ordered]@{
            source_fixture = "phase2-source-fixture-intervention-v1"
            source_runner = "stein.phase2.source-fixture.intervention.v1"
            gate = "P2-INTERVENTION"
            gate_fixture = "phase2-intervention-v1"
            gate_runner = "stein.phase2.intervention.v1"
            subchecks = @(
                "allow_decision", "audit_acknowledged", "candidate_validated",
                "near_deadline_trace", "uncertainty_qualified")
        }
        "phase2-source-fixture-policy-failsafe" = [ordered]@{
            source_fixture = "phase2-source-fixture-policy-failsafe-v1"
            source_runner = "stein.phase2.source-fixture.policy-failsafe.v1"
            gate = "P2-POLICY-FAILSAFE"
            gate_fixture = "phase2-policy-failsafe-v1"
            gate_runner = "stein.phase2.policy-failsafe.v1"
            subchecks = @(
                "audit_failure_denies", "authority_absent_denies", "cap_cooldown_denies",
                "invalid_output_denies", "legacy_empty_trace_denies", "lock_denies",
                "model_failure_denies", "mute_denies", "policy_failure_denies",
                "refusal_denies", "revision_mismatch_denies", "stale_source_denies",
                "tool_shaped_denies", "trace_content_free")
        }
        "phase2-source-fixture-notification" = [ordered]@{
            source_fixture = "phase2-source-fixture-notification-v1"
            source_runner = "stein.phase2.source-fixture.notification.v1"
            gate = "P2-NOTIFICATION"
            gate_fixture = "phase2-notification-v1"
            gate_runner = "stein.phase2.notification.v1"
            subchecks = @(
                "audit_truthful", "diagnostic_denied", "input_bearing_denied",
                "malformed_denied", "unpackaged_denied")
        }
        "phase2-source-fixture-outbox-recovery" = [ordered]@{
            source_fixture = "phase2-source-fixture-outbox-recovery-v1"
            source_runner = "stein.phase2.source-fixture.outbox-recovery.v1"
            gate = "P2-OUTBOX-RECOVERY"
            gate_fixture = "phase2-outbox-recovery-v1"
            gate_runner = "stein.phase2.outbox-recovery.v1"
            subchecks = @(
                "atomic_attempt_marker", "before_marker_no_call", "legacy_repair",
                "os_submission_unknown", "post_marker_unknown",
                "repository_open_no_semantic_recovery", "terminal_audit_unknown")
        }
        "phase2-source-fixture-revocation-race" = [ordered]@{
            source_fixture = "phase2-source-fixture-revocation-race-v1"
            source_runner = "stein.phase2.source-fixture.revocation-race.v1"
            gate = "P2-REVOCATION-RACE"
            gate_fixture = "phase2-revocation-race-v1"
            gate_runner = "stein.phase2.revocation-race.v1"
            subchecks = @(
                "credential_cleanup_pending", "delivery_late_denied",
                "native_cleanup_pending", "observation_late_denied",
                "queue_late_denied", "reasoning_late_denied")
        }
        "phase2-source-fixture-retention" = [ordered]@{
            source_fixture = "phase2-source-fixture-retention-v1"
            source_runner = "stein.phase2.source-fixture.retention.v1"
            gate = "P2-RETENTION"
            gate_fixture = "phase2-retention-v1"
            gate_runner = "stein.phase2.retention.v1"
            subchecks = @(
                "audit_thirty_day", "context_session", "deletion_all_paths",
                "observation_ten_minute", "outbox_actionability", "raw_immediate",
                "sweep_cadence", "sweep_shutdown_join")
        }
    }
}

function Test-SteinSourceFixtureSafeRelativePath {
    param([Parameter(Mandatory = $true)][string] $Value)

    if ($Value.Length -lt 1 -or $Value.Length -gt 512 -or
        [IO.Path]::IsPathRooted($Value) -or $Value.Contains("\") -or
        $Value -cmatch '[\x00-\x1f<>:"|?*]') {
        return $false
    }
    $parts = @($Value.Split('/'))
    if ($parts.Count -lt 1) {
        return $false
    }
    foreach ($part in $parts) {
        if ($part.Length -lt 1 -or $part.Length -gt 255 -or
            $part -ceq "." -or $part -ceq ".." -or $part -ieq ".git" -or
            $part.EndsWith(" ", [StringComparison]::Ordinal) -or
            $part.EndsWith(".", [StringComparison]::Ordinal)) {
            return $false
        }
    }
    return $true
}

function Assert-SteinSourceFixtureRegistry {
    param([Parameter(Mandatory = $true)] $Registry)

    Assert-SteinSourceFixtureJsonShape `
        -Value $Registry `
        -ExpectedProperties @(
            "schema_version", "registry_id", "receipt_schema_version", "fixtures") `
        -FailureCode "source_fixture_registry_schema_invalid"
    if (($Registry.schema_version -isnot [int] -and
            $Registry.schema_version -isnot [long]) -or
        [long]$Registry.schema_version -ne 1 -or
        [string]$Registry.registry_id -cne "stein.phase2.source-fixture.registry.v1" -or
        ($Registry.receipt_schema_version -isnot [int] -and
            $Registry.receipt_schema_version -isnot [long]) -or
        [long]$Registry.receipt_schema_version -ne 1) {
        throw "source_fixture_registry_identity_invalid"
    }

    $expected = Get-SteinSourceFixtureExpectedDefinitions
    $fixtures = @($Registry.fixtures)
    if ($fixtures.Count -ne $expected.Count) {
        throw "source_fixture_registry_fixture_set_invalid"
    }
    $expectedIds = @($expected.Keys)
    $seenFixtureIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenRunnerIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $totalInvocations = 0
    for ($fixtureIndex = 0; $fixtureIndex -lt $fixtures.Count; $fixtureIndex++) {
        $fixture = $fixtures[$fixtureIndex]
        Assert-SteinSourceFixtureJsonShape `
            -Value $fixture `
            -ExpectedProperties @(
                "source_check_id", "source_fixture_id", "source_runner_id",
                "gate_id", "gate_fixture_id", "gate_runner_id",
                "semantic_source_paths", "subchecks") `
            -FailureCode "source_fixture_registry_fixture_schema_invalid"
        $sourceCheckId = [string]$fixture.source_check_id
        if ($sourceCheckId -cne [string]$expectedIds[$fixtureIndex] -or
            [string]$fixture.source_fixture_id -cne
                [string]$expected[$sourceCheckId].source_fixture -or
            [string]$fixture.source_runner_id -cne
                [string]$expected[$sourceCheckId].source_runner -or
            [string]$fixture.gate_id -cne [string]$expected[$sourceCheckId].gate -or
            [string]$fixture.gate_fixture_id -cne
                [string]$expected[$sourceCheckId].gate_fixture -or
            [string]$fixture.gate_runner_id -cne
                [string]$expected[$sourceCheckId].gate_runner -or
            -not $seenFixtureIds.Add([string]$fixture.source_fixture_id) -or
            -not $seenRunnerIds.Add([string]$fixture.source_runner_id)) {
            throw "source_fixture_registry_fixture_identity_invalid"
        }

        $semanticPaths = @($fixture.semantic_source_paths | ForEach-Object { [string]$_ })
        if ($semanticPaths.Count -lt 2 -or $semanticPaths.Count -gt 64 -or
            @($semanticPaths | Select-Object -Unique).Count -ne $semanticPaths.Count) {
            throw "source_fixture_registry_semantic_path_set_invalid"
        }
        $sortedSemanticPaths = @($semanticPaths)
        [Array]::Sort($sortedSemanticPaths, [StringComparer]::Ordinal)
        for ($pathIndex = 0; $pathIndex -lt $semanticPaths.Count; $pathIndex++) {
            if ($semanticPaths[$pathIndex] -cne $sortedSemanticPaths[$pathIndex] -or
                -not (Test-SteinSourceFixtureSafeRelativePath -Value $semanticPaths[$pathIndex])) {
                throw "source_fixture_registry_semantic_path_invalid"
            }
        }

        $subchecks = @($fixture.subchecks)
        $expectedSubchecks = @($expected[$sourceCheckId].subchecks)
        if ($subchecks.Count -ne $expectedSubchecks.Count) {
            throw "source_fixture_registry_subcheck_set_invalid"
        }
        for ($subcheckIndex = 0; $subcheckIndex -lt $subchecks.Count; $subcheckIndex++) {
            $subcheck = $subchecks[$subcheckIndex]
            Assert-SteinSourceFixtureJsonShape `
                -Value $subcheck `
                -ExpectedProperties @("id", "invocations") `
                -FailureCode "source_fixture_registry_subcheck_schema_invalid"
            if ([string]$subcheck.id -cne [string]$expectedSubchecks[$subcheckIndex] -or
                [string]$subcheck.id -cnotmatch '^[a-z][a-z0-9_]{2,63}$') {
                throw "source_fixture_registry_subcheck_identity_invalid"
            }
            $invocations = @($subcheck.invocations)
            if ($invocations.Count -lt 1 -or $invocations.Count -gt 16) {
                throw "source_fixture_registry_invocation_set_invalid"
            }
            foreach ($invocation in $invocations) {
                Assert-SteinSourceFixtureJsonShape `
                    -Value $invocation `
                    -ExpectedProperties @("kind", "module", "test") `
                    -FailureCode "source_fixture_registry_invocation_schema_invalid"
                $kind = [string]$invocation.kind
                $module = [string]$invocation.module
                $test = [string]$invocation.test
                if ($kind -cnotin @(
                        "core", "store", "windows", "model", "desktop", "cli",
                        "protocol", "ipc", "boundary") -or
                    $module.Length -gt 96 -or
                    $module -cnotmatch '^[a-z][a-z0-9_]*(?:::[a-z][a-z0-9_]*)*$' -or
                    $test -cnotmatch '^[a-z][a-z0-9_]{1,127}$') {
                    throw "source_fixture_registry_invocation_identity_invalid"
                }
                switch ($kind) {
                    "store" {
                        if ($module -cne "repository") {
                            throw "source_fixture_registry_invocation_identity_invalid"
                        }
                    }
                    "model" {
                        if ($module -cne "tests") {
                            throw "source_fixture_registry_invocation_identity_invalid"
                        }
                    }
                    "desktop" {
                        if ($module -cnotin @("toast_activation", "phase2_secrets_tests")) {
                            throw "source_fixture_registry_invocation_identity_invalid"
                        }
                    }
                    "cli" {
                        if ($module -cne "tests") {
                            throw "source_fixture_registry_invocation_identity_invalid"
                        }
                    }
                    "protocol" {
                        if ($module -cne "protocol_contract") {
                            throw "source_fixture_registry_invocation_identity_invalid"
                        }
                    }
                    "ipc" {
                        if ($module -cnotin @("client::implementation", "server::implementation")) {
                            throw "source_fixture_registry_invocation_identity_invalid"
                        }
                    }
                    "boundary" {
                        if ($sourceCheckId -cne "phase2-source-fixture-model-contract" -or
                            [string]$subcheck.id -cne "no_provider_objects" -or
                            $module -cne "boundary" -or $test -cne "boundary_contract") {
                            throw "source_fixture_registry_invocation_identity_invalid"
                        }
                    }
                }
                $totalInvocations++
                if ($totalInvocations -gt 256) {
                    throw "source_fixture_registry_invocation_set_invalid"
                }
            }
        }
    }
    if ($totalInvocations -lt 8) {
        throw "source_fixture_registry_invocation_set_invalid"
    }
    return $true
}

function Get-SteinSourceFixtureCommand {
    param(
        [Parameter(Mandatory = $true)] $Invocation,
        [switch] $ListOnly
    )

    $kind = [string]$Invocation.kind
    $module = [string]$Invocation.module
    $test = [string]$Invocation.test
    $qualifiedName = $null
    $prefix = $null
    switch ($kind) {
        "core" {
            $qualifiedName = "$module`::tests::$test"
            $prefix = @(
                "test", "--locked", "--manifest-path", "Cargo.toml",
                "-p", "stein-core", "--lib")
        }
        "store" {
            $qualifiedName = $test
            $prefix = @(
                "test", "--locked", "--manifest-path", "Cargo.toml",
                "-p", "stein-store-sqlite", "--test", "repository")
        }
        "windows" {
            $qualifiedName = "$module`::tests::$test"
            $prefix = @(
                "test", "--locked", "--manifest-path", "Cargo.toml",
                "-p", "stein-platform-windows", "--lib")
        }
        "model" {
            $qualifiedName = "tests::$test"
            $prefix = @(
                "test", "--locked", "--manifest-path", "Cargo.toml",
                "-p", "stein-model-openai", "--lib")
        }
        "desktop" {
            $qualifiedName = if ($module -ceq "toast_activation") {
                "toast_activation::tests::$test"
            }
            else {
                "$module`::$test"
            }
            $prefix = @(
                "test", "--locked", "--manifest-path", "Cargo.toml",
                "-p", "stein-desktop", "--lib")
        }
        "cli" {
            $qualifiedName = "tests::$test"
            $prefix = @(
                "test", "--locked", "--manifest-path", "Cargo.toml",
                "-p", "stein-cli", "--bin", "stein-cli")
        }
        "protocol" {
            $qualifiedName = $test
            $prefix = @(
                "test", "--locked", "--manifest-path", "Cargo.toml",
                "-p", "stein-protocol", "--test", "protocol_contract")
        }
        "ipc" {
            $qualifiedName = "$module`::tests::$test"
            $prefix = @(
                "test", "--locked", "--manifest-path", "Cargo.toml",
                "-p", "stein-ipc", "--lib")
        }
        "boundary" {
            if ($ListOnly) {
                throw "source_fixture_boundary_has_no_list_command"
            }
            return [pscustomobject]@{
                kind = "boundary"
                qualified_name = "boundary_contract"
                executable = "powershell.exe"
                arguments = @(
                    "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                    "scripts/windows/check-boundaries.ps1", "-Json")
                working_directory = "."
            }
        }
        default { throw "source_fixture_command_kind_invalid" }
    }
    $suffix = if ($ListOnly) {
        @("--", $qualifiedName, "--exact", "--list")
    }
    else {
        @("--", $qualifiedName, "--exact", "--test-threads=1")
    }
    return [pscustomobject]@{
        kind = "cargo_test"
        qualified_name = $qualifiedName
        executable = "cargo.exe"
        arguments = @($prefix + $suffix)
        working_directory = "."
    }
}

function Get-SteinSourceFixtureInvocationId {
    param([Parameter(Mandatory = $true)] $Invocation)

    $material = @(
        "stein-source-fixture-invocation-v1",
        "kind=$([string]$Invocation.kind)",
        "module=$([string]$Invocation.module)",
        "test=$([string]$Invocation.test)") -join "`n"
    $digest = Get-SteinSourceEvidenceTextSha256 -Value $material
    return "source-invocation-$($digest.Substring(0, 24))"
}

function Get-SteinSourceFixtureHarnessDefinition {
    param([Parameter(Mandatory = $true)] $Invocation)

    $kind = [string]$Invocation.kind
    switch ($kind) {
        "core" {
            $package = "stein-core"
            $targetKind = "lib"
            $targetName = "stein_core"
            $manifest = "crates/stein-core/Cargo.toml"
            $selection = @("--lib")
        }
        "store" {
            $package = "stein-store-sqlite"
            $targetKind = "test"
            $targetName = "repository"
            $manifest = "crates/stein-store-sqlite/Cargo.toml"
            $selection = @("--test", "repository")
        }
        "windows" {
            $package = "stein-platform-windows"
            $targetKind = "lib"
            $targetName = "stein_platform_windows"
            $manifest = "crates/stein-platform-windows/Cargo.toml"
            $selection = @("--lib")
        }
        "model" {
            $package = "stein-model-openai"
            $targetKind = "lib"
            $targetName = "stein_model_openai"
            $manifest = "crates/stein-model-openai/Cargo.toml"
            $selection = @("--lib")
        }
        "desktop" {
            $package = "stein-desktop"
            $targetKind = "lib"
            $targetName = "stein_desktop_lib"
            $manifest = "apps/desktop/src-tauri/Cargo.toml"
            $selection = @("--lib")
        }
        "cli" {
            $package = "stein-cli"
            $targetKind = "bin"
            $targetName = "stein-cli"
            $manifest = "apps/core-cli/Cargo.toml"
            $selection = @("--bin", "stein-cli")
        }
        "protocol" {
            $package = "stein-protocol"
            $targetKind = "test"
            $targetName = "protocol_contract"
            $manifest = "crates/stein-protocol/Cargo.toml"
            $selection = @("--test", "protocol_contract")
        }
        "ipc" {
            $package = "stein-ipc"
            $targetKind = "lib"
            $targetName = "stein_ipc"
            $manifest = "crates/stein-ipc/Cargo.toml"
            $selection = @("--lib")
        }
        "boundary" { return $null }
        default { throw "source_fixture_harness_kind_invalid" }
    }
    $harnessId = "cargo-harness-$package-$targetKind-$targetName" -replace '_', '-'
    return [pscustomobject]@{
        harness_id = $harnessId
        package = $package
        target_kind = $targetKind
        target_name = $targetName
        manifest_path = $manifest
        compile_arguments = @(
            @(
                "test", "--locked", "--manifest-path", "Cargo.toml",
                "-p", $package) + $selection +
                @("--no-run", "--message-format=json-render-diagnostics"))
    }
}

function Resolve-SteinSourceFixtureCompilerArtifact {
    param(
        [Parameter(Mandatory = $true)][string] $StandardOutput,
        [Parameter(Mandatory = $true)] $Harness,
        [Parameter(Mandatory = $true)][string] $SnapshotRoot,
        [Parameter(Mandatory = $true)][string] $TargetRoot
    )

    $matches = New-Object Collections.Generic.List[object]
    $lineCount = 0
    foreach ($line in @($StandardOutput -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        $lineCount++
        if ($lineCount -gt 100000 -or $line.Length -gt 1048576) {
            throw "source_fixture_compiler_artifact_output_invalid"
        }
        try {
            $message = $line | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "source_fixture_compiler_artifact_output_invalid"
        }
        if ([string]$message.reason -cne "compiler-artifact" -or
            $null -eq $message.executable) {
            continue
        }
        $kinds = @($message.target.kind | ForEach-Object { [string]$_ })
        if ([string]$message.target.name -cne [string]$Harness.target_name -or
            $kinds.Count -ne 1 -or $kinds[0] -cne [string]$Harness.target_kind -or
            $message.profile.test -isnot [bool] -or -not [bool]$message.profile.test) {
            continue
        }
        $expectedManifest = [IO.Path]::GetFullPath((Join-Path $SnapshotRoot (
                    [string]$Harness.manifest_path).Replace(
                    '/', [IO.Path]::DirectorySeparatorChar)))
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$message.manifest_path),
                $expectedManifest,
                [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        $matches.Add($message)
    }
    if ($matches.Count -ne 1) {
        throw "source_fixture_compiler_artifact_not_exact"
    }
    $targetPath = [IO.Path]::GetFullPath($TargetRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $executable = [IO.Path]::GetFullPath([string]$matches[0].executable)
    if (-not $executable.StartsWith(
            "$targetPath$([IO.Path]::DirectorySeparatorChar)",
            [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetExtension($executable) -cne ".exe") {
        throw "source_fixture_compiler_artifact_outside_target"
    }
    $probe = Split-Path -Parent $executable
    while ($probe.Length -ge $targetPath.Length) {
        $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "source_fixture_compiler_artifact_reparse_invalid"
        }
        if ([string]::Equals($probe, $targetPath, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $probe = Split-Path -Parent $probe
    }
    $item = Get-Item -LiteralPath $executable -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -lt 1) {
        throw "source_fixture_compiler_artifact_invalid"
    }
    return [pscustomobject]@{
        Path = $item.FullName
        MatchCount = $matches.Count
    }
}

function Get-SteinSourceFixtureOutputRecord {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    return [ordered]@{
        size = [long]$bytes.Length
        sha256 = Get-SteinSourceEvidenceTextSha256 -Value $Value
    }
}

function Assert-SteinSourceFixtureListOutput {
    param(
        [Parameter(Mandatory = $true)][string] $QualifiedName,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $StandardOutput
    )

    $lines = @($StandardOutput -split "`r?`n" | Where-Object { $_.Length -ne 0 })
    $testLines = @($lines | Where-Object { $_ -cmatch ': test$' })
    $exactLine = "$QualifiedName`: test"
    if ($lines.Count -ne 2 -or
        $testLines.Count -ne 1 -or [string]$testLines[0] -cne $exactLine -or
        [string]$lines[0] -cne $exactLine -or
        [string]$lines[1] -cne "1 test, 0 benchmarks") {
        throw "source_fixture_test_list_not_exact"
    }
    return 1
}

function Assert-SteinSourceFixtureExecutionOutput {
    param(
        [Parameter(Mandatory = $true)][string] $QualifiedName,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $StandardOutput
    )

    $lines = @($StandardOutput -split "`r?`n" | Where-Object { $_.Length -ne 0 })
    $escaped = [regex]::Escape($QualifiedName)
    $passedLines = @($lines | Where-Object { $_ -cmatch "^test $escaped \.\.\. ok$" })
    $summaryLines = @($lines | Where-Object {
            $_ -cmatch '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s$'
        })
    if ($lines.Count -ne 3 -or
        [string]$lines[0] -cne 'running 1 test' -or
        $passedLines.Count -ne 1 -or [string]$lines[1] -cne [string]$passedLines[0] -or
        $summaryLines.Count -ne 1 -or [string]$lines[2] -cne [string]$summaryLines[0]) {
        throw "source_fixture_test_execution_not_exact"
    }
    return [pscustomobject]@{ passed = 1; failed = 0 }
}

function Assert-SteinSourceFixtureBoundaryOutput {
    param([Parameter(Mandatory = $true)][string] $StandardOutput)

    try {
        $value = $StandardOutput | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "source_fixture_boundary_output_invalid"
    }
    Assert-SteinSourceFixtureJsonShape `
        -Value $value `
        -ExpectedProperties @("schemaVersion", "passed", "checks", "violations") `
        -FailureCode "source_fixture_boundary_output_invalid"
    if ([long]$value.schemaVersion -ne 1 -or $value.passed -isnot [bool] -or
        -not [bool]$value.passed) {
        throw "source_fixture_boundary_output_invalid"
    }
    $expectedChecks = @(
        "core_direct_dependencies", "protocol_direct_dependencies",
        "core_source_imports", "protocol_source_imports")
    $checks = @($value.checks)
    if ($checks.Count -ne $expectedChecks.Count) {
        throw "source_fixture_boundary_output_invalid"
    }
    for ($index = 0; $index -lt $checks.Count; $index++) {
        Assert-SteinSourceFixtureJsonShape `
            -Value $checks[$index] `
            -ExpectedProperties @("name", "passed", "summary") `
            -FailureCode "source_fixture_boundary_output_invalid"
        if ([string]$checks[$index].name -cne $expectedChecks[$index] -or
            $checks[$index].passed -isnot [bool] -or
            -not [bool]$checks[$index].passed -or
            $checks[$index].summary -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$checks[$index].summary)) {
            throw "source_fixture_boundary_output_invalid"
        }
    }
    Assert-SteinSourceFixtureJsonShape `
        -Value $value.violations `
        -ExpectedProperties @("coreSource", "protocolSource") `
        -FailureCode "source_fixture_boundary_output_invalid"
    if (@($value.violations.coreSource).Count -ne 0 -or
        @($value.violations.protocolSource).Count -ne 0) {
        throw "source_fixture_boundary_output_invalid"
    }
    return $true
}

function Assert-SteinSourceFixtureExactArray {
    param(
        [AllowEmptyCollection()][object[]] $Actual,
        [AllowEmptyCollection()][object[]] $Expected,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    $actualValues = @($Actual | ForEach-Object { [string]$_ })
    $expectedValues = @($Expected | ForEach-Object { [string]$_ })
    if ($actualValues.Count -ne $expectedValues.Count) {
        throw $FailureCode
    }
    for ($index = 0; $index -lt $actualValues.Count; $index++) {
        if ($actualValues[$index] -cne $expectedValues[$index]) {
            throw $FailureCode
        }
    }
}

function Assert-SteinSourceFixtureHash {
    param(
        [AllowNull()] $Value,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if ($Value -isnot [string] -or
        [string]$Value -cnotmatch '^[0-9a-f]{64}$') {
        throw $FailureCode
    }
}

function Assert-SteinSourceFixtureOutputRecord {
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    Assert-SteinSourceFixtureJsonShape `
        -Value $Record `
        -ExpectedProperties @("size", "sha256") `
        -FailureCode $FailureCode
    if (($Record.size -isnot [int] -and $Record.size -isnot [long]) -or
        [long]$Record.size -lt 0 -or [long]$Record.size -gt 16777216) {
        throw $FailureCode
    }
    Assert-SteinSourceFixtureHash -Value $Record.sha256 -FailureCode $FailureCode
}

function Assert-SteinSourceFixtureReceipt {
    param(
        [Parameter(Mandatory = $true)] $Receipt,
        [Parameter(Mandatory = $true)] $Fixture,
        [Parameter(Mandatory = $true)][string] $ExpectedRegistrySha256,
        [string] $ExpectedCommit,
        [string] $ExpectedTree,
        [int] $ExpectedTreeFileCount = -1,
        [string] $ExpectedTreeManifestSha256,
        [string] $ExpectedSemanticManifestSha256,
        [string] $ExpectedCargoLauncherSha256,
        [string] $ExpectedCargoResolvedSha256,
        [string] $ExpectedRustcLauncherSha256,
        [string] $ExpectedRustcResolvedSha256,
        [string] $ExpectedRustupToolchain,
        [string] $ExpectedRustupVersion,
        [string] $ExpectedRustupSha256,
        [string] $ExpectedGitLauncherVersion,
        [string] $ExpectedGitLauncherSha256,
        [string] $ExpectedGitResolvedVersion,
        [string] $ExpectedGitResolvedSha256,
        [string] $ExpectedCompilerEnvironmentSha256,
        [string] $ExpectedGitEnvironmentSha256
    )

    $failureCode = "source_fixture_receipt_invalid"
    Assert-SteinSourceFixtureJsonShape `
        -Value $Receipt `
        -ExpectedProperties @(
            "schema_version", "claim", "source_check_id", "source_fixture_id",
            "source_runner_id", "gate_id", "gate_fixture_id", "gate_runner_id",
            "result", "bindings", "environment", "semantic_sources", "harnesses",
            "executions", "subchecks", "summary") `
        -FailureCode $failureCode
    if (($Receipt.schema_version -isnot [int] -and
            $Receipt.schema_version -isnot [long]) -or
        [long]$Receipt.schema_version -ne 1 -or
        [string]$Receipt.claim -cne "closed_source_fixture_only" -or
        [string]$Receipt.source_check_id -cne [string]$Fixture.source_check_id -or
        [string]$Receipt.source_fixture_id -cne [string]$Fixture.source_fixture_id -or
        [string]$Receipt.source_runner_id -cne [string]$Fixture.source_runner_id -or
        [string]$Receipt.gate_id -cne [string]$Fixture.gate_id -or
        [string]$Receipt.gate_fixture_id -cne [string]$Fixture.gate_fixture_id -or
        [string]$Receipt.gate_runner_id -cne [string]$Fixture.gate_runner_id -or
        [string]$Receipt.result -cne "pass") {
        throw $failureCode
    }
    Assert-SteinSourceFixtureJsonShape `
        -Value $Receipt.bindings `
        -ExpectedProperties @(
            "candidate_git_commit", "candidate_git_tree", "candidate_tree_file_count",
            "candidate_tree_manifest_sha256", "registry_sha256",
            "fixture_definition_sha256", "semantic_source_manifest_sha256",
            "rustup_toolchain", "rustup_version", "rustup_sha256",
            "cargo_launcher_sha256", "cargo_resolved_sha256",
            "rustc_launcher_sha256", "rustc_resolved_sha256",
            "git_launcher_version", "git_launcher_sha256",
            "git_resolved_version", "git_resolved_sha256",
            "compiler_environment_sha256", "git_environment_sha256") `
        -FailureCode $failureCode
    if ([string]$Receipt.bindings.candidate_git_commit -cnotmatch
            '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        [string]$Receipt.bindings.candidate_git_tree -cnotmatch
            '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        ([string]$Receipt.bindings.candidate_git_commit).Length -ne
            ([string]$Receipt.bindings.candidate_git_tree).Length -or
        ($Receipt.bindings.candidate_tree_file_count -isnot [int] -and
            $Receipt.bindings.candidate_tree_file_count -isnot [long]) -or
        [long]$Receipt.bindings.candidate_tree_file_count -lt 1 -or
        [long]$Receipt.bindings.candidate_tree_file_count -gt 100000 -or
        [string]$Receipt.bindings.registry_sha256 -cne $ExpectedRegistrySha256 -or
        [string]$Receipt.bindings.rustup_toolchain -cnotmatch
            '^[0-9A-Za-z][0-9A-Za-z._-]{2,127}$' -or
        [string]$Receipt.bindings.rustup_version -cnotmatch
            '^[\x20-\x7e]{1,160}$' -or
        [string]$Receipt.bindings.git_launcher_version -cnotmatch
            '^[\x20-\x7e]{1,160}$' -or
        [string]$Receipt.bindings.git_resolved_version -cne
            [string]$Receipt.bindings.git_launcher_version) {
        throw $failureCode
    }
    foreach ($hashProperty in @(
            "candidate_tree_manifest_sha256", "registry_sha256",
            "fixture_definition_sha256", "semantic_source_manifest_sha256",
            "cargo_launcher_sha256", "cargo_resolved_sha256",
            "rustc_launcher_sha256", "rustc_resolved_sha256",
            "rustup_sha256",
            "git_launcher_sha256", "git_resolved_sha256",
            "compiler_environment_sha256", "git_environment_sha256")) {
        Assert-SteinSourceFixtureHash `
            -Value $Receipt.bindings.$hashProperty `
            -FailureCode $failureCode
    }
    $fixtureDefinitionDigest = Get-SteinSourceEvidenceObjectDigest -Value $Fixture
    if ([string]$Receipt.bindings.fixture_definition_sha256 -cne
        $fixtureDefinitionDigest) {
        throw $failureCode
    }
    foreach ($comparison in @(
            [pscustomobject]@{ actual = $Receipt.bindings.candidate_git_commit; expected = $ExpectedCommit },
            [pscustomobject]@{ actual = $Receipt.bindings.candidate_git_tree; expected = $ExpectedTree },
            [pscustomobject]@{ actual = $Receipt.bindings.candidate_tree_manifest_sha256; expected = $ExpectedTreeManifestSha256 },
            [pscustomobject]@{ actual = $Receipt.bindings.semantic_source_manifest_sha256; expected = $ExpectedSemanticManifestSha256 },
            [pscustomobject]@{ actual = $Receipt.bindings.cargo_launcher_sha256; expected = $ExpectedCargoLauncherSha256 },
            [pscustomobject]@{ actual = $Receipt.bindings.cargo_resolved_sha256; expected = $ExpectedCargoResolvedSha256 },
            [pscustomobject]@{ actual = $Receipt.bindings.rustc_launcher_sha256; expected = $ExpectedRustcLauncherSha256 },
            [pscustomobject]@{ actual = $Receipt.bindings.rustc_resolved_sha256; expected = $ExpectedRustcResolvedSha256 },
            [pscustomobject]@{ actual = $Receipt.bindings.rustup_toolchain; expected = $ExpectedRustupToolchain },
            [pscustomobject]@{ actual = $Receipt.bindings.rustup_version; expected = $ExpectedRustupVersion },
            [pscustomobject]@{ actual = $Receipt.bindings.rustup_sha256; expected = $ExpectedRustupSha256 },
            [pscustomobject]@{ actual = $Receipt.bindings.git_launcher_version; expected = $ExpectedGitLauncherVersion },
            [pscustomobject]@{ actual = $Receipt.bindings.git_launcher_sha256; expected = $ExpectedGitLauncherSha256 },
            [pscustomobject]@{ actual = $Receipt.bindings.git_resolved_version; expected = $ExpectedGitResolvedVersion },
            [pscustomobject]@{ actual = $Receipt.bindings.git_resolved_sha256; expected = $ExpectedGitResolvedSha256 },
            [pscustomobject]@{ actual = $Receipt.bindings.compiler_environment_sha256; expected = $ExpectedCompilerEnvironmentSha256 },
            [pscustomobject]@{ actual = $Receipt.bindings.git_environment_sha256; expected = $ExpectedGitEnvironmentSha256 })) {
        if (-not [string]::IsNullOrWhiteSpace([string]$comparison.expected) -and
            [string]$comparison.actual -cne [string]$comparison.expected) {
            throw $failureCode
        }
    }
    if ($ExpectedTreeFileCount -ge 0 -and
        [long]$Receipt.bindings.candidate_tree_file_count -ne
            $ExpectedTreeFileCount) {
        throw $failureCode
    }

    Assert-SteinSourceFixtureJsonShape `
        -Value $Receipt.environment `
        -ExpectedProperties @(
            "source", "target", "tracked_source_lock", "working_directory",
            "cargo_home_precondition", "cargo_home_initial_entry_count",
            "cargo_config_precondition", "cargo_config_postcondition",
            "effective_compiler_environment", "effective_git_environment") `
        -FailureCode $failureCode
    if ([string]$Receipt.environment.source -cne "private_exact_git_snapshot" -or
        [string]$Receipt.environment.target -cne "fresh_private_shared_suite_target" -or
        [string]$Receipt.environment.tracked_source_lock -cne
            "all_candidate_files_held_read_only" -or
        [string]$Receipt.environment.working_directory -cne "." -or
        [string]$Receipt.environment.cargo_home_precondition -cne
            "fresh_private_owner_only_empty" -or
        [string]$Receipt.environment.cargo_config_precondition -cne
            "execution_and_snapshot_ancestor_configs_absent" -or
        [string]$Receipt.environment.cargo_config_postcondition -cne
            "execution_and_snapshot_ancestor_configs_absent" -or
        [long]$Receipt.environment.cargo_home_initial_entry_count -ne 0) {
        throw $failureCode
    }
    $effectiveCompilerEnvironment =
        Get-SteinSourceFixtureCompilerEnvironmentRecord `
            -RustupToolchain ([string]$Receipt.bindings.rustup_toolchain) `
            -PathSha256 `
                ([string]$Receipt.environment.effective_compiler_environment.PATH_SHA256)
    Assert-SteinSourceFixtureJsonShape `
        -Value $Receipt.environment.effective_compiler_environment `
        -ExpectedProperties @($effectiveCompilerEnvironment.Keys) `
        -FailureCode $failureCode
    foreach ($environmentName in $effectiveCompilerEnvironment.Keys) {
        if ([string]$Receipt.environment.effective_compiler_environment.$environmentName -cne
            [string]$effectiveCompilerEnvironment[$environmentName]) {
            throw $failureCode
        }
    }
    if ((Get-SteinSourceEvidenceObjectDigest `
            -Value $Receipt.environment.effective_compiler_environment) -cne
        [string]$Receipt.bindings.compiler_environment_sha256) {
        throw $failureCode
    }
    $effectiveGitEnvironment = Get-SteinSourceFixtureGitEnvironmentRecord `
        -PathSha256 `
            ([string]$Receipt.environment.effective_git_environment.PATH_SHA256)
    Assert-SteinSourceFixtureJsonShape `
        -Value $Receipt.environment.effective_git_environment `
        -ExpectedProperties @($effectiveGitEnvironment.Keys) `
        -FailureCode $failureCode
    foreach ($environmentName in $effectiveGitEnvironment.Keys) {
        if ([string]$Receipt.environment.effective_git_environment.$environmentName -cne
            [string]$effectiveGitEnvironment[$environmentName]) {
            throw $failureCode
        }
    }
    if ((Get-SteinSourceEvidenceObjectDigest `
            -Value $Receipt.environment.effective_git_environment) -cne
        [string]$Receipt.bindings.git_environment_sha256) {
        throw $failureCode
    }

    $semanticSources = @($Receipt.semantic_sources)
    $semanticPaths = @($Fixture.semantic_source_paths | ForEach-Object { [string]$_ })
    if ($semanticSources.Count -ne $semanticPaths.Count) {
        throw $failureCode
    }
    for ($sourceIndex = 0; $sourceIndex -lt $semanticSources.Count; $sourceIndex++) {
        $source = $semanticSources[$sourceIndex]
        Assert-SteinSourceFixtureJsonShape `
            -Value $source `
            -ExpectedProperties @("path", "size", "sha256", "git_blob_object_id") `
            -FailureCode $failureCode
        if ([string]$source.path -cne $semanticPaths[$sourceIndex] -or
            ($source.size -isnot [int] -and $source.size -isnot [long]) -or
            [long]$source.size -lt 1 -or
            [string]$source.git_blob_object_id -cnotmatch
                '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
            throw $failureCode
        }
        Assert-SteinSourceFixtureHash -Value $source.sha256 -FailureCode $failureCode
    }
    $recomputedSemanticDigest = Get-SteinSourceEvidenceObjectDigest -Value $semanticSources
    if ([string]$Receipt.bindings.semantic_source_manifest_sha256 -cne
        $recomputedSemanticDigest) {
        throw $failureCode
    }

    $expectedHarnessOrder = New-Object Collections.Generic.List[string]
    $expectedHarnesses = @{}
    foreach ($fixtureSubcheck in @($Fixture.subchecks)) {
        foreach ($fixtureInvocation in @($fixtureSubcheck.invocations)) {
            $harness = Get-SteinSourceFixtureHarnessDefinition -Invocation $fixtureInvocation
            if ($null -eq $harness) {
                continue
            }
            $harnessMaterial = $harness | ConvertTo-Json -Depth 8 -Compress
            if ($expectedHarnesses.ContainsKey([string]$harness.harness_id)) {
                if ([string]$expectedHarnesses[[string]$harness.harness_id].material -cne
                    $harnessMaterial) {
                    throw $failureCode
                }
            }
            else {
                $expectedHarnesses[[string]$harness.harness_id] = [pscustomobject]@{
                    definition = $harness
                    material = $harnessMaterial
                }
                $expectedHarnessOrder.Add([string]$harness.harness_id)
            }
        }
    }
    $receiptHarnesses = @($Receipt.harnesses)
    if ($receiptHarnesses.Count -ne $expectedHarnessOrder.Count) {
        throw $failureCode
    }
    for ($harnessIndex = 0; $harnessIndex -lt $receiptHarnesses.Count; $harnessIndex++) {
        $receiptHarness = $receiptHarnesses[$harnessIndex]
        $expectedHarnessId = [string]$expectedHarnessOrder[$harnessIndex]
        $definition = $expectedHarnesses[$expectedHarnessId].definition
        Assert-SteinSourceFixtureJsonShape `
            -Value $receiptHarness `
            -ExpectedProperties @(
                "harness_id", "package", "target_kind", "target_name", "manifest_path",
                "binary", "compile") `
            -FailureCode $failureCode
        if ([string]$receiptHarness.harness_id -cne $expectedHarnessId -or
            [string]$receiptHarness.package -cne [string]$definition.package -or
            [string]$receiptHarness.target_kind -cne [string]$definition.target_kind -or
            [string]$receiptHarness.target_name -cne [string]$definition.target_name -or
            [string]$receiptHarness.manifest_path -cne [string]$definition.manifest_path) {
            throw $failureCode
        }
        Assert-SteinSourceFixtureJsonShape `
            -Value $receiptHarness.binary `
            -ExpectedProperties @("size", "sha256") `
            -FailureCode $failureCode
        if (($receiptHarness.binary.size -isnot [int] -and
                $receiptHarness.binary.size -isnot [long]) -or
            [long]$receiptHarness.binary.size -lt 1 -or
            [long]$receiptHarness.binary.size -gt 2147483648) {
            throw $failureCode
        }
        Assert-SteinSourceFixtureHash `
            -Value $receiptHarness.binary.sha256 `
            -FailureCode $failureCode
        Assert-SteinSourceFixtureJsonShape `
            -Value $receiptHarness.compile `
            -ExpectedProperties @(
                "executable", "arguments", "working_directory", "exit_code", "stdout",
                "stderr", "compiler_artifact_matches") `
            -FailureCode $failureCode
        if ([string]$receiptHarness.compile.executable -cne "cargo.exe" -or
            [string]$receiptHarness.compile.working_directory -cne "." -or
            [long]$receiptHarness.compile.exit_code -ne 0 -or
            [long]$receiptHarness.compile.compiler_artifact_matches -ne 1) {
            throw $failureCode
        }
        Assert-SteinSourceFixtureExactArray `
            -Actual @($receiptHarness.compile.arguments) `
            -Expected @($definition.compile_arguments) `
            -FailureCode $failureCode
        foreach ($record in @($receiptHarness.compile.stdout, $receiptHarness.compile.stderr)) {
            Assert-SteinSourceFixtureOutputRecord -Record $record -FailureCode $failureCode
        }
    }

    $receiptSubchecks = @($Receipt.subchecks)
    $fixtureSubchecks = @($Fixture.subchecks)
    if ($receiptSubchecks.Count -ne $fixtureSubchecks.Count) {
        throw $failureCode
    }
    $expectedExecutionOrder = New-Object Collections.Generic.List[string]
    $expectedInvocations = @{}
    $mappingCount = 0
    for ($subcheckIndex = 0; $subcheckIndex -lt $fixtureSubchecks.Count; $subcheckIndex++) {
        $receiptSubcheck = $receiptSubchecks[$subcheckIndex]
        $fixtureSubcheck = $fixtureSubchecks[$subcheckIndex]
        Assert-SteinSourceFixtureJsonShape `
            -Value $receiptSubcheck `
            -ExpectedProperties @("id", "result", "execution_ids") `
            -FailureCode $failureCode
        $expectedExecutionIds = New-Object Collections.Generic.List[string]
        foreach ($fixtureInvocation in @($fixtureSubcheck.invocations)) {
            $executionId = Get-SteinSourceFixtureInvocationId -Invocation $fixtureInvocation
            $expectedExecutionIds.Add($executionId)
            $mappingCount++
            $invocationMaterial = $fixtureInvocation | ConvertTo-Json -Depth 4 -Compress
            if ($expectedInvocations.ContainsKey($executionId)) {
                if ([string]$expectedInvocations[$executionId].material -cne $invocationMaterial) {
                    throw $failureCode
                }
            }
            else {
                $expectedInvocations[$executionId] = [pscustomobject]@{
                    invocation = $fixtureInvocation
                    material = $invocationMaterial
                }
                $expectedExecutionOrder.Add($executionId)
            }
        }
        if ([string]$receiptSubcheck.id -cne [string]$fixtureSubcheck.id -or
            [string]$receiptSubcheck.result -cne "pass") {
            throw $failureCode
        }
        Assert-SteinSourceFixtureExactArray `
            -Actual @($receiptSubcheck.execution_ids) `
            -Expected @($expectedExecutionIds | ForEach-Object { $_ }) `
            -FailureCode $failureCode
    }

    $receiptExecutions = @($Receipt.executions)
    if ($receiptExecutions.Count -ne $expectedExecutionOrder.Count) {
        throw $failureCode
    }
    $cargoCount = 0
    $boundaryCount = 0
    for ($executionIndex = 0; $executionIndex -lt $receiptExecutions.Count; $executionIndex++) {
        $receiptInvocation = $receiptExecutions[$executionIndex]
        $expectedExecutionId = [string]$expectedExecutionOrder[$executionIndex]
        $fixtureInvocation = $expectedInvocations[$expectedExecutionId].invocation
        $isBoundary = [string]$fixtureInvocation.kind -ceq "boundary"
        $expectedProperties = @(
            "execution_id", "sequence", "kind", "qualified_test_name", "executable",
            "arguments", "working_directory", "execution")
        if (-not $isBoundary) {
            $expectedProperties += @("harness_id", "registered_cargo_arguments", "preflight")
        }
        else {
            $expectedProperties += @('nested_tool')
        }
        Assert-SteinSourceFixtureJsonShape `
            -Value $receiptInvocation `
            -ExpectedProperties $expectedProperties `
            -FailureCode $failureCode
        $command = Get-SteinSourceFixtureCommand -Invocation $fixtureInvocation
        if ([string]$receiptInvocation.execution_id -cne $expectedExecutionId -or
            [long]$receiptInvocation.sequence -ne ($executionIndex + 1) -or
            [string]$receiptInvocation.kind -cne
                $(if ($isBoundary) { "boundary" } else { "cargo_test" }) -or
            [string]$receiptInvocation.qualified_test_name -cne
                [string]$command.qualified_name -or
            [string]$receiptInvocation.executable -cne
                $(if ($isBoundary) { "powershell.exe" } else { "locked_test_binary" }) -or
            [string]$receiptInvocation.working_directory -cne ".") {
            throw $failureCode
        }
        if ($isBoundary) {
            Assert-SteinSourceFixtureExactArray `
                -Actual @($receiptInvocation.arguments) `
                -Expected @($command.arguments) `
                -FailureCode $failureCode
            Assert-SteinSourceFixtureJsonShape `
                -Value $receiptInvocation.nested_tool `
                -ExpectedProperties @(
                    'executable', 'sha256', 'arguments', 'working_directory') `
                -FailureCode $failureCode
            Assert-SteinSourceFixtureHash `
                -Value $receiptInvocation.nested_tool.sha256 `
                -FailureCode $failureCode
            Assert-SteinSourceFixtureExactArray `
                -Actual @($receiptInvocation.nested_tool.arguments) `
                -Expected @(
                    'metadata', '--locked', '--no-deps', '--format-version',
                    '1', '--manifest-path', 'Cargo.toml') `
                -FailureCode $failureCode
            if ([string]$receiptInvocation.nested_tool.executable -cne
                    'resolved_cargo_payload' -or
                [string]$receiptInvocation.nested_tool.sha256 -cne
                    [string]$Receipt.bindings.cargo_resolved_sha256 -or
                [string]$receiptInvocation.nested_tool.working_directory -cne
                    'validated_config_free_system_directory') {
                throw $failureCode
            }
            Assert-SteinSourceFixtureJsonShape `
                -Value $receiptInvocation.execution `
                -ExpectedProperties @(
                    "exit_code", "stdout", "stderr", "passed_checks", "failed_checks") `
                -FailureCode $failureCode
            if ([long]$receiptInvocation.execution.exit_code -ne 0 -or
                [long]$receiptInvocation.execution.passed_checks -ne 4 -or
                [long]$receiptInvocation.execution.failed_checks -ne 0 -or
                [long]$receiptInvocation.execution.stderr.size -ne 0) {
                throw $failureCode
            }
            $boundaryCount++
        }
        else {
            $expectedHarness = Get-SteinSourceFixtureHarnessDefinition `
                -Invocation $fixtureInvocation
            if ([string]$receiptInvocation.harness_id -cne
                    [string]$expectedHarness.harness_id -or
                -not $expectedHarnesses.ContainsKey([string]$receiptInvocation.harness_id)) {
                throw $failureCode
            }
            Assert-SteinSourceFixtureExactArray `
                -Actual @($receiptInvocation.registered_cargo_arguments) `
                -Expected @($command.arguments) `
                -FailureCode $failureCode
            Assert-SteinSourceFixtureExactArray `
                -Actual @($receiptInvocation.arguments) `
                -Expected @(
                    [string]$command.qualified_name, "--exact", "--test-threads=1") `
                -FailureCode $failureCode
            Assert-SteinSourceFixtureJsonShape `
                -Value $receiptInvocation.preflight `
                -ExpectedProperties @(
                    "exit_code", "arguments", "stdout", "stderr", "exact_test_matches") `
                -FailureCode $failureCode
            $listCommand = Get-SteinSourceFixtureCommand `
                -Invocation $fixtureInvocation `
                -ListOnly
            Assert-SteinSourceFixtureExactArray `
                -Actual @($receiptInvocation.preflight.arguments) `
                -Expected @([string]$listCommand.qualified_name, "--exact", "--list") `
                -FailureCode $failureCode
            Assert-SteinSourceFixtureJsonShape `
                -Value $receiptInvocation.execution `
                -ExpectedProperties @(
                    "exit_code", "stdout", "stderr", "passed_tests", "failed_tests") `
                -FailureCode $failureCode
            if ([long]$receiptInvocation.preflight.exit_code -ne 0 -or
                [long]$receiptInvocation.preflight.exact_test_matches -ne 1 -or
                [long]$receiptInvocation.execution.exit_code -ne 0 -or
                [long]$receiptInvocation.execution.passed_tests -ne 1 -or
                [long]$receiptInvocation.execution.failed_tests -ne 0 -or
                [long]$receiptInvocation.preflight.stderr.size -ne 0 -or
                [long]$receiptInvocation.execution.stderr.size -ne 0) {
                throw $failureCode
            }
            foreach ($record in @(
                    $receiptInvocation.preflight.stdout,
                    $receiptInvocation.preflight.stderr)) {
                Assert-SteinSourceFixtureOutputRecord `
                    -Record $record `
                    -FailureCode $failureCode
            }
            $cargoCount++
        }
        foreach ($record in @(
                $receiptInvocation.execution.stdout,
                $receiptInvocation.execution.stderr)) {
            Assert-SteinSourceFixtureOutputRecord `
                -Record $record `
                -FailureCode $failureCode
        }
    }
    Assert-SteinSourceFixtureJsonShape `
        -Value $Receipt.summary `
        -ExpectedProperties @(
            "subcheck_count", "harness_count", "invocation_mapping_count",
            "unique_execution_count", "cargo_test_execution_count",
            "boundary_execution_count") `
        -FailureCode $failureCode
    if ([long]$Receipt.summary.subcheck_count -ne $fixtureSubchecks.Count -or
        [long]$Receipt.summary.harness_count -ne $receiptHarnesses.Count -or
        [long]$Receipt.summary.invocation_mapping_count -ne $mappingCount -or
        [long]$Receipt.summary.unique_execution_count -ne $receiptExecutions.Count -or
        [long]$Receipt.summary.cargo_test_execution_count -ne $cargoCount -or
        [long]$Receipt.summary.boundary_execution_count -ne $boundaryCount) {
        throw $failureCode
    }
    return $true
}

function Assert-SteinSourceFixtureIndex {
    param(
        [Parameter(Mandatory = $true)] $Index,
        [Parameter(Mandatory = $true)] $Registry,
        [Parameter(Mandatory = $true)][string] $ExpectedRegistrySha256,
        [string] $ExpectedCommit,
        [string] $ExpectedTree,
        [string] $ExpectedGitLauncherVersion,
        [string] $ExpectedGitLauncherSha256,
        [string] $ExpectedGitResolvedVersion,
        [string] $ExpectedGitResolvedSha256,
        [string] $ExpectedRustupVersion,
        [string] $ExpectedRustupSha256,
        [string] $ExpectedRustupToolchain
    )

    $failureCode = "source_fixture_index_invalid"
    Assert-SteinSourceFixtureJsonShape `
        -Value $Index `
        -ExpectedProperties @(
            "schema_version", "suite_id", "result", "candidate_git_commit",
            "candidate_git_tree", "registry_sha256", "git", "rustup",
            "receipts") `
        -FailureCode $failureCode
    if (($Index.schema_version -isnot [int] -and
            $Index.schema_version -isnot [long]) -or
        [long]$Index.schema_version -ne 1 -or
        [string]$Index.suite_id -cne "stein.phase2.source-fixture-suite.v1" -or
        [string]$Index.result -cne "pass" -or
        [string]$Index.candidate_git_commit -cnotmatch
            '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        [string]$Index.candidate_git_tree -cnotmatch
            '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        [string]$Index.registry_sha256 -cne $ExpectedRegistrySha256 -or
        (-not [string]::IsNullOrWhiteSpace($ExpectedCommit) -and
            [string]$Index.candidate_git_commit -cne $ExpectedCommit) -or
        (-not [string]::IsNullOrWhiteSpace($ExpectedTree) -and
            [string]$Index.candidate_git_tree -cne $ExpectedTree)) {
        throw $failureCode
    }
    Assert-SteinSourceFixtureJsonShape `
        -Value $Index.git `
        -ExpectedProperties @(
            "launcher_version", "launcher_sha256", "resolved_version",
            "resolved_sha256") `
        -FailureCode $failureCode
    foreach ($hashProperty in @("launcher_sha256", "resolved_sha256")) {
        Assert-SteinSourceFixtureHash `
            -Value $Index.git.$hashProperty `
            -FailureCode $failureCode
    }
    if ([string]$Index.git.launcher_version -cnotmatch '^[\x20-\x7e]{1,160}$' -or
        [string]$Index.git.resolved_version -cne [string]$Index.git.launcher_version) {
        throw $failureCode
    }
    foreach ($comparison in @(
            [pscustomobject]@{ actual = $Index.git.launcher_version; expected = $ExpectedGitLauncherVersion },
            [pscustomobject]@{ actual = $Index.git.launcher_sha256; expected = $ExpectedGitLauncherSha256 },
            [pscustomobject]@{ actual = $Index.git.resolved_version; expected = $ExpectedGitResolvedVersion },
            [pscustomobject]@{ actual = $Index.git.resolved_sha256; expected = $ExpectedGitResolvedSha256 })) {
        if (-not [string]::IsNullOrWhiteSpace([string]$comparison.expected) -and
            [string]$comparison.actual -cne [string]$comparison.expected) {
            throw $failureCode
        }
    }
    Assert-SteinSourceFixtureJsonShape `
        -Value $Index.rustup `
        -ExpectedProperties @('version', 'sha256', 'toolchain') `
        -FailureCode $failureCode
    Assert-SteinSourceFixtureHash `
        -Value $Index.rustup.sha256 `
        -FailureCode $failureCode
    if ([string]$Index.rustup.version -cnotmatch '^[\x20-\x7e]{1,160}$' -or
        [string]$Index.rustup.toolchain -cnotmatch
            '^[0-9A-Za-z][0-9A-Za-z._-]{2,127}$') {
        throw $failureCode
    }
    foreach ($comparison in @(
            [pscustomobject]@{ actual = $Index.rustup.version; expected = $ExpectedRustupVersion },
            [pscustomobject]@{ actual = $Index.rustup.sha256; expected = $ExpectedRustupSha256 },
            [pscustomobject]@{ actual = $Index.rustup.toolchain; expected = $ExpectedRustupToolchain })) {
        if (-not [string]::IsNullOrWhiteSpace([string]$comparison.expected) -and
            [string]$comparison.actual -cne [string]$comparison.expected) {
            throw $failureCode
        }
    }
    $receipts = @($Index.receipts)
    $fixtures = @($Registry.fixtures)
    if ($receipts.Count -ne $fixtures.Count) {
        throw $failureCode
    }
    for ($indexPosition = 0; $indexPosition -lt $fixtures.Count; $indexPosition++) {
        $descriptor = $receipts[$indexPosition]
        $fixture = $fixtures[$indexPosition]
        Assert-SteinSourceFixtureJsonShape `
            -Value $descriptor `
            -ExpectedProperties @(
                "source_check_id", "source_fixture_id", "source_runner_id", "gate_id",
                "gate_fixture_id", "gate_runner_id", "path", "size", "sha256") `
            -FailureCode $failureCode
        $expectedPath = "$([string]$fixture.source_check_id).receipt.json"
        if ([string]$descriptor.source_check_id -cne [string]$fixture.source_check_id -or
            [string]$descriptor.source_fixture_id -cne
                [string]$fixture.source_fixture_id -or
            [string]$descriptor.source_runner_id -cne [string]$fixture.source_runner_id -or
            [string]$descriptor.gate_id -cne [string]$fixture.gate_id -or
            [string]$descriptor.gate_fixture_id -cne [string]$fixture.gate_fixture_id -or
            [string]$descriptor.gate_runner_id -cne [string]$fixture.gate_runner_id -or
            [string]$descriptor.path -cne $expectedPath -or
            ($descriptor.size -isnot [int] -and $descriptor.size -isnot [long]) -or
            [long]$descriptor.size -lt 1 -or [long]$descriptor.size -gt 4194304) {
            throw $failureCode
        }
        Assert-SteinSourceFixtureHash -Value $descriptor.sha256 -FailureCode $failureCode
    }
    return $true
}

function Resolve-SteinSourceFixtureWindowsPowerShell {
    $system = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($system)) {
        throw "source_fixture_powershell_unavailable"
    }
    $candidate = [IO.Path]::GetFullPath(
        (Join-Path $system "WindowsPowerShell\v1.0\powershell.exe"))
    $item = Get-SteinSourceEvidenceRegularFileItem -Path $candidate
    if ([IO.Path]::GetFileName($item.FullName) -cne "powershell.exe") {
        throw "source_fixture_powershell_invalid"
    }
    return $item.FullName
}

function Resolve-SteinSourceFixtureRustTool {
    param(
        [Parameter(Mandatory = $true)][string] $RustupExecutable,
        [Parameter(Mandatory = $true)][string] $Toolchain,
        [Parameter(Mandatory = $true)][ValidateSet("cargo", "rustc")][string] $Name,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )

    $result = Invoke-SteinSourceEvidenceProcess `
        -Executable $RustupExecutable `
        -Arguments @("which", "--toolchain", $Toolchain, $Name) `
        -WorkingDirectory $WorkingDirectory `
        -MaximumStandardOutputCharacters 4096 `
        -MaximumStandardErrorCharacters 512
    $path = $result.stdout.Trim()
    if (-not [string]::IsNullOrWhiteSpace([string]$result.stderr) -or
        -not [IO.Path]::IsPathRooted($path) -or
        [IO.Path]::GetFileName($path) -cne "$Name.exe") {
        throw "source_fixture_rust_tool_invalid"
    }
    return (Get-SteinSourceEvidenceRegularFileItem -Path $path).FullName
}

function Get-SteinSourceFixtureTreeBinding {
    param([Parameter(Mandatory = $true)] $Snapshot)

    $records = New-Object Collections.Generic.List[string]
    foreach ($file in @($Snapshot.Files)) {
        $path = [string]$file.RelativePath
        $pathBytes = [Text.UTF8Encoding]::new($false).GetByteCount($path)
        $records.Add(
            "$pathBytes`:$path|$([string]$file.Mode)|$([string]$file.ObjectId)")
    }
    $records.Sort([StringComparer]::Ordinal)
    $recordArray = $records.ToArray()
    return [ordered]@{
        file_count = $recordArray.Count
        manifest_sha256 = Get-SteinSourceEvidenceTextSha256 `
            -Value ($recordArray -join "`n")
    }
}

function Get-SteinSourceFixtureSemanticBinding {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)][string[]] $RelativePaths
    )

    $byPath = @{}
    foreach ($record in @($Snapshot.Files)) {
        $byPath[[string]$record.RelativePath] = $record
    }
    $records = New-Object Collections.Generic.List[object]
    foreach ($relativePath in $RelativePaths) {
        if (-not $byPath.ContainsKey($relativePath)) {
            throw "source_fixture_semantic_source_missing"
        }
        $path = Resolve-SteinPackageRegularFileUnderRoot `
            -Root $Snapshot.Root `
            -Path (Join-Path $Snapshot.Root $relativePath.Replace(
                    '/', [IO.Path]::DirectorySeparatorChar))
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        $records.Add([ordered]@{
                path = $relativePath
                size = [long]$item.Length
                sha256 = Get-SteinSourceEvidenceSha256 -Path $item.FullName
                git_blob_object_id = [string]$byPath[$relativePath].ObjectId
            })
    }
    $recordArray = @($records | ForEach-Object { $_ })
    return [pscustomobject]@{
        Records = $recordArray
        Digest = Get-SteinSourceEvidenceObjectDigest -Value $recordArray
    }
}

function Invoke-SteinSourceFixtureProcessCapture {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )

    return Invoke-SteinSourceEvidenceProcess `
        -Executable $Executable `
        -Arguments $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -AllowedExitCodes @(0..255) `
        -MaximumStandardOutputCharacters 4194304 `
        -MaximumStandardErrorCharacters 4194304
}

function Assert-SteinSourceFixtureGitBindingRecord {
    param(
        [Parameter(Mandatory = $true)][string] $LauncherPath,
        [Parameter(Mandatory = $true)][string] $ResolvedPath,
        [Parameter(Mandatory = $true)] $Record
    )

    Assert-SteinSourceFixtureJsonShape `
        -Value $Record `
        -ExpectedProperties @(
            "version", "executable_sha256", "resolved_version",
            "resolved_executable_sha256") `
        -FailureCode "source_fixture_git_binding_invalid"
    foreach ($hashProperty in @("executable_sha256", "resolved_executable_sha256")) {
        Assert-SteinSourceFixtureHash `
            -Value $Record.$hashProperty `
            -FailureCode "source_fixture_git_binding_invalid"
    }
    if ([string]$Record.version -cnotmatch '^[\x20-\x7e]{1,160}$' -or
        [string]$Record.resolved_version -cne [string]$Record.version -or
        (Get-SteinSourceEvidenceSha256 -Path $LauncherPath) -cne
            [string]$Record.executable_sha256 -or
        (Get-SteinSourceEvidenceSha256 -Path $ResolvedPath) -cne
            [string]$Record.resolved_executable_sha256) {
        throw "source_fixture_git_binding_invalid"
    }
    return $true
}

function Get-SteinSourceFixtureGitBinding {
    param(
        [Parameter(Mandatory = $true)][string] $LauncherExecutable,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )

    $launcher = Get-SteinSourceEvidenceRegularFileItem -Path $LauncherExecutable
    $launcherDirectory = [IO.Path]::GetFullPath(
        (Split-Path -Parent $launcher.FullName)).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    if ([IO.Path]::GetFileName($launcher.FullName) -cne "git.exe" -or
        [IO.Path]::GetFileName($launcherDirectory) -cne "cmd") {
        throw "source_fixture_git_launcher_invalid"
    }
    $installationRoot = [IO.Path]::GetFullPath(
        (Split-Path -Parent $launcherDirectory)).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $resolvedPath = [IO.Path]::GetFullPath(
        (Join-Path $installationRoot "mingw64\bin\git.exe"))
    if (-not $resolvedPath.StartsWith(
            "$installationRoot$([IO.Path]::DirectorySeparatorChar)",
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "source_fixture_git_payload_invalid"
    }
    $resolved = Get-SteinSourceEvidenceRegularFileItem -Path $resolvedPath
    $record = Get-SteinSourceEvidenceGitToolRecord `
        -Executable $launcher.FullName `
        -WorkingDirectory $WorkingDirectory
    $null = Assert-SteinSourceFixtureGitBindingRecord `
        -LauncherPath $launcher.FullName `
        -ResolvedPath $resolved.FullName `
        -Record $record
    return [pscustomobject]@{
        LauncherPath = [string]$launcher.FullName
        ResolvedPath = [string]$resolved.FullName
        Record = $record
    }
}

function Get-SteinSourceFixtureCompilerEnvironmentNames {
    return @(
        "CARGO_HOME", "CARGO_INCREMENTAL", "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET_DIR", "CARGO_TERM_COLOR", "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN")
}

function Test-SteinSourceFixtureSensitiveEnvironmentName {
    param([Parameter(Mandatory = $true)][string] $Name)

    return $Name -match '^(?:CARGO_|RUST|CC(?:_.+)?$|CXX(?:_.+)?$|AR(?:_.+)?$|CFLAGS(?:_.+)?$|CXXFLAGS(?:_.+)?$|RANLIB(?:_.+)?$|RC(?:_.+)?$|LINK(?:_.+)?$|LIB(?:_.+)?$|BINDGEN|PKG_CONFIG|VCPKG|GIT_)'
}

function Get-SteinSourceFixtureRejectedCompilerOverrideNames {
    return @(
        "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN")
}

function Assert-SteinSourceFixtureCompilerOverridesAbsent {
    param([Parameter(Mandatory = $true)][Collections.IDictionary] $Environment)

    foreach ($name in @($Environment.Keys | ForEach-Object { [string]$_ })) {
        $value = [string]$Environment[$name]
        $isRejectedCompilerName =
            $name -match '^(?:CARGO_|RUSTC(?:_|$)|RUSTFLAGS$|RUSTUP_HOME$|RUSTUP_TOOLCHAIN$|CC(?:_.+)?$|CXX(?:_.+)?$|AR(?:_.+)?$|CFLAGS(?:_.+)?$|CXXFLAGS(?:_.+)?$|RANLIB(?:_.+)?$|RC(?:_.+)?$|LINK(?:_.+)?$|LIB(?:_.+)?$|BINDGEN|PKG_CONFIG|VCPKG)'
        $isGitRedirect = $name -match '^(?:GIT_DIR|GIT_WORK_TREE|GIT_OBJECT_DIRECTORY|GIT_ALTERNATE_OBJECT_DIRECTORIES|GIT_REPLACE_REF_BASE|GIT_CONFIG(?:_|$)|GIT_COMMON_DIR|GIT_INDEX_FILE|GIT_NAMESPACE|GIT_CEILING_DIRECTORIES|GIT_DISCOVERY_ACROSS_FILESYSTEM)$'
        if (($isRejectedCompilerName -or $isGitRedirect) -and
            -not [string]::IsNullOrEmpty($value)) {
            throw "source_fixture_compiler_override_set"
        }
    }
    return $true
}

function Get-SteinSourceFixturePathSha256 {
    $pathValue = [Environment]::GetEnvironmentVariable(
        'PATH',
        [EnvironmentVariableTarget]::Process)
    return Get-SteinSourceEvidenceTextSha256 -Value ([string]$pathValue)
}

function Get-SteinSourceFixtureGitEnvironmentRecord {
    param([Parameter(Mandatory = $true)][string] $PathSha256)

    Assert-SteinSourceFixtureHash `
        -Value $PathSha256 `
        -FailureCode 'source_fixture_git_environment_invalid'
    return [ordered]@{
        GIT_CONFIG_NOSYSTEM = '1'
        GIT_CONFIG_GLOBAL = 'NUL'
        GIT_CONFIG_COUNT = '0'
        GIT_NO_REPLACE_OBJECTS = '1'
        GIT_TERMINAL_PROMPT = '0'
        GIT_OPTIONAL_LOCKS = '0'
        OTHER_GIT_ENVIRONMENT = 'cleared'
        PATH_SHA256 = $PathSha256
    }
}

function Assert-SteinSourceFixtureCargoConfigAbsent {
    param([Parameter(Mandatory = $true)][string[]] $StartPaths)

    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($startPath in $StartPaths) {
        $cursor = Get-Item -LiteralPath ([IO.Path]::GetFullPath($startPath)) `
            -Force -ErrorAction Stop
        if (-not $cursor.PSIsContainer) {
            throw 'source_fixture_cargo_config_path_invalid'
        }
        while ($null -ne $cursor) {
            if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'source_fixture_cargo_config_ancestor_reparse'
            }
            if ($seen.Add([string]$cursor.FullName)) {
                foreach ($relativeConfig in @(
                        '.cargo\config', '.cargo\config.toml')) {
                    $configPath = Join-Path $cursor.FullName $relativeConfig
                    if (Test-Path -LiteralPath $configPath) {
                        throw 'source_fixture_cargo_config_discovered'
                    }
                }
            }
            $cursor = $cursor.Parent
        }
    }
    return $true
}

function ConvertTo-SteinSourceFixtureActualCargoArguments {
    param(
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $SnapshotRoot
    )

    $actual = @($Arguments | ForEach-Object { [string]$_ })
    $matches = @(
        for ($index = 0; $index -lt ($actual.Count - 1); $index++) {
            if ($actual[$index] -ceq '--manifest-path' -and
                $actual[$index + 1] -ceq 'Cargo.toml') {
                $index
            }
        })
    if ($matches.Count -ne 1) {
        throw 'source_fixture_manifest_argument_invalid'
    }
    $actual[[int]$matches[0] + 1] = [IO.Path]::GetFullPath(
        (Join-Path $SnapshotRoot 'Cargo.toml'))
    return $actual
}

function New-SteinSourceFixturePrivateCargoHome {
    param([Parameter(Mandatory = $true)][string] $BuildRoot)

    $root = Resolve-SteinPackageRegularDirectoryWithAncestors -Path $BuildRoot
    $path = Join-Path $root "cargo-home"
    if (Test-Path -LiteralPath $path) {
        throw "source_fixture_private_cargo_home_not_fresh"
    }
    $null = New-Item -ItemType Directory -Path $path -ErrorAction Stop
    $null = Protect-SteinPackageOwnerOnlyDirectory -Path $path
    $resolved = Assert-SteinPackageOwnerOnlyDirectory -Path $path
    if (@(Get-ChildItem -LiteralPath $resolved -Force).Count -ne 0) {
        throw "source_fixture_private_cargo_home_not_empty"
    }
    return $resolved
}

function Get-SteinSourceFixtureCompilerEnvironmentRecord {
    param(
        [Parameter(Mandatory = $true)][string] $RustupToolchain,
        [Parameter(Mandatory = $true)][string] $PathSha256
    )

    if ($RustupToolchain -cnotmatch '^[0-9A-Za-z][0-9A-Za-z._-]{2,127}$') {
        throw "source_fixture_rustup_toolchain_invalid"
    }
    Assert-SteinSourceFixtureHash `
        -Value $PathSha256 `
        -FailureCode 'source_fixture_compiler_environment_invalid'
    return [ordered]@{
        CARGO_HOME = "fresh_private_owner_only_empty_at_suite_start"
        CARGO_INCREMENTAL = "0"
        CARGO_TARGET_DIR = "fresh_private_shared_suite_target"
        CARGO_BUILD_TARGET_DIR = "cleared"
        CARGO_TERM_COLOR = "never"
        CARGO_BUILD_RUSTC = "resolved_rustc_payload"
        CARGO_BUILD_RUSTC_WRAPPER = "cleared"
        CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER = "cleared"
        RUSTC = "resolved_rustc_payload"
        RUSTC_WRAPPER = "cleared"
        RUSTC_WORKSPACE_WRAPPER = "cleared"
        RUSTFLAGS = "cleared"
        CARGO_ENCODED_RUSTFLAGS = "cleared"
        RUSTUP_TOOLCHAIN = $RustupToolchain
        UNREGISTERED_TOOL_OVERRIDE_PREFIXES = "cleared"
        PATH_SHA256 = $PathSha256
    }
}

function Assert-SteinSourceFixtureEffectiveCompilerEnvironment {
    param(
        [Parameter(Mandatory = $true)][string] $CargoHome,
        [Parameter(Mandatory = $true)][string] $TargetDirectory,
        [Parameter(Mandatory = $true)][string] $RustcExecutable,
        [Parameter(Mandatory = $true)][string] $RustupToolchain,
        [Parameter(Mandatory = $true)][string] $PathSha256
    )

    foreach ($expected in @(
            [pscustomobject]@{ name = "CARGO_HOME"; value = $CargoHome },
            [pscustomobject]@{ name = "CARGO_INCREMENTAL"; value = "0" },
            [pscustomobject]@{ name = "CARGO_TARGET_DIR"; value = $TargetDirectory },
            [pscustomobject]@{ name = "CARGO_TERM_COLOR"; value = "never" },
            [pscustomobject]@{ name = "CARGO_BUILD_RUSTC"; value = $RustcExecutable },
            [pscustomobject]@{ name = "RUSTC"; value = $RustcExecutable },
            [pscustomobject]@{ name = "RUSTUP_TOOLCHAIN"; value = $RustupToolchain })) {
        if ([Environment]::GetEnvironmentVariable(
                [string]$expected.name,
                [EnvironmentVariableTarget]::Process) -cne [string]$expected.value) {
            throw "source_fixture_compiler_environment_invalid"
        }
    }
    foreach ($cleared in @(
            "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")) {
        if (-not [string]::IsNullOrEmpty(
                [Environment]::GetEnvironmentVariable(
                    $cleared,
                    [EnvironmentVariableTarget]::Process))) {
            throw "source_fixture_compiler_environment_invalid"
        }
    }
    if (@(Get-ChildItem -LiteralPath $CargoHome -Force).Count -ne 0) {
        throw "source_fixture_private_cargo_home_not_empty"
    }
    if ((Get-SteinSourceFixturePathSha256) -cne $PathSha256) {
        throw "source_fixture_compiler_environment_invalid"
    }
    foreach ($environmentEntry in [Environment]::GetEnvironmentVariables(
            [EnvironmentVariableTarget]::Process).GetEnumerator()) {
        $name = [string]$environmentEntry.Key
        if ((Test-SteinSourceFixtureSensitiveEnvironmentName -Name $name) -and
            $name -notin @(
                'CARGO_HOME', 'CARGO_INCREMENTAL', 'CARGO_TARGET_DIR',
                'CARGO_TERM_COLOR', 'CARGO_BUILD_RUSTC', 'RUSTC',
                'RUSTUP_TOOLCHAIN', 'GIT_CONFIG_NOSYSTEM',
                'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_COUNT',
                'GIT_NO_REPLACE_OBJECTS', 'GIT_TERMINAL_PROMPT',
                'GIT_OPTIONAL_LOCKS') -and
            -not [string]::IsNullOrEmpty([string]$environmentEntry.Value)) {
            throw "source_fixture_compiler_environment_invalid"
        }
    }
    return $true
}

function Write-SteinSourceFixtureJsonNew {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $Value,
        [int] $Depth = 24
    )

    $json = $Value | ConvertTo-Json -Depth $Depth
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::Read)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        if ($stream.Length -ne $bytes.Length) {
            throw "source_fixture_receipt_write_invalid"
        }
    }
    finally {
        $stream.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    $read = Read-SteinSourceFixtureLockedJson -Path $Path -MaximumBytes 4194304
    return [pscustomobject]@{
        value = $read.value
        path = $Path
        size = [long]$read.size
        sha256 = [string]$read.sha256
    }
}

function Assert-SteinSourceFixtureFileStable {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][long] $ExpectedSize,
        [Parameter(Mandatory = $true)][string] $ExpectedSha256,
        [long] $MaximumBytes = 4194304
    )

    $completed = Read-SteinSourceFixtureLockedJson `
        -Path $Path `
        -MaximumBytes $MaximumBytes
    if ([long]$completed.size -ne $ExpectedSize -or
        [string]$completed.sha256 -cne $ExpectedSha256) {
        throw "source_fixture_receipt_changed"
    }
    return $true
}

function Resolve-SteinSourceFixtureOutputDirectory {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $Path
    )

    $root = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $candidate = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    }
    else {
        [IO.Path]::GetFullPath((Join-Path $root $Path))
    }
    $allowedRoot = [IO.Path]::GetFullPath(
        (Join-Path $root "artifacts\evidence\phase-2")).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    if (-not $candidate.StartsWith(
            "$allowedRoot$([IO.Path]::DirectorySeparatorChar)",
            [StringComparison]::OrdinalIgnoreCase) -or
        (Test-Path -LiteralPath $candidate)) {
        throw "source_fixture_output_directory_invalid"
    }
    $parent = Split-Path -Parent $candidate
    $probe = $parent
    while ($probe.Length -ge $root.Length) {
        $item = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "source_fixture_output_directory_invalid"
        }
        if ([string]::Equals($probe, $root, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $probe = Split-Path -Parent $probe
    }
    $null = New-Item -ItemType Directory -Path $candidate -ErrorAction Stop
    $null = Protect-SteinPackageOwnerOnlyDirectory -Path $candidate
    return Assert-SteinPackageOwnerOnlyDirectory -Path $candidate
}

function Invoke-SteinSourceFixtureSuite {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $Destination
    )

    if ($env:OS -cne "Windows_NT") {
        throw "source_fixture_windows_host_required"
    }
    $repositoryPath = [IO.Path]::GetFullPath($RepositoryRoot)
    $registryPath = Join-Path $repositoryPath `
        "scripts\windows\phase2\Source-Fixture-Registry.json"
    $registryRead = Read-SteinSourceFixtureLockedJson `
        -Path $registryPath `
        -MaximumBytes 1048576
    if ([string]$registryRead.sha256 -cne
        $script:SteinSourceFixtureRegistrySha256) {
        throw "source_fixture_registry_digest_invalid"
    }
    $null = Assert-SteinSourceFixtureRegistry -Registry $registryRead.value

    $cargoLauncher = [string]@(Get-Command `
            "cargo.exe" -CommandType Application -ErrorAction Stop)[0].Source
    $rustcLauncher = [string]@(Get-Command `
            "rustc.exe" -CommandType Application -ErrorAction Stop)[0].Source
    $rustup = [string]@(Get-Command `
            "rustup.exe" -CommandType Application -ErrorAction Stop)[0].Source
    $gitLauncher = [string]@(Get-Command `
            "git.exe" -CommandType Application -ErrorAction Stop)[0].Source

    $buildRoot = $null
    $snapshotLocks = $null
    $currentLocks = New-Object Collections.Generic.List[object]
    $candidateGeneratorLocks = New-Object Collections.Generic.List[object]
    $toolLocks = New-Object Collections.Generic.List[object]
    $binaryLocks = New-Object Collections.Generic.List[object]
    $receiptFiles = New-Object Collections.Generic.List[object]
    $originalEnvironment = @{}
    $environmentNameSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @(
        @(Get-SteinSourceFixtureCompilerEnvironmentNames) + @(
        "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_COUNT",
        "GIT_NO_REPLACE_OBJECTS", "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS",
        "STEIN_CORE_EXECUTABLE_SHA256", "STEIN_PRODUCTION_PACKAGE_FAMILY_NAME",
        "STEIN_PRODUCTION_BROKER_AUMID", "STEIN_EDGE_EXTENSION_ID",
        "STEIN_EDGE_EXTENSION_VERSION", "STEIN_EDGE_PUBLISHER_SHA256",
        "STEIN_EDGE_HOST_PUBLISHER_SHA256"))) {
        $null = $environmentNameSet.Add([string]$name)
    }
    foreach ($environmentEntry in [Environment]::GetEnvironmentVariables(
            [EnvironmentVariableTarget]::Process).GetEnumerator()) {
        if (Test-SteinSourceFixtureSensitiveEnvironmentName `
                -Name ([string]$environmentEntry.Key)) {
            $null = $environmentNameSet.Add([string]$environmentEntry.Key)
        }
    }
    $environmentNames = @($environmentNameSet | ForEach-Object { [string]$_ })
    foreach ($name in $environmentNames) {
        $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable(
            $name,
            [EnvironmentVariableTarget]::Process)
    }
    try {
        $null = Assert-SteinSourceFixtureCompilerOverridesAbsent `
            -Environment $originalEnvironment
        foreach ($name in $environmentNames) {
            if (Test-SteinSourceFixtureSensitiveEnvironmentName -Name $name) {
                [Environment]::SetEnvironmentVariable(
                    $name,
                    $null,
                    [EnvironmentVariableTarget]::Process)
            }
        }
        $env:GIT_CONFIG_NOSYSTEM = '1'
        $env:GIT_CONFIG_GLOBAL = 'NUL'
        $env:GIT_CONFIG_COUNT = '0'
        $env:GIT_NO_REPLACE_OBJECTS = '1'
        $env:GIT_TERMINAL_PROMPT = '0'
        $env:GIT_OPTIONAL_LOCKS = '0'
        $pathSha256 = Get-SteinSourceFixturePathSha256
        $gitEnvironmentRecord = Get-SteinSourceFixtureGitEnvironmentRecord `
            -PathSha256 $pathSha256
        $gitEnvironmentSha256 = Get-SteinSourceEvidenceObjectDigest `
            -Value $gitEnvironmentRecord
        $gitBinding = Get-SteinSourceFixtureGitBinding `
            -LauncherExecutable $gitLauncher `
            -WorkingDirectory $repositoryPath
        foreach ($gitTool in @(
                [pscustomobject]@{
                    path = [string]$gitBinding.LauncherPath
                    hash = [string]$gitBinding.Record.executable_sha256
                },
                [pscustomobject]@{
                    path = [string]$gitBinding.ResolvedPath
                    hash = [string]$gitBinding.Record.resolved_executable_sha256
                })) {
            $toolLocks.Add((Open-SteinPackageVerifiedFileLock `
                    -Path ([string]$gitTool.path) `
                    -ExpectedSha256 ([string]$gitTool.hash)))
        }
        $gitVersionResult = Invoke-SteinSourceFixtureProcessCapture `
            -Executable ([string]$gitBinding.ResolvedPath) `
            -Arguments @("--version") `
            -WorkingDirectory $repositoryPath
        if ([int]$gitVersionResult.exit_code -ne 0 -or
            -not [string]::IsNullOrWhiteSpace([string]$gitVersionResult.stderr) -or
            [string]$gitVersionResult.stdout.Trim() -cne
                [string]$gitBinding.Record.resolved_version) {
            throw "source_fixture_git_binding_invalid"
        }
        $expectedGitDirectory = [IO.Path]::GetFullPath(
            (Join-Path $repositoryPath '.git')).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        foreach ($gitDirectoryQuery in @('--absolute-git-dir', '--git-common-dir')) {
            $gitDirectoryResult = Invoke-SteinSourceFixtureProcessCapture `
                -Executable ([string]$gitBinding.ResolvedPath) `
                -Arguments @(
                    '--no-replace-objects', '-C', $repositoryPath,
                    'rev-parse', $gitDirectoryQuery) `
                -WorkingDirectory $repositoryPath
            $gitDirectoryText = ([string]$gitDirectoryResult.stdout).Trim()
            $gitDirectoryPath = if ([IO.Path]::IsPathRooted($gitDirectoryText)) {
                [IO.Path]::GetFullPath($gitDirectoryText)
            }
            else {
                [IO.Path]::GetFullPath((Join-Path $repositoryPath $gitDirectoryText))
            }
            if ([int]$gitDirectoryResult.exit_code -ne 0 -or
                -not [string]::IsNullOrWhiteSpace([string]$gitDirectoryResult.stderr) -or
                $gitDirectoryPath.TrimEnd(
                    [IO.Path]::DirectorySeparatorChar,
                    [IO.Path]::AltDirectorySeparatorChar) -cne $expectedGitDirectory) {
                throw 'source_fixture_git_repository_redirected'
            }
        }
        $candidateState = Get-SteinCleanGitCandidateState `
            -RepositoryRoot $repositoryPath `
            -GitExecutable ([string]$gitBinding.ResolvedPath) `
            -ExpectedGitExecutableSha256 `
                ([string]$gitBinding.Record.resolved_executable_sha256)

        $outputPath = Resolve-SteinSourceFixtureOutputDirectory `
            -RepositoryRoot $repositoryPath `
            -Path $Destination
        $buildRoot = New-SteinPackagePrivateTemporaryDirectory -Purpose "build"
        $snapshot = New-SteinExactGitCandidateSnapshot `
            -RepositoryRoot $repositoryPath `
            -GitExecutable ([string]$gitBinding.ResolvedPath) `
            -ExpectedGitExecutableSha256 `
                ([string]$gitBinding.Record.resolved_executable_sha256) `
            -ExpectedCommit ([string]$candidateState.Commit) `
            -ExpectedTree ([string]$candidateState.Tree) `
            -BuildRoot $buildRoot
        $snapshotLocks = Open-SteinExactCandidateSnapshotLocks -Snapshot $snapshot
        $treeBinding = Get-SteinSourceFixtureTreeBinding -Snapshot $snapshot

        foreach ($relativePath in @(
                "scripts/windows/phase2/Run-Source-Fixture.ps1",
                "scripts/windows/phase2/Source-Fixture-Registry.json",
                "scripts/windows/phase2/Source-Evidence.ps1",
                "scripts/windows/phase2/Evidence-Contract.ps1",
                "packaging/windows-msix/PackageTools.ps1")) {
            $publicPath = Join-Path $repositoryPath $relativePath.Replace(
                '/', [IO.Path]::DirectorySeparatorChar)
            $candidatePath = Join-Path $snapshot.Root $relativePath.Replace(
                '/', [IO.Path]::DirectorySeparatorChar)
            $candidateHash = Get-SteinSourceEvidenceSha256 -Path $candidatePath
            $candidateGeneratorLock = Open-SteinPackageVerifiedFileLock `
                -Path $candidatePath `
                -ExpectedSha256 $candidateHash
            $candidateGeneratorLocks.Add($candidateGeneratorLock)
            $bootstrapBinding = @($script:SteinSourceFixtureBootstrapBindings |
                Where-Object {
                    [string]$_.record.path -ceq $relativePath
                })
            if ($bootstrapBinding.Count -gt 1) {
                throw "source_fixture_running_generator_differs_from_candidate"
            }
            if ($bootstrapBinding.Count -eq 1) {
                if ([string]$bootstrapBinding[0].record.sha256 -cne $candidateHash -or
                    [long]$bootstrapBinding[0].record.size -ne
                        [long]$candidateGeneratorLock.Size) {
                    throw "source_fixture_running_generator_differs_from_candidate"
                }
            }
            else {
                if ((Get-SteinSourceEvidenceSha256 -Path $publicPath) -cne $candidateHash) {
                    throw "source_fixture_running_generator_differs_from_candidate"
                }
                $currentLocks.Add((Open-SteinPackageVerifiedFileLock `
                        -Path $publicPath `
                        -ExpectedSha256 $candidateHash))
            }
        }
        $null = Assert-SteinSourceFixtureBootstrapSourcesStable
        if ((Get-SteinSourceEvidenceSha256 `
                -Path (Join-Path $snapshot.Root `
                    "scripts\windows\phase2\Source-Fixture-Registry.json")) -cne
            [string]$registryRead.sha256) {
            throw "source_fixture_registry_differs_from_candidate"
        }

        $rustupInitialSha256 = Get-SteinSourceEvidenceSha256 -Path $rustup
        $rustupLock = Open-SteinPackageVerifiedFileLock `
            -Path $rustup `
            -ExpectedSha256 $rustupInitialSha256
        $toolLocks.Add($rustupLock)
        $rustupRecord = Get-SteinSourceEvidenceToolRecord `
            -Executable $rustup `
            -VersionArguments @('--version') `
            -WorkingDirectory $snapshot.Root
        if ([string]$rustupRecord.executable_sha256 -cne
            [string]$rustupLock.Sha256) {
            throw 'source_fixture_rustup_changed'
        }

        $rustupToolchain = Get-SteinSourceEvidenceRustupToolchainId `
            -RustupExecutable $rustup `
            -WorkingDirectory $snapshot.Root
        $cargoResolved = Resolve-SteinSourceFixtureRustTool `
            -RustupExecutable $rustup `
            -Toolchain $rustupToolchain `
            -Name "cargo" `
            -WorkingDirectory $snapshot.Root
        $rustcResolved = Resolve-SteinSourceFixtureRustTool `
            -RustupExecutable $rustup `
            -Toolchain $rustupToolchain `
            -Name "rustc" `
            -WorkingDirectory $snapshot.Root
        $rustToolLocks = @(
            [pscustomobject]@{
                path = $cargoLauncher
                hash = Get-SteinSourceEvidenceSha256 -Path $cargoLauncher
            },
            [pscustomobject]@{
                path = $cargoResolved
                hash = Get-SteinSourceEvidenceSha256 -Path $cargoResolved
            },
            [pscustomobject]@{
                path = $rustcLauncher
                hash = Get-SteinSourceEvidenceSha256 -Path $rustcLauncher
            },
            [pscustomobject]@{
                path = $rustcResolved
                hash = Get-SteinSourceEvidenceSha256 -Path $rustcResolved
            })
        foreach ($rustTool in $rustToolLocks) {
            $toolLocks.Add((Open-SteinPackageVerifiedFileLock `
                    -Path ([string]$rustTool.path) `
                    -ExpectedSha256 ([string]$rustTool.hash)))
        }
        $cargoRecord = Get-SteinSourceEvidenceRustToolRecord `
            -LauncherExecutable $cargoLauncher `
            -RustupExecutable $rustup `
            -ToolName "cargo" `
            -RustupToolchain $rustupToolchain `
            -WorkingDirectory $snapshot.Root
        $rustcRecord = Get-SteinSourceEvidenceRustToolRecord `
            -LauncherExecutable $rustcLauncher `
            -RustupExecutable $rustup `
            -ToolName "rustc" `
            -RustupToolchain $rustupToolchain `
            -WorkingDirectory $snapshot.Root
        if ([string]$cargoRecord.resolved_executable_sha256 -cne
                (Get-SteinSourceEvidenceSha256 -Path $cargoResolved) -or
            [string]$cargoRecord.executable_sha256 -cne
                (Get-SteinSourceEvidenceSha256 -Path $cargoLauncher) -or
            [string]$rustcRecord.resolved_executable_sha256 -cne
                (Get-SteinSourceEvidenceSha256 -Path $rustcResolved) -or
            [string]$rustcRecord.executable_sha256 -cne
                (Get-SteinSourceEvidenceSha256 -Path $rustcLauncher)) {
            throw "source_fixture_rust_tool_changed"
        }
        $powershell = Resolve-SteinSourceFixtureWindowsPowerShell
        foreach ($tool in @(
                [pscustomobject]@{ path = $powershell; hash = (Get-SteinSourceEvidenceSha256 -Path $powershell) })) {
            $toolLocks.Add((Open-SteinPackageVerifiedFileLock `
                    -Path ([string]$tool.path) `
                    -ExpectedSha256 ([string]$tool.hash)))
        }

        $targetDirectory = Join-Path $buildRoot "cargo-target"
        $null = New-Item -ItemType Directory -Path $targetDirectory -ErrorAction Stop
        if (@(Get-ChildItem -LiteralPath $targetDirectory -Force).Count -ne 0) {
            throw "source_fixture_private_target_not_empty"
        }
        $cargoHome = New-SteinSourceFixturePrivateCargoHome -BuildRoot $buildRoot
        $cargoExecutionDirectory =
            Resolve-SteinPackageRegularDirectoryWithAncestors `
                -Path ([Environment]::SystemDirectory)
        $null = Assert-SteinSourceFixtureCargoConfigAbsent `
            -StartPaths @($cargoExecutionDirectory, [string]$snapshot.Root)
        $compilerEnvironmentRecord = Get-SteinSourceFixtureCompilerEnvironmentRecord `
            -RustupToolchain $rustupToolchain `
            -PathSha256 $pathSha256
        $compilerEnvironmentSha256 = Get-SteinSourceEvidenceObjectDigest `
            -Value $compilerEnvironmentRecord
        $env:CARGO_HOME = $cargoHome
        $env:CARGO_INCREMENTAL = "0"
        $env:CARGO_TARGET_DIR = $targetDirectory
        $env:CARGO_BUILD_TARGET_DIR = $null
        $env:CARGO_TERM_COLOR = "never"
        $env:RUSTC = $rustcResolved
        $env:CARGO_BUILD_RUSTC = $rustcResolved
        foreach ($clearedCompilerVariable in @(
                "CARGO_BUILD_RUSTC_WRAPPER",
                "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS")) {
            [Environment]::SetEnvironmentVariable(
                $clearedCompilerVariable,
                $null,
                [EnvironmentVariableTarget]::Process)
        }
        $env:RUSTUP_TOOLCHAIN = $rustupToolchain
        $env:STEIN_CORE_EXECUTABLE_SHA256 = "1" * 64
        $env:STEIN_PRODUCTION_PACKAGE_FAMILY_NAME =
            "STEIN.PersonalIntelligence_123456789abcd"
        $env:STEIN_PRODUCTION_BROKER_AUMID =
            "$($env:STEIN_PRODUCTION_PACKAGE_FAMILY_NAME)!PrivateBroker"
        $env:STEIN_EDGE_EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
        $env:STEIN_EDGE_EXTENSION_VERSION = "0.1.0"
        $env:STEIN_EDGE_PUBLISHER_SHA256 = "2" * 64
        $env:STEIN_EDGE_HOST_PUBLISHER_SHA256 = "3" * 64
        $null = Assert-SteinSourceFixtureEffectiveCompilerEnvironment `
            -CargoHome $cargoHome `
            -TargetDirectory $targetDirectory `
            -RustcExecutable $rustcResolved `
            -RustupToolchain $rustupToolchain `
            -PathSha256 $pathSha256

        $harnessOrder = New-Object Collections.Generic.List[string]
        $harnessDefinitions = @{}
        foreach ($fixtureDefinition in @($registryRead.value.fixtures)) {
            foreach ($subcheckDefinition in @($fixtureDefinition.subchecks)) {
                foreach ($invocationDefinition in @($subcheckDefinition.invocations)) {
                    $harness = Get-SteinSourceFixtureHarnessDefinition `
                        -Invocation $invocationDefinition
                    if ($null -eq $harness) {
                        continue
                    }
                    $harnessMaterial = $harness | ConvertTo-Json -Depth 8 -Compress
                    if ($harnessDefinitions.ContainsKey([string]$harness.harness_id)) {
                        if ([string]$harnessDefinitions[[string]$harness.harness_id].Material -cne
                            $harnessMaterial) {
                            throw "source_fixture_harness_definition_conflict"
                        }
                        continue
                    }
                    $harnessDefinitions[[string]$harness.harness_id] = [pscustomobject]@{
                        Definition = $harness
                        Material = $harnessMaterial
                    }
                    $harnessOrder.Add([string]$harness.harness_id)
                }
            }
        }
        $compiledHarnesses = @{}
        foreach ($harnessId in $harnessOrder) {
            $harness = $harnessDefinitions[$harnessId].Definition
            $actualCompileArguments =
                ConvertTo-SteinSourceFixtureActualCargoArguments `
                    -Arguments @($harness.compile_arguments) `
                    -SnapshotRoot $snapshot.Root
            $null = Assert-SteinSourceFixtureCargoConfigAbsent `
                -StartPaths @($cargoExecutionDirectory, [string]$snapshot.Root)
            $compileResult = Invoke-SteinSourceFixtureProcessCapture `
                -Executable $cargoResolved `
                -Arguments $actualCompileArguments `
                -WorkingDirectory $cargoExecutionDirectory
            $null = Assert-SteinSourceFixtureCargoConfigAbsent `
                -StartPaths @($cargoExecutionDirectory, [string]$snapshot.Root)
            if ([int]$compileResult.exit_code -ne 0) {
                throw "source_fixture_harness_compile_failed"
            }
            $artifact = Resolve-SteinSourceFixtureCompilerArtifact `
                -StandardOutput ([string]$compileResult.stdout) `
                -Harness $harness `
                -SnapshotRoot $snapshot.Root `
                -TargetRoot $targetDirectory
            $binaryItem = Get-Item -LiteralPath $artifact.Path -Force -ErrorAction Stop
            $binaryHash = Get-SteinSourceEvidenceSha256 -Path $binaryItem.FullName
            $binaryLock = Open-SteinPackageVerifiedFileLock `
                -Path $binaryItem.FullName `
                -ExpectedSha256 $binaryHash
            $binaryLocks.Add($binaryLock)
            $harnessRecord = [ordered]@{
                harness_id = [string]$harness.harness_id
                package = [string]$harness.package
                target_kind = [string]$harness.target_kind
                target_name = [string]$harness.target_name
                manifest_path = [string]$harness.manifest_path
                binary = [ordered]@{
                    size = [long]$binaryLock.Size
                    sha256 = [string]$binaryLock.Sha256
                }
                compile = [ordered]@{
                    executable = "cargo.exe"
                    arguments = @($harness.compile_arguments)
                    working_directory = "."
                    exit_code = [int]$compileResult.exit_code
                    stdout = Get-SteinSourceFixtureOutputRecord `
                        -Value ([string]$compileResult.stdout)
                    stderr = Get-SteinSourceFixtureOutputRecord `
                        -Value ([string]$compileResult.stderr)
                    compiler_artifact_matches = [int]$artifact.MatchCount
                }
            }
            $compiledHarnesses[$harnessId] = [pscustomobject]@{
                Definition = $harness
                Record = $harnessRecord
                BinaryPath = [string]$binaryItem.FullName
                Lock = $binaryLock
            }
        }

        foreach ($fixture in @($registryRead.value.fixtures)) {
            $semantic = Get-SteinSourceFixtureSemanticBinding `
                -Snapshot $snapshot `
                -RelativePaths @($fixture.semantic_source_paths | ForEach-Object { [string]$_ })
            $receiptSubchecks = New-Object Collections.Generic.List[object]
            $receiptExecutions = New-Object Collections.Generic.List[object]
            $executionsById = @{}
            $fixtureHarnessIds = New-Object Collections.Generic.List[string]
            $fixtureHarnessSet = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::Ordinal)
            $invocationMappingCount = 0
            $cargoExecutionCount = 0
            $boundaryExecutionCount = 0
            foreach ($subcheck in @($fixture.subchecks)) {
                $executionIds = New-Object Collections.Generic.List[string]
                foreach ($invocation in @($subcheck.invocations)) {
                    $invocationMappingCount++
                    $executionId = Get-SteinSourceFixtureInvocationId -Invocation $invocation
                    $executionIds.Add($executionId)
                    $invocationMaterial = $invocation | ConvertTo-Json -Depth 4 -Compress
                    if ($executionsById.ContainsKey($executionId)) {
                        if ([string]$executionsById[$executionId] -cne $invocationMaterial) {
                            throw "source_fixture_invocation_identity_collision"
                        }
                        continue
                    }
                    $executionsById[$executionId] = $invocationMaterial
                    $executionSequence = $receiptExecutions.Count + 1
                    if ([string]$invocation.kind -ceq "boundary") {
                        $command = Get-SteinSourceFixtureCommand -Invocation $invocation
                        $actualBoundaryArguments = @($command.arguments | ForEach-Object {
                                [string]$_
                            })
                        $fileSwitchIndexes = @(for ($argumentIndex = 0;
                                $argumentIndex -lt $actualBoundaryArguments.Count;
                                $argumentIndex++) {
                                if ($actualBoundaryArguments[$argumentIndex] -ceq '-File') {
                                    $argumentIndex
                                }
                            })
                        if ($fileSwitchIndexes.Count -ne 1 -or
                            [int]$fileSwitchIndexes[0] -ge
                                ($actualBoundaryArguments.Count - 1)) {
                            throw "source_fixture_boundary_command_invalid"
                        }
                        $actualBoundaryScript = Resolve-SteinPackageRegularFileUnderRoot `
                            -Root ([string]$snapshot.Root) `
                            -Path (Join-Path ([string]$snapshot.Root) `
                                'scripts\windows\check-boundaries.ps1')
                        $actualBoundaryArguments[[int]$fileSwitchIndexes[0] + 1] =
                            $actualBoundaryScript
                        $null = Assert-SteinSourceFixtureCargoConfigAbsent `
                            -StartPaths @(
                                $cargoExecutionDirectory, [string]$snapshot.Root)
                        $result = Invoke-SteinSourceFixtureProcessCapture `
                            -Executable $powershell `
                            -Arguments @(
                                @($actualBoundaryArguments) + @(
                                    '-CargoExecutable', $cargoResolved,
                                    '-CargoExecutableSha256',
                                    [string]$cargoRecord.resolved_executable_sha256)) `
                            -WorkingDirectory $cargoExecutionDirectory
                        $null = Assert-SteinSourceFixtureCargoConfigAbsent `
                            -StartPaths @(
                                $cargoExecutionDirectory, [string]$snapshot.Root)
                        if ([int]$result.exit_code -ne 0 -or
                            -not [string]::IsNullOrWhiteSpace(
                                [string]$result.stderr)) {
                            throw "source_fixture_boundary_failed"
                        }
                        $null = Assert-SteinSourceFixtureBoundaryOutput `
                            -StandardOutput ([string]$result.stdout)
                        $boundaryExecutionCount++
                        $receiptExecutions.Add([ordered]@{
                                execution_id = $executionId
                                sequence = $executionSequence
                                kind = "boundary"
                                qualified_test_name = "boundary_contract"
                                executable = "powershell.exe"
                                arguments = @($command.arguments)
                                working_directory = "."
                                nested_tool = [ordered]@{
                                    executable = 'resolved_cargo_payload'
                                    sha256 = [string]$cargoRecord.resolved_executable_sha256
                                    arguments = @(
                                        'metadata', '--locked', '--no-deps',
                                        '--format-version', '1', '--manifest-path',
                                        'Cargo.toml')
                                    working_directory = 'validated_config_free_system_directory'
                                }
                                execution = [ordered]@{
                                    exit_code = [int]$result.exit_code
                                    stdout = Get-SteinSourceFixtureOutputRecord `
                                        -Value ([string]$result.stdout)
                                    stderr = Get-SteinSourceFixtureOutputRecord `
                                        -Value ([string]$result.stderr)
                                    passed_checks = 4
                                    failed_checks = 0
                                }
                            })
                        continue
                    }

                    $registeredListCommand = Get-SteinSourceFixtureCommand `
                        -Invocation $invocation `
                        -ListOnly
                    $registeredCommand = Get-SteinSourceFixtureCommand -Invocation $invocation
                    $harness = Get-SteinSourceFixtureHarnessDefinition -Invocation $invocation
                    $harnessId = [string]$harness.harness_id
                    if (-not $compiledHarnesses.ContainsKey($harnessId)) {
                        throw "source_fixture_harness_unavailable"
                    }
                    if ($fixtureHarnessSet.Add($harnessId)) {
                        $fixtureHarnessIds.Add($harnessId)
                    }
                    $compiledHarness = $compiledHarnesses[$harnessId]
                    $listArguments = @(
                        [string]$registeredListCommand.qualified_name, "--exact", "--list")
                    $listResult = Invoke-SteinSourceFixtureProcessCapture `
                        -Executable ([string]$compiledHarness.BinaryPath) `
                        -Arguments $listArguments `
                        -WorkingDirectory $snapshot.Root
                    if ([int]$listResult.exit_code -ne 0 -or
                        -not [string]::IsNullOrWhiteSpace(
                            [string]$listResult.stderr)) {
                        throw "source_fixture_test_list_failed"
                    }
                    $matchCount = Assert-SteinSourceFixtureListOutput `
                        -QualifiedName ([string]$registeredListCommand.qualified_name) `
                        -StandardOutput ([string]$listResult.stdout)
                    $directArguments = @(
                        [string]$registeredCommand.qualified_name,
                        "--exact", "--test-threads=1")
                    $result = Invoke-SteinSourceFixtureProcessCapture `
                        -Executable ([string]$compiledHarness.BinaryPath) `
                        -Arguments $directArguments `
                        -WorkingDirectory $snapshot.Root
                    if ([int]$result.exit_code -ne 0 -or
                        -not [string]::IsNullOrWhiteSpace(
                            [string]$result.stderr)) {
                        throw "source_fixture_test_execution_failed"
                    }
                    $execution = Assert-SteinSourceFixtureExecutionOutput `
                        -QualifiedName ([string]$registeredCommand.qualified_name) `
                        -StandardOutput ([string]$result.stdout)
                    $cargoExecutionCount++
                    $receiptExecutions.Add([ordered]@{
                            execution_id = $executionId
                            sequence = $executionSequence
                            kind = "cargo_test"
                            qualified_test_name = [string]$registeredCommand.qualified_name
                            harness_id = $harnessId
                            executable = "locked_test_binary"
                            registered_cargo_arguments = @($registeredCommand.arguments)
                            arguments = $directArguments
                            working_directory = "."
                            preflight = [ordered]@{
                                exit_code = [int]$listResult.exit_code
                                arguments = $listArguments
                                stdout = Get-SteinSourceFixtureOutputRecord `
                                    -Value ([string]$listResult.stdout)
                                stderr = Get-SteinSourceFixtureOutputRecord `
                                    -Value ([string]$listResult.stderr)
                                exact_test_matches = [int]$matchCount
                            }
                            execution = [ordered]@{
                                exit_code = [int]$result.exit_code
                                stdout = Get-SteinSourceFixtureOutputRecord `
                                    -Value ([string]$result.stdout)
                                stderr = Get-SteinSourceFixtureOutputRecord `
                                    -Value ([string]$result.stderr)
                                passed_tests = [int]$execution.passed
                                failed_tests = [int]$execution.failed
                            }
                        })
                }
                $receiptSubchecks.Add([ordered]@{
                        id = [string]$subcheck.id
                        result = "pass"
                        execution_ids = @($executionIds | ForEach-Object { $_ })
                    })
            }

            $fixtureDefinitionDigest = Get-SteinSourceEvidenceObjectDigest -Value $fixture
            $receipt = [ordered]@{
                schema_version = 1
                claim = "closed_source_fixture_only"
                source_check_id = [string]$fixture.source_check_id
                source_fixture_id = [string]$fixture.source_fixture_id
                source_runner_id = [string]$fixture.source_runner_id
                gate_id = [string]$fixture.gate_id
                gate_fixture_id = [string]$fixture.gate_fixture_id
                gate_runner_id = [string]$fixture.gate_runner_id
                result = "pass"
                bindings = [ordered]@{
                    candidate_git_commit = [string]$snapshot.Commit
                    candidate_git_tree = [string]$snapshot.Tree
                    candidate_tree_file_count = [int]$treeBinding.file_count
                    candidate_tree_manifest_sha256 = [string]$treeBinding.manifest_sha256
                    registry_sha256 = [string]$registryRead.sha256
                    fixture_definition_sha256 = $fixtureDefinitionDigest
                    semantic_source_manifest_sha256 = [string]$semantic.Digest
                    rustup_toolchain = $rustupToolchain
                    rustup_version = [string]$rustupRecord.version
                    rustup_sha256 = [string]$rustupRecord.executable_sha256
                    cargo_launcher_sha256 = [string]$cargoRecord.executable_sha256
                    cargo_resolved_sha256 = [string]$cargoRecord.resolved_executable_sha256
                    rustc_launcher_sha256 = [string]$rustcRecord.executable_sha256
                    rustc_resolved_sha256 = [string]$rustcRecord.resolved_executable_sha256
                    git_launcher_version = [string]$gitBinding.Record.version
                    git_launcher_sha256 = [string]$gitBinding.Record.executable_sha256
                    git_resolved_version = [string]$gitBinding.Record.resolved_version
                    git_resolved_sha256 =
                        [string]$gitBinding.Record.resolved_executable_sha256
                    compiler_environment_sha256 = $compilerEnvironmentSha256
                    git_environment_sha256 = $gitEnvironmentSha256
                }
                environment = [ordered]@{
                    source = "private_exact_git_snapshot"
                    target = "fresh_private_shared_suite_target"
                    tracked_source_lock = "all_candidate_files_held_read_only"
                    working_directory = "."
                    cargo_home_precondition = "fresh_private_owner_only_empty"
                    cargo_home_initial_entry_count = 0
                    cargo_config_precondition =
                        "execution_and_snapshot_ancestor_configs_absent"
                    cargo_config_postcondition =
                        "execution_and_snapshot_ancestor_configs_absent"
                    effective_compiler_environment = $compilerEnvironmentRecord
                    effective_git_environment = $gitEnvironmentRecord
                }
                semantic_sources = @($semantic.Records)
                harnesses = @($fixtureHarnessIds | ForEach-Object {
                        $compiledHarnesses[[string]$_].Record
                    })
                executions = @($receiptExecutions | ForEach-Object { $_ })
                subchecks = @($receiptSubchecks | ForEach-Object { $_ })
                summary = [ordered]@{
                    subcheck_count = @($fixture.subchecks).Count
                    harness_count = $fixtureHarnessIds.Count
                    invocation_mapping_count = $invocationMappingCount
                    unique_execution_count = $receiptExecutions.Count
                    cargo_test_execution_count = $cargoExecutionCount
                    boundary_execution_count = $boundaryExecutionCount
                }
            }
            $null = Assert-SteinSourceFixtureReceipt `
                -Receipt ([pscustomobject]$receipt) `
                -Fixture $fixture `
                -ExpectedRegistrySha256 ([string]$registryRead.sha256) `
                -ExpectedCommit ([string]$snapshot.Commit) `
                -ExpectedTree ([string]$snapshot.Tree) `
                -ExpectedTreeFileCount ([int]$treeBinding.file_count) `
                -ExpectedTreeManifestSha256 ([string]$treeBinding.manifest_sha256) `
                -ExpectedSemanticManifestSha256 ([string]$semantic.Digest) `
                -ExpectedCargoLauncherSha256 ([string]$cargoRecord.executable_sha256) `
                -ExpectedCargoResolvedSha256 ([string]$cargoRecord.resolved_executable_sha256) `
                -ExpectedRustcLauncherSha256 ([string]$rustcRecord.executable_sha256) `
                -ExpectedRustcResolvedSha256 ([string]$rustcRecord.resolved_executable_sha256) `
                -ExpectedRustupToolchain $rustupToolchain `
                -ExpectedRustupVersion ([string]$rustupRecord.version) `
                -ExpectedRustupSha256 ([string]$rustupRecord.executable_sha256) `
                -ExpectedGitLauncherVersion ([string]$gitBinding.Record.version) `
                -ExpectedGitLauncherSha256 `
                    ([string]$gitBinding.Record.executable_sha256) `
                -ExpectedGitResolvedVersion `
                    ([string]$gitBinding.Record.resolved_version) `
                -ExpectedGitResolvedSha256 `
                    ([string]$gitBinding.Record.resolved_executable_sha256) `
                -ExpectedCompilerEnvironmentSha256 $compilerEnvironmentSha256 `
                -ExpectedGitEnvironmentSha256 $gitEnvironmentSha256
            $receiptName = "$([string]$fixture.source_check_id).receipt.json"
            $receiptFile = Write-SteinSourceFixtureJsonNew `
                -Path (Join-Path $outputPath $receiptName) `
                -Value $receipt `
                -Depth 32
            $receiptFiles.Add([pscustomobject]@{
                    SourceCheckId = [string]$fixture.source_check_id
                    SourceFixtureId = [string]$fixture.source_fixture_id
                    SourceRunnerId = [string]$fixture.source_runner_id
                    GateId = [string]$fixture.gate_id
                    GateFixtureId = [string]$fixture.gate_fixture_id
                    GateRunnerId = [string]$fixture.gate_runner_id
                    Name = $receiptName
                    Path = [string]$receiptFile.path
                    Size = [long]$receiptFile.size
                    Sha256 = [string]$receiptFile.sha256
                })
        }

        $completedLocks = Open-SteinExactCandidateSnapshotLocks -Snapshot $snapshot
        $null = Assert-SteinSourceFixtureCargoConfigAbsent `
            -StartPaths @($cargoExecutionDirectory, [string]$snapshot.Root)
        try {
            if ([int]$completedLocks.TrackedFileCount -ne [int]$snapshotLocks.TrackedFileCount) {
                throw "source_fixture_candidate_tree_changed"
            }
        }
        finally {
            foreach ($stream in $completedLocks.Streams) {
                $stream.Dispose()
            }
        }
        foreach ($locked in @($currentLocks) + @($candidateGeneratorLocks) +
                @($toolLocks) + @($binaryLocks)) {
            if ((Get-SteinPackageStreamSha256 -Stream $locked.Stream) -cne
                [string]$locked.Sha256) {
                throw "source_fixture_locked_input_changed"
            }
        }

        $indexReceipts = @($receiptFiles | ForEach-Object {
                [ordered]@{
                    source_check_id = [string]$_.SourceCheckId
                    source_fixture_id = [string]$_.SourceFixtureId
                    source_runner_id = [string]$_.SourceRunnerId
                    gate_id = [string]$_.GateId
                    gate_fixture_id = [string]$_.GateFixtureId
                    gate_runner_id = [string]$_.GateRunnerId
                    path = [string]$_.Name
                    size = [long]$_.Size
                    sha256 = [string]$_.Sha256
                }
            })
        $index = [ordered]@{
            schema_version = 1
            suite_id = "stein.phase2.source-fixture-suite.v1"
            result = "pass"
            candidate_git_commit = [string]$snapshot.Commit
            candidate_git_tree = [string]$snapshot.Tree
            registry_sha256 = [string]$registryRead.sha256
            git = [ordered]@{
                launcher_version = [string]$gitBinding.Record.version
                launcher_sha256 = [string]$gitBinding.Record.executable_sha256
                resolved_version = [string]$gitBinding.Record.resolved_version
                resolved_sha256 = [string]$gitBinding.Record.resolved_executable_sha256
            }
            rustup = [ordered]@{
                version = [string]$rustupRecord.version
                sha256 = [string]$rustupRecord.executable_sha256
                toolchain = $rustupToolchain
            }
            receipts = $indexReceipts
        }
        $null = Assert-SteinSourceFixtureIndex `
            -Index ([pscustomobject]$index) `
            -Registry $registryRead.value `
            -ExpectedRegistrySha256 ([string]$registryRead.sha256) `
            -ExpectedCommit ([string]$snapshot.Commit) `
            -ExpectedTree ([string]$snapshot.Tree) `
            -ExpectedGitLauncherVersion ([string]$gitBinding.Record.version) `
            -ExpectedGitLauncherSha256 ([string]$gitBinding.Record.executable_sha256) `
            -ExpectedGitResolvedVersion ([string]$gitBinding.Record.resolved_version) `
            -ExpectedGitResolvedSha256 `
                ([string]$gitBinding.Record.resolved_executable_sha256) `
            -ExpectedRustupVersion ([string]$rustupRecord.version) `
            -ExpectedRustupSha256 ([string]$rustupRecord.executable_sha256) `
            -ExpectedRustupToolchain $rustupToolchain
        $indexFile = Write-SteinSourceFixtureJsonNew `
            -Path (Join-Path $outputPath "index.json") `
            -Value $index
        foreach ($receiptFile in $receiptFiles) {
            $null = Assert-SteinSourceFixtureFileStable `
                -Path ([string]$receiptFile.Path) `
                -ExpectedSize ([long]$receiptFile.Size) `
                -ExpectedSha256 ([string]$receiptFile.Sha256)
        }
        $null = Assert-SteinSourceFixtureFileStable `
            -Path ([string]$indexFile.path) `
            -ExpectedSize ([long]$indexFile.size) `
            -ExpectedSha256 ([string]$indexFile.sha256)
        $actualFiles = @(Get-ChildItem -LiteralPath $outputPath -Force)
        if ($actualFiles.Count -ne ($receiptFiles.Count + 1) -or
            @($actualFiles | Where-Object {
                    $_.PSIsContainer -or
                    (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
                }).Count -ne 0) {
            throw "source_fixture_output_set_changed"
        }
        $null = Assert-SteinSourceFixtureBootstrapSourcesStable
        Write-Output "source_fixture_suite=pass"
        Write-Output "receipt_count=$($receiptFiles.Count)"
    }
    finally {
        foreach ($name in $environmentNames) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $originalEnvironment[$name],
                [EnvironmentVariableTarget]::Process)
        }
        foreach ($locked in @($binaryLocks) + @($toolLocks) +
                @($candidateGeneratorLocks) + @($currentLocks)) {
            if ($null -ne $locked -and $null -ne $locked.Stream) {
                $locked.Stream.Dispose()
            }
        }
        if ($null -ne $snapshotLocks) {
            foreach ($stream in $snapshotLocks.Streams) {
                $stream.Dispose()
            }
        }
        if ($null -ne $buildRoot -and (Test-Path -LiteralPath $buildRoot)) {
            Remove-SteinPackagePrivateTemporaryDirectory `
                -Path $buildRoot `
                -Purpose "build"
        }
    }
}

if ($LibraryOnly) {
    return
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    throw "OutputDirectory is required."
}
try {
    Invoke-SteinSourceFixtureSuite `
        -RepositoryRoot $sourceFixtureRepositoryRoot `
        -Destination $OutputDirectory
}
finally {
    try {
        $null = Assert-SteinSourceFixtureBootstrapSourcesStable
    }
    finally {
        foreach ($binding in $script:SteinSourceFixtureBootstrapBindings) {
            $binding.stream.Dispose()
        }
    }
}
