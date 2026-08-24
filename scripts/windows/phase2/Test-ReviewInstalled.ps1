[CmdletBinding()]
param([switch] $ReviewTestLibraryOnly)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

if ([string]$PSVersionTable.PSEdition -ceq "Core" -and
    $PSVersionTable.PSVersion -lt [Version]"7.5") {
    [Console]::Error.WriteLine("powershell_core_7_5_or_newer_required")
    exit 1
}

$reviewerPath = Join-Path $PSScriptRoot "Review-Installed.ps1"
$launcherPath = Join-Path $PSScriptRoot "Review-Installed.cmd"
$commonPath = Join-Path $PSScriptRoot "Common.ps1"
$contractPath = Join-Path $PSScriptRoot "Evidence-Contract.ps1"
$specificationPath = Join-Path $PSScriptRoot "Evidence-Spec.json"
$sourceFixtureRegistryPath = Join-Path $PSScriptRoot "Source-Fixture-Registry.json"
$sourceFixtureTestPath = Join-Path $PSScriptRoot "Test-SourceFixture.ps1"
foreach ($requiredPath in @(
        $reviewerPath, $launcherPath, $commonPath, $contractPath, $specificationPath,
        $sourceFixtureRegistryPath, $sourceFixtureTestPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "The installed evidence reviewer fixture is incomplete."
    }
}

$tokens = $null
$parseErrors = $null
$reviewerAst = [Management.Automation.Language.Parser]::ParseFile(
    $reviewerPath,
    [ref]$tokens,
    [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    throw "Review-Installed.ps1 does not parse."
}
$parameterNames = @($reviewerAst.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
foreach ($parameterName in @(
        "EvidenceDirectory", "ExpectedRootAnchorSha256", "ReviewManifest", "OutputRoot")) {
    if ($parameterName -cnotin $parameterNames) {
        throw "Review-Installed.ps1 is missing a required review input."
    }
}
foreach ($mandatoryName in @(
        "EvidenceDirectory", "ExpectedRootAnchorSha256", "ReviewManifest")) {
    $parameter = @($reviewerAst.ParamBlock.Parameters | Where-Object {
        $_.Name.VariablePath.UserPath -ceq $mandatoryName
    })[0]
    if ($parameter.Extent.Text.IndexOf(
            "Mandatory = `$true",
            [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "A root or review binding input is not mandatory."
    }
}

$reviewerSource = Get-Content -LiteralPath $reviewerPath -Raw
$contractSource = Get-Content -LiteralPath $contractPath -Raw
$reviewerValidationSource = $reviewerSource + "`n" + $contractSource
$gateMatch = [regex]::Match(
    $reviewerSource,
    '(?ms)\$script:SteinPhase2ReviewGateIds\s*=\s*@\((?<body>.*?)^\s*\)')
if (-not $gateMatch.Success) {
    throw "Review-Installed.ps1 has no statically readable gate set."
}
$actualGates = @(
    [regex]::Matches($gateMatch.Groups["body"].Value, '"(?<gate>P2-[A-Z0-9-]+)"') |
        ForEach-Object { $_.Groups["gate"].Value }
)
$expectedGates = @(
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
if ($actualGates.Count -ne 32 -or
    @(Compare-Object `
        -ReferenceObject ($expectedGates | Sort-Object) `
        -DifferenceObject ($actualGates | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "Review-Installed.ps1 does not preserve the exact 32-gate set."
}

$commandNames = @($reviewerAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst]
}, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $null -ne $_ })
foreach ($forbiddenCommand in @(
        "Add-AppxPackage", "Remove-AppxPackage",
        "Register-ScheduledTask", "Unregister-ScheduledTask",
        "Start-ScheduledTask", "Stop-ScheduledTask",
        "Start-Process", "Stop-Process",
        "Get-Credential", "Read-Host", "Invoke-Expression")) {
    if ($commandNames -icontains $forbiddenCommand) {
        throw "Review-Installed.ps1 contains an installed-state mutation or secret-input command."
    }
}
foreach ($requiredLiteral in @(
        "review_pass_requirements_not_satisfied",
        "json_artifact_hash_or_size_mismatch",
        "native_fixture_result",
        "Evidence-Contract.ps1",
        "Evidence-Spec.json",
        "Assert-SteinPhase2GateEvidenceResult",
        "Assert-SteinPhase2SourceEvidenceBinding",
        "Assert-SteinPhase2LinuxPortableArtifact",
        "Assert-SteinPhase2PrivateDiagnosticArtifact",
        "Assert-SteinPhase2ToastComDenialArtifact",
        "Assert-SteinPhase2NoLeaksProducerArtifact",
        "Assert-SteinPhase2NoLeaksReceiptPair",
        "Read-SteinReviewJsonFile",
        "[IO.FileShare]::Read",
        "Open-SteinReviewBootstrapFileBinding",
        "Get-SteinReviewLockedStreamSha256",
        "SteinReviewRuntimeSourceBindings",
        "review_underlying_artifact_hash_or_size_mismatch",
        "source_check_ids",
        "cli_executable_size",
        "desktop_executable_sha256",
        "desktop_dist_manifest_sha256",
        "runner_artifacts",
        "source_collector_declared_fail",
        "source_collector_declared_blocked",
        "screenshot_can_prove_gate = `$false",
        "collector_rows_rehashed = 32",
        "local_paths_retained = `$false",
        "user_sid_retained = `$false",
        "raw_host_retained = `$false",
        "powershell_core_7_5_or_newer_required",
        '$convertParameters.DateKind = "String"',
        "installed_state_mutated = `$false",
        "complete_acceptance",
        "reviewer-generator.json",
        "root-anchor.json")) {
    if ($reviewerValidationSource.IndexOf($requiredLiteral, [StringComparison]::Ordinal) -lt 0) {
        throw "Review-Installed.ps1 is missing a fail-closed reviewer invariant."
    }
}
if ([regex]::Matches($reviewerSource, '(?m)-ExpectedSha256\b').Count -lt 8) {
    throw "Review-Installed.ps1 does not bind every parsed JSON artifact to locked bytes."
}

$launcher = Get-Content -LiteralPath $launcherPath -Raw
foreach ($requiredLiteral in @(
        'set "STEIN_WINDOWS_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"',
        'if defined PROCESSOR_ARCHITEW6432 set "STEIN_WINDOWS_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"',
        'if not exist "%STEIN_WINDOWS_POWERSHELL%" goto :host_unavailable',
        'STEIN_WINDOWS_POWERSHELL_ATTRIBUTES=%%~aI',
        'STEIN_WINDOWS_POWERSHELL_SIZE=%%~zI',
        'STEIN_WINDOWS_POWERSHELL_ATTRIBUTES:l=',
        '"%STEIN_WINDOWS_POWERSHELL%" -NoLogo -NoProfile -ExecutionPolicy Bypass',
        '-File "%~dp0Review-Installed.ps1" %*',
        ':host_unavailable')) {
    if ($launcher.IndexOf($requiredLiteral, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Review-Installed.cmd no longer uses the validated exact Windows PowerShell host."
    }
}
if ($launcher -match '(?im)^\s*powershell\.exe(?:\s|$)' -or
    $launcher.IndexOf("%PATH%", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "Review-Installed.cmd permits PATH-based PowerShell resolution."
}

. $commonPath
. (Join-Path $PSScriptRoot "Evidence-Contract.ps1")
. $sourceFixtureTestPath -FixtureTestLibraryOnly
$evidenceSpecificationPath = Join-Path $PSScriptRoot "Evidence-Spec.json"
$evidenceSpecificationSha256 = Get-SteinPhase2Sha256 -Path $evidenceSpecificationPath
$evidenceSpecification = Read-SteinPhase2EvidenceSpecification `
    -Path $evidenceSpecificationPath `
    -ExpectedGateIds $expectedGates `
    -ExpectedSha256 $evidenceSpecificationSha256
Assert-SteinPhase2WindowsHost

function Write-SteinReviewTestJson {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $Value
    )

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop
    }
    $Value | ConvertTo-Json -Depth 32 |
        Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    return [ordered]@{
        path = $null
        size = [long]$item.Length
        sha256 = Get-SteinPhase2Sha256 -Path $item.FullName
    }
}

function Get-SteinReviewTestArtifact {
    param(
        [Parameter(Mandatory = $true)][string] $EvidenceRoot,
        [Parameter(Mandatory = $true)][string] $Path
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    return [ordered]@{
        path = $item.FullName.Substring($EvidenceRoot.Length + 1).Replace("\", "/")
        size = [long]$item.Length
        sha256 = Get-SteinPhase2Sha256 -Path $item.FullName
    }
}

function Get-SteinReviewTestStringSha256 {
    param([Parameter(Mandatory = $true)][string] $Value)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString(
            $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).
            Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-SteinReviewTestCollectorRuntimeSources {
    $repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..")).Path
    $definitions = @(
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
    return @($definitions | ForEach-Object {
        $path = Join-Path $repoRoot ([string]$_.path)
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        [ordered]@{
            role = [string]$_.role
            path = [string]$_.path
            size = [long]$item.Length
            sha256 = Get-SteinPhase2Sha256 -Path $item.FullName
        }
    })
}

function New-SteinReviewSyntheticFixture {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [hashtable] $SourceStatuses = @{},
        [string] $HostProductName = "Windows Synthetic Test",
        [switch] $FabricatedGeneratorSource,
        [switch] $MismatchedRowCommand,
        [switch] $DuplicateRowOutputArtifact,
        [switch] $OmitMandatorySourceCheck,
        [switch] $PinnedExecutionNotRun,
        [switch] $CommandProvenanceNotRun,
        [switch] $PortableAttestationNotRun,
        [switch] $MismatchedPackageBinding,
        [switch] $CorruptSourceFixtureReceipt,
        [string] $PromoteFrozenSourceCheckId
    )

    $evidenceRoot = Join-Path $Root "evidence"
    $reviewRoot = Join-Path $Root "review"
    $attachmentRoot = Join-Path $reviewRoot "attachments"
    $outputRoot = Join-Path $Root "output"
    foreach ($directory in @($evidenceRoot, $attachmentRoot, $outputRoot)) {
        $null = New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop
    }
    $rowsDirectory = Join-Path $evidenceRoot "ledger-rows"
    $null = New-Item -ItemType Directory -Path $rowsDirectory -ErrorAction Stop

    $recordedAt = [DateTime]::UtcNow.AddMinutes(-1).ToString(
        "yyyy-MM-dd'T'HH:mm:ss'.0000000Z'",
        [Globalization.CultureInfo]::InvariantCulture)
    $runtimeSources = if ($FabricatedGeneratorSource) {
        @(
            [ordered]@{
                role = "harness"
                path = "scripts/windows/phase2/Verify-Installed.ps1"
                size = 1
                sha256 = ("1" * 64)
            }
        )
    }
    else {
        @(Get-SteinReviewTestCollectorRuntimeSources)
    }
    $generator = [ordered]@{
        schema_version = 1
        harness_identity = "phase2-installed-evidence-v1"
        runtime_source_files = $runtimeSources
        source_paths = "repository_relative_only"
        source_stability = "required_before_ledger"
        trust_scope = "content_integrity_only_not_authentication"
    }
    $generatorPath = Join-Path $evidenceRoot "generator.json"
    $null = Write-SteinReviewTestJson -Path $generatorPath -Value $generator
    $generatorArtifact = Get-SteinReviewTestArtifact `
        -EvidenceRoot $evidenceRoot `
        -Path $generatorPath

    $hostRecord = [ordered]@{
        schema_version = 1
        host_identity_sha256 = ("2" * 64)
        computer_name_retained = $false
        user_name_retained = $false
        user_sid_retained = $false
        os = [ordered]@{
            product_name = $HostProductName
            display_version = "synthetic"
            build_number = "99999"
            update_build_revision = 1
            process_architecture = "AMD64"
            operating_system_64_bit = $true
            process_64_bit = $true
        }
        powershell = [ordered]@{
            edition = [string]$PSVersionTable.PSEdition
            version = "5.1"
        }
        elevated = $false
        evidence_owner_sid_only = $true
    }
    $hostPath = Join-Path $evidenceRoot "host.json"
    $null = Write-SteinReviewTestJson -Path $hostPath -Value $hostRecord
    $hostArtifact = Get-SteinReviewTestArtifact `
        -EvidenceRoot $evidenceRoot `
        -Path $hostPath

    $package = [ordered]@{
        publisher = "CN=STEIN Synthetic"
        signing_certificate_thumbprint = ("A" * 40)
        version = "2.0.0.0"
        package_path = "<local-path-sha256:$('3' * 64)>"
        release_identity_schema_version = 3
        install_record_schema_version = 2
        package_family_name = "STEIN.Synthetic_fixture"
        desktop_aumid = "STEIN.Synthetic_fixture!Desktop"
        broker_aumid = "STEIN.Synthetic_fixture!PrivateBroker"
        browser_producer_aumid = "STEIN.Synthetic_fixture!BrowserObservationProducer"
        msix_sha256 = ("4" * 64)
        core_sha256 = ("5" * 64)
        browser_host_sha256 = ("6" * 64)
        candidate_git_commit = $null
        candidate_git_tree = $null
        source_verification_sha256 = $null
        source_root_anchor_sha256 = $null
        source_root_digest_sha256 = $null
        installed_payload_file_count = 8
        cli_executable_size = 4096
        cli_executable_sha256 = ("7" * 64)
        desktop_executable_size = 8192
        desktop_executable_sha256 = ("b" * 64)
        desktop_dist_file_count = 3
        desktop_dist_manifest_sha256 = ("c" * 64)
    }
    $versions = [ordered]@{
        package_version = "2.0.0.0"
        runtime_build_id = "synthetic-build"
        protocol_version = 1
        release_identity_schema_version = 3
        install_record_schema_version = 2
        durable_persistence_capability_schema_version = 1
        numeric_database_schema_reported = $true
        expected_policy_profile_id = "phase2-focus-v1"
        policy_profile_reported_by_installed_runtime = $false
    }

    $attachmentTemplatePath = Join-Path $evidenceRoot "attachments-template.json"
    $null = Write-SteinReviewTestJson `
        -Path $attachmentTemplatePath `
        -Value ([ordered]@{ schema_version = 1; attachments = @() })
    $attachmentTemplateArtifact = Get-SteinReviewTestArtifact `
        -EvidenceRoot $evidenceRoot `
        -Path $attachmentTemplatePath
    $fixtureTemplatePath = Join-Path $evidenceRoot "native-fixture-result-template.json"
    $null = Write-SteinReviewTestJson `
        -Path $fixtureTemplatePath `
        -Value ([ordered]@{
            schema_version = 1
            fixture_id = "synthetic-template"
            gate_id = "P2-BUILD"
            result = "not_run"
            recorded_at_utc = $recordedAt
            command_id = "synthetic:template"
            exit_code = $null
        })
    $fixtureTemplateArtifact = Get-SteinReviewTestArtifact `
        -EvidenceRoot $evidenceRoot `
        -Path $fixtureTemplatePath
    $checksDirectory = Join-Path $evidenceRoot "checks"
    $null = New-Item -ItemType Directory -Path $checksDirectory -ErrorAction Stop
    $checkCommand = [ordered]@{
        identity = "synthetic:collector-check"
        executable = "powershell-host"
        arguments = @("-Synthetic")
        local_path_representation = "deterministic_sha256_token"
        arguments_omitted = $false
    }
    $checkOutputRecord = [ordered]@{
        schema_version = 1
        check_id = "synthetic-collector-check"
        status = "pass"
        command = $checkCommand
        started_at_utc = $recordedAt
        completed_at_utc = $recordedAt
        duration_ms = 0
        exit_code = 0
        failure_summary = $null
        result = [ordered]@{
            verified = $true
            template = $attachmentTemplateArtifact
            native_fixture_result_template = $fixtureTemplateArtifact
        }
    }
    $checkOutputPath = Join-Path $checksDirectory "synthetic-collector-check.json"
    $null = Write-SteinReviewTestJson -Path $checkOutputPath -Value $checkOutputRecord
    $checkOutputArtifact = Get-SteinReviewTestArtifact `
        -EvidenceRoot $evidenceRoot `
        -Path $checkOutputPath
    $collectorCheck = [ordered]@{
        id = "synthetic-collector-check"
        status = "pass"
        command = $checkCommand
        started_at_utc = $recordedAt
        completed_at_utc = $recordedAt
        duration_ms = 0
        exit_code = 0
        failure_summary = $null
        output = $checkOutputArtifact
    }

    $attachmentMappings = New-Object Collections.Generic.List[object]
    $reviewRecords = New-Object Collections.Generic.List[object]
    $ledgerRows = New-Object Collections.Generic.List[object]
    $rowPaths = @{}
    $nativePaths = @{}
    $screenshotAttachmentId = "screenshot-p2-build"
    $sourceCommit = "8" * 40
    $sourceTree = "c" * 40
    $sourceGeneratorFiles = @(
        @($evidenceSpecification.specification.source_report_contract.required_generator_paths) |
            ForEach-Object {
                $generatorPath = [string]$_
                $isFixtureRegistry = $generatorPath -ceq
                    "scripts/windows/phase2/Source-Fixture-Registry.json"
                $registryItem = if ($isFixtureRegistry) {
                    Get-Item -LiteralPath $sourceFixtureRegistryPath `
                        -Force `
                        -ErrorAction Stop
                }
                else { $null }
                [ordered]@{
                    path = $generatorPath
                    size = if ($isFixtureRegistry) {
                        [long]$registryItem.Length
                    }
                    else { 1L }
                    sha256 = if ($isFixtureRegistry) {
                        Get-SteinPhase2Sha256 -Path $registryItem.FullName
                    }
                    else { "9" * 64 }
                }
            })
    $sourceGeneratorHash = Get-SteinPhase2EvidenceTextSha256 `
        -Value ($sourceGeneratorFiles | ConvertTo-Json -Depth 16 -Compress)
    $sourceProvenance = [ordered]@{
        schema_version = 2
        classification = "bounded_content_free_source_provenance"
        repository = [ordered]@{
            head_commit = $sourceCommit
            clean = $true
        }
        toolchain = [ordered]@{
            cargo = [ordered]@{
                version = "cargo 1.0.0 (synthetic)"
                executable_sha256 = "1" * 64
                rustup_toolchain = "synthetic-x86_64-pc-windows-msvc"
                resolved_version = "cargo 1.0.0 (synthetic)"
                resolved_executable_sha256 = "2" * 64
            }
            rustc = [ordered]@{
                version = "rustc 1.0.0 (synthetic)"
                executable_sha256 = "1" * 64
                rustup_toolchain = "synthetic-x86_64-pc-windows-msvc"
                resolved_version = "rustc 1.0.0 (synthetic)"
                resolved_executable_sha256 = "3" * 64
            }
            pnpm = [ordered]@{
                version = "1.0.0"
                executable_sha256 = "4" * 64
                resolved_entrypoint_sha256 = "5" * 64
            }
            rustup = [ordered]@{
                version = "rustup 1.0.0 (synthetic)"
                executable_sha256 = "6" * 64
            }
            node = [ordered]@{
                version = "v1.0.0"
                executable_sha256 = "7" * 64
            }
            git = [ordered]@{
                version = "git version 1.0.0.synthetic"
                executable_sha256 = "8" * 64
                resolved_version = "git version 1.0.0.synthetic"
                resolved_executable_sha256 = "9" * 64
            }
            pwsh = [ordered]@{
                version = "PowerShell 7.0.0"
                executable_sha256 = "a" * 64
                authenticode_status = "valid"
                signer_subject = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
            }
        }
        dependency_locks = @(
            [ordered]@{ path = "Cargo.lock"; size = 16; sha256 = "e" * 64 }
        )
    }
    $sourceFixtureRegistry = Read-SteinSourceFixtureLockedJson `
        -Path $sourceFixtureRegistryPath `
        -MaximumBytes 1048576
    $sourceFixtureRegistryGenerator = @($sourceGeneratorFiles | Where-Object {
            [string]$_.path -ceq
                "scripts/windows/phase2/Source-Fixture-Registry.json"
        })
    if ($sourceFixtureRegistryGenerator.Count -ne 1) {
        throw "The synthetic source report has no exact fixture-registry generator."
    }
    $sourceFixtureSuite = New-SteinSourceFixtureSyntheticSuiteArtifacts `
        -Registry $sourceFixtureRegistry.value `
        -RegistrySha256 ([string]$sourceFixtureRegistryGenerator[0].sha256) `
        -OutputDirectory (Join-Path $Root "synthetic-source-fixture-artifacts") `
        -CandidateGitCommit $sourceCommit `
        -CandidateGitTree $sourceTree `
        -RustupToolchain `
            ([string]$sourceProvenance.toolchain.cargo.rustup_toolchain) `
        -CargoLauncherSha256 `
            ([string]$sourceProvenance.toolchain.cargo.executable_sha256) `
        -CargoResolvedSha256 `
            ([string]$sourceProvenance.toolchain.cargo.resolved_executable_sha256) `
        -RustcLauncherSha256 `
            ([string]$sourceProvenance.toolchain.rustc.executable_sha256) `
        -RustcResolvedSha256 `
            ([string]$sourceProvenance.toolchain.rustc.resolved_executable_sha256) `
        -RustupVersion ([string]$sourceProvenance.toolchain.rustup.version) `
        -RustupSha256 `
            ([string]$sourceProvenance.toolchain.rustup.executable_sha256) `
        -GitLauncherVersion ([string]$sourceProvenance.toolchain.git.version) `
        -GitLauncherSha256 `
            ([string]$sourceProvenance.toolchain.git.executable_sha256) `
        -GitResolvedVersion `
            ([string]$sourceProvenance.toolchain.git.resolved_version) `
        -GitResolvedSha256 `
            ([string]$sourceProvenance.toolchain.git.resolved_executable_sha256)
    $sourceFixtureByCheck = @{}
    foreach ($fixtureRecord in @($sourceFixtureSuite.Records)) {
        $sourceFixtureByCheck[
            [string]$fixtureRecord.Fixture.source_check_id] = $fixtureRecord
    }
    $emptySourceLogHash = Get-SteinSourceEvidenceTextSha256 -Value ""
    $sourceChecks = @(
        foreach ($sourceCheckId in @(
                $evidenceSpecification.specification.source_report_contract.required_pass_check_ids)) {
            if ($OmitMandatorySourceCheck -and
                [string]$sourceCheckId -ceq "no-leaks-scanner-static") {
                continue
            }
            if ($sourceFixtureByCheck.ContainsKey([string]$sourceCheckId)) {
                $fixtureRecord = $sourceFixtureByCheck[[string]$sourceCheckId]
                [ordered]@{
                    id = [string]$sourceCheckId
                    status = "pass"
                    executable = "powershell.exe"
                    arguments = @(
                        "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-File", "scripts/windows/phase2/Run-Source-Fixture.ps1",
                        "-OutputDirectory",
                        "artifacts/evidence/phase-2/source-synthetic/source-fixtures")
                    working_directory = "."
                    started_at = $recordedAt
                    completed_at = $recordedAt
                    duration_ms = 0
                    exit_code = 0
                    failure_summary = $null
                    stdout = [ordered]@{
                        path = "source-fixture-suite.stdout.txt"
                        size = 0
                        sha256 = $emptySourceLogHash
                    }
                    stderr = [ordered]@{
                        path = "source-fixture-suite.stderr.txt"
                        size = 0
                        sha256 = $emptySourceLogHash
                    }
                    source_fixture_receipt = $fixtureRecord.Receipt
                    source_fixture_receipt_artifact = [ordered]@{
                        path = "source-fixtures/$([string]$fixtureRecord.Name)"
                        size = [long]$fixtureRecord.Size
                        sha256 = [string]$fixtureRecord.Sha256
                    }
                    source_fixture_suite_index = [ordered]@{
                        path = "source-fixtures/index.json"
                        size = [long]$sourceFixtureSuite.IndexSize
                        sha256 = [string]$sourceFixtureSuite.IndexSha256
                    }
                }
            }
            else {
                [ordered]@{
                    id = [string]$sourceCheckId
                    status = "pass"
                    exit_code = 0
                }
            }
        }
        foreach ($sourceCheckId in @(
                $evidenceSpecification.specification.source_report_contract.allowed_not_run_check_ids)) {
            $notRunReasons = [ordered]@{
                "native-toolchain-provenance" = "Authenticated Rust/rustup/Git/VS/MSVC/Windows SDK/package-tool payload, runtime, sysroot, library, and linker provenance is not implemented."
                "no-leaks-producer-workflow" = "Candidate-owned installed artifact producer is not implemented."
                "pinned-clean-build-environment" = "Authenticated immutable candidate input and fresh dependency, build, and output isolation are not implemented for every source check."
                "portable-runner-attestation" = "Authenticated GitHub artifact attestation tied to repository, workflow, commit, and artifact digest is not implemented."
                "source-report-command-provenance" = "Independent closed command/argument/working-directory provenance for every source-report check is not implemented."
                "windows-native-ignored-fixtures" = "Requires explicit native-fixture workflow support; interactive native fixtures remain unimplemented source evidence."
            }
            if ([string]$sourceCheckId -ceq $PromoteFrozenSourceCheckId) {
                [ordered]@{
                    id = [string]$sourceCheckId
                    status = "pass"
                    exit_code = 0
                }
            }
            else {
                [ordered]@{
                    id = [string]$sourceCheckId
                    status = "not_run"
                    reason = [string]$notRunReasons[[string]$sourceCheckId]
                }
            }
        }
    )
    if ($CorruptSourceFixtureReceipt) {
        $corruptReceiptCheck = @($sourceChecks | Where-Object {
                [string]$_.id -clike 'phase2-source-fixture-*'
            })[0]
        $corruptReceiptCheck.source_fixture_receipt.gate_runner_id =
            "stein.phase2.invalid.v1"
    }
    $sourceProvenanceHash = Get-SteinPhase2EvidenceTextSha256 `
        -Value ($sourceProvenance | ConvertTo-Json -Depth 16 -Compress)
    $sourceChecksHash = Get-SteinPhase2EvidenceTextSha256 `
        -Value ($sourceChecks | ConvertTo-Json -Depth 40 -Compress)
    $sourceReportRecord = [ordered]@{
        schema_version = 2
        claim = "source_verification_only"
        installed_or_signed_evidence = $false
        passed = $true
        complete_acceptance = $false
        provenance = $sourceProvenance
        integrity = [ordered]@{
            semantics = "content_integrity_only_not_authentication"
            generator = [ordered]@{
                schema_version = 1
                files = $sourceGeneratorFiles
                digest_sha256 = $sourceGeneratorHash
            }
            provenance_sha256 = $sourceProvenanceHash
            checks_sha256 = $sourceChecksHash
            root_anchor_path = "root-anchor.json"
        }
        checks = $sourceChecks
        summary = [ordered]@{
            pass = @($sourceChecks | Where-Object { $_.status -ceq "pass" }).Count
            fail = 0
            not_run = @($sourceChecks | Where-Object {
                    $_.status -ceq "not_run"
                }).Count
        }
    }
    $sourceReportPath = Join-Path $attachmentRoot "source-verification.json"
    $null = Write-SteinReviewTestJson -Path $sourceReportPath -Value $sourceReportRecord
    $sourceReportItem = Get-Item -LiteralPath $sourceReportPath -Force -ErrorAction Stop
    $sourceReportHash = Get-SteinPhase2Sha256 -Path $sourceReportPath
    $sourceRootMaterial = @(
        "stein-phase2-source-evidence-root-v1",
        "source_verification_sha256=$sourceReportHash",
        "generator_sha256=$sourceGeneratorHash",
        "provenance_sha256=$sourceProvenanceHash",
        "checks_sha256=$sourceChecksHash"
    ) -join "`n"
    $sourceRootRecord = [ordered]@{
        schema_version = 1
        claim = "source_verification_only"
        integrity_semantics = "content_integrity_only_not_authentication"
        source_verification = [ordered]@{
            path = "source-verification.json"
            size = [long]$sourceReportItem.Length
            sha256 = $sourceReportHash
        }
        generator_sha256 = $sourceGeneratorHash
        provenance_sha256 = $sourceProvenanceHash
        checks_sha256 = $sourceChecksHash
        root_digest_sha256 = Get-SteinReviewTestStringSha256 -Value $sourceRootMaterial
    }
    $sourceRootPath = Join-Path $attachmentRoot "source-root-anchor.json"
    $null = Write-SteinReviewTestJson -Path $sourceRootPath -Value $sourceRootRecord
    $sourceRootItem = Get-Item -LiteralPath $sourceRootPath -Force -ErrorAction Stop
    $sourceRootHash = Get-SteinPhase2Sha256 -Path $sourceRootPath
    $package.candidate_git_commit = $sourceCommit
    $package.candidate_git_tree = $sourceTree
    $package.source_verification_sha256 = $sourceReportHash
    $package.source_root_anchor_sha256 = $sourceRootHash
    $package.source_root_digest_sha256 = [string]$sourceRootRecord.root_digest_sha256

    foreach ($gateId in $expectedGates) {
        $leaf = $gateId.ToLowerInvariant() -replace "[^a-z0-9._-]", "-"
        $attachmentId = "fixture-$leaf"
        $gateSpecification = $evidenceSpecification.gates_by_id[$gateId]
        $subcheckRecords = New-Object Collections.Generic.List[object]
        $subcheckOrigins = @{}
        foreach ($subcheckId in @($gateSpecification.required_subchecks)) {
            $subcheckOrigins[[string]$subcheckId] = Get-SteinPhase2GateSubcheckOrigin `
                -Gate $gateSpecification `
                -SubcheckId ([string]$subcheckId)
        }
        $origins = @($subcheckOrigins.Values | Sort-Object -Unique)
        $sourceGateFrozen = 'source_verification' -cin $origins
        $artifactRecords = New-Object Collections.Generic.List[object]
        $artifactMappings = New-Object Collections.Generic.List[object]
        foreach ($sharedArtifact in @(
                [pscustomobject]@{
                    id = "source-verification-report"
                    path = $sourceReportPath
                    hash = $sourceReportHash
                    size = [long]$sourceReportItem.Length
                },
                [pscustomobject]@{
                    id = "source-root-anchor"
                    path = $sourceRootPath
                    hash = $sourceRootHash
                    size = [long]$sourceRootItem.Length
                })) {
            $artifactRecords.Add([ordered]@{
                artifact_id = [string]$sharedArtifact.id
                proof_class = "source_provenance"
                origin = "source_verification"
                sha256 = [string]$sharedArtifact.hash
                size = [long]$sharedArtifact.size
            })
            $artifactMappings.Add([ordered]@{
                artifact_id = [string]$sharedArtifact.id
                path = "attachments/$([IO.Path]::GetFileName([string]$sharedArtifact.path))"
                sha256 = [string]$sharedArtifact.hash
                size = [long]$sharedArtifact.size
            })
        }

        $linuxBinding = $null
        $linuxArtifactId = $null
        $linuxLogArtifactIds = @{}
        if ($gateId -ceq "P2-PORTABLE-FIXTURE") {
            $linuxArtifactId = "portable-linux-result"
            $linuxSubchecks = @(
                foreach ($linuxSubcheckId in @($gateSpecification.linux_artifact.required_subchecks)) {
                    $linuxLogArtifactId =
                        [string]$gateSpecification.linux_artifact.artifact_id_prefix +
                        [string]$linuxSubcheckId
                    $linuxLogPath = Join-Path `
                        $attachmentRoot `
                        "$leaf-$linuxLogArtifactId.log"
                    [IO.File]::WriteAllText(
                        $linuxLogPath,
                        "synthetic portable log for $linuxSubcheckId`n",
                        [Text.UTF8Encoding]::new($false))
                    $linuxLogItem = Get-Item `
                        -LiteralPath $linuxLogPath `
                        -Force `
                        -ErrorAction Stop
                    $linuxLogHash = Get-SteinPhase2Sha256 -Path $linuxLogPath
                    $linuxLogArtifactIds[[string]$linuxSubcheckId] = $linuxLogArtifactId
                    $artifactRecords.Add([ordered]@{
                        artifact_id = $linuxLogArtifactId
                        proof_class = "portable_linux"
                        origin = "linux_ci"
                        sha256 = $linuxLogHash
                        size = [long]$linuxLogItem.Length
                    })
                    $artifactMappings.Add([ordered]@{
                        artifact_id = $linuxLogArtifactId
                        path = "attachments/$([IO.Path]::GetFileName($linuxLogPath))"
                        sha256 = $linuxLogHash
                        size = [long]$linuxLogItem.Length
                    })
                    [ordered]@{
                        id = [string]$linuxSubcheckId
                        command = "cargo synthetic $linuxSubcheckId"
                        exit_code = 0
                        result = "pass"
                        artifact = [ordered]@{
                            path = "logs/$linuxSubcheckId.log"
                            size_bytes = [long]$linuxLogItem.Length
                            sha256 = $linuxLogHash
                        }
                    }
                })
            $linuxArtifactRecord = [ordered]@{
                schema_version = 1
                gate_id = "P2-PORTABLE-FIXTURE"
                fixture_id = "phase2-portable-semantic-v1"
                runner_id = "github-actions-ubuntu-portable-v1"
                result = "pass"
                generated_at = $recordedAt
                repository = [ordered]@{
                    commit = $sourceCommit
                    tree = "c" * 40
                    clean_before = $true
                    clean_after = $true
                }
                toolchain = [ordered]@{
                    rustc_verbose = "rustc synthetic linux"
                    cargo_version = "cargo synthetic"
                    rust_toolchain_sha256 = "d" * 64
                    cargo_lock_sha256 = "e" * 64
                }
                generator = [ordered]@{
                    workflow_path = ".github/workflows/portable-semantic.yml"
                    workflow_sha256 = "f" * 64
                }
                subchecks = $linuxSubchecks
            }
            $linuxPath = Join-Path $attachmentRoot "$leaf-linux.json"
            $null = Write-SteinReviewTestJson -Path $linuxPath -Value $linuxArtifactRecord
            $linuxItem = Get-Item -LiteralPath $linuxPath -Force -ErrorAction Stop
            $linuxHash = Get-SteinPhase2Sha256 -Path $linuxPath
            $artifactRecords.Add([ordered]@{
                artifact_id = $linuxArtifactId
                proof_class = "portable_linux"
                origin = "linux_ci"
                sha256 = $linuxHash
                size = [long]$linuxItem.Length
            })
            $artifactMappings.Add([ordered]@{
                artifact_id = $linuxArtifactId
                path = "attachments/$([IO.Path]::GetFileName($linuxPath))"
                sha256 = $linuxHash
                size = [long]$linuxItem.Length
            })
            $linuxBinding = [ordered]@{
                artifact_id = $linuxArtifactId
                sha256 = $linuxHash
                fixture_id = "phase2-portable-semantic-v1"
                runner_id = "github-actions-ubuntu-portable-v1"
            }
        }

        $proofArtifactIdsByOrigin = @{}
        foreach ($origin in $origins) {
            $proofArtifactIdsByOrigin[[string]$origin] =
                New-Object Collections.Generic.List[string]
        }
        $runnerArtifactBindings = New-Object Collections.Generic.List[object]
        $runnerProofClasses = @{}
        $noLeaksCatalogHash = $null
        $noLeaksProducerManifestHash = $null
        $noLeaksProducerSourceHash = $null
        if ($gateId -ceq "P2-NO-LEAKS") {
            $noLeaksCatalogHash = Get-SteinReviewTestStringSha256 `
                -Value "synthetic-no-leaks-catalog"
            $producerSourcePath = Join-Path $attachmentRoot "$leaf-producer-source.ps1"
            [IO.File]::WriteAllText(
                $producerSourcePath,
                "# synthetic contract-only sentinel producer source`n",
                [Text.UTF8Encoding]::new($false))
            $producerSourceItem = Get-Item `
                -LiteralPath $producerSourcePath `
                -Force `
                -ErrorAction Stop
            $noLeaksProducerSourceHash = Get-SteinPhase2Sha256 -Path $producerSourcePath
            $producerManifestPath = Join-Path $attachmentRoot "$leaf-producer-manifest.json"
            $null = Write-SteinReviewTestJson `
                -Path $producerManifestPath `
                -Value ([ordered]@{
                    schema_version = 1
                    producer_id = "stein-phase2-no-leaks-artifact-producer-v1"
                    synthetic_contract_only = $true
                })
            $producerManifestItem = Get-Item `
                -LiteralPath $producerManifestPath `
                -Force `
                -ErrorAction Stop
            $noLeaksProducerManifestHash = Get-SteinPhase2Sha256 -Path $producerManifestPath
            foreach ($producerArtifact in @(
                    [pscustomobject]@{
                        id = "no-leaks-producer-source"
                        path = $producerSourcePath
                        hash = $noLeaksProducerSourceHash
                        size = [long]$producerSourceItem.Length
                        origin = "source_verification"
                    },
                    [pscustomobject]@{
                        id = "no-leaks-producer-manifest"
                        path = $producerManifestPath
                        hash = $noLeaksProducerManifestHash
                        size = [long]$producerManifestItem.Length
                        origin = "installed_native"
                    })) {
                $artifactRecords.Add([ordered]@{
                    artifact_id = [string]$producerArtifact.id
                    proof_class = "privacy_scan"
                    origin = [string]$producerArtifact.origin
                    sha256 = [string]$producerArtifact.hash
                    size = [long]$producerArtifact.size
                })
                $artifactMappings.Add([ordered]@{
                    artifact_id = [string]$producerArtifact.id
                    path = "attachments/$([IO.Path]::GetFileName([string]$producerArtifact.path))"
                    sha256 = [string]$producerArtifact.hash
                    size = [long]$producerArtifact.size
                })
                $proofArtifactIdsByOrigin[[string]$producerArtifact.origin].Add(
                    [string]$producerArtifact.id)
            }
        }
        if ($null -ne $gateSpecification.PSObject.Properties["runner_artifacts"]) {
            foreach ($runnerArtifactSpecification in @($gateSpecification.runner_artifacts)) {
                $runnerArtifactId = "runner-$($runnerArtifactSpecification.artifact_role.Replace('_', '-'))"
                $runnerArtifactPath = Join-Path $attachmentRoot "$leaf-$runnerArtifactId.json"
                $runnerSubchecks = if (
                    [string]$runnerArtifactSpecification.artifact_role -ceq "no_leaks_scan") {
                    @($runnerArtifactSpecification.required_subchecks | ForEach-Object {
                        [ordered]@{
                            id = [string]$_
                            result = "pass"
                            files_inspected = 1
                            matches_found = 0
                        }
                    })
                }
                elseif ([string]$runnerArtifactSpecification.artifact_role -ceq
                    "no_leaks_sentinel_producer") {
                    @($runnerArtifactSpecification.required_subchecks | ForEach-Object {
                        [ordered]@{
                            id = [string]$_
                            result = "pass"
                            artifacts_produced = 1
                        }
                    })
                }
                else {
                    @($runnerArtifactSpecification.required_subchecks | ForEach-Object {
                        [ordered]@{ id = [string]$_; result = "pass" }
                    })
                }
                $runnerArtifactRecord = if (
                    [string]$runnerArtifactSpecification.artifact_role -ceq "no_leaks_scan") {
                    [ordered]@{
                        schema_version = 1
                        gate_id = "P2-NO-LEAKS"
                        fixture_id = [string]$runnerArtifactSpecification.fixture_id
                        runner_id = [string]$runnerArtifactSpecification.runner_id
                        result = "pass"
                        bindings = [ordered]@{
                            package_msix_sha256 = [string]$package.msix_sha256
                            candidate_git_commit = $sourceCommit
                            source_verification_sha256 = $sourceReportHash
                            artifact_catalog_sha256 = $noLeaksCatalogHash
                            artifact_count = $runnerSubchecks.Count
                        }
                        summary = [ordered]@{
                            required = $runnerSubchecks.Count
                            passed = $runnerSubchecks.Count
                            failed = 0
                            not_run = 0
                            files_inspected = $runnerSubchecks.Count
                        }
                        subchecks = $runnerSubchecks
                    }
                }
                elseif ([string]$runnerArtifactSpecification.artifact_role -ceq
                    "no_leaks_sentinel_producer") {
                    [ordered]@{
                        schema_version = 1
                        gate_id = "P2-NO-LEAKS"
                        fixture_id = [string]$runnerArtifactSpecification.fixture_id
                        runner_id = [string]$runnerArtifactSpecification.runner_id
                        result = "pass"
                        bindings = [ordered]@{
                            package_msix_sha256 = [string]$package.msix_sha256
                            candidate_git_commit = $sourceCommit
                            source_verification_sha256 = $sourceReportHash
                            producer_manifest_sha256 = $noLeaksProducerManifestHash
                            producer_source_sha256 = $noLeaksProducerSourceHash
                            artifact_catalog_sha256 = $noLeaksCatalogHash
                            artifact_count = $runnerSubchecks.Count
                        }
                        summary = [ordered]@{
                            required = $runnerSubchecks.Count
                            passed = $runnerSubchecks.Count
                            failed = 0
                            not_run = 0
                            artifacts_produced = $runnerSubchecks.Count
                        }
                        subchecks = $runnerSubchecks
                    }
                }
                else {
                    [ordered]@{
                        schema_version = 1
                        fixture_id = [string]$runnerArtifactSpecification.fixture_id
                        runner_id = [string]$runnerArtifactSpecification.runner_id
                        result = "pass"
                        summary = [ordered]@{
                            required = $runnerSubchecks.Count
                            passed = $runnerSubchecks.Count
                            failed = 0
                            not_run = 0
                        }
                        subchecks = $runnerSubchecks
                    }
                }
                $null = Write-SteinReviewTestJson `
                    -Path $runnerArtifactPath `
                    -Value $runnerArtifactRecord
                $runnerArtifactItem = Get-Item `
                    -LiteralPath $runnerArtifactPath `
                    -Force `
                    -ErrorAction Stop
                $runnerArtifactHash = Get-SteinPhase2Sha256 -Path $runnerArtifactPath
                $artifactRecords.Add([ordered]@{
                    artifact_id = $runnerArtifactId
                    proof_class = [string]$runnerArtifactSpecification.proof_class
                    origin = [string]$runnerArtifactSpecification.origin
                    sha256 = $runnerArtifactHash
                    size = [long]$runnerArtifactItem.Length
                })
                $artifactMappings.Add([ordered]@{
                    artifact_id = $runnerArtifactId
                    path = "attachments/$([IO.Path]::GetFileName($runnerArtifactPath))"
                    sha256 = $runnerArtifactHash
                    size = [long]$runnerArtifactItem.Length
                })
                $proofArtifactIdsByOrigin[[string]$runnerArtifactSpecification.origin].Add(
                    $runnerArtifactId)
                $runnerProofClasses[[string]$runnerArtifactSpecification.proof_class] = $true
                $runnerArtifactBindings.Add([ordered]@{
                    artifact_role = [string]$runnerArtifactSpecification.artifact_role
                    artifact_id = $runnerArtifactId
                    fixture_id = [string]$runnerArtifactSpecification.fixture_id
                    runner_id = [string]$runnerArtifactSpecification.runner_id
                    sha256 = $runnerArtifactHash
                })
            }
        }
        $proofIndex = 0
        foreach ($proofClass in @($gateSpecification.required_proof_classes)) {
            if ($runnerProofClasses.ContainsKey([string]$proofClass)) {
                continue
            }
            if ($gateId -ceq "P2-PORTABLE-FIXTURE" -and
                [string]$proofClass -ceq "portable_linux") {
                $proofArtifactIdsByOrigin["linux_ci"].Add($linuxArtifactId)
                continue
            }
            $origin = [string]$origins[$proofIndex % $origins.Count]
            if ([string]$proofClass -ceq "source_contract" -and
                "source_verification" -cin $origins) {
                $origin = "source_verification"
            }
            $proofArtifactId = "proof-$($proofClass.Replace('_', '-'))"
            $proofPath = Join-Path $attachmentRoot "$leaf-$proofArtifactId.json"
            $null = Write-SteinReviewTestJson `
                -Path $proofPath `
                -Value ([ordered]@{
                    schema_version = 1
                    gate_id = $gateId
                    proof_class = [string]$proofClass
                    origin = $origin
                    synthetic = $true
                })
            $proofItem = Get-Item -LiteralPath $proofPath -Force -ErrorAction Stop
            $proofHash = Get-SteinPhase2Sha256 -Path $proofPath
            $artifactRecords.Add([ordered]@{
                artifact_id = $proofArtifactId
                proof_class = [string]$proofClass
                origin = $origin
                sha256 = $proofHash
                size = [long]$proofItem.Length
            })
            $artifactMappings.Add([ordered]@{
                artifact_id = $proofArtifactId
                path = "attachments/$([IO.Path]::GetFileName($proofPath))"
                sha256 = $proofHash
                size = [long]$proofItem.Length
            })
            $proofArtifactIdsByOrigin[$origin].Add($proofArtifactId)
            $proofIndex++
        }
        foreach ($origin in $origins) {
            if ($proofArtifactIdsByOrigin[$origin].Count -eq 0) {
                $fallbackId = "proof-origin-$($origin.Replace('_', '-'))"
                $fallbackPath = Join-Path $attachmentRoot "$leaf-$fallbackId.json"
                $null = Write-SteinReviewTestJson `
                    -Path $fallbackPath `
                    -Value ([ordered]@{ origin = $origin; synthetic = $true })
                $fallbackItem = Get-Item -LiteralPath $fallbackPath -Force -ErrorAction Stop
                $fallbackHash = Get-SteinPhase2Sha256 -Path $fallbackPath
                $artifactRecords.Add([ordered]@{
                    artifact_id = $fallbackId
                    proof_class = [string]@($gateSpecification.required_proof_classes)[0]
                    origin = $origin
                    sha256 = $fallbackHash
                    size = [long]$fallbackItem.Length
                })
                $artifactMappings.Add([ordered]@{
                    artifact_id = $fallbackId
                    path = "attachments/$([IO.Path]::GetFileName($fallbackPath))"
                    sha256 = $fallbackHash
                    size = [long]$fallbackItem.Length
                })
                $proofArtifactIdsByOrigin[$origin].Add($fallbackId)
            }
        }
        $firstSubcheckByOrigin = @{}
        foreach ($subcheckId in @($gateSpecification.required_subchecks)) {
            $origin = [string]$subcheckOrigins[[string]$subcheckId]
            $artifactIds = @(if (-not $firstSubcheckByOrigin.ContainsKey($origin)) {
                    $firstSubcheckByOrigin[$origin] = $true
                    @($proofArtifactIdsByOrigin[$origin])
                }
                else { @([string]$proofArtifactIdsByOrigin[$origin][0]) })
            if ($null -ne $gateSpecification.PSObject.Properties["runner_artifacts"]) {
                foreach ($runnerArtifactSpecification in @($gateSpecification.runner_artifacts)) {
                    if ([string]$subcheckId -cin @($runnerArtifactSpecification.required_subchecks)) {
                        $runnerBinding = @($runnerArtifactBindings | Where-Object {
                            [string]$_.artifact_role -ceq
                                [string]$runnerArtifactSpecification.artifact_role
                        })[0]
                        if ([string]$runnerBinding.artifact_id -cnotin $artifactIds) {
                            $artifactIds += [string]$runnerBinding.artifact_id
                        }
                    }
                }
            }
            if ($origin -ceq "linux_ci" -and
                $linuxLogArtifactIds.ContainsKey([string]$subcheckId)) {
                $linuxLogArtifactId = $linuxLogArtifactIds[[string]$subcheckId]
                if ($linuxLogArtifactId -cnotin $artifactIds) {
                    $artifactIds += $linuxLogArtifactId
                }
            }
            $subcheckRecords.Add([ordered]@{
                id = [string]$subcheckId
                origin = $origin
                result = "pass"
                artifact_ids = $artifactIds
                source_check_ids = if ($origin -ceq "source_verification") {
                    $sourceMappingProperty =
                        $gateSpecification.source_subcheck_check_ids.PSObject.Properties[
                            [string]$subcheckId]
                    @(
                        @($sourceMappingProperty.Value) +
                            @(
                                "native-toolchain-provenance",
                                "pinned-clean-build-environment",
                                "source-report-command-provenance") |
                            Sort-Object -Unique)
                }
                else { @() }
            })
        }
        $fixtureRecord = [ordered]@{
            schema_version = 2
            contract_id = [string]$evidenceSpecification.specification.contract_id
            contract_sha256 = $evidenceSpecificationSha256
            gate_id = $gateId
            fixture_id = [string]$gateSpecification.fixture_id
            runner_id = [string]$gateSpecification.runner_id
            result = if ($sourceGateFrozen) { "not_run" } else { "pass" }
            recorded_at_utc = $recordedAt
            exit_code = if ($sourceGateFrozen) { $null } else { 0 }
            runner = [ordered]@{
                platform = "windows"
                architecture = "AMD64"
                non_elevated = $true
                installed_package = $true
            }
            proof_classes = @($gateSpecification.required_proof_classes)
            subchecks = @($subcheckRecords | ForEach-Object { $_ })
            bindings = [ordered]@{
                package = [ordered]@{
                    package_family_name = [string]$package.package_family_name
                    version = [string]$package.version
                    msix_sha256 = [string]$package.msix_sha256
                    core_sha256 = [string]$package.core_sha256
                    browser_host_sha256 = [string]$package.browser_host_sha256
                    cli_executable_size = [long]$package.cli_executable_size
                    cli_executable_sha256 = [string]$package.cli_executable_sha256
                    desktop_executable_size = [long]$package.desktop_executable_size
                    desktop_executable_sha256 = [string]$package.desktop_executable_sha256
                    desktop_dist_file_count = [int]$package.desktop_dist_file_count
                    desktop_dist_manifest_sha256 = if (
                        $MismatchedPackageBinding -and $gateId -ceq "P2-BUILD") {
                        "d" * 64
                    }
                    else { [string]$package.desktop_dist_manifest_sha256 }
                    candidate_git_commit = [string]$package.candidate_git_commit
                    candidate_git_tree = [string]$package.candidate_git_tree
                    source_verification_sha256 = [string]$package.source_verification_sha256
                    source_root_anchor_sha256 = [string]$package.source_root_anchor_sha256
                    source_root_digest_sha256 = [string]$package.source_root_digest_sha256
                }
                commit = [ordered]@{
                    object_id = $sourceCommit
                    tree_id = [string]$package.candidate_git_tree
                }
                collector = [ordered]@{
                    host_identity_sha256 = [string]$hostRecord.host_identity_sha256
                    evidence_owner_sid_only = $true
                }
                source_report = [ordered]@{
                    report_artifact_id = "source-verification-report"
                    root_anchor_artifact_id = "source-root-anchor"
                    report_sha256 = $sourceReportHash
                    root_anchor_sha256 = $sourceRootHash
                    root_digest_sha256 = [string]$sourceRootRecord.root_digest_sha256
                }
                linux_artifact = $linuxBinding
                runner_artifacts = @($runnerArtifactBindings | ForEach-Object { $_ })
            }
            artifacts = @($artifactRecords | ForEach-Object { $_ })
        }
        $nativePath = Join-Path $attachmentRoot "$leaf.json"
        $null = Write-SteinReviewTestJson -Path $nativePath -Value $fixtureRecord
        $nativeItem = Get-Item -LiteralPath $nativePath -Force -ErrorAction Stop
        $nativeHash = Get-SteinPhase2Sha256 -Path $nativePath
        $nativePaths[$gateId] = $nativePath
        $metadata = [ordered]@{
            attachment_id = $attachmentId
            gate_id = $gateId
            kind = "native_fixture_result"
            declared_result = if ($sourceGateFrozen) { "not_run" } else { "pass" }
            recorded_at_utc = $recordedAt
            sha256 = $nativeHash
            size = [long]$nativeItem.Length
            privacy_reviewed = $true
            synthetic_only = $true
            source_path_retained = $false
            file_copied = $false
            semantic_result_verified_by_harness = $false
            native_fixture = [ordered]@{
                schema_version = 2
                contract_id = [string]$fixtureRecord.contract_id
                contract_sha256 = [string]$fixtureRecord.contract_sha256
                fixture_id = [string]$fixtureRecord.fixture_id
                runner_id = [string]$fixtureRecord.runner_id
                exit_code = if ($sourceGateFrozen) { $null } else { 0 }
                closed_content_free_schema_verified = $true
                proof_classes = @($fixtureRecord.proof_classes)
                subchecks = @($fixtureRecord.subchecks)
                bindings = $fixtureRecord.bindings
                artifacts = @($fixtureRecord.artifacts)
            }
        }
        $rowAttachments = New-Object Collections.Generic.List[object]
        $rowAttachments.Add($metadata)
        $attachmentMappings.Add([ordered]@{
            attachment_id = $attachmentId
            gate_id = $gateId
            kind = "native_fixture_result"
            path = "attachments/$leaf.json"
            sha256 = $nativeHash
            artifacts = @($artifactMappings | ForEach-Object { $_ })
        })
        if ($gateId -ceq "P2-BUILD") {
            $screenshotPath = Join-Path $attachmentRoot "p2-build.png"
            [IO.File]::WriteAllBytes(
                $screenshotPath,
                [byte[]](137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0))
            $screenshotItem = Get-Item -LiteralPath $screenshotPath -Force -ErrorAction Stop
            $screenshotHash = Get-SteinPhase2Sha256 -Path $screenshotPath
            $screenshotMetadata = [ordered]@{
                attachment_id = $screenshotAttachmentId
                gate_id = $gateId
                kind = "redacted_screenshot"
                declared_result = "pass"
                recorded_at_utc = $recordedAt
                sha256 = $screenshotHash
                size = [long]$screenshotItem.Length
                privacy_reviewed = $true
                synthetic_only = $true
                source_path_retained = $false
                file_copied = $false
                semantic_result_verified_by_harness = $false
                native_fixture = $null
            }
            $rowAttachments.Add($screenshotMetadata)
            $attachmentMappings.Add([ordered]@{
                attachment_id = $screenshotAttachmentId
                gate_id = $gateId
                kind = "redacted_screenshot"
                path = "attachments/p2-build.png"
                sha256 = $screenshotHash
                artifacts = @()
            })
        }

        $status = "not_run"
        if ($SourceStatuses.ContainsKey($gateId)) {
            $status = [string]$SourceStatuses[$gateId]
        }
        $reasonCode = switch ($status) {
            "fail" { "synthetic_collector_fail" }
            "blocked" { "synthetic_collector_blocked" }
            "pass" { "synthetic_collector_pass" }
            default { "synthetic_fixture_requires_review" }
        }
        $rowCommands = @()
        if ($gateId -ceq "P2-BUILD") {
            $rowCommands = @(
                [ordered]@{
                    check_id = "synthetic-collector-check"
                    status = if ($MismatchedRowCommand) { "not_run" } else { "pass" }
                    command = $checkCommand
                    exit_code = 0
                    output = $checkOutputArtifact
                })
        }
        $rowPayload = [ordered]@{
            schema_version = 1
            gate_id = $gateId
            status = $status
            reason_code = $reasonCode
            harness_identity = "phase2-installed-evidence-v1"
            generator_provenance = $generatorArtifact
            host_provenance = $hostArtifact
            package = $package
            versions = $versions
            policy_profile = [ordered]@{
                expected_id = "phase2-focus-v1"
                reported_by_installed_runtime = $false
                accepted_as_installed_policy_evidence = $false
            }
            commands = $rowCommands
            attachments = @($rowAttachments | ForEach-Object { $_ })
            screenshot_can_prove_gate = $false
            attached_pass_promoted_by_harness = $false
        }
        $rowPath = Join-Path $rowsDirectory "$leaf.json"
        $null = Write-SteinReviewTestJson -Path $rowPath -Value $rowPayload
        $rowArtifact = Get-SteinReviewTestArtifact `
            -EvidenceRoot $evidenceRoot `
            -Path $rowPath
        $rowPaths[$gateId] = $rowPath
        $rowOutputArtifacts = @($rowCommands | ForEach-Object { $_.output }) + @($rowArtifact)
        if ($DuplicateRowOutputArtifact -and $gateId -ceq "P2-BUILD") {
            $rowOutputArtifacts += @($rowArtifact)
        }
        $ledgerRows.Add([ordered]@{
            gate_id = $gateId
            status = $status
            reason_code = $reasonCode
            harness_identity = "phase2-installed-evidence-v1"
            versions = $versions
            commands = $rowCommands
            output_artifacts = $rowOutputArtifacts
            attachments = @($rowAttachments | ForEach-Object { $_ })
            generator_provenance = $generatorArtifact
            host_provenance = $hostArtifact
            row_artifact = $rowArtifact
        })
        $reviewRecords.Add([ordered]@{
            review_record_id = "review-$leaf"
            gate_id = $gateId
            disposition = "pass"
            reason_code = "synthetic_independent_review_pass"
            source_row_sha256 = [string]$rowArtifact.sha256
            native_fixture_attachment_id = $attachmentId
            native_fixture_sha256 = $nativeHash
            independent_review = $true
            semantic_review_completed = $true
            privacy_review_completed = $true
            synthetic_only = $true
            reviewed_at_utc = $recordedAt
        })
    }

    $failCount = @($ledgerRows | Where-Object { $_.status -ceq "fail" }).Count
    $blockedCount = @($ledgerRows | Where-Object { $_.status -ceq "blocked" }).Count
    $notRunCount = @($ledgerRows | Where-Object { $_.status -ceq "not_run" }).Count
    $passCount = @($ledgerRows | Where-Object { $_.status -ceq "pass" }).Count
    $ledger = [ordered]@{
        schema_version = 1
        run_id = [Guid]::NewGuid().ToString("N")
        claim = "installed_machine_verification_only"
        installed_or_signed_evidence = $true
        machine_verification_passed = $true
        complete_acceptance = $false
        started_at_utc = $recordedAt
        completed_at_utc = $recordedAt
        duration_ms = 1
        generator_provenance = $generatorArtifact
        host_provenance = $hostArtifact
        package = $package
        schema_versions = [ordered]@{
            ledger = 1
            release_identity = 1
            install_record = 2
            durable_persistence_capability = 1
        }
        policy_profile = [ordered]@{
            expected_id = "phase2-focus-v1"
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
        checks = @($collectorCheck)
        rows = @($ledgerRows | ForEach-Object { $_ })
        summary = [ordered]@{
            checks = [ordered]@{
                pass = 1
                fail = 0
                blocked = 0
                not_run = 0
            }
            rows = [ordered]@{
                pass = $passCount
                fail = $failCount
                blocked = $blockedCount
                not_run = $notRunCount
            }
        }
    }
    $ledgerPath = Join-Path $evidenceRoot "ledger.json"
    $null = Write-SteinReviewTestJson -Path $ledgerPath -Value $ledger
    $ledgerArtifact = Get-SteinReviewTestArtifact `
        -EvidenceRoot $evidenceRoot `
        -Path $ledgerPath
    $rootMaterial = @(
        "phase2-installed-evidence-root-v1",
        $ledger.run_id,
        $generatorArtifact.sha256,
        $hostArtifact.sha256,
        $ledgerArtifact.sha256
    ) -join "`0"
    $rootAnchor = [ordered]@{
        schema_version = 1
        run_id = $ledger.run_id
        harness_identity = "phase2-installed-evidence-v1"
        digest_algorithm = "sha256"
        root_digest_sha256 = Get-SteinReviewTestStringSha256 -Value $rootMaterial
        digest_material = "identity_nul_run_nul_generator_nul_host_nul_ledger"
        generator = $generatorArtifact
        host = $hostArtifact
        ledger = $ledgerArtifact
        trust_scope = "content_integrity_only_not_authentication"
    }
    $rootAnchorPath = Join-Path $evidenceRoot "root-anchor.json"
    $null = Write-SteinReviewTestJson -Path $rootAnchorPath -Value $rootAnchor
    $rootAnchorHash = Get-SteinPhase2Sha256 -Path $rootAnchorPath

    $manifest = [ordered]@{
        schema_version = 1
        review_identity = "phase2-installed-independent-review-v1"
        source_root_anchor_sha256 = $rootAnchorHash
        source_root_digest_sha256 = $rootAnchor.root_digest_sha256
        source_ledger_sha256 = $ledgerArtifact.sha256
        attachments = @($attachmentMappings | ForEach-Object { $_ })
        reviews = @($reviewRecords | ForEach-Object { $_ })
    }
    $manifestPath = Join-Path $reviewRoot "review-manifest.json"
    $null = Write-SteinReviewTestJson -Path $manifestPath -Value $manifest
    Protect-SteinPhase2OwnerOnlyTree -Root $evidenceRoot

    return [pscustomobject]@{
        root = $Root
        evidence_root = $evidenceRoot
        review_root = $reviewRoot
        output_root = $outputRoot
        manifest_path = $manifestPath
        root_anchor_path = $rootAnchorPath
        root_anchor_sha256 = $rootAnchorHash
        row_paths = $rowPaths
        native_paths = $nativePaths
        screenshot_attachment_id = $screenshotAttachmentId
    }
}

function Get-SteinReviewTestManifest {
    param([Parameter(Mandatory = $true)][string] $Path)

    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 |
        ConvertFrom-Json -ErrorAction Stop
}

function Set-SteinReviewTestManifest {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $Manifest
    )

    $Manifest | ConvertTo-Json -Depth 32 |
        Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}

function Invoke-SteinReviewTestCase {
    param(
        [Parameter(Mandatory = $true)] $Fixture,
        [Parameter(Mandatory = $true)][int] $ExpectedExitCode,
        [switch] $ExpectOutput,
        [string] $ExpectedGate,
        [string] $ExpectedGateStatus,
        [string] $RootAnchorSha256
    )

    if ([string]::IsNullOrWhiteSpace($RootAnchorSha256)) {
        $RootAnchorSha256 = [string]$Fixture.root_anchor_sha256
    }
    $hostExecutable = (Get-Process -Id $PID -ErrorAction Stop).Path
    $arguments = @("-NoLogo", "-NoProfile")
    if ([string]$PSVersionTable.PSEdition -ceq "Desktop") {
        $arguments += @("-ExecutionPolicy", "Bypass")
    }
    $arguments += @(
        "-File", $reviewerPath,
        "-EvidenceDirectory", $Fixture.evidence_root,
        "-ExpectedRootAnchorSha256", $RootAnchorSha256,
        "-ReviewManifest", $Fixture.manifest_path,
        "-OutputRoot", $Fixture.output_root)
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell promotes redirected native stderr to ErrorRecord objects.
        # Keep those records in the bounded synthetic transcript without aborting the case.
        $ErrorActionPreference = "Continue"
        $output = @(& $hostExecutable @arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if ($exitCode -ne $ExpectedExitCode) {
        $safeLastLine = if ($output.Count -ne 0) {
            (@($output | Select-Object -Last 8 | ForEach-Object { [string]$_ }) -join " | ")
        }
        else { "<no-output>" }
        throw "Reviewer test case exit mismatch: expected $ExpectedExitCode, got $exitCode; $safeLastLine"
    }
    if ($ExpectedExitCode -ne 0) {
        $transcript = @($output | ForEach-Object { [string]$_ }) -join "`n"
        if ($transcript -match '(?i)(?:[a-z]:[\\/]|S-1-[0-9]+(?:-[0-9]+){2,})' -or
            (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME) -and
                $env:COMPUTERNAME.Length -ge 3 -and
                $transcript.IndexOf(
                    $env:COMPUTERNAME,
                    [StringComparison]::OrdinalIgnoreCase) -ge 0)) {
            throw "A rejected reviewer input leaked a local path, SID, or host name."
        }
    }
    $outputs = @(Get-ChildItem -LiteralPath $Fixture.output_root -Directory -Force |
        Where-Object { $_.Name -like "reviewed-*" })
    if ($ExpectOutput) {
        if ($outputs.Count -ne 1) {
            $caseLeaf = Split-Path -Leaf (Split-Path -Parent $Fixture.output_root)
            throw "Reviewer case $caseLeaf emitted $($outputs.Count) protected outputs; expected one."
        }
        Assert-SteinPhase2OwnerOnlyTree -Root $outputs[0].FullName
        $ledgerPath = Join-Path $outputs[0].FullName "ledger.json"
        $rootPath = Join-Path $outputs[0].FullName "root-anchor.json"
        $generatorPath = Join-Path $outputs[0].FullName "reviewer-generator.json"
        foreach ($path in @($ledgerPath, $rootPath, $generatorPath)) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "A promoted evidence bundle is incomplete."
            }
        }
        $finalLedger = Get-Content -LiteralPath $ledgerPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
        $finalRoot = Get-Content -LiteralPath $rootPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
        $finalGenerator = Get-Content -LiteralPath $generatorPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
        $outputFiles = @(Get-ChildItem -LiteralPath $outputs[0].FullName -File -Recurse -Force)
        if ($outputFiles.Count -ne 3 -or
            [string]$finalRoot.reviewer_generator.path -cne "reviewer-generator.json" -or
            [string]$finalRoot.ledger.path -cne "ledger.json" -or
            [long]$finalRoot.reviewer_generator.size -ne
                (Get-Item -LiteralPath $generatorPath -Force).Length -or
            [long]$finalRoot.ledger.size -ne
                (Get-Item -LiteralPath $ledgerPath -Force).Length -or
            [string]$finalRoot.reviewer_generator.sha256 -cne
                (Get-SteinPhase2Sha256 -Path $generatorPath) -or
            [string]$finalRoot.ledger.sha256 -cne
                (Get-SteinPhase2Sha256 -Path $ledgerPath)) {
            throw "A promoted evidence bundle does not bind its exact final artifacts."
        }
        $expectedFinalRootMaterial = @(
            "phase2-installed-review-root-v1",
            [string]$finalRoot.run_id,
            [string]$finalRoot.reviewer_generator.sha256,
            [string]$finalRoot.source_root_anchor_sha256,
            [string]$finalRoot.review_manifest_sha256,
            [string]$finalRoot.ledger.sha256
        ) -join "`0"
        if ([string]$finalRoot.root_digest_sha256 -cne
            (Get-SteinReviewTestStringSha256 -Value $expectedFinalRootMaterial) -or
            [string]$finalGenerator.harness_identity -cne "phase2-installed-review-v1") {
            throw "A promoted evidence bundle has an invalid final integrity root."
        }
        if (@($finalLedger.rows).Count -ne 32) {
            throw "A promoted ledger does not retain the exact 32-gate set."
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedGate)) {
            $row = @($finalLedger.rows | Where-Object {
                [string]$_.gate_id -ceq $ExpectedGate
            })
            if ($row.Count -ne 1 -or
                [string]$row[0].status -cne $ExpectedGateStatus) {
                throw "A source fail/blocked/not-run result did not propagate conservatively."
            }
        }
        return $finalLedger
    }
    if ($outputs.Count -ne 0) {
        throw "An invalid reviewer input emitted a promoted output."
    }
    return $null
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..")).Path
if ($ReviewTestLibraryOnly) {
    return
}
$testRoot = Join-Path $repoRoot (
    "artifacts\evidence\phase-2\review-tests-" + [Guid]::NewGuid().ToString("N"))
$artifactsRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot "artifacts"))
$testRootCanonical = [IO.Path]::GetFullPath($testRoot)
$artifactsPrefix = $artifactsRoot.TrimEnd("\", "/") + [IO.Path]::DirectorySeparatorChar
if (-not $testRootCanonical.StartsWith(
        $artifactsPrefix,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "The reviewer test root escaped repository artifacts."
}

$cases = New-Object Collections.Generic.List[string]
try {
    $null = New-Item -ItemType Directory -Path $testRoot -Force -ErrorAction Stop

    foreach ($functionName in @(
            "Get-SteinReviewLockedStreamSha256",
            "Open-SteinReviewBootstrapFileBinding")) {
        $functionAst = @($reviewerAst.FindAll({
                    param($node)
                    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $functionName
                }, $true))
        if ($functionAst.Count -ne 1) {
            throw "The reviewer runtime-source lock helper is not uniquely defined."
        }
        . ([scriptblock]::Create($functionAst[0].Extent.Text))
    }
    $lockProbeRoot = Join-Path $testRoot "runtime-lock-probe"
    $null = New-Item -ItemType Directory -Path $lockProbeRoot -ErrorAction Stop
    $lockProbePath = Join-Path $lockProbeRoot "source.ps1"
    $replacementPath = Join-Path $lockProbeRoot "replacement.ps1"
    [IO.File]::WriteAllText($lockProbePath, "locked-review-source")
    [IO.File]::WriteAllText($replacementPath, "replacement-review-source")
    $binding = Open-SteinReviewBootstrapFileBinding `
        -Role "lock-probe" `
        -Path $lockProbePath `
        -RepositoryRoot $testRoot
    try {
        $writeRejected = $false
        try {
            [IO.File]::WriteAllText($lockProbePath, "mutated-review-source")
        }
        catch {
            $writeRejected = $true
        }
        $replacementRejected = $false
        try {
            Move-Item `
                -LiteralPath $replacementPath `
                -Destination $lockProbePath `
                -Force `
                -ErrorAction Stop
        }
        catch {
            $replacementRejected = $true
        }
        $sameHandleSha256 = Get-SteinReviewLockedStreamSha256 `
            -Stream $binding.stream `
            -FailureCode "reviewer_runtime_source_changed"
        if (-not $writeRejected -or -not $replacementRejected -or
            $sameHandleSha256 -cne [string]$binding.record.sha256) {
            throw "The reviewer runtime-source lock allowed a swap or changed bytes."
        }
    }
    finally {
        $binding.stream.Dispose()
    }
    $cases.Add("reviewer_runtime_source_swap_rejected")

    $frozenBaseline = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "frozen-baseline")
    $frozenLedger = Invoke-SteinReviewTestCase `
        -Fixture $frozenBaseline `
        -ExpectedExitCode 3 `
        -ExpectOutput
    $sourceOriginGateIds = @(
        $evidenceSpecification.specification.gates | Where-Object {
            $sourceSubchecksProperty =
                $_.PSObject.Properties['source_subchecks']
            $null -ne $sourceSubchecksProperty -and
                @($sourceSubchecksProperty.Value).Count -gt 0
        } | ForEach-Object { [string]$_.gate_id })
    $sourceOriginRows = @($frozenLedger.rows | Where-Object {
            [string]$_.gate_id -cin $sourceOriginGateIds
        })
    if ([bool]$frozenLedger.complete_acceptance -or
        $sourceOriginRows.Count -lt 1 -or
        @($sourceOriginRows | Where-Object { [string]$_.status -ceq "pass" }).Count -ne 0 -or
        [int]$frozenLedger.source_integrity.collector_rows_rehashed -ne 32 -or
        [int]$frozenLedger.source_integrity.collector_attachments_rehashed -ne 33) {
        throw "The frozen source-evidence blockers did not conservatively prevent promotion."
    }
    $positiveOutput = @(
        Get-ChildItem -LiteralPath $frozenBaseline.output_root -Directory -Force)[0]
    $outputText = @(
        Get-ChildItem -LiteralPath $positiveOutput.FullName -File -Recurse -Force |
            ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 }
    ) -join "`n"
    if ($outputText -match '(?i)(?:[a-z]:[\\/]|S-1-[0-9]+(?:-[0-9]+){2,})') {
        throw "The content-minimized final bundle retained a local path or SID."
    }
    $cases.Add("frozen_source_evidence_baseline_cannot_complete")

    $missingSourceContractCheck = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "missing-source-contract-check") `
        -OmitMandatorySourceCheck
    $null = Invoke-SteinReviewTestCase `
        -Fixture $missingSourceContractCheck `
        -ExpectedExitCode 1
    $cases.Add("missing_mandatory_source_contract_check_rejected")

    foreach ($frozenCheckId in @(
            "native-toolchain-provenance",
            "no-leaks-producer-workflow",
            "pinned-clean-build-environment",
            "portable-runner-attestation",
            "source-report-command-provenance",
            "windows-native-ignored-fixtures")) {
        $forgedFrozenPass = New-SteinReviewSyntheticFixture `
            -Root (Join-Path $testRoot ("forged-" + $frozenCheckId)) `
            -PromoteFrozenSourceCheckId $frozenCheckId
        $null = Invoke-SteinReviewTestCase `
            -Fixture $forgedFrozenPass `
            -ExpectedExitCode 1
        $cases.Add("frozen_$($frozenCheckId.Replace('-', '_'))_pass_rejected")
    }

    $corruptSourceFixtureReceipt = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "corrupt-source-fixture-receipt") `
        -CorruptSourceFixtureReceipt
    $null = Invoke-SteinReviewTestCase `
        -Fixture $corruptSourceFixtureReceipt `
        -ExpectedExitCode 1
    $cases.Add("corrupt_source_fixture_receipt_rejected")

    $mismatchedPackageBinding = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "mismatched-package-binding") `
        -MismatchedPackageBinding
    $null = Invoke-SteinReviewTestCase `
        -Fixture $mismatchedPackageBinding `
        -ExpectedExitCode 1
    $cases.Add("signed_package_subartifact_mismatch_rejected")

    $fabricatedSource = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "fabricated-source") `
        -FabricatedGeneratorSource
    $null = Invoke-SteinReviewTestCase -Fixture $fabricatedSource -ExpectedExitCode 1
    $cases.Add("fabricated_collector_runtime_source_rejected")

    $extraEvidence = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "extra-evidence")
    Set-Content `
        -LiteralPath (Join-Path $extraEvidence.evidence_root "unanchored.json") `
        -Value '{"unanchored":true}' `
        -Encoding UTF8 `
        -ErrorAction Stop
    Protect-SteinPhase2OwnerOnlyTree -Root $extraEvidence.evidence_root
    $null = Invoke-SteinReviewTestCase -Fixture $extraEvidence -ExpectedExitCode 1
    $cases.Add("unanchored_collector_file_rejected")

    $missingEvidence = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "missing-evidence")
    [IO.File]::Delete([string]$missingEvidence.row_paths["P2-BUILD"])
    $null = Invoke-SteinReviewTestCase -Fixture $missingEvidence -ExpectedExitCode 1
    $cases.Add("missing_collector_file_rejected")

    $duplicateArtifact = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "duplicate-artifact") `
        -DuplicateRowOutputArtifact
    $null = Invoke-SteinReviewTestCase -Fixture $duplicateArtifact -ExpectedExitCode 1
    $cases.Add("duplicate_row_artifact_rejected")

    $rowCommandMismatch = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "row-command-mismatch") `
        -MismatchedRowCommand
    $null = Invoke-SteinReviewTestCase -Fixture $rowCommandMismatch -ExpectedExitCode 1
    $cases.Add("row_command_check_mismatch_rejected")

    $staleReview = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "stale-review")
    $manifest = Get-SteinReviewTestManifest -Path $staleReview.manifest_path
    $manifest.reviews[0].reviewed_at_utc = [DateTime]::UtcNow.AddHours(-1).ToString("o")
    Set-SteinReviewTestManifest -Path $staleReview.manifest_path -Manifest $manifest
    $null = Invoke-SteinReviewTestCase -Fixture $staleReview -ExpectedExitCode 1
    $cases.Add("review_predating_collection_rejected")

    $screenshot = New-SteinReviewSyntheticFixture -Root (Join-Path $testRoot "screenshot")
    $manifest = Get-SteinReviewTestManifest -Path $screenshot.manifest_path
    $screenshotMapping = @($manifest.attachments | Where-Object {
        [string]$_.attachment_id -ceq $screenshot.screenshot_attachment_id
    })[0]
    $manifest.reviews[0].native_fixture_attachment_id = $screenshotMapping.attachment_id
    $manifest.reviews[0].native_fixture_sha256 = $screenshotMapping.sha256
    Set-SteinReviewTestManifest -Path $screenshot.manifest_path -Manifest $manifest
    $null = Invoke-SteinReviewTestCase -Fixture $screenshot -ExpectedExitCode 1
    $cases.Add("screenshot_cannot_promote")

    $changedRow = New-SteinReviewSyntheticFixture -Root (Join-Path $testRoot "changed-row")
    [IO.File]::AppendAllText(
        [string]$changedRow.row_paths["P2-BUILD"],
        "changed")
    $null = Invoke-SteinReviewTestCase -Fixture $changedRow -ExpectedExitCode 1
    $cases.Add("changed_row_rejected")

    $changedAttachment = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "changed-attachment")
    [IO.File]::AppendAllText(
        [string]$changedAttachment.native_paths["P2-BUILD"],
        "changed")
    $null = Invoke-SteinReviewTestCase -Fixture $changedAttachment -ExpectedExitCode 1
    $cases.Add("changed_attachment_rejected")

    $extraField = New-SteinReviewSyntheticFixture -Root (Join-Path $testRoot "extra-field")
    $manifest = Get-SteinReviewTestManifest -Path $extraField.manifest_path
    $manifest | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
    Set-SteinReviewTestManifest -Path $extraField.manifest_path -Manifest $manifest
    $null = Invoke-SteinReviewTestCase -Fixture $extraField -ExpectedExitCode 1
    $cases.Add("extra_manifest_field_rejected")

    $missingField = New-SteinReviewSyntheticFixture -Root (Join-Path $testRoot "missing-field")
    $manifest = Get-SteinReviewTestManifest -Path $missingField.manifest_path
    $manifest.reviews[0].PSObject.Properties.Remove("synthetic_only")
    Set-SteinReviewTestManifest -Path $missingField.manifest_path -Manifest $manifest
    $null = Invoke-SteinReviewTestCase -Fixture $missingField -ExpectedExitCode 1
    $cases.Add("missing_review_field_rejected")

    $duplicateGate = New-SteinReviewSyntheticFixture -Root (Join-Path $testRoot "duplicate-gate")
    $manifest = Get-SteinReviewTestManifest -Path $duplicateGate.manifest_path
    $manifest.reviews[1].gate_id = $manifest.reviews[0].gate_id
    Set-SteinReviewTestManifest -Path $duplicateGate.manifest_path -Manifest $manifest
    $null = Invoke-SteinReviewTestCase -Fixture $duplicateGate -ExpectedExitCode 1
    $cases.Add("duplicate_gate_rejected")

    $missingAttachment = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "missing-attachment")
    $manifest = Get-SteinReviewTestManifest -Path $missingAttachment.manifest_path
    $manifest.attachments = @($manifest.attachments | Select-Object -Skip 1)
    Set-SteinReviewTestManifest -Path $missingAttachment.manifest_path -Manifest $manifest
    $null = Invoke-SteinReviewTestCase -Fixture $missingAttachment -ExpectedExitCode 1
    $cases.Add("missing_attachment_mapping_rejected")

    $pathEscape = New-SteinReviewSyntheticFixture -Root (Join-Path $testRoot "path-escape")
    $manifest = Get-SteinReviewTestManifest -Path $pathEscape.manifest_path
    $manifest.attachments[0].path = "../escape.json"
    Set-SteinReviewTestManifest -Path $pathEscape.manifest_path -Manifest $manifest
    $null = Invoke-SteinReviewTestCase -Fixture $pathEscape -ExpectedExitCode 1
    $cases.Add("attachment_path_escape_rejected")

    $reparse = New-SteinReviewSyntheticFixture -Root (Join-Path $testRoot "reparse")
    $junctionPath = Join-Path $reparse.review_root "linked-attachments"
    $null = New-Item `
        -ItemType Junction `
        -Path $junctionPath `
        -Target (Join-Path $reparse.review_root "attachments") `
        -ErrorAction Stop
    $manifest = Get-SteinReviewTestManifest -Path $reparse.manifest_path
    $manifest.attachments[0].path = "linked-attachments/p2-build.json"
    Set-SteinReviewTestManifest -Path $reparse.manifest_path -Manifest $manifest
    $null = Invoke-SteinReviewTestCase -Fixture $reparse -ExpectedExitCode 1
    $cases.Add("attachment_reparse_rejected")

    $independence = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "independence") `
        -SourceStatuses @{ "P2-BUILD" = "pass" }
    $manifest = Get-SteinReviewTestManifest -Path $independence.manifest_path
    $manifest.reviews[0].independent_review = $false
    Set-SteinReviewTestManifest -Path $independence.manifest_path -Manifest $manifest
    $null = Invoke-SteinReviewTestCase -Fixture $independence -ExpectedExitCode 1
    $cases.Add("independent_review_required")

    $rawPath = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "raw-path") `
        -HostProductName "C:\Users\synthetic\private"
    $null = Invoke-SteinReviewTestCase -Fixture $rawPath -ExpectedExitCode 1
    $cases.Add("raw_local_path_rejected")

    $rawSid = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "raw-sid") `
        -HostProductName "S-1-5-21-111111-222222-333333-1001"
    $null = Invoke-SteinReviewTestCase -Fixture $rawSid -ExpectedExitCode 1
    $cases.Add("raw_sid_rejected")

    $rawHost = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "raw-host") `
        -HostProductName ([string]$env:COMPUTERNAME)
    $null = Invoke-SteinReviewTestCase -Fixture $rawHost -ExpectedExitCode 1
    $cases.Add("raw_host_rejected")

    $blocked = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "blocked") `
        -SourceStatuses @{ "P2-BUILD" = "blocked" }
    $blockedLedger = Invoke-SteinReviewTestCase `
        -Fixture $blocked `
        -ExpectedExitCode 2 `
        -ExpectOutput `
        -ExpectedGate "P2-BUILD" `
        -ExpectedGateStatus "blocked"
    if ([bool]$blockedLedger.complete_acceptance) {
        throw "A blocked source row produced complete acceptance."
    }
    $cases.Add("source_blocked_propagates")

    $failed = New-SteinReviewSyntheticFixture `
        -Root (Join-Path $testRoot "failed") `
        -SourceStatuses @{ "P2-BUILD" = "fail" }
    $failedLedger = Invoke-SteinReviewTestCase `
        -Fixture $failed `
        -ExpectedExitCode 1 `
        -ExpectOutput `
        -ExpectedGate "P2-BUILD" `
        -ExpectedGateStatus "fail"
    if ([bool]$failedLedger.complete_acceptance) {
        throw "A failed source row produced complete acceptance."
    }
    $cases.Add("source_fail_propagates")

    $notRun = New-SteinReviewSyntheticFixture -Root (Join-Path $testRoot "not-run")
    $manifest = Get-SteinReviewTestManifest -Path $notRun.manifest_path
    $manifest.reviews[0].disposition = "not_run"
    $manifest.reviews[0].native_fixture_attachment_id = $null
    $manifest.reviews[0].native_fixture_sha256 = $null
    $manifest.reviews[0].independent_review = $false
    $manifest.reviews[0].semantic_review_completed = $false
    $manifest.reviews[0].privacy_review_completed = $false
    Set-SteinReviewTestManifest -Path $notRun.manifest_path -Manifest $manifest
    $notRunLedger = Invoke-SteinReviewTestCase `
        -Fixture $notRun `
        -ExpectedExitCode 3 `
        -ExpectOutput `
        -ExpectedGate "P2-BUILD" `
        -ExpectedGateStatus "not_run"
    if ([bool]$notRunLedger.complete_acceptance) {
        throw "An unreviewed row produced complete acceptance."
    }
    $cases.Add("not_run_prevents_completion")

    $wrongAnchor = New-SteinReviewSyntheticFixture -Root (Join-Path $testRoot "wrong-anchor")
    $null = Invoke-SteinReviewTestCase `
        -Fixture $wrongAnchor `
        -ExpectedExitCode 1 `
        -RootAnchorSha256 ("0" * 64)
    $cases.Add("unpinned_root_anchor_rejected")

    [pscustomobject]@{
        verified = $true
        powershell_edition = [string]$PSVersionTable.PSEdition
        powershell_version = [string]$PSVersionTable.PSVersion
        exact_gate_count = $actualGates.Count
        frozen_baseline_incomplete = $true
        reviewer_runtime_source_swap_rejected = $true
        negative_case_count = $cases.Count
        cases = @($cases | ForEach-Object { $_ })
        installed_state_mutations = 0
    } | ConvertTo-Json -Compress -Depth 4
}
finally {
    if (Test-Path -LiteralPath $testRootCanonical) {
        if (-not $testRootCanonical.StartsWith(
                $artifactsPrefix,
                [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($testRootCanonical) -cnotmatch '^review-tests-[0-9a-f]{32}$') {
            throw "Refusing to remove an unverified reviewer test path."
        }
        Remove-Item -LiteralPath $testRootCanonical -Recurse -Force -ErrorAction SilentlyContinue
    }
}
