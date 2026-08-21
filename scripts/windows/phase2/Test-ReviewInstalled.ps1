[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$reviewerPath = Join-Path $PSScriptRoot "Review-Installed.ps1"
$launcherPath = Join-Path $PSScriptRoot "Review-Installed.cmd"
$commonPath = Join-Path $PSScriptRoot "Common.ps1"
foreach ($requiredPath in @($reviewerPath, $launcherPath, $commonPath)) {
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
        "source_collector_declared_fail",
        "source_collector_declared_blocked",
        "screenshot_can_prove_gate = `$false",
        "collector_rows_rehashed = 32",
        "local_paths_retained = `$false",
        "user_sid_retained = `$false",
        "raw_host_retained = `$false",
        "installed_state_mutated = `$false",
        "complete_acceptance",
        "reviewer-generator.json",
        "root-anchor.json")) {
    if ($reviewerSource.IndexOf($requiredLiteral, [StringComparison]::Ordinal) -lt 0) {
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
        [switch] $DuplicateRowOutputArtifact
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

    $recordedAt = [DateTime]::UtcNow.AddMinutes(-1).ToString("o")
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
        release_identity_schema_version = 1
        install_record_schema_version = 2
        package_family_name = "STEIN.Synthetic_fixture"
        desktop_aumid = "STEIN.Synthetic_fixture!Desktop"
        broker_aumid = "STEIN.Synthetic_fixture!PrivateBroker"
        browser_producer_aumid = "STEIN.Synthetic_fixture!BrowserObservationProducer"
        msix_sha256 = ("4" * 64)
        core_sha256 = ("5" * 64)
        browser_host_sha256 = ("6" * 64)
        installed_payload_file_count = 8
        cli_sha256 = ("7" * 64)
    }
    $versions = [ordered]@{
        package_version = "2.0.0.0"
        runtime_build_id = "synthetic-build"
        protocol_version = 1
        release_identity_schema_version = 1
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
    foreach ($gateId in $expectedGates) {
        $leaf = $gateId.ToLowerInvariant() -replace "[^a-z0-9._-]", "-"
        $attachmentId = "fixture-$leaf"
        $fixtureRecord = [ordered]@{
            schema_version = 1
            fixture_id = $attachmentId
            gate_id = $gateId
            result = "pass"
            recorded_at_utc = $recordedAt
            command_id = "synthetic:$leaf"
            exit_code = 0
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
            declared_result = "pass"
            recorded_at_utc = $recordedAt
            sha256 = $nativeHash
            size = [long]$nativeItem.Length
            privacy_reviewed = $true
            synthetic_only = $true
            source_path_retained = $false
            file_copied = $false
            semantic_result_verified_by_harness = $false
            native_fixture = [ordered]@{
                schema_version = 1
                fixture_id = $attachmentId
                command_id = "synthetic:$leaf"
                exit_code = 0
                closed_content_free_schema_verified = $true
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
            throw "A valid reviewer case did not emit exactly one protected output."
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

    $positive = New-SteinReviewSyntheticFixture -Root (Join-Path $testRoot "positive")
    $positiveLedger = Invoke-SteinReviewTestCase `
        -Fixture $positive `
        -ExpectedExitCode 0 `
        -ExpectOutput
    if (-not [bool]$positiveLedger.complete_acceptance -or
        @($positiveLedger.rows | Where-Object { $_.status -cne "pass" }).Count -ne 0 -or
        [int]$positiveLedger.source_integrity.collector_rows_rehashed -ne 32 -or
        [int]$positiveLedger.source_integrity.collector_attachments_rehashed -ne 33) {
        throw "The positive reviewer fixture did not produce complete acceptance."
    }
    $positiveOutput = @(
        Get-ChildItem -LiteralPath $positive.output_root -Directory -Force)[0]
    $outputText = @(
        Get-ChildItem -LiteralPath $positiveOutput.FullName -File -Recurse -Force |
            ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 }
    ) -join "`n"
    if ($outputText -match '(?i)(?:[a-z]:[\\/]|S-1-[0-9]+(?:-[0-9]+){2,})') {
        throw "The content-minimized final bundle retained a local path or SID."
    }
    $cases.Add("positive_complete_acceptance")

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

    $independence = New-SteinReviewSyntheticFixture -Root (Join-Path $testRoot "independence")
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
        positive_complete_acceptance = $true
        negative_case_count = $cases.Count - 1
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
