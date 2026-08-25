Set-StrictMode -Version 3.0

$script:SteinPortableRepository = 'grandmastr/STEIN'
$script:SteinPortableRepositoryUri = 'https://github.com/grandmastr/STEIN'
$script:SteinPortableRepositoryIdentifier = '1335864815'
$script:SteinPortableRepositoryOwnerUri = 'https://github.com/grandmastr'
$script:SteinPortableRepositoryOwnerIdentifier = '24866656'
$script:SteinPortableWorkflowPath = '.github/workflows/portable-semantic.yml'
$script:SteinPortableWorkflowIdentity =
    'https://github.com/grandmastr/STEIN/.github/workflows/portable-semantic.yml'
$script:SteinPortablePredicateType = 'https://slsa.dev/provenance/v1'
$script:SteinPortableBundleMediaType =
    'application/vnd.dev.sigstore.bundle.v0.3+json'
$script:SteinPortableVerificationMediaType =
    'application/vnd.dev.sigstore.verificationresult+json;version=0.1'
$script:SteinPortableOidcIssuer = 'https://token.actions.githubusercontent.com'
$script:SteinPortableCommands = [ordered]@{
    rust_format = 'cargo fmt --all -- --check'
    portable_check = 'cargo check --locked --all-targets -p stein-core -p stein-protocol -p stein-ipc -p stein-model-openai -p stein-store-sqlite'
    portable_clippy = 'cargo clippy --locked --all-targets -p stein-core -p stein-protocol -p stein-ipc -p stein-model-openai -p stein-store-sqlite -- -D warnings'
    semantic_full_loop = 'cargo test --locked -p stein-core --lib second_mind::tests::full_loop_records_audited_delivery_and_ephemeral_correction -- --exact'
    semantic_outbox_recovery = 'cargo test --locked -p stein-core --lib second_mind::tests::unavailable_channel_queues_then_fresh_recovery_delivers_once -- --exact'
    semantic_restart_recovery = 'cargo test --locked -p stein-core --lib second_mind::tests::restart_recovery_requires_authorized_continuity_and_fresh_health -- --exact'
    portable_full_suite = 'cargo test --locked --all-targets -p stein-core -p stein-protocol -p stein-ipc -p stein-model-openai -p stein-store-sqlite'
}

function Assert-SteinPortableExactProperties {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string[]] $Expected,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if ($null -eq $Value -or $Value -is [string] -or $null -eq $Value.PSObject) {
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

function Assert-SteinPortableSourceRef {
    param([Parameter(Mandatory = $true)][string] $SourceRef)

    if ($SourceRef.Length -lt 12 -or $SourceRef.Length -gt 255 -or
        $SourceRef -cnotmatch '^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]*$' -or
        $SourceRef.Contains('//') -or $SourceRef.Contains('..') -or
        $SourceRef.EndsWith('/') -or $SourceRef.EndsWith('.') -or
        $SourceRef.EndsWith('.lock')) {
        throw 'portable_attestation_source_ref_invalid'
    }
    foreach ($segment in $SourceRef.Substring('refs/heads/'.Length).Split('/')) {
        if ([string]::IsNullOrWhiteSpace($segment) -or $segment -cin @('.', '..')) {
            throw 'portable_attestation_source_ref_invalid'
        }
    }
    return $SourceRef
}

function Assert-SteinPortableVerificationJsonDocument {
    param([Parameter(Mandatory = $true)][string] $Text)

    if ($Text.Length -lt 2 -or $Text.Length -gt 16777216) {
        throw 'portable_attestation_json_document_invalid'
    }
    $first = 0
    $last = $Text.Length - 1
    while ($first -le $last -and $Text[$first] -cin @(
            [char]0x20, [char]0x09, [char]0x0A, [char]0x0D)) {
        $first++
    }
    while ($last -ge $first -and $Text[$last] -cin @(
            [char]0x20, [char]0x09, [char]0x0A, [char]0x0D)) {
        $last--
    }
    if ($first -ge $last -or $Text[$first] -cne '[' -or
        $Text[$last] -cne ']') {
        throw 'portable_attestation_json_document_invalid'
    }
    return $true
}

function Assert-SteinPortableAttestationVerification {
    param(
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)][object[]] $VerificationResults,
        [Parameter(Mandatory = $true)][string] $ExpectedCommit,
        [Parameter(Mandatory = $true)][string] $ExpectedSourceRef,
        [Parameter(Mandatory = $true)][string] $ExpectedSubjectSha256
    )

    if ($ExpectedCommit -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        $ExpectedSubjectSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'portable_attestation_expected_binding_invalid'
    }
    $null = Assert-SteinPortableSourceRef -SourceRef $ExpectedSourceRef
    $normalizedResults = @(if ($VerificationResults.Count -eq 1 -and
                $VerificationResults[0] -is [Array]) {
            $VerificationResults[0] | ForEach-Object { $_ }
        }
        else {
            $VerificationResults | ForEach-Object { $_ }
        })
    if ($normalizedResults.Count -ne 1) {
        throw 'portable_attestation_result_count_invalid'
    }
    $entry = $normalizedResults[0]
    Assert-SteinPortableExactProperties -Value $entry `
        -Expected @('attestation', 'verificationResult') `
        -FailureCode 'portable_attestation_result_shape_invalid'
    Assert-SteinPortableExactProperties -Value $entry.attestation `
        -Expected @('bundle', 'bundle_url', 'initiator') `
        -FailureCode 'portable_attestation_result_shape_invalid'
    Assert-SteinPortableExactProperties -Value $entry.attestation.bundle `
        -Expected @('mediaType', 'verificationMaterial', 'dsseEnvelope') `
        -FailureCode 'portable_attestation_result_shape_invalid'
    if ([string]$entry.attestation.bundle.mediaType -cne
            $script:SteinPortableBundleMediaType -or
        [string]$entry.attestation.bundle_url -cne '' -or
        [string]$entry.attestation.initiator -cne '') {
        throw 'portable_attestation_bundle_binding_invalid'
    }

    $result = $entry.verificationResult
    Assert-SteinPortableExactProperties -Value $result `
        -Expected @(
            'mediaType', 'signature', 'verifiedTimestamps',
            'verifiedIdentity', 'statement') `
        -FailureCode 'portable_attestation_result_shape_invalid'
    if ([string]$result.mediaType -cne $script:SteinPortableVerificationMediaType) {
        throw 'portable_attestation_verification_media_type_invalid'
    }
    Assert-SteinPortableExactProperties -Value $result.signature `
        -Expected @('certificate') `
        -FailureCode 'portable_attestation_result_shape_invalid'
    Assert-SteinPortableExactProperties -Value $result.verifiedIdentity `
        -Expected @('subjectAlternativeName', 'issuer', 'runnerEnvironment') `
        -FailureCode 'portable_attestation_result_shape_invalid'
    Assert-SteinPortableExactProperties `
        -Value $result.verifiedIdentity.subjectAlternativeName `
        -Expected @('subjectAlternativeName') `
        -FailureCode 'portable_attestation_result_shape_invalid'
    Assert-SteinPortableExactProperties -Value $result.verifiedIdentity.issuer `
        -Expected @('issuer', 'regexp') `
        -FailureCode 'portable_attestation_result_shape_invalid'
    $workflowIdentity = "$($script:SteinPortableWorkflowIdentity)@$ExpectedSourceRef"
    if ([string]$result.verifiedIdentity.subjectAlternativeName.subjectAlternativeName -cne
            $workflowIdentity -or
        [string]$result.verifiedIdentity.issuer.issuer -cne '' -or
        [string]$result.verifiedIdentity.issuer.regexp -cne '.*' -or
        [string]$result.verifiedIdentity.runnerEnvironment -cne 'github-hosted') {
        throw 'portable_attestation_verified_identity_invalid'
    }

    $certificate = $result.signature.certificate
    Assert-SteinPortableExactProperties -Value $certificate `
        -Expected @(
            'certificateIssuer', 'subjectAlternativeName', 'issuer',
            'githubWorkflowTrigger', 'githubWorkflowSHA', 'githubWorkflowName',
            'githubWorkflowRepository', 'githubWorkflowRef', 'buildSignerURI',
            'buildSignerDigest', 'runnerEnvironment', 'sourceRepositoryURI',
            'sourceRepositoryDigest', 'sourceRepositoryRef',
            'sourceRepositoryIdentifier', 'sourceRepositoryOwnerURI',
            'sourceRepositoryOwnerIdentifier', 'buildConfigURI',
            'buildConfigDigest', 'buildTrigger', 'runInvocationURI',
            'sourceRepositoryVisibilityAtSigning') `
        -FailureCode 'portable_attestation_certificate_shape_invalid'
    if ([string]$certificate.certificateIssuer -cne
            'CN=sigstore-intermediate,O=sigstore.dev' -or
        [string]$certificate.subjectAlternativeName -cne $workflowIdentity -or
        [string]$certificate.issuer -cne $script:SteinPortableOidcIssuer -or
        [string]$certificate.githubWorkflowTrigger -cne 'workflow_dispatch' -or
        [string]$certificate.githubWorkflowSHA -cne $ExpectedCommit -or
        [string]$certificate.githubWorkflowName -cne 'portable-semantic-fixture' -or
        [string]$certificate.githubWorkflowRepository -cne
            $script:SteinPortableRepository -or
        [string]$certificate.githubWorkflowRef -cne $ExpectedSourceRef -or
        [string]$certificate.buildSignerURI -cne $workflowIdentity -or
        [string]$certificate.buildSignerDigest -cne $ExpectedCommit -or
        [string]$certificate.runnerEnvironment -cne 'github-hosted' -or
        [string]$certificate.sourceRepositoryURI -cne
            $script:SteinPortableRepositoryUri -or
        [string]$certificate.sourceRepositoryDigest -cne $ExpectedCommit -or
        [string]$certificate.sourceRepositoryRef -cne $ExpectedSourceRef -or
        [string]$certificate.sourceRepositoryIdentifier -cne
            $script:SteinPortableRepositoryIdentifier -or
        [string]$certificate.sourceRepositoryOwnerURI -cne
            $script:SteinPortableRepositoryOwnerUri -or
        [string]$certificate.sourceRepositoryOwnerIdentifier -cne
            $script:SteinPortableRepositoryOwnerIdentifier -or
        [string]$certificate.buildConfigURI -cne $workflowIdentity -or
        [string]$certificate.buildConfigDigest -cne $ExpectedCommit -or
        [string]$certificate.buildTrigger -cne 'workflow_dispatch' -or
        [string]$certificate.runInvocationURI -cnotmatch
            '^https://github\.com/grandmastr/STEIN/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*$' -or
        [string]$certificate.sourceRepositoryVisibilityAtSigning -cne 'public') {
        throw 'portable_attestation_certificate_binding_invalid'
    }

    $timestamps = @($result.verifiedTimestamps)
    if ($timestamps.Count -lt 1 -or $timestamps.Count -gt 8) {
        throw 'portable_attestation_timestamp_invalid'
    }
    $parsedTimestamps = New-Object Collections.Generic.List[DateTimeOffset]
    foreach ($timestamp in $timestamps) {
        Assert-SteinPortableExactProperties -Value $timestamp `
            -Expected @('type', 'uri', 'timestamp') `
            -FailureCode 'portable_attestation_timestamp_invalid'
        $parsedTimestamp = [DateTimeOffset]::MinValue
        if ([string]$timestamp.type -cne 'Tlog' -or
            [string]$timestamp.uri -cne 'https://rekor.sigstore.dev' -or
            -not [DateTimeOffset]::TryParse(
                [string]$timestamp.timestamp,
                [ref]$parsedTimestamp)) {
            throw 'portable_attestation_timestamp_invalid'
        }
        $parsedTimestamps.Add($parsedTimestamp)
    }
    $orderedTimestamps = @($parsedTimestamps.ToArray() | Sort-Object UtcDateTime)

    $statement = $result.statement
    Assert-SteinPortableExactProperties -Value $statement `
        -Expected @('_type', 'subject', 'predicateType', 'predicate') `
        -FailureCode 'portable_attestation_statement_shape_invalid'
    if ([string]$statement._type -cne 'https://in-toto.io/Statement/v1' -or
        [string]$statement.predicateType -cne $script:SteinPortablePredicateType -or
        $null -eq $statement.predicate) {
        throw 'portable_attestation_statement_binding_invalid'
    }
    $subjects = @($statement.subject)
    if ($subjects.Count -ne 1) {
        throw 'portable_attestation_subject_invalid'
    }
    Assert-SteinPortableExactProperties -Value $subjects[0] `
        -Expected @('name', 'digest') `
        -FailureCode 'portable_attestation_subject_invalid'
    Assert-SteinPortableExactProperties -Value $subjects[0].digest `
        -Expected @('sha256') `
        -FailureCode 'portable_attestation_subject_invalid'
    if ([string]$subjects[0].name -cne 'portable-fixture.json' -or
        [string]$subjects[0].digest.sha256 -cne $ExpectedSubjectSha256) {
        throw 'portable_attestation_subject_invalid'
    }

    return [pscustomobject]@{
        CandidateCommit = $ExpectedCommit
        SourceRef = $ExpectedSourceRef
        SubjectSha256 = $ExpectedSubjectSha256
        RunInvocationUri = [string]$certificate.runInvocationURI
        VerifiedTimestampCount = $timestamps.Count
        EarliestVerifiedTimestamp = $orderedTimestamps[0]
        LatestVerifiedTimestamp = $orderedTimestamps[$orderedTimestamps.Count - 1]
    }
}

function Assert-SteinPortableFixture {
    param(
        [Parameter(Mandatory = $true)] $Fixture,
        [Parameter(Mandatory = $true)][string] $ExpectedCommit,
        [Parameter(Mandatory = $true)][string] $ExpectedTree,
        [Parameter(Mandatory = $true)][string] $ExpectedWorkflowSha256,
        [Parameter(Mandatory = $true)][string] $ExpectedCargoLockSha256,
        [Parameter(Mandatory = $true)][string] $ExpectedRustToolchainSha256
    )

    foreach ($digest in @(
            $ExpectedWorkflowSha256,
            $ExpectedCargoLockSha256,
            $ExpectedRustToolchainSha256)) {
        if ($digest -cnotmatch '^[0-9a-f]{64}$') {
            throw 'portable_fixture_expected_binding_invalid'
        }
    }
    if ($ExpectedCommit -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        $ExpectedTree -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        $ExpectedCommit.Length -ne $ExpectedTree.Length) {
        throw 'portable_fixture_expected_binding_invalid'
    }
    Assert-SteinPortableExactProperties -Value $Fixture `
        -Expected @(
            'fixture_id', 'gate_id', 'generated_at', 'generator', 'repository',
            'result', 'runner_id', 'schema_version', 'subchecks', 'toolchain') `
        -FailureCode 'portable_fixture_shape_invalid'
    $generatedAt = [DateTimeOffset]::MinValue
    if (($Fixture.schema_version -isnot [int] -and
            $Fixture.schema_version -isnot [long]) -or
        [long]$Fixture.schema_version -ne 1 -or
        [string]$Fixture.gate_id -cne 'P2-PORTABLE-FIXTURE' -or
        [string]$Fixture.fixture_id -cne 'phase2-portable-semantic-v1' -or
        [string]$Fixture.runner_id -cne 'github-actions-ubuntu-portable-v1' -or
        [string]$Fixture.result -cne 'pass' -or
        [string]$Fixture.generated_at -cnotmatch
            '^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z$' -or
        -not [DateTimeOffset]::TryParse(
            [string]$Fixture.generated_at,
            [ref]$generatedAt)) {
        throw 'portable_fixture_binding_invalid'
    }
    Assert-SteinPortableExactProperties -Value $Fixture.generator `
        -Expected @('workflow_path', 'workflow_sha256') `
        -FailureCode 'portable_fixture_shape_invalid'
    Assert-SteinPortableExactProperties -Value $Fixture.repository `
        -Expected @('clean_after', 'clean_before', 'commit', 'tree') `
        -FailureCode 'portable_fixture_shape_invalid'
    Assert-SteinPortableExactProperties -Value $Fixture.toolchain `
        -Expected @(
            'cargo_lock_sha256', 'cargo_version', 'rust_toolchain_sha256',
            'rustc_verbose') `
        -FailureCode 'portable_fixture_shape_invalid'
    if ([string]$Fixture.generator.workflow_path -cne
            $script:SteinPortableWorkflowPath -or
        [string]$Fixture.generator.workflow_sha256 -cne
            $ExpectedWorkflowSha256 -or
        $Fixture.repository.clean_before -isnot [bool] -or
        $Fixture.repository.clean_after -isnot [bool] -or
        -not [bool]$Fixture.repository.clean_before -or
        -not [bool]$Fixture.repository.clean_after -or
        [string]$Fixture.repository.commit -cne $ExpectedCommit -or
        [string]$Fixture.repository.tree -cne $ExpectedTree -or
        [string]$Fixture.toolchain.cargo_lock_sha256 -cne
            $ExpectedCargoLockSha256 -or
        [string]$Fixture.toolchain.rust_toolchain_sha256 -cne
            $ExpectedRustToolchainSha256 -or
        [string]$Fixture.toolchain.cargo_version -cnotmatch
            '^cargo [0-9]+\.[0-9]+\.[0-9]+ \([0-9a-f]{9,40} 20[0-9]{2}-[0-9]{2}-[0-9]{2}\)$' -or
        [string]$Fixture.toolchain.rustc_verbose -notmatch
            '^rustc [0-9]+\.[0-9]+\.[0-9]+ ' -or
        [string]$Fixture.toolchain.rustc_verbose -notmatch
            '(?m)^host: x86_64-unknown-linux-gnu$' -or
        [string]$Fixture.toolchain.rustc_verbose -notmatch
            '(?m)^release: [0-9]+\.[0-9]+\.[0-9]+$' -or
        [string]$Fixture.toolchain.rustc_verbose -notmatch
            '(?m)^LLVM version: [0-9]+\.[0-9]+\.[0-9]+$' -or
        [string]$Fixture.toolchain.rustc_verbose.Length -gt 4096) {
        throw 'portable_fixture_binding_invalid'
    }

    $subchecks = @($Fixture.subchecks)
    $expectedIds = @($script:SteinPortableCommands.Keys)
    if ($subchecks.Count -ne $expectedIds.Count) {
        throw 'portable_fixture_subchecks_invalid'
    }
    $artifacts = New-Object Collections.Generic.List[object]
    for ($index = 0; $index -lt $expectedIds.Count; $index++) {
        $id = [string]$expectedIds[$index]
        $subcheck = $subchecks[$index]
        Assert-SteinPortableExactProperties -Value $subcheck `
            -Expected @('artifact', 'command', 'exit_code', 'id', 'result') `
            -FailureCode 'portable_fixture_subchecks_invalid'
        Assert-SteinPortableExactProperties -Value $subcheck.artifact `
            -Expected @('path', 'sha256', 'size_bytes') `
            -FailureCode 'portable_fixture_subchecks_invalid'
        if ([string]$subcheck.id -cne $id -or
            [string]$subcheck.command -cne
                [string]$script:SteinPortableCommands[$id] -or
            ($subcheck.exit_code -isnot [int] -and
                $subcheck.exit_code -isnot [long]) -or
            [long]$subcheck.exit_code -ne 0 -or
            [string]$subcheck.result -cne 'pass' -or
            [string]$subcheck.artifact.path -cne "logs/$id.log" -or
            ($subcheck.artifact.size_bytes -isnot [int] -and
                $subcheck.artifact.size_bytes -isnot [long]) -or
            [long]$subcheck.artifact.size_bytes -lt 1 -or
            [long]$subcheck.artifact.size_bytes -gt 16777216 -or
            [string]$subcheck.artifact.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'portable_fixture_subchecks_invalid'
        }
        $artifacts.Add([pscustomobject]@{
                Id = $id
                Path = [string]$subcheck.artifact.path
                Size = [long]$subcheck.artifact.size_bytes
                Sha256 = [string]$subcheck.artifact.sha256
            })
    }
    return [pscustomobject]@{
        CandidateCommit = $ExpectedCommit
        CandidateTree = $ExpectedTree
        GeneratedAt = $generatedAt
        Artifacts = $artifacts.ToArray()
    }
}
