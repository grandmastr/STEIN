[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$libraryPath = Join-Path $PSScriptRoot 'Portable-Attestation.ps1'
if (-not (Test-Path -LiteralPath $libraryPath -PathType Leaf)) {
    throw 'The portable-attestation contract library is missing.'
}
. $libraryPath

function Copy-SteinPortableTestValue {
    param([Parameter(Mandatory = $true)] $Value)

    $json = $Value | ConvertTo-Json -Depth 30 -Compress
    $converter = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
    if ($converter.Parameters.ContainsKey('DateKind')) {
        return $json | ConvertFrom-Json -DateKind String -ErrorAction Stop
    }
    return $json | ConvertFrom-Json -ErrorAction Stop
}

function Assert-SteinPortableTestRejected {
    param(
        [Parameter(Mandatory = $true)][scriptblock] $Action,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    if (-not $rejected) {
        throw "The portable-attestation contract accepted $Description."
    }
}

$commit = 'f04f7b0fa08aa20fceea51babeb48653d489bf3d'
$tree = '859944fb3324f812c994dc397b4a6f218aa1f5cb'
$sourceRef = 'refs/heads/phase-2-completion'
$subjectSha256 = '059067aeaaf68d9ccf3a2fbf6e776a6c8b9303ef8600a212b59a20c555059410'
$workflowSha256 = '13ea21fbf6ef59b0558b4711e1d2f9f441d3c0d428190556b711e16948bdf286'
$cargoLockSha256 = 'b8f8e357fea07919cbbf3f8c66cf83ee0956973058fb3603438f4284af0d0879'
$rustToolchainSha256 = '8de87df201fa188e09f8ce58cb52466c745dbb7422ac962a5a85f0a75f185b5f'
$workflowIdentity =
    "https://github.com/grandmastr/STEIN/.github/workflows/portable-semantic.yml@$sourceRef"

$certificate = [pscustomobject][ordered]@{
    certificateIssuer = 'CN=sigstore-intermediate,O=sigstore.dev'
    subjectAlternativeName = $workflowIdentity
    issuer = 'https://token.actions.githubusercontent.com'
    githubWorkflowTrigger = 'workflow_dispatch'
    githubWorkflowSHA = $commit
    githubWorkflowName = 'portable-semantic-fixture'
    githubWorkflowRepository = 'grandmastr/STEIN'
    githubWorkflowRef = $sourceRef
    buildSignerURI = $workflowIdentity
    buildSignerDigest = $commit
    runnerEnvironment = 'github-hosted'
    sourceRepositoryURI = 'https://github.com/grandmastr/STEIN'
    sourceRepositoryDigest = $commit
    sourceRepositoryRef = $sourceRef
    sourceRepositoryIdentifier = '1335864815'
    sourceRepositoryOwnerURI = 'https://github.com/grandmastr'
    sourceRepositoryOwnerIdentifier = '24866656'
    buildConfigURI = $workflowIdentity
    buildConfigDigest = $commit
    buildTrigger = 'workflow_dispatch'
    runInvocationURI =
        'https://github.com/grandmastr/STEIN/actions/runs/32797206475/attempts/1'
    sourceRepositoryVisibilityAtSigning = 'public'
}
$verificationEntry = [pscustomobject][ordered]@{
    attestation = [pscustomobject][ordered]@{
        bundle = [pscustomobject][ordered]@{
            mediaType = 'application/vnd.dev.sigstore.bundle.v0.3+json'
            verificationMaterial = [pscustomobject]@{ content = 'synthetic' }
            dsseEnvelope = [pscustomobject]@{ content = 'synthetic' }
        }
        bundle_url = ''
        initiator = ''
    }
    verificationResult = [pscustomobject][ordered]@{
        mediaType = 'application/vnd.dev.sigstore.verificationresult+json;version=0.1'
        signature = [pscustomobject][ordered]@{ certificate = $certificate }
        verifiedTimestamps = @([pscustomobject][ordered]@{
                type = 'Tlog'
                uri = 'https://rekor.sigstore.dev'
                timestamp = '2026-08-25T02:23:27+01:00'
            })
        verifiedIdentity = [pscustomobject][ordered]@{
            subjectAlternativeName = [pscustomobject][ordered]@{
                subjectAlternativeName = $workflowIdentity
            }
            issuer = [pscustomobject][ordered]@{ issuer = ''; regexp = '.*' }
            runnerEnvironment = 'github-hosted'
        }
        statement = [pscustomobject][ordered]@{
            _type = 'https://in-toto.io/Statement/v1'
            subject = @([pscustomobject][ordered]@{
                    name = 'portable-fixture.json'
                    digest = [pscustomobject][ordered]@{ sha256 = $subjectSha256 }
                })
            predicateType = 'https://slsa.dev/provenance/v1'
            predicate = [pscustomobject]@{ buildDefinition = [pscustomobject]@{} }
        }
    }
}
$verification = @(Copy-SteinPortableTestValue -Value @($verificationEntry))
$verified = Assert-SteinPortableAttestationVerification `
    -VerificationResults $verification `
    -ExpectedCommit $commit `
    -ExpectedSourceRef $sourceRef `
    -ExpectedSubjectSha256 $subjectSha256
if ([string]$verified.CandidateCommit -cne $commit -or
    [string]$verified.SourceRef -cne $sourceRef -or
    [int]$verified.VerifiedTimestampCount -ne 1) {
    throw 'The portable attestation passing contract is invalid.'
}

$verificationMutations = @(
    @{ Name = 'an extra result property'; Apply = { param($v) $v[0] | Add-Member extra $true } },
    @{ Name = 'an extra verified attestation'; Apply = { param($v) return @($v[0], (Copy-SteinPortableTestValue $v[0])) } },
    @{ Name = 'a wrong bundle media type'; Apply = { param($v) $v[0].attestation.bundle.mediaType = 'wrong' } },
    @{ Name = 'a wrong verification media type'; Apply = { param($v) $v[0].verificationResult.mediaType = 'wrong' } },
    @{ Name = 'a wrong predicate'; Apply = { param($v) $v[0].verificationResult.statement.predicateType = 'wrong' } },
    @{ Name = 'an extra digest algorithm'; Apply = { param($v) $v[0].verificationResult.statement.subject[0].digest | Add-Member sha512 ('a' * 128) } },
    @{ Name = 'a wrong subject name'; Apply = { param($v) $v[0].verificationResult.statement.subject[0].name = 'other.json' } },
    @{ Name = 'a wrong subject digest'; Apply = { param($v) $v[0].verificationResult.statement.subject[0].digest.sha256 = ('a' * 64) } },
    @{ Name = 'no verified timestamp'; Apply = { param($v) $v[0].verificationResult.verifiedTimestamps = @() } },
    @{ Name = 'a wrong timestamp witness'; Apply = { param($v) $v[0].verificationResult.verifiedTimestamps[0].uri = 'https://example.test' } },
    @{ Name = 'a wrong OIDC issuer'; Apply = { param($v) $v[0].verificationResult.signature.certificate.issuer = 'wrong' } },
    @{ Name = 'a wrong repository'; Apply = { param($v) $v[0].verificationResult.signature.certificate.sourceRepositoryURI = 'https://github.com/grandmastr/OTHER' } },
    @{ Name = 'a wrong workflow'; Apply = { param($v) $v[0].verificationResult.signature.certificate.buildSignerURI = 'https://github.com/grandmastr/STEIN/.github/workflows/other.yml@refs/heads/phase-2-completion' } },
    @{ Name = 'a wrong ref'; Apply = { param($v) $v[0].verificationResult.signature.certificate.sourceRepositoryRef = 'refs/heads/main' } },
    @{ Name = 'a wrong source digest'; Apply = { param($v) $v[0].verificationResult.signature.certificate.sourceRepositoryDigest = ('a' * 40) } },
    @{ Name = 'a wrong signer digest'; Apply = { param($v) $v[0].verificationResult.signature.certificate.buildSignerDigest = ('a' * 40) } },
    @{ Name = 'a self-hosted runner'; Apply = { param($v) $v[0].verificationResult.signature.certificate.runnerEnvironment = 'self-hosted' } },
    @{ Name = 'a pull-request trigger'; Apply = { param($v) $v[0].verificationResult.signature.certificate.buildTrigger = 'pull_request' } },
    @{ Name = 'a wrong run URI'; Apply = { param($v) $v[0].verificationResult.signature.certificate.runInvocationURI = 'https://example.test' } }
)
$verificationNegativeCount = 0
$null = Assert-SteinPortableVerificationJsonDocument -Text "[{}]`n"
Assert-SteinPortableTestRejected `
    -Description 'a top-level verification object instead of an array' `
    -Action {
        $null = Assert-SteinPortableVerificationJsonDocument -Text "{}`n"
    }
$verificationNegativeCount++
foreach ($mutation in $verificationMutations) {
    $candidate = @(Copy-SteinPortableTestValue -Value $verification)
    $replacement = & $mutation.Apply $candidate
    if ($null -ne $replacement) { $candidate = @($replacement) }
    Assert-SteinPortableTestRejected -Description ([string]$mutation.Name) -Action {
        $null = Assert-SteinPortableAttestationVerification `
            -VerificationResults $candidate `
            -ExpectedCommit $commit `
            -ExpectedSourceRef $sourceRef `
            -ExpectedSubjectSha256 $subjectSha256
    }
    $verificationNegativeCount++
}
foreach ($invalidRef in @(
        'refs/pull/1/merge', 'refs/heads/a..b', 'refs/heads/a//b',
        'refs/heads/a.lock', 'refs/heads/a/')) {
    Assert-SteinPortableTestRejected -Description "the source ref $invalidRef" -Action {
        $null = Assert-SteinPortableSourceRef -SourceRef $invalidRef
    }
    $verificationNegativeCount++
}

$subchecks = New-Object Collections.Generic.List[object]
$index = 0
foreach ($entry in $script:SteinPortableCommands.GetEnumerator()) {
    $index++
    $subchecks.Add([pscustomobject][ordered]@{
            artifact = [pscustomobject][ordered]@{
                path = "logs/$([string]$entry.Key).log"
                sha256 = ('{0:x64}' -f $index)
                size_bytes = 100 + $index
            }
            command = [string]$entry.Value
            exit_code = 0
            id = [string]$entry.Key
            result = 'pass'
        })
}
$fixture = [pscustomobject][ordered]@{
    fixture_id = 'phase2-portable-semantic-v1'
    gate_id = 'P2-PORTABLE-FIXTURE'
    generated_at = '2026-08-25T01:23:18.452251Z'
    generator = [pscustomobject][ordered]@{
        workflow_path = '.github/workflows/portable-semantic.yml'
        workflow_sha256 = $workflowSha256
    }
    repository = [pscustomobject][ordered]@{
        clean_after = $true
        clean_before = $true
        commit = $commit
        tree = $tree
    }
    result = 'pass'
    runner_id = 'github-actions-ubuntu-portable-v1'
    schema_version = 1
    subchecks = $subchecks.ToArray()
    toolchain = [pscustomobject][ordered]@{
        cargo_lock_sha256 = $cargoLockSha256
        cargo_version = 'cargo 1.98.0 (797e8a9bc 2026-08-05)'
        rust_toolchain_sha256 = $rustToolchainSha256
        rustc_verbose = "rustc 1.98.0 (88d9e12ae 2026-08-18)`nbinary: rustc`ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea`ncommit-date: 2026-08-18`nhost: x86_64-unknown-linux-gnu`nrelease: 1.98.0`nLLVM version: 22.1.8`n"
    }
}
$fixture = Copy-SteinPortableTestValue -Value $fixture
$validatedFixture = Assert-SteinPortableFixture `
    -Fixture $fixture `
    -ExpectedCommit $commit `
    -ExpectedTree $tree `
    -ExpectedWorkflowSha256 $workflowSha256 `
    -ExpectedCargoLockSha256 $cargoLockSha256 `
    -ExpectedRustToolchainSha256 $rustToolchainSha256
if (@($validatedFixture.Artifacts).Count -ne 7) {
    throw 'The portable fixture passing contract is invalid.'
}

$fixtureMutations = @(
    @{ Name = 'an extra fixture property'; Apply = { param($v) $v | Add-Member extra $true } },
    @{ Name = 'a dirty pre-run tree'; Apply = { param($v) $v.repository.clean_before = $false } },
    @{ Name = 'a dirty post-run tree'; Apply = { param($v) $v.repository.clean_after = $false } },
    @{ Name = 'a wrong fixture commit'; Apply = { param($v) $v.repository.commit = ('a' * 40) } },
    @{ Name = 'a wrong fixture tree'; Apply = { param($v) $v.repository.tree = ('a' * 40) } },
    @{ Name = 'a wrong workflow path'; Apply = { param($v) $v.generator.workflow_path = 'other.yml' } },
    @{ Name = 'a wrong workflow hash'; Apply = { param($v) $v.generator.workflow_sha256 = ('a' * 64) } },
    @{ Name = 'a wrong Cargo lock hash'; Apply = { param($v) $v.toolchain.cargo_lock_sha256 = ('a' * 64) } },
    @{ Name = 'a wrong Rust toolchain hash'; Apply = { param($v) $v.toolchain.rust_toolchain_sha256 = ('a' * 64) } },
    @{ Name = 'a reordered subcheck'; Apply = { param($v) $swap = $v.subchecks[0]; $v.subchecks[0] = $v.subchecks[1]; $v.subchecks[1] = $swap } },
    @{ Name = 'a wrong subcheck command'; Apply = { param($v) $v.subchecks[0].command = 'cargo test' } },
    @{ Name = 'a failed subcheck'; Apply = { param($v) $v.subchecks[0].result = 'fail' } },
    @{ Name = 'a nonzero subcheck exit'; Apply = { param($v) $v.subchecks[0].exit_code = 1 } },
    @{ Name = 'a wrong log path'; Apply = { param($v) $v.subchecks[0].artifact.path = 'logs/other.log' } },
    @{ Name = 'an empty log'; Apply = { param($v) $v.subchecks[0].artifact.size_bytes = 0 } },
    @{ Name = 'an invalid log digest'; Apply = { param($v) $v.subchecks[0].artifact.sha256 = ('A' * 64) } },
    @{ Name = 'an extra subcheck'; Apply = { param($v) $v.subchecks = @($v.subchecks) + @($v.subchecks[0]) } }
)
$fixtureNegativeCount = 0
foreach ($mutation in $fixtureMutations) {
    $candidate = Copy-SteinPortableTestValue -Value $fixture
    & $mutation.Apply $candidate
    Assert-SteinPortableTestRejected -Description ([string]$mutation.Name) -Action {
        $null = Assert-SteinPortableFixture `
            -Fixture $candidate `
            -ExpectedCommit $commit `
            -ExpectedTree $tree `
            -ExpectedWorkflowSha256 $workflowSha256 `
            -ExpectedCargoLockSha256 $cargoLockSha256 `
            -ExpectedRustToolchainSha256 $rustToolchainSha256
    }
    $fixtureNegativeCount++
}

[pscustomobject]@{
    verified = $true
    attestation_negative_case_count = $verificationNegativeCount
    fixture_negative_case_count = $fixtureNegativeCount
    exact_subcheck_count = @($validatedFixture.Artifacts).Count
    authenticated_certificate_bound = $true
    verification_array_document_bound = $true
    workflow_controlled_predicate_not_trusted = $true
}
