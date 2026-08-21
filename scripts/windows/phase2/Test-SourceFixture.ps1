[CmdletBinding()]
param([switch] $FixtureTestLibraryOnly)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
. (Join-Path $PSScriptRoot "Run-Source-Fixture.ps1") -LibraryOnly

function Copy-SteinSourceFixtureTestObject {
    param([Parameter(Mandatory = $true)] $Value)

    return ($Value | ConvertTo-Json -Depth 40 -Compress) |
        ConvertFrom-Json -ErrorAction Stop
}

function Assert-SteinSourceFixtureTestRejected {
    param(
        [Parameter(Mandatory = $true)][scriptblock] $Action,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $rejected = $false
    try {
        & $Action
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "Source fixture contract accepted $Description."
    }
}

function New-SteinSourceFixtureSyntheticReceipt {
    param(
        [Parameter(Mandatory = $true)] $Fixture,
        [Parameter(Mandatory = $true)][string] $RegistrySha256,
        [string] $CandidateGitCommit = ("a" * 40),
        [string] $CandidateGitTree = ("b" * 40),
        [string] $RustupToolchain = "stable-x86_64-pc-windows-msvc",
        [string] $CargoLauncherSha256 = ("3" * 64),
        [string] $CargoResolvedSha256 = ("4" * 64),
        [string] $RustcLauncherSha256 = ("5" * 64),
        [string] $RustcResolvedSha256 = ("6" * 64),
        [string] $RustupVersion = "rustup 1.28.2 (synthetic)",
        [string] $RustupSha256 = ("8" * 64),
        [string] $GitLauncherVersion = "git version 2.51.0.windows.1",
        [string] $GitLauncherSha256 = ("9" * 64),
        [string] $GitResolvedVersion = "git version 2.51.0.windows.1",
        [string] $GitResolvedSha256 = ("0" * 64),
        $CandidateSnapshot
    )

    $emptyHash = Get-SteinSourceEvidenceTextSha256 -Value ""
    $executions = New-Object Collections.Generic.List[object]
    $executionIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $harnessIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $harnesses = New-Object Collections.Generic.List[object]
    $subchecks = New-Object Collections.Generic.List[object]
    $mappingCount = 0
    $cargoCount = 0
    $boundaryCount = 0
    foreach ($subcheck in @($Fixture.subchecks)) {
        $subcheckExecutionIds = New-Object Collections.Generic.List[string]
        foreach ($invocation in @($subcheck.invocations)) {
            $mappingCount++
            $executionId = Get-SteinSourceFixtureInvocationId -Invocation $invocation
            $subcheckExecutionIds.Add($executionId)
            if (-not $executionIds.Add($executionId)) {
                continue
            }
            $command = Get-SteinSourceFixtureCommand -Invocation $invocation
            if ([string]$invocation.kind -ceq "boundary") {
                $boundaryCount++
                $executions.Add([ordered]@{
                        execution_id = $executionId
                        sequence = $executions.Count + 1
                        kind = "boundary"
                        qualified_test_name = [string]$command.qualified_name
                        executable = "powershell.exe"
                        arguments = @($command.arguments)
                        working_directory = "."
                        nested_tool = [ordered]@{
                            executable = "resolved_cargo_payload"
                            sha256 = $CargoResolvedSha256
                            arguments = @(
                                "metadata", "--locked", "--no-deps",
                                "--format-version", "1", "--manifest-path",
                                "Cargo.toml")
                            working_directory =
                                "validated_config_free_system_directory"
                        }
                        execution = [ordered]@{
                            exit_code = 0
                            stdout = [ordered]@{ size = 0; sha256 = $emptyHash }
                            stderr = [ordered]@{ size = 0; sha256 = $emptyHash }
                            passed_checks = 4
                            failed_checks = 0
                        }
                    })
                continue
            }
            $cargoCount++
            $listCommand = Get-SteinSourceFixtureCommand `
                -Invocation $invocation `
                -ListOnly
            $harness = Get-SteinSourceFixtureHarnessDefinition -Invocation $invocation
            if ($harnessIds.Add([string]$harness.harness_id)) {
                $harnesses.Add([ordered]@{
                        harness_id = [string]$harness.harness_id
                        package = [string]$harness.package
                        target_kind = [string]$harness.target_kind
                        target_name = [string]$harness.target_name
                        manifest_path = [string]$harness.manifest_path
                        binary = [ordered]@{ size = 1; sha256 = "8" * 64 }
                        compile = [ordered]@{
                            executable = "cargo.exe"
                            arguments = @($harness.compile_arguments)
                            working_directory = "."
                            exit_code = 0
                            stdout = [ordered]@{ size = 0; sha256 = $emptyHash }
                            stderr = [ordered]@{ size = 0; sha256 = $emptyHash }
                            compiler_artifact_matches = 1
                        }
                    })
            }
            $executions.Add([ordered]@{
                    execution_id = $executionId
                    sequence = $executions.Count + 1
                    kind = "cargo_test"
                    qualified_test_name = [string]$command.qualified_name
                    harness_id = [string]$harness.harness_id
                    executable = "locked_test_binary"
                    registered_cargo_arguments = @($command.arguments)
                    arguments = @(
                        [string]$command.qualified_name, "--exact", "--test-threads=1")
                    working_directory = "."
                    preflight = [ordered]@{
                        exit_code = 0
                        arguments = @(
                            [string]$listCommand.qualified_name, "--exact", "--list")
                        stdout = [ordered]@{ size = 0; sha256 = $emptyHash }
                        stderr = [ordered]@{ size = 0; sha256 = $emptyHash }
                        exact_test_matches = 1
                    }
                    execution = [ordered]@{
                        exit_code = 0
                        stdout = [ordered]@{ size = 0; sha256 = $emptyHash }
                        stderr = [ordered]@{ size = 0; sha256 = $emptyHash }
                        passed_tests = 1
                        failed_tests = 0
                    }
                })
        }
        $subchecks.Add([ordered]@{
                id = [string]$subcheck.id
                result = "pass"
                execution_ids = @($subcheckExecutionIds | ForEach-Object { $_ })
            })
    }
    $candidateFilesByPath = @{}
    if ($null -ne $CandidateSnapshot) {
        foreach ($candidateFile in @($CandidateSnapshot.Files)) {
            $candidateFilesByPath[[string]$candidateFile.RelativePath] = $candidateFile
        }
    }
    $semanticSources = @($Fixture.semantic_source_paths | ForEach-Object {
            $semanticPath = [string]$_
            if ($null -ne $CandidateSnapshot) {
                if (-not $candidateFilesByPath.ContainsKey($semanticPath)) {
                    throw "The synthetic grounded receipt is missing a semantic source."
                }
                $candidatePath = Resolve-SteinPackageRegularFileUnderRoot `
                    -Root ([string]$CandidateSnapshot.Root) `
                    -Path (Join-Path ([string]$CandidateSnapshot.Root) (
                            $semanticPath.Replace(
                                '/',
                                [IO.Path]::DirectorySeparatorChar)))
                $candidateItem = Get-Item `
                    -LiteralPath $candidatePath `
                    -Force `
                    -ErrorAction Stop
                [ordered]@{
                    path = $semanticPath
                    size = [long]$candidateItem.Length
                    sha256 = Get-SteinSourceEvidenceSha256 -Path $candidatePath
                    git_blob_object_id =
                        [string]$candidateFilesByPath[$semanticPath].ObjectId
                }
            }
            else {
                [ordered]@{
                    path = $semanticPath
                    size = 1
                    sha256 = "1" * 64
                    git_blob_object_id = "a" * 40
                }
            }
        })
    $treeBinding = if ($null -ne $CandidateSnapshot) {
        Get-SteinSourceFixtureTreeBinding -Snapshot $CandidateSnapshot
    }
    else {
        [ordered]@{ file_count = 100; manifest_sha256 = "2" * 64 }
    }
    $compilerEnvironment = Get-SteinSourceFixtureCompilerEnvironmentRecord `
        -RustupToolchain $RustupToolchain `
        -PathSha256 ("b" * 64)
    $gitEnvironment = Get-SteinSourceFixtureGitEnvironmentRecord `
        -PathSha256 ("b" * 64)
    return [pscustomobject][ordered]@{
        schema_version = 1
        claim = "closed_source_fixture_only"
        source_check_id = [string]$Fixture.source_check_id
        source_fixture_id = [string]$Fixture.source_fixture_id
        source_runner_id = [string]$Fixture.source_runner_id
        gate_id = [string]$Fixture.gate_id
        gate_fixture_id = [string]$Fixture.gate_fixture_id
        gate_runner_id = [string]$Fixture.gate_runner_id
        result = "pass"
        bindings = [ordered]@{
            candidate_git_commit = $CandidateGitCommit
            candidate_git_tree = $CandidateGitTree
            candidate_tree_file_count = [long]$treeBinding.file_count
            candidate_tree_manifest_sha256 = [string]$treeBinding.manifest_sha256
            registry_sha256 = $RegistrySha256
            fixture_definition_sha256 = Get-SteinSourceEvidenceObjectDigest `
                -Value $Fixture
            semantic_source_manifest_sha256 = Get-SteinSourceEvidenceObjectDigest `
                -Value $semanticSources
            rustup_toolchain = $RustupToolchain
            rustup_version = $RustupVersion
            rustup_sha256 = $RustupSha256
            cargo_launcher_sha256 = $CargoLauncherSha256
            cargo_resolved_sha256 = $CargoResolvedSha256
            rustc_launcher_sha256 = $RustcLauncherSha256
            rustc_resolved_sha256 = $RustcResolvedSha256
            git_launcher_version = $GitLauncherVersion
            git_launcher_sha256 = $GitLauncherSha256
            git_resolved_version = $GitResolvedVersion
            git_resolved_sha256 = $GitResolvedSha256
            compiler_environment_sha256 = Get-SteinSourceEvidenceObjectDigest `
                -Value $compilerEnvironment
            git_environment_sha256 = Get-SteinSourceEvidenceObjectDigest `
                -Value $gitEnvironment
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
            effective_compiler_environment = $compilerEnvironment
            effective_git_environment = $gitEnvironment
        }
        semantic_sources = $semanticSources
        harnesses = @($harnesses | ForEach-Object { $_ })
        executions = @($executions | ForEach-Object { $_ })
        subchecks = @($subchecks | ForEach-Object { $_ })
        summary = [ordered]@{
            subcheck_count = @($Fixture.subchecks).Count
            harness_count = $harnesses.Count
            invocation_mapping_count = $mappingCount
            unique_execution_count = $executions.Count
            cargo_test_execution_count = $cargoCount
            boundary_execution_count = $boundaryCount
        }
    }
}

function New-SteinSourceFixtureSyntheticSuiteArtifacts {
    param(
        [Parameter(Mandatory = $true)] $Registry,
        [Parameter(Mandatory = $true)][string] $RegistrySha256,
        [Parameter(Mandatory = $true)][string] $OutputDirectory,
        [Parameter(Mandatory = $true)][string] $CandidateGitCommit,
        [Parameter(Mandatory = $true)][string] $CandidateGitTree,
        [Parameter(Mandatory = $true)][string] $RustupToolchain,
        [Parameter(Mandatory = $true)][string] $CargoLauncherSha256,
        [Parameter(Mandatory = $true)][string] $CargoResolvedSha256,
        [Parameter(Mandatory = $true)][string] $RustcLauncherSha256,
        [Parameter(Mandatory = $true)][string] $RustcResolvedSha256,
        [string] $RustupVersion = "rustup 1.28.2 (synthetic)",
        [string] $RustupSha256 = ("8" * 64),
        [Parameter(Mandatory = $true)][string] $GitLauncherVersion,
        [Parameter(Mandatory = $true)][string] $GitLauncherSha256,
        [Parameter(Mandatory = $true)][string] $GitResolvedVersion,
        [Parameter(Mandatory = $true)][string] $GitResolvedSha256,
        $CandidateSnapshot
    )

    if (Test-Path -LiteralPath $OutputDirectory) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force).Count -ne 0) {
            throw "The synthetic source-fixture output directory is not empty."
        }
    }
    else {
        $null = New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop
    }
    $records = New-Object Collections.Generic.List[object]
    foreach ($fixture in @($Registry.fixtures)) {
        $receipt = New-SteinSourceFixtureSyntheticReceipt `
            -Fixture $fixture `
            -RegistrySha256 $RegistrySha256 `
            -CandidateGitCommit $CandidateGitCommit `
            -CandidateGitTree $CandidateGitTree `
            -RustupToolchain $RustupToolchain `
            -CargoLauncherSha256 $CargoLauncherSha256 `
            -CargoResolvedSha256 $CargoResolvedSha256 `
            -RustcLauncherSha256 $RustcLauncherSha256 `
            -RustcResolvedSha256 $RustcResolvedSha256 `
            -RustupVersion $RustupVersion `
            -RustupSha256 $RustupSha256 `
            -GitLauncherVersion $GitLauncherVersion `
            -GitLauncherSha256 $GitLauncherSha256 `
            -GitResolvedVersion $GitResolvedVersion `
            -GitResolvedSha256 $GitResolvedSha256 `
            -CandidateSnapshot $CandidateSnapshot
        $name = "$([string]$fixture.source_check_id).receipt.json"
        $file = Write-SteinSourceFixtureJsonNew `
            -Path (Join-Path $OutputDirectory $name) `
            -Value $receipt `
            -Depth 40
        $records.Add([pscustomobject]@{
                Fixture = $fixture
                Receipt = $receipt
                Name = $name
                Size = [long]$file.size
                Sha256 = [string]$file.sha256
            })
    }
    $index = [ordered]@{
        schema_version = 1
        suite_id = "stein.phase2.source-fixture-suite.v1"
        result = "pass"
        candidate_git_commit = $CandidateGitCommit
        candidate_git_tree = $CandidateGitTree
        registry_sha256 = $RegistrySha256
        git = [ordered]@{
            launcher_version = $GitLauncherVersion
            launcher_sha256 = $GitLauncherSha256
            resolved_version = $GitResolvedVersion
            resolved_sha256 = $GitResolvedSha256
        }
        rustup = [ordered]@{
            version = $RustupVersion
            sha256 = $RustupSha256
            toolchain = $RustupToolchain
        }
        receipts = @($records | ForEach-Object {
                [ordered]@{
                    source_check_id = [string]$_.Fixture.source_check_id
                    source_fixture_id = [string]$_.Fixture.source_fixture_id
                    source_runner_id = [string]$_.Fixture.source_runner_id
                    gate_id = [string]$_.Fixture.gate_id
                    gate_fixture_id = [string]$_.Fixture.gate_fixture_id
                    gate_runner_id = [string]$_.Fixture.gate_runner_id
                    path = [string]$_.Name
                    size = [long]$_.Size
                    sha256 = [string]$_.Sha256
                }
            })
    }
    $indexFile = Write-SteinSourceFixtureJsonNew `
        -Path (Join-Path $OutputDirectory "index.json") `
        -Value $index `
        -Depth 16
    return [pscustomobject]@{
        Records = @($records | ForEach-Object { $_ })
        Index = $index
        IndexSize = [long]$indexFile.size
        IndexSha256 = [string]$indexFile.sha256
    }
}

if ($FixtureTestLibraryOnly) {
    return
}

$bootstrapRecords = @(Assert-SteinSourceFixtureBootstrapSourcesStable)
$bootstrapRoles = @($bootstrapRecords | ForEach-Object { [string]$_.role })
$expectedBootstrapRoles = @(
    'evidence-contract', 'package-tools', 'runner', 'source-evidence')
if ($bootstrapRecords.Count -ne 4 -or
    @(Compare-Object `
        -ReferenceObject $expectedBootstrapRoles `
        -DifferenceObject $bootstrapRoles `
        -CaseSensitive).Count -ne 0) {
    throw "The source fixture bootstrap dependency set is not exact."
}
$originalBootstrapRole = [string]$script:SteinSourceFixtureBootstrapBindings[0].record.role
try {
    $script:SteinSourceFixtureBootstrapBindings[0].record.role = 'unrelated-source'
    Assert-SteinSourceFixtureTestRejected `
        -Description "a substituted bootstrap dependency role" `
        -Action { Assert-SteinSourceFixtureBootstrapSourcesStable }
}
finally {
    $script:SteinSourceFixtureBootstrapBindings[0].record.role = $originalBootstrapRole
}
$null = Assert-SteinSourceFixtureBootstrapSourcesStable

$registryPath = Join-Path $PSScriptRoot "Source-Fixture-Registry.json"
$registryRead = Read-SteinSourceFixtureLockedJson `
    -Path $registryPath `
    -MaximumBytes 1048576
if ([string]$registryRead.sha256 -cne
    $script:SteinSourceFixtureRegistrySha256) {
    throw "The source fixture registry differs from its frozen digest."
}
$null = Assert-SteinSourceFixtureRegistry -Registry $registryRead.value
$fixtures = @($registryRead.value.fixtures)
$expectedDefinitions = Get-SteinSourceFixtureExpectedDefinitions
if ($fixtures.Count -ne 13 -or $expectedDefinitions.Count -ne 13) {
    throw "The source fixture registry does not expose the closed fixture set."
}

$mappingCount = 0
$uniqueExecutionCount = 0
$globalUniqueExecutions = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
foreach ($fixture in $fixtures) {
    $unique = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($subcheck in @($fixture.subchecks)) {
        foreach ($invocation in @($subcheck.invocations)) {
            $mappingCount++
            $invocationId = Get-SteinSourceFixtureInvocationId -Invocation $invocation
            $null = $unique.Add($invocationId)
            $null = $globalUniqueExecutions.Add($invocationId)
            $execution = Get-SteinSourceFixtureCommand -Invocation $invocation
            if ([string]$execution.working_directory -cne "." -or
                [string]$execution.arguments[0] -cne
                    $(if ([string]$invocation.kind -ceq "boundary") {
                            "-NoLogo"
                        }
                        else { "test" })) {
                throw "A source fixture command is not closed."
            }
            if ([string]$invocation.kind -cne "boundary") {
                $list = Get-SteinSourceFixtureCommand -Invocation $invocation -ListOnly
                if ([string]$list.executable -cne "cargo.exe" -or
                    [string]$list.arguments[-1] -cne "--list" -or
                    [string]$execution.arguments[-1] -cne "--test-threads=1") {
                    throw "A source fixture Cargo command is not exact."
                }
            }
        }
    }
    $uniqueExecutionCount += $unique.Count
}
if (@($fixtures.subchecks).Count -ne 71 -or
    $mappingCount -ne 140 -or
    $uniqueExecutionCount -ne 117 -or
    $globalUniqueExecutions.Count -ne 107) {
    throw "The source fixture registry does not exercise deduplicated mappings."
}

$null = Assert-SteinSourceFixtureListOutput `
    -QualifiedName "module::tests::exact_test" `
    -StandardOutput "module::tests::exact_test: test`r`n`r`n1 test, 0 benchmarks`r`n"
$null = Assert-SteinSourceFixtureExecutionOutput `
    -QualifiedName "module::tests::exact_test" `
    -StandardOutput @"
running 1 test
test module::tests::exact_test ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
"@
Assert-SteinSourceFixtureTestRejected `
    -Description "a zero-match test list" `
    -Action {
        Assert-SteinSourceFixtureListOutput `
            -QualifiedName "module::tests::exact_test" `
            -StandardOutput "0 tests, 0 benchmarks"
    }
Assert-SteinSourceFixtureTestRejected `
    -Description "a duplicate-match test list" `
    -Action {
        Assert-SteinSourceFixtureListOutput `
            -QualifiedName "module::tests::exact_test" `
            -StandardOutput "module::tests::exact_test: test`nmodule::tests::exact_test: test`n1 test, 0 benchmarks"
    }
Assert-SteinSourceFixtureTestRejected `
    -Description "a zero-pass execution" `
    -Action {
        Assert-SteinSourceFixtureExecutionOutput `
            -QualifiedName "module::tests::exact_test" `
            -StandardOutput "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s"
    }

$hostileRegistryCases = @(
    [pscustomobject]@{ description = "an extra registry property"; mutate = {
            param($value); $value | Add-Member -NotePropertyName extra -NotePropertyValue $true
        } },
    [pscustomobject]@{ description = "fixture reordering"; mutate = {
            param($value); $first = $value.fixtures[0]; $value.fixtures[0] = $value.fixtures[1]; $value.fixtures[1] = $first
        } },
    [pscustomobject]@{ description = "an unsafe semantic path"; mutate = {
            param($value); $value.fixtures[0].semantic_source_paths[0] = "../Cargo.lock"
        } },
    [pscustomobject]@{ description = "subcheck reordering"; mutate = {
            param($value); $first = $value.fixtures[0].subchecks[0]; $value.fixtures[0].subchecks[0] = $value.fixtures[0].subchecks[1]; $value.fixtures[0].subchecks[1] = $first
        } },
    [pscustomobject]@{ description = "an empty invocation list"; mutate = {
            param($value); $value.fixtures[0].subchecks[0].invocations = @()
        } },
    [pscustomobject]@{ description = "a foreign installed gate identity"; mutate = {
            param($value); $value.fixtures[0].gate_id = "P2-BUILD"
        } },
    [pscustomobject]@{ description = "a boundary invocation outside its closed mapping"; mutate = {
            param($value); $value.fixtures[0].subchecks[0].invocations[0].kind = "boundary"; $value.fixtures[0].subchecks[0].invocations[0].module = "boundary"; $value.fixtures[0].subchecks[0].invocations[0].test = "boundary_contract"
        } })
foreach ($case in $hostileRegistryCases) {
    $hostile = Copy-SteinSourceFixtureTestObject -Value $registryRead.value
    & $case.mutate $hostile
    Assert-SteinSourceFixtureTestRejected `
        -Description ([string]$case.description) `
        -Action { Assert-SteinSourceFixtureRegistry -Registry $hostile }
}
$unrelatedTestRegistry = Copy-SteinSourceFixtureTestObject -Value $registryRead.value
$unrelatedTestRegistry.fixtures[0].subchecks[0].invocations[0].test =
    [string]$registryRead.value.fixtures[0].subchecks[0].invocations[1].test
$null = Assert-SteinSourceFixtureRegistry -Registry $unrelatedTestRegistry
$unrelatedTestRegistryDigest = Get-SteinSourceEvidenceTextSha256 `
    -Value ($unrelatedTestRegistry | ConvertTo-Json -Depth 40 -Compress)
if ($unrelatedTestRegistryDigest -ceq $script:SteinSourceFixtureRegistrySha256) {
    throw "An unrelated-test registry substitution retained the frozen digest."
}

$syntheticFixture = $fixtures[0]
$syntheticReceipt = New-SteinSourceFixtureSyntheticReceipt `
    -Fixture $syntheticFixture `
    -RegistrySha256 ([string]$registryRead.sha256)
$null = Assert-SteinSourceFixtureReceipt `
    -Receipt $syntheticReceipt `
    -Fixture $syntheticFixture `
    -ExpectedRegistrySha256 ([string]$registryRead.sha256) `
    -ExpectedCommit ("a" * 40) `
    -ExpectedTree ("b" * 40) `
    -ExpectedTreeFileCount 100 `
    -ExpectedTreeManifestSha256 ("2" * 64) `
    -ExpectedSemanticManifestSha256 ([string]$syntheticReceipt.bindings.semantic_source_manifest_sha256) `
    -ExpectedCargoLauncherSha256 ("3" * 64) `
    -ExpectedCargoResolvedSha256 ("4" * 64) `
    -ExpectedRustcLauncherSha256 ("5" * 64) `
    -ExpectedRustcResolvedSha256 ("6" * 64) `
    -ExpectedRustupToolchain "stable-x86_64-pc-windows-msvc" `
    -ExpectedGitLauncherVersion "git version 2.51.0.windows.1" `
    -ExpectedGitLauncherSha256 ("9" * 64) `
    -ExpectedGitResolvedVersion "git version 2.51.0.windows.1" `
    -ExpectedGitResolvedSha256 ("0" * 64) `
    -ExpectedCompilerEnvironmentSha256 `
        ([string]$syntheticReceipt.bindings.compiler_environment_sha256)

$hostileReceiptCases = @(
    [pscustomobject]@{ description = "a receipt gate substitution"; mutate = {
            param($value); $value.gate_id = "P2-BUILD"
        } },
    [pscustomobject]@{ description = "a zero-match receipt"; mutate = {
            param($value); $value.executions[0].preflight.exact_test_matches = 0
        } },
    [pscustomobject]@{ description = "a zero-pass receipt"; mutate = {
            param($value); $value.executions[0].execution.passed_tests = 0
        } },
    [pscustomobject]@{ description = "a reordered receipt subcheck"; mutate = {
            param($value); $first = $value.subchecks[0]; $value.subchecks[0] = $value.subchecks[1]; $value.subchecks[1] = $first
        } },
    [pscustomobject]@{ description = "a changed exact argument"; mutate = {
            param($value); $value.executions[0].arguments[1] = "--offline"
        } },
    [pscustomobject]@{ description = "a hostile semantic path"; mutate = {
            param($value); $value.semantic_sources[0].path = "../Cargo.lock"
        } },
    [pscustomobject]@{ description = "a Git launcher/payload mismatch"; mutate = {
            param($value); $value.bindings.git_resolved_version = "git version 0.0.0"
        } },
    [pscustomobject]@{ description = "a compiler-environment mutation"; mutate = {
            param($value); $value.environment.effective_compiler_environment.RUSTFLAGS = "-Ctarget-cpu=native"
        } },
    [pscustomobject]@{ description = "a nonempty private Cargo home precondition"; mutate = {
            param($value); $value.environment.cargo_home_initial_entry_count = 1
        } },
    [pscustomobject]@{ description = "a duplicate execution"; mutate = {
            param($value); $value.executions += $value.executions[0]
        } })
foreach ($case in $hostileReceiptCases) {
    $hostile = Copy-SteinSourceFixtureTestObject -Value $syntheticReceipt
    & $case.mutate $hostile
    Assert-SteinSourceFixtureTestRejected `
        -Description ([string]$case.description) `
        -Action {
            Assert-SteinSourceFixtureReceipt `
                -Receipt $hostile `
                -Fixture $syntheticFixture `
                -ExpectedRegistrySha256 ([string]$registryRead.sha256)
        }
}

$indexReceipts = @($fixtures | ForEach-Object {
        [ordered]@{
            source_check_id = [string]$_.source_check_id
            source_fixture_id = [string]$_.source_fixture_id
            source_runner_id = [string]$_.source_runner_id
            gate_id = [string]$_.gate_id
            gate_fixture_id = [string]$_.gate_fixture_id
            gate_runner_id = [string]$_.gate_runner_id
            path = "$([string]$_.source_check_id).receipt.json"
            size = 1
            sha256 = "7" * 64
        }
    })
$syntheticIndex = [pscustomobject][ordered]@{
    schema_version = 1
    suite_id = "stein.phase2.source-fixture-suite.v1"
    result = "pass"
    candidate_git_commit = "a" * 40
    candidate_git_tree = "b" * 40
    registry_sha256 = [string]$registryRead.sha256
    git = [ordered]@{
        launcher_version = "git version 2.51.0.windows.1"
        launcher_sha256 = "9" * 64
        resolved_version = "git version 2.51.0.windows.1"
        resolved_sha256 = "0" * 64
    }
    rustup = [ordered]@{
        version = "rustup 1.28.2 (synthetic)"
        sha256 = "8" * 64
        toolchain = "stable-x86_64-pc-windows-msvc"
    }
    receipts = $indexReceipts
}
$null = Assert-SteinSourceFixtureIndex `
    -Index $syntheticIndex `
    -Registry $registryRead.value `
    -ExpectedRegistrySha256 ([string]$registryRead.sha256) `
    -ExpectedCommit ("a" * 40) `
    -ExpectedTree ("b" * 40) `
    -ExpectedGitLauncherVersion "git version 2.51.0.windows.1" `
    -ExpectedGitLauncherSha256 ("9" * 64) `
    -ExpectedGitResolvedVersion "git version 2.51.0.windows.1" `
    -ExpectedGitResolvedSha256 ("0" * 64)
$hostileIndex = Copy-SteinSourceFixtureTestObject -Value $syntheticIndex
$hostileIndex.receipts[0].path = "../receipt.json"
Assert-SteinSourceFixtureTestRejected `
    -Description "a hostile receipt-index path" `
    -Action {
        Assert-SteinSourceFixtureIndex `
            -Index $hostileIndex `
            -Registry $registryRead.value `
            -ExpectedRegistrySha256 ([string]$registryRead.sha256)
    }
$hostileGitIndex = Copy-SteinSourceFixtureTestObject -Value $syntheticIndex
$hostileGitIndex.git.resolved_sha256 = "f" * 64
Assert-SteinSourceFixtureTestRejected `
    -Description "a receipt-index Git payload mismatch" `
    -Action {
        Assert-SteinSourceFixtureIndex `
            -Index $hostileGitIndex `
            -Registry $registryRead.value `
            -ExpectedRegistrySha256 ([string]$registryRead.sha256) `
            -ExpectedGitResolvedSha256 ("0" * 64)
    }

$scratch = $null
$snapshotLocks = $null
try {
    $scratch = New-SteinPackagePrivateTemporaryDirectory -Purpose "build"
    $bootstrapProbeRoot = Join-Path $scratch 'bootstrap-lock-probe'
    $null = New-Item -ItemType Directory -Path $bootstrapProbeRoot -ErrorAction Stop
    $bootstrapProbePath = Join-Path $bootstrapProbeRoot 'source.ps1'
    $bootstrapReplacementPath = Join-Path $bootstrapProbeRoot 'replacement.ps1'
    [IO.File]::WriteAllText($bootstrapProbePath, 'locked-source-fixture-bootstrap')
    [IO.File]::WriteAllText($bootstrapReplacementPath, 'replacement-source-fixture-bootstrap')
    $bootstrapProbeBinding = Open-SteinSourceFixtureBootstrapBinding `
        -Role 'lock-probe' `
        -Path $bootstrapProbePath `
        -RepositoryRoot $bootstrapProbeRoot
    try {
        Assert-SteinSourceFixtureTestRejected `
            -Description 'a write to a retained source-fixture bootstrap input' `
            -Action {
                [IO.File]::WriteAllText($bootstrapProbePath, 'mutated-source-fixture-bootstrap')
            }
        Assert-SteinSourceFixtureTestRejected `
            -Description 'a replacement of a retained source-fixture bootstrap input' `
            -Action {
                Move-Item `
                    -LiteralPath $bootstrapReplacementPath `
                    -Destination $bootstrapProbePath `
                    -Force `
                    -ErrorAction Stop
            }
        if ((Get-SteinSourceFixtureBootstrapStreamSha256 `
                    -Stream $bootstrapProbeBinding.stream `
                    -FailureCode 'source_fixture_bootstrap_source_changed') -cne
                [string]$bootstrapProbeBinding.record.sha256) {
            throw 'The retained source-fixture bootstrap stream changed.'
        }
    }
    finally {
        $bootstrapProbeBinding.stream.Dispose()
    }
    $closedEnvironment = @{}
    foreach ($environmentName in @(Get-SteinSourceFixtureCompilerEnvironmentNames)) {
        $closedEnvironment[$environmentName] = $null
    }
    $null = Assert-SteinSourceFixtureCompilerOverridesAbsent `
        -Environment $closedEnvironment
    $hostileCompilerEnvironment = @{}
    foreach ($environmentName in $closedEnvironment.Keys) {
        $hostileCompilerEnvironment[$environmentName] = $closedEnvironment[$environmentName]
    }
    $hostileCompilerEnvironment["RUSTFLAGS"] = "-Ctarget-cpu=native"
    Assert-SteinSourceFixtureTestRejected `
        -Description "a hostile compiler override" `
        -Action {
            Assert-SteinSourceFixtureCompilerOverridesAbsent `
                -Environment $hostileCompilerEnvironment
        }
    foreach ($mixedCaseOverride in @(
            [pscustomobject]@{ name = 'rustflags'; value = '-Copt-level=0' },
            [pscustomobject]@{ name = 'CaRgO_BuIlD_RuStC_WrApPeR'; value = 'hostile.exe' },
            [pscustomobject]@{ name = 'git_dir'; value = 'C:\hostile.git' },
            [pscustomobject]@{ name = 'cC'; value = 'hostile-cl.exe' })) {
        $mixedCaseEnvironment = [Collections.Hashtable]::new(
            [StringComparer]::Ordinal)
        $mixedCaseEnvironment[[string]$mixedCaseOverride.name] =
            [string]$mixedCaseOverride.value
        Assert-SteinSourceFixtureTestRejected `
            -Description "a mixed-case compiler or Git override" `
            -Action {
                Assert-SteinSourceFixtureCompilerOverridesAbsent `
                    -Environment $mixedCaseEnvironment
            }
    }
    $hostileCargoHome = Join-Path $scratch "hostile-cargo-home"
    $null = New-Item -ItemType Directory -Path $hostileCargoHome -ErrorAction Stop
    [IO.File]::WriteAllText(
        (Join-Path $hostileCargoHome "config.toml"),
        "[build]`nrustc-wrapper='hostile.exe'`n",
        [Text.UTF8Encoding]::new($false))
    $isolatedCargoHome = New-SteinSourceFixturePrivateCargoHome -BuildRoot $scratch
    if ([string]::Equals(
            $hostileCargoHome,
            $isolatedCargoHome,
            [StringComparison]::OrdinalIgnoreCase) -or
        @(Get-ChildItem -LiteralPath $isolatedCargoHome -Force).Count -ne 0) {
        throw "The source fixture runner did not isolate a hostile Cargo config."
    }
    $candidateConfigRoot = Join-Path $scratch "candidate-config-poison"
    $candidateCargoDirectory = Join-Path $candidateConfigRoot ".cargo"
    $null = New-Item `
        -ItemType Directory `
        -Path $candidateCargoDirectory `
        -Force `
        -ErrorAction Stop
    [IO.File]::WriteAllText(
        (Join-Path $candidateCargoDirectory "config.toml"),
        "[build]`nrustc-wrapper='hostile.exe'`n",
        [Text.UTF8Encoding]::new($false))
    Assert-SteinSourceFixtureTestRejected `
        -Description "a candidate Cargo config" `
        -Action {
            Assert-SteinSourceFixtureCargoConfigAbsent `
                -StartPaths @($candidateConfigRoot)
        }
    $ancestorConfigRoot = Join-Path $scratch "ancestor-config-poison"
    $ancestorCargoDirectory = Join-Path $ancestorConfigRoot ".cargo"
    $ancestorNestedDirectory = Join-Path $ancestorConfigRoot "nested\candidate"
    $null = New-Item -ItemType Directory -Path $ancestorCargoDirectory `
        -Force -ErrorAction Stop
    $null = New-Item -ItemType Directory -Path $ancestorNestedDirectory `
        -Force -ErrorAction Stop
    [IO.File]::WriteAllText(
        (Join-Path $ancestorCargoDirectory "config"),
        "[build]`nrustflags=['--cfg','hostile']`n",
        [Text.UTF8Encoding]::new($false))
    Assert-SteinSourceFixtureTestRejected `
        -Description "an ancestor Cargo config" `
        -Action {
            Assert-SteinSourceFixtureCargoConfigAbsent `
                -StartPaths @($ancestorNestedDirectory)
        }

    $jsonPath = Join-Path $scratch "receipt.json"
    $jsonFile = Write-SteinSourceFixtureJsonNew `
        -Path $jsonPath `
        -Value ([ordered]@{ schema_version = 1; result = "pass" })
    [IO.File]::WriteAllText(
        $jsonPath,
        '{"schema_version":1,"result":"fail"}',
        [Text.UTF8Encoding]::new($false))
    Assert-SteinSourceFixtureTestRejected `
        -Description "a receipt changed after capture" `
        -Action {
            Assert-SteinSourceFixtureFileStable `
                -Path $jsonPath `
                -ExpectedSize ([long]$jsonFile.size) `
                -ExpectedSha256 ([string]$jsonFile.sha256)
        }

    $invalidUtf8Path = Join-Path $scratch "invalid.json"
    [IO.File]::WriteAllBytes($invalidUtf8Path, [byte[]]@(0x7b, 0xff, 0x7d))
    Assert-SteinSourceFixtureTestRejected `
        -Description "invalid UTF-8 JSON" `
        -Action { Read-SteinSourceFixtureLockedJson -Path $invalidUtf8Path }

    $compilerSnapshot = Join-Path $scratch "compiler-snapshot"
    $compilerManifest = Join-Path $compilerSnapshot `
        "crates\stein-store-sqlite\Cargo.toml"
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $compilerManifest) `
        -Force -ErrorAction Stop
    [IO.File]::WriteAllText(
        $compilerManifest,
        "[package]`nname='stein-store-sqlite'`n",
        [Text.UTF8Encoding]::new($false))
    $compilerTarget = Join-Path $scratch "compiler-target"
    $compilerDeps = Join-Path $compilerTarget "debug\deps"
    $null = New-Item -ItemType Directory -Path $compilerDeps -Force -ErrorAction Stop
    $compilerExecutable = Join-Path $compilerDeps "repository-synthetic.exe"
    [IO.File]::WriteAllBytes($compilerExecutable, [byte[]]@(1, 2, 3, 4))
    $compilerHarness = Get-SteinSourceFixtureHarnessDefinition `
        -Invocation $fixtures[0].subchecks[0].invocations[0]
    $compilerMessage = [ordered]@{
        reason = "compiler-artifact"
        package_id = "path+file:///synthetic#0.1.0"
        manifest_path = $compilerManifest
        target = [ordered]@{
            name = [string]$compilerHarness.target_name
            kind = @([string]$compilerHarness.target_kind)
        }
        profile = [ordered]@{ test = $true }
        executable = $compilerExecutable
    } | ConvertTo-Json -Depth 8 -Compress
    $resolvedCompilerArtifact = Resolve-SteinSourceFixtureCompilerArtifact `
        -StandardOutput $compilerMessage `
        -Harness $compilerHarness `
        -SnapshotRoot $compilerSnapshot `
        -TargetRoot $compilerTarget
    if ([string]$resolvedCompilerArtifact.Path -cne $compilerExecutable -or
        [int]$resolvedCompilerArtifact.MatchCount -ne 1) {
        throw "The closed compiler-artifact parser did not select one exact binary."
    }
    Assert-SteinSourceFixtureTestRejected `
        -Description "a missing compiler artifact" `
        -Action {
            Resolve-SteinSourceFixtureCompilerArtifact `
                -StandardOutput '{"reason":"build-finished","success":true}' `
                -Harness $compilerHarness `
                -SnapshotRoot $compilerSnapshot `
                -TargetRoot $compilerTarget
        }
    Assert-SteinSourceFixtureTestRejected `
        -Description "an extra compiler artifact" `
        -Action {
            Resolve-SteinSourceFixtureCompilerArtifact `
                -StandardOutput "$compilerMessage`n$compilerMessage" `
                -Harness $compilerHarness `
                -SnapshotRoot $compilerSnapshot `
                -TargetRoot $compilerTarget
        }
    $outsideExecutable = Join-Path $scratch "outside.exe"
    [IO.File]::WriteAllBytes($outsideExecutable, [byte[]]@(1, 2, 3, 4))
    $outsideMessageValue = $compilerMessage | ConvertFrom-Json
    $outsideMessageValue.executable = $outsideExecutable
    $outsideMessage = $outsideMessageValue | ConvertTo-Json -Depth 8 -Compress
    Assert-SteinSourceFixtureTestRejected `
        -Description "a compiler artifact outside the private target" `
        -Action {
            Resolve-SteinSourceFixtureCompilerArtifact `
                -StandardOutput $outsideMessage `
                -Harness $compilerHarness `
                -SnapshotRoot $compilerSnapshot `
                -TargetRoot $compilerTarget
        }
    $reparseTarget = Join-Path $scratch "compiler-reparse-target"
    $null = New-Item -ItemType Directory -Path $reparseTarget -ErrorAction Stop
    $reparseExecutable = Join-Path $reparseTarget "repository-reparse.exe"
    [IO.File]::WriteAllBytes($reparseExecutable, [byte[]]@(1, 2, 3, 4))
    $compilerJunction = Join-Path $compilerTarget "junction"
    $null = New-Item -ItemType Junction -Path $compilerJunction -Target $reparseTarget `
        -ErrorAction Stop
    $reparseMessageValue = $compilerMessage | ConvertFrom-Json
    $reparseMessageValue.executable = Join-Path $compilerJunction "repository-reparse.exe"
    $reparseMessage = $reparseMessageValue | ConvertTo-Json -Depth 8 -Compress
    Assert-SteinSourceFixtureTestRejected `
        -Description "a compiler artifact below a reparse ancestor" `
        -Action {
            Resolve-SteinSourceFixtureCompilerArtifact `
                -StandardOutput $reparseMessage `
                -Harness $compilerHarness `
                -SnapshotRoot $compilerSnapshot `
                -TargetRoot $compilerTarget
        }
    $compilerHash = Get-SteinSourceEvidenceSha256 -Path $compilerExecutable
    $compilerLock = Open-SteinPackageVerifiedFileLock `
        -Path $compilerExecutable `
        -ExpectedSha256 $compilerHash
    try {
        Assert-SteinSourceFixtureTestRejected `
            -Description "a post-hash compiler-artifact swap" `
            -Action {
                [IO.File]::WriteAllBytes($compilerExecutable, [byte[]]@(5, 6, 7, 8))
            }
    }
    finally {
        $compilerLock.Stream.Dispose()
    }

    $junctionTarget = Join-Path $scratch "junction-target"
    $null = New-Item -ItemType Directory -Path $junctionTarget -ErrorAction Stop
    [IO.File]::WriteAllText(
        (Join-Path $junctionTarget "registry.json"),
        '{"schema_version":1}',
        [Text.UTF8Encoding]::new($false))
    $junction = Join-Path $scratch "registry-junction"
    $null = New-Item -ItemType Junction -Path $junction -Target $junctionTarget `
        -ErrorAction Stop
    Assert-SteinSourceFixtureTestRejected `
        -Description "a registry below a reparse ancestor" `
        -Action {
            Read-SteinSourceFixtureLockedJson `
                -Path (Join-Path $junction "registry.json")
        }

    $syntheticRepository = Join-Path $scratch "synthetic-repository"
    $null = New-Item -ItemType Directory -Path $syntheticRepository -ErrorAction Stop
    $gitLauncher = [string]@(Get-Command `
            "git.exe" -CommandType Application -ErrorAction Stop)[0].Source
    $gitBinding = Get-SteinSourceFixtureGitBinding `
        -LauncherExecutable $gitLauncher `
        -WorkingDirectory $scratch
    $git = [string]$gitBinding.ResolvedPath
    $hostileGitRecord = Copy-SteinSourceFixtureTestObject -Value $gitBinding.Record
    $hostileGitRecord.resolved_executable_sha256 = "f" * 64
    Assert-SteinSourceFixtureTestRejected `
        -Description "a Git launcher/payload hash mismatch" `
        -Action {
            Assert-SteinSourceFixtureGitBindingRecord `
                -LauncherPath ([string]$gitBinding.LauncherPath) `
                -ResolvedPath ([string]$gitBinding.ResolvedPath) `
                -Record $hostileGitRecord
        }
    & $git -C $syntheticRepository init --quiet | Out-Null
    & $git -C $syntheticRepository config user.name "STEIN Synthetic Fixture" | Out-Null
    & $git -C $syntheticRepository config user.email "synthetic@example.invalid" | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $syntheticRepository "synthetic.txt"),
        "synthetic source fixture`n",
        [Text.UTF8Encoding]::new($false))
    & $git -C $syntheticRepository add -- synthetic.txt | Out-Null
    & $git -C $syntheticRepository commit --quiet -m "synthetic fixture" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "The synthetic Git candidate could not be committed."
    }
    $gitHash = Get-SteinSourceEvidenceSha256 -Path $git
    $state = Get-SteinCleanGitCandidateState `
        -RepositoryRoot $syntheticRepository `
        -GitExecutable $git `
        -ExpectedGitExecutableSha256 $gitHash
    $snapshot = New-SteinExactGitCandidateSnapshot `
        -RepositoryRoot $syntheticRepository `
        -GitExecutable $git `
        -ExpectedGitExecutableSha256 $gitHash `
        -ExpectedCommit ([string]$state.Commit) `
        -ExpectedTree ([string]$state.Tree) `
        -BuildRoot $scratch
    $snapshotLocks = Open-SteinExactCandidateSnapshotLocks -Snapshot $snapshot
    Assert-SteinSourceFixtureTestRejected `
        -Description "a write to a locked exact candidate" `
        -Action {
            [IO.File]::WriteAllText(
                (Join-Path $snapshot.Root "synthetic.txt"),
                "mutated",
                [Text.UTF8Encoding]::new($false))
        }
    foreach ($stream in $snapshotLocks.Streams) {
        $stream.Dispose()
    }
    $snapshotLocks = $null
    [IO.File]::WriteAllText(
        (Join-Path $snapshot.Root "synthetic.txt"),
        "mutated",
        [Text.UTF8Encoding]::new($false))
    Assert-SteinSourceFixtureTestRejected `
        -Description "a mutated exact candidate" `
        -Action { Open-SteinExactCandidateSnapshotLocks -Snapshot $snapshot }
}
finally {
    if ($null -ne $snapshotLocks) {
        foreach ($stream in $snapshotLocks.Streams) {
            $stream.Dispose()
        }
    }
    if ($null -ne $scratch -and (Test-Path -LiteralPath $scratch)) {
        Remove-SteinPackagePrivateTemporaryDirectory -Path $scratch -Purpose "build"
    }
}

[pscustomobject]@{
    schema_version = 1
    registry_id = [string]$registryRead.value.registry_id
    fixture_count = $fixtures.Count
    subcheck_count = @($fixtures.subchecks).Count
    invocation_mapping_count = $mappingCount
    unique_execution_count = $uniqueExecutionCount
    global_unique_execution_count = $globalUniqueExecutions.Count
    exact_list_and_execution_parser = $true
    hostile_registry_rejected = $true
    hostile_receipt_rejected = $true
    compiler_artifact_set_rejected = $true
    locked_test_binary_swap_rejected = $true
    hostile_compiler_override_rejected = $true
    hostile_cargo_config_isolated = $true
    git_launcher_payload_mismatch_rejected = $true
    reparse_ancestor_rejected = $true
    candidate_mutation_rejected = $true
    receipt_mutation_rejected = $true
    bootstrap_source_swap_rejected = $true
    bootstrap_role_substitution_rejected = $true
}
