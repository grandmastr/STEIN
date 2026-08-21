[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..")).Path
$helperPath = Join-Path $PSScriptRoot "Source-Evidence.ps1"
$verifyPath = Join-Path $PSScriptRoot "Verify-Source.ps1"
$launcherPath = Join-Path $PSScriptRoot "Verify-Source.cmd"
$reviewerPath = Join-Path $PSScriptRoot "Review-Installed.ps1"
$reviewerLauncherPath = Join-Path $PSScriptRoot "Review-Installed.cmd"
$reviewerTestPath = Join-Path $PSScriptRoot "Test-ReviewInstalled.ps1"
$commonPath = Join-Path $PSScriptRoot "Common.ps1"
$evidenceSpecPath = Join-Path $PSScriptRoot "Evidence-Spec.json"
$evidenceContractPath = Join-Path $PSScriptRoot "Evidence-Contract.ps1"
$sourceFixtureRegistryPath = Join-Path $PSScriptRoot "Source-Fixture-Registry.json"
$sourceFixtureRunnerPath = Join-Path $PSScriptRoot "Run-Source-Fixture.ps1"
$sourceFixtureTestPath = Join-Path $PSScriptRoot "Test-SourceFixture.ps1"
$noLeaksScannerPath = Join-Path $PSScriptRoot "Scan-NoLeaks.ps1"
$noLeaksScannerLauncherPath = Join-Path $PSScriptRoot "Scan-NoLeaks.cmd"
$noLeaksScannerTestPath = Join-Path $PSScriptRoot "Test-ScanNoLeaks.ps1"
$packageToolsPath = Join-Path $repoRoot "packaging\windows-msix\PackageTools.ps1"
foreach ($path in @(
        $helperPath,
        $verifyPath,
        $launcherPath,
        $reviewerPath,
        $reviewerLauncherPath,
        $reviewerTestPath,
        $commonPath,
        $evidenceSpecPath,
        $evidenceContractPath,
        $sourceFixtureRegistryPath,
        $sourceFixtureRunnerPath,
        $sourceFixtureTestPath,
        $noLeaksScannerPath,
        $noLeaksScannerLauncherPath,
        $noLeaksScannerTestPath,
        $packageToolsPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The source-evidence verifier is incomplete."
    }
}
. $helperPath

$tokens = $null
$parseErrors = $null
$verifyAst = [Management.Automation.Language.Parser]::ParseFile(
    $verifyPath,
    [ref]$tokens,
    [ref]$parseErrors)
if (@($parseErrors).Count -ne 0 -or $null -eq $verifyAst) {
    throw "Verify-Source.ps1 does not parse."
}
$verifySource = [IO.File]::ReadAllText($verifyPath)
foreach ($required in @(
        'Source-Evidence.ps1',
        'schema_version = 2',
        'Get-SteinSourceEvidenceProvenance',
        'source-provenance-stability',
        'Get-SteinSourceEvidenceGenerator',
        'New-SteinSourceEvidenceRootAnchor',
        'root-anchor.json',
        'content_integrity_only_not_authentication',
        'source_verification_only',
        'installed_or_signed_evidence = $false',
        'complete_acceptance = $false',
        'Resolve-SteinSourcePwsh',
        'Get-AuthenticodeSignature',
        'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US',
        'installed-reviewer-windows-powershell-contract',
        'installed-reviewer-pwsh-contract',
        'no-leaks-scanner-static',
        'Test-ScanNoLeaks.ps1',
        'no-leaks-producer-workflow',
        'Candidate-owned installed artifact producer is not implemented.',
        'Test-ReviewInstalled.ps1',
        'Open-SteinSourceBootstrapBinding',
        'Get-SteinSourceBootstrapStreamSha256',
        'SteinSourceBootstrapBindings',
        'source_generator_differs_from_loaded_bootstrap',
        '$launchArguments[5] = [string]$sourceFixtureRunnerBootstrapBinding[0].full_path')) {
    if ($verifySource.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "Verify-Source.ps1 is missing a source-evidence invariant."
    }
}
$bootstrapRoles = @(
    [regex]::Matches(
        $verifySource,
        "role = '(?<role>harness|package-tools|source-evidence|source-fixture-runner)'") |
        ForEach-Object { [string]$_.Groups['role'].Value })
$expectedBootstrapRoles = @(
    'harness', 'package-tools', 'source-evidence', 'source-fixture-runner')
if ($bootstrapRoles.Count -ne 4 -or
    @(Compare-Object `
        -ReferenceObject $expectedBootstrapRoles `
        -DifferenceObject $bootstrapRoles `
        -CaseSensitive).Count -ne 0 -or
    $verifySource.IndexOf(
        '$script:SteinSourceBootstrapBindings = @(',
        [StringComparison]::Ordinal) -gt
        $verifySource.IndexOf(
            '. $sourceEvidenceBootstrapBinding[0].full_path',
            [StringComparison]::Ordinal)) {
    throw "Verify-Source.ps1 does not lock its exact bootstrap dependencies before import."
}
$generatorMatch = [regex]::Match(
    $verifySource,
    '(?ms)\$generator\s*=\s*Get-SteinSourceEvidenceGenerator\s*`.*?-Paths\s*@\((?<body>.*?)^\s{4}\)')
if (-not $generatorMatch.Success) {
    throw "Verify-Source.ps1 has no statically readable generator set."
}
$generatorRelativePaths = @(
    [regex]::Matches(
        $generatorMatch.Groups["body"].Value,
        'Join-Path\s+\$PSScriptRoot\s+"(?<leaf>[^"]+)"') |
        ForEach-Object {
            "scripts/windows/phase2/$([string]$_.Groups["leaf"].Value)".Replace("\", "/")
        }
    [regex]::Matches(
        $generatorMatch.Groups["body"].Value,
        'Join-Path\s+\$repoRoot\s+"(?<path>[^"]+)"') |
        ForEach-Object { ([string]$_.Groups["path"].Value).Replace("\", "/") }
)
$expectedGeneratorRelativePaths = @(
    "scripts/windows/phase2/Verify-Source.ps1",
    "scripts/windows/phase2/Verify-Source.cmd",
    "scripts/windows/phase2/Source-Evidence.ps1",
    "scripts/windows/phase2/Source-Fixture-Registry.json",
    "scripts/windows/phase2/Run-Source-Fixture.ps1",
    "scripts/windows/phase2/Test-SourceFixture.ps1",
    "scripts/windows/phase2/Test-VerifySource.ps1",
    "scripts/windows/phase2/Review-Installed.ps1",
    "scripts/windows/phase2/Review-Installed.cmd",
    "scripts/windows/phase2/Test-ReviewInstalled.ps1",
    "scripts/windows/phase2/Common.ps1",
    "scripts/windows/phase2/Evidence-Spec.json",
    "scripts/windows/phase2/Evidence-Contract.ps1",
    "scripts/windows/phase2/Scan-NoLeaks.ps1",
    "scripts/windows/phase2/Scan-NoLeaks.cmd",
    "scripts/windows/phase2/Test-ScanNoLeaks.ps1",
    "packaging/windows-msix/PackageTools.ps1"
)
if ($generatorRelativePaths.Count -ne $expectedGeneratorRelativePaths.Count -or
    @(Compare-Object `
        -ReferenceObject ($expectedGeneratorRelativePaths | Sort-Object) `
        -DifferenceObject ($generatorRelativePaths | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "Verify-Source.ps1 does not hash its exact source-evidence generator set."
}
$evidenceSpec = Get-Content -LiteralPath $evidenceSpecPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -ErrorAction Stop
$sourceFixtureRegistry = Get-Content `
    -LiteralPath $sourceFixtureRegistryPath `
    -Raw `
    -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
$sourceFixtureRegistrySha256 = Get-SteinSourceEvidenceSha256 `
    -Path $sourceFixtureRegistryPath
if ([string]$evidenceSpec.source_report_contract.source_fixture_registry_sha256 -cne
        $sourceFixtureRegistrySha256 -or
    @($sourceFixtureRegistry.fixtures).Count -ne 13) {
    throw "The evidence specification does not freeze the exact source-fixture registry."
}
$contractGeneratorPaths = @(
    $evidenceSpec.source_report_contract.required_generator_paths)
if ($contractGeneratorPaths.Count -ne $expectedGeneratorRelativePaths.Count -or
    @(Compare-Object `
        -ReferenceObject ($expectedGeneratorRelativePaths | Sort-Object) `
        -DifferenceObject ($contractGeneratorPaths | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "The evidence specification and source generator path sets disagree."
}
$implementedSourceCheckIds = @(
    [regex]::Matches(
        $verifySource,
        '(?ms)(?:Invoke-SteinSourceCheck|Add-SteinNotRunCheck)\s+`?\s*-Id\s+"(?<id>[a-z][a-z0-9-]+)"') |
        ForEach-Object { [string]$_.Groups['id'].Value }
    'source-provenance-stability'
    @($sourceFixtureRegistry.fixtures | ForEach-Object {
            [string]$_.source_check_id
        })
) | Sort-Object -Unique
$contractSourceCheckIds = @(
    @($evidenceSpec.source_report_contract.required_pass_check_ids) +
    @($evidenceSpec.source_report_contract.allowed_not_run_check_ids))
if ($implementedSourceCheckIds.Count -ne $contractSourceCheckIds.Count -or
    @(Compare-Object `
        -ReferenceObject ($contractSourceCheckIds | Sort-Object) `
        -DifferenceObject ($implementedSourceCheckIds | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "The evidence specification and source check implementations disagree."
}
$gateSpecificFixtureIds = @(
    $sourceFixtureRegistry.fixtures | ForEach-Object {
        [string]$_.source_check_id
    })
$requiredFixtureIds = @(
    $evidenceSpec.source_report_contract.required_pass_check_ids |
        Where-Object { [string]$_ -cmatch '^phase2-source-fixture-' })
if ($gateSpecificFixtureIds.Count -ne 13 -or
    $requiredFixtureIds.Count -ne 13 -or
    @(Compare-Object `
            -ReferenceObject ($gateSpecificFixtureIds | Sort-Object) `
            -DifferenceObject ($requiredFixtureIds | Sort-Object) `
            -CaseSensitive).Count -ne 0) {
    throw "The exact required gate-specific source-fixture set is invalid."
}
$mappedGateSpecificFixtureIds = New-Object Collections.Generic.List[string]
foreach ($gate in @($evidenceSpec.gates | Where-Object {
            $null -ne $_.PSObject.Properties['source_subcheck_check_ids']
        })) {
    foreach ($mapping in @($gate.source_subcheck_check_ids.PSObject.Properties)) {
        $mappedIds = @($mapping.Value)
        if ('rust-tests' -cin $mappedIds -and
            ([string]$gate.gate_id -cne 'P2-BUILD' -or
                [string]$mapping.Name -cne 'rust_tests')) {
            throw "A generic Rust suite is mapped to a named source semantic."
        }
        foreach ($mappedId in @($mappedIds | Where-Object {
                    [string]$_ -cmatch '^phase2-source-fixture-'
                })) {
            $mappedGateSpecificFixtureIds.Add([string]$mappedId)
        }
    }
}
if (@(Compare-Object `
        -ReferenceObject ($gateSpecificFixtureIds | Sort-Object -Unique) `
        -DifferenceObject ($mappedGateSpecificFixtureIds | Sort-Object -Unique) `
        -CaseSensitive).Count -ne 0) {
    throw "The gate-specific source-fixture mappings are incomplete."
}

$reviewerHostBindings = @{}
[regex]::Matches(
    $verifySource,
    '(?ms)Invoke-SteinSourceCheck\s+`?\s*-Id\s+"(?<id>installed-reviewer-(?:windows-powershell|pwsh)-contract)"\s+`?\s*-Executable\s+\$(?<host>powershell|pwsh)\s+`?.*?Test-ReviewInstalled\.ps1') |
    ForEach-Object {
        $reviewerHostBindings[[string]$_.Groups["id"].Value] =
            [string]$_.Groups["host"].Value
    }
if ($reviewerHostBindings.Count -ne 2 -or
    [string]$reviewerHostBindings["installed-reviewer-windows-powershell-contract"] -cne
        "powershell" -or
    [string]$reviewerHostBindings["installed-reviewer-pwsh-contract"] -cne "pwsh") {
    throw "Verify-Source.ps1 does not fail closed across both reviewer PowerShell hosts."
}

$pwshResolverAsts = @($verifyAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq "Resolve-SteinSourcePwsh"
        }, $true))
if ($pwshResolverAsts.Count -ne 1) {
    throw "Verify-Source.ps1 does not contain one statically testable pwsh resolver."
}
$pwshResolverCommands = @($pwshResolverAsts[0].FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $null -ne $_ })
foreach ($commandName in $pwshResolverCommands) {
    if ($commandName -cnotin @(
            "Get-Command", "Select-Object", "Get-Item", "Get-AuthenticodeSignature")) {
        throw "The pwsh resolver can execute an unvalidated discovered application."
    }
}

$pwshPoisonRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-source-pwsh-poison-" + [Guid]::NewGuid().ToString("N"))
$pwshPoisonRootCanonical = [IO.Path]::GetFullPath($pwshPoisonRoot)
$temporaryRootCanonical = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar)
$originalPath = $env:Path
try {
    $null = New-Item -ItemType Directory -Path $pwshPoisonRoot -ErrorAction Stop
    $fakePwsh = Join-Path $pwshPoisonRoot "pwsh.exe"
    [IO.File]::WriteAllText(
        $fakePwsh,
        "synthetic unsigned pwsh path poison; must never execute",
        [Text.UTF8Encoding]::new($false))
    $env:Path = "$pwshPoisonRoot$([IO.Path]::PathSeparator)$originalPath"
    $discoveredPwsh = Get-Command "pwsh.exe" -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    if (-not [string]::Equals(
            [IO.Path]::GetFullPath([string]$discoveredPwsh.Source),
            [IO.Path]::GetFullPath($fakePwsh),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "The pwsh PATH-poison fixture did not control application discovery."
    }
    $resolverScript = [ScriptBlock]::Create(
        "$($pwshResolverAsts[0].Extent.Text)`nResolve-SteinSourcePwsh")
    $poisonRejected = $false
    try {
        $null = & $resolverScript
    }
    catch {
        $poisonRejected = $true
    }
    if (-not $poisonRejected) {
        throw "The pwsh resolver accepted an unsigned PATH-poisoned executable."
    }
}
finally {
    $env:Path = $originalPath
    if (Test-Path -LiteralPath $pwshPoisonRootCanonical) {
        if (-not $pwshPoisonRootCanonical.StartsWith(
                "$temporaryRootCanonical$([IO.Path]::DirectorySeparatorChar)stein-source-pwsh-poison-",
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "The pwsh PATH-poison cleanup target is invalid."
        }
        Remove-Item -LiteralPath $pwshPoisonRootCanonical -Recurse -Force
    }
}

$resolvedTrustedPwsh = [string](& $resolverScript)
$discoveredTrustedPwsh = [string](
    Get-Command "pwsh.exe" -CommandType Application -ErrorAction Stop |
        Select-Object -First 1).Source
if ([string]::IsNullOrWhiteSpace($resolvedTrustedPwsh) -or
    -not [string]::Equals(
        [IO.Path]::GetFullPath($resolvedTrustedPwsh),
        [IO.Path]::GetFullPath($discoveredTrustedPwsh),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "The pwsh resolver did not return the validated Microsoft-signed host."
}

$toolExecutables = [ordered]@{
    cargo = [string]@(Get-Command "cargo.exe" -CommandType Application -ErrorAction Stop)[0].Source
    rustc = [string]@(Get-Command "rustc.exe" -CommandType Application -ErrorAction Stop)[0].Source
    rustup = [string]@(Get-Command "rustup.exe" -CommandType Application -ErrorAction Stop)[0].Source
    node = [string]@(Get-Command "node.exe" -CommandType Application -ErrorAction Stop)[0].Source
    pnpm = [string]@(Get-Command "pnpm.cmd" -CommandType Application -ErrorAction Stop)[0].Source
    git = [string]@(Get-Command "git.exe" -CommandType Application -ErrorAction Stop)[0].Source
    pwsh = $resolvedTrustedPwsh
}
$ignoredGeneratedPaths = @(
    "artifacts/evidence/phase-2/source-contract/source-verification.json",
    "target/source-contract",
    "apps/desktop/dist/source-contract",
    "apps/desktop/node_modules/source-contract",
    "apps/desktop/src-tauri/gen/source-contract",
    "extensions/edge/node_modules/source-contract",
    "apps/edge-native-host/target/source-contract"
)
foreach ($ignoredGeneratedPath in $ignoredGeneratedPaths) {
    $ignoreResult = Invoke-SteinSourceEvidenceProcess `
        -Executable ([string]$toolExecutables["git"]) `
        -Arguments @("check-ignore", "--no-index", "-q", "--", $ignoredGeneratedPath) `
        -WorkingDirectory $repoRoot `
        -AllowedExitCodes @(0, 1) `
        -MaximumStandardOutputCharacters 0
    if ($ignoreResult.exit_code -ne 0) {
        throw "A generated source-verification output is not ignored by Git."
    }
}
$provenance = Get-SteinSourceEvidenceProvenance `
    -RepositoryRoot $repoRoot `
    -ToolExecutables $toolExecutables
$provenanceJson = $provenance | ConvertTo-Json -Depth 16 -Compress
if ($provenanceJson.IndexOf($repoRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
    (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE) -and
        $provenanceJson.IndexOf($env:USERPROFILE, [StringComparison]::OrdinalIgnoreCase) -ge 0)) {
    throw "Source provenance retained a local filesystem path."
}
$expectedToolNames = @("cargo", "rustc", "rustup", "node", "pnpm", "git", "pwsh")
$actualToolNames = @($provenance.toolchain.Keys | ForEach-Object { [string]$_ })
if ([int]$provenance.schema_version -ne 2 -or
    [string]$provenance.classification -cne "bounded_content_free_source_provenance" -or
    [string]$provenance.repository.head_commit -notmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
    [string]$provenance.repository.state_sha256 -notmatch '^[0-9a-f]{64}$' -or
    $actualToolNames.Count -ne $expectedToolNames.Count -or
    @(Compare-Object `
        -ReferenceObject ($expectedToolNames | Sort-Object) `
        -DifferenceObject ($actualToolNames | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "Source repository provenance is invalid."
}
foreach ($rustToolName in @("cargo", "rustc")) {
    $rustTool = $provenance.toolchain.$rustToolName
    $rustProperties = @($rustTool.Keys | ForEach-Object { [string]$_ })
    $expectedRustProperties = @(
        "version",
        "executable_sha256",
        "rustup_toolchain",
        "resolved_version",
        "resolved_executable_sha256")
    if ($rustProperties.Count -ne $expectedRustProperties.Count -or
        @(Compare-Object `
            -ReferenceObject ($expectedRustProperties | Sort-Object) `
            -DifferenceObject ($rustProperties | Sort-Object) `
            -CaseSensitive).Count -ne 0 -or
        [string]$rustTool.rustup_toolchain -notmatch
            '^[0-9A-Za-z][0-9A-Za-z._-]{2,127}$' -or
        [string]$rustTool.resolved_version -cne [string]$rustTool.version -or
        [string]$rustTool.resolved_executable_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "A rustup-selected source toolchain record is invalid."
    }
}
if ([string]$provenance.toolchain.cargo.rustup_toolchain -cne
        [string]$provenance.toolchain.rustc.rustup_toolchain -or
    [string]$provenance.toolchain.pnpm.resolved_entrypoint_sha256 -notmatch
        '^[0-9a-f]{64}$' -or
    [string]$provenance.toolchain.git.resolved_version -cne
        [string]$provenance.toolchain.git.version -or
    [string]$provenance.toolchain.git.resolved_executable_sha256 -notmatch
        '^[0-9a-f]{64}$') {
    throw "Resolved source toolchain payload provenance is invalid."
}
$gitProperties = @(
    $provenance.toolchain.git.Keys | ForEach-Object { [string]$_ })
$expectedGitProperties = @(
    "version",
    "executable_sha256",
    "resolved_version",
    "resolved_executable_sha256")
if ($gitProperties.Count -ne $expectedGitProperties.Count -or
    @(Compare-Object `
        -ReferenceObject ($expectedGitProperties | Sort-Object) `
        -DifferenceObject ($gitProperties | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "The resolved Git source toolchain record is invalid."
}
foreach ($toolName in $expectedToolNames) {
    $tool = $provenance.toolchain.$toolName
    if ([string]::IsNullOrWhiteSpace([string]$tool.version) -or
        [string]$tool.version -notmatch '^[\x20-\x7e]{1,160}$' -or
        [string]$tool.executable_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "A source toolchain provenance record is invalid."
    }
}
if ([string]$provenance.toolchain.pwsh.authenticode_status -cne "valid" -or
    [string]$provenance.toolchain.pwsh.signer_subject -cne
        "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") {
    throw "The pwsh toolchain provenance does not retain its closed publisher validation."
}
if ([string]$provenance.build_versions.rust_workspace_package -notmatch '^[0-9]+\.[0-9]+\.[0-9]+' -or
    [string]$provenance.build_versions.minimum_rust -notmatch '^[0-9]+\.[0-9]+' -or
    [string]$provenance.build_versions.desktop_package -notmatch '^[0-9]+\.[0-9]+\.[0-9]+' -or
    [string]$provenance.build_versions.edge_extension_package -notmatch '^[0-9]+\.[0-9]+\.[0-9]+' -or
    [string]$provenance.build_versions.edge_native_host_package -notmatch '^[0-9]+\.[0-9]+\.[0-9]+') {
    throw "Source build-version provenance is invalid."
}

$contracts = $provenance.contract_versions
if ([int]$contracts.schemas.sqlite_application -le 0 -or
    [int]$contracts.schemas.stein_identity -ne 1 -or
    [int]$contracts.schemas.user_preferences -ne 1 -or
    [int]$contracts.schemas.protocol_message -ne 1 -or
    [int]$contracts.migrations.count -lt 11 -or
    @($contracts.migrations.identifiers).Count -ne [int]$contracts.migrations.count -or
    [string]$contracts.migrations.identifiers_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [string]$contracts.migrations.implementation_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [int]$contracts.protocol.major -ne 1 -or
    [int]$contracts.protocol.minimum_minor -ne 0 -or
    [int]$contracts.protocol.maximum_minor -lt 2 -or
    [string]$contracts.protocol.current -cne "$($contracts.protocol.major).$($contracts.protocol.maximum_minor)" -or
    [string]$contracts.policy.profile_id -cne "phase2-focus-v1" -or
    [int]$contracts.policy.input_schema -ne 1) {
    throw "Source contract-version provenance is invalid."
}

$generator = Get-SteinSourceEvidenceGenerator `
    -RepositoryRoot $repoRoot `
    -Paths @(
        $verifyPath,
        $launcherPath,
        $helperPath,
        $sourceFixtureRegistryPath,
        $sourceFixtureRunnerPath,
        $sourceFixtureTestPath,
        $PSCommandPath,
        $reviewerPath,
        $reviewerLauncherPath,
        $reviewerTestPath,
        $commonPath,
        $evidenceSpecPath,
        $evidenceContractPath,
        $noLeaksScannerPath,
        $noLeaksScannerLauncherPath,
        $noLeaksScannerTestPath,
        $packageToolsPath)
$generatorJson = $generator | ConvertTo-Json -Depth 8 -Compress
if ([int]$generator.schema_version -ne 1 -or
    @($generator.files).Count -ne 17 -or
    [string]$generator.digest_sha256 -notmatch '^[0-9a-f]{64}$' -or
    $generatorJson.IndexOf($repoRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "Source generator provenance is invalid."
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-source-evidence-" + [Guid]::NewGuid().ToString("N"))
$externalFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-source-evidence-external-" + [Guid]::NewGuid().ToString("N"))
$junctionPath = Join-Path $fixtureRoot "linked-external"
try {
    $null = New-Item -ItemType Directory -Path $fixtureRoot -ErrorAction Stop
    $null = New-Item -ItemType Directory -Path $externalFixtureRoot -ErrorAction Stop
    foreach ($functionName in @(
            'Get-SteinSourceBootstrapStreamSha256',
            'Open-SteinSourceBootstrapBinding')) {
        $functionAst = @($verifyAst.FindAll({
                    param($node)
                    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $functionName
                }, $true))
        if ($functionAst.Count -ne 1) {
            throw "A source bootstrap lock helper is not uniquely defined."
        }
        . ([scriptblock]::Create($functionAst[0].Extent.Text))
    }
    $bootstrapProbeRoot = Join-Path $fixtureRoot 'bootstrap-lock-probe'
    $null = New-Item -ItemType Directory -Path $bootstrapProbeRoot -ErrorAction Stop
    $bootstrapProbePath = Join-Path $bootstrapProbeRoot 'source.ps1'
    $bootstrapReplacementPath = Join-Path $bootstrapProbeRoot 'replacement.ps1'
    [IO.File]::WriteAllText($bootstrapProbePath, 'locked-source-bootstrap')
    [IO.File]::WriteAllText($bootstrapReplacementPath, 'replacement-source-bootstrap')
    $bootstrapBinding = Open-SteinSourceBootstrapBinding `
        -Role 'lock-probe' `
        -Path $bootstrapProbePath `
        -RepositoryRoot $fixtureRoot
    try {
        $bootstrapWriteRejected = $false
        try {
            [IO.File]::WriteAllText($bootstrapProbePath, 'mutated-source-bootstrap')
        }
        catch {
            $bootstrapWriteRejected = $true
        }
        $bootstrapReplacementRejected = $false
        try {
            Move-Item `
                -LiteralPath $bootstrapReplacementPath `
                -Destination $bootstrapProbePath `
                -Force `
                -ErrorAction Stop
        }
        catch {
            $bootstrapReplacementRejected = $true
        }
        $bootstrapSameHandleSha256 = Get-SteinSourceBootstrapStreamSha256 `
            -Stream $bootstrapBinding.stream `
            -FailureCode 'source_bootstrap_source_changed'
        if (-not $bootstrapWriteRejected -or -not $bootstrapReplacementRejected -or
            $bootstrapSameHandleSha256 -cne [string]$bootstrapBinding.record.sha256) {
            throw "The source bootstrap lock allowed a write, replacement, or byte change."
        }
    }
    finally {
        $bootstrapBinding.stream.Dispose()
    }
    if (-not [string]::Equals(
            [IO.Path]::GetFileName($bootstrapProbeRoot),
            'bootstrap-lock-probe',
            [StringComparison]::Ordinal) -or
        -not [IO.Path]::GetFullPath($bootstrapProbeRoot).StartsWith(
            "$([IO.Path]::GetFullPath($fixtureRoot).TrimEnd('\', '/'))$([IO.Path]::DirectorySeparatorChar)",
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "The source bootstrap probe cleanup target is invalid."
    }
    [IO.Directory]::Delete($bootstrapProbeRoot, $true)
    $externalSourcePath = Join-Path $externalFixtureRoot "external-source.ps1"
    [IO.File]::WriteAllText(
        $externalSourcePath,
        "synthetic external source that must not enter provenance",
        [Text.UTF8Encoding]::new($false))
    $null = New-Item `
        -ItemType Junction `
        -Path $junctionPath `
        -Target $externalFixtureRoot `
        -ErrorAction Stop
    $junctionRejected = $false
    try {
        $null = Get-SteinSourceEvidenceFileRecord `
            -RepositoryRoot $fixtureRoot `
            -Path (Join-Path $junctionPath "external-source.ps1")
    }
    catch {
        $junctionRejected = $true
    }
    if (-not $junctionRejected) {
        throw "Source generator provenance accepted a reparse ancestor."
    }
    $toolJunctionRejected = $false
    try {
        $null = Get-SteinSourceEvidenceRegularFileItem `
            -Path (Join-Path $junctionPath "external-source.ps1")
    }
    catch {
        $toolJunctionRejected = $true
    }
    if (-not $toolJunctionRejected) {
        throw "Source tool provenance accepted a reparse ancestor."
    }
    [IO.Directory]::Delete($junctionPath, $false)
    if (-not (Test-Path -LiteralPath $externalSourcePath -PathType Leaf)) {
        throw "The reparse negative fixture altered its external target."
    }

    $git = [string]$toolExecutables["git"]
    foreach ($arguments in @(
            @("init", "--quiet"),
            @("config", "user.name", "STEIN Fixture"),
            @("config", "user.email", "fixture@stein.invalid"))) {
        $null = Invoke-SteinSourceEvidenceProcess `
            -Executable $git `
            -Arguments $arguments `
            -WorkingDirectory $fixtureRoot
    }
    [IO.File]::WriteAllText(
        (Join-Path $fixtureRoot "tracked.txt"),
        "synthetic tracked source",
        [Text.UTF8Encoding]::new($false))
    $null = Invoke-SteinSourceEvidenceProcess `
        -Executable $git `
        -Arguments @("add", "--", "tracked.txt") `
        -WorkingDirectory $fixtureRoot
    $null = Invoke-SteinSourceEvidenceProcess `
        -Executable $git `
        -Arguments @(
            "-c", "commit.gpgsign=false",
            "-c", "core.hooksPath=NUL",
            "commit", "--quiet", "-m", "source evidence fixture") `
        -WorkingDirectory $fixtureRoot
    $cleanState = Get-SteinSourceEvidenceRepositoryState `
        -RepositoryRoot $fixtureRoot `
        -GitExecutable $git
    if (-not [bool]$cleanState.clean -or
        [int]$cleanState.tracked_changed_path_count -ne 0 -or
        [int]$cleanState.untracked_path_count -ne 0) {
        throw "The clean Git source fixture was not reported as clean."
    }
    [IO.File]::AppendAllText((Join-Path $fixtureRoot "tracked.txt"), " changed")
    [IO.File]::WriteAllText(
        (Join-Path $fixtureRoot "untracked.txt"),
        "synthetic untracked source",
        [Text.UTF8Encoding]::new($false))
    $dirtyState = Get-SteinSourceEvidenceRepositoryState `
        -RepositoryRoot $fixtureRoot `
        -GitExecutable $git
    $dirtyStateAgain = Get-SteinSourceEvidenceRepositoryState `
        -RepositoryRoot $fixtureRoot `
        -GitExecutable $git
    $dirtyJson = $dirtyState | ConvertTo-Json -Depth 6 -Compress
    if ([bool]$dirtyState.clean -or
        [bool]$dirtyState.has_staged_changes -or
        -not [bool]$dirtyState.has_unstaged_changes -or
        [int]$dirtyState.tracked_changed_path_count -ne 1 -or
        [int]$dirtyState.untracked_path_count -ne 1 -or
        [string]$dirtyState.state_sha256 -cne [string]$dirtyStateAgain.state_sha256 -or
        $dirtyJson.IndexOf("tracked.txt", [StringComparison]::Ordinal) -ge 0 -or
        $dirtyJson.IndexOf("untracked.txt", [StringComparison]::Ordinal) -ge 0 -or
        $dirtyJson.IndexOf($fixtureRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The dirty Git source fixture violated its content-free deterministic contract."
    }

    $reportPath = Join-Path $fixtureRoot "source-verification.json"
    [IO.File]::WriteAllText(
        $reportPath,
        '{"schema_version":2,"claim":"source_verification_only"}',
        [Text.UTF8Encoding]::new($false))
    $anchor = New-SteinSourceEvidenceRootAnchor `
        -ReportPath $reportPath `
        -GeneratorDigest ('a' * 64) `
        -ProvenanceDigest ('b' * 64) `
        -ChecksDigest ('c' * 64)
    if ([string]$anchor.source_verification.sha256 -cne `
            "b501939f6f18e81eccc1f032499a770b5488f7854c11160a70cae80a7b1d354e" -or
        [string]$anchor.root_digest_sha256 -cne `
            "24c34d67d35ee27f73fa255da70a1ea05d57034df7ddd2018776a28221813eb8" -or
        [string]$anchor.integrity_semantics -cne `
            "content_integrity_only_not_authentication") {
        throw "The source-evidence root-anchor contract is not deterministic."
    }
}
finally {
    $resolvedFixtureRoot = [IO.Path]::GetFullPath($fixtureRoot)
    $resolvedExternalFixtureRoot = [IO.Path]::GetFullPath($externalFixtureRoot)
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    if (Test-Path -LiteralPath $junctionPath) {
        [IO.Directory]::Delete($junctionPath, $false)
    }
    if (Test-Path -LiteralPath $resolvedFixtureRoot) {
        if (-not $resolvedFixtureRoot.StartsWith(
                "$temporaryRoot$([IO.Path]::DirectorySeparatorChar)stein-source-evidence-",
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "The source-evidence fixture cleanup target is invalid."
        }
        Remove-Item -LiteralPath $resolvedFixtureRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $resolvedExternalFixtureRoot) {
        if (-not $resolvedExternalFixtureRoot.StartsWith(
                "$temporaryRoot$([IO.Path]::DirectorySeparatorChar)stein-source-evidence-external-",
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "The external source-evidence fixture cleanup target is invalid."
        }
        Remove-Item -LiteralPath $resolvedExternalFixtureRoot -Recurse -Force
    }
}

[pscustomobject]@{
    verified = $true
    report_schema_version = 2
    provenance_schema_version = 2
    generator_file_count = @($generator.files).Count
    source_report_check_count = $contractSourceCheckIds.Count
    source_report_contract_bound = $true
    gate_specific_source_mapping_bound = $true
    repository_state_content_free = $true
    generated_outputs_ignored = $true
    toolchain_version_count = $actualToolNames.Count
    dual_reviewer_shell_contract = $true
    pwsh_path_poison_rejected = $true
    trusted_pwsh_resolved = $true
    generator_reparse_ancestor_rejected = $true
    tool_reparse_ancestor_rejected = $true
    migration_identifier_count = [int]$contracts.migrations.count
    protocol_version = [string]$contracts.protocol.current
    policy_profile = [string]$contracts.policy.profile_id
    deterministic_root_anchor = $true
    bootstrap_source_swap_rejected = $true
    bootstrap_role_set_closed = $true
}
