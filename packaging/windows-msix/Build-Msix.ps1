[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9A-Fa-f ]{40,59}$")]
    [string] $CertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Publisher,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $PublisherDisplayName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^https://")]
    [string] $TimestampUrl,

    [ValidatePattern("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")]
    [string] $Version = "0.1.0.0",

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[a-p]{32}$")]
    [string] $EdgeExtensionId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9]+(?:\.[0-9]+){0,3}$")]
    [string] $EdgeExtensionVersion,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $EdgePublisherSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]
    [string] $ExpectedCandidateGitCommit,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]
    [string] $ExpectedCandidateGitTree,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $SourceVerificationReportPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $SourceRootAnchorPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $ExpectedSourceVerificationSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $ExpectedSourceRootAnchorSha256,

    [string] $OutputPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-SteinBuildBootstrapStreamSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [IO.FileStream] $Stream
    )

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $Stream.Position = 0
        return [BitConverter]::ToString($sha256.ComputeHash($Stream)).Replace(
            '-',
            '').ToLowerInvariant()
    }
    finally {
        $Stream.Position = 0
        $sha256.Dispose()
    }
}

function Open-SteinBuildBootstrapScriptBinding {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -lt 1 -or
        $item.Length -gt 4194304) {
        throw "A signed-build bootstrap script is not a regular bounded file."
    }
    $probe = Split-Path -Parent $item.FullName
    $volume = [IO.Path]::GetPathRoot($probe)
    while ($probe.Length -ge $volume.Length) {
        $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "A signed-build bootstrap script has an unsafe ancestor."
        }
        if ([string]::Equals(
                $probe,
                $volume,
                [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $probe = Split-Path -Parent $probe
    }

    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $length = [long]$stream.Length
        if ($length -ne [long]$item.Length) {
            throw "A signed-build bootstrap script changed before it was locked."
        }
        return [pscustomobject]@{
            FullPath = $item.FullName
            Length = $length
            Sha256 = Get-SteinBuildBootstrapStreamSha256 -Stream $stream
            Stream = $stream
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Assert-SteinBuildBootstrapScriptBindingStable {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Binding
    )

    if ([long]$Binding.Stream.Length -ne [long]$Binding.Length -or
        (Get-SteinBuildBootstrapStreamSha256 -Stream $Binding.Stream) -cne
            [string]$Binding.Sha256) {
        throw "A signed-build bootstrap script changed while it was in use."
    }
}

$buildBootstrapBindings = New-Object Collections.Generic.List[object]
$buildBootstrapFailure = $null
try {
    $buildScriptBootstrapBinding = Open-SteinBuildBootstrapScriptBinding `
        -Path $PSCommandPath
    $buildBootstrapBindings.Add($buildScriptBootstrapBinding)
    $packageToolsBootstrapBinding = Open-SteinBuildBootstrapScriptBinding `
        -Path (Join-Path $PSScriptRoot "PackageTools.ps1")
    $buildBootstrapBindings.Add($packageToolsBootstrapBinding)

    . $packageToolsBootstrapBinding.FullPath
    foreach ($binding in $buildBootstrapBindings) {
        $null = Assert-SteinBuildBootstrapScriptBindingStable -Binding $binding
    }

$repoRoot = Resolve-SteinPackageRegularDirectoryWithAncestors `
    -Path (Join-Path $PSScriptRoot "..\..")
$bootstrapSourceBinding = Get-SteinVerifiedSourceBuildBinding `
    -RepositoryRoot $repoRoot `
    -SourceVerificationReportPath $SourceVerificationReportPath `
    -SourceRootAnchorPath $SourceRootAnchorPath `
    -ExpectedSourceVerificationSha256 $ExpectedSourceVerificationSha256 `
    -ExpectedSourceRootAnchorSha256 $ExpectedSourceRootAnchorSha256 `
    -ExpectedCandidateGitCommit $ExpectedCandidateGitCommit `
    -ExpectedCandidateGitTree $ExpectedCandidateGitTree `
    -BootstrapOnly
if ([string]$bootstrapSourceBinding.CandidateBindingScope -cne "bootstrap_only") {
    throw "The initial source binding exceeded its bootstrap-only scope."
}
$toolchain = Get-SteinVerifiedBuildToolchain `
    -SourceBinding $bootstrapSourceBinding `
    -WorkingDirectory $repoRoot
$buildRoot = New-SteinPackagePrivateTemporaryDirectory -Purpose "build"
$snapshot = $null
$sourceBinding = $null
$sourceLocks = $null
$distLocks = $null
$candidateBuildScriptLock = $null
$candidatePackageToolsLock = $null
try {
    $snapshot = New-SteinExactGitCandidateSnapshot `
        -RepositoryRoot $repoRoot `
        -GitExecutable $toolchain.Git `
        -ExpectedGitExecutableSha256 `
            $bootstrapSourceBinding.GitResolvedExecutableSha256 `
        -ExpectedCommit $ExpectedCandidateGitCommit `
        -ExpectedTree $ExpectedCandidateGitTree `
        -BuildRoot $buildRoot
    $sourceLocks = Open-SteinExactCandidateSnapshotLocks -Snapshot $snapshot
    $sourceBinding = Get-SteinVerifiedSourceBuildBinding `
        -RepositoryRoot $repoRoot `
        -CandidateRoot $snapshot.Root `
        -CandidateSnapshot $snapshot `
        -SourceVerificationReportPath $SourceVerificationReportPath `
        -SourceRootAnchorPath $SourceRootAnchorPath `
        -ExpectedSourceVerificationSha256 $ExpectedSourceVerificationSha256 `
        -ExpectedSourceRootAnchorSha256 $ExpectedSourceRootAnchorSha256 `
        -ExpectedCandidateGitCommit $ExpectedCandidateGitCommit `
        -ExpectedCandidateGitTree $ExpectedCandidateGitTree
    if ([string]$sourceBinding.CandidateBindingScope -cne
            "authoritative_locked_snapshot" -or
        [long]$sourceBinding.CandidateTreeFileCount -ne @($snapshot.Files).Count -or
        -not (Test-SteinPackageSha256Value `
            -Value ([string]$sourceBinding.CandidateTreeManifestSha256))) {
        throw "The authoritative source binding did not ground the locked candidate tree."
    }
    foreach ($bindingProperty in @(
            "GitExecutableSha256", "GitResolvedExecutableSha256",
            "CargoExecutableSha256",
            "CargoResolvedExecutableSha256", "RustcExecutableSha256",
            "RustcResolvedExecutableSha256", "RustupExecutableSha256",
            "NodeExecutableSha256", "PnpmExecutableSha256",
            "PnpmResolvedEntrypointSha256", "RustupToolchain")) {
        if ([string]$sourceBinding.$bindingProperty -cne
            [string]$bootstrapSourceBinding.$bindingProperty) {
            throw "The private candidate uses a different source toolchain contract."
        }
    }
    $candidateBuildScript = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $snapshot.Root `
        -Path (Join-Path $snapshot.Root "packaging\windows-msix\Build-Msix.ps1")
    $candidatePackageTools = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $snapshot.Root `
        -Path (Join-Path $snapshot.Root "packaging\windows-msix\PackageTools.ps1")
    $candidateBuildScriptHash = Get-SteinPackageFileSha256 -Path $candidateBuildScript
    $candidatePackageToolsHash = Get-SteinPackageFileSha256 -Path $candidatePackageTools
    if ([long]$buildScriptBootstrapBinding.Length -ne
            [long](Get-Item -LiteralPath $candidateBuildScript -Force).Length -or
        [string]$buildScriptBootstrapBinding.Sha256 -cne $candidateBuildScriptHash -or
        [long]$packageToolsBootstrapBinding.Length -ne
            [long](Get-Item -LiteralPath $candidatePackageTools -Force).Length -or
        [string]$packageToolsBootstrapBinding.Sha256 -cne $candidatePackageToolsHash) {
        throw "The running packaging scripts differ from the exact candidate tree."
    }
    $candidateBuildScriptLock = $buildScriptBootstrapBinding
    $candidatePackageToolsLock = $packageToolsBootstrapBinding
}
catch {
    $candidatePrimaryFailure = $_
    $candidateCleanupFailure = $null
    try {
        if ($null -ne $sourceLocks) {
            foreach ($stream in $sourceLocks.Streams) { $stream.Dispose() }
        }
        foreach ($lockedTool in $toolchain.Locks) { $lockedTool.Stream.Dispose() }
        if (Test-Path -LiteralPath $buildRoot) {
            Remove-SteinPackagePrivateTemporaryDirectory `
                -Path $buildRoot `
                -Purpose "build"
        }
    }
    catch {
        $candidateCleanupFailure = $_
    }
    throw (Resolve-SteinPackagePrimaryAndCleanupFailure `
        -PrimaryFailure $candidatePrimaryFailure `
        -CleanupFailure $candidateCleanupFailure)
}

$packageTemporaryPath = $null
$coreCompanionTemporaryPath = $null
$cliCompanionTemporaryPath = $null
$identityTemporaryPath = $null
$browserIdentityTemporaryPath = $null
$desktopExecutableLock = $null
$coreExecutableLock = $null
$cliExecutableLock = $null
$hostExecutableLock = $null
$brokerExecutableLock = $null
$stagingLocks = $null
$stagingMappingLock = $null
$previousEnvironment = @{}
$buildOperationFailure = $null
$buildCleanupFailure = $null
try {
$candidateRoot = $snapshot.Root
$templatePath = Join-Path $candidateRoot "packaging\windows-msix\AppxManifest.xml.in"
$assetSource = Join-Path $candidateRoot "packaging\windows-msix\assets"
$desktopRoot = Join-Path $candidateRoot "apps\desktop"
$desktopDistRoot = Join-Path $desktopRoot "dist"
$desktopNodeModules = Join-Path $desktopRoot "node_modules"
$stagingRoot = Join-Path $buildRoot "staging"
$workspaceTargetRoot = Join-Path $buildRoot "targets\workspace"
$edgeTargetRoot = Join-Path $buildRoot "targets\edge"
$cargoHome = Join-Path $buildRoot "cargo-home"
$pnpmStore = Join-Path $buildRoot "pnpm-store"
$pnpmHome = Join-Path $buildRoot "pnpm-home"
$corepackHome = Join-Path $buildRoot "corepack-home"
$nodeConfigHome = Join-Path $buildRoot "node-config"
$npmUserConfig = Join-Path $nodeConfigHome "npmrc"
$makeAppx = Resolve-WindowsSdkTool -Name "makeappx.exe"
$signTool = Resolve-WindowsSdkTool -Name "signtool.exe"
$certificate = Get-ExactSigningCertificate `
    -Thumbprint $CertificateThumbprint `
    -Publisher $Publisher
$normalizedThumbprint = $certificate.Thumbprint.ToUpperInvariant()
$hostPublisherSha256 = $certificate.GetCertHashString(
    [Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()
if ($hostPublisherSha256 -notmatch "^[0-9a-f]{64}$" -or
    $hostPublisherSha256 -eq ("0" * 64) -or
    $EdgePublisherSha256 -eq ("0" * 64)) {
    throw "Exact nonzero SHA-256 publisher certificate identities are required."
}
$packageFamilyName = Get-ExactPackageFamilyName `
    -PackageName $script:ProductionPackageName `
    -Publisher $Publisher
$brokerAumid = "$packageFamilyName!$script:BrokerApplicationId"
$browserProducerAumid = "$packageFamilyName!$script:BrowserProducerApplicationId"

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot "out\STEIN-$Version-x64.msix"
}
$outputParent = Split-Path -Parent $OutputPath
if ([string]::IsNullOrWhiteSpace($outputParent)) {
    throw "OutputPath must include a parent directory."
}
$null = New-Item -ItemType Directory -Path $outputParent -Force
$outputParent = Resolve-SteinPackageRegularDirectoryWithAncestors -Path $outputParent
$outputPath = Join-Path $outputParent (Split-Path -Leaf $OutputPath)
if ([IO.Path]::GetExtension($outputPath) -ine ".msix") {
    throw "OutputPath must use the .msix extension."
}
$publicationId = [Guid]::NewGuid().ToString('N')
$packageTemporaryPath = "$outputPath.$publicationId.tmp.msix"
$coreCompanionPath = "$outputPath.core.exe"
$coreCompanionTemporaryPath = "$coreCompanionPath.$publicationId.tmp"
$cliCompanionPath = "$outputPath.cli.exe"
$cliCompanionTemporaryPath = "$cliCompanionPath.$publicationId.tmp"
$identityPath = "$outputPath.identity.json"
$identityTemporaryPath = "$identityPath.$publicationId.tmp"
$browserIdentityPath = "$outputPath.browser.json"
$browserIdentityTemporaryPath = "$browserIdentityPath.$publicationId.tmp"

$managedEnvironmentNames = @(
    "STEIN_CORE_EXECUTABLE_SHA256",
    "STEIN_PRODUCTION_PACKAGE_FAMILY_NAME",
    "STEIN_PRODUCTION_BROKER_AUMID",
    "STEIN_EDGE_EXTENSION_ID",
    "STEIN_EDGE_EXTENSION_VERSION",
    "STEIN_EDGE_PUBLISHER_SHA256",
    "STEIN_EDGE_HOST_PUBLISHER_SHA256",
    "CARGO_HOME",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET_DIR",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTUP_TOOLCHAIN",
    "NODE_OPTIONS",
    "PNPM_HOME",
    "COREPACK_HOME",
    "NPM_CONFIG_USERCONFIG",
    "XDG_CONFIG_HOME",
    "CI")
$previousEnvironment = @{}
foreach ($environmentName in $managedEnvironmentNames) {
    $previousEnvironment[$environmentName] = [Environment]::GetEnvironmentVariable(
        $environmentName,
        [EnvironmentVariableTarget]::Process)
}
$rejectedOverrides = @(
    "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN", "NODE_OPTIONS")

    foreach ($overrideName in $rejectedOverrides) {
        if (-not [string]::IsNullOrEmpty(
                [string]$previousEnvironment[$overrideName])) {
            throw "A compiler, output, or renderer override is set: $overrideName"
        }
    }
    foreach ($privateDirectory in @(
            $workspaceTargetRoot, $edgeTargetRoot, $cargoHome, $pnpmStore,
            $pnpmHome, $corepackHome, $nodeConfigHome)) {
        $null = New-Item -ItemType Directory -Path $privateDirectory -Force
    }
    [Environment]::SetEnvironmentVariable(
        "CARGO_HOME", $cargoHome, [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "CARGO_TARGET_DIR", $null, [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "CARGO_BUILD_TARGET_DIR", $null, [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "RUSTC", $toolchain.Rustc, [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "CARGO_BUILD_RUSTC", $toolchain.Rustc, [EnvironmentVariableTarget]::Process)
    foreach ($clearedCompilerVariable in @(
            "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "NODE_OPTIONS")) {
        [Environment]::SetEnvironmentVariable(
            $clearedCompilerVariable,
            $null,
            [EnvironmentVariableTarget]::Process)
    }
    [Environment]::SetEnvironmentVariable(
        "RUSTUP_TOOLCHAIN",
        $sourceBinding.RustupToolchain,
        [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "PNPM_HOME", $pnpmHome, [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "COREPACK_HOME", $corepackHome, [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "NPM_CONFIG_USERCONFIG", $npmUserConfig, [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "XDG_CONFIG_HOME", $nodeConfigHome, [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "CI", "true", [EnvironmentVariableTarget]::Process)

    # These values are derived from the exact selected certificate Publisher
    # and are compiled into the signed CORE image. Runtime/task configuration
    # cannot substitute another package as the private peer.
    [Environment]::SetEnvironmentVariable(
        "STEIN_PRODUCTION_PACKAGE_FAMILY_NAME",
        $packageFamilyName,
        [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "STEIN_PRODUCTION_BROKER_AUMID",
        $brokerAumid,
        [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "STEIN_EDGE_EXTENSION_ID",
        $EdgeExtensionId,
        [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "STEIN_EDGE_EXTENSION_VERSION",
        $EdgeExtensionVersion,
        [EnvironmentVariableTarget]::Process)

    if ((Test-Path -LiteralPath $desktopDistRoot) -or
        (Test-Path -LiteralPath $desktopNodeModules)) {
        throw "The private candidate snapshot contains stale renderer output."
    }
    Push-Location $candidateRoot
    try {
        & $toolchain.Node $toolchain.PnpmEntrypoint `
            --dir $desktopRoot `
            install `
            --frozen-lockfile `
            --store-dir $pnpmStore `
            --package-import-method copy `
            --config.node-linker=hoisted
        Assert-NativeCommandSucceeded -Operation "private desktop dependency install"
        if (Test-Path -LiteralPath $desktopDistRoot) {
            throw "Desktop dependency installation produced stale renderer output."
        }
        & $toolchain.Node $toolchain.PnpmEntrypoint `
            --dir $desktopRoot `
            run build
        Assert-NativeCommandSucceeded -Operation "fresh desktop renderer build"
    }
    finally {
        Pop-Location
    }
    $distLocks = Open-SteinPackageDirectoryManifestLock `
        -Root $desktopDistRoot `
        -Domain "stein-desktop-dist-manifest-v1"
    $postRendererSnapshot = Open-SteinExactCandidateSnapshotLocks `
        -Snapshot $snapshot `
        -AllowedAdditionalRelativeRoots @(
            "apps/desktop/node_modules", "apps/desktop/dist")
    foreach ($stream in $postRendererSnapshot.Streams) { $stream.Dispose() }

    Push-Location $candidateRoot
    try {
        & $toolchain.Cargo build `
            --release `
            --locked `
            --target-dir $workspaceTargetRoot `
            --manifest-path (Join-Path $candidateRoot "Cargo.toml") `
            --package stein-core-daemon `
            --features "stein-core-daemon/production-private-endpoint,stein-core-daemon/production-edge-producer" `
            --package stein-cli `
            --package stein-desktop
        Assert-NativeCommandSucceeded -Operation "private Rust CORE/desktop release build"
    }
    finally {
        Pop-Location
    }

    $coreExecutable = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $workspaceTargetRoot `
        -Path (Join-Path $workspaceTargetRoot "release\stein-core.exe")
    $cliExecutable = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $workspaceTargetRoot `
        -Path (Join-Path $workspaceTargetRoot "release\stein-cli.exe")
    $desktopExecutable = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $workspaceTargetRoot `
        -Path (Join-Path $workspaceTargetRoot "release\stein-desktop.exe")
    $desktopDigest = Get-SteinPackageFileSha256 -Path $desktopExecutable
    $desktopExecutableLock = Open-SteinPackageVerifiedFileLock `
        -Path $desktopExecutable `
        -ExpectedSha256 $desktopDigest
    $desktopSize = [long]$desktopExecutableLock.Size

    # CORE is intentionally installed outside the MSIX under Task Scheduler.
    # Sign it first, then bind the broker build to the exact signed bytes.
    & $signTool sign `
        /sha1 $normalizedThumbprint `
        /fd SHA256 `
        /tr $TimestampUrl `
        /td SHA256 `
        $coreExecutable *> $null
    Assert-NativeCommandSucceeded -Operation "CORE Authenticode signing"
    & $signTool verify /pa /all /v $coreExecutable *> $null
    Assert-NativeCommandSucceeded -Operation "CORE Authenticode verification"
    $coreSignature = Get-AuthenticodeSignature -LiteralPath $coreExecutable
    if ($coreSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $coreSignature.SignerCertificate -or
        $coreSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $normalizedThumbprint) {
        throw "CORE signature is not valid under the exact selected certificate."
    }

    # The external diagnostic CLI is an independently signed companion used
    # for readiness, shutdown, and support. It never receives private-client
    # assurance, but lifecycle tooling must still deploy a verified release.
    & $signTool sign `
        /sha1 $normalizedThumbprint `
        /fd SHA256 `
        /tr $TimestampUrl `
        /td SHA256 `
        $cliExecutable *> $null
    Assert-NativeCommandSucceeded -Operation "diagnostic CLI Authenticode signing"
    & $signTool verify /pa /all /v $cliExecutable *> $null
    Assert-NativeCommandSucceeded -Operation "diagnostic CLI Authenticode verification"
    $cliSignature = Get-AuthenticodeSignature -LiteralPath $cliExecutable
    if ($cliSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $cliSignature.SignerCertificate -or
        $cliSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $normalizedThumbprint -or
        $cliSignature.SignerCertificate.Subject -cne $Publisher) {
        throw "Diagnostic CLI signature is not valid under the exact selected certificate."
    }

    $coreDigest = Get-SteinPackageFileSha256 -Path $coreExecutable
    $cliDigest = Get-SteinPackageFileSha256 -Path $cliExecutable
    $coreExecutableLock = Open-SteinPackageVerifiedFileLock `
        -Path $coreExecutable `
        -ExpectedSha256 $coreDigest
    $cliExecutableLock = Open-SteinPackageVerifiedFileLock `
        -Path $cliExecutable `
        -ExpectedSha256 $cliDigest
    $coreSize = [long]$coreExecutableLock.Size
    $cliSize = [long]$cliExecutableLock.Size
    [Environment]::SetEnvironmentVariable(
        "STEIN_CORE_EXECUTABLE_SHA256",
        $coreDigest,
        [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "STEIN_EDGE_PUBLISHER_SHA256",
        $EdgePublisherSha256,
        [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "STEIN_EDGE_HOST_PUBLISHER_SHA256",
        $hostPublisherSha256,
        [EnvironmentVariableTarget]::Process)

    Push-Location $candidateRoot
    try {
        & $toolchain.Cargo build `
            --release `
            --locked `
            --target-dir $edgeTargetRoot `
            --manifest-path (Join-Path $candidateRoot "apps\edge-native-host\Cargo.toml") `
            --features production-edge-host
        Assert-NativeCommandSucceeded -Operation "private Edge native host release build"
    }
    finally {
        Pop-Location
    }
    $hostExecutable = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $edgeTargetRoot `
        -Path (Join-Path $edgeTargetRoot "release\stein-edge-native-host.exe")
    & $signTool sign `
        /sha1 $normalizedThumbprint `
        /fd SHA256 `
        /tr $TimestampUrl `
        /td SHA256 `
        $hostExecutable *> $null
    Assert-NativeCommandSucceeded -Operation "Edge native host Authenticode signing"
    $null = Assert-SteinExactAuthenticodeSignature `
        -Path $hostExecutable `
        -CertificateThumbprint $normalizedThumbprint `
        -Publisher $Publisher
    $hostDigest = Get-SteinPackageFileSha256 -Path $hostExecutable
    $hostExecutableLock = Open-SteinPackageVerifiedFileLock `
        -Path $hostExecutable `
        -ExpectedSha256 $hostDigest

    Push-Location $candidateRoot
    try {
        & $toolchain.Cargo build `
            --release `
            --locked `
            --target-dir $workspaceTargetRoot `
            --manifest-path (Join-Path $candidateRoot "Cargo.toml") `
            --package stein-private-broker
        Assert-NativeCommandSucceeded -Operation "private broker release build"
    }
    finally {
        Pop-Location
    }
    $brokerExecutable = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $workspaceTargetRoot `
        -Path (Join-Path $workspaceTargetRoot "release\stein-private-broker.exe")
    $brokerDigest = Get-SteinPackageFileSha256 -Path $brokerExecutable
    $brokerExecutableLock = Open-SteinPackageVerifiedFileLock `
        -Path $brokerExecutable `
        -ExpectedSha256 $brokerDigest

    $completedDist = Open-SteinPackageDirectoryManifestLock `
        -Root $desktopDistRoot `
        -Domain "stein-desktop-dist-manifest-v1"
    try {
        if ($completedDist.FileCount -ne $distLocks.FileCount -or
            $completedDist.TotalSize -ne $distLocks.TotalSize -or
            $completedDist.ManifestSha256 -cne $distLocks.ManifestSha256) {
            throw "The fresh renderer output changed during the desktop build."
        }
    }
    finally {
        foreach ($stream in $completedDist.Streams) { $stream.Dispose() }
    }
    $completedSnapshot = Open-SteinExactCandidateSnapshotLocks `
        -Snapshot $snapshot `
        -AllowedAdditionalRelativeRoots @(
            "apps/desktop/node_modules", "apps/desktop/dist")
    foreach ($stream in $completedSnapshot.Streams) { $stream.Dispose() }
    $null = Assert-SteinVerifiedBuildToolchainLocks -Toolchain $toolchain

    $null = New-Item -ItemType Directory -Path (Join-Path $stagingRoot "bin") -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $stagingRoot "Assets") -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $stagingRoot "Metadata") -Force
    Copy-Item -LiteralPath $desktopExecutable -Destination (Join-Path $stagingRoot "bin\stein-desktop.exe")
    Copy-Item -LiteralPath $brokerExecutable -Destination (Join-Path $stagingRoot "bin\stein-private-broker.exe")
    Copy-Item -LiteralPath $hostExecutable -Destination (Join-Path $stagingRoot "bin\stein-edge-native-host.exe")

    $coreBindingJson = [ordered]@{
        schema_version = 3
        core_executable_sha256 = $coreDigest
        cli_executable_size = $cliSize
        cli_executable_sha256 = $cliDigest
        desktop_executable_size = $desktopSize
        desktop_executable_sha256 = $desktopDigest
        desktop_dist_file_count = $distLocks.FileCount
        desktop_dist_manifest_sha256 = $distLocks.ManifestSha256
        candidate_git_commit = $sourceBinding.CandidateGitCommit
        candidate_git_tree = $sourceBinding.CandidateGitTree
        source_verification_sha256 = $sourceBinding.SourceVerificationSha256
        source_root_anchor_sha256 = $sourceBinding.SourceRootAnchorSha256
        source_root_digest_sha256 = $sourceBinding.SourceRootDigestSha256
    } | ConvertTo-Json
    [IO.File]::WriteAllText(
        (Join-Path $stagingRoot "Metadata\CoreBinding.json"),
        $coreBindingJson,
        [Text.UTF8Encoding]::new($false))
    $null = Test-SteinCoreBindingContract `
        -BindingPath (Join-Path $stagingRoot "Metadata\CoreBinding.json") `
        -ExpectedCoreSha256 $coreDigest `
        -ExpectedCliSize $cliSize `
        -ExpectedCliSha256 $cliDigest `
        -ExpectedDesktopSize $desktopSize `
        -ExpectedDesktopSha256 $desktopDigest `
        -ExpectedDesktopDistFileCount $distLocks.FileCount `
        -ExpectedDesktopDistManifestSha256 $distLocks.ManifestSha256 `
        -ExpectedCandidateGitCommit $sourceBinding.CandidateGitCommit `
        -ExpectedCandidateGitTree $sourceBinding.CandidateGitTree `
        -ExpectedSourceVerificationSha256 $sourceBinding.SourceVerificationSha256 `
        -ExpectedSourceRootAnchorSha256 $sourceBinding.SourceRootAnchorSha256 `
        -ExpectedSourceRootDigestSha256 $sourceBinding.SourceRootDigestSha256

    foreach ($assetName in @("StoreLogo", "Square44x44Logo", "Square150x150Logo")) {
        $encoded = (Get-Content -LiteralPath (Join-Path $assetSource "$assetName.png.base64") -Raw).Trim()
        [IO.File]::WriteAllBytes(
            (Join-Path $stagingRoot "Assets\$assetName.png"),
            [Convert]::FromBase64String($encoded))
    }

    $manifest = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8
    $manifest = $manifest.Replace("{{PUBLISHER}}", [Security.SecurityElement]::Escape($Publisher))
    $manifest = $manifest.Replace(
        "{{PUBLISHER_DISPLAY_NAME}}",
        [Security.SecurityElement]::Escape($PublisherDisplayName))
    $manifest = $manifest.Replace("{{VERSION}}", $Version)
    if ($manifest.Contains("{{")) {
        throw "Manifest rendering left an unresolved placeholder."
    }
    $renderedManifest = Join-Path $stagingRoot "AppxManifest.xml"
    Set-Content -LiteralPath $renderedManifest -Value $manifest -Encoding UTF8
    $null = Test-SteinManifestContract `
        -ManifestPath $renderedManifest `
        -ExpectedPublisher $Publisher `
        -ExpectedVersion $Version `
        -PackageRoot $stagingRoot

    $stagingLocks = Open-SteinPackageDirectoryManifestLock `
        -Root $stagingRoot `
        -Domain "stein-msix-staging-manifest-v1"
    $null = Assert-SteinFixedApplicationPayloadMapsEqual `
        -ExpectedFiles @($stagingLocks.Files) `
        -ActualFiles @($stagingLocks.Files)
    $null = Assert-SteinFixedApplicationPayloadFileIdentity `
        -Files @($stagingLocks.Files) `
        -RelativePath "bin\stein-desktop.exe" `
        -ExpectedSize ([long]$desktopExecutableLock.Size) `
        -ExpectedSha256 $desktopDigest
    $null = Assert-SteinFixedApplicationPayloadFileIdentity `
        -Files @($stagingLocks.Files) `
        -RelativePath "bin\stein-edge-native-host.exe" `
        -ExpectedSize ([long]$hostExecutableLock.Size) `
        -ExpectedSha256 $hostDigest
    $null = Assert-SteinFixedApplicationPayloadFileIdentity `
        -Files @($stagingLocks.Files) `
        -RelativePath "bin\stein-private-broker.exe" `
        -ExpectedSize ([long]$brokerExecutableLock.Size) `
        -ExpectedSha256 $brokerDigest
    $stagingMappingLock = New-SteinPackageLockedMakeAppxMapping `
        -StagingManifest $stagingLocks `
        -MappingPath (Join-Path $buildRoot "makeappx.map.txt")

    & $makeAppx pack /f $stagingMappingLock.Path /p $packageTemporaryPath /o *> $null
    Assert-NativeCommandSucceeded -Operation "MakeAppx package creation"

    & $signTool sign `
        /sha1 $normalizedThumbprint `
        /fd SHA256 `
        /tr $TimestampUrl `
        /td SHA256 `
        $packageTemporaryPath *> $null
    Assert-NativeCommandSucceeded -Operation "MSIX signing"

    $packageVerificationResults = @(& (Join-Path `
            $candidateRoot `
            "packaging\windows-msix\Verify-Msix.ps1") `
        -PackagePath $packageTemporaryPath `
        -CertificateThumbprint $normalizedThumbprint `
        -Publisher $Publisher `
        -Version $Version `
        -ExpectedCoreSha256 $coreDigest `
        -ExpectedHostSha256 $hostDigest `
        -ExpectedCliSize $cliSize `
        -ExpectedCliSha256 $cliDigest `
        -ExpectedDesktopSize $desktopSize `
        -ExpectedDesktopSha256 $desktopDigest `
        -ExpectedDesktopDistFileCount $distLocks.FileCount `
        -ExpectedDesktopDistManifestSha256 $distLocks.ManifestSha256 `
        -ExpectedCandidateGitCommit $sourceBinding.CandidateGitCommit `
        -ExpectedCandidateGitTree $sourceBinding.CandidateGitTree `
        -ExpectedSourceVerificationSha256 $sourceBinding.SourceVerificationSha256 `
        -ExpectedSourceRootAnchorSha256 $sourceBinding.SourceRootAnchorSha256 `
        -ExpectedSourceRootDigestSha256 $sourceBinding.SourceRootDigestSha256)
    if ($packageVerificationResults.Count -ne 1) {
        throw "MSIX verification did not return one exact byte identity."
    }
    $packageVerification = $packageVerificationResults[0]
    $null = Assert-SteinFixedApplicationPayloadMapsEqual `
        -ExpectedFiles @($stagingLocks.Files) `
        -ActualFiles @($packageVerification.InstalledPayloadFiles)
    if (-not (Test-SteinPackageSha256Value -Value ([string]$packageVerification.Sha256)) -or
        $packageVerification.CliExecutableSize -ne $cliSize -or
        $packageVerification.CliExecutableSha256 -cne $cliDigest -or
        $packageVerification.DesktopExecutableSize -ne $desktopSize -or
        $packageVerification.DesktopExecutableSha256 -cne $desktopDigest -or
        $packageVerification.DesktopDistFileCount -ne $distLocks.FileCount -or
        $packageVerification.DesktopDistManifestSha256 -cne
            $distLocks.ManifestSha256 -or
        $packageVerification.CandidateGitCommit -cne $sourceBinding.CandidateGitCommit -or
        $packageVerification.CandidateGitTree -cne $sourceBinding.CandidateGitTree -or
        $packageVerification.SourceVerificationSha256 -cne $sourceBinding.SourceVerificationSha256 -or
        $packageVerification.SourceRootAnchorSha256 -cne $sourceBinding.SourceRootAnchorSha256 -or
        $packageVerification.SourceRootDigestSha256 -cne $sourceBinding.SourceRootDigestSha256) {
        throw "MSIX verification did not reproduce the exact signed source binding."
    }
    $verifiedPackageSha256 = [string]$packageVerification.Sha256
    $verifiedPackageSize = (Get-Item -LiteralPath $packageTemporaryPath -Force).Length

    # Publish the exact signed CORE bytes that were hashed into the broker.
    # The installer consumes this companion file; it must never rebuild or
    # select another target\release artifact after the broker was compiled.
    $finalCoreDigest = (Get-FileHash -LiteralPath $coreExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($finalCoreDigest -cne $coreDigest) {
        throw "The signed CORE executable changed after the broker digest was pinned."
    }
    Copy-Item -LiteralPath $coreExecutable -Destination $coreCompanionTemporaryPath
    $companionDigest = (Get-FileHash -LiteralPath $coreCompanionTemporaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($companionDigest -cne $coreDigest) {
        throw "The published CORE companion does not match the broker-pinned bytes."
    }
    $companionSignature = Get-AuthenticodeSignature -LiteralPath $coreCompanionTemporaryPath
    if ($companionSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $companionSignature.SignerCertificate -or
        $companionSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $normalizedThumbprint -or
        $companionSignature.SignerCertificate.Subject -cne $Publisher) {
        throw "The published CORE companion does not carry the exact selected signature."
    }
    $verifiedCoreCompanionSize = (Get-Item `
            -LiteralPath $coreCompanionTemporaryPath `
            -Force).Length
    Copy-Item -LiteralPath $cliExecutable -Destination $cliCompanionTemporaryPath
    $cliCompanionDigest = (Get-FileHash -LiteralPath $cliCompanionTemporaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($cliCompanionDigest -cne $cliDigest) {
        throw "The published diagnostic CLI does not match the signed release bytes."
    }
    $cliCompanionSignature = Get-AuthenticodeSignature -LiteralPath $cliCompanionTemporaryPath
    if ($cliCompanionSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $cliCompanionSignature.SignerCertificate -or
        $cliCompanionSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $normalizedThumbprint -or
        $cliCompanionSignature.SignerCertificate.Subject -cne $Publisher) {
        throw "The published diagnostic CLI does not carry the exact selected signature."
    }
    $verifiedCliCompanionSize = (Get-Item `
            -LiteralPath $cliCompanionTemporaryPath `
            -Force).Length
    $identityRecord = [ordered] @{
        identity_schema_version = 3
        package_name = $script:ProductionPackageName
        publisher = $Publisher
        package_family_name = $packageFamilyName
        desktop_aumid = "$packageFamilyName!$script:DesktopApplicationId"
        broker_aumid = $brokerAumid
        browser_producer_aumid = $browserProducerAumid
        version = $Version
        architecture = "x64"
        signing_certificate_thumbprint = $normalizedThumbprint
        core_executable_file = (Split-Path -Leaf $coreCompanionPath)
        core_executable_size = $verifiedCoreCompanionSize
        core_executable_sha256 = $coreDigest
        browser_host_sha256 = $hostDigest
        candidate_git_commit = $sourceBinding.CandidateGitCommit
        candidate_git_tree = $sourceBinding.CandidateGitTree
        source_verification_sha256 = $sourceBinding.SourceVerificationSha256
        source_root_anchor_sha256 = $sourceBinding.SourceRootAnchorSha256
        source_root_digest_sha256 = $sourceBinding.SourceRootDigestSha256
        desktop_executable_size = $desktopSize
        desktop_executable_sha256 = $desktopDigest
        desktop_dist_file_count = $distLocks.FileCount
        desktop_dist_manifest_sha256 = $distLocks.ManifestSha256
        cli_executable_file = (Split-Path -Leaf $cliCompanionPath)
        cli_executable_size = $verifiedCliCompanionSize
        cli_executable_sha256 = $cliDigest
        msix_size = $verifiedPackageSize
        msix_sha256 = $verifiedPackageSha256
    }
    $identityJson = $identityRecord | ConvertTo-Json
    $identityExpectedSize = [Text.UTF8Encoding]::new($false).GetByteCount($identityJson)
    $identityExpectedSha256 = Get-SteinPackageTextSha256 -Value $identityJson
    [IO.File]::WriteAllText(
        $identityTemporaryPath,
        $identityJson,
        [Text.UTF8Encoding]::new($false))
    $browserIdentityJson = [ordered] @{
        identity_schema_version = 1
        package_family_name = $packageFamilyName
        package_version = $Version
        browser_producer_aumid = $browserProducerAumid
        browser_host_relative_path = "bin\stein-edge-native-host.exe"
        browser_host_sha256 = $hostDigest
        browser_host_publisher_sha256 = $hostPublisherSha256
        edge_extension_id = $EdgeExtensionId
        edge_extension_version = $EdgeExtensionVersion
        edge_publisher_sha256 = $EdgePublisherSha256
        installed_runtime_admission = "not_run_requires_direct_edge_launch_fixture"
    } | ConvertTo-Json
    $browserIdentityExpectedSize = [Text.UTF8Encoding]::new($false).GetByteCount(
        $browserIdentityJson)
    $browserIdentityExpectedSha256 = Get-SteinPackageTextSha256 `
        -Value $browserIdentityJson
    [IO.File]::WriteAllText(
        $browserIdentityTemporaryPath,
        $browserIdentityJson,
        [Text.UTF8Encoding]::new($false))

    $publicationSnapshot = Open-SteinExactCandidateSnapshotLocks `
        -Snapshot $snapshot `
        -AllowedAdditionalRelativeRoots @(
            "apps/desktop/node_modules", "apps/desktop/dist")
    foreach ($stream in $publicationSnapshot.Streams) { $stream.Dispose() }
    $null = Assert-SteinVerifiedBuildToolchainLocks -Toolchain $toolchain
    if ((Get-SteinPackageStreamSha256 -Stream $candidateBuildScriptLock.Stream) -cne
            $candidateBuildScriptLock.Sha256 -or
        (Get-SteinPackageStreamSha256 -Stream $candidatePackageToolsLock.Stream) -cne
            $candidatePackageToolsLock.Sha256) {
        throw "A running packaging script changed during signed release generation."
    }

    $publicationEntries = @(
        [pscustomobject]@{
            Temporary = $packageTemporaryPath
            Final = $outputPath
            Backup = "$outputPath.$publicationId.backup"
            ExpectedSize = $verifiedPackageSize
            ExpectedSha256 = $verifiedPackageSha256
        },
        [pscustomobject]@{
            Temporary = $coreCompanionTemporaryPath
            Final = $coreCompanionPath
            Backup = "$coreCompanionPath.$publicationId.backup"
            ExpectedSize = $verifiedCoreCompanionSize
            ExpectedSha256 = $coreDigest
        },
        [pscustomobject]@{
            Temporary = $cliCompanionTemporaryPath
            Final = $cliCompanionPath
            Backup = "$cliCompanionPath.$publicationId.backup"
            ExpectedSize = $verifiedCliCompanionSize
            ExpectedSha256 = $cliDigest
        },
        [pscustomobject]@{
            Temporary = $identityTemporaryPath
            Final = $identityPath
            Backup = "$identityPath.$publicationId.backup"
            ExpectedSize = $identityExpectedSize
            ExpectedSha256 = $identityExpectedSha256
        },
        [pscustomobject]@{
            Temporary = $browserIdentityTemporaryPath
            Final = $browserIdentityPath
            Backup = "$browserIdentityPath.$publicationId.backup"
            ExpectedSize = $browserIdentityExpectedSize
            ExpectedSha256 = $browserIdentityExpectedSha256
        }
    )
    $null = Publish-SteinVerifiedReleaseArtifactSet `
        -OutputRoot $outputParent `
        -Entries $publicationEntries

    Write-Output "Created and verified signed MSIX: $outputPath"
    Write-Output "Published broker-pinned signed CORE: $coreCompanionPath"
    Write-Output "Published signed diagnostic CLI: $cliCompanionPath"
    Write-Output "Recorded exact package identities: $identityPath"
    Write-Output "Recorded blocked browser producer identity: $browserIdentityPath"
}
catch {
    $buildOperationFailure = $_
}
finally {
    try {
        if ($null -ne $stagingMappingLock) {
            $stagingMappingLock.Stream.Dispose()
        }
        if ($null -ne $stagingLocks) {
            foreach ($stream in $stagingLocks.Streams) { $stream.Dispose() }
        }
        foreach ($lockedExecutable in @(
                $desktopExecutableLock,
                $coreExecutableLock,
                $cliExecutableLock,
                $hostExecutableLock,
                $brokerExecutableLock)) {
            if ($null -ne $lockedExecutable) { $lockedExecutable.Stream.Dispose() }
        }
        if ($null -ne $distLocks) {
            foreach ($stream in $distLocks.Streams) { $stream.Dispose() }
        }
        if ($null -ne $sourceLocks) {
            foreach ($stream in $sourceLocks.Streams) { $stream.Dispose() }
        }
        foreach ($lockedTool in $toolchain.Locks) { $lockedTool.Stream.Dispose() }
        foreach ($environmentName in @($previousEnvironment.Keys)) {
            [Environment]::SetEnvironmentVariable(
                [string]$environmentName,
                $previousEnvironment[$environmentName],
                [EnvironmentVariableTarget]::Process)
        }
        foreach ($temporaryReleasePath in @(
                $coreCompanionTemporaryPath,
                $cliCompanionTemporaryPath,
                $packageTemporaryPath,
                $identityTemporaryPath,
                $browserIdentityTemporaryPath)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$temporaryReleasePath) -and
                (Test-Path -LiteralPath $temporaryReleasePath)) {
                Remove-Item -LiteralPath $temporaryReleasePath -Force -ErrorAction Stop
            }
        }
        if (Test-Path -LiteralPath $buildRoot) {
            Remove-SteinPackagePrivateTemporaryDirectory `
                -Path $buildRoot `
                -Purpose "build"
        }
    }
    catch {
        $buildCleanupFailure = $_
    }
}
$buildResolvedFailure = Resolve-SteinPackagePrimaryAndCleanupFailure `
    -PrimaryFailure $buildOperationFailure `
    -CleanupFailure $buildCleanupFailure
if ($null -ne $buildResolvedFailure) {
    throw $buildResolvedFailure
}
}
catch {
    $buildBootstrapFailure = $_
}
finally {
    foreach ($binding in $buildBootstrapBindings) {
        try {
            $null = Assert-SteinBuildBootstrapScriptBindingStable -Binding $binding
        }
        catch {
            if ($null -eq $buildBootstrapFailure) {
                $buildBootstrapFailure = $_
            }
        }
        finally {
            $binding.Stream.Dispose()
        }
    }
}
if ($null -ne $buildBootstrapFailure) {
    throw $buildBootstrapFailure
}
