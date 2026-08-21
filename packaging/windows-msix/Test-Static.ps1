[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "PackageTools.ps1")

function Remove-SteinStaticTemporaryLeaf {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $temporaryRoot = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path ([IO.Path]::GetTempPath())
    $fullPath = [IO.Path]::GetFullPath($Path)
    $parentPath = [IO.Path]::GetFullPath((Split-Path -Parent $fullPath)).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $leafName = Split-Path -Leaf $fullPath
    if (-not [string]::Equals(
            $parentPath,
            $temporaryRoot,
            [StringComparison]::OrdinalIgnoreCase) -or
        $leafName -notmatch '^stein-[A-Za-z0-9.-]+$') {
        throw "A static-test cleanup target escaped the exact temporary leaf boundary."
    }

    $rootItem = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    $rootIsReparse = (($rootItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0)
    if ($rootIsReparse) {
        if ($rootItem.PSIsContainer) {
            [IO.Directory]::Delete($fullPath, $false)
        }
        else {
            [IO.File]::Delete($fullPath)
        }
        return
    }
    if (-not $rootItem.PSIsContainer) {
        [IO.File]::SetAttributes($fullPath, [IO.FileAttributes]::Normal)
        [IO.File]::Delete($fullPath)
        return
    }

    $pending = New-Object Collections.Generic.Stack[string]
    $directories = New-Object Collections.Generic.List[string]
    $pending.Push($fullPath)
    while ($pending.Count -gt 0) {
        $directoryPath = $pending.Pop()
        $directoryItem = Get-Item `
            -LiteralPath $directoryPath `
            -Force `
            -ErrorAction Stop
        if (-not $directoryItem.PSIsContainer) {
            throw "A static-test cleanup directory changed type."
        }
        if (($directoryItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            [IO.Directory]::Delete($directoryPath, $false)
            continue
        }
        $directories.Add($directoryPath)
        foreach ($candidate in @(Get-ChildItem `
                    -LiteralPath $directoryPath `
                    -Force `
                    -ErrorAction Stop)) {
            $candidatePath = [IO.Path]::GetFullPath($candidate.FullName)
            if (-not $candidatePath.StartsWith(
                    "$fullPath$([IO.Path]::DirectorySeparatorChar)",
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "A static-test cleanup entry escaped its exact temporary leaf."
            }
            $item = Get-Item `
                -LiteralPath $candidatePath `
                -Force `
                -ErrorAction Stop
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                if ($item.PSIsContainer) {
                    [IO.Directory]::Delete($candidatePath, $false)
                }
                else {
                    [IO.File]::Delete($candidatePath)
                }
            }
            elseif ($item.PSIsContainer) {
                $pending.Push($candidatePath)
            }
            else {
                [IO.File]::SetAttributes(
                    $candidatePath,
                    [IO.FileAttributes]::Normal)
                [IO.File]::Delete($candidatePath)
            }
        }
    }
    for ($index = $directories.Count - 1; $index -ge 0; $index--) {
        $directoryPath = $directories[$index]
        $directoryItem = Get-Item `
            -LiteralPath $directoryPath `
            -Force `
            -ErrorAction Stop
        if (-not $directoryItem.PSIsContainer) {
            throw "A static-test cleanup directory changed type."
        }
        [IO.Directory]::Delete($directoryPath, $false)
    }
}

foreach ($unsafeSnapshotPath in @(
        "source/foo:bar.rs",
        "source/CON/file.rs",
        "source/trailing-dot./file.rs",
        "source/trailing-space /file.rs")) {
    if (Test-SteinPackageSafeWindowsRelativePath -Value $unsafeSnapshotPath) {
        throw "The exact candidate snapshot accepted a Windows-unsafe path."
    }
}

$aclFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-acl-static-" + [Guid]::NewGuid().ToString("N"))
try {
    $aclRootItem = New-Item `
        -ItemType Directory `
        -Path $aclFixtureRoot `
        -ErrorAction Stop
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $everyoneSid = [Security.Principal.SecurityIdentifier]::new("S-1-1-0")
    $aclSecurity = Get-SteinPackageFileSystemSecurity -Item $aclRootItem
    $aclSecurity.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($aclSecurity.GetAccessRules(
                $true,
                $true,
                [Security.Principal.SecurityIdentifier]))) {
        $aclSecurity.RemoveAccessRuleSpecific($rule)
    }
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $aclSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $currentSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    $aclSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $everyoneSid,
            [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    Set-SteinPackageFileSystemSecurity `
        -Item $aclRootItem `
        -Security $aclSecurity
    $inheritedBroadDirectory = Join-Path $aclFixtureRoot "inherited-broad"
    $null = New-Item `
        -ItemType Directory `
        -Path $inheritedBroadDirectory `
        -ErrorAction Stop
    $inheritedBroadAclRejected = $false
    try {
        $null = Assert-SteinPackageOwnerOnlyDirectory `
            -Path $inheritedBroadDirectory
    }
    catch { $inheritedBroadAclRejected = $true }
    if (-not $inheritedBroadAclRejected) {
        throw "The private temporary-root ACL contract accepted inherited broad access."
    }
}
finally {
    if (Test-Path -LiteralPath $aclFixtureRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $aclFixtureRoot
    }
}

$junctionTargetRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-junction-target-" + [Guid]::NewGuid().ToString("N"))
$privateCleanupRoot = $null
try {
    $null = New-Item `
        -ItemType Directory `
        -Path $junctionTargetRoot `
        -ErrorAction Stop
    $junctionMarker = Join-Path $junctionTargetRoot "survives.txt"
    [IO.File]::WriteAllText(
        $junctionMarker,
        "external junction target",
        [Text.UTF8Encoding]::new($false))
    $privateCleanupRoot = New-SteinPackagePrivateTemporaryDirectory `
        -Purpose "build"
    $null = New-Item `
        -ItemType Junction `
        -Path (Join-Path $privateCleanupRoot "external-link") `
        -Target $junctionTargetRoot `
        -ErrorAction Stop
    Remove-SteinPackagePrivateTemporaryDirectory `
        -Path $privateCleanupRoot `
        -Purpose "build"
    $privateCleanupRoot = $null
    if (-not (Test-Path -LiteralPath $junctionMarker -PathType Leaf)) {
        throw "Private temporary cleanup traversed an external junction target."
    }
}
finally {
    if ($null -ne $privateCleanupRoot -and
        (Test-Path -LiteralPath $privateCleanupRoot)) {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $privateCleanupRoot `
            -Purpose "build"
    }
    if (Test-Path -LiteralPath $junctionTargetRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $junctionTargetRoot
    }
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$manifestPath = Join-Path $PSScriptRoot "AppxManifest.xml.in"
$contract = Test-SteinManifestContract -ManifestPath $manifestPath
if ($contract.Publisher -cne "{{PUBLISHER}}" -or $contract.Version -cne "{{VERSION}}") {
    throw "Source manifest must require explicit Publisher and version rendering."
}
$staticFamily = Get-ExactPackageFamilyName `
    -PackageName $script:ProductionPackageName `
    -Publisher "CN=STEIN Static Validation"
if ($staticFamily -notmatch "^STEIN\.PersonalIntelligence_[a-hj-km-np-tv-z0-9]{13}$" -or
    "$staticFamily!$script:DesktopApplicationId" -notmatch "!Desktop$" -or
    "$staticFamily!$script:BrokerApplicationId" -notmatch "!PrivateBroker$" -or
    "$staticFamily!$script:BrowserProducerApplicationId" -notmatch "!BrowserObservationProducer$") {
    throw "Windows could not derive the stable PFN/AUMID shape."
}

Add-Type -AssemblyName System.Drawing
$expectedAssets = @{
    "StoreLogo" = 50
    "Square44x44Logo" = 44
    "Square150x150Logo" = 150
}
foreach ($asset in $expectedAssets.GetEnumerator()) {
    $encodedPath = Join-Path $PSScriptRoot "assets\$($asset.Key).png.base64"
    $bytes = [Convert]::FromBase64String((Get-Content -LiteralPath $encodedPath -Raw).Trim())
    $stream = [IO.MemoryStream]::new($bytes, $false)
    try {
        $image = [Drawing.Image]::FromStream($stream, $true, $true)
        try {
            if ($image.RawFormat.Guid -ne [Drawing.Imaging.ImageFormat]::Png.Guid -or
                $image.Width -ne $asset.Value -or
                $image.Height -ne $asset.Value) {
                throw "A package asset is not the required PNG dimension."
            }
        }
        finally {
            $image.Dispose()
        }
    }
    finally {
        $stream.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

$buildScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot "Build-Msix.ps1") -Raw
$cliManifest = Get-Content -LiteralPath (Join-Path $repoRoot "apps\core-cli\Cargo.toml") -Raw
$cliPackageMatch = [regex]::Match(
    $cliManifest,
    '(?m)^name\s*=\s*"(?<name>[a-z0-9_-]+)"\s*$')
if (-not $cliPackageMatch.Success -or
    $cliPackageMatch.Groups["name"].Value -cne "stein-cli" -or
    $buildScript.IndexOf("--package stein-cli", [StringComparison]::Ordinal) -lt 0 -or
    $buildScript.IndexOf("--package stein-core-cli", [StringComparison]::Ordinal) -ge 0 -or
    ([regex]::Matches($buildScript, '(?m)^\s*--locked\b')).Count -ne 3) {
    throw "The signed build does not select the exact Cargo package/lockfile set."
}
$forbiddenCertificateMutations = @(
    "New-SelfSignedCertificate",
    "Import-Certificate",
    "Import-PfxCertificate",
    "certutil -addstore",
    "Add-AppxPackage"
)
foreach ($forbidden in $forbiddenCertificateMutations) {
    if ($buildScript.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Build script contains a forbidden certificate/install mutation."
    }
}
foreach ($required in @(
    "makeappx",
    "signtool",
    "STEIN_CORE_EXECUTABLE_SHA256",
    "STEIN_PRODUCTION_PACKAGE_FAMILY_NAME",
    "STEIN_PRODUCTION_BROKER_AUMID",
    "stein-core-daemon/production-private-endpoint",
    "stein-core-daemon/production-edge-producer",
    "STEIN_EDGE_EXTENSION_ID",
    "STEIN_EDGE_EXTENSION_VERSION",
    "stein-edge-native-host.exe",
    "not_run_requires_direct_edge_launch_fixture",
    "core_executable_file",
    "coreCompanionPath",
    "cli_executable_file",
    "cliCompanionPath",
    "identity_schema_version",
    "msix_size",
    "ExpectedCandidateGitCommit",
    "ExpectedCandidateGitTree",
    "SourceVerificationReportPath",
    "SourceRootAnchorPath",
    "ExpectedSourceVerificationSha256",
    "ExpectedSourceRootAnchorSha256",
    "Get-SteinVerifiedSourceBuildBinding",
    "Get-SteinVerifiedBuildToolchain",
    "New-SteinExactGitCandidateSnapshot",
    "Open-SteinExactCandidateSnapshotLocks",
    "Open-SteinPackageDirectoryManifestLock",
    "Assert-SteinFixedApplicationPayloadMapsEqual",
    "Assert-SteinFixedApplicationPayloadFileIdentity",
    "New-SteinPackageLockedMakeAppxMapping",
    "stein-msix-staging-manifest-v1",
    "stagingLocks",
    "workspaceTargetRoot",
    "desktopDistRoot",
    "candidateRoot",
    "packaging\windows-msix\Verify-Msix.ps1",
    "Publish-SteinVerifiedReleaseArtifactSet",
    "ExpectedSize",
    "ExpectedSha256",
    "packageVerificationResults",
    "verifiedPackageSha256",
    "identityExpectedSha256",
    "browserIdentityExpectedSha256",
    "GitResolvedExecutableSha256",
    "CargoExecutableSha256",
    "RustcExecutableSha256"
)) {
    if ($buildScript.IndexOf($required, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Build script is missing a required fail-closed packaging step."
    }
}

$identityProperties = @(
    "identity_schema_version",
    "package_name",
    "publisher",
    "package_family_name",
    "desktop_aumid",
    "broker_aumid",
    "browser_producer_aumid",
    "version",
    "architecture",
    "signing_certificate_thumbprint",
    "core_executable_file",
    "core_executable_size",
    "core_executable_sha256",
    "browser_host_sha256",
    "candidate_git_commit",
    "candidate_git_tree",
    "source_verification_sha256",
    "source_root_anchor_sha256",
    "source_root_digest_sha256",
    "desktop_executable_size",
    "desktop_executable_sha256",
    "desktop_dist_file_count",
    "desktop_dist_manifest_sha256",
    "cli_executable_file",
    "cli_executable_size",
    "cli_executable_sha256",
    "msix_size",
    "msix_sha256"
)
$identityRecordMatch = [regex]::Match(
    $buildScript,
    '(?ms)\$identityRecord\s*=\s*\[ordered\]\s*@\{(?<body>.*?)^\s*\}')
if (-not $identityRecordMatch.Success) {
    throw "Build script does not contain the expected ordered release identity record."
}
$buildIdentityProperties = @(
    [regex]::Matches(
        $identityRecordMatch.Groups["body"].Value,
        '(?m)^\s*(?<key>[a-z0-9_]+)\s*=') |
        ForEach-Object { $_.Groups["key"].Value }
)
if ($buildIdentityProperties.Count -ne $identityProperties.Count -or
    @(Compare-Object `
        -ReferenceObject ($identityProperties | Sort-Object) `
        -DifferenceObject ($buildIdentityProperties | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "Build-Msix.ps1 does not emit the exact Phase 2 identity schema."
}

$verifyScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot "Verify-Msix.ps1") -Raw
if ($verifyScript.IndexOf("Get-ExactSigningCertificate", [StringComparison]::Ordinal) -ge 0 -or
    $verifyScript.IndexOf("Assert-SteinExactAuthenticodeSignature", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedCoreSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedHostSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedCliSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedDesktopSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedDesktopDistManifestSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedCandidateGitCommit", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedCandidateGitTree", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedSourceVerificationSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedSourceRootAnchorSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedSourceRootDigestSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("packageReadLock", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("[IO.FileShare]::Read", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("Test-SteinCoreBindingContract", [StringComparison]::Ordinal) -lt 0) {
    throw "MSIX verification must pin the signature without requiring the signing private key."
}
if ($buildScript -cnotmatch '(?m)^\s*identity_schema_version\s*=\s*3\s*$' -or
    $buildScript.IndexOf(
        "New-SteinExactGitCandidateSnapshot",
        [StringComparison]::Ordinal) -lt 0 -or
    $buildScript.IndexOf("--frozen-lockfile", [StringComparison]::Ordinal) -lt 0 -or
    $buildScript.IndexOf(
        "Open-SteinPackageDirectoryManifestLock",
        [StringComparison]::Ordinal) -lt 0 -or
    $buildScript -cnotmatch '(?ms)-GitExecutable\s+\$toolchain\.Git\s*`?\r?\n\s*-ExpectedGitExecutableSha256\s+`?\r?\n\s*\$bootstrapSourceBinding\.GitResolvedExecutableSha256' -or
    ([regex]::Matches(
            $buildScript,
            '--target-dir',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant)).Count -lt 3 -or
    $buildScript.IndexOf('$toolchain.Cargo build', [StringComparison]::Ordinal) -lt 0 -or
    $buildScript.IndexOf('$toolchain.PnpmEntrypoint', [StringComparison]::Ordinal) -lt 0 -or
    $buildScript.IndexOf('--package stein-cli', [StringComparison]::Ordinal) -lt 0) {
    throw "The signed build does not use schema-3 identity and the private pinned-tree build boundary."
}
$packageToolsSource = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot "PackageTools.ps1") -Raw
$publicationFunctionMatch = [regex]::Match(
    $packageToolsSource,
    '(?ms)^function Publish-SteinVerifiedReleaseArtifactSet\s*\{(?<body>.*?)^function Test-SteinCoreBindingContract')
if (-not $publicationFunctionMatch.Success) {
    throw "The closed release publication helper is unavailable."
}
$publicationFunctionSource = $publicationFunctionMatch.Groups["body"].Value
$publicationLockIndex = $publicationFunctionSource.IndexOf(
    "[IO.FileShare]::Read)",
    [StringComparison]::Ordinal)
$publicationCleanupIndex = $publicationFunctionSource.IndexOf(
    'Remove-Item -LiteralPath $entry.Backup',
    [StringComparison]::Ordinal)
if ($publicationLockIndex -lt 0 -or
    $publicationCleanupIndex -le $publicationLockIndex -or
    $publicationFunctionSource.IndexOf(
        "A published release artifact differs from the verified temporary bytes.",
        [StringComparison]::Ordinal) -lt 0 -or
    $publicationFunctionSource.IndexOf(
        "The verified release is published, but old-backup cleanup is incomplete.",
        [StringComparison]::Ordinal) -lt 0) {
    throw "Release publication does not verify and lock every final before backup cleanup."
}

$provenanceFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-msix-provenance-static-" + [Guid]::NewGuid().ToString("N"))
try {
    $null = New-Item -ItemType Directory -Path $provenanceFixtureRoot -ErrorAction Stop
    $sourceReportSpecPath = Join-Path $repoRoot "scripts\windows\phase2\Evidence-Spec.json"
    $sourceReportSpecText = Get-Content -LiteralPath $sourceReportSpecPath -Raw
    $sourceReportSpec = $sourceReportSpecText | ConvertFrom-Json -ErrorAction Stop
    [IO.File]::WriteAllText(
        (Join-Path $provenanceFixtureRoot ".gitignore"),
        "artifacts/`n",
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(
        (Join-Path $provenanceFixtureRoot "candidate.txt"),
        "synthetic-candidate`n",
        [Text.UTF8Encoding]::new($false))
    $syntheticDependencyLocks = @(
        "Cargo.lock",
        "apps/desktop/pnpm-lock.yaml",
        "extensions/edge/pnpm-lock.yaml",
        "apps/edge-native-host/Cargo.lock")
    foreach ($dependencyLockRelativePath in $syntheticDependencyLocks) {
        $dependencyLockPath = Join-Path $provenanceFixtureRoot (
            $dependencyLockRelativePath.Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar))
        $dependencyLockParent = Split-Path -Parent $dependencyLockPath
        if (-not (Test-Path -LiteralPath $dependencyLockParent)) {
            $null = New-Item -ItemType Directory -Path $dependencyLockParent -Force
        }
        [IO.File]::WriteAllText(
            $dependencyLockPath,
            "synthetic lock: $dependencyLockRelativePath`n",
            [Text.UTF8Encoding]::new($false))
    }
    foreach ($generatorRelativePath in @(
            $sourceReportSpec.source_report_contract.required_generator_paths)) {
        $generatorPath = Join-Path $provenanceFixtureRoot (
            ([string]$generatorRelativePath).Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar))
        $generatorParent = Split-Path -Parent $generatorPath
        if (-not (Test-Path -LiteralPath $generatorParent)) {
            $null = New-Item -ItemType Directory -Path $generatorParent -Force
        }
        $generatorText = if ([string]$generatorRelativePath -ceq
            "scripts/windows/phase2/Evidence-Spec.json") {
            $sourceReportSpecText
        }
        else {
            "synthetic generator: $generatorRelativePath`n"
        }
        [IO.File]::WriteAllText(
            $generatorPath,
            $generatorText,
            [Text.UTF8Encoding]::new($false))
    }
    $gitCommand = Get-Command git.exe -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    & $gitCommand.Source -C $provenanceFixtureRoot init --quiet
    Assert-NativeCommandSucceeded -Operation "provenance fixture Git initialization"
    & $gitCommand.Source -C $provenanceFixtureRoot config user.name "STEIN Synthetic Fixture"
    Assert-NativeCommandSucceeded -Operation "provenance fixture Git name configuration"
    & $gitCommand.Source -C $provenanceFixtureRoot config user.email "synthetic@example.invalid"
    Assert-NativeCommandSucceeded -Operation "provenance fixture Git email configuration"
    & $gitCommand.Source -C $provenanceFixtureRoot add -- .
    Assert-NativeCommandSucceeded -Operation "provenance fixture Git staging"
    & $gitCommand.Source -C $provenanceFixtureRoot `
        -c commit.gpgsign=false commit --quiet -m "synthetic provenance fixture"
    Assert-NativeCommandSucceeded -Operation "provenance fixture Git commit"

    $gitExecutableDigest = Get-SteinPackageFileSha256 -Path $gitCommand.Source
    $gitFixtureState = Get-SteinCleanGitCandidateState `
        -RepositoryRoot $provenanceFixtureRoot `
        -GitExecutable $gitCommand.Source `
        -ExpectedGitExecutableSha256 $gitExecutableDigest

    $evidenceDirectory = Join-Path $provenanceFixtureRoot "artifacts\evidence\phase-2\source-static"
    $null = New-Item -ItemType Directory -Path $evidenceDirectory -Force -ErrorAction Stop
    $reportPath = Join-Path $evidenceDirectory "source-verification.json"
    $anchorPath = Join-Path $evidenceDirectory "root-anchor.json"
    $chainDigest = "a1" * 32
    $logPaths = @{
        stdout = Join-Path $evidenceDirectory "synthetic.stdout.txt"
        stderr = Join-Path $evidenceDirectory "synthetic.stderr.txt"
    }
    foreach ($logPath in $logPaths.Values) {
        [IO.File]::WriteAllText($logPath, "", [Text.UTF8Encoding]::new($false))
    }
    $newLogRecord = {
        param([string] $Path)
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return [ordered]@{
            path = $item.FullName.Substring($provenanceFixtureRoot.Length + 1).Replace("\", "/")
            size = [long]$item.Length
            sha256 = Get-SteinPackageFileSha256 -Path $item.FullName
        }
    }
    $generatorFiles = @(
        $sourceReportSpec.source_report_contract.required_generator_paths |
            ForEach-Object {
                $relative = [string]$_
                $path = Join-Path $provenanceFixtureRoot (
                    $relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
                $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                [ordered]@{
                    path = $relative
                    size = [long]$item.Length
                    sha256 = Get-SteinPackageFileSha256 -Path $item.FullName
                }
            })
    $generatorDigest = Get-SteinPackageTextSha256 `
        -Value ($generatorFiles | ConvertTo-Json -Depth 16 -Compress)
    $rustToolchainId = "synthetic-x86_64-pc-windows-msvc"
    $report = [ordered]@{
        schema_version = 2
        claim = "source_verification_only"
        installed_or_signed_evidence = $false
        passed = $true
        complete_acceptance = $false
        started_at = "2026-08-21T00:00:00.0000000Z"
        completed_at = "2026-08-21T00:01:00.0000000Z"
        host = [ordered]@{}
        provenance = [ordered]@{
            schema_version = 2
            classification = "bounded_content_free_source_provenance"
            repository = [ordered]@{
                head_commit = $gitFixtureState.Commit
                object_format = if ($gitFixtureState.Commit.Length -eq 40) { "sha1" } else { "sha256" }
                clean = $true
                has_staged_changes = $false
                has_unstaged_changes = $false
                tracked_changed_path_count = 0
                untracked_path_count = 0
                porcelain_status_sha256 = $chainDigest
                raw_diff_sha256 = $chainDigest
                tracked_manifest_sha256 = $chainDigest
                untracked_manifest_sha256 = $chainDigest
                state_sha256 = $chainDigest
            }
            toolchain = [ordered]@{
                cargo = [ordered]@{
                    version = "cargo synthetic"
                    executable_sha256 = $gitExecutableDigest
                    rustup_toolchain = $rustToolchainId
                    resolved_version = "cargo synthetic"
                    resolved_executable_sha256 = $gitExecutableDigest
                }
                rustc = [ordered]@{
                    version = "rustc synthetic"
                    executable_sha256 = $gitExecutableDigest
                    rustup_toolchain = $rustToolchainId
                    resolved_version = "rustc synthetic"
                    resolved_executable_sha256 = $gitExecutableDigest
                }
                rustup = [ordered]@{
                    version = "rustup synthetic"
                    executable_sha256 = $gitExecutableDigest
                }
                node = [ordered]@{
                    version = "node synthetic"
                    executable_sha256 = $gitExecutableDigest
                }
                pnpm = [ordered]@{
                    version = "pnpm synthetic"
                    executable_sha256 = $gitExecutableDigest
                    resolved_entrypoint_sha256 = $gitExecutableDigest
                }
                git = [ordered]@{
                    version = "git version synthetic"
                    executable_sha256 = $gitExecutableDigest
                    resolved_version = "git version synthetic"
                    resolved_executable_sha256 = $gitExecutableDigest
                }
                pwsh = [ordered]@{
                    version = "pwsh synthetic"
                    executable_sha256 = $gitExecutableDigest
                    authenticode_status = "valid"
                    signer_subject = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                }
            }
            build_versions = [ordered]@{}
            contract_versions = [ordered]@{}
            dependency_locks = @($syntheticDependencyLocks | ForEach-Object {
                    $relative = [string]$_
                    $path = Join-Path $provenanceFixtureRoot (
                        $relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
                    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    [ordered]@{
                        path = $relative
                        size = [long]$item.Length
                        sha256 = Get-SteinPackageFileSha256 -Path $item.FullName
                    }
                })
        }
        integrity = [ordered]@{
            semantics = "content_integrity_only_not_authentication"
            generator = [ordered]@{
                schema_version = 1
                files = @()
                digest_sha256 = $generatorDigest
            }
            provenance_sha256 = $null
            checks_sha256 = $null
            root_anchor_path = "root-anchor.json"
        }
        checks = @()
        summary = [ordered]@{
            pass = 0
            fail = 0
            not_run = 0
        }
    }
    $report.integrity.generator.files = $generatorFiles
    $provenanceDigest = Get-SteinPackageTextSha256 `
        -Value ($report.provenance | ConvertTo-Json -Depth 16 -Compress)
    $checks = New-Object Collections.Generic.List[object]
    foreach ($checkId in @(
            $sourceReportSpec.source_report_contract.required_pass_check_ids)) {
        if ([string]$checkId -ceq "source-provenance-stability") {
            $checks.Add([ordered]@{
                    id = [string]$checkId
                    status = "pass"
                    initial_provenance_sha256 = $provenanceDigest
                    completed_provenance_sha256 = $provenanceDigest
                    failure_summary = $null
                })
        }
        else {
            $checks.Add([ordered]@{
                    id = [string]$checkId
                    status = "pass"
                    executable = "synthetic.exe"
                    arguments = @("--synthetic")
                    working_directory = ""
                    started_at = "2026-08-21T00:00:00.0000000Z"
                    completed_at = "2026-08-21T00:00:01.0000000Z"
                    duration_ms = 1000L
                    exit_code = 0
                    failure_summary = $null
                    stdout = & $newLogRecord $logPaths.stdout
                    stderr = & $newLogRecord $logPaths.stderr
                })
        }
    }
    foreach ($checkId in @(
            $sourceReportSpec.source_report_contract.allowed_not_run_check_ids)) {
        $checks.Add([ordered]@{
                id = [string]$checkId
                status = "not_run"
                reason = "Synthetic fixture does not execute this optional workflow."
            })
    }
    $report.checks = $checks.ToArray()
    $report.summary.pass = @($report.checks | Where-Object status -ceq "pass").Count
    $report.summary.not_run = @(
        $report.checks | Where-Object status -ceq "not_run").Count
    $checksDigest = Get-SteinPackageTextSha256 `
        -Value (@($report.checks | ForEach-Object { $_ }) |
            ConvertTo-Json -Depth 16 -Compress)
    $report.integrity.provenance_sha256 = $provenanceDigest
    $report.integrity.checks_sha256 = $checksDigest
    [IO.File]::WriteAllText(
        $reportPath,
        ($report | ConvertTo-Json -Depth 16),
        [Text.UTF8Encoding]::new($false))
    $reportItem = Get-Item -LiteralPath $reportPath -Force -ErrorAction Stop
    $reportDigest = Get-SteinPackageFileSha256 -Path $reportPath
    $rootMaterial = @(
        "stein-phase2-source-evidence-root-v1",
        "source_verification_sha256=$reportDigest",
        "generator_sha256=$generatorDigest",
        "provenance_sha256=$provenanceDigest",
        "checks_sha256=$checksDigest"
    ) -join "`n"
    $rootDigest = Get-SteinPackageTextSha256 -Value $rootMaterial
    $anchor = [ordered]@{
        schema_version = 1
        claim = "source_verification_only"
        integrity_semantics = "content_integrity_only_not_authentication"
        source_verification = [ordered]@{
            path = "source-verification.json"
            size = [long]$reportItem.Length
            sha256 = $reportDigest
        }
        generator_sha256 = $generatorDigest
        provenance_sha256 = $provenanceDigest
        checks_sha256 = $checksDigest
        root_digest_sha256 = $rootDigest
    }
    [IO.File]::WriteAllText(
        $anchorPath,
        ($anchor | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false))
    $anchorDigest = Get-SteinPackageFileSha256 -Path $anchorPath
    $verifiedSourceBinding = Get-SteinVerifiedSourceBuildBinding `
        -RepositoryRoot $provenanceFixtureRoot `
        -SourceVerificationReportPath $reportPath `
        -SourceRootAnchorPath $anchorPath `
        -ExpectedSourceVerificationSha256 $reportDigest `
        -ExpectedSourceRootAnchorSha256 $anchorDigest `
        -ExpectedCandidateGitCommit $gitFixtureState.Commit `
        -ExpectedCandidateGitTree $gitFixtureState.Tree
    if ($verifiedSourceBinding.CandidateGitCommit -cne $gitFixtureState.Commit -or
        $verifiedSourceBinding.CandidateGitTree -cne $gitFixtureState.Tree -or
        $verifiedSourceBinding.SourceRootDigestSha256 -cne $rootDigest) {
        throw "The signed-build source provenance fixture did not reproduce its exact binding."
    }

    $missingCheckRejected = $false
    try {
        $null = Assert-SteinPackageSourceReportCheckContract `
            -Checks @($report.checks | Select-Object -Skip 1) `
            -Contract $sourceReportSpec.source_report_contract `
            -RepositoryRoot $provenanceFixtureRoot `
            -ReportDirectory $evidenceDirectory
    }
    catch { $missingCheckRejected = $true }
    $duplicateCheckRejected = $false
    try {
        $null = Assert-SteinPackageSourceReportCheckContract `
            -Checks @($report.checks + @($report.checks[0])) `
            -Contract $sourceReportSpec.source_report_contract `
            -RepositoryRoot $provenanceFixtureRoot `
            -ReportDirectory $evidenceDirectory
    }
    catch { $duplicateCheckRejected = $true }
    $requiredNotRunChecks = @($report.checks | ForEach-Object {
            if ([string]$_.id -ceq
                [string]$sourceReportSpec.source_report_contract.required_pass_check_ids[0]) {
                [ordered]@{
                    id = [string]$_.id
                    status = "not_run"
                    reason = "Synthetic required-check bypass."
                }
            }
            else { $_ }
        })
    $requiredNotRunRejected = $false
    try {
        $null = Assert-SteinPackageSourceReportCheckContract `
            -Checks $requiredNotRunChecks `
            -Contract $sourceReportSpec.source_report_contract `
            -RepositoryRoot $provenanceFixtureRoot `
            -ReportDirectory $evidenceDirectory
    }
    catch { $requiredNotRunRejected = $true }
    if (-not $missingCheckRejected -or -not $duplicateCheckRejected -or
        -not $requiredNotRunRejected) {
        throw "The signed-build source check catalog accepted an incomplete or downgraded run."
    }

    $wrongEvidenceDigestRejected = $false
    try {
        $null = Get-SteinVerifiedSourceBuildBinding `
            -RepositoryRoot $provenanceFixtureRoot `
            -SourceVerificationReportPath $reportPath `
            -SourceRootAnchorPath $anchorPath `
            -ExpectedSourceVerificationSha256 ("f6" * 32) `
            -ExpectedSourceRootAnchorSha256 $anchorDigest `
            -ExpectedCandidateGitCommit $gitFixtureState.Commit `
            -ExpectedCandidateGitTree $gitFixtureState.Tree
    }
    catch {
        $wrongEvidenceDigestRejected = $true
    }
    if (-not $wrongEvidenceDigestRejected) {
        throw "The signed-build source provenance contract accepted a substituted report digest."
    }

    & $gitCommand.Source -C $provenanceFixtureRoot update-index `
        --assume-unchanged candidate.txt
    Assert-NativeCommandSucceeded -Operation "provenance fixture hidden-index setup"
    [IO.File]::WriteAllText(
        (Join-Path $provenanceFixtureRoot "candidate.txt"),
        "hidden-worktree-mutation`n",
        [Text.UTF8Encoding]::new($false))
    $snapshotRoot = New-SteinPackagePrivateTemporaryDirectory -Purpose "build"
    try {
        $snapshotFixture = New-SteinExactGitCandidateSnapshot `
            -RepositoryRoot $provenanceFixtureRoot `
            -GitExecutable $gitCommand.Source `
            -ExpectedGitExecutableSha256 $gitExecutableDigest `
            -ExpectedCommit $gitFixtureState.Commit `
            -ExpectedTree $gitFixtureState.Tree `
            -BuildRoot $snapshotRoot
        if ([IO.File]::ReadAllText(
                (Join-Path $snapshotFixture.Root "candidate.txt")) -cne
            "synthetic-candidate`n") {
            throw "The exact candidate snapshot consumed hidden worktree bytes."
        }
        $snapshotLocks = Open-SteinExactCandidateSnapshotLocks -Snapshot $snapshotFixture
        try {
            [IO.File]::WriteAllText(
                (Join-Path $snapshotFixture.Root "injected.rs"),
                "synthetic insertion",
                [Text.UTF8Encoding]::new($false))
            $insertedFileRejected = $false
            try {
                $unexpectedSnapshot = Open-SteinExactCandidateSnapshotLocks `
                    -Snapshot $snapshotFixture
                foreach ($stream in $unexpectedSnapshot.Streams) { $stream.Dispose() }
            }
            catch { $insertedFileRejected = $true }
            if (-not $insertedFileRejected) {
                throw "The exact candidate snapshot accepted an inserted source file."
            }
        }
        finally {
            foreach ($stream in $snapshotLocks.Streams) { $stream.Dispose() }
        }
    }
    finally {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $snapshotRoot `
            -Purpose "build"
    }
}
finally {
    if (Test-Path -LiteralPath $provenanceFixtureRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $provenanceFixtureRoot
    }
}

$publicationFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-msix-publication-static-" + [Guid]::NewGuid().ToString("N"))
try {
    $null = New-Item -ItemType Directory -Path $publicationFixtureRoot -ErrorAction Stop
    $finalOne = Join-Path $publicationFixtureRoot "one.msix"
    $finalTwo = Join-Path $publicationFixtureRoot "two.json"
    $temporaryOne = Join-Path $publicationFixtureRoot "one.tmp.msix"
    $temporaryTwo = Join-Path $publicationFixtureRoot "two.tmp.json"
    $backupOne = Join-Path $publicationFixtureRoot "one.backup"
    $backupTwo = Join-Path $publicationFixtureRoot "two.backup"
    $publicationEntries = @(
        [pscustomobject]@{
            Temporary = $temporaryOne
            Final = $finalOne
            Backup = $backupOne
            ExpectedSize = $null
            ExpectedSha256 = $null
        },
        [pscustomobject]@{
            Temporary = $temporaryTwo
            Final = $finalTwo
            Backup = $backupTwo
            ExpectedSize = $null
            ExpectedSha256 = $null
        }
    )
    [IO.File]::WriteAllText($finalOne, "old-one", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($finalTwo, "old-two", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($temporaryOne, "new-one", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($temporaryTwo, "new-two", [Text.UTF8Encoding]::new($false))
    foreach ($entry in $publicationEntries) {
        $entry.ExpectedSize = (Get-Item -LiteralPath $entry.Temporary).Length
        $entry.ExpectedSha256 = Get-SteinPackageFileSha256 -Path $entry.Temporary
    }
    $null = Publish-SteinVerifiedReleaseArtifactSet `
        -OutputRoot $publicationFixtureRoot `
        -Entries $publicationEntries
    if ([IO.File]::ReadAllText($finalOne) -cne "new-one" -or
        [IO.File]::ReadAllText($finalTwo) -cne "new-two" -or
        (Test-Path -LiteralPath $temporaryOne) -or
        (Test-Path -LiteralPath $temporaryTwo) -or
        (Test-Path -LiteralPath $backupOne) -or
        (Test-Path -LiteralPath $backupTwo)) {
        throw "Verified release publication did not replace the exact artifact set."
    }

    [IO.File]::WriteAllText($finalOne, "old-one", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($finalTwo, "old-two", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($temporaryOne, "new-one", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($temporaryTwo, "new-two", [Text.UTF8Encoding]::new($false))
    foreach ($entry in $publicationEntries) {
        $entry.ExpectedSize = (Get-Item -LiteralPath $entry.Temporary).Length
        $entry.ExpectedSha256 = Get-SteinPackageFileSha256 -Path $entry.Temporary
    }
    $expectedTemporaryOneSha256 = $publicationEntries[0].ExpectedSha256
    $publicationEntries[0].ExpectedSha256 = "f7" * 32
    $wrongPublicationBytesRejected = $false
    try {
        $null = Publish-SteinVerifiedReleaseArtifactSet `
            -OutputRoot $publicationFixtureRoot `
            -Entries $publicationEntries
    }
    catch {
        $wrongPublicationBytesRejected = $true
    }
    $publicationEntries[0].ExpectedSha256 = $expectedTemporaryOneSha256
    if (-not $wrongPublicationBytesRejected -or
        [IO.File]::ReadAllText($finalOne) -cne "old-one" -or
        [IO.File]::ReadAllText($finalTwo) -cne "old-two") {
        throw "Release publication accepted unverified temporary bytes."
    }
    $lockedTemporary = [IO.FileStream]::new(
        $temporaryTwo,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $publicationFailureRejected = $false
    try {
        $null = Publish-SteinVerifiedReleaseArtifactSet `
            -OutputRoot $publicationFixtureRoot `
            -Entries $publicationEntries
    }
    catch {
        $publicationFailureRejected = $true
    }
    finally {
        $lockedTemporary.Dispose()
    }
    if (-not $publicationFailureRejected -or
        [IO.File]::ReadAllText($finalOne) -cne "old-one" -or
        [IO.File]::ReadAllText($finalTwo) -cne "old-two" -or
        (Test-Path -LiteralPath $backupOne) -or
        (Test-Path -LiteralPath $backupTwo)) {
        throw "Controlled release publication failure did not restore the previous artifact set."
    }
}
finally {
    if (Test-Path -LiteralPath $publicationFixtureRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $publicationFixtureRoot
    }
}

$toastActivationSource = Get-Content -LiteralPath (
    Join-Path $repoRoot "apps\desktop\src-tauri\src\toast_activation.rs") -Raw
foreach ($required in @(
        "3DB3B5B0-1BA5-49D1-A8F0-CF2B3EA6D781",
        "0x3db3b5b0_1ba5_49d1_a8f0_cf2b3ea6d781",
        "INotificationActivationCallback",
        "current_desktop_aumid",
        "action=open&intervention=",
        "resolve_toast_activation",
        "-ToastActivated")) {
    if ($toastActivationSource.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The packaged toast activator source is missing a pinned identity or routing invariant."
    }
}
foreach ($forbidden in @(
        "std::env::args().nth",
        "activationType=protocol",
        "GetCurrentPackageFullName")) {
    if ($toastActivationSource.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The packaged toast activator contains an unapproved argument or identity path."
    }
}
$notificationSource = Get-Content -LiteralPath (
    Join-Path $repoRoot "crates\stein-platform-windows\src\notification.rs") -Raw
foreach ($required in @(
        'action=open&intervention={intervention_id}',
        'activationType=\"foreground\"')) {
    if ($notificationSource.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The native notification payload no longer matches the packaged activation contract."
    }
}
foreach ($forbidden in @('activationType=\"protocol\"', 'stein://')) {
    if ($notificationSource.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The native notification payload contains an unapproved activation route."
    }
}

$pixelSource = Get-Content -LiteralPath (
    Join-Path $repoRoot "crates\stein-platform-windows\src\pixel.rs") -Raw
$observationSource = Get-Content -LiteralPath (
    Join-Path $repoRoot "crates\stein-platform-windows\src\observation.rs") -Raw
foreach ($required in @(
        "GraphicsCapturePicker",
        "IInitializeWithWindow",
        "PeekMessageW",
        'PIXEL_BINDING_PREFIX: &str = "winpixel:v1:"',
        "CreateFreeThreaded",
        "SetIsCursorCaptureEnabled(false)",
        "MAXIMUM_TRANSIENT_PIXEL_BYTES",
        "current_native_presence",
        "CaptureWorkerLease")) {
    if ($pixelSource.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The native pixel adapter is missing a picker, boundary, or transient-lifetime invariant."
    }
}
foreach ($required in @(
        "ObserveScreenPixels",
        "ResourceKind::ScreenRegion",
        "ObservationRetention::SingleOperation",
        "structured_scope_precedes_pixels",
        "mark_external_structured_source_active")) {
    if ($observationSource.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The Windows observation adapter is missing a pixel authority or minimization invariant."
    }
}
foreach ($forbidden in @(
        "TryCreateFromWindowId",
        "TryCreateFromDisplayId",
        "SetIsBorderRequired(false)",
        "GraphicsCaptureAccessKind::Programmatic",
        ".DisplayName()")) {
    if (($pixelSource + $observationSource).IndexOf(
            $forbidden,
            [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The pixel adapter contains an unapproved programmatic, borderless, or label-bearing capture path."
    }
}
$manifestSource = Get-Content -LiteralPath $manifestPath -Raw
foreach ($forbidden in @(
        "graphicsCaptureProgrammatic",
        "graphicsCaptureWithoutBorder")) {
    if ($manifestSource.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The package requests a broader graphics-capture capability than the picker-only daemon path."
    }
}

$phase2LifecycleRoot = Join-Path $repoRoot "scripts\windows\phase2"
$phase2PowerShell = @(
    "Common.ps1",
    "Lifecycle.ps1",
    "Install.ps1",
    "Upgrade.ps1",
    "Status.ps1",
    "Uninstall.ps1",
    "Source-Evidence.ps1",
    "Evidence-Contract.ps1",
    "Scan-NoLeaks.ps1",
    "Verify-Source.ps1",
    "Verify-Installed.ps1",
    "Review-Installed.ps1",
    "Test-VerifySource.ps1",
    "Test-VerifyInstalled.ps1",
    "Test-ScanNoLeaks.ps1",
    "Test-ReviewInstalled.ps1"
)
$phase2Launchers = @(
    "Install.cmd",
    "Upgrade.cmd",
    "Status.cmd",
    "Uninstall.cmd",
    "Verify-Source.cmd",
    "Verify-Installed.cmd",
    "Review-Installed.cmd"
)
$phase2EvidenceFiles = @(
    "Evidence-Spec.json",
    "Scan-NoLeaks.cmd"
)
foreach ($leaf in $phase2PowerShell + $phase2Launchers + $phase2EvidenceFiles + @("README.md")) {
    if (-not (Test-Path -LiteralPath (Join-Path $phase2LifecycleRoot $leaf) -PathType Leaf)) {
        throw "The Phase 2 lifecycle is missing $leaf."
    }
}
foreach ($leaf in $phase2PowerShell) {
    $path = Join-Path $phase2LifecycleRoot $leaf
    $tokens = $null
    $parseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$parseErrors)
    if (@($parseErrors).Count -ne 0) {
        throw "A Phase 2 lifecycle PowerShell script does not parse."
    }
    $source = Get-Content -LiteralPath $path -Raw
    foreach ($forbidden in @(
            "New-SelfSignedCertificate",
            "Import-Certificate",
            "Import-PfxCertificate",
            "certutil -addstore",
            "Set-ExecutionPolicy",
            "-AllUsers",
            "RunLevel Highest",
            "ServiceAccount")) {
        if ($source.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "A Phase 2 lifecycle script contains a forbidden privilege/certificate mutation."
        }
    }
}
foreach ($leaf in $phase2Launchers) {
    $source = Get-Content -LiteralPath (Join-Path $phase2LifecycleRoot $leaf) -Raw
    $scriptLeaf = [IO.Path]::ChangeExtension($leaf, ".ps1")
    foreach ($requiredLauncherFragment in @(
            'set "STEIN_WINDOWS_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"',
            'if defined PROCESSOR_ARCHITEW6432 set "STEIN_WINDOWS_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"',
            'if not exist "%STEIN_WINDOWS_POWERSHELL%" goto :host_unavailable',
            'STEIN_WINDOWS_POWERSHELL_ATTRIBUTES=%%~aI',
            'STEIN_WINDOWS_POWERSHELL_SIZE=%%~zI',
            'if not defined STEIN_WINDOWS_POWERSHELL_ATTRIBUTES goto :host_unavailable',
            'if not defined STEIN_WINDOWS_POWERSHELL_SIZE goto :host_unavailable',
            'STEIN_WINDOWS_POWERSHELL_ATTRIBUTES:l=',
            'if "%STEIN_WINDOWS_POWERSHELL_SIZE%"=="0" goto :host_unavailable',
            '"%STEIN_WINDOWS_POWERSHELL%" -NoLogo -NoProfile -ExecutionPolicy Bypass',
            "-File `"%~dp0$scriptLeaf`" %*",
            'exit /b %ERRORLEVEL%',
            ':host_unavailable',
            'exit /b 1')) {
        if ($source.IndexOf(
                $requiredLauncherFragment,
                [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "A Phase 2 launcher does not use the validated exact Windows PowerShell host."
        }
    }
    if ($source -match '(?im)^\s*powershell\.exe(?:\s|$)' -or
        $source.IndexOf("%PATH%", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "A Phase 2 launcher permits PATH-based Windows PowerShell resolution."
    }
}
$noLeaksLauncherSource = Get-Content `
    -LiteralPath (Join-Path $phase2LifecycleRoot "Scan-NoLeaks.cmd") `
    -Raw
foreach ($requiredNoLeaksLauncherFragment in @(
        'set "STEIN_NO_LEAKS_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"',
        'if defined PROCESSOR_ARCHITEW6432 set "STEIN_NO_LEAKS_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"',
        'if not exist "%STEIN_NO_LEAKS_POWERSHELL%" goto :host_unavailable',
        'STEIN_NO_LEAKS_POWERSHELL_ATTRIBUTES=%%~aI',
        'STEIN_NO_LEAKS_POWERSHELL_SIZE=%%~zI',
        'if not defined STEIN_NO_LEAKS_POWERSHELL_ATTRIBUTES goto :host_unavailable',
        'if not defined STEIN_NO_LEAKS_POWERSHELL_SIZE goto :host_unavailable',
        'STEIN_NO_LEAKS_POWERSHELL_ATTRIBUTES:l=',
        'if "%STEIN_NO_LEAKS_POWERSHELL_SIZE%"=="0" goto :host_unavailable',
        '"%STEIN_NO_LEAKS_POWERSHELL%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scan-NoLeaks.ps1" %*',
        'exit /b %ERRORLEVEL%',
        ':host_unavailable',
        'exit /b 1')) {
    if ($noLeaksLauncherSource.IndexOf(
            $requiredNoLeaksLauncherFragment,
            [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "The no-leaks scanner launcher does not use the validated exact Windows PowerShell host."
    }
}
if ($noLeaksLauncherSource -match '(?im)^\s*powershell\.exe(?:\s|$)' -or
    $noLeaksLauncherSource.IndexOf("%PATH%", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "The no-leaks scanner launcher permits PATH-based Windows PowerShell resolution."
}

$launcherPathPoisonRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-launcher-path-poison-" + [Guid]::NewGuid().ToString("N"))
$originalLauncherPath = $env:PATH
try {
    $null = New-Item -ItemType Directory -Path $launcherPathPoisonRoot -ErrorAction Stop
    $fakePowerShell = Join-Path $launcherPathPoisonRoot "powershell.exe"
    [IO.File]::WriteAllText($fakePowerShell, "synthetic-path-poison")
    $env:PATH = "$launcherPathPoisonRoot$([IO.Path]::PathSeparator)$originalLauncherPath"
    $discoveredPowerShell = (Get-Command `
        "powershell.exe" `
        -CommandType Application `
        -ErrorAction Stop | Select-Object -First 1).Source
    if (-not [string]::Equals(
            $discoveredPowerShell,
            $fakePowerShell,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "The launcher PATH-poisoning negative fixture did not control command discovery."
    }
    $commandHost = Join-Path (
        [Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "cmd.exe"
    foreach ($leaf in $phase2Launchers) {
        $launcherPath = Join-Path $phase2LifecycleRoot $leaf
        $launcherArguments = '"' + $launcherPath + '" -?'
        $null = @(& $commandHost /d /c $launcherArguments 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "A Phase 2 launcher executed a PATH-poisoned Windows PowerShell host."
        }
    }
}
finally {
    $env:PATH = $originalLauncherPath
    if (Test-Path -LiteralPath $launcherPathPoisonRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $launcherPathPoisonRoot
    }
}

$installedEvidenceStatic = & (Join-Path $phase2LifecycleRoot "Test-VerifyInstalled.ps1")
if ($null -eq $installedEvidenceStatic -or
    -not [bool]$installedEvidenceStatic.verified -or
    [int]$installedEvidenceStatic.ledger_gate_count -ne 32 -or
    [int]$installedEvidenceStatic.installed_mutation_commands -ne 0 -or
    [bool]$installedEvidenceStatic.pass_attachment_auto_promotion -or
    [bool]$installedEvidenceStatic.path_based_executable_resolution -or
    -not [bool]$installedEvidenceStatic.windows_powershell_acl_compatibility -or
    -not [bool]$installedEvidenceStatic.installed_extra_file_rejected -or
    -not [bool]$installedEvidenceStatic.installed_payload_tamper_rejected -or
    -not [bool]$installedEvidenceStatic.generic_zero_exit_json_rejected -or
    -not [bool]$installedEvidenceStatic.evidence_spec_swap_rejected -or
    -not [bool]$installedEvidenceStatic.closed_runner_order_enforced -or
    -not [bool]$installedEvidenceStatic.no_leaks_pair_mismatch_rejected -or
    -not [bool]$installedEvidenceStatic.exact_gate_evidence_contract) {
    throw "The Phase 2 installed-evidence harness failed its static contract."
}

$noLeaksScannerTestHost = Join-Path (
    [Environment]::GetFolderPath([Environment+SpecialFolder]::System)) (
    "WindowsPowerShell\v1.0\powershell.exe")
$noLeaksScannerStatic = @(& $noLeaksScannerTestHost `
        -NoLogo `
        -NoProfile `
        -ExecutionPolicy Bypass `
        -File (Join-Path $phase2LifecycleRoot "Test-ScanNoLeaks.ps1") 2>&1)
$noLeaksScannerExitCode = $LASTEXITCODE
$noLeaksScannerStaticText = ($noLeaksScannerStatic | Out-String).Trim()
if ($noLeaksScannerExitCode -ne 0 -or $noLeaksScannerStaticText -cne
    "P2-NO-LEAKS synthetic scanner contract tests passed on both PowerShell hosts.") {
    throw "The Phase 2 no-leaks scanner failed its static contract."
}

$reviewerStaticJson = (& (Join-Path $phase2LifecycleRoot "Test-ReviewInstalled.ps1") |
        Out-String).Trim()
$reviewerStatic = $reviewerStaticJson | ConvertFrom-Json -ErrorAction Stop
if ($null -eq $reviewerStatic -or
    -not [bool]$reviewerStatic.verified -or
    [int]$reviewerStatic.exact_gate_count -ne 32 -or
    -not [bool]$reviewerStatic.positive_complete_acceptance -or
    [int]$reviewerStatic.negative_case_count -ne 28 -or
    [int]$reviewerStatic.installed_state_mutations -ne 0) {
    throw "The Phase 2 installed-evidence reviewer failed its static contract."
}

$sourceEvidenceStatic = & (Join-Path $phase2LifecycleRoot "Test-VerifySource.ps1")
if ($null -eq $sourceEvidenceStatic -or
    -not [bool]$sourceEvidenceStatic.verified -or
    [int]$sourceEvidenceStatic.report_schema_version -ne 2 -or
    [int]$sourceEvidenceStatic.provenance_schema_version -ne 2 -or
    [int]$sourceEvidenceStatic.generator_file_count -ne 14 -or
    [int]$sourceEvidenceStatic.source_report_check_count -ne 44 -or
    -not [bool]$sourceEvidenceStatic.source_report_contract_bound -or
    -not [bool]$sourceEvidenceStatic.gate_specific_source_mapping_bound -or
    -not [bool]$sourceEvidenceStatic.repository_state_content_free -or
    -not [bool]$sourceEvidenceStatic.generated_outputs_ignored -or
    [int]$sourceEvidenceStatic.toolchain_version_count -ne 7 -or
    -not [bool]$sourceEvidenceStatic.dual_reviewer_shell_contract -or
    -not [bool]$sourceEvidenceStatic.pwsh_path_poison_rejected -or
    -not [bool]$sourceEvidenceStatic.trusted_pwsh_resolved -or
    -not [bool]$sourceEvidenceStatic.generator_reparse_ancestor_rejected -or
    -not [bool]$sourceEvidenceStatic.tool_reparse_ancestor_rejected -or
    [int]$sourceEvidenceStatic.migration_identifier_count -lt 11 -or
    [string]$sourceEvidenceStatic.protocol_version -notmatch '^[0-9]+\.[0-9]+$' -or
    [string]::IsNullOrWhiteSpace([string]$sourceEvidenceStatic.policy_profile) -or
    -not [bool]$sourceEvidenceStatic.deterministic_root_anchor) {
    throw "The Phase 2 source-evidence harness failed its static contract."
}

$phase2Common = Get-Content -LiteralPath (Join-Path $phase2LifecycleRoot "Common.ps1") -Raw
$phase2Lifecycle = Get-Content -LiteralPath (Join-Path $phase2LifecycleRoot "Lifecycle.ps1") -Raw
$phase2Uninstall = Get-Content -LiteralPath (Join-Path $phase2LifecycleRoot "Uninstall.ps1") -Raw
$commonIdentityMatch = [regex]::Match(
    $phase2Common,
    '(?ms)Description\s+"The release identity record"\s+`?\s*-ExpectedProperties\s+@\((?<body>.*?)^\s*\)')
if (-not $commonIdentityMatch.Success) {
    throw "Common.ps1 does not contain the closed release identity schema."
}
$commonIdentityProperties = @(
    [regex]::Matches($commonIdentityMatch.Groups["body"].Value, '"(?<key>[a-z0-9_]+)"') |
        ForEach-Object { $_.Groups["key"].Value }
)
if ($commonIdentityProperties.Count -ne $identityProperties.Count -or
    @(Compare-Object `
        -ReferenceObject ($identityProperties | Sort-Object) `
        -DifferenceObject ($commonIdentityProperties | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "Build-Msix.ps1 and Common.ps1 do not share the exact release identity schema."
}
foreach ($required in @(
        "Get-SteinPhase2ReleaseBundle",
        "Assert-SteinExactAuthenticodeSignature",
        "Get-ExactPackageFamilyName",
        "desktop_aumid",
        "broker_aumid",
        "Assert-SteinPhase2OwnerOnlyTree",
        "Assert-SteinPhase2PersistenceReadyStatus",
        "durable_persistence",
        "STEIN:model-route:",
        "New-SteinPhase2ColdRecoveryCopy")) {
    if (($phase2Common + $phase2Lifecycle).IndexOf(
            $required,
            [StringComparison]::Ordinal) -lt 0) {
        throw "The Phase 2 lifecycle is missing a required trust/recovery invariant."
    }
}
foreach ($required in @(
        "Add-AppxPackage",
        "ForceApplicationShutdown",
        "ForceUpdateFromAnyVersion",
        "Register-SteinPhase2Task",
        '-Argument "--installed"',
        "AllowStartIfOnBatteries",
        "DontStopIfGoingOnBatteries",
        "MultipleInstances IgnoreNew")) {
    if (($phase2Common + $phase2Lifecycle).IndexOf(
            $required,
            [StringComparison]::Ordinal) -lt 0) {
        throw "The Phase 2 lifecycle is missing a required package/task invariant."
    }
}
if ($phase2Uninstall.IndexOf("Remove-AppxPackage", [StringComparison]::Ordinal) -lt 0 -and
    $phase2Lifecycle.IndexOf("Remove-AppxPackage", [StringComparison]::Ordinal) -lt 0) {
    throw "The Phase 2 lifecycle has no exact current-user package removal path."
}

# Temp-only path checks exercise the safety guard without installing a package,
# changing a task, stopping a process, or touching a certificate store.
$phase2TemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-phase2-static-" + [Guid]::NewGuid().ToString("N"))
try {
    $fakeLocalAppData = Join-Path $phase2TemporaryRoot "LocalAppData"
    $safeRoot = Join-Path $fakeLocalAppData "STEIN"
    $null = New-Item -ItemType Directory -Path $safeRoot -Force
    . (Join-Path $phase2LifecycleRoot "Common.ps1")
    $resolvedSafeRoot = Assert-SteinPhase2InstallRoot `
        -InstallRoot $safeRoot `
        -KnownLocalAppData $fakeLocalAppData
    if (-not (Test-SteinPhase2PathEqual -Left $resolvedSafeRoot -Right $safeRoot)) {
        throw "The Phase 2 safe-root fixture did not preserve the exact path."
    }
    $unsafeRejected = $false
    try {
        $null = Assert-SteinPhase2InstallRoot `
            -InstallRoot $fakeLocalAppData `
            -KnownLocalAppData $fakeLocalAppData
    }
    catch {
        $unsafeRejected = $true
    }
    if (-not $unsafeRejected) {
        throw "The Phase 2 safe-root guard accepted a broad LOCALAPPDATA target."
    }
    $dataRoot = Join-Path $safeRoot "data"
    $null = New-Item -ItemType Directory -Path $dataRoot -Force
    $databasePath = Join-Path $dataRoot "stein.db"
    [IO.File]::WriteAllBytes(
        $databasePath,
        [Text.Encoding]::ASCII.GetBytes("SQLite format 3`0synthetic-page"))
    Protect-SteinPhase2OwnerOnlyTree -Root $safeRoot
    Assert-SteinPhase2OwnerOnlyTree -Root $safeRoot
    $recovery = New-SteinPhase2ColdRecoveryCopy `
        -DatabasePath $databasePath `
        -RecoveryPath (Join-Path $dataRoot ".phase2-upgrade-recovery-static.db")
    [IO.File]::WriteAllText($databasePath, "changed")
    Restore-SteinPhase2ColdRecoveryCopy `
        -DatabasePath $databasePath `
        -Recovery $recovery
    Assert-SteinPhase2Hash -Path $databasePath -ExpectedSha256 $recovery.Sha256
    $healthyPersistenceStatus = [pscustomobject]@{
        runtime = [pscustomobject]@{ health = "healthy" }
        capabilities = @(
            [pscustomobject]@{
                capability = "durable_persistence"
                schema_version = 1
                state = "healthy"
            }
        )
    }
    $null = Assert-SteinPhase2PersistenceReadyStatus -Status $healthyPersistenceStatus
    $unavailablePersistenceRejected = $false
    try {
        $null = Assert-SteinPhase2PersistenceReadyStatus -Status ([pscustomobject]@{
            runtime = [pscustomobject]@{ health = "healthy" }
            capabilities = @(
                [pscustomobject]@{
                    capability = "durable_persistence"
                    schema_version = 1
                    state = "unavailable"
                    unavailable_reason = "dependency_unavailable"
                }
            )
        })
    }
    catch {
        $unavailablePersistenceRejected = $true
    }
    if (-not $unavailablePersistenceRejected) {
        throw "The Phase 2 readiness gate accepted unavailable durable persistence."
    }
    Initialize-SteinPhase2CredentialNativeApi
    if ($null -eq ("Stein.Phase2CredentialNative" -as [type])) {
        throw "The exact-prefix Credential Manager cleanup binding did not compile."
    }
}
finally {
    if (Test-Path -LiteralPath $phase2TemporaryRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $phase2TemporaryRoot
    }
}

$brokerManifest = Get-Content -LiteralPath (Join-Path $repoRoot "apps\private-broker\Cargo.toml") -Raw
foreach ($forbiddenDependency in @("serde", "serde_json", "stein-protocol", "stein-ipc")) {
    if ($brokerManifest -match "(?m)^\s*$([regex]::Escape($forbiddenDependency))\s*=") {
        throw "The blind broker acquired a protocol-decoding dependency."
    }
}

$brokerSource = Get-Content -LiteralPath (Join-Path $repoRoot "apps\private-broker\src\windows.rs") -Raw
foreach ($requiredSource in @(
    "admit_named_pipe_peer",
    "PackagePeerClass::PackagedDesktop",
    "verify_core_pipe_server",
    "first_pipe_instance(true)",
    "max_instances(1)"
)) {
    if ($brokerSource.IndexOf($requiredSource, [StringComparison]::Ordinal) -lt 0) {
        throw "Broker source is missing a required native admission or one-client invariant."
    }
}
$librarySource = Get-Content -LiteralPath (Join-Path $repoRoot "apps\private-broker\src\lib.rs") -Raw
$sharedBrokerSource = Get-Content -LiteralPath (
    Join-Path $repoRoot "crates\stein-broker-windows\src\lib.rs") -Raw
foreach ($endpoint in @(
    '\\.\pipe\LOCAL\stein-private-broker-v1',
    '\\.\pipe\LOCAL\stein-core-private-v1'
)) {
    if ($sharedBrokerSource.IndexOf($endpoint, [StringComparison]::Ordinal) -lt 0) {
        throw "Broker source is missing a fixed LOCAL endpoint."
    }
}
foreach ($sharedConstant in @("BROKER_RELAY_PIPE", "CORE_PRIVATE_PIPE")) {
    if ($librarySource.IndexOf(
            "stein_broker_windows::$sharedConstant",
            [StringComparison]::Ordinal) -lt 0) {
        throw "Broker application is not using the shared endpoint contract."
    }
}

$sdkPathPoisonRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-sdk-path-poison-" + [Guid]::NewGuid().ToString("N"))
$originalExecutablePath = $env:PATH
try {
    $null = New-Item -ItemType Directory -Path $sdkPathPoisonRoot -ErrorAction Stop
    foreach ($toolName in @("makeappx.exe", "signtool.exe")) {
        [IO.File]::WriteAllText(
            (Join-Path $sdkPathPoisonRoot $toolName),
            "synthetic-path-poison")
    }
    $env:PATH = "$sdkPathPoisonRoot$([IO.Path]::PathSeparator)$originalExecutablePath"
    foreach ($toolName in @("makeappx.exe", "signtool.exe")) {
        $poisonedPath = (Get-Command $toolName -CommandType Application -ErrorAction Stop |
            Select-Object -First 1).Source
        $expectedPoisonedPath = (Get-Item `
            -LiteralPath (Join-Path $sdkPathPoisonRoot $toolName) `
            -Force `
            -ErrorAction Stop).FullName
        if (-not [string]::Equals(
                $poisonedPath,
                $expectedPoisonedPath,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "The SDK PATH-poisoning negative fixture did not control command discovery."
        }
        $trustedTool = Resolve-WindowsSdkTool -Name $toolName
        if ($trustedTool.StartsWith(
                "$sdkPathPoisonRoot$([IO.Path]::DirectorySeparatorChar)",
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows SDK tool resolution accepted a PATH-poisoned executable."
        }
        $trustedItem = Get-Item -LiteralPath $trustedTool -Force -ErrorAction Stop
        if ($trustedItem.PSIsContainer -or
            (($trustedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $trustedItem.Length -le 0) {
            throw "Windows SDK tool resolution returned a non-regular executable."
        }
    }
}
finally {
    $env:PATH = $originalExecutablePath
    if (Test-Path -LiteralPath $sdkPathPoisonRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $sdkPathPoisonRoot
    }
}

$packageToolsSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot "PackageTools.ps1") -Raw
foreach ($requiredSdkResolverInvariant in @(
        "Microsoft\Windows Kits\Installed Roots",
        "KitsRoot10",
        "FileAttributes]::ReparsePoint")) {
    if ($packageToolsSource.IndexOf(
            $requiredSdkResolverInvariant,
            [StringComparison]::Ordinal) -lt 0) {
        throw "Windows SDK tool resolution is missing a trusted-root invariant."
    }
}
if ($packageToolsSource.IndexOf("Get-Command `$Name", [StringComparison]::Ordinal) -ge 0) {
    throw "Windows SDK tool resolution still consults PATH."
}

$makeAppx = Resolve-WindowsSdkTool -Name "makeappx.exe"
$schemaRoot = Join-Path ([IO.Path]::GetTempPath()) ("stein-msix-static-" + [Guid]::NewGuid().ToString("N"))
$schemaPackage = "$schemaRoot.msix"
$schemaUnpack = "$schemaRoot.unpack"
$schemaMapping = "$schemaRoot.mapping.txt"
$staticStagingLocks = $null
$staticMappingLock = $null
try {
    $null = New-Item -ItemType Directory -Path (Join-Path $schemaRoot "bin") -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $schemaRoot "Assets") -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $schemaRoot "Metadata") -Force
    $fixtureExecutable = Join-Path $env:WINDIR "System32\where.exe"
    Copy-Item -LiteralPath $fixtureExecutable -Destination (Join-Path $schemaRoot "bin\stein-desktop.exe")
    Copy-Item -LiteralPath $fixtureExecutable -Destination (Join-Path $schemaRoot "bin\stein-private-broker.exe")
    Copy-Item -LiteralPath $fixtureExecutable -Destination (Join-Path $schemaRoot "bin\stein-edge-native-host.exe")
    foreach ($asset in $expectedAssets.GetEnumerator()) {
        $encodedPath = Join-Path $PSScriptRoot "assets\$($asset.Key).png.base64"
        [IO.File]::WriteAllBytes(
            (Join-Path $schemaRoot "Assets\$($asset.Key).png"),
            [Convert]::FromBase64String((Get-Content -LiteralPath $encodedPath -Raw).Trim()))
    }
    $staticCoreDigest = "ab" * 32
    $staticCandidateCommit = "1a" * 20
    $staticCandidateTree = "2b" * 20
    $staticSourceVerificationDigest = "3c" * 32
    $staticSourceAnchorDigest = "4d" * 32
    $staticSourceRootDigest = "5e" * 32
    $staticCliSize = 12345L
    $staticCliDigest = "6f" * 32
    $staticDesktopSize = (Get-Item `
            -LiteralPath (Join-Path $schemaRoot "bin\stein-desktop.exe") `
            -Force).Length
    $staticDesktopDigest = Get-SteinPackageFileSha256 `
        -Path (Join-Path $schemaRoot "bin\stein-desktop.exe")
    $staticDesktopDistCount = 2
    $staticDesktopDistDigest = "7a" * 32
    $staticCoreBinding = [ordered]@{
        schema_version = 3
        core_executable_sha256 = $staticCoreDigest
        cli_executable_size = $staticCliSize
        cli_executable_sha256 = $staticCliDigest
        desktop_executable_size = $staticDesktopSize
        desktop_executable_sha256 = $staticDesktopDigest
        desktop_dist_file_count = $staticDesktopDistCount
        desktop_dist_manifest_sha256 = $staticDesktopDistDigest
        candidate_git_commit = $staticCandidateCommit
        candidate_git_tree = $staticCandidateTree
        source_verification_sha256 = $staticSourceVerificationDigest
        source_root_anchor_sha256 = $staticSourceAnchorDigest
        source_root_digest_sha256 = $staticSourceRootDigest
    }
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($staticCoreBinding | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $null = Test-SteinCoreBindingContract `
        -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
        -ExpectedCoreSha256 $staticCoreDigest `
        -ExpectedCliSize $staticCliSize `
        -ExpectedCliSha256 $staticCliDigest `
        -ExpectedDesktopSize $staticDesktopSize `
        -ExpectedDesktopSha256 $staticDesktopDigest `
        -ExpectedDesktopDistFileCount $staticDesktopDistCount `
        -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
        -ExpectedCandidateGitCommit $staticCandidateCommit `
        -ExpectedCandidateGitTree $staticCandidateTree `
        -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
        -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
        -ExpectedSourceRootDigestSha256 $staticSourceRootDigest
    $staticCoreBinding["schema_version"] = 2
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($staticCoreBinding | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $legacySchemaRejected = $false
    try {
        $null = Test-SteinCoreBindingContract `
            -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
            -ExpectedCoreSha256 $staticCoreDigest `
            -ExpectedCliSize $staticCliSize `
            -ExpectedCliSha256 $staticCliDigest `
            -ExpectedDesktopSize $staticDesktopSize `
            -ExpectedDesktopSha256 $staticDesktopDigest `
            -ExpectedDesktopDistFileCount $staticDesktopDistCount `
            -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
            -ExpectedCandidateGitCommit $staticCandidateCommit `
            -ExpectedCandidateGitTree $staticCandidateTree `
            -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
            -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
            -ExpectedSourceRootDigestSha256 $staticSourceRootDigest
    }
    catch { $legacySchemaRejected = $true }
    if (-not $legacySchemaRejected) {
        throw "The signed package binding accepted legacy schema 2 metadata."
    }
    $staticCoreBinding["schema_version"] = "3"
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($staticCoreBinding | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $textSchemaVersionRejected = $false
    try {
        $null = Test-SteinCoreBindingContract `
            -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
            -ExpectedCoreSha256 $staticCoreDigest `
            -ExpectedCliSize $staticCliSize `
            -ExpectedCliSha256 $staticCliDigest `
            -ExpectedDesktopSize $staticDesktopSize `
            -ExpectedDesktopSha256 $staticDesktopDigest `
            -ExpectedDesktopDistFileCount $staticDesktopDistCount `
            -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
            -ExpectedCandidateGitCommit $staticCandidateCommit `
            -ExpectedCandidateGitTree $staticCandidateTree `
            -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
            -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
            -ExpectedSourceRootDigestSha256 $staticSourceRootDigest
    }
    catch {
        $textSchemaVersionRejected = $true
    }
    $staticCoreBinding["schema_version"] = 3
    if (-not $textSchemaVersionRejected) {
        throw "The signed package binding accepted a textual schema version."
    }
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($staticCoreBinding | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $wrongSignedSourceBindingRejected = $false
    try {
        $null = Test-SteinCoreBindingContract `
            -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
            -ExpectedCoreSha256 $staticCoreDigest `
            -ExpectedCliSize $staticCliSize `
            -ExpectedCliSha256 $staticCliDigest `
            -ExpectedDesktopSize $staticDesktopSize `
            -ExpectedDesktopSha256 $staticDesktopDigest `
            -ExpectedDesktopDistFileCount $staticDesktopDistCount `
            -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
            -ExpectedCandidateGitCommit $staticCandidateCommit `
            -ExpectedCandidateGitTree $staticCandidateTree `
            -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
            -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
            -ExpectedSourceRootDigestSha256 ("6f" * 32)
    }
    catch {
        $wrongSignedSourceBindingRejected = $true
    }
    if (-not $wrongSignedSourceBindingRejected) {
        throw "The signed package binding accepted a different source root digest."
    }

    $wrongSignedCliBindingRejected = $false
    try {
        $null = Test-SteinCoreBindingContract `
            -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
            -ExpectedCoreSha256 $staticCoreDigest `
            -ExpectedCliSize $staticCliSize `
            -ExpectedCliSha256 ("9c" * 32) `
            -ExpectedDesktopSize $staticDesktopSize `
            -ExpectedDesktopSha256 $staticDesktopDigest `
            -ExpectedDesktopDistFileCount $staticDesktopDistCount `
            -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
            -ExpectedCandidateGitCommit $staticCandidateCommit `
            -ExpectedCandidateGitTree $staticCandidateTree `
            -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
            -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
            -ExpectedSourceRootDigestSha256 $staticSourceRootDigest
    }
    catch { $wrongSignedCliBindingRejected = $true }
    if (-not $wrongSignedCliBindingRejected) {
        throw "The signed package binding accepted substituted companion CLI bytes."
    }

    $bindingWithExtraProperty = [ordered]@{}
    foreach ($entry in $staticCoreBinding.GetEnumerator()) {
        $bindingWithExtraProperty[$entry.Key] = $entry.Value
    }
    $bindingWithExtraProperty["unexpected"] = "synthetic"
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($bindingWithExtraProperty | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $openSignedBindingRejected = $false
    try {
        $null = Test-SteinCoreBindingContract `
            -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
            -ExpectedCoreSha256 $staticCoreDigest `
            -ExpectedCliSize $staticCliSize `
            -ExpectedCliSha256 $staticCliDigest `
            -ExpectedDesktopSize $staticDesktopSize `
            -ExpectedDesktopSha256 $staticDesktopDigest `
            -ExpectedDesktopDistFileCount $staticDesktopDistCount `
            -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
            -ExpectedCandidateGitCommit $staticCandidateCommit `
            -ExpectedCandidateGitTree $staticCandidateTree `
            -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
            -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
            -ExpectedSourceRootDigestSha256 $staticSourceRootDigest
    }
    catch {
        $openSignedBindingRejected = $true
    }
    if (-not $openSignedBindingRejected) {
        throw "The signed package binding accepted an open metadata schema."
    }
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($staticCoreBinding | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $schemaManifest = (Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8).
        Replace("{{PUBLISHER}}", "CN=STEIN Static Validation").
        Replace("{{PUBLISHER_DISPLAY_NAME}}", "STEIN Static Validation").
        Replace("{{VERSION}}", "0.0.0.1")
    Set-Content -LiteralPath (Join-Path $schemaRoot "AppxManifest.xml") -Value $schemaManifest -Encoding UTF8
    $staticStagingLocks = Open-SteinPackageDirectoryManifestLock `
        -Root $schemaRoot `
        -Domain "stein-msix-staging-manifest-v1"
    $null = Assert-SteinFixedApplicationPayloadMapsEqual `
        -ExpectedFiles @($staticStagingLocks.Files) `
        -ActualFiles @($staticStagingLocks.Files)
    $staticBrokerPath = Join-Path $schemaRoot "bin\stein-private-broker.exe"
    $staticBrokerItem = Get-Item `
        -LiteralPath $staticBrokerPath `
        -Force `
        -ErrorAction Stop
    $staticBrokerDigest = Get-SteinPackageFileSha256 -Path $staticBrokerPath
    $null = Assert-SteinFixedApplicationPayloadFileIdentity `
        -Files @($staticStagingLocks.Files) `
        -RelativePath "bin\stein-private-broker.exe" `
        -ExpectedSize ([long]$staticBrokerItem.Length) `
        -ExpectedSha256 $staticBrokerDigest
    $stagedBrokerSubstitutionRejected = $false
    try {
        $null = Assert-SteinFixedApplicationPayloadFileIdentity `
            -Files @($staticStagingLocks.Files) `
            -RelativePath "bin\stein-private-broker.exe" `
            -ExpectedSize ([long]$staticBrokerItem.Length) `
            -ExpectedSha256 ("8c" * 32)
    }
    catch { $stagedBrokerSubstitutionRejected = $true }
    if (-not $stagedBrokerSubstitutionRejected) {
        throw "The pre-pack staging map accepted substituted broker output bytes."
    }
    $stagingMutationRejected = $false
    try {
        [IO.File]::WriteAllText(
            (Join-Path $schemaRoot "bin\stein-private-broker.exe"),
            "synthetic staging mutation",
            [Text.UTF8Encoding]::new($false))
    }
    catch {
        $stagingMutationRejected = $true
    }
    if (-not $stagingMutationRejected) {
        throw "The pre-pack staging locks allowed a fixed payload mutation."
    }
    $staticMappingLock = New-SteinPackageLockedMakeAppxMapping `
        -StagingManifest $staticStagingLocks `
        -MappingPath $schemaMapping
    $lateOptionalRoot = Join-Path $schemaRoot "AppxMetadata"
    $null = New-Item `
        -ItemType Directory `
        -Path $lateOptionalRoot `
        -ErrorAction Stop
    [IO.File]::WriteAllText(
        (Join-Path $lateOptionalRoot "CodeIntegrity.cat"),
        "synthetic late optional injection",
        [Text.UTF8Encoding]::new($false))
    & $makeAppx pack /f $staticMappingLock.Path /p $schemaPackage /o *> $null
    Assert-NativeCommandSucceeded -Operation "MakeAppx static schema validation"
    & $makeAppx unpack /p $schemaPackage /d $schemaUnpack /o *> $null
    Assert-NativeCommandSucceeded -Operation "MakeAppx static closed-layout validation"
    $actualUnsignedPackageFiles = @(
        Get-ChildItem -LiteralPath $schemaUnpack -Recurse -File | ForEach-Object {
            $_.FullName.Substring($schemaUnpack.Length + 1).Replace("\", "/")
        } | Sort-Object
    )
    $expectedUnsignedPackageFiles = @(
        "AppxBlockMap.xml",
        "AppxManifest.xml",
        "Assets/Square150x150Logo.png",
        "Assets/Square44x44Logo.png",
        "Assets/StoreLogo.png",
        "Metadata/CoreBinding.json",
        "bin/stein-desktop.exe",
        "bin/stein-edge-native-host.exe",
        "bin/stein-private-broker.exe"
    ) | Sort-Object
    if ($actualUnsignedPackageFiles.Count -ne $expectedUnsignedPackageFiles.Count -or
        @(Compare-Object `
            -ReferenceObject $expectedUnsignedPackageFiles `
            -DifferenceObject $actualUnsignedPackageFiles `
            -CaseSensitive).Count -ne 0) {
        throw "MakeAppx emitted a file outside the exact unsigned package layout: $($actualUnsignedPackageFiles -join ', ')."
    }
    $null = Assert-SteinClosedUnpackedPackageLayout -PackageRoot $schemaUnpack
    $unpackedPayloadMap = @(
        foreach ($relativePath in @(Get-SteinFixedApplicationPayloadRelativePaths)) {
            $payloadPath = Join-Path $schemaUnpack $relativePath
            $payload = Get-Item -LiteralPath $payloadPath -Force -ErrorAction Stop
            [pscustomobject]@{
                relative_path = $relativePath
                size = [long]$payload.Length
                sha256 = Get-SteinPackageFileSha256 -Path $payload.FullName
            }
        })
    $null = Assert-SteinFixedApplicationPayloadMapsEqual `
        -ExpectedFiles @($staticStagingLocks.Files) `
        -ActualFiles $unpackedPayloadMap
    $substitutedPayloadMap = @($unpackedPayloadMap | ForEach-Object {
            if ([string]$_.relative_path -ceq "bin\stein-private-broker.exe") {
                [pscustomobject]@{
                    relative_path = [string]$_.relative_path
                    size = [long]$_.size
                    sha256 = "8b" * 32
                }
            }
            else { $_ }
        })
    $substitutedPayloadRejected = $false
    try {
        $null = Assert-SteinFixedApplicationPayloadMapsEqual `
            -ExpectedFiles @($staticStagingLocks.Files) `
            -ActualFiles $substitutedPayloadMap
    }
    catch { $substitutedPayloadRejected = $true }
    if (-not $substitutedPayloadRejected) {
        throw "The signed package comparison accepted a substituted staging payload."
    }

    $hiddenMetadataRoot = Join-Path $schemaUnpack "AppxMetadata"
    $null = New-Item -ItemType Directory -Path $hiddenMetadataRoot -Force -ErrorAction Stop
    [IO.File]::WriteAllText(
        (Join-Path $hiddenMetadataRoot "hidden.exe"),
        "synthetic-unreviewed-package-payload")
    $hiddenMetadataRejected = $false
    try {
        $null = Assert-SteinClosedUnpackedPackageLayout -PackageRoot $schemaUnpack
    }
    catch {
        $hiddenMetadataRejected = $true
    }
    if (-not $hiddenMetadataRejected) {
        throw "The closed package layout accepted an unreviewed AppxMetadata payload."
    }
}
finally {
    if ($null -ne $staticMappingLock) {
        $staticMappingLock.Stream.Dispose()
    }
    if ($null -ne $staticStagingLocks) {
        foreach ($stream in $staticStagingLocks.Streams) { $stream.Dispose() }
    }
    if (Test-Path -LiteralPath $schemaRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $schemaRoot
    }
    if (Test-Path -LiteralPath $schemaPackage) {
        Remove-SteinStaticTemporaryLeaf -Path $schemaPackage
    }
    if (Test-Path -LiteralPath $schemaUnpack) {
        Remove-SteinStaticTemporaryLeaf -Path $schemaUnpack
    }
    if (Test-Path -LiteralPath $schemaMapping) {
        Remove-SteinStaticTemporaryLeaf -Path $schemaMapping
    }
}

Write-Output "Windows MSIX source manifest, MakeAppx schema, assets, signing discipline, and broker boundaries are valid."
