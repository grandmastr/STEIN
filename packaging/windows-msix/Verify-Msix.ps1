[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PackagePath,

    [Parameter(Mandatory = $true)]
    [string] $CertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Publisher,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $ExpectedCoreSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $ExpectedHostSha256,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [long]::MaxValue)]
    [long] $ExpectedCliSize,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $ExpectedCliSha256,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [long]::MaxValue)]
    [long] $ExpectedDesktopSize,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $ExpectedDesktopSha256,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 10000)]
    [int] $ExpectedDesktopDistFileCount,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $ExpectedDesktopDistManifestSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]
    [string] $ExpectedCandidateGitCommit,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]
    [string] $ExpectedCandidateGitTree,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $ExpectedSourceVerificationSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $ExpectedSourceRootAnchorSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string] $ExpectedSourceRootDigestSha256
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "PackageTools.ps1")

$resolvedPackage = Resolve-SteinPackageRegularFileWithAncestors -Path $PackagePath
if ([IO.Path]::GetExtension($resolvedPackage) -ine ".msix") {
    throw "PackagePath must identify an MSIX package."
}
$normalizedThumbprint = ConvertTo-SteinCertificateThumbprint -Thumbprint $CertificateThumbprint
$makeAppx = Resolve-WindowsSdkTool -Name "makeappx.exe"
$unpackRoot = New-SteinPackagePrivateTemporaryDirectory -Purpose "verify"
$packageReadLock = $null

try {
    $packageReadLock = [IO.FileStream]::new(
        $resolvedPackage,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $null = Assert-SteinExactAuthenticodeSignature `
        -Path $resolvedPackage `
        -CertificateThumbprint $normalizedThumbprint `
        -Publisher $Publisher

    & $makeAppx unpack /p $resolvedPackage /d $unpackRoot /o *> $null
    Assert-NativeCommandSucceeded -Operation "MakeAppx package unpack"
    $manifestPath = Join-Path $unpackRoot "AppxManifest.xml"
    $contract = Test-SteinManifestContract `
        -ManifestPath $manifestPath `
        -ExpectedPublisher $Publisher `
        -ExpectedVersion $Version `
        -PackageRoot $unpackRoot
    $signedBinding = Test-SteinCoreBindingContract `
        -BindingPath (Join-Path $unpackRoot "Metadata\CoreBinding.json") `
        -ExpectedCoreSha256 $ExpectedCoreSha256 `
        -ExpectedCliSize $ExpectedCliSize `
        -ExpectedCliSha256 $ExpectedCliSha256 `
        -ExpectedDesktopSize $ExpectedDesktopSize `
        -ExpectedDesktopSha256 $ExpectedDesktopSha256 `
        -ExpectedDesktopDistFileCount $ExpectedDesktopDistFileCount `
        -ExpectedDesktopDistManifestSha256 $ExpectedDesktopDistManifestSha256 `
        -ExpectedCandidateGitCommit $ExpectedCandidateGitCommit `
        -ExpectedCandidateGitTree $ExpectedCandidateGitTree `
        -ExpectedSourceVerificationSha256 $ExpectedSourceVerificationSha256 `
        -ExpectedSourceRootAnchorSha256 $ExpectedSourceRootAnchorSha256 `
        -ExpectedSourceRootDigestSha256 $ExpectedSourceRootDigestSha256
    $desktopPath = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $unpackRoot `
        -Path (Join-Path $unpackRoot "bin\stein-desktop.exe")
    $desktopItem = Get-Item -LiteralPath $desktopPath -Force -ErrorAction Stop
    if ($desktopItem.Length -ne $signedBinding.DesktopExecutableSize -or
        (Get-SteinPackageFileSha256 -Path $desktopPath) -cne
            $signedBinding.DesktopExecutableSha256) {
        throw "The packaged desktop executable differs from its signed build binding."
    }
    $hostPath = Join-Path $unpackRoot "bin\stein-edge-native-host.exe"
    $hostSha256 = (Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hostSha256 -cne $ExpectedHostSha256) {
        throw "The packaged Edge native host does not match the release-bound bytes."
    }
    $null = Assert-SteinExactAuthenticodeSignature `
        -Path $hostPath `
        -CertificateThumbprint $normalizedThumbprint `
        -Publisher $Publisher

    $null = Assert-SteinClosedUnpackedPackageLayout -PackageRoot $unpackRoot

    $installedPayloadFiles = @(
        foreach ($relativePath in @(Get-SteinFixedApplicationPayloadRelativePaths | Sort-Object)) {
            $payloadPath = Join-Path $unpackRoot $relativePath
            $payload = Get-Item -LiteralPath $payloadPath -Force -ErrorAction Stop
            if (($payload.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $payload.PSIsContainer) {
                throw "A fixed installed payload entry is not a regular file."
            }
            [pscustomobject]@{
                relative_path = $relativePath
                size = [long]$payload.Length
                sha256 = (Get-FileHash -LiteralPath $payload.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    )

    $packageFamilyName = Get-ExactPackageFamilyName `
        -PackageName $contract.PackageName `
        -Publisher $Publisher
    if ($packageFamilyName -notmatch "^STEIN\.PersonalIntelligence_[a-hj-km-np-tv-z0-9]{13}$") {
        throw "Windows returned an unexpected production package family name."
    }

    [pscustomobject] @{
        PackagePath = $resolvedPackage
        PackageFamilyName = $packageFamilyName
        DesktopAumid = "$packageFamilyName!$script:DesktopApplicationId"
        BrokerAumid = "$packageFamilyName!$script:BrokerApplicationId"
        BrowserProducerAumid = "$packageFamilyName!$script:BrowserProducerApplicationId"
        BrokerPinnedCoreSha256 = $signedBinding.CoreExecutableSha256
        CliExecutableSize = $signedBinding.CliExecutableSize
        CliExecutableSha256 = $signedBinding.CliExecutableSha256
        DesktopExecutableSize = $signedBinding.DesktopExecutableSize
        DesktopExecutableSha256 = $signedBinding.DesktopExecutableSha256
        DesktopDistFileCount = $signedBinding.DesktopDistFileCount
        DesktopDistManifestSha256 = $signedBinding.DesktopDistManifestSha256
        CandidateGitCommit = $signedBinding.CandidateGitCommit
        CandidateGitTree = $signedBinding.CandidateGitTree
        SourceVerificationSha256 = $signedBinding.SourceVerificationSha256
        SourceRootAnchorSha256 = $signedBinding.SourceRootAnchorSha256
        SourceRootDigestSha256 = $signedBinding.SourceRootDigestSha256
        BrowserHostSha256 = $hostSha256
        InstalledPayloadFiles = $installedPayloadFiles
        Sha256 = Get-SteinPackageFileSha256 -Path $resolvedPackage
    }
}
finally {
    if ($null -ne $packageReadLock) {
        $packageReadLock.Dispose()
    }
    if (Test-Path -LiteralPath $unpackRoot) {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $unpackRoot `
            -Purpose "verify"
    }
}
