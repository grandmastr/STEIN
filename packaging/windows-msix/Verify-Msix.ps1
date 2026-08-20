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
    [string] $ExpectedHostSha256
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "PackageTools.ps1")

$resolvedPackage = (Resolve-Path -LiteralPath $PackagePath -ErrorAction Stop).Path
if ([IO.Path]::GetExtension($resolvedPackage) -ine ".msix") {
    throw "PackagePath must identify an MSIX package."
}
$normalizedThumbprint = ConvertTo-SteinCertificateThumbprint -Thumbprint $CertificateThumbprint
$makeAppx = Resolve-WindowsSdkTool -Name "makeappx.exe"
$unpackRoot = Join-Path ([IO.Path]::GetTempPath()) ("stein-msix-verify-" + [Guid]::NewGuid().ToString("N"))

try {
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
    $brokerPinnedCoreSha256 = Test-SteinCoreBindingContract `
        -BindingPath (Join-Path $unpackRoot "Metadata\CoreBinding.json") `
        -ExpectedCoreSha256 $ExpectedCoreSha256
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
        BrokerPinnedCoreSha256 = $brokerPinnedCoreSha256
        BrowserHostSha256 = $hostSha256
        InstalledPayloadFiles = $installedPayloadFiles
        Sha256 = (Get-FileHash -LiteralPath $resolvedPackage -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
finally {
    if (Test-Path -LiteralPath $unpackRoot) {
        Remove-Item -LiteralPath $unpackRoot -Recurse -Force
    }
}
