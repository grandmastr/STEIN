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
    [string] $ExpectedCoreSha256
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

    & $makeAppx unpack /p $resolvedPackage /d $unpackRoot /o | Out-Host
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

    $allowedFiles = @(
        "AppxManifest.xml",
        "AppxBlockMap.xml",
        "AppxSignature.p7x",
        "[Content_Types].xml",
        "bin\stein-desktop.exe",
        "bin\stein-private-broker.exe",
        "Metadata\CoreBinding.json",
        "Assets\StoreLogo.png",
        "Assets\Square44x44Logo.png",
        "Assets\Square150x150Logo.png"
    )
    $unexpected = Get-ChildItem -LiteralPath $unpackRoot -Recurse -File | Where-Object {
        $relative = $_.FullName.Substring($unpackRoot.Length).TrimStart("\")
        $relative -notin $allowedFiles -and -not $relative.StartsWith("AppxMetadata\", [StringComparison]::Ordinal)
    }
    if ($unexpected) {
        throw "MSIX contains a file outside the closed package layout."
    }

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
        BrokerPinnedCoreSha256 = $brokerPinnedCoreSha256
        Sha256 = (Get-FileHash -LiteralPath $resolvedPackage -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
finally {
    if (Test-Path -LiteralPath $unpackRoot) {
        Remove-Item -LiteralPath $unpackRoot -Recurse -Force
    }
}
