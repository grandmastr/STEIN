[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+(?:\.[0-9]+){0,3}$')]
    [string]$PublishedExtensionVersion,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$EdgePublisherSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$HostPublisherSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^STEIN\.PersonalIntelligence_[a-hj-km-np-tv-z0-9]{13}$')]
    [string]$PackageFamilyName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$PackageVersion,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$HostSha256,

    [Parameter(Mandatory = $true)]
    [string]$InstalledHostPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $ScriptRoot '..\..'))
$ExtensionSource = Join-Path $RepositoryRoot 'extensions\edge'
$OutputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$ReleaseExtension = Join-Path $OutputRoot 'extension'
$ReleaseHost = Join-Path $OutputRoot 'native-host'
$HostPath = [IO.Path]::GetFullPath($InstalledHostPath)
$ExpectedHostName = 'stein-edge-native-host.exe'

if ($ExtensionId -eq ('a' * 32 -join '')) {
    throw 'A placeholder Edge extension ID is not a release identity.'
}
if ($EdgePublisherSha256 -eq ('0' * 64 -join '') -or $HostPublisherSha256 -eq ('0' * 64 -join '')) {
    throw 'Publisher certificate digests must be nonzero release values.'
}
if ($HostSha256 -eq ('0' * 64 -join '') -or
    (Split-Path -Leaf $HostPath) -cne $ExpectedHostName -or
    -not (Test-Path -LiteralPath $HostPath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $HostPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $HostSha256) {
    throw 'The native host path and digest must identify the exact installed package-owned host.'
}

$SourceManifestPath = Join-Path $ExtensionSource 'manifest.json'
$SourceManifest = Get-Content -LiteralPath $SourceManifestPath -Raw | ConvertFrom-Json
if ($SourceManifest.version -ne $PublishedExtensionVersion) {
    throw 'The claimed Edge Add-ons version does not match manifest.json.'
}

if (Test-Path -LiteralPath $OutputRoot) {
    if (@(Get-ChildItem -LiteralPath $OutputRoot -Force).Count -ne 0) {
        throw 'The Edge artifact output directory must be empty.'
    }
}
New-Item -ItemType Directory -Path $ReleaseExtension -Force | Out-Null
New-Item -ItemType Directory -Path $ReleaseHost -Force | Out-Null

foreach ($Name in @('manifest.json', 'policy.js', 'service-worker.js')) {
    Copy-Item -LiteralPath (Join-Path $ExtensionSource $Name) -Destination (Join-Path $ReleaseExtension $Name)
}

$SourceConfig = Get-Content -LiteralPath (Join-Path $ExtensionSource 'extension-config.js') -Raw
$ReleaseConfig = $SourceConfig.Replace('__STEIN_EDGE_EXTENSION_ID__', $ExtensionId)
if ($ReleaseConfig.Contains('__STEIN_EDGE_EXTENSION_ID__')) {
    throw 'The release extension identity token was not resolved exactly once.'
}
[IO.File]::WriteAllText(
    (Join-Path $ReleaseExtension 'extension-config.js'),
    $ReleaseConfig,
    [Text.UTF8Encoding]::new($false)
)

$HostTemplate = Get-Content -LiteralPath (Join-Path $ScriptRoot 'native-host-manifest.json.in') -Raw
$EscapedHostPath = $HostPath.Replace('\', '\\').Replace('"', '\"')
$HostManifestText = $HostTemplate.Replace('__STEIN_EDGE_EXTENSION_ID__', $ExtensionId).
    Replace('__STEIN_NATIVE_HOST_PATH__', $EscapedHostPath)
$HostManifestPath = Join-Path $ReleaseHost 'com.stein.personal_intelligence.browser.json'
[IO.File]::WriteAllText($HostManifestPath, $HostManifestText, [Text.UTF8Encoding]::new($false))
$HostManifest = Get-Content -LiteralPath $HostManifestPath -Raw | ConvertFrom-Json
$ExpectedOrigin = "chrome-extension://$ExtensionId/"
if ($HostManifest.allowed_origins.Count -ne 1 -or $HostManifest.allowed_origins[0] -ne $ExpectedOrigin) {
    throw 'The native host manifest does not contain exactly the release extension origin.'
}

$ContentEntries = @()
foreach ($File in Get-ChildItem -LiteralPath $ReleaseExtension -File | Sort-Object Name) {
    $ContentEntries += [ordered]@{
        path = $File.Name
        bytes = $File.Length
        sha256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$ContentManifestPath = Join-Path $OutputRoot 'extension-content-manifest.json'
$ContentManifestText = $ContentEntries | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($ContentManifestPath, $ContentManifestText, [Text.UTF8Encoding]::new($false))
$ContentManifestSha256 = (Get-FileHash -LiteralPath $ContentManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

$ReleaseIdentity = [ordered]@{
    extension_id = $ExtensionId
    extension_version = $PublishedExtensionVersion
    extension_origin = $ExpectedOrigin
    extension_content_manifest_sha256 = $ContentManifestSha256
    edge_publisher_sha256 = $EdgePublisherSha256
    host_publisher_sha256 = $HostPublisherSha256
    native_host_name = 'com.stein.personal_intelligence.browser'
    native_host_path = $HostPath
    native_host_sha256 = $HostSha256
    native_host_registry_key = 'HKCU\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.stein.personal_intelligence.browser'
    package_family_name = $PackageFamilyName
    package_version = $PackageVersion
    manifest_application_id = 'BrowserObservationProducer'
    browser_producer_aumid = "$PackageFamilyName!BrowserObservationProducer"
    provenance_state = 'blocked_pending_edge_addons_publication_and_native_launch_fixture'
}
$ReleaseIdentityText = $ReleaseIdentity | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText(
    (Join-Path $OutputRoot 'release-identity.json'),
    $ReleaseIdentityText,
    [Text.UTF8Encoding]::new($false)
)

Write-Output $OutputRoot
