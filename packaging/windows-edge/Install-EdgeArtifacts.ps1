[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$HostName = 'com.stein.personal_intelligence.browser'
$PackageName = 'STEIN.PersonalIntelligence'
$ApplicationId = 'BrowserObservationProducer'
$RegistryPath = "HKCU:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\$HostName"
$LocalRoot = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\')
$OwnedRoot = [IO.Path]::GetFullPath((Join-Path $LocalRoot 'STEIN\browser-host'))
$CurrentRoot = Join-Path $OwnedRoot 'current'

function Assert-ExactChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )
    $prefix = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    $candidate = [IO.Path]::GetFullPath($Child)
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The requested path is outside the owned installation boundary.'
    }
    return $candidate
}

function Assert-NoExistingReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)
    $candidate = [IO.Path]::GetFullPath($Path)
    while ($candidate.StartsWith($LocalRoot, [StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $candidate) {
            $item = Get-Item -LiteralPath $candidate -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'The owned installation boundary contains a reparse point.'
            }
        }
        if ($candidate -ieq $LocalRoot) { break }
        $candidate = Split-Path -Parent $candidate
    }
}

$ArtifactRoot = (Resolve-Path -LiteralPath $ArtifactDirectory -ErrorAction Stop).Path
$IdentityPath = Join-Path $ArtifactRoot 'release-identity.json'
$ManifestSource = Join-Path $ArtifactRoot 'native-host\com.stein.personal_intelligence.browser.json'
$Identity = Get-Content -LiteralPath $IdentityPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
$HostManifest = Get-Content -LiteralPath $ManifestSource -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop

if ([string]$Identity.native_host_name -cne $HostName -or
    [string]$Identity.manifest_application_id -cne $ApplicationId -or
    [string]$Identity.native_host_registry_key -cne 'HKCU\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.stein.personal_intelligence.browser' -or
    [string]$Identity.provenance_state -cne 'blocked_pending_edge_addons_publication_and_native_launch_fixture' -or
    [string]$Identity.extension_id -notmatch '^[a-p]{32}$' -or
    [string]$Identity.extension_version -notmatch '^[0-9]+(?:\.[0-9]+){0,3}$' -or
    [string]$Identity.package_family_name -notmatch '^STEIN\.PersonalIntelligence_[a-hj-km-np-tv-z0-9]{13}$' -or
    [string]$Identity.package_version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' -or
    [string]$Identity.native_host_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [string]$Identity.host_publisher_sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'The Edge release identity is incomplete or outside the production contract.'
}
if ([string]$Identity.browser_producer_aumid -cne "$($Identity.package_family_name)!$ApplicationId") {
    throw 'The browser producer AUMID is not the exact packaged application identity.'
}

$Packages = @(
    Get-AppxPackage -Name $PackageName -PackageTypeFilter Main |
        Where-Object {
            $_.PackageFamilyName -ceq [string]$Identity.package_family_name -and
            $_.Version.ToString() -ceq [string]$Identity.package_version
        }
)
if ($Packages.Count -ne 1) {
    throw 'The exact signed STEIN package identity/version is not installed for this user.'
}
$Package = $Packages[0]
$PackageRoot = [IO.Path]::GetFullPath($Package.InstallLocation)
$ExpectedHostPath = Assert-ExactChildPath -Parent $PackageRoot -Child (Join-Path $PackageRoot 'bin\stein-edge-native-host.exe')
$DeclaredHostPath = [IO.Path]::GetFullPath([string]$Identity.native_host_path)
if ($DeclaredHostPath -ine $ExpectedHostPath -or
    [IO.Path]::GetFullPath([string]$HostManifest.path) -ine $ExpectedHostPath -or
    -not (Test-Path -LiteralPath $ExpectedHostPath -PathType Leaf)) {
    throw 'The release does not target the exact package-owned Edge native host.'
}

$PackageManifest = Get-AppxPackageManifest -Package $Package.PackageFullName
$Applications = @($PackageManifest.Package.Applications.Application | Where-Object { $_.Id -ceq $ApplicationId })
if ($Applications.Count -ne 1 -or
    [string]$Applications[0].Executable -cne 'bin\stein-edge-native-host.exe') {
    throw 'The installed package does not declare the exact browser producer application.'
}
$HostSha256 = (Get-FileHash -LiteralPath $ExpectedHostPath -Algorithm SHA256).Hash.ToLowerInvariant()
$Signature = Get-AuthenticodeSignature -LiteralPath $ExpectedHostPath
$PublisherSha256 = if ($null -ne $Signature.SignerCertificate) {
    $Signature.SignerCertificate.GetCertHashString(
        [Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()
} else { '' }
if ($HostSha256 -cne [string]$Identity.native_host_sha256 -or
    $Signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $PublisherSha256 -cne [string]$Identity.host_publisher_sha256) {
    throw 'The installed browser producer bytes or publisher signature do not match the release.'
}
$ExpectedOrigin = "chrome-extension://$($Identity.extension_id)/"
if ([string]$HostManifest.name -cne $HostName -or
    @($HostManifest.allowed_origins).Count -ne 1 -or
    [string]$HostManifest.allowed_origins[0] -cne $ExpectedOrigin -or
    [string]$HostManifest.type -cne 'stdio') {
    throw 'The native-messaging manifest is not bound to the exact published extension.'
}

Assert-NoExistingReparsePoint -Path $OwnedRoot
$StageRoot = Assert-ExactChildPath -Parent $OwnedRoot -Child (Join-Path $OwnedRoot ('.stage-' + [Guid]::NewGuid().ToString('N')))
$BackupRoot = Assert-ExactChildPath -Parent $OwnedRoot -Child (Join-Path $OwnedRoot ('.previous-' + [Guid]::NewGuid().ToString('N')))
$MovedCurrent = $false
$InstalledNewCurrent = $false
$RegistryExisted = Test-Path -LiteralPath $RegistryPath
$PreviousRegistration = if ($RegistryExisted) {
    [string](Get-Item -LiteralPath $RegistryPath).GetValue('')
} else { $null }
if ($RegistryExisted -and -not [string]::IsNullOrWhiteSpace($PreviousRegistration)) {
    $ExpectedExistingManifest = [IO.Path]::GetFullPath((
        Join-Path $CurrentRoot "$HostName.json"))
    if ([IO.Path]::GetFullPath($PreviousRegistration) -ine $ExpectedExistingManifest) {
        throw 'The existing native-messaging registration is not owned by this STEIN installation.'
    }
}
try {
    New-Item -ItemType Directory -Path $StageRoot -Force | Out-Null
    Copy-Item -LiteralPath $ManifestSource -Destination (Join-Path $StageRoot "$HostName.json")
    Copy-Item -LiteralPath $IdentityPath -Destination (Join-Path $StageRoot 'release-identity.json')
    [ordered]@{
        schema_version = 1
        package_family_name = [string]$Identity.package_family_name
        package_version = [string]$Identity.package_version
        browser_producer_aumid = [string]$Identity.browser_producer_aumid
        native_host_sha256 = $HostSha256
        runtime_package_identity_admission = 'not_run_requires_direct_edge_launch_fixture'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $StageRoot 'installed-state.json') -Encoding UTF8

    if (Test-Path -LiteralPath $CurrentRoot) {
        Assert-NoExistingReparsePoint -Path $CurrentRoot
        Move-Item -LiteralPath $CurrentRoot -Destination $BackupRoot
        $MovedCurrent = $true
    }
    Move-Item -LiteralPath $StageRoot -Destination $CurrentRoot
    $InstalledNewCurrent = $true
    $InstalledManifest = Join-Path $CurrentRoot "$HostName.json"
    New-Item -Path $RegistryPath -Force | Out-Null
    Set-Item -LiteralPath $RegistryPath -Value $InstalledManifest
    if ([string](Get-Item -LiteralPath $RegistryPath).GetValue('') -cne $InstalledManifest) {
        throw 'The exact per-user native-messaging registration was not retained.'
    }
    if ($MovedCurrent -and (Test-Path -LiteralPath $BackupRoot)) {
        Remove-Item -LiteralPath $BackupRoot -Recurse -Force
    }
}
catch {
    if ($InstalledNewCurrent -and (Test-Path -LiteralPath $CurrentRoot)) {
        Remove-Item -LiteralPath $CurrentRoot -Recurse -Force
    }
    if ($MovedCurrent -and (Test-Path -LiteralPath $BackupRoot)) {
        Move-Item -LiteralPath $BackupRoot -Destination $CurrentRoot
    }
    if ($RegistryExisted) {
        Set-Item -LiteralPath $RegistryPath -Value $PreviousRegistration
    } elseif (Test-Path -LiteralPath $RegistryPath) {
        Remove-Item -LiteralPath $RegistryPath -Force
    }
    throw
}
finally {
    if (Test-Path -LiteralPath $StageRoot) {
        Remove-Item -LiteralPath $StageRoot -Recurse -Force
    }
}

Write-Output 'Installed the exact Edge native-messaging registration. Runtime PFN/AUMID admission remains NOT RUN.'
