[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $ScriptRoot '..\..'))
$ExtensionRoot = Join-Path $RepositoryRoot 'extensions\edge'
$Manifest = Get-Content -LiteralPath (Join-Path $ExtensionRoot 'manifest.json') -Raw | ConvertFrom-Json
$ExpectedPermissions = @('activeTab', 'nativeMessaging', 'scripting', 'storage') | Sort-Object
$ActualPermissions = @($Manifest.permissions) | Sort-Object

if (($ActualPermissions -join ',') -ne ($ExpectedPermissions -join ',')) {
    throw 'The Edge extension permission set is not exact.'
}
foreach ($ForbiddenProperty in @('host_permissions', 'content_scripts', 'optional_host_permissions')) {
    if ($Manifest.PSObject.Properties.Name -contains $ForbiddenProperty) {
        throw "The Edge manifest contains forbidden property $ForbiddenProperty."
    }
}
if ($Manifest.incognito -ne 'not_allowed' -or $Manifest.manifest_version -ne 3) {
    throw 'The Edge manifest is not the expected non-incognito MV3 package.'
}

$SourceText = @(
    Get-Content -LiteralPath (Join-Path $ExtensionRoot 'policy.js') -Raw
    Get-Content -LiteralPath (Join-Path $ExtensionRoot 'service-worker.js') -Raw
) -join "`n"
foreach ($Forbidden in @('chrome.tabs.query', 'chrome.history', 'storage.local', 'storage.sync', '<all_urls>', 'console.log')) {
    if ($SourceText.Contains($Forbidden)) {
        throw "The extension contains forbidden collection or logging API $Forbidden."
    }
}

$BuildScriptText = Get-Content -LiteralPath (Join-Path $ScriptRoot 'Build-EdgeArtifacts.ps1') -Raw
foreach ($Mutation in @('Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'reg.exe', 'Add-AppxPackage', 'Start-Process')) {
    if ($BuildScriptText.Contains($Mutation)) {
        throw "The static build unexpectedly mutates installation state through $Mutation."
    }
}

$InstallScriptPath = Join-Path $ScriptRoot 'Install-EdgeArtifacts.ps1'
$UninstallScriptPath = Join-Path $ScriptRoot 'Uninstall-EdgeArtifacts.ps1'
foreach ($ScriptPath in @($InstallScriptPath, $UninstallScriptPath)) {
    $Tokens = $null
    $ParseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath,
        [ref]$Tokens,
        [ref]$ParseErrors)
    if (@($ParseErrors).Count -ne 0) {
        throw 'An Edge lifecycle script does not parse.'
    }
}
$InstallScriptText = Get-Content -LiteralPath $InstallScriptPath -Raw
$UninstallScriptText = Get-Content -LiteralPath $UninstallScriptPath -Raw
foreach ($Required in @(
    'Get-AppxPackage',
    'Get-AppxPackageManifest',
    'BrowserObservationProducer',
    'Get-AuthenticodeSignature',
    'runtime_package_identity_admission',
    'not_run_requires_direct_edge_launch_fixture',
    'HKCU:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts'
)) {
    if ($InstallScriptText.IndexOf($Required, [StringComparison]::Ordinal) -lt 0) {
        throw 'The Edge installer is missing an exact installed-identity or runtime-residual check.'
    }
}
foreach ($Required in @(
    "DeleteValue('', `$false)",
    'ReparsePoint',
    'Remove-Item -LiteralPath $OwnedRoot -Recurse -Force'
)) {
    if ($UninstallScriptText.IndexOf($Required, [StringComparison]::Ordinal) -lt 0) {
        throw 'The Edge uninstaller is missing an exact-value or owned-boundary invariant.'
    }
}
foreach ($Forbidden in @('Add-AppxPackage', 'Start-Process', 'Remove-AppxPackage')) {
    if ($InstallScriptText.Contains($Forbidden) -or $UninstallScriptText.Contains($Forbidden)) {
        throw "The Edge lifecycle scripts unexpectedly manage package/launch state through $Forbidden."
    }
}

$TemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("stein-edge-static-" + [Guid]::NewGuid().ToString('N'))
try {
    $ExtensionId = 'abcdefghijklmnopabcdefghijklmnop'
    $HostPath = Join-Path $TemporaryRoot 'installed-package\bin\stein-edge-native-host.exe'
    New-Item -ItemType Directory -Path (Split-Path -Parent $HostPath) -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\where.exe') -Destination $HostPath
    $HostSha256 = (Get-FileHash -LiteralPath $HostPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $PackageFamilyName = 'STEIN.PersonalIntelligence_qrfd6g9swygw6'
    $ArtifactRoot = Join-Path $TemporaryRoot 'artifacts'
    & (Join-Path $ScriptRoot 'Build-EdgeArtifacts.ps1') `
        -ExtensionId $ExtensionId `
        -PublishedExtensionVersion $Manifest.version `
        -EdgePublisherSha256 ('1' * 64 -join '') `
        -HostPublisherSha256 ('2' * 64 -join '') `
        -PackageFamilyName $PackageFamilyName `
        -PackageVersion '0.1.0.0' `
        -HostSha256 $HostSha256 `
        -InstalledHostPath $HostPath `
        -OutputDirectory $ArtifactRoot | Out-Null

    $HostManifest = Get-Content -LiteralPath (Join-Path $ArtifactRoot 'native-host\com.stein.personal_intelligence.browser.json') -Raw | ConvertFrom-Json
    if ($HostManifest.allowed_origins.Count -ne 1 -or $HostManifest.allowed_origins[0] -ne "chrome-extension://$ExtensionId/") {
        throw 'The generated host manifest origin is not exact.'
    }
    if ([IO.Path]::GetFullPath($HostManifest.path) -ne [IO.Path]::GetFullPath($HostPath)) {
        throw 'The generated native-host path is not the selected stable path.'
    }
    $ReleaseConfig = Get-Content -LiteralPath (Join-Path $ArtifactRoot 'extension\extension-config.js') -Raw
    if (!$ReleaseConfig.Contains($ExtensionId) -or $ReleaseConfig.Contains('__STEIN_EDGE_EXTENSION_ID__')) {
        throw 'The generated extension does not pin the exact release identity.'
    }
    $Identity = Get-Content -LiteralPath (Join-Path $ArtifactRoot 'release-identity.json') -Raw | ConvertFrom-Json
    if ($Identity.provenance_state -ne 'blocked_pending_edge_addons_publication_and_native_launch_fixture') {
        throw 'Static packaging must not claim live release provenance.'
    }
    if ($Identity.browser_producer_aumid -cne "$PackageFamilyName!BrowserObservationProducer" -or
        $Identity.native_host_sha256 -cne $HostSha256) {
        throw 'Static packaging did not bind the exact package host identity.'
    }
    $ContentManifest = Get-Content -LiteralPath (Join-Path $ArtifactRoot 'extension-content-manifest.json') -Raw | ConvertFrom-Json
    if ((@($ContentManifest.path) | Sort-Object) -join ',' -ne 'extension-config.js,manifest.json,policy.js,service-worker.js') {
        throw 'The extension content manifest is not exact.'
    }
}
finally {
    $ResolvedTemporary = [IO.Path]::GetFullPath($TemporaryRoot)
    $ResolvedSystemTemporary = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($ResolvedTemporary.StartsWith($ResolvedSystemTemporary, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $ResolvedTemporary).StartsWith('stein-edge-static-', [StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $ResolvedTemporary -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Output 'Windows Edge static packaging checks passed.'
