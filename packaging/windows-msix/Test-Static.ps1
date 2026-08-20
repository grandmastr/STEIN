[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "PackageTools.ps1")

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
    "msix_size"
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
    $verifyScript.IndexOf("Test-SteinCoreBindingContract", [StringComparison]::Ordinal) -lt 0) {
    throw "MSIX verification must pin the signature without requiring the signing private key."
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
    "Verify-Source.ps1",
    "Verify-Installed.ps1",
    "Test-VerifyInstalled.ps1"
)
$phase2Launchers = @(
    "Install.cmd",
    "Upgrade.cmd",
    "Status.cmd",
    "Uninstall.cmd",
    "Verify-Source.cmd",
    "Verify-Installed.cmd"
)
foreach ($leaf in $phase2PowerShell + $phase2Launchers + @("README.md")) {
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
        Remove-Item -LiteralPath $launcherPathPoisonRoot -Recurse -Force
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
    -not [bool]$installedEvidenceStatic.installed_payload_tamper_rejected) {
    throw "The Phase 2 installed-evidence harness failed its static contract."
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
        Remove-Item -LiteralPath $phase2TemporaryRoot -Recurse -Force
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
        Remove-Item -LiteralPath $sdkPathPoisonRoot -Recurse -Force
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
    [ordered]@{
        schema_version = 1
        core_executable_sha256 = $staticCoreDigest
    } | ConvertTo-Json | Set-Content `
        -LiteralPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
        -Encoding UTF8
    $null = Test-SteinCoreBindingContract `
        -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
        -ExpectedCoreSha256 $staticCoreDigest
    $schemaManifest = (Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8).
        Replace("{{PUBLISHER}}", "CN=STEIN Static Validation").
        Replace("{{PUBLISHER_DISPLAY_NAME}}", "STEIN Static Validation").
        Replace("{{VERSION}}", "0.0.0.1")
    Set-Content -LiteralPath (Join-Path $schemaRoot "AppxManifest.xml") -Value $schemaManifest -Encoding UTF8
    & $makeAppx pack /d $schemaRoot /p $schemaPackage /o *> $null
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
    if (Test-Path -LiteralPath $schemaRoot) {
        Remove-Item -LiteralPath $schemaRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $schemaPackage) {
        Remove-Item -LiteralPath $schemaPackage -Force
    }
    if (Test-Path -LiteralPath $schemaUnpack) {
        Remove-Item -LiteralPath $schemaUnpack -Recurse -Force
    }
}

Write-Output "Windows MSIX source manifest, MakeAppx schema, assets, signing discipline, and broker boundaries are valid."
