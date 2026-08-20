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

    [string] $OutputPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "PackageTools.ps1")

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$templatePath = Join-Path $PSScriptRoot "AppxManifest.xml.in"
$assetSource = Join-Path $PSScriptRoot "assets"
$cargo = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
if (-not (Test-Path -LiteralPath $cargo -PathType Leaf)) {
    $cargoCommand = Get-Command cargo.exe -ErrorAction Stop | Select-Object -First 1
    $cargo = $cargoCommand.Source
}
$makeAppx = Resolve-WindowsSdkTool -Name "makeappx.exe"
$signTool = Resolve-WindowsSdkTool -Name "signtool.exe"
$certificate = Get-ExactSigningCertificate `
    -Thumbprint $CertificateThumbprint `
    -Publisher $Publisher
$normalizedThumbprint = $certificate.Thumbprint.ToUpperInvariant()
$packageFamilyName = Get-ExactPackageFamilyName `
    -PackageName $script:ProductionPackageName `
    -Publisher $Publisher
$brokerAumid = "$packageFamilyName!$script:BrokerApplicationId"

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot "out\STEIN-$Version-x64.msix"
}
$outputParent = Split-Path -Parent $OutputPath
if ([string]::IsNullOrWhiteSpace($outputParent)) {
    throw "OutputPath must include a parent directory."
}
$null = New-Item -ItemType Directory -Path $outputParent -Force
$outputParent = (Resolve-Path -LiteralPath $outputParent).Path
$outputPath = Join-Path $outputParent (Split-Path -Leaf $OutputPath)
if ([IO.Path]::GetExtension($outputPath) -ine ".msix") {
    throw "OutputPath must use the .msix extension."
}
$coreCompanionPath = "$outputPath.core.exe"
$coreCompanionTemporaryPath = "$coreCompanionPath.$([Guid]::NewGuid().ToString('N')).tmp"
$cliCompanionPath = "$outputPath.cli.exe"
$cliCompanionTemporaryPath = "$cliCompanionPath.$([Guid]::NewGuid().ToString('N')).tmp"

$stagingRoot = Join-Path ([IO.Path]::GetTempPath()) ("stein-msix-" + [Guid]::NewGuid().ToString("N"))
$previousCoreDigest = [Environment]::GetEnvironmentVariable(
    "STEIN_CORE_EXECUTABLE_SHA256",
    [EnvironmentVariableTarget]::Process)
$previousPackageFamilyName = [Environment]::GetEnvironmentVariable(
    "STEIN_PRODUCTION_PACKAGE_FAMILY_NAME",
    [EnvironmentVariableTarget]::Process)
$previousBrokerAumid = [Environment]::GetEnvironmentVariable(
    "STEIN_PRODUCTION_BROKER_AUMID",
    [EnvironmentVariableTarget]::Process)

try {
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

    & $cargo build `
        --release `
        --manifest-path (Join-Path $repoRoot "Cargo.toml") `
        --package stein-core-daemon `
        --features stein-core-daemon/production-private-endpoint `
        --package stein-core-cli `
        --package stein-desktop
    Assert-NativeCommandSucceeded -Operation "Rust CORE/desktop release build"

    $coreExecutable = Join-Path $repoRoot "target\release\stein-core.exe"
    $cliExecutable = Join-Path $repoRoot "target\release\stein-cli.exe"
    $desktopExecutable = Join-Path $repoRoot "target\release\stein-desktop.exe"
    foreach ($executable in @($coreExecutable, $cliExecutable, $desktopExecutable)) {
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
            throw "A required release executable was not produced."
        }
    }

    # CORE is intentionally installed outside the MSIX under Task Scheduler.
    # Sign it first, then bind the broker build to the exact signed bytes.
    & $signTool sign `
        /sha1 $normalizedThumbprint `
        /fd SHA256 `
        /tr $TimestampUrl `
        /td SHA256 `
        $coreExecutable
    Assert-NativeCommandSucceeded -Operation "CORE Authenticode signing"
    & $signTool verify /pa /all /v $coreExecutable
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
        $cliExecutable
    Assert-NativeCommandSucceeded -Operation "diagnostic CLI Authenticode signing"
    & $signTool verify /pa /all /v $cliExecutable
    Assert-NativeCommandSucceeded -Operation "diagnostic CLI Authenticode verification"
    $cliSignature = Get-AuthenticodeSignature -LiteralPath $cliExecutable
    if ($cliSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $cliSignature.SignerCertificate -or
        $cliSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $normalizedThumbprint -or
        $cliSignature.SignerCertificate.Subject -cne $Publisher) {
        throw "Diagnostic CLI signature is not valid under the exact selected certificate."
    }

    $coreDigest = (Get-FileHash -LiteralPath $coreExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
    $cliDigest = (Get-FileHash -LiteralPath $cliExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
    [Environment]::SetEnvironmentVariable(
        "STEIN_CORE_EXECUTABLE_SHA256",
        $coreDigest,
        [EnvironmentVariableTarget]::Process)

    & $cargo build `
        --release `
        --manifest-path (Join-Path $repoRoot "Cargo.toml") `
        --package stein-private-broker
    Assert-NativeCommandSucceeded -Operation "private broker release build"
    $brokerExecutable = Join-Path $repoRoot "target\release\stein-private-broker.exe"
    if (-not (Test-Path -LiteralPath $brokerExecutable -PathType Leaf)) {
        throw "The private broker release executable was not produced."
    }

    $null = New-Item -ItemType Directory -Path (Join-Path $stagingRoot "bin") -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $stagingRoot "Assets") -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $stagingRoot "Metadata") -Force
    Copy-Item -LiteralPath $desktopExecutable -Destination (Join-Path $stagingRoot "bin\stein-desktop.exe")
    Copy-Item -LiteralPath $brokerExecutable -Destination (Join-Path $stagingRoot "bin\stein-private-broker.exe")
    [ordered]@{
        schema_version = 1
        core_executable_sha256 = $coreDigest
    } | ConvertTo-Json | Set-Content `
        -LiteralPath (Join-Path $stagingRoot "Metadata\CoreBinding.json") `
        -Encoding UTF8
    $null = Test-SteinCoreBindingContract `
        -BindingPath (Join-Path $stagingRoot "Metadata\CoreBinding.json") `
        -ExpectedCoreSha256 $coreDigest

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

    if (Test-Path -LiteralPath $outputPath) {
        Remove-Item -LiteralPath $outputPath -Force
    }
    & $makeAppx pack /d $stagingRoot /p $outputPath /o
    Assert-NativeCommandSucceeded -Operation "MakeAppx package creation"

    & $signTool sign `
        /sha1 $normalizedThumbprint `
        /fd SHA256 `
        /tr $TimestampUrl `
        /td SHA256 `
        $outputPath
    Assert-NativeCommandSucceeded -Operation "MSIX signing"

    & (Join-Path $PSScriptRoot "Verify-Msix.ps1") `
        -PackagePath $outputPath `
        -CertificateThumbprint $normalizedThumbprint `
        -Publisher $Publisher `
        -Version $Version `
        -ExpectedCoreSha256 $coreDigest
    if (-not $?) {
        throw "MSIX verification script failed."
    }

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
    Move-Item -LiteralPath $coreCompanionTemporaryPath -Destination $coreCompanionPath -Force

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
    Move-Item -LiteralPath $cliCompanionTemporaryPath -Destination $cliCompanionPath -Force

    $identityRecord = [ordered] @{
        identity_schema_version = 1
        package_name = $script:ProductionPackageName
        publisher = $Publisher
        package_family_name = $packageFamilyName
        desktop_aumid = "$packageFamilyName!$script:DesktopApplicationId"
        broker_aumid = $brokerAumid
        version = $Version
        architecture = "x64"
        signing_certificate_thumbprint = $normalizedThumbprint
        core_executable_file = (Split-Path -Leaf $coreCompanionPath)
        core_executable_size = (Get-Item -LiteralPath $coreCompanionPath).Length
        core_executable_sha256 = $coreDigest
        cli_executable_file = (Split-Path -Leaf $cliCompanionPath)
        cli_executable_size = (Get-Item -LiteralPath $cliCompanionPath).Length
        cli_executable_sha256 = $cliDigest
        msix_size = (Get-Item -LiteralPath $outputPath).Length
        msix_sha256 = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $identityPath = "$outputPath.identity.json"
    $identityRecord | ConvertTo-Json | Set-Content -LiteralPath $identityPath -Encoding UTF8

    Write-Output "Created and verified signed MSIX: $outputPath"
    Write-Output "Published broker-pinned signed CORE: $coreCompanionPath"
    Write-Output "Published signed diagnostic CLI: $cliCompanionPath"
    Write-Output "Recorded exact package identities: $identityPath"
}
finally {
    [Environment]::SetEnvironmentVariable(
        "STEIN_CORE_EXECUTABLE_SHA256",
        $previousCoreDigest,
        [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "STEIN_PRODUCTION_PACKAGE_FAMILY_NAME",
        $previousPackageFamilyName,
        [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable(
        "STEIN_PRODUCTION_BROKER_AUMID",
        $previousBrokerAumid,
        [EnvironmentVariableTarget]::Process)
    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $coreCompanionTemporaryPath) {
        Remove-Item -LiteralPath $coreCompanionTemporaryPath -Force
    }
    if (Test-Path -LiteralPath $cliCompanionTemporaryPath) {
        Remove-Item -LiteralPath $cliCompanionTemporaryPath -Force
    }
}
