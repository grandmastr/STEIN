[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Publisher,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9A-Fa-f ]{40,59}$")]
    [string] $CertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")]
    [string] $Version,

    [string] $InstallRoot = (Join-Path (
        [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) "STEIN"),

    [switch] $Json
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
. (Join-Path $PSScriptRoot "Common.ps1")

$result = [ordered]@{
    healthy = $false
    installed = $false
    lifecycle_state = "missing"
    package_name = $script:SteinPhase2PackageName
    package_family_name = $null
    desktop_aumid = $null
    broker_aumid = $null
    browser_producer_aumid = $null
    version = $null
    package_count = 0
    task_name = $null
    task_count = 0
    task_state = "Missing"
    core_process_count = 0
    files_verified = $false
    owner_acl_verified = $false
    core = $null
    migration_readiness_verified = $false
    migration_readiness_signal = $null
    numeric_schema_version_reported = $false
    recovery_required = $false
    failure = $null
}

try {
    Assert-SteinPhase2WindowsHost
    $InstallRoot = Assert-SteinPhase2InstallRoot -InstallRoot $InstallRoot
    $result.task_name = Get-SteinPhase2TaskName
    $result.package_count = @(Get-SteinPhase2InstalledPackages).Count
    $result.task_count = @(
        Get-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction SilentlyContinue
    ).Count
    if (-not (Test-Path -LiteralPath $InstallRoot -PathType Container)) {
        throw "STEIN is not installed for the current user."
    }
    Assert-SteinPhase2NoReparseTree -Root $InstallRoot
    $record = Read-SteinPhase2InstallRecord -InstallRoot $InstallRoot -AllowUninstalled
    $result.lifecycle_state = [string]$record.state
    $result.package_family_name = [string]$record.package_family_name
    $result.desktop_aumid = [string]$record.desktop_aumid
    $result.broker_aumid = [string]$record.broker_aumid
    $result.browser_producer_aumid = [string]$record.browser_producer_aumid
    $result.version = [string]$record.version
    if ([string]$record.publisher -cne $Publisher -or
        ([string]$record.signing_certificate_thumbprint).ToUpperInvariant() -cne
            (ConvertTo-SteinCertificateThumbprint -Thumbprint $CertificateThumbprint) -or
        [string]$record.version -cne $Version) {
        throw "Operator pins do not match the protected install record."
    }
    if ([string]$record.state -ceq "uninstalled") {
        $uninstalledRecoveryArtifacts = @(
            Get-ChildItem -LiteralPath (Join-Path $InstallRoot "data") `
                -Filter ".phase2-uninstall-rollback-*" `
                -Force `
                -ErrorAction SilentlyContinue
        )
        if ($result.package_count -ne 0 -or $result.task_count -ne 0 -or
            (Test-Path -LiteralPath (Join-Path $InstallRoot "bin")) -or
            (Test-Path -LiteralPath (Join-Path $InstallRoot "lifecycle")) -or
            $uninstalledRecoveryArtifacts.Count -ne 0) {
            throw "The uninstalled record has orphan package/task/lifecycle state."
        }
        Assert-SteinPhase2OwnerOnlyTree -Root $InstallRoot
        $result.owner_acl_verified = $true
        throw "STEIN is cleanly uninstalled; protected user data is preserved."
    }

    $installed = Get-SteinPhase2InstalledBundle `
        -InstallRoot $InstallRoot `
        -Publisher $Publisher `
        -CertificateThumbprint $CertificateThumbprint `
        -Version $Version
    $result.files_verified = $true
    $package = Assert-SteinPhase2InstalledPackage -Bundle $installed.Bundle
    if ([string]$package.PackageFullName -cne [string]$record.package_full_name) {
        throw "Installed package full name differs from the protected install record."
    }
    $task = Assert-SteinPhase2Task `
        -InstallRoot $InstallRoot `
        -CorePath $installed.CorePath
    $result.task_state = [string]$task.State
    $result.core_process_count = @(
        Get-SteinPhase2ProcessByPath -ExecutablePath $installed.CorePath
    ).Count
    if ($result.core_process_count -ne 1) {
        throw "Expected exactly one installed CORE process."
    }
    Assert-SteinPhase2OwnerOnlyTree -Root $InstallRoot
    $result.owner_acl_verified = $true
    $recoveryArtifacts = @(
        Get-ChildItem -LiteralPath (Join-Path $InstallRoot "data") `
            -Filter ".phase2-upgrade-recovery-*.db" `
            -File `
            -ErrorAction SilentlyContinue
    )
    $uninstallRecoveryArtifacts = @(
        Get-ChildItem -LiteralPath (Join-Path $InstallRoot "data") `
            -Filter ".phase2-uninstall-rollback-*" `
            -Force `
            -ErrorAction SilentlyContinue
    )
    if ((Test-Path -LiteralPath (Join-Path $InstallRoot "lifecycle\recovery-required.json")) -or
        (Test-Path -LiteralPath (Join-Path $InstallRoot "lifecycle\upgrade-in-progress.json")) -or
        $recoveryArtifacts.Count -ne 0 -or
        $uninstallRecoveryArtifacts.Count -ne 0) {
        $result.recovery_required = $true
        throw "Protected upgrade/recovery state remains unresolved."
    }
    $status = Invoke-SteinPhase2CliJson `
        -CliPath $installed.CliPath `
        -Arguments "status --json" `
        -TimeoutMilliseconds 3000
    if (-not $status.Succeeded -or $null -eq $status.Json) {
        throw "CORE diagnostic readiness is unavailable or unhealthy."
    }
    $null = Assert-SteinPhase2PersistenceReadyStatus -Status $status.Json
    $result.core = $status.Json
    $result.migration_readiness_verified = $true
    $result.migration_readiness_signal = "durable_persistence:healthy"
    $result.installed = $true
    $result.healthy = $true
}
catch {
    $result.failure = $_.Exception.Message
}

if ($Json) {
    $result | ConvertTo-Json -Depth 10 -Compress
}
else {
    $result | ConvertTo-Json -Depth 10
}
if (-not $result.healthy) {
    exit 1
}
