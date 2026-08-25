[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
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

    [switch] $RemoveData,

    [string] $PackagePath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
. (Join-Path $PSScriptRoot "Lifecycle.ps1")

Assert-SteinPhase2WindowsHost
$InstallRoot = Assert-SteinPhase2InstallRoot -InstallRoot $InstallRoot
if (-not (Test-Path -LiteralPath $InstallRoot -PathType Container)) {
    throw "No verified current-user STEIN installation exists."
}
Assert-SteinPhase2NoReparseTree -Root $InstallRoot
$record = Read-SteinPhase2InstallRecord -InstallRoot $InstallRoot -AllowUninstalled
$normalizedThumbprint = ConvertTo-SteinCertificateThumbprint -Thumbprint $CertificateThumbprint
if ([string]$record.publisher -cne $Publisher -or
    ([string]$record.signing_certificate_thumbprint).ToUpperInvariant() -cne $normalizedThumbprint -or
    [string]$record.version -cne $Version) {
    throw "Operator pins do not match the protected install record."
}
Assert-SteinPhase2OwnerOnlyTree -Root $InstallRoot

$alreadyUninstalled = [string]$record.state -ceq "uninstalled"
$installed = $null
$taskXml = $null
if (-not $alreadyUninstalled) {
    $installed = Get-SteinPhase2InstalledBundle `
        -InstallRoot $InstallRoot `
        -Publisher $Publisher `
        -CertificateThumbprint $normalizedThumbprint `
        -Version $Version
    $null = Assert-SteinPhase2InstalledPackage -Bundle $installed.Bundle
    $null = Assert-SteinPhase2Task `
        -InstallRoot $InstallRoot `
        -CorePath $installed.CorePath
    if (@(Get-SteinPhase2ProcessByPath -ExecutablePath $installed.CorePath).Count -gt 1) {
        throw "Multiple installed CORE processes make uninstall ambiguous."
    }
    $taskXml = Export-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction Stop
}
else {
    if (@(Get-SteinPhase2InstalledPackages).Count -ne 0 -or
        @(Get-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction SilentlyContinue).Count -ne 0 -or
        (Test-Path -LiteralPath (Join-Path $InstallRoot "bin")) -or
        (Test-Path -LiteralPath (Join-Path $InstallRoot "lifecycle"))) {
        throw "The uninstalled record has orphan package/task/lifecycle state."
    }
    if ($RemoveData) {
        if ([string]::IsNullOrWhiteSpace($PackagePath)) {
            throw "RemoveData after a prior uninstall requires PackagePath for fresh signed-bundle verification."
        }
        $removalBundle = Get-SteinPhase2ReleaseBundle `
            -PackagePath $PackagePath `
            -Publisher $Publisher `
            -CertificateThumbprint $normalizedThumbprint `
            -Version $Version
        if ($removalBundle.PackageFamilyName -cne [string]$record.package_family_name -or
            $removalBundle.DesktopAumid -cne [string]$record.desktop_aumid -or
            $removalBundle.BrokerAumid -cne [string]$record.broker_aumid -or
            $removalBundle.BrowserProducerAumid -cne [string]$record.browser_producer_aumid -or
            $removalBundle.BrowserHostSha256 -cne [string]$record.browser_host_sha256) {
            throw "The signed removal bundle does not match the uninstalled identity record."
        }
    }
}

$unresolvedRecovery = @(
    Get-ChildItem -LiteralPath (Join-Path $InstallRoot "data") `
        -Filter ".phase2-*-recovery-*" `
        -Force `
        -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath (Join-Path $InstallRoot "data") `
        -Filter ".phase2-uninstall-rollback-*" `
        -Force `
        -ErrorAction SilentlyContinue
)
if (-not $RemoveData -and (
        (Test-Path -LiteralPath (Join-Path $InstallRoot "lifecycle\recovery-required.json")) -or
        (Test-Path -LiteralPath (Join-Path $InstallRoot "lifecycle\upgrade-in-progress.json")) -or
        $unresolvedRecovery.Count -ne 0)) {
    throw "Default uninstall refuses unresolved protected recovery state; recover it or explicitly choose RemoveData."
}

$operation = if ($RemoveData) {
    "Uninstall the exact Phase 2 package and delete verified current-user data and STEIN model-route credentials"
}
else {
    "Uninstall the exact Phase 2 package while preserving current-user data and credentials"
}
if (-not $PSCmdlet.ShouldProcess($InstallRoot, $operation)) {
    return
}

$mutationStarted = $false
$rollbackRoot = $null
$rollbackBundle = $null
$restored = $false
$uninstallCommitted = $false
try {
    if (-not $alreadyUninstalled) {
        $rollbackRoot = Join-Path $InstallRoot (
            "data\.phase2-uninstall-rollback-" + [Guid]::NewGuid().ToString("N"))
        $rollbackBundle = Copy-SteinPhase2BundleToDirectory `
            -Bundle $installed.Bundle `
            -Destination $rollbackRoot `
            -Publisher $installed.Bundle.Publisher `
            -CertificateThumbprint $installed.Bundle.CertificateThumbprint `
            -Version $installed.Bundle.Version
        $mutationStarted = $true
        $processes = @(Get-SteinPhase2ProcessByPath -ExecutablePath $installed.CorePath)
        if ($processes.Count -eq 1) {
            $shutdown = Invoke-SteinPhase2Process `
                -FilePath $installed.CliPath `
                -Arguments "shutdown --timeout-ms 5000" `
                -TimeoutMilliseconds 7000
            if (-not $shutdown.Succeeded -or
                -not (Wait-SteinPhase2ProcessExit `
                    -ExecutablePath $installed.CorePath `
                    -TimeoutMilliseconds 10000)) {
                Stop-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction SilentlyContinue
                if (-not (Stop-SteinPhase2ProcessByPath -ExecutablePath $installed.CorePath)) {
                    throw "The exact installed CORE process could not be stopped."
                }
            }
        }
        Stop-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction SilentlyContinue
        Unregister-ScheduledTask `
            -TaskName (Get-SteinPhase2TaskName) `
            -Confirm:$false `
            -ErrorAction Stop
        Remove-SteinPhase2ExactPackageIfPresent -Bundle $installed.Bundle
    }

    if ($RemoveData) {
        $mutationStarted = $true
        $credentialCount = Remove-SteinPhase2Credentials
        Remove-Item -LiteralPath $InstallRoot -Recurse -Force -ErrorAction Stop
    }
    else {
        foreach ($relative in @("bin", "lifecycle")) {
            $path = Join-Path $InstallRoot $relative
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            }
        }
        $record.state = "uninstalled"
        $record.updated_at_utc = [DateTime]::UtcNow.ToString("o")
        Write-SteinPhase2JsonAtomic `
            -Path (Join-Path $InstallRoot "install.json") `
            -Value $record
        Protect-SteinPhase2OwnerOnlyTree -Root $InstallRoot
        $credentialCount = 0
    }

    if (@(Get-SteinPhase2InstalledPackages).Count -ne 0 -or
        @(Get-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction SilentlyContinue).Count -ne 0 -or
        (-not $alreadyUninstalled -and
            @(Get-SteinPhase2ProcessByPath -ExecutablePath $installed.CorePath).Count -ne 0) -or
        (Test-Path -LiteralPath (Join-Path $InstallRoot "bin"))) {
        throw "Uninstall postconditions found an orphan package, task, process, or binary directory."
    }
    if ($RemoveData -and (Test-Path -LiteralPath $InstallRoot)) {
        throw "Explicit remove-data left the verified STEIN root behind."
    }
    $uninstallCommitted = $true

    if (-not $RemoveData -and
        $null -ne $rollbackRoot -and
        (Test-Path -LiteralPath $rollbackRoot)) {
        Remove-Item -LiteralPath $rollbackRoot -Recurse -Force -ErrorAction Stop
        $rollbackRoot = $null
    }

    [pscustomobject]@{
        uninstalled = $true
        data_preserved = (-not $RemoveData)
        credentials_preserved = (-not $RemoveData)
        credentials_removed = $credentialCount
        package_family_name = [string]$record.package_family_name
        version = [string]$record.version
    } | ConvertTo-Json -Depth 4
}
catch {
    $failure = $_
    if ($uninstallCommitted) {
        throw "Uninstall postconditions succeeded, but protected rollback-cache cleanup failed. RemoveData can explicitly clear the preserved root."
    }
    if (-not $mutationStarted) {
        if ($null -ne $rollbackRoot -and (Test-Path -LiteralPath $rollbackRoot)) {
            Remove-Item -LiteralPath $rollbackRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        throw $failure
    }
    if (-not $RemoveData -and -not $alreadyUninstalled -and $null -ne $rollbackBundle) {
        try {
            $packages = @(Get-SteinPhase2InstalledPackages)
            $packageIsExact = $packages.Count -eq 1 -and
                [string]$packages[0].PackageFamilyName -ceq $rollbackBundle.PackageFamilyName -and
                [string]$packages[0].Version -ceq $rollbackBundle.Version
            if (-not $packageIsExact) {
                Add-AppxPackage `
                    -Path $rollbackBundle.PackagePath `
                    -ForceApplicationShutdown `
                    -ForceUpdateFromAnyVersion `
                    -ErrorAction Stop
            }
            $lifecycleRoot = Join-Path $InstallRoot "lifecycle"
            if (-not (Test-Path -LiteralPath $lifecycleRoot -PathType Container)) {
                $null = New-Item -ItemType Directory -Path $lifecycleRoot -ErrorAction Stop
                Protect-SteinPhase2OwnerOnlyPath -Path $lifecycleRoot
            }
            $currentRoot = Join-Path $lifecycleRoot "current"
            if (Test-Path -LiteralPath $currentRoot) {
                Remove-Item -LiteralPath $currentRoot -Recurse -Force -ErrorAction Stop
            }
            $null = Copy-SteinPhase2BundleToDirectory `
                -Bundle $rollbackBundle `
                -Destination $currentRoot `
                -Publisher $rollbackBundle.Publisher `
                -CertificateThumbprint $rollbackBundle.CertificateThumbprint `
                -Version $rollbackBundle.Version
            $binRoot = Join-Path $InstallRoot "bin"
            if (-not (Test-Path -LiteralPath $binRoot -PathType Container)) {
                $null = New-Item -ItemType Directory -Path $binRoot -ErrorAction Stop
                Protect-SteinPhase2OwnerOnlyPath -Path $binRoot
            }
            $binaries = Install-SteinPhase2Binaries `
                -Bundle $rollbackBundle `
                -InstallRoot $InstallRoot
            Register-ScheduledTask `
                -TaskName (Get-SteinPhase2TaskName) `
                -Xml $taskXml `
                -Force `
                -ErrorAction Stop | Out-Null
            $record.state = "installed"
            $record.updated_at_utc = [DateTime]::UtcNow.ToString("o")
            Write-SteinPhase2JsonAtomic `
                -Path (Join-Path $InstallRoot "install.json") `
                -Value $record
            Start-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction Stop
            $null = Wait-SteinPhase2Ready `
                -Bundle $rollbackBundle `
                -InstallRoot $InstallRoot `
                -CorePath $binaries.CorePath `
                -CliPath $binaries.CliPath
            if (Test-Path -LiteralPath $rollbackRoot) {
                Remove-Item -LiteralPath $rollbackRoot -Recurse -Force -ErrorAction Stop
                $rollbackRoot = $null
            }
            $restored = $true
        }
        catch {
            $restored = $false
            try {
                Write-SteinPhase2RecoveryRequired -InstallRoot $InstallRoot -Stage "uninstall_rollback"
            }
            catch { }
        }
    }
    if ($restored) {
        throw "Uninstall failed; the prior installed lifecycle was restored. Original failure: $($failure.Exception.Message)"
    }
    throw "Uninstall failed and may require protected lifecycle cleanup."
}
