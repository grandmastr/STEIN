Set-StrictMode -Version 3.0
. (Join-Path $PSScriptRoot "Common.ps1")

function Initialize-SteinPhase2Directories {
    param([Parameter(Mandatory = $true)][string] $InstallRoot)

    if (-not (Test-Path -LiteralPath $InstallRoot)) {
        $null = New-Item -ItemType Directory -Path $InstallRoot -ErrorAction Stop
    }
    Protect-SteinPhase2OwnerOnlyPath -Path $InstallRoot
    foreach ($relative in @("bin", "data", "logs", "lifecycle")) {
        $path = Join-Path $InstallRoot $relative
        if (-not (Test-Path -LiteralPath $path)) {
            $null = New-Item -ItemType Directory -Path $path -ErrorAction Stop
        }
        Protect-SteinPhase2OwnerOnlyTree -Root $path
    }
    Assert-SteinPhase2OwnerOnlyTree -Root $InstallRoot
}

function Install-SteinPhase2Binaries {
    param(
        [Parameter(Mandatory = $true)] $Bundle,
        [Parameter(Mandatory = $true)][string] $InstallRoot
    )

    $binRoot = Join-Path $InstallRoot "bin"
    $corePath = Join-Path $binRoot "stein-core.exe"
    $cliPath = Join-Path $binRoot "stein-cli.exe"
    $coreTemporary = Join-Path $binRoot (".stein-core." + [Guid]::NewGuid().ToString("N") + ".tmp")
    $cliTemporary = Join-Path $binRoot (".stein-cli." + [Guid]::NewGuid().ToString("N") + ".tmp")
    try {
        Copy-Item -LiteralPath $Bundle.CorePath -Destination $coreTemporary -ErrorAction Stop
        Copy-Item -LiteralPath $Bundle.CliPath -Destination $cliTemporary -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyPath -Path $coreTemporary
        Protect-SteinPhase2OwnerOnlyPath -Path $cliTemporary
        Assert-SteinPhase2Size -Path $coreTemporary -ExpectedSize $Bundle.CoreSize
        Assert-SteinPhase2Hash -Path $coreTemporary -ExpectedSha256 $Bundle.CoreSha256
        Assert-SteinPhase2Size -Path $cliTemporary -ExpectedSize $Bundle.CliSize
        Assert-SteinPhase2Hash -Path $cliTemporary -ExpectedSha256 $Bundle.CliSha256
        $null = Assert-SteinExactAuthenticodeSignature `
            -Path $coreTemporary `
            -CertificateThumbprint $Bundle.CertificateThumbprint `
            -Publisher $Bundle.Publisher
        $null = Assert-SteinExactAuthenticodeSignature `
            -Path $cliTemporary `
            -CertificateThumbprint $Bundle.CertificateThumbprint `
            -Publisher $Bundle.Publisher
        Move-Item -LiteralPath $coreTemporary -Destination $corePath -Force -ErrorAction Stop
        Move-Item -LiteralPath $cliTemporary -Destination $cliPath -Force -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyPath -Path $corePath
        Protect-SteinPhase2OwnerOnlyPath -Path $cliPath
        return [pscustomobject]@{
            CorePath = $corePath
            CliPath = $cliPath
        }
    }
    finally {
        foreach ($temporary in @($coreTemporary, $cliTemporary)) {
            if (Test-Path -LiteralPath $temporary) {
                Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Assert-SteinPhase2FreshPreconditions {
    param(
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)] $Bundle
    )

    if (@(Get-SteinPhase2InstalledPackages).Count -ne 0) {
        throw "A STEIN production MSIX is already installed; use Upgrade.ps1."
    }
    if (@(Get-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction SilentlyContinue).Count -ne 0) {
        throw "A SID-qualified STEIN task already exists; use Upgrade.ps1."
    }
    if (Test-Path -LiteralPath $InstallRoot) {
        Assert-SteinPhase2NoReparseTree -Root $InstallRoot
        $recordPath = Join-Path $InstallRoot "install.json"
        if (Test-Path -LiteralPath $recordPath -PathType Leaf) {
            $record = Read-SteinPhase2InstallRecord -InstallRoot $InstallRoot -AllowUninstalled
            if ([string]$record.state -cne "uninstalled" -or
                [string]$record.publisher -cne $Bundle.Publisher -or
                [string]$record.package_family_name -cne $Bundle.PackageFamilyName) {
                throw "Existing lifecycle metadata is not a compatible uninstalled Phase 2 record."
            }
        }
        $unexpected = @(Get-ChildItem -LiteralPath $InstallRoot -Force -ErrorAction Stop |
            Where-Object { $_.Name -notin @("data", "logs", "install.json") })
        if ($unexpected.Count -ne 0) {
            throw "InstallRoot contains lifecycle files not covered by an uninstalled record."
        }
    }
}

function Remove-SteinPhase2ExactPackageIfPresent {
    param([Parameter(Mandatory = $true)] $Bundle)

    $packages = @(Get-SteinPhase2InstalledPackages)
    foreach ($package in $packages) {
        if ([string]$package.PackageFamilyName -cne $Bundle.PackageFamilyName -or
            [string]$package.Publisher -cne $Bundle.Publisher) {
            throw "Refusing to remove a STEIN package outside the exact verified identity."
        }
        Remove-AppxPackage -Package $package.PackageFullName -Confirm:$false -ErrorAction Stop
    }
}

function Write-SteinPhase2RecoveryRequired {
    param(
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)][string] $Stage
    )

    $lifecycleRoot = Join-Path $InstallRoot "lifecycle"
    if (-not (Test-Path -LiteralPath $lifecycleRoot -PathType Container)) {
        return
    }
    $record = [ordered]@{
        schema_version = 1
        state = "recovery_required"
        stage = $Stage
        recorded_at_utc = [DateTime]::UtcNow.ToString("o")
        owner_sid = Get-SteinPhase2CurrentUserSid
    }
    Write-SteinPhase2JsonAtomic `
        -Path (Join-Path $lifecycleRoot "recovery-required.json") `
        -Value $record
}

function Install-SteinPhase2Fresh {
    param(
        [Parameter(Mandatory = $true)][string] $PackagePath,
        [Parameter(Mandatory = $true)][string] $Publisher,
        [Parameter(Mandatory = $true)][string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)][string] $Version,
        [Parameter(Mandatory = $true)][string] $InstallRoot
    )

    Assert-SteinPhase2WindowsHost
    $InstallRoot = Assert-SteinPhase2InstallRoot -InstallRoot $InstallRoot
    $sourceBundle = Get-SteinPhase2ReleaseBundle `
        -PackagePath $PackagePath `
        -Publisher $Publisher `
        -CertificateThumbprint $CertificateThumbprint `
        -Version $Version
    Assert-SteinPhase2FreshPreconditions -InstallRoot $InstallRoot -Bundle $sourceBundle

    $taskRegistered = $false
    $packageInstalled = $false
    $packageMutationAttempted = $false
    $stageRoot = $null
    try {
        Initialize-SteinPhase2Directories -InstallRoot $InstallRoot
        $stageRoot = Join-Path $InstallRoot (
            "lifecycle\staging-" + [Guid]::NewGuid().ToString("N"))
        $bundle = Copy-SteinPhase2BundleToDirectory `
            -Bundle $sourceBundle `
            -Destination $stageRoot `
            -Publisher $Publisher `
            -CertificateThumbprint $CertificateThumbprint `
            -Version $Version

        $packageMutationAttempted = $true
        Add-AppxPackage `
            -Path $bundle.PackagePath `
            -ForceApplicationShutdown `
            -ErrorAction Stop
        $packageInstalled = $true
        $installedPackage = Assert-SteinPhase2InstalledPackage -Bundle $bundle

        $binaries = Install-SteinPhase2Binaries -Bundle $bundle -InstallRoot $InstallRoot
        $currentRoot = Join-Path $InstallRoot "lifecycle\current"
        if (Test-Path -LiteralPath $currentRoot) {
            throw "A current release directory appeared during fresh installation."
        }
        Move-Item -LiteralPath $stageRoot -Destination $currentRoot -ErrorAction Stop
        $stageRoot = $null
        Protect-SteinPhase2OwnerOnlyTree -Root $currentRoot

        $null = Register-SteinPhase2Task `
            -InstallRoot $InstallRoot `
            -CorePath $binaries.CorePath
        $taskRegistered = $true
        $null = Assert-SteinPhase2Task `
            -InstallRoot $InstallRoot `
            -CorePath $binaries.CorePath
        Start-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction Stop
        $runtime = Wait-SteinPhase2Ready `
            -Bundle $bundle `
            -InstallRoot $InstallRoot `
            -CorePath $binaries.CorePath `
            -CliPath $binaries.CliPath

        $record = New-SteinPhase2InstallRecord `
            -Bundle $bundle `
            -InstalledPackage $installedPackage `
            -InstallRoot $InstallRoot `
            -State "installed"
        Write-SteinPhase2JsonAtomic `
            -Path (Join-Path $InstallRoot "install.json") `
            -Value $record
        Protect-SteinPhase2OwnerOnlyTree -Root $InstallRoot
        Assert-SteinPhase2OwnerOnlyTree -Root $InstallRoot

        return [pscustomobject]@{
            installed = $true
            upgraded = $false
            package_family_name = $bundle.PackageFamilyName
            desktop_aumid = $bundle.DesktopAumid
            broker_aumid = $bundle.BrokerAumid
            version = $bundle.Version
            task_name = Get-SteinPhase2TaskName
            core = $runtime
            migration_readiness_verified = $true
            migration_readiness_signal = "durable_persistence:healthy"
            numeric_schema_version_reported = $false
        }
    }
    catch {
        $failure = $_
        $rollbackFailed = $false
        try {
            if ($taskRegistered -or
                @(Get-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction SilentlyContinue).Count -gt 0) {
                Stop-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction SilentlyContinue
                Unregister-ScheduledTask `
                    -TaskName (Get-SteinPhase2TaskName) `
                    -Confirm:$false `
                    -ErrorAction SilentlyContinue
            }
            $corePath = Join-Path $InstallRoot "bin\stein-core.exe"
            if (Test-Path -LiteralPath $corePath -PathType Leaf) {
                if (-not (Stop-SteinPhase2ProcessByPath -ExecutablePath $corePath)) {
                    $rollbackFailed = $true
                }
            }
            if ($packageInstalled -or $packageMutationAttempted) {
                Remove-SteinPhase2ExactPackageIfPresent -Bundle $sourceBundle
            }
            foreach ($relative in @("bin", "lifecycle")) {
                $path = Join-Path $InstallRoot $relative
                if (Test-Path -LiteralPath $path) {
                    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                }
            }
        }
        catch {
            $rollbackFailed = $true
        }
        if ($rollbackFailed) {
            try {
                Write-SteinPhase2RecoveryRequired -InstallRoot $InstallRoot -Stage "fresh_install"
            }
            catch { }
            throw "Phase 2 installation failed and automatic cleanup is incomplete; protected recovery state remains."
        }
        throw $failure
    }
    finally {
        if ($null -ne $stageRoot -and (Test-Path -LiteralPath $stageRoot)) {
            Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-SteinLegacyPhase1Install {
    param([Parameter(Mandatory = $true)][string] $InstallRoot)

    $manifestPath = Join-Path $InstallRoot "install.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return $null
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 |
        ConvertFrom-Json -ErrorAction Stop
    if (-not $manifest.PSObject.Properties["schemaVersion"] -or
        [int]$manifest.schemaVersion -ne 1) {
        return $null
    }
    Assert-SteinPhase2JsonShape -Value $manifest -Description "The legacy Phase 1 install record" `
        -ExpectedProperties @(
            "schemaVersion",
            "version",
            "installedAtUtc",
            "installedBy",
            "installedBySid",
            "taskName",
            "installRoot",
            "packageBuiltAtUtc"
        )
    if ([string]$manifest.installedBySid -cne (Get-SteinPhase2CurrentUserSid) -or
        [string]$manifest.taskName -cne (Get-SteinPhase2TaskName) -or
        -not (Test-SteinPhase2PathEqual -Left ([string]$manifest.installRoot) -Right $InstallRoot)) {
        throw "The legacy Phase 1 install record does not belong to this exact user/root."
    }

    $binRoot = Join-Path $InstallRoot "bin"
    $files = @{}
    foreach ($leaf in @(
            "stein-core.exe",
            "stein-cli.exe",
            "stein-desktop.exe",
            "start-core.cmd")) {
        $files[$leaf] = Resolve-SteinPhase2RegularFile -Path (Join-Path $binRoot $leaf)
    }
    $tasks = @(Get-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction SilentlyContinue)
    if ($tasks.Count -ne 1 -or
        [string]$tasks[0].Principal.RunLevel -cne "Limited") {
        throw "The legacy Phase 1 task is missing or is not limited."
    }
    $task = $tasks[0]
    $actions = @($task.Actions)
    $triggers = @($task.Triggers)
    $expectedCmd = Join-Path $env:SystemRoot "System32\cmd.exe"
    $expectedArguments = '/d /c ""{0}""' -f $files["start-core.cmd"]
    if ($actions.Count -ne 1 -or
        $triggers.Count -ne 1 -or
        -not (Test-SteinPhase2PathEqual -Left ([string]$actions[0].Execute) -Right $expectedCmd) -or
        [string]$actions[0].Arguments -cne $expectedArguments -or
        -not (Test-SteinPhase2PathEqual `
            -Left ([string]$actions[0].WorkingDirectory) `
            -Right $InstallRoot) -or
        (Resolve-SteinPhase2IdentitySid -Identity ([string]$triggers[0].UserId)) -cne
            (Get-SteinPhase2CurrentUserSid) -or
        (Resolve-SteinPhase2IdentitySid -Identity ([string]$task.Principal.UserId)) -cne
            (Get-SteinPhase2CurrentUserSid) -or
        [string]$task.Principal.LogonType -cne "Interactive" -or
        [bool]$task.Settings.DisallowStartIfOnBatteries -or
        [bool]$task.Settings.StopIfGoingOnBatteries -or
        [string]$task.Settings.MultipleInstances -cne "IgnoreNew") {
        throw "The legacy Phase 1 task does not match its accepted lifecycle contract."
    }
    $launcher = Get-Content -LiteralPath $files["start-core.cmd"] -Raw -Encoding Default
    if ($launcher.IndexOf('"%~dp0stein-core.exe" --installed', [StringComparison]::Ordinal) -lt 0 -or
        $launcher.IndexOf("--private-package", [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $launcher.IndexOf("--broker-aumid", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The legacy Phase 1 launcher does not invoke only the accepted installed CORE mode."
    }
    $processes = @(Get-SteinPhase2ProcessByPath -ExecutablePath $files["stein-core.exe"])
    if ($processes.Count -ne 1) {
        throw "The legacy Phase 1 install does not have exactly one CORE process."
    }
    $status = Invoke-SteinPhase2CliJson `
        -CliPath $files["stein-cli.exe"] `
        -Arguments "status --json" `
        -TimeoutMilliseconds 3000
    if (-not $status.Succeeded -or
        $null -eq $status.Json -or
        $status.Json.runtime.health -cne "healthy") {
        throw "The legacy Phase 1 daemon is not healthy enough for a checked transition."
    }
    if (@(Get-SteinPhase2InstalledPackages).Count -ne 0) {
        throw "A production MSIX already exists beside the legacy Phase 1 install."
    }
    return [pscustomobject]@{
        Manifest = $manifest
        ManifestPath = $manifestPath
        BinRoot = $binRoot
        CorePath = $files["stein-core.exe"]
        CliPath = $files["stein-cli.exe"]
        DesktopPath = $files["stein-desktop.exe"]
        Task = $task
    }
}

function Get-SteinCurrentPhase2ForUpgrade {
    param(
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)] $NewBundle
    )

    $record = Read-SteinPhase2InstallRecord -InstallRoot $InstallRoot
    $current = Get-SteinPhase2InstalledBundle `
        -InstallRoot $InstallRoot `
        -Publisher ([string]$record.publisher) `
        -CertificateThumbprint ([string]$record.signing_certificate_thumbprint) `
        -Version ([string]$record.version)
    if ($current.Bundle.Publisher -cne $NewBundle.Publisher -or
        $current.Bundle.PackageFamilyName -cne $NewBundle.PackageFamilyName) {
        throw "Regular upgrade cannot rotate Publisher/PFN; uninstall or an explicit future identity-rotation flow is required."
    }
    if ((ConvertTo-SteinPhase2Version -Version $NewBundle.Version) -le
        (ConvertTo-SteinPhase2Version -Version $current.Bundle.Version)) {
        throw "Upgrade requires a strictly newer four-component package version."
    }
    $installedPackage = Assert-SteinPhase2InstalledPackage -Bundle $current.Bundle
    if ([string]$installedPackage.PackageFullName -cne [string]$record.package_full_name) {
        throw "The current package full name differs from the protected install record."
    }
    $null = Assert-SteinPhase2Task `
        -InstallRoot $InstallRoot `
        -CorePath $current.CorePath
    if (@(Get-SteinPhase2ProcessByPath -ExecutablePath $current.CorePath).Count -ne 1) {
        throw "Upgrade requires exactly one current installed CORE process."
    }
    $status = Invoke-SteinPhase2CliJson `
        -CliPath $current.CliPath `
        -Arguments "status --json" `
        -TimeoutMilliseconds 3000
    if (-not $status.Succeeded -or $null -eq $status.Json) {
        throw "The current daemon is not healthy enough for a checked upgrade."
    }
    $null = Assert-SteinPhase2PersistenceReadyStatus -Status $status.Json
    Assert-SteinPhase2OwnerOnlyTree -Root $InstallRoot
    if (Test-Path -LiteralPath (Join-Path $InstallRoot "lifecycle\recovery-required.json")) {
        throw "A prior lifecycle recovery condition must be resolved before upgrade."
    }
    return $current
}

function Export-SteinPhase2TaskXml {
    param(
        [Parameter(Mandatory = $true)][string] $TaskName,
        [Parameter(Mandatory = $true)][string] $Destination
    )

    $xml = Export-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $xml | Set-Content -LiteralPath $Destination -Encoding Unicode -ErrorAction Stop
    Protect-SteinPhase2OwnerOnlyPath -Path $Destination
}

function Restore-SteinPhase2TaskXml {
    param(
        [Parameter(Mandatory = $true)][string] $TaskName,
        [Parameter(Mandatory = $true)][string] $Source
    )

    $xml = Get-Content -LiteralPath $Source -Raw -Encoding Unicode -ErrorAction Stop
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Xml $xml `
        -Force `
        -ErrorAction Stop | Out-Null
}

function Wait-SteinLegacyPhase1Ready {
    param(
        [Parameter(Mandatory = $true)][string] $CorePath,
        [Parameter(Mandatory = $true)][string] $CliPath
    )

    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.ElapsedMilliseconds -lt $script:SteinPhase2ReadyTimeoutMilliseconds) {
        if (@(Get-SteinPhase2ProcessByPath -ExecutablePath $CorePath).Count -eq 1) {
            $status = Invoke-SteinPhase2CliJson `
                -CliPath $CliPath `
                -Arguments "status --json" `
                -TimeoutMilliseconds 1500
            if ($status.Succeeded -and
                $null -ne $status.Json -and
                $status.Json.runtime.health -ceq "healthy") {
                return
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw "The restored legacy Phase 1 daemon did not become healthy."
}

function Remove-SteinLegacyShortcutIfExact {
    param([Parameter(Mandatory = $true)][string] $LegacyDesktopPath)

    $shortcutPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "STEIN.lnk"
    if (-not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)) {
        return
    }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    if (Test-SteinPhase2PathEqual -Left ([string]$shortcut.TargetPath) -Right $LegacyDesktopPath) {
        Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction Stop
    }
}

function Upgrade-SteinPhase2 {
    param(
        [Parameter(Mandatory = $true)][string] $PackagePath,
        [Parameter(Mandatory = $true)][string] $Publisher,
        [Parameter(Mandatory = $true)][string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)][string] $Version,
        [Parameter(Mandatory = $true)][string] $InstallRoot
    )

    Assert-SteinPhase2WindowsHost
    $InstallRoot = Assert-SteinPhase2InstallRoot -InstallRoot $InstallRoot
    if (-not (Test-Path -LiteralPath $InstallRoot -PathType Container)) {
        throw "No installed STEIN lifecycle exists; use Install.ps1."
    }
    Assert-SteinPhase2NoReparseTree -Root $InstallRoot
    $sourceBundle = Get-SteinPhase2ReleaseBundle `
        -PackagePath $PackagePath `
        -Publisher $Publisher `
        -CertificateThumbprint $CertificateThumbprint `
        -Version $Version

    $legacy = Get-SteinLegacyPhase1Install -InstallRoot $InstallRoot
    $current = $null
    if ($null -eq $legacy) {
        $current = Get-SteinCurrentPhase2ForUpgrade `
            -InstallRoot $InstallRoot `
            -NewBundle $sourceBundle
    }

    Initialize-SteinPhase2Directories -InstallRoot $InstallRoot
    $lifecycleRoot = Join-Path $InstallRoot "lifecycle"
    $transactionId = [Guid]::NewGuid().ToString("N")
    $stageRoot = Join-Path $lifecycleRoot "staging-$transactionId"
    $rollbackRoot = Join-Path $lifecycleRoot "rollback-$transactionId"
    $databasePath = Join-Path $InstallRoot "data\stein.db"
    $recoveryPath = Join-Path $InstallRoot "data\.phase2-upgrade-recovery-$transactionId.db"
    $inProgressPath = Join-Path $lifecycleRoot "upgrade-in-progress.json"
    $taskXmlPath = Join-Path $rollbackRoot "task.xml"
    $oldDatabaseExisted = Test-Path -LiteralPath $databasePath -PathType Leaf
    $recovery = $null
    $packageChanged = $false
    $packageMutationAttempted = $false
    $newTaskRegistered = $false
    $rollbackSucceeded = $false
    $mutationStarted = $false
    $oldInstalledAt = if ($null -ne $legacy) {
        [string]$legacy.Manifest.installedAtUtc
    }
    else {
        [string]$current.Record.installed_at_utc
    }

    try {
        $bundle = Copy-SteinPhase2BundleToDirectory `
            -Bundle $sourceBundle `
            -Destination $stageRoot `
            -Publisher $Publisher `
            -CertificateThumbprint $CertificateThumbprint `
            -Version $Version
        $null = New-Item -ItemType Directory -Path $rollbackRoot -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyPath -Path $rollbackRoot
        Export-SteinPhase2TaskXml `
            -TaskName (Get-SteinPhase2TaskName) `
            -Destination $taskXmlPath

        $transaction = [ordered]@{
            schema_version = 1
            state = "upgrade_in_progress"
            transaction_id = $transactionId
            from_lifecycle = if ($null -ne $legacy) { "phase1" } else { "phase2" }
            to_version = $bundle.Version
            owner_sid = Get-SteinPhase2CurrentUserSid
            started_at_utc = [DateTime]::UtcNow.ToString("o")
        }
        Write-SteinPhase2JsonAtomic -Path $inProgressPath -Value $transaction

        $rollbackBin = Join-Path $rollbackRoot "bin"
        Copy-Item -LiteralPath (Join-Path $InstallRoot "bin") `
            -Destination $rollbackBin `
            -Recurse `
            -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyTree -Root $rollbackBin
        Copy-Item -LiteralPath (Join-Path $InstallRoot "install.json") `
            -Destination (Join-Path $rollbackRoot "install.json") `
            -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyPath -Path (Join-Path $rollbackRoot "install.json")

        if ($null -eq $legacy) {
            $rollbackRelease = Join-Path $rollbackRoot "release"
            Copy-Item -LiteralPath (Join-Path $lifecycleRoot "current") `
                -Destination $rollbackRelease `
                -Recurse `
                -ErrorAction Stop
            Protect-SteinPhase2OwnerOnlyTree -Root $rollbackRelease
            $oldBundle = Get-SteinPhase2ReleaseBundle `
                -PackagePath (Join-Path $rollbackRelease $current.Bundle.PackageLeaf) `
                -Publisher $current.Bundle.Publisher `
                -CertificateThumbprint $current.Bundle.CertificateThumbprint `
                -Version $current.Bundle.Version
        }
        else {
            $oldBundle = $null
        }

        # Every rollback input is now protected and independently readable.
        # Only after that point may this script stop or replace live state.
        $mutationStarted = $true
        $oldCorePath = if ($null -ne $legacy) { $legacy.CorePath } else { $current.CorePath }
        $oldCliPath = if ($null -ne $legacy) { $legacy.CliPath } else { $current.CliPath }
        Stop-SteinPhase2DaemonCleanly -CorePath $oldCorePath -CliPath $oldCliPath
        if ($null -ne $legacy -and
            -not (Stop-SteinPhase2ProcessByPath -ExecutablePath $legacy.DesktopPath)) {
            throw "The unpackaged Phase 1 desktop did not stop for the package transition."
        }

        $recovery = New-SteinPhase2ColdRecoveryCopy `
            -DatabasePath $databasePath `
            -RecoveryPath $recoveryPath

        $packageMutationAttempted = $true
        Add-AppxPackage `
            -Path $bundle.PackagePath `
            -ForceApplicationShutdown `
            -ErrorAction Stop
        $packageChanged = $true
        $installedPackage = Assert-SteinPhase2InstalledPackage -Bundle $bundle

        $binRoot = Join-Path $InstallRoot "bin"
        Remove-Item -LiteralPath $binRoot -Recurse -Force -ErrorAction Stop
        $null = New-Item -ItemType Directory -Path $binRoot -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyPath -Path $binRoot
        $binaries = Install-SteinPhase2Binaries -Bundle $bundle -InstallRoot $InstallRoot

        $currentRoot = Join-Path $lifecycleRoot "current"
        if (Test-Path -LiteralPath $currentRoot) {
            Remove-Item -LiteralPath $currentRoot -Recurse -Force -ErrorAction Stop
        }
        Move-Item -LiteralPath $stageRoot -Destination $currentRoot -ErrorAction Stop
        $stageRoot = $null
        Protect-SteinPhase2OwnerOnlyTree -Root $currentRoot

        $null = Register-SteinPhase2Task `
            -InstallRoot $InstallRoot `
            -CorePath $binaries.CorePath
        $newTaskRegistered = $true
        Start-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction Stop
        $runtime = Wait-SteinPhase2Ready `
            -Bundle $bundle `
            -InstallRoot $InstallRoot `
            -CorePath $binaries.CorePath `
            -CliPath $binaries.CliPath

        $record = New-SteinPhase2InstallRecord `
            -Bundle $bundle `
            -InstalledPackage $installedPackage `
            -InstallRoot $InstallRoot `
            -State "installed" `
            -InstalledAtUtc $oldInstalledAt
        Write-SteinPhase2JsonAtomic `
            -Path (Join-Path $InstallRoot "install.json") `
            -Value $record

        if ($null -ne $legacy) {
            Remove-SteinLegacyShortcutIfExact -LegacyDesktopPath $legacy.DesktopPath
        }
        if ($null -ne $recovery -and (Test-Path -LiteralPath $recovery.Path)) {
            Remove-Item -LiteralPath $recovery.Path -Force -ErrorAction Stop
        }
        Remove-Item -LiteralPath $rollbackRoot -Recurse -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $inProgressPath) {
            Remove-Item -LiteralPath $inProgressPath -Force -ErrorAction Stop
        }
        Protect-SteinPhase2OwnerOnlyTree -Root $InstallRoot
        Assert-SteinPhase2OwnerOnlyTree -Root $InstallRoot

        return [pscustomobject]@{
            installed = $true
            upgraded = $true
            upgraded_from = if ($null -ne $legacy) { "phase1" } else { $current.Bundle.Version }
            package_family_name = $bundle.PackageFamilyName
            desktop_aumid = $bundle.DesktopAumid
            broker_aumid = $bundle.BrokerAumid
            version = $bundle.Version
            task_name = Get-SteinPhase2TaskName
            core = $runtime
            migration_readiness_verified = $true
            migration_readiness_signal = "durable_persistence:healthy"
            numeric_schema_version_reported = $false
        }
    }
    catch {
        $failure = $_
        if (-not $mutationStarted) {
            foreach ($path in @($inProgressPath, $rollbackRoot)) {
                if (Test-Path -LiteralPath $path) {
                    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            throw $failure
        }
        try {
            Stop-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction SilentlyContinue
            Unregister-ScheduledTask `
                -TaskName (Get-SteinPhase2TaskName) `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
            $newCorePath = Join-Path $InstallRoot "bin\stein-core.exe"
            if (Test-Path -LiteralPath $newCorePath -PathType Leaf) {
                $null = Stop-SteinPhase2ProcessByPath -ExecutablePath $newCorePath
            }

            if ($null -ne $legacy) {
                if ($packageChanged -or $packageMutationAttempted) {
                    Remove-SteinPhase2ExactPackageIfPresent -Bundle $sourceBundle
                }
            }
            elseif ($packageChanged -or $packageMutationAttempted) {
                Add-AppxPackage `
                    -Path $oldBundle.PackagePath `
                    -ForceApplicationShutdown `
                    -ForceUpdateFromAnyVersion `
                    -ErrorAction Stop
                $null = Assert-SteinPhase2InstalledPackage -Bundle $oldBundle
            }

            $binRoot = Join-Path $InstallRoot "bin"
            if (Test-Path -LiteralPath $binRoot) {
                Remove-Item -LiteralPath $binRoot -Recurse -Force -ErrorAction Stop
            }
            Move-Item -LiteralPath (Join-Path $rollbackRoot "bin") `
                -Destination $binRoot `
                -ErrorAction Stop
            Protect-SteinPhase2OwnerOnlyTree -Root $binRoot
            Copy-Item -LiteralPath (Join-Path $rollbackRoot "install.json") `
                -Destination (Join-Path $InstallRoot "install.json") `
                -Force `
                -ErrorAction Stop
            Protect-SteinPhase2OwnerOnlyPath -Path (Join-Path $InstallRoot "install.json")

            if ($null -eq $legacy) {
                $currentRoot = Join-Path $lifecycleRoot "current"
                if (Test-Path -LiteralPath $currentRoot) {
                    Remove-Item -LiteralPath $currentRoot -Recurse -Force -ErrorAction Stop
                }
                Move-Item -LiteralPath (Join-Path $rollbackRoot "release") `
                    -Destination $currentRoot `
                    -ErrorAction Stop
                Protect-SteinPhase2OwnerOnlyTree -Root $currentRoot
            }

            if ($oldDatabaseExisted) {
                Restore-SteinPhase2ColdRecoveryCopy `
                    -DatabasePath $databasePath `
                    -Recovery $recovery
            }
            else {
                foreach ($path in @(
                        $databasePath,
                        "$databasePath-journal",
                        "$databasePath-wal",
                        "$databasePath-shm")) {
                    if (Test-Path -LiteralPath $path) {
                        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                    }
                }
            }

            Restore-SteinPhase2TaskXml `
                -TaskName (Get-SteinPhase2TaskName) `
                -Source $taskXmlPath
            Start-ScheduledTask -TaskName (Get-SteinPhase2TaskName) -ErrorAction Stop
            if ($null -ne $legacy) {
                Wait-SteinLegacyPhase1Ready `
                    -CorePath (Join-Path $binRoot "stein-core.exe") `
                    -CliPath (Join-Path $binRoot "stein-cli.exe")
            }
            else {
                $null = Wait-SteinPhase2Ready `
                    -Bundle $oldBundle `
                    -InstallRoot $InstallRoot `
                    -CorePath (Join-Path $binRoot "stein-core.exe") `
                    -CliPath (Join-Path $binRoot "stein-cli.exe")
            }
            $rollbackSucceeded = $true
        }
        catch {
            $rollbackSucceeded = $false
        }

        if ($rollbackSucceeded) {
            foreach ($path in @($recoveryPath, $inProgressPath, $rollbackRoot)) {
                if (Test-Path -LiteralPath $path) {
                    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            if ($null -ne $stageRoot -and (Test-Path -LiteralPath $stageRoot)) {
                Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
                $stageRoot = $null
            }
            throw "Phase 2 upgrade failed; the prior installation was restored. Original failure: $($failure.Exception.Message)"
        }

        try {
            Write-SteinPhase2RecoveryRequired -InstallRoot $InstallRoot -Stage "upgrade_rollback"
        }
        catch { }
        throw "Phase 2 upgrade failed and automatic rollback is incomplete; do not start CORE until protected recovery state is resolved."
    }
    finally {
        if ($null -ne $stageRoot -and (Test-Path -LiteralPath $stageRoot)) {
            Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
