[CmdletBinding()]
param(
    [string]$PackageDir,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "STEIN"),
    [switch]$NoDesktopShortcut
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
. (Join-Path $PSScriptRoot "common.ps1")

$InstallRoot = Assert-SteinSafeInstallRoot $InstallRoot
if ([string]::IsNullOrWhiteSpace($PackageDir)) {
    # Windows PowerShell 5.1 can evaluate a $PSScriptRoot-backed parameter
    # default as an empty string when the script is entered through `-File`.
    # Resolve it after the script context has been established instead.
    $PackageDir = $PSScriptRoot
}
$PackageDir = (Resolve-Path $PackageDir).Path
$PackageManifest = Test-SteinPackage -PackageDir $PackageDir
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$IdentitySid = Get-SteinCurrentUserSid
$TaskName = Get-SteinTaskName
$BinDir = Join-Path $InstallRoot "bin"
$LogDir = Join-Path $InstallRoot "logs"
$DataDir = Join-Path $InstallRoot "data"
$CoreExe = Join-Path $BinDir "stein-core.exe"
$CliExe = Join-Path $BinDir "stein-cli.exe"
$DesktopExe = Join-Path $BinDir "stein-desktop.exe"
$CoreLauncher = Join-Path $BinDir "start-core.cmd"

New-Item -ItemType Directory -Path $BinDir, $LogDir, $DataDir -Force | Out-Null

$ExistingTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
if ($ExistingTasks.Count -gt 1) {
    throw "Multiple current-user STEIN tasks already exist; refusing an ambiguous upgrade"
}

if ($ExistingTasks.Count -eq 1) {
    if (Test-Path -LiteralPath $CliExe -PathType Leaf) {
        Write-Host "[STEIN] Requesting clean CORE shutdown before upgrade"
        $null = Invoke-SteinProcess `
            -FilePath $CliExe `
            -Arguments "shutdown --timeout-ms 3000" `
            -TimeoutMilliseconds 4500
    }
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}

if (-not (Stop-SteinProcessByPath -ExecutablePath $DesktopExe -TimeoutMilliseconds 5000)) {
    throw "The installed STEIN desktop did not stop before upgrade"
}
if (-not (Stop-SteinProcessByPath -ExecutablePath $CoreExe -TimeoutMilliseconds 5000)) {
    throw "The installed CORE process did not stop before upgrade"
}

foreach ($Name in @("stein-core.exe", "stein-cli.exe", "stein-desktop.exe", "start-core.cmd")) {
    Copy-Item -LiteralPath (Join-Path $PackageDir $Name) -Destination (Join-Path $BinDir $Name) -Force
}

$CmdExe = Join-Path $env:SystemRoot "System32\cmd.exe"
$LauncherArguments = '/d /c ""{0}""' -f $CoreLauncher
$Action = New-ScheduledTaskAction `
    -Execute $CmdExe `
    -Argument $LauncherArguments `
    -WorkingDirectory $InstallRoot
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $Identity
$Principal = New-ScheduledTaskPrincipal -UserId $Identity -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RestartCount 10 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "Presentation-independent per-user STEIN CORE daemon ($IdentitySid)" `
    -Force | Out-Null

$RegisteredTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop)
if ($RegisteredTasks.Count -ne 1) {
    throw "Expected exactly one registered current-user STEIN task"
}

Start-ScheduledTask -TaskName $TaskName

$Ready = $false
$LastStatus = $null
$ReadyTimer = [Diagnostics.Stopwatch]::StartNew()
while ($ReadyTimer.ElapsedMilliseconds -lt 30000) {
    $StatusAttempt = Invoke-SteinCliJson `
        -CliPath $CliExe `
        -Arguments "status --json" `
        -TimeoutMilliseconds 1250
    if (
        $StatusAttempt.succeeded -and
        $StatusAttempt.json -and
        $StatusAttempt.json.runtime.health -eq "healthy"
    ) {
        $Ready = $true
        $LastStatus = $StatusAttempt.json
        break
    }
    Start-Sleep -Milliseconds 250
}
if (-not $Ready) {
    $TaskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    $LastTaskResult = if ($TaskInfo) { $TaskInfo.LastTaskResult } else { $null }
    throw "CORE did not become ready within 30 seconds. Last task result: $LastTaskResult"
}

$InstalledCoreProcesses = @(Get-SteinProcessByPath $CoreExe)
if ($InstalledCoreProcesses.Count -ne 1) {
    throw "Expected exactly one installed CORE process; found $($InstalledCoreProcesses.Count)"
}

if (-not $NoDesktopShortcut) {
    $Shell = New-Object -ComObject WScript.Shell
    $ShortcutPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "STEIN.lnk"
    $Shortcut = $Shell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $DesktopExe
    $Shortcut.WorkingDirectory = $InstallRoot
    $Shortcut.Description = "Open the STEIN Phase 1 desktop"
    $Shortcut.Save()
}

$InstallManifest = [ordered]@{
    schemaVersion = 1
    version = $PackageManifest.version
    installedAtUtc = [DateTime]::UtcNow.ToString("o")
    installedBy = $Identity
    installedBySid = $IdentitySid
    taskName = $TaskName
    installRoot = $InstallRoot
    packageBuiltAtUtc = $PackageManifest.builtAtUtc
}
$InstallManifest | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $InstallRoot "install.json") -Encoding UTF8

Write-Host "[STEIN] Installed for $Identity at $InstallRoot"
$LastStatus | ConvertTo-Json -Depth 8
