[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "STEIN"),
    [switch]$Json
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
. (Join-Path $PSScriptRoot "common.ps1")

$InstallRoot = Assert-SteinSafeInstallRoot $InstallRoot
$TaskName = Get-SteinTaskName
$CoreExe = Join-Path $InstallRoot "bin\stein-core.exe"
$CliExe = Join-Path $InstallRoot "bin\stein-cli.exe"
$DesktopExe = Join-Path $InstallRoot "bin\stein-desktop.exe"
$InstallManifestPath = Join-Path $InstallRoot "install.json"
$RequiredFilesPresent = @($CoreExe, $CliExe, $DesktopExe, $InstallManifestPath) |
    ForEach-Object { Test-Path -LiteralPath $_ -PathType Leaf }
$Installed = -not ($RequiredFilesPresent -contains $false)

$Tasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
$Task = if ($Tasks.Count -eq 1) { $Tasks[0] } else { $null }
$TaskInfo = if ($Task) {
    Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
} else {
    $null
}
$CoreProcesses = @(Get-SteinProcessByPath $CoreExe)
$DesktopProcesses = @(Get-SteinProcessByPath $DesktopExe)

$CoreStatus = $null
$StatusFailure = $null
if (Test-Path -LiteralPath $CliExe -PathType Leaf) {
    $StatusAttempt = Invoke-SteinCliJson `
        -CliPath $CliExe `
        -Arguments "status --json" `
        -TimeoutMilliseconds 2000
    if ($StatusAttempt.succeeded) {
        $CoreStatus = $StatusAttempt.json
    } else {
        $StatusFailure = if ($StatusAttempt.timedOut) {
            "CORE status timed out"
        } elseif ($StatusAttempt.stderr) {
            $StatusAttempt.stderr.Trim()
        } else {
            "CORE status failed with exit code $($StatusAttempt.exitCode)"
        }
    }
}

$Healthy = (
    $Installed -and
    $Tasks.Count -eq 1 -and
    $CoreProcesses.Count -eq 1 -and
    $CoreStatus -and
    $CoreStatus.runtime.health -eq "healthy"
)
$Result = [ordered]@{
    healthy = [bool]$Healthy
    installed = [bool]$Installed
    taskName = $TaskName
    taskCount = $Tasks.Count
    taskState = if ($Task) { [string]$Task.State } else { "Missing" }
    lastTaskResult = if ($TaskInfo) { $TaskInfo.LastTaskResult } else { $null }
    lastRunTime = if ($TaskInfo) { $TaskInfo.LastRunTime } else { $null }
    coreProcessCount = $CoreProcesses.Count
    desktopProcessCount = $DesktopProcesses.Count
    core = $CoreStatus
    statusFailure = $StatusFailure
}

if ($Json) {
    $Result | ConvertTo-Json -Depth 8 -Compress
} else {
    $Result | ConvertTo-Json -Depth 8
}

if (-not $Healthy) {
    exit 1
}
