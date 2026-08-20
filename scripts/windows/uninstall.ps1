[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Medium")]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "STEIN"),
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
. (Join-Path $PSScriptRoot "common.ps1")

$InstallRoot = Assert-SteinSafeInstallRoot $InstallRoot
$IdentitySid = Get-SteinCurrentUserSid
$TaskName = Get-SteinTaskName
$BinDir = Join-Path $InstallRoot "bin"
$CliExe = Join-Path $BinDir "stein-cli.exe"
$CoreExe = Join-Path $BinDir "stein-core.exe"
$DesktopExe = Join-Path $BinDir "stein-desktop.exe"
$InstallManifestPath = Join-Path $InstallRoot "install.json"

if ($RemoveData) {
    if (-not (Test-Path -LiteralPath $InstallManifestPath -PathType Leaf)) {
        throw "Refusing RemoveData without the STEIN install manifest: $InstallManifestPath"
    }
    $InstallManifest = Get-Content -LiteralPath $InstallManifestPath -Raw | ConvertFrom-Json
    if (
        -not $InstallManifest.PSObject.Properties["installedBySid"] -or
        $InstallManifest.installedBySid -ne $IdentitySid
    ) {
        throw "Refusing RemoveData because the install manifest belongs to another user"
    }
    if (
        -not $InstallManifest.PSObject.Properties["installRoot"] -or
        -not (Test-SteinPathEqual -Left $InstallManifest.installRoot -Right $InstallRoot)
    ) {
        throw "Refusing RemoveData because the install manifest does not match InstallRoot"
    }
}

$Operation = if ($RemoveData) {
    "Uninstall STEIN and recursively remove its verified per-user data"
} else {
    "Uninstall STEIN binaries while preserving its per-user data"
}

if ($PSCmdlet.ShouldProcess($InstallRoot, $Operation)) {
    if (Test-Path -LiteralPath $CliExe -PathType Leaf) {
        $null = Invoke-SteinProcess `
            -FilePath $CliExe `
            -Arguments "shutdown --timeout-ms 3000" `
            -TimeoutMilliseconds 4500
    }

    $Tasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    if ($Tasks.Count -gt 0) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }

    if (-not (Stop-SteinProcessByPath -ExecutablePath $DesktopExe -TimeoutMilliseconds 5000)) {
        throw "The installed STEIN desktop did not stop during uninstall"
    }
    if (-not (Stop-SteinProcessByPath -ExecutablePath $CoreExe -TimeoutMilliseconds 5000)) {
        throw "The installed CORE process did not stop during uninstall"
    }

    if ($Tasks.Count -gt 0) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    }

    $ShortcutPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "STEIN.lnk"
    if (Test-Path -LiteralPath $ShortcutPath -PathType Leaf) {
        Remove-Item -LiteralPath $ShortcutPath -Force
    }
    if (Test-Path -LiteralPath $BinDir) {
        Remove-Item -LiteralPath $BinDir -Recurse -Force
    }

    if ($RemoveData) {
        Remove-Item -LiteralPath $InstallRoot -Recurse -Force
    } elseif (Test-Path -LiteralPath $InstallManifestPath -PathType Leaf) {
        $PreservedManifest = Get-Content -LiteralPath $InstallManifestPath -Raw | ConvertFrom-Json
        $PreservedManifest | Add-Member `
            -NotePropertyName uninstalledAtUtc `
            -NotePropertyValue ([DateTime]::UtcNow.ToString("o")) `
            -Force
        $PreservedManifest | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath $InstallManifestPath -Encoding UTF8
    }

    $RemainingTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    $RemainingCore = @(Get-SteinProcessByPath $CoreExe)
    $RemainingDesktop = @(Get-SteinProcessByPath $DesktopExe)
    if (
        $RemainingTasks.Count -ne 0 -or
        $RemainingCore.Count -ne 0 -or
        $RemainingDesktop.Count -ne 0 -or
        (Test-Path -LiteralPath $BinDir)
    ) {
        throw "Uninstall postconditions failed; a task, process, or binary directory remains"
    }

    if ($RemoveData) {
        Write-Host "[STEIN] Uninstalled and removed verified per-user data at $InstallRoot"
    } else {
        Write-Host "[STEIN] Uninstalled; logs/data under $InstallRoot were preserved"
    }
}
