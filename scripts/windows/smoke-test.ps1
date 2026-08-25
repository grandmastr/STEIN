[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "STEIN"),
    [string]$ReportPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
. (Join-Path $PSScriptRoot "common.ps1")

$InstallRoot = Assert-SteinSafeInstallRoot $InstallRoot
$TaskName = Get-SteinTaskName
$CliExe = Join-Path $InstallRoot "bin\stein-cli.exe"
$CoreExe = Join-Path $InstallRoot "bin\stein-core.exe"
$DesktopExe = Join-Path $InstallRoot "bin\stein-desktop.exe"
$CoreLauncher = Join-Path $InstallRoot "bin\start-core.cmd"
$SupervisionProofMarker = Join-Path $InstallRoot "data\supervision-proof.once"
if (-not $ReportPath) {
    $ReportPath = Join-Path $InstallRoot "smoke-report.json"
}

$Checks = New-Object System.Collections.Generic.List[object]
$FailureMessage = $null
$RenderedReport = $null

function Add-Check([string]$Name, [bool]$Passed, [object]$Evidence) {
    $script:Checks.Add([ordered]@{
        name = $Name
        passed = $Passed
        evidence = $Evidence
    }) | Out-Null
}

function Assert-Check([string]$Name, [bool]$Passed, [object]$Evidence) {
    Add-Check -Name $Name -Passed $Passed -Evidence $Evidence
    if (-not $Passed) {
        throw "Smoke prerequisite failed: $Name"
    }
}

function Invoke-CheckedJson([string]$Arguments, [int]$TimeoutMilliseconds = 6000) {
    $Result = Invoke-SteinCliJson `
        -CliPath $script:CliExe `
        -Arguments $Arguments `
        -TimeoutMilliseconds $TimeoutMilliseconds
    if (-not $Result.succeeded -or -not $Result.json) {
        $Detail = if ($Result.timedOut) {
            "timed out"
        } elseif ($Result.stderr) {
            $Result.stderr.Trim()
        } else {
            "exit code $($Result.exitCode)"
        }
        throw "stein-cli $Arguments failed: $Detail"
    }
    return $Result.json
}

function Wait-SteinDesktopConnection(
    [Parameter(Mandatory = $true)][Diagnostics.Process]$DesktopProcess,
    [Parameter(Mandatory = $true)][string]$ExpectedDaemonInstance,
    [int]$TimeoutMilliseconds = 20000
) {
    $Timer = [Diagnostics.Stopwatch]::StartNew()
    $LastStatus = $null
    while ($Timer.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        $DesktopProcess.Refresh()
        if ($DesktopProcess.HasExited) {
            return [pscustomobject]@{
                connected = $false
                stayedAlive = $false
                processCount = @(Get-SteinProcessByPath $script:DesktopExe).Count
                status = $LastStatus
                detail = "desktop exited with code $($DesktopProcess.ExitCode)"
            }
        }
        $Attempt = Invoke-SteinCliJson `
            -CliPath $script:CliExe `
            -Arguments "status --json" `
            -TimeoutMilliseconds 1250
        if ($Attempt.succeeded -and $Attempt.json) {
            $LastStatus = $Attempt.json
            $ProcessCount = @(Get-SteinProcessByPath $script:DesktopExe).Count
            if (
                $ProcessCount -eq 1 -and
                $LastStatus.runtime.health -eq "healthy" -and
                $LastStatus.runtime.daemonInstanceId -eq $ExpectedDaemonInstance -and
                [int]$LastStatus.runtime.activeConnections -ge 2
            ) {
                return [pscustomobject]@{
                    connected = $true
                    stayedAlive = $true
                    processCount = $ProcessCount
                    status = $LastStatus
                    detail = "desktop and CLI were concurrently connected"
                }
            }
        }
        Start-Sleep -Milliseconds 250
    }
    $DesktopProcess.Refresh()
    return [pscustomobject]@{
        connected = $false
        stayedAlive = (-not $DesktopProcess.HasExited)
        processCount = @(Get-SteinProcessByPath $script:DesktopExe).Count
        status = $LastStatus
        detail = "desktop did not establish a visible CORE connection within 20 seconds"
    }
}

try {
    Assert-Check "required_binaries" `
        ((Test-Path -LiteralPath $CliExe -PathType Leaf) -and
         (Test-Path -LiteralPath $CoreExe -PathType Leaf) -and
         (Test-Path -LiteralPath $DesktopExe -PathType Leaf)) `
        ([ordered]@{ cli = $CliExe; core = $CoreExe; desktop = $DesktopExe })

    $Tasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    Assert-Check "exactly_one_task" ($Tasks.Count -eq 1) `
        ([ordered]@{ taskName = $TaskName; count = $Tasks.Count })
    $Task = $Tasks[0]
    Assert-Check "task_limited_interactive" `
        ($Task.Principal.RunLevel -eq "Limited" -and $Task.Principal.LogonType -eq "Interactive") `
        ([ordered]@{
            runLevel = [string]$Task.Principal.RunLevel
            logonType = [string]$Task.Principal.LogonType
        })
    Assert-Check "task_restart_policy" `
        ($Task.Settings.RestartCount -ge 1 -and $Task.Settings.RestartInterval) `
        ([ordered]@{
            count = $Task.Settings.RestartCount
            interval = [string]$Task.Settings.RestartInterval
        })
    Assert-Check "task_battery_safe" `
        (-not $Task.Settings.DisallowStartIfOnBatteries -and -not $Task.Settings.StopIfGoingOnBatteries) `
        ([ordered]@{
            disallowStartIfOnBatteries = [bool]$Task.Settings.DisallowStartIfOnBatteries
            stopIfGoingOnBatteries = [bool]$Task.Settings.StopIfGoingOnBatteries
        })
    Assert-Check "task_uses_supervision_launcher" `
        ($Task.Actions.Count -eq 1 -and
         [IO.Path]::GetFileName($Task.Actions[0].Execute) -eq "cmd.exe" -and
         $Task.Actions[0].Arguments.Contains($CoreLauncher)) `
        ([ordered]@{
            execute = $Task.Actions[0].Execute
            arguments = $Task.Actions[0].Arguments
        })

    $PreexistingDesktop = @(Get-SteinProcessByPath $DesktopExe)
    if ($PreexistingDesktop.Count -gt 0) {
        $DesktopStopped = Stop-SteinProcessByPath -ExecutablePath $DesktopExe -TimeoutMilliseconds 5000
        Assert-Check "clean_desktop_precondition" $DesktopStopped `
            ([ordered]@{ stoppedCount = $PreexistingDesktop.Count })
    } else {
        Add-Check "clean_desktop_precondition" $true "no presentation process was running"
    }

    $CoreProcesses = @(Get-SteinProcessByPath $CoreExe)
    Assert-Check "exactly_one_daemon" ($CoreProcesses.Count -eq 1) `
        ([ordered]@{ count = $CoreProcesses.Count; processIds = @($CoreProcesses.ProcessId) })

    $Initial = Invoke-CheckedJson "status --json"
    Assert-Check "daemon_without_desktop" `
        ($Initial.runtime.health -eq "healthy" -and @(Get-SteinProcessByPath $DesktopExe).Count -eq 0) `
        ([ordered]@{
            health = $Initial.runtime.health
            daemonInstanceId = $Initial.runtime.daemonInstanceId
            desktopProcessCount = @(Get-SteinProcessByPath $DesktopExe).Count
        })
    $OriginalInstance = [string]$Initial.runtime.daemonInstanceId

    $Proof = Invoke-CheckedJson "proof --json" 10000
    Assert-Check "command_event_reconnect_snapshot" ([bool]$Proof.passed) $Proof

    $BadProtocol = Invoke-SteinProcess `
        -FilePath $CliExe `
        -Arguments "protocol-check --major 999 --json" `
        -TimeoutMilliseconds 6000
    $BadProtocolJson = $null
    if (-not [string]::IsNullOrWhiteSpace($BadProtocol.stdout)) {
        try { $BadProtocolJson = $BadProtocol.stdout | ConvertFrom-Json } catch { }
    }
    Assert-Check "incompatible_major_rejected" `
        (-not $BadProtocol.timedOut -and
         $BadProtocol.exitCode -ne 0 -and
         $null -ne $BadProtocolJson -and
         $BadProtocolJson.accepted -eq $false -and
         $BadProtocolJson.requestedMajor -eq 999 -and
         ([string]$BadProtocolJson.error).Contains("compatible protocol version")) `
        ([ordered]@{
            exitCode = $BadProtocol.exitCode
            timedOut = $BadProtocol.timedOut
            accepted = if ($BadProtocolJson) { $BadProtocolJson.accepted } else { $null }
            requestedMajor = if ($BadProtocolJson) { $BadProtocolJson.requestedMajor } else { $null }
            error = if ($BadProtocolJson) { $BadProtocolJson.error } else { $null }
        })

    $Cancellation = Invoke-CheckedJson "cancellation-proof --json" 6000
    Assert-Check "request_cancellation" ([bool]$Cancellation.passed) $Cancellation

    $ConnectionLimit = Invoke-CheckedJson "connection-limit-proof --json" 15000
    Assert-Check "connection_limit_and_recovery" ([bool]$ConnectionLimit.passed) $ConnectionLimit

    $DesktopFirst = Start-Process -FilePath $DesktopExe -PassThru
    $FirstConnection = Wait-SteinDesktopConnection `
        -DesktopProcess $DesktopFirst `
        -ExpectedDaemonInstance $OriginalInstance
    Assert-Check "desktop_stays_alive_and_connects" `
        ($FirstConnection.stayedAlive -and $FirstConnection.connected) `
        ([ordered]@{
            processId = $DesktopFirst.Id
            processCount = $FirstConnection.processCount
            activeConnections = if ($FirstConnection.status) {
                $FirstConnection.status.runtime.activeConnections
            } else { $null }
            detail = $FirstConnection.detail
        })

    Assert-Check "desktop_first_close" `
        (Stop-SteinProcessByPath -ExecutablePath $DesktopExe -TimeoutMilliseconds 5000) `
        ([ordered]@{ priorProcessId = $DesktopFirst.Id })
    $AfterClose = Invoke-CheckedJson "status --json"
    Assert-Check "desktop_independence" `
        ($AfterClose.runtime.health -eq "healthy" -and
         $AfterClose.runtime.daemonInstanceId -eq $OriginalInstance -and
         @(Get-SteinProcessByPath $CoreExe).Count -eq 1) `
        ([ordered]@{
            daemonInstanceId = $AfterClose.runtime.daemonInstanceId
            coreProcessCount = @(Get-SteinProcessByPath $CoreExe).Count
        })

    $DesktopSecond = Start-Process -FilePath $DesktopExe -PassThru
    $SecondConnection = Wait-SteinDesktopConnection `
        -DesktopProcess $DesktopSecond `
        -ExpectedDaemonInstance $OriginalInstance
    Assert-Check "desktop_reopen_reconnects_same_daemon" `
        ($SecondConnection.stayedAlive -and
         $SecondConnection.connected -and
         $SecondConnection.status.runtime.daemonInstanceId -eq $OriginalInstance) `
        ([ordered]@{
            processId = $DesktopSecond.Id
            processCount = $SecondConnection.processCount
            daemonInstanceId = if ($SecondConnection.status) {
                $SecondConnection.status.runtime.daemonInstanceId
            } else { $null }
            activeConnections = if ($SecondConnection.status) {
                $SecondConnection.status.runtime.activeConnections
            } else { $null }
            detail = $SecondConnection.detail
        })
    Assert-Check "desktop_second_close" `
        (Stop-SteinProcessByPath -ExecutablePath $DesktopExe -TimeoutMilliseconds 5000) `
        ([ordered]@{ priorProcessId = $DesktopSecond.Id })

    $CoreBeforeRestart = @(Get-SteinProcessByPath $CoreExe)
    Assert-Check "single_daemon_before_restart" ($CoreBeforeRestart.Count -eq 1) `
        ([ordered]@{ count = $CoreBeforeRestart.Count })

    New-Item -ItemType Directory -Path (Split-Path -Parent $SupervisionProofMarker) -Force |
        Out-Null
    Set-Content -LiteralPath $SupervisionProofMarker -Value "one-shot" -Encoding ASCII
    $Shutdown = Invoke-SteinProcess `
        -FilePath $CliExe `
        -Arguments "shutdown --timeout-ms 3000" `
        -TimeoutMilliseconds 4500
    Assert-Check "supervision_setup_clean_shutdown" $Shutdown.succeeded `
        ([ordered]@{
            exitCode = $Shutdown.exitCode
            timedOut = $Shutdown.timedOut
            output = $Shutdown.stdout.Trim()
        })

    $Restarted = $null
    $RestartTimer = [Diagnostics.Stopwatch]::StartNew()
    while ($RestartTimer.ElapsedMilliseconds -lt 30000) {
        $RestartAttempt = Invoke-SteinCliJson `
            -CliPath $CliExe `
            -Arguments "status --json" `
            -TimeoutMilliseconds 1250
        if (
            $RestartAttempt.succeeded -and
            $RestartAttempt.json -and
            $RestartAttempt.json.runtime.daemonInstanceId -ne $OriginalInstance
        ) {
            $Restarted = $RestartAttempt.json
            break
        }
        Start-Sleep -Milliseconds 250
    }
    Assert-Check "supervised_restart" ([bool]$Restarted) `
        ([ordered]@{
            oldInstance = $OriginalInstance
            newInstance = if ($Restarted) { $Restarted.runtime.daemonInstanceId } else { $null }
            markerConsumed = -not (Test-Path -LiteralPath $SupervisionProofMarker)
            oldProcessId = $CoreBeforeRestart[0].ProcessId
            elapsedMilliseconds = $RestartTimer.ElapsedMilliseconds
        })
    Assert-Check "supervised_restart_was_failure_driven" `
        (-not (Test-Path -LiteralPath $SupervisionProofMarker)) `
        ([ordered]@{
            markerConsumed = -not (Test-Path -LiteralPath $SupervisionProofMarker)
            taskState = [string](Get-ScheduledTask -TaskName $TaskName).State
        })
    $CoreAfterRestart = @(Get-SteinProcessByPath $CoreExe)
    Assert-Check "exactly_one_daemon_after_restart" ($CoreAfterRestart.Count -eq 1) `
        ([ordered]@{ count = $CoreAfterRestart.Count; processIds = @($CoreAfterRestart.ProcessId) })
} catch {
    $FailureMessage = $_.Exception.Message
    Add-Check "smoke_execution" $false $FailureMessage
} finally {
    $null = Stop-SteinProcessByPath -ExecutablePath $DesktopExe -TimeoutMilliseconds 5000
    if (Test-Path -LiteralPath $SupervisionProofMarker -PathType Leaf) {
        Remove-Item -LiteralPath $SupervisionProofMarker -Force -ErrorAction SilentlyContinue
    }

    if (@(Get-SteinProcessByPath $CoreExe).Count -eq 0) {
        try {
            $RemainingTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
            if ($RemainingTasks.Count -eq 1) {
                Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            }
        } catch { }
    }

    $FinalTask = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    $FinalTaskInfo = if ($FinalTask.Count -eq 1) {
        Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    } else { $null }
    $Passed = ($FailureMessage -eq $null -and -not ($Checks | Where-Object { -not $_.passed }))
    $Report = [ordered]@{
        schemaVersion = 1
        passed = [bool]$Passed
        testedAtUtc = [DateTime]::UtcNow.ToString("o")
        user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        userSid = Get-SteinCurrentUserSid
        taskName = $TaskName
        failure = $FailureMessage
        checks = $Checks
        task = [ordered]@{
            count = $FinalTask.Count
            state = if ($FinalTask.Count -eq 1) { [string]$FinalTask[0].State } else { "Missing" }
            lastResult = if ($FinalTaskInfo) { $FinalTaskInfo.LastTaskResult } else { $null }
            lastRunTime = if ($FinalTaskInfo) { $FinalTaskInfo.LastRunTime } else { $null }
        }
    }
    $ReportDirectory = Split-Path -Parent $ReportPath
    if ($ReportDirectory) {
        New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
    }
    $RenderedReport = $Report | ConvertTo-Json -Depth 12
    $RenderedReport | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}

$RenderedReport
if (-not $Passed) {
    throw "STEIN smoke test failed; report retained at $ReportPath"
}
