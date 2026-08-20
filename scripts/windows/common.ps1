Set-StrictMode -Version 3.0

function Get-SteinCurrentUserSid {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Get-SteinTaskName {
    $Sid = Get-SteinCurrentUserSid
    # ScheduledTasks treats TaskName as a wildcard pattern. Keep the
    # per-user SID qualifier free of wildcard metacharacters so every
    # lifecycle command addresses exactly the registered task.
    return "STEIN Core SID-$Sid"
}

function ConvertTo-SteinCanonicalPath([Parameter(Mandatory = $true)][string]$Path) {
    return [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Test-SteinPathEqual(
    [Parameter(Mandatory = $true)][string]$Left,
    [Parameter(Mandatory = $true)][string]$Right
) {
    return [string]::Equals(
        (ConvertTo-SteinCanonicalPath $Left),
        (ConvertTo-SteinCanonicalPath $Right),
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-SteinSafeInstallRoot([Parameter(Mandatory = $true)][string]$InstallRoot) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is unavailable; refusing to resolve a per-user install root"
    }

    $Candidate = ConvertTo-SteinCanonicalPath $InstallRoot
    $LocalAppData = ConvertTo-SteinCanonicalPath $env:LOCALAPPDATA
    $RequiredPrefix = $LocalAppData + [IO.Path]::DirectorySeparatorChar
    if (-not $Candidate.StartsWith($RequiredPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "InstallRoot must be a child of the current user's LOCALAPPDATA directory: $LocalAppData"
    }
    if ($Candidate.Length -le ($RequiredPrefix.Length + 1)) {
        throw "InstallRoot is too broad for safe lifecycle operations: $Candidate"
    }
    return $Candidate
}

function Get-SteinProcessByPath([Parameter(Mandatory = $true)][string]$ExecutablePath) {
    $Canonical = ConvertTo-SteinCanonicalPath $ExecutablePath
    $Name = [IO.Path]::GetFileName($Canonical).Replace("'", "''")
    return @(
        Get-CimInstance Win32_Process -Filter "Name = '$Name'" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ExecutablePath -and
                [string]::Equals(
                    (ConvertTo-SteinCanonicalPath $_.ExecutablePath),
                    $Canonical,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    )
}

function Wait-SteinProcessExit(
    [Parameter(Mandatory = $true)][string]$ExecutablePath,
    [int]$TimeoutMilliseconds = 5000
) {
    $Timer = [Diagnostics.Stopwatch]::StartNew()
    while ($Timer.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        if (@(Get-SteinProcessByPath $ExecutablePath).Count -eq 0) {
            return $true
        }
        Start-Sleep -Milliseconds 100
    }
    return (@(Get-SteinProcessByPath $ExecutablePath).Count -eq 0)
}

function Stop-SteinProcessByPath(
    [Parameter(Mandatory = $true)][string]$ExecutablePath,
    [int]$TimeoutMilliseconds = 5000
) {
    $Processes = @(Get-SteinProcessByPath $ExecutablePath)
    foreach ($Process in $Processes) {
        Stop-Process -Id $Process.ProcessId -Force -ErrorAction SilentlyContinue
    }
    if ($Processes.Count -eq 0) {
        return $true
    }
    return (Wait-SteinProcessExit -ExecutablePath $ExecutablePath -TimeoutMilliseconds $TimeoutMilliseconds)
}

function Invoke-SteinProcess(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [string]$Arguments = "",
    [int]$TimeoutMilliseconds = 2000
) {
    $StartInfo = New-Object Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $FilePath
    $StartInfo.Arguments = $Arguments
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true

    $Process = New-Object Diagnostics.Process
    $Process.StartInfo = $StartInfo
    try {
        if (-not $Process.Start()) {
            throw "process did not start"
        }
        if (-not $Process.WaitForExit($TimeoutMilliseconds)) {
            try { $Process.Kill() } catch { }
            $Process.WaitForExit()
            return [pscustomobject]@{
                succeeded = $false
                timedOut = $true
                exitCode = $null
                stdout = $Process.StandardOutput.ReadToEnd()
                stderr = $Process.StandardError.ReadToEnd()
            }
        }
        $Process.WaitForExit()
        return [pscustomobject]@{
            succeeded = ($Process.ExitCode -eq 0)
            timedOut = $false
            exitCode = $Process.ExitCode
            stdout = $Process.StandardOutput.ReadToEnd()
            stderr = $Process.StandardError.ReadToEnd()
        }
    } catch {
        return [pscustomobject]@{
            succeeded = $false
            timedOut = $false
            exitCode = $null
            stdout = ""
            stderr = $_.Exception.Message
        }
    } finally {
        $Process.Dispose()
    }
}

function Invoke-SteinCliJson(
    [Parameter(Mandatory = $true)][string]$CliPath,
    [Parameter(Mandatory = $true)][string]$Arguments,
    [int]$TimeoutMilliseconds = 2000
) {
    $Result = Invoke-SteinProcess -FilePath $CliPath -Arguments $Arguments -TimeoutMilliseconds $TimeoutMilliseconds
    $Json = $null
    if ($Result.succeeded -and -not [string]::IsNullOrWhiteSpace($Result.stdout)) {
        try {
            $Json = $Result.stdout | ConvertFrom-Json
        } catch {
            $Result.succeeded = $false
            $Result.stderr = "CLI returned invalid JSON: $($_.Exception.Message)"
        }
    }
    $Result | Add-Member -NotePropertyName json -NotePropertyValue $Json
    return $Result
}

function Test-SteinPackage(
    [Parameter(Mandatory = $true)][string]$PackageDir,
    [string[]]$RequiredFiles = @(
        "stein-core.exe",
        "stein-cli.exe",
        "stein-desktop.exe",
        "start-core.cmd"
    )
) {
    $ManifestPath = Join-Path $PackageDir "manifest.json"
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Package manifest is missing: $ManifestPath"
    }
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    if ($Manifest.platform -ne "windows-x86_64") {
        throw "Package platform is not windows-x86_64"
    }
    $Entries = @($Manifest.files)
    foreach ($Required in $RequiredFiles) {
        if (-not ($Entries | Where-Object { $_.name -eq $Required })) {
            throw "Package manifest does not contain $Required"
        }
    }
    foreach ($Entry in $Entries) {
        $Name = [string]$Entry.name
        if ([IO.Path]::GetFileName($Name) -ne $Name) {
            throw "Package manifest contains an unsafe file name: $Name"
        }
        $Path = Join-Path $PackageDir $Name
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Package file is missing: $Name"
        }
        $File = Get-Item -LiteralPath $Path
        if ($File.Length -ne [long]$Entry.size) {
            throw "Package size mismatch for $Name"
        }
        $ActualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($ActualHash -ne ([string]$Entry.sha256).ToLowerInvariant()) {
            throw "Package hash mismatch for $Name"
        }
    }
    return $Manifest
}
