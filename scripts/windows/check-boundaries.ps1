[CmdletBinding()]
param(
    [switch]$Json,
    [string]$CargoExecutable,
    [string]$CargoExecutableSha256
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$CargoLock = $null
if ([string]::IsNullOrWhiteSpace($CargoExecutable) -xor
    [string]::IsNullOrWhiteSpace($CargoExecutableSha256)) {
    throw "Cargo executable identity must be supplied as an exact pair."
}
if ([string]::IsNullOrWhiteSpace($CargoExecutable)) {
    $CargoPath = [string]@(Get-Command "cargo.exe" -CommandType Application `
            -ErrorAction Stop)[0].Source
}
else {
    if ($CargoExecutableSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "Cargo executable SHA-256 is invalid."
    }
    $CargoPath = [IO.Path]::GetFullPath($CargoExecutable)
    $CargoItem = Get-Item -LiteralPath $CargoPath -Force -ErrorAction Stop
    if ($CargoItem.PSIsContainer -or
        (($CargoItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Cargo executable is not a regular file."
    }
    $cursor = $CargoItem.Directory
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Cargo executable has a reparse-point ancestor."
        }
        $cursor = $cursor.Parent
    }
    $CargoLock = [IO.FileStream]::new(
        $CargoPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $actualCargoSha256 = [BitConverter]::ToString(
            $sha256.ComputeHash($CargoLock)).Replace("-", "").ToLowerInvariant()
        $CargoLock.Position = 0
    }
    finally {
        $sha256.Dispose()
    }
    if ($actualCargoSha256 -cne $CargoExecutableSha256) {
        $CargoLock.Dispose()
        $CargoLock = $null
        throw "Cargo executable differs from its expected SHA-256."
    }
}

$Checks = New-Object Collections.Generic.List[object]

function Add-BoundaryCheck(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][bool]$Passed,
    [Parameter(Mandatory = $true)][string]$Summary
) {
    $Checks.Add([pscustomobject]@{
        name = $Name
        passed = $Passed
        summary = $Summary
    })
}

function Get-CargoPackage(
    [Parameter(Mandatory = $true)][object]$Metadata,
    [Parameter(Mandatory = $true)][string]$Name
) {
    $Matches = @($Metadata.packages | Where-Object { $_.name -eq $Name })
    if ($Matches.Count -ne 1) {
        throw "Expected exactly one Cargo package named $Name; found $($Matches.Count)"
    }
    return $Matches[0]
}

function Test-ForbiddenDependencies(
    [Parameter(Mandatory = $true)][object]$Package,
    [Parameter(Mandatory = $true)][string[]]$Forbidden
) {
    $Names = @($Package.dependencies | ForEach-Object { $_.name })
    return @($Forbidden | Where-Object { $Names -contains $_ })
}

function Find-ForbiddenSourceReferences(
    [Parameter(Mandatory = $true)][string]$Directory,
    [Parameter(Mandatory = $true)][string[]]$Patterns
) {
    $Files = @(Get-ChildItem -LiteralPath $Directory -Recurse -File -Filter "*.rs")
    if ($Files.Count -eq 0) {
        throw "No Rust sources found for boundary check: $Directory"
    }
    return @(
        $Files |
            Select-String -Pattern $Patterns -CaseSensitive |
            ForEach-Object {
                [pscustomobject]@{
                    file = $_.Path.Substring($RepoRoot.Length + 1)
                    line = $_.LineNumber
                    pattern = $_.Pattern
                }
            }
    )
}

try {
    $MetadataText = (& $CargoPath metadata --locked --no-deps --format-version 1 `
            --manifest-path (Join-Path $RepoRoot "Cargo.toml")) -join `
        [Environment]::NewLine
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed"
    }
    $Metadata = $MetadataText | ConvertFrom-Json

    Push-Location $RepoRoot
    try {

    $Core = Get-CargoPackage -Metadata $Metadata -Name "stein-core"
    $Protocol = Get-CargoPackage -Metadata $Metadata -Name "stein-protocol"

    $AdapterDependencies = @(
        "reqwest",
        "rusqlite",
        "tauri",
        "windows",
        "windows-sys",
        "stein-broker-windows",
        "stein-model-openai",
        "stein-platform-windows",
        "stein-store-sqlite"
    )
    $CoreViolations = @(Test-ForbiddenDependencies -Package $Core -Forbidden $AdapterDependencies)
    $CoreSummary = if ($CoreViolations.Count -eq 0) {
            "CORE has no direct platform/provider/persistence/presentation adapter dependency."
        } else {
            "Forbidden CORE dependencies: $($CoreViolations -join ', ')"
        }
    Add-BoundaryCheck -Name "core_direct_dependencies" -Passed ($CoreViolations.Count -eq 0) -Summary $CoreSummary

    $ProtocolForbidden = @(
        "reqwest",
        "rusqlite",
        "tauri",
        "windows",
        "windows-sys",
        "stein-core",
        "stein-ipc",
        "stein-broker-windows",
        "stein-model-openai",
        "stein-platform-windows",
        "stein-store-sqlite"
    )
    $ProtocolViolations = @(Test-ForbiddenDependencies -Package $Protocol -Forbidden $ProtocolForbidden)
    $ProtocolSummary = if ($ProtocolViolations.Count -eq 0) {
            "The wire contract has no domain/platform/provider/persistence/presentation dependency."
        } else {
            "Forbidden protocol dependencies: $($ProtocolViolations -join ', ')"
        }
    Add-BoundaryCheck -Name "protocol_direct_dependencies" -Passed ($ProtocolViolations.Count -eq 0) -Summary $ProtocolSummary

    $ForbiddenReferences = @(
        "reqwest::",
        "rusqlite::",
        "tauri::",
        "windows::",
        "windows_sys::",
        "stein_broker_windows",
        "stein_model_openai",
        "stein_platform_windows",
        "stein_store_sqlite"
    )
    $CoreSourceViolations = @(Find-ForbiddenSourceReferences -Directory (Join-Path $RepoRoot "crates\stein-core\src") -Patterns $ForbiddenReferences)
    $CoreSourceSummary = if ($CoreSourceViolations.Count -eq 0) {
            "CORE source imports only platform-neutral contracts."
        } else {
            "CORE source contains $($CoreSourceViolations.Count) forbidden adapter reference(s)."
        }
    Add-BoundaryCheck -Name "core_source_imports" -Passed ($CoreSourceViolations.Count -eq 0) -Summary $CoreSourceSummary

    $ProtocolSourceViolations = @(Find-ForbiddenSourceReferences -Directory (Join-Path $RepoRoot "crates\stein-protocol\src") -Patterns ($ForbiddenReferences + @("stein_core", "stein_ipc")))
    $ProtocolSourceSummary = if ($ProtocolSourceViolations.Count -eq 0) {
            "Protocol source remains a standalone privacy-filtered wire contract."
        } else {
            "Protocol source contains $($ProtocolSourceViolations.Count) forbidden reference(s)."
        }
    Add-BoundaryCheck -Name "protocol_source_imports" -Passed ($ProtocolSourceViolations.Count -eq 0) -Summary $ProtocolSourceSummary

    $Passed = @($Checks | Where-Object { -not $_.passed }).Count -eq 0
    $CheckArray = @($Checks | ForEach-Object { $_ })
    $Report = [pscustomobject]@{
        schemaVersion = 1
        passed = $Passed
        checks = $CheckArray
        violations = [pscustomobject]@{
            coreSource = $CoreSourceViolations
            protocolSource = $ProtocolSourceViolations
        }
    }
    if ($Json) {
        $Report | ConvertTo-Json -Depth 8
    } else {
        foreach ($Check in $Checks) {
            $Marker = if ($Check.passed) { "PASS" } else { "FAIL" }
            Write-Host "[$Marker] $($Check.name): $($Check.summary)"
        }
    }
        if (-not $Passed) {
            exit 1
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    if ($null -ne $CargoLock) {
        $CargoLock.Dispose()
    }
}
