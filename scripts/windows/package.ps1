[CmdletBinding()]
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ArtifactParent = Join-Path $RepoRoot "artifacts"
$ArtifactRoot = Join-Path $ArtifactParent "windows"
$StageRoot = Join-Path $ArtifactParent ("windows-stage-" + [Guid]::NewGuid().ToString("N"))
$BackupRoot = Join-Path $ArtifactParent ("windows-backup-" + [Guid]::NewGuid().ToString("N"))

if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot "build.ps1")
    if ($LASTEXITCODE -ne 0) { throw "build.ps1 failed" }
}

$WorkspaceManifest = Get-Content -LiteralPath (Join-Path $RepoRoot "Cargo.toml") -Raw
$VersionMatch = [regex]::Match(
    $WorkspaceManifest,
    '(?ms)^\[workspace\.package\].*?^version\s*=\s*"([^"]+)"'
)
if (-not $VersionMatch.Success) {
    throw "Could not determine the workspace version from Cargo.toml"
}
$Version = $VersionMatch.Groups[1].Value

$Files = [ordered]@{
    "stein-core.exe" = Join-Path $RepoRoot "target\release\stein-core.exe"
    "stein-cli.exe" = Join-Path $RepoRoot "target\release\stein-cli.exe"
    "stein-desktop.exe" = Join-Path $RepoRoot "target\release\stein-desktop.exe"
    "start-core.cmd" = Join-Path $PSScriptRoot "start-core.cmd"
    "common.ps1" = Join-Path $PSScriptRoot "common.ps1"
    "install.ps1" = Join-Path $PSScriptRoot "install.ps1"
    "uninstall.ps1" = Join-Path $PSScriptRoot "uninstall.ps1"
    "status.ps1" = Join-Path $PSScriptRoot "status.ps1"
    "smoke-test.ps1" = Join-Path $PSScriptRoot "smoke-test.ps1"
    "install.cmd" = Join-Path $PSScriptRoot "install.cmd"
    "uninstall.cmd" = Join-Path $PSScriptRoot "uninstall.cmd"
    "status.cmd" = Join-Path $PSScriptRoot "status.cmd"
    "smoke-test.cmd" = Join-Path $PSScriptRoot "smoke-test.cmd"
    "README.md" = Join-Path $PSScriptRoot "README.md"
}

New-Item -ItemType Directory -Path $ArtifactParent, $StageRoot -Force | Out-Null
try {
    foreach ($Name in $Files.Keys) {
        $Source = $Files[$Name]
        if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
            throw "Missing package input: $Source"
        }
        Copy-Item -LiteralPath $Source -Destination (Join-Path $StageRoot $Name)
    }

    $ManifestEntries = @(
        Get-ChildItem -LiteralPath $StageRoot -File |
            Sort-Object Name |
            ForEach-Object {
                [ordered]@{
                    name = $_.Name
                    size = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
    )
    $Manifest = [ordered]@{
        schemaVersion = 1
        version = $Version
        builtAtUtc = [DateTime]::UtcNow.ToString("o")
        platform = "windows-x86_64"
        files = $ManifestEntries
    }
    $Manifest | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $StageRoot "manifest.json") -Encoding UTF8

    if (Test-Path -LiteralPath $ArtifactRoot) {
        $CanonicalArtifact = [IO.Path]::GetFullPath($ArtifactRoot).TrimEnd('\')
        $CanonicalParent = [IO.Path]::GetFullPath($ArtifactParent).TrimEnd('\')
        if (
            [IO.Path]::GetFileName($CanonicalArtifact) -ne "windows" -or
            -not [string]::Equals(
                [IO.Path]::GetDirectoryName($CanonicalArtifact),
                $CanonicalParent,
                [StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw "Refusing to replace an unexpected artifact path"
        }
        Move-Item -LiteralPath $ArtifactRoot -Destination $BackupRoot
    }
    try {
        Move-Item -LiteralPath $StageRoot -Destination $ArtifactRoot
    } catch {
        if (
            (Test-Path -LiteralPath $BackupRoot) -and
            -not (Test-Path -LiteralPath $ArtifactRoot)
        ) {
            Move-Item -LiteralPath $BackupRoot -Destination $ArtifactRoot
        }
        throw
    }
    if (Test-Path -LiteralPath $BackupRoot) {
        Remove-Item -LiteralPath $BackupRoot -Recurse -Force
    }
} finally {
    if (Test-Path -LiteralPath $StageRoot) {
        Remove-Item -LiteralPath $StageRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $BackupRoot) {
        if (Test-Path -LiteralPath $ArtifactRoot) {
            Remove-Item -LiteralPath $BackupRoot -Recurse -Force
        } else {
            Write-Warning "Previous package retained at $BackupRoot after replacement failure"
        }
    }
}

Write-Host "[STEIN] Packaged version $Version at $ArtifactRoot"
