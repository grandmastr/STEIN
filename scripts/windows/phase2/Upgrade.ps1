[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PackagePath,

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
        [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) "STEIN")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
. (Join-Path $PSScriptRoot "Lifecycle.ps1")

$result = Upgrade-SteinPhase2 `
    -PackagePath $PackagePath `
    -Publisher $Publisher `
    -CertificateThumbprint $CertificateThumbprint `
    -Version $Version `
    -InstallRoot $InstallRoot
$result | ConvertTo-Json -Depth 10
