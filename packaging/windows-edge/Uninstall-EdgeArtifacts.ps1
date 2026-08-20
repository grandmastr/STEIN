[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$HostName = 'com.stein.personal_intelligence.browser'
$RegistryPath = "HKCU:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\$HostName"
$LocalRoot = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\')
$OwnedRoot = [IO.Path]::GetFullPath((Join-Path $LocalRoot 'STEIN\browser-host'))
$ExpectedPrefix = [IO.Path]::GetFullPath((Join-Path $LocalRoot 'STEIN')).TrimEnd('\') + '\'
if (-not $OwnedRoot.StartsWith($ExpectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    (Split-Path -Leaf $OwnedRoot) -cne 'browser-host') {
    throw 'The browser-host cleanup target is outside the exact STEIN LocalAppData boundary.'
}

if (Test-Path -LiteralPath $RegistryPath) {
    $RegistryKey = Get-Item -LiteralPath $RegistryPath
    $Registration = [string]$RegistryKey.GetValue('')
    $ExpectedManifest = [IO.Path]::GetFullPath((Join-Path $OwnedRoot "current\$HostName.json"))
    if (-not [string]::IsNullOrWhiteSpace($Registration) -and
        [IO.Path]::GetFullPath($Registration) -ine $ExpectedManifest) {
        throw 'The Edge native-messaging registration is not owned by this STEIN installation.'
    }
    if (-not [string]::IsNullOrWhiteSpace($Registration)) {
        $RegistryKey.DeleteValue('', $false)
    }
    $RegistryKey.Close()
}

if (Test-Path -LiteralPath $OwnedRoot) {
    $ResolvedOwnedRoot = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $OwnedRoot).Path)
    if ($ResolvedOwnedRoot -ine $OwnedRoot) {
        throw 'The browser-host cleanup target resolved outside the exact owned path.'
    }
    $ReparsePoints = @(
        Get-Item -LiteralPath $OwnedRoot -Force
        Get-ChildItem -LiteralPath $OwnedRoot -Recurse -Force
    ) | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }
    if (@($ReparsePoints).Count -ne 0) {
        throw 'The browser-host cleanup target contains a reparse point.'
    }
    Remove-Item -LiteralPath $OwnedRoot -Recurse -Force
}

Write-Output 'Removed only the owned Edge native-messaging registration and browser-host metadata.'
