Set-StrictMode -Version Latest

$script:SteinPackageEvidenceContractPath = [IO.Path]::GetFullPath((Join-Path `
    $PSScriptRoot "..\..\scripts\windows\phase2\Evidence-Contract.ps1"))
if (-not (Test-Path -LiteralPath $script:SteinPackageEvidenceContractPath `
        -PathType Leaf)) {
    throw "The Phase 2 evidence contract is unavailable to the package signer."
}
$evidenceContractItem = Get-Item `
    -LiteralPath $script:SteinPackageEvidenceContractPath `
    -Force `
    -ErrorAction Stop
if ($evidenceContractItem.PSIsContainer -or
    (($evidenceContractItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) -or
    $evidenceContractItem.Length -lt 1 -or
    $evidenceContractItem.Length -gt 2097152) {
    throw "The Phase 2 evidence contract is not a regular bounded signer input."
}
$evidenceContractProbe = Split-Path -Parent $evidenceContractItem.FullName
$evidenceContractVolume = [IO.Path]::GetPathRoot($evidenceContractProbe)
while ($evidenceContractProbe.Length -ge $evidenceContractVolume.Length) {
    $probeItem = Get-Item `
        -LiteralPath $evidenceContractProbe `
        -Force `
        -ErrorAction Stop
    if (-not $probeItem.PSIsContainer -or
        (($probeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "The Phase 2 evidence contract has an unsafe ancestor."
    }
    if ([string]::Equals(
            $evidenceContractProbe,
            $evidenceContractVolume,
            [StringComparison]::OrdinalIgnoreCase)) {
        break
    }
    $evidenceContractProbe = Split-Path -Parent $evidenceContractProbe
}
$script:SteinPackageEvidenceContractLock = [IO.FileStream]::new(
    $evidenceContractItem.FullName,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read)
$evidenceContractSha256 = [Security.Cryptography.SHA256]::Create()
try {
    $script:SteinPackageEvidenceContractSha256 = [BitConverter]::ToString(
        $evidenceContractSha256.ComputeHash(
            $script:SteinPackageEvidenceContractLock)).Replace(
            '-',
            '').ToLowerInvariant()
    $script:SteinPackageEvidenceContractLock.Position = 0
}
finally {
    $evidenceContractSha256.Dispose()
}
. $script:SteinPackageEvidenceContractPath
$evidenceContractSha256 = [Security.Cryptography.SHA256]::Create()
try {
    if ([BitConverter]::ToString($evidenceContractSha256.ComputeHash(
                $script:SteinPackageEvidenceContractLock)).Replace(
                '-',
                '').ToLowerInvariant() -cne
            $script:SteinPackageEvidenceContractSha256) {
        throw "The Phase 2 evidence contract changed while the signer loaded it."
    }
    $script:SteinPackageEvidenceContractLock.Position = 0
}
finally {
    $evidenceContractSha256.Dispose()
}

$script:FoundationNamespace = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
$script:UapNamespace = "http://schemas.microsoft.com/appx/manifest/uap/windows10"
$script:Uap10Namespace = "http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
$script:ComNamespace = "http://schemas.microsoft.com/appx/manifest/com/windows10"
$script:DesktopNamespace = "http://schemas.microsoft.com/appx/manifest/desktop/windows10"
$script:RestrictedCapabilityNamespace = "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
$script:ProductionPackageName = "STEIN.PersonalIntelligence"
$script:DesktopApplicationId = "Desktop"
$script:BrokerApplicationId = "PrivateBroker"
$script:BrowserProducerApplicationId = "BrowserObservationProducer"
$script:ToastActivatorClsid = "3DB3B5B0-1BA5-49D1-A8F0-CF2B3EA6D781"

function ConvertTo-SteinCertificateThumbprint {
    param([Parameter(Mandatory = $true)][string] $Thumbprint)

    $normalized = $Thumbprint.Replace(" ", "").ToUpperInvariant()
    if ($normalized -notmatch "^[0-9A-F]{40}$") {
        throw "Certificate thumbprint must be exactly 40 hexadecimal characters."
    }
    return $normalized
}

function Resolve-WindowsSdkTool {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("makeappx.exe", "signtool.exe")]
        [string] $Name
    )

    $installedRoots = Get-ItemProperty `
        -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots" `
        -ErrorAction Stop
    $kitsRootValue = [string]$installedRoots.KitsRoot10
    if ([string]::IsNullOrWhiteSpace($kitsRootValue)) {
        throw "Windows SDK tool directory is unavailable."
    }
    $kitsRoot = [IO.Path]::GetFullPath($kitsRootValue).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $binRoot = [IO.Path]::GetFullPath((Join-Path $kitsRoot "bin")).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $kitsPrefix = "$kitsRoot$([IO.Path]::DirectorySeparatorChar)"
    if (-not $binRoot.StartsWith($kitsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Windows SDK tool directory is unavailable."
    }

    $volumeRoot = [IO.Path]::GetPathRoot($kitsRoot)
    $probe = $binRoot
    while ($probe.Length -ge $volumeRoot.Length) {
        $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Windows SDK tool directory is unavailable."
        }
        if ([string]::Equals($probe, $volumeRoot, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            throw "Windows SDK tool directory is unavailable."
        }
        $probe = $parent
    }

    $candidates = New-Object Collections.Generic.List[object]
    foreach ($versionDirectory in @(
            Get-ChildItem -LiteralPath $binRoot -Directory -Force -ErrorAction Stop)) {
        $sdkVersion = $null
        if ($versionDirectory.Name -notmatch "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" -or
            -not [version]::TryParse($versionDirectory.Name, [ref]$sdkVersion)) {
            continue
        }
        if (($versionDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Windows SDK tool directory is unavailable."
        }
        $architectureRoot = [IO.Path]::GetFullPath(
            (Join-Path $versionDirectory.FullName "x64"))
        $architectureItem = Get-Item `
            -LiteralPath $architectureRoot `
            -Force `
            -ErrorAction SilentlyContinue
        if ($null -eq $architectureItem) {
            continue
        }
        if (-not $architectureItem.PSIsContainer -or
            (($architectureItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Windows SDK tool directory is unavailable."
        }
        $candidatePath = [IO.Path]::GetFullPath((Join-Path $architectureRoot $Name))
        $binPrefix = "$binRoot$([IO.Path]::DirectorySeparatorChar)"
        if (-not $candidatePath.StartsWith($binPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows SDK tool directory is unavailable."
        }
        $candidateItem = Get-Item `
            -LiteralPath $candidatePath `
            -Force `
            -ErrorAction SilentlyContinue
        if ($null -eq $candidateItem) {
            continue
        }
        if ($candidateItem.PSIsContainer -or
            (($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $candidateItem.Length -le 0) {
            throw "Required Windows SDK tool is unavailable."
        }
        $candidates.Add([pscustomobject]@{
            version = $sdkVersion
            path = $candidateItem.FullName
        })
    }
    $candidate = @($candidates | Sort-Object version -Descending | Select-Object -First 1)
    if ($candidate.Count -ne 1) {
        throw "Required Windows SDK tool is unavailable."
    }
    return [string]$candidate[0].path
}

function Get-ExactSigningCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Thumbprint,
        [Parameter(Mandatory = $true)]
        [string] $Publisher
    )

    $normalized = ConvertTo-SteinCertificateThumbprint -Thumbprint $Thumbprint
    if ([string]::IsNullOrWhiteSpace($Publisher) -or $Publisher.Contains("{{")) {
        throw "An exact production Publisher distinguished name is required."
    }

    $certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$normalized" -ErrorAction Stop
    if ($certificate.Thumbprint.ToUpperInvariant() -cne $normalized) {
        throw "The selected certificate thumbprint did not match exactly."
    }
    if ($certificate.Subject -cne $Publisher) {
        throw "The selected certificate subject does not exactly match Publisher."
    }
    if (-not $certificate.HasPrivateKey) {
        throw "The selected signing certificate has no accessible private key."
    }
    $now = [DateTime]::UtcNow
    if ($certificate.NotBefore.ToUniversalTime() -gt $now -or $certificate.NotAfter.ToUniversalTime() -le $now) {
        throw "The selected signing certificate is not currently valid."
    }
    $codeSigningOid = "1.3.6.1.5.5.7.3.3"
    $ekuValues = @($certificate.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value })
    if ($ekuValues -notcontains $codeSigningOid) {
        throw "The selected certificate is not valid for code signing."
    }
    return $certificate
}

function Assert-SteinExactAuthenticodeSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [Parameter(Mandatory = $true)]
        [string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)]
        [string] $Publisher
    )

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Authenticode verification requires a regular file."
    }
    if ([string]::IsNullOrWhiteSpace($Publisher) -or $Publisher.Contains("{{")) {
        throw "An exact production Publisher distinguished name is required."
    }

    $normalized = ConvertTo-SteinCertificateThumbprint -Thumbprint $CertificateThumbprint
    $signTool = Resolve-WindowsSdkTool -Name "signtool.exe"
    & $signTool verify /pa /all /v $resolved *> $null
    Assert-NativeCommandSucceeded -Operation "Authenticode trust verification"

    $signature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $normalized -or
        $signature.SignerCertificate.Subject -cne $Publisher) {
        throw "The file does not carry the exact operator-pinned valid signature."
    }

    $codeSigningOid = "1.3.6.1.5.5.7.3.3"
    $ekuValues = @(
        $signature.SignerCertificate.EnhancedKeyUsageList |
            ForEach-Object { $_.ObjectId.Value }
    )
    if ($ekuValues -notcontains $codeSigningOid) {
        throw "The file signer is not valid for code signing."
    }

    return $signature
}

function Assert-NativeCommandSucceeded {
    param([Parameter(Mandatory = $true)][string] $Operation)
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE."
    }
}

function Assert-SteinPackageJsonShape {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string[]] $ExpectedProperties,
        [Parameter(Mandatory = $true)][string] $Description
    )

    if ($null -eq $Value) {
        throw "$Description is empty."
    }
    $actual = @($Value.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    $expected = @($ExpectedProperties | Sort-Object)
    if ($actual.Count -ne $expected.Count -or
        @(Compare-Object `
            -ReferenceObject $expected `
            -DifferenceObject $actual `
            -CaseSensitive).Count -ne 0) {
        throw "$Description does not use the closed expected schema."
    }
}

function Test-SteinPackageSha256Value {
    param([Parameter(Mandatory = $true)][string] $Value)

    return $Value -cmatch "^[0-9a-f]{64}$" -and $Value -cne ("0" * 64)
}

function Test-SteinPackageGitObjectId {
    param([Parameter(Mandatory = $true)][string] $Value)

    return $Value -cmatch "^(?:[0-9a-f]{40}|[0-9a-f]{64})$" -and
        $Value -cne ("0" * $Value.Length)
}

function Test-SteinPackageSafeWindowsRelativePath {
    param([Parameter(Mandatory = $true)][string] $Value)

    if ($Value.Length -le 0 -or $Value.Length -gt 4096 -or
        $Value.Contains("\") -or [IO.Path]::IsPathRooted($Value) -or
        $Value.IndexOfAny([char[]]@('<', '>', ':', '"', '|', '?', '*')) -ge 0 -or
        $Value -match '[\x00-\x1f]') {
        return $false
    }
    $parts = @([Text.RegularExpressions.Regex]::Split(
            $Value,
            '/',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant))
    if ($parts.Count -le 0) {
        return $false
    }
    foreach ($part in $parts) {
        if ($part.Length -le 0 -or $part.Length -gt 255 -or
            $part -ceq "." -or $part -ceq ".." -or $part -ieq ".git" -or
            $part.EndsWith(" ", [StringComparison]::Ordinal) -or
            $part.EndsWith(".", [StringComparison]::Ordinal)) {
            return $false
        }
        $baseName = @($part -split '\.', 2)[0]
        if ($baseName -imatch '^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            return $false
        }
    }
    return $true
}

function Get-SteinPackageFileSha256 {
    param([Parameter(Mandatory = $true)][string] $Path)

    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            return [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace(
                "-",
                "").ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-SteinPackageTextSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace(
            "-",
            "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Resolve-SteinPackageRegularFileWithAncestors {
    param([Parameter(Mandatory = $true)][string] $Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0) {
        throw "A required build input is not a regular non-reparse file."
    }

    $volumeRoot = [IO.Path]::GetPathRoot($resolved).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $probe = Split-Path -Parent $resolved
    while (-not [string]::IsNullOrWhiteSpace($probe)) {
        $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "A required build input has an invalid ancestor."
        }
        if ([string]::Equals(
                $probe.TrimEnd(
                    [IO.Path]::DirectorySeparatorChar,
                    [IO.Path]::AltDirectorySeparatorChar),
                $volumeRoot,
                [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            throw "A required build input has no exact filesystem root."
        }
        $probe = $parent
    }
    return $item.FullName
}

function Resolve-SteinPackageRegularDirectoryWithAncestors {
    param([Parameter(Mandatory = $true)][string] $Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $volumeRoot = [IO.Path]::GetPathRoot($resolved).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $probe = $resolved
    while (-not [string]::IsNullOrWhiteSpace($probe)) {
        $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "A required build directory has an invalid ancestor."
        }
        if ([string]::Equals(
                $probe.TrimEnd(
                    [IO.Path]::DirectorySeparatorChar,
                    [IO.Path]::AltDirectorySeparatorChar),
                $volumeRoot,
                [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            throw "A required build directory has no exact filesystem root."
        }
        $probe = $parent
    }
    return $resolved
}

function Resolve-SteinPackageRegularFileUnderRoot {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $Path,
        [switch] $AllowEmpty
    )

    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $rootItem = Get-Item -LiteralPath $rootPath -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "The build evidence root is not a regular directory."
    }
    $candidate = [IO.Path]::GetFullPath($Path)
    $prefix = "$rootPath$([IO.Path]::DirectorySeparatorChar)"
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "A build evidence file escaped its exact root."
    }

    $probe = Split-Path -Parent $candidate
    while ($probe.Length -ge $rootPath.Length) {
        $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "A build evidence file has an invalid ancestor."
        }
        if ([string]::Equals($probe, $rootPath, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            throw "A build evidence file escaped its exact root."
        }
        $probe = $parent
    }

    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        (-not $AllowEmpty -and $item.Length -le 0)) {
        throw "A build evidence input is not a regular non-empty file."
    }
    return $item.FullName
}

function Get-SteinPackagePrivateTemporaryRoot {
    return Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path ([IO.Path]::GetTempPath())
}

function Get-SteinPackageFileSystemSecurity {
    param([Parameter(Mandatory = $true)][IO.FileSystemInfo] $Item)

    $sections = [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    $aclExtensions = "System.IO.FileSystemAclExtensions" -as [type]
    if ($null -ne $aclExtensions) {
        if ($Item.PSIsContainer) {
            return [IO.FileSystemAclExtensions]::GetAccessControl(
                [IO.DirectoryInfo]$Item,
                $sections)
        }
        return [IO.FileSystemAclExtensions]::GetAccessControl(
            [IO.FileInfo]$Item,
            $sections)
    }
    if ($Item.PSIsContainer) {
        return [IO.Directory]::GetAccessControl($Item.FullName, $sections)
    }
    return [IO.File]::GetAccessControl($Item.FullName, $sections)
}

function Set-SteinPackageFileSystemSecurity {
    param(
        [Parameter(Mandatory = $true)][IO.FileSystemInfo] $Item,
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemSecurity] $Security
    )

    $aclExtensions = "System.IO.FileSystemAclExtensions" -as [type]
    if ($null -ne $aclExtensions) {
        if ($Item.PSIsContainer) {
            [IO.FileSystemAclExtensions]::SetAccessControl(
                [IO.DirectoryInfo]$Item,
                [Security.AccessControl.DirectorySecurity]$Security)
            return
        }
        [IO.FileSystemAclExtensions]::SetAccessControl(
            [IO.FileInfo]$Item,
            [Security.AccessControl.FileSecurity]$Security)
        return
    }
    if ($Item.PSIsContainer) {
        [IO.Directory]::SetAccessControl(
            $Item.FullName,
            [Security.AccessControl.DirectorySecurity]$Security)
        return
    }
    [IO.File]::SetAccessControl(
        $Item.FullName,
        [Security.AccessControl.FileSecurity]$Security)
}

function Assert-SteinPackageOwnerOnlyDirectory {
    param([Parameter(Mandatory = $true)][string] $Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "A private packaging directory is not a regular directory."
    }
    $expectedSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $security = Get-SteinPackageFileSystemSecurity -Item $item
    $ownerSid = $security.GetOwner(
        [Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -cne $expectedSid -or -not $security.AreAccessRulesProtected) {
        throw "A private packaging directory is not owner-only."
    }
    $rules = @($security.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]))
    $hasFullControl = $false
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -cne $expectedSid -or
            $rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow) {
            throw "A private packaging directory grants another identity access."
        }
        if (($rule.FileSystemRights -band
                [Security.AccessControl.FileSystemRights]::FullControl) -eq
            [Security.AccessControl.FileSystemRights]::FullControl) {
            $hasFullControl = $true
        }
    }
    if (-not $hasFullControl) {
        throw "The private packaging directory owner lacks full control."
    }
    return $item.FullName
}

function Protect-SteinPackageOwnerOnlyDirectory {
    param([Parameter(Mandatory = $true)][string] $Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "A private packaging directory is not a regular directory."
    }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $security = Get-SteinPackageFileSystemSecurity -Item $item
    $security.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($security.GetAccessRules(
                $true,
                $false,
                [Security.Principal.SecurityIdentifier]))) {
        $security.RemoveAccessRuleSpecific($existingRule)
    }
    if ($security.GetOwner(
            [Security.Principal.SecurityIdentifier]).Value -cne $sid.Value) {
        $security.SetOwner($sid)
    }
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
    $security.AddAccessRule($rule)
    Set-SteinPackageFileSystemSecurity -Item $item -Security $security
    return Assert-SteinPackageOwnerOnlyDirectory -Path $item.FullName
}

function Assert-SteinPackagePrivateTemporaryDirectory {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet("build", "verify")]
        [string] $Purpose
    )

    $temporaryRoot = Get-SteinPackagePrivateTemporaryRoot
    $candidate = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $prefix = "$temporaryRoot$([IO.Path]::DirectorySeparatorChar)"
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals(
            (Split-Path -Parent $candidate),
            $temporaryRoot,
            [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $candidate) -cnotmatch
            "^stein-msix-$Purpose-[0-9a-f]{32}$") {
        throw "The private packaging temporary directory has an invalid identity."
    }
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "The private packaging temporary directory is unsafe."
    }
    $null = Assert-SteinPackageOwnerOnlyDirectory -Path $candidate
    return $candidate
}

function New-SteinPackagePrivateTemporaryDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("build", "verify")]
        [string] $Purpose
    )

    $temporaryRoot = Get-SteinPackagePrivateTemporaryRoot
    $leaf = "stein-msix-$Purpose-$([Guid]::NewGuid().ToString('N'))"
    $path = [IO.Path]::GetFullPath((Join-Path $temporaryRoot $leaf))
    if (-not [string]::Equals(
            (Split-Path -Parent $path),
            $temporaryRoot,
            [StringComparison]::OrdinalIgnoreCase) -or
        (Test-Path -LiteralPath $path)) {
        throw "A private packaging temporary directory could not be selected."
    }
    $null = New-Item -ItemType Directory -Path $path -ErrorAction Stop
    $null = Protect-SteinPackageOwnerOnlyDirectory -Path $path
    return Assert-SteinPackagePrivateTemporaryDirectory `
        -Path $path `
        -Purpose $Purpose
}

function Get-SteinPackageStreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream] $Stream)

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw "A packaging byte stream cannot be verified exactly."
    }
    $Stream.Position = 0
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha256.ComputeHash($Stream)).Replace(
            "-",
            "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
        $Stream.Position = 0
    }
}

function Open-SteinPackageVerifiedFileLock {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $ExpectedSha256
    )

    if (-not (Test-SteinPackageSha256Value -Value $ExpectedSha256)) {
        throw "A locked packaging tool digest is invalid."
    }
    $resolved = Resolve-SteinPackageRegularFileWithAncestors -Path $Path
    $stream = [IO.FileStream]::new(
        $resolved,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ((Get-SteinPackageStreamSha256 -Stream $stream) -cne $ExpectedSha256) {
            throw "A locked packaging tool differs from source provenance."
        }
        return [pscustomobject]@{
            Path = $resolved
            Stream = $stream
            Size = [long]$stream.Length
            Sha256 = $ExpectedSha256
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Get-SteinPackageGitBlobObjectId {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet("sha1", "sha256")]
        [string] $ObjectFormat
    )

    $resolved = Resolve-SteinPackageRegularFileWithAncestors -Path $Path
    $stream = [IO.FileStream]::new(
        $resolved,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $algorithm = if ($ObjectFormat -ceq "sha1") {
            [Security.Cryptography.SHA1]::Create()
        }
        else {
            [Security.Cryptography.SHA256]::Create()
        }
        try {
            $header = [Text.Encoding]::ASCII.GetBytes("blob $($stream.Length)`0")
            $null = $algorithm.TransformBlock($header, 0, $header.Length, $header, 0)
            $buffer = New-Object byte[] 65536
            try {
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $null = $algorithm.TransformBlock($buffer, 0, $read, $buffer, 0)
                }
                $null = $algorithm.TransformFinalBlock($buffer, 0, 0)
                return [BitConverter]::ToString($algorithm.Hash).Replace(
                    "-",
                    "").ToLowerInvariant()
            }
            finally {
                [Array]::Clear($buffer, 0, $buffer.Length)
                [Array]::Clear($header, 0, $header.Length)
            }
        }
        finally {
            $algorithm.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function New-SteinExactGitCandidateSnapshot {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $GitExecutable,
        [Parameter(Mandatory = $true)][string] $ExpectedGitExecutableSha256,
        [Parameter(Mandatory = $true)][string] $ExpectedCommit,
        [Parameter(Mandatory = $true)][string] $ExpectedTree,
        [Parameter(Mandatory = $true)][string] $BuildRoot
    )

    if (-not (Test-SteinPackageGitObjectId -Value $ExpectedCommit) -or
        -not (Test-SteinPackageGitObjectId -Value $ExpectedTree) -or
        $ExpectedCommit.Length -ne $ExpectedTree.Length) {
        throw "The exact Git candidate snapshot identity is invalid."
    }
    $repositoryPath = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path $RepositoryRoot
    $root = Assert-SteinPackagePrivateTemporaryDirectory `
        -Path $BuildRoot `
        -Purpose "build"
    $gitPath = Resolve-SteinPackageRegularFileWithAncestors -Path $GitExecutable
    if ((Get-SteinPackageFileSha256 -Path $gitPath) -cne
        $ExpectedGitExecutableSha256) {
        throw "Git differs from the source-provenance tool."
    }

    $invokeGitText = {
        param([string[]] $Arguments, [long] $MaximumCharacters)
        $output = @(& $gitPath `
                -c core.fsmonitor=false `
                -c core.untrackedCache=false `
                -C $repositoryPath `
                @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
        $text = ($output | ForEach-Object { [string]$_ }) -join "`n"
        if ($exitCode -ne 0 -or $text.Length -gt $MaximumCharacters) {
            throw "Git could not resolve the exact candidate object."
        }
        return $text.Trim()
    }
    $commit = & $invokeGitText @("rev-parse", "--verify", "$ExpectedCommit^{commit}") 256
    $tree = & $invokeGitText @("rev-parse", "--verify", "$ExpectedCommit^{tree}") 256
    $objectFormat = & $invokeGitText @("rev-parse", "--show-object-format") 32
    if ($commit -cne $ExpectedCommit -or $tree -cne $ExpectedTree -or
        $objectFormat -cnotin @("sha1", "sha256") -or
        $commit.Length -ne $(if ($objectFormat -ceq "sha1") { 40 } else { 64 })) {
        throw "Git resolved a different candidate commit or tree."
    }

    $treeListPath = Join-Path $root "candidate-tree.list"
    $treeErrorPath = Join-Path $root "candidate-tree.stderr"
    $process = Start-Process `
        -FilePath $gitPath `
        -ArgumentList @(
            "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            "ls-tree", "-r", "-z", "--full-tree", $ExpectedCommit) `
        -WorkingDirectory $repositoryPath `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput $treeListPath `
        -RedirectStandardError $treeErrorPath
    try {
        $null = $process.Handle
        $process.WaitForExit()
        $treeExitCode = $process.ExitCode
    }
    finally {
        $process.Dispose()
    }
    $treeError = [IO.File]::ReadAllText(
        $treeErrorPath,
        [Text.UTF8Encoding]::new($false, $true))
    $treeListItem = Get-Item -LiteralPath $treeListPath -Force -ErrorAction Stop
    if ($treeExitCode -ne 0 -or $treeError.Length -ne 0 -or
        $treeListItem.Length -le 0 -or $treeListItem.Length -gt 33554432) {
        throw "Git could not enumerate the exact candidate tree."
    }
    $treeBytes = [IO.File]::ReadAllBytes($treeListPath)
    $records = New-Object Collections.Generic.List[object]
    $pathSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    try {
        $recordStart = 0
        for ($index = 0; $index -lt $treeBytes.Length; $index++) {
            if ($treeBytes[$index] -ne 0) {
                continue
            }
            if ($index -eq $recordStart) {
                throw "Git returned an empty candidate tree record."
            }
            $recordText = [Text.UTF8Encoding]::new($false, $true).GetString(
                $treeBytes,
                $recordStart,
                $index - $recordStart)
            if ($recordText -notmatch
                '^(?<mode>[0-9]{6}) (?<type>[a-z]+) (?<oid>[0-9a-f]+)\t(?<path>.+)$') {
                throw "Git returned an invalid candidate tree record."
            }
            $mode = [string]$Matches['mode']
            $type = [string]$Matches['type']
            $oid = [string]$Matches['oid']
            $relative = [string]$Matches['path']
            if ($mode -cnotin @("100644", "100755") -or
                $type -cne "blob" -or
                $oid -cnotmatch "^[0-9a-f]{$($ExpectedCommit.Length)}$" -or
                -not (Test-SteinPackageSafeWindowsRelativePath -Value $relative) -or
                -not $pathSet.Add($relative)) {
                throw "The candidate tree contains an unsupported path or object."
            }
            $records.Add([pscustomobject]@{
                    RelativePath = $relative
                    ObjectId = $oid
                    Mode = $mode
                })
            if ($records.Count -gt 100000) {
                throw "The candidate tree exceeds its file-count bound."
            }
            $recordStart = $index + 1
        }
        if ($recordStart -ne $treeBytes.Length -or $records.Count -le 0) {
            throw "Git returned an incomplete candidate tree listing."
        }
    }
    finally {
        [Array]::Clear($treeBytes, 0, $treeBytes.Length)
    }

    $archivePath = Join-Path $root "candidate.zip"
    $archiveOutput = @(& $gitPath `
            -c core.fsmonitor=false `
            -c core.untrackedCache=false `
            -C $repositoryPath `
            archive `
            --format=zip `
            "--output=$archivePath" `
            $ExpectedCommit 2>&1)
    if ($LASTEXITCODE -ne 0 -or $archiveOutput.Count -ne 0) {
        throw "Git could not export the exact candidate tree."
    }
    $archivePath = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $root `
        -Path $archivePath
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $candidateRoot = Join-Path $root "candidate"
    if (Test-Path -LiteralPath $candidateRoot) {
        throw "The private candidate snapshot path already exists."
    }
    $null = New-Item -ItemType Directory -Path $candidateRoot -ErrorAction Stop
    $candidateRoot = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path $candidateRoot
    $expected = @{}
    foreach ($record in $records) {
        $expected[[string]$record.RelativePath] = $record
    }
    $seenArchivePaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $totalSize = 0L
        foreach ($entry in $archive.Entries) {
            $relative = ([string]$entry.FullName).Replace("\", "/")
            if ($relative.EndsWith("/", [StringComparison]::Ordinal)) {
                continue
            }
            $unixMode = ([uint32]$entry.ExternalAttributes -shr 16) -band 0xF000
            if (-not (Test-SteinPackageSafeWindowsRelativePath -Value $relative) -or
                $unixMode -eq 0xA000 -or
                -not $seenArchivePaths.Add($relative) -or
                -not $expected.ContainsKey($relative) -or
                $entry.Length -lt 0 -or $entry.Length -gt 2147483648) {
                throw "The Git archive differs from the closed candidate tree."
            }
            $totalSize += [long]$entry.Length
            if ($totalSize -gt 8589934592) {
                throw "The Git archive exceeds its extracted-size bound."
            }
            $destination = [IO.Path]::GetFullPath((Join-Path $candidateRoot (
                        $relative.Replace('/', [IO.Path]::DirectorySeparatorChar))))
            if (-not $destination.StartsWith(
                    "$candidateRoot$([IO.Path]::DirectorySeparatorChar)",
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "A Git archive entry escaped the candidate root."
            }
            $parent = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $parent)) {
                $null = New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop
            }
            $input = $entry.Open()
            $output = [IO.FileStream]::new(
                $destination,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None)
            try {
                $input.CopyTo($output)
            }
            finally {
                $output.Dispose()
                $input.Dispose()
            }
            if ((Get-SteinPackageGitBlobObjectId `
                    -Path $destination `
                    -ObjectFormat $objectFormat) -cne
                [string]$expected[$relative].ObjectId) {
                throw "An extracted candidate file differs from its Git blob."
            }
        }
    }
    finally {
        $archive.Dispose()
    }
    if ($seenArchivePaths.Count -ne $records.Count) {
        throw "Git archive attributes omitted or added a candidate file."
    }
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction Stop
    Remove-Item -LiteralPath $treeListPath -Force -ErrorAction Stop
    Remove-Item -LiteralPath $treeErrorPath -Force -ErrorAction Stop
    return [pscustomobject]@{
        Root = $candidateRoot
        Commit = $ExpectedCommit
        Tree = $ExpectedTree
        ObjectFormat = $objectFormat
        Files = $records.ToArray()
    }
}

function Get-SteinPackageSourceFixtureTreeBinding {
    param([Parameter(Mandatory = $true)] $Snapshot)

    $files = @($Snapshot.Files)
    if ($files.Count -lt 1 -or $files.Count -gt 100000) {
        throw "The source-fixture candidate tree is outside its file-count bound."
    }
    $records = New-Object Collections.Generic.List[string]
    $paths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $objectIdLength = if ([string]$Snapshot.ObjectFormat -ceq 'sha1') {
        40
    }
    elseif ([string]$Snapshot.ObjectFormat -ceq 'sha256') {
        64
    }
    else {
        throw "The source-fixture candidate object format is invalid."
    }
    foreach ($file in $files) {
        $path = [string]$file.RelativePath
        if (-not (Test-SteinPackageSafeWindowsRelativePath -Value $path) -or
            -not $paths.Add($path) -or
            [string]$file.Mode -cnotin @('100644', '100755') -or
            [string]$file.ObjectId -cnotmatch "^[0-9a-f]{$objectIdLength}$") {
            throw "The source-fixture candidate tree record is invalid."
        }
        $pathBytes = [Text.UTF8Encoding]::new($false).GetByteCount($path)
        $records.Add(
            "$pathBytes`:$path|$([string]$file.Mode)|$([string]$file.ObjectId)")
    }
    $records.Sort([StringComparer]::Ordinal)
    $recordArray = $records.ToArray()
    return [pscustomobject]@{
        FileCount = $recordArray.Count
        ManifestSha256 = Get-SteinPackageTextSha256 `
            -Value ($recordArray -join "`n")
    }
}

function Open-SteinExactCandidateSnapshotLocks {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [string[]] $AllowedAdditionalRelativeRoots = @()
    )

    $root = Resolve-SteinPackageRegularDirectoryWithAncestors -Path $Snapshot.Root
    $allowedPrefixes = @($AllowedAdditionalRelativeRoots | ForEach-Object {
            ([string]$_).Replace("\", "/").TrimEnd('/') + "/"
        })
    $expected = @{}
    foreach ($record in @($Snapshot.Files)) {
        $expected[[string]$record.RelativePath] = $record
    }
    $streams = New-Object Collections.Generic.List[IO.FileStream]
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $pending = New-Object Collections.Generic.Stack[string]
    $pending.Push($root)
    $entryCount = 0
    try {
        while ($pending.Count -gt 0) {
            $directoryPath = $pending.Pop()
            $directory = Get-Item -LiteralPath $directoryPath -Force -ErrorAction Stop
            if (-not $directory.PSIsContainer -or
                (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw "The candidate snapshot contains an unsafe directory."
            }
            foreach ($entry in @(Get-ChildItem `
                        -LiteralPath $directory.FullName `
                        -Force `
                        -ErrorAction Stop)) {
                $entryCount++
                if ($entryCount -gt 500000) {
                    throw "The candidate snapshot contains an unsafe entry."
                }
                $relative = $entry.FullName.Substring($root.Length + 1).Replace("\", "/")
                $allowed = @($allowedPrefixes | Where-Object {
                        $relative.StartsWith($_, [StringComparison]::OrdinalIgnoreCase)
                    }).Count -gt 0
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    if (-not $allowed -or $expected.ContainsKey($relative)) {
                        throw "The candidate snapshot contains an unsafe reparse entry."
                    }
                    # A provenance-bound pnpm install can create links below its
                    # closed generated root. Never follow them during source checks.
                    continue
                }
                if ($entry.PSIsContainer) {
                    $pending.Push($entry.FullName)
                    continue
                }
                if ($expected.ContainsKey($relative)) {
                    if (-not $seen.Add($relative)) {
                        throw "The candidate snapshot contains a duplicate tracked file."
                    }
                    $stream = [IO.FileStream]::new(
                        $entry.FullName,
                        [IO.FileMode]::Open,
                        [IO.FileAccess]::Read,
                        [IO.FileShare]::Read)
                    $streams.Add($stream)
                    if ((Get-SteinPackageGitBlobObjectId `
                            -Path $entry.FullName `
                            -ObjectFormat $Snapshot.ObjectFormat) -cne
                        [string]$expected[$relative].ObjectId) {
                        throw "A candidate snapshot file changed after export."
                    }
                    continue
                }
                if (-not $allowed) {
                    throw "The candidate snapshot contains an unexpected generated file."
                }
            }
        }
        if ($seen.Count -ne $expected.Count) {
            throw "The candidate snapshot omits a tracked file."
        }
        return [pscustomobject]@{
            Root = $root
            Streams = $streams
            TrackedFileCount = $seen.Count
        }
    }
    catch {
        foreach ($stream in $streams) {
            $stream.Dispose()
        }
        throw
    }
}

function Open-SteinPackageDirectoryManifestLock {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $Domain
    )

    if ($Domain -cnotmatch "^[a-z][a-z0-9-]{2,63}$") {
        throw "A locked directory manifest domain is invalid."
    }
    $rootPath = Resolve-SteinPackageRegularDirectoryWithAncestors -Path $Root
    $files = New-Object Collections.Generic.List[object]
    $pending = New-Object Collections.Generic.Stack[string]
    $pending.Push($rootPath)
    while ($pending.Count -gt 0) {
        $directoryPath = $pending.Pop()
        $directory = Get-Item -LiteralPath $directoryPath -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "A locked directory manifest contains an unsafe directory."
        }
        foreach ($entry in @(Get-ChildItem `
                    -LiteralPath $directory.FullName `
                    -Force `
                    -ErrorAction Stop)) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "A locked directory manifest contains a reparse point."
            }
            if ($entry.PSIsContainer) {
                $pending.Push($entry.FullName)
            }
            else {
                $relative = $entry.FullName.Substring($rootPath.Length + 1).Replace("\", "/")
                $files.Add([pscustomobject]@{
                        RelativePath = $relative
                        Path = $entry.FullName
                        Size = [long]$entry.Length
                    })
                if ($files.Count -gt 10000) {
                    throw "A locked directory manifest exceeds its file-count bound."
                }
            }
        }
    }
    if ($files.Count -le 0) {
        throw "A locked directory manifest is empty."
    }
    $streams = New-Object Collections.Generic.List[IO.FileStream]
    $records = New-Object Collections.Generic.List[string]
    $manifestFiles = New-Object Collections.Generic.List[object]
    $totalSize = 0L
    try {
        foreach ($file in @($files | Sort-Object RelativePath)) {
            $stream = [IO.FileStream]::new(
                $file.Path,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read)
            $streams.Add($stream)
            if ($stream.Length -ne [long]$file.Size) {
                throw "A locked directory file changed during manifest capture."
            }
            $digest = Get-SteinPackageStreamSha256 -Stream $stream
            $pathBytes = [Text.UTF8Encoding]::new($false).GetByteCount(
                [string]$file.RelativePath)
            $records.Add(
                "$pathBytes`:$([string]$file.RelativePath)`n$($stream.Length):$digest")
            $manifestFiles.Add([pscustomobject]@{
                    relative_path = ([string]$file.RelativePath).Replace("\", "/")
                    size = [long]$stream.Length
                    sha256 = $digest
                })
            $totalSize += $stream.Length
            if ($totalSize -gt 536870912) {
                throw "A locked directory manifest exceeds its byte bound."
            }
        }
        $expectedPaths = [Collections.Generic.Dictionary[string,long]]::new(
            [StringComparer]::Ordinal)
        foreach ($file in $files) {
            if ($expectedPaths.ContainsKey([string]$file.RelativePath)) {
                throw "A locked directory manifest contains a duplicate path."
            }
            $expectedPaths.Add(
                [string]$file.RelativePath,
                [long]$file.Size)
        }
        $seenPaths = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        $postPending = New-Object Collections.Generic.Stack[string]
        $postPending.Push($rootPath)
        while ($postPending.Count -gt 0) {
            $postDirectoryPath = $postPending.Pop()
            $postDirectory = Get-Item `
                -LiteralPath $postDirectoryPath `
                -Force `
                -ErrorAction Stop
            if (-not $postDirectory.PSIsContainer -or
                (($postDirectory.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw "A locked directory manifest changed during stable enumeration."
            }
            foreach ($postEntry in @(Get-ChildItem `
                        -LiteralPath $postDirectory.FullName `
                        -Force `
                        -ErrorAction Stop)) {
                if (($postEntry.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "A locked directory manifest contains a reparse point."
                }
                if ($postEntry.PSIsContainer) {
                    $postPending.Push($postEntry.FullName)
                    continue
                }
                $postRelative = $postEntry.FullName.Substring(
                    $rootPath.Length + 1).Replace("\", "/")
                if (-not $expectedPaths.ContainsKey($postRelative) -or
                    -not $seenPaths.Add($postRelative) -or
                    [long]$postEntry.Length -ne $expectedPaths[$postRelative]) {
                    throw "A locked directory manifest changed during stable enumeration."
                }
            }
        }
        if ($seenPaths.Count -ne $expectedPaths.Count) {
            throw "A locked directory manifest changed during stable enumeration."
        }
        $material = "$Domain`n" + ($records.ToArray() -join "`n")
        return [pscustomobject]@{
            Root = $rootPath
            FileCount = $files.Count
            TotalSize = $totalSize
            ManifestSha256 = Get-SteinPackageTextSha256 -Value $material
            Files = $manifestFiles.ToArray()
            Streams = $streams
        }
    }
    catch {
        foreach ($stream in $streams) {
            $stream.Dispose()
        }
        throw
    }
}

function Invoke-SteinPackageBoundedVersionCommand {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory,
        [switch] $AllowStandardError
    )

    $workingPath = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path $WorkingDirectory
    $executablePath = Resolve-SteinPackageRegularFileWithAncestors `
        -Path $Executable
    $quoteArgument = {
        param([string] $Value)
        if ($Value -notmatch '[\s"]') {
            return $Value
        }
        $builder = [Text.StringBuilder]::new()
        $null = $builder.Append('"')
        $backslashes = 0
        foreach ($character in $Value.ToCharArray()) {
            if ($character -ceq '\') {
                $backslashes++
                continue
            }
            if ($character -ceq '"') {
                $null = $builder.Append(('\' * (($backslashes * 2) + 1)))
                $null = $builder.Append('"')
                $backslashes = 0
                continue
            }
            if ($backslashes -gt 0) {
                $null = $builder.Append(('\' * $backslashes))
                $backslashes = 0
            }
            $null = $builder.Append($character)
        }
        if ($backslashes -gt 0) {
            $null = $builder.Append(('\' * ($backslashes * 2)))
        }
        $null = $builder.Append('"')
        return $builder.ToString()
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $executablePath
    $startInfo.WorkingDirectory = $workingPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Arguments = (@($Arguments | ForEach-Object {
                & $quoteArgument ([string]$_)
            }) -join ' ')
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "A provenance-bound build tool could not start."
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
    }
    finally {
        $process.Dispose()
    }
    $text = ([string]$stdout).Trim()
    if ($exitCode -ne 0 -or $text.Length -le 0 -or $text.Length -gt 4096 -or
        $text.Contains("`r") -or $text.Contains("`n") -or
        ([string]$stderr).Length -gt 512 -or
        (-not $AllowStandardError -and
            -not [string]::IsNullOrWhiteSpace([string]$stderr))) {
        throw "A provenance-bound build tool returned an invalid result."
    }
    return $text
}

function Get-SteinVerifiedBuildToolchain {
    param(
        [Parameter(Mandatory = $true)] $SourceBinding,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )

    $workingPath = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path $WorkingDirectory
    $locks = New-Object Collections.Generic.List[object]
    try {
        $commands = @{}
        foreach ($entry in @(
                [pscustomobject]@{ Name = "cargo"; Command = "cargo.exe"; Hash = $SourceBinding.CargoExecutableSha256 },
                [pscustomobject]@{ Name = "rustc"; Command = "rustc.exe"; Hash = $SourceBinding.RustcExecutableSha256 },
                [pscustomobject]@{ Name = "rustup"; Command = "rustup.exe"; Hash = $SourceBinding.RustupExecutableSha256 },
                [pscustomobject]@{ Name = "node"; Command = "node.exe"; Hash = $SourceBinding.NodeExecutableSha256 },
                [pscustomobject]@{ Name = "pnpm"; Command = "pnpm.cmd"; Hash = $SourceBinding.PnpmExecutableSha256 },
                [pscustomobject]@{ Name = "git"; Command = "git.exe"; Hash = $SourceBinding.GitExecutableSha256 })) {
            $command = Get-Command $entry.Command `
                -CommandType Application `
                -ErrorAction Stop |
                Select-Object -First 1
            if ($null -eq $command -or
                [IO.Path]::GetFileName([string]$command.Source) -cne $entry.Command) {
                throw "A source-provenance build tool resolved unexpectedly."
            }
            $locked = Open-SteinPackageVerifiedFileLock `
                -Path ([string]$command.Source) `
                -ExpectedSha256 ([string]$entry.Hash)
            $locks.Add($locked)
            $commands[[string]$entry.Name] = $locked.Path
        }

        $gitCommandRoot = [IO.Path]::GetFullPath(
            (Split-Path -Parent $commands["git"])).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        if ((Split-Path -Leaf $gitCommandRoot) -cne "cmd") {
            throw "The Git-for-Windows launcher location is unsupported."
        }
        $gitInstallRoot = [IO.Path]::GetFullPath(
            (Split-Path -Parent $gitCommandRoot)).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $resolvedGitPath = [IO.Path]::GetFullPath(
            (Join-Path $gitInstallRoot "mingw64\bin\git.exe"))
        if (-not $resolvedGitPath.StartsWith(
                "$gitInstallRoot$([IO.Path]::DirectorySeparatorChar)",
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "The resolved Git payload escaped its installation root."
        }
        $resolvedGitLock = Open-SteinPackageVerifiedFileLock `
            -Path $resolvedGitPath `
            -ExpectedSha256 ([string]$SourceBinding.GitResolvedExecutableSha256)
        $locks.Add($resolvedGitLock)

        $active = Invoke-SteinPackageBoundedVersionCommand `
            -Executable $commands["rustup"] `
            -Arguments @("show", "active-toolchain") `
            -WorkingDirectory $workingPath
        $activeToolchain = @($active -split '\s+', 2)[0]
        if ($activeToolchain -cne [string]$SourceBinding.RustupToolchain) {
            throw "The active Rust toolchain differs from source provenance."
        }
        $resolvedRust = @{}
        foreach ($tool in @("cargo", "rustc")) {
            $resolvedPath = Invoke-SteinPackageBoundedVersionCommand `
                -Executable $commands["rustup"] `
                -Arguments @(
                    "which", "--toolchain", [string]$SourceBinding.RustupToolchain, $tool) `
                -WorkingDirectory $workingPath
            if (-not [IO.Path]::IsPathRooted($resolvedPath) -or
                [IO.Path]::GetFileName($resolvedPath) -cne "$tool.exe") {
                throw "Rustup resolved an invalid build-tool payload."
            }
            $expectedHash = if ($tool -ceq "cargo") {
                [string]$SourceBinding.CargoResolvedExecutableSha256
            }
            else {
                [string]$SourceBinding.RustcResolvedExecutableSha256
            }
            $locked = Open-SteinPackageVerifiedFileLock `
                -Path $resolvedPath `
                -ExpectedSha256 $expectedHash
            $locks.Add($locked)
            $resolvedRust[$tool] = $locked.Path
        }

        $pnpmLocked = @($locks | Where-Object {
                [string]::Equals(
                    [string]$_.Path,
                    [string]$commands["pnpm"],
                    [StringComparison]::OrdinalIgnoreCase)
            })[0]
        if ($pnpmLocked.Size -gt 65536) {
            throw "The pnpm launcher exceeds its provenance size bound."
        }
        $pnpmBytes = New-Object byte[] ([int]$pnpmLocked.Size)
        try {
            $pnpmLocked.Stream.Position = 0
            $offset = 0
            while ($offset -lt $pnpmBytes.Length) {
                $read = $pnpmLocked.Stream.Read(
                    $pnpmBytes,
                    $offset,
                    $pnpmBytes.Length - $offset)
                if ($read -le 0) {
                    throw "The pnpm launcher could not be read exactly."
                }
                $offset += $read
            }
            $pnpmLocked.Stream.Position = 0
            $pnpmText = [Text.UTF8Encoding]::new($false, $true).GetString($pnpmBytes)
        }
        finally {
            [Array]::Clear($pnpmBytes, 0, $pnpmBytes.Length)
        }
        $entrypointMatches = [regex]::Matches(
            $pnpmText,
            '"%dp0%\\(?<relative>node_modules\\pnpm\\bin\\pnpm\.(?:cjs|mjs|js))"\s+%\*',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($entrypointMatches.Count -ne 1) {
            throw "The pnpm launcher entrypoint differs from source provenance."
        }
        $relativeEntrypoint = [string]$entrypointMatches[0].Groups['relative'].Value
        if ($relativeEntrypoint.Contains("..") -or
            [IO.Path]::IsPathRooted($relativeEntrypoint)) {
            throw "The pnpm launcher entrypoint is invalid."
        }
        $pnpmRoot = [IO.Path]::GetFullPath((Split-Path -Parent $commands["pnpm"])).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $pnpmEntrypoint = [IO.Path]::GetFullPath(
            (Join-Path $pnpmRoot $relativeEntrypoint))
        if (-not $pnpmEntrypoint.StartsWith(
                "$pnpmRoot$([IO.Path]::DirectorySeparatorChar)",
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "The pnpm launcher entrypoint escaped its installation root."
        }
        $pnpmEntrypointLock = Open-SteinPackageVerifiedFileLock `
            -Path $pnpmEntrypoint `
            -ExpectedSha256 ([string]$SourceBinding.PnpmResolvedEntrypointSha256)
        $locks.Add($pnpmEntrypointLock)
        $siblingNode = Join-Path $pnpmRoot "node.exe"
        if (Test-Path -LiteralPath $siblingNode -PathType Leaf) {
            if (-not [string]::Equals(
                    (Resolve-SteinPackageRegularFileWithAncestors -Path $siblingNode),
                    [string]$commands["node"],
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "The pnpm launcher selects a different Node runtime."
            }
        }

        $actualVersions = @{
            cargo = Invoke-SteinPackageBoundedVersionCommand `
                -Executable $resolvedRust["cargo"] `
                -Arguments @("--version") `
                -WorkingDirectory $workingPath
            rustc = Invoke-SteinPackageBoundedVersionCommand `
                -Executable $resolvedRust["rustc"] `
                -Arguments @("--version") `
                -WorkingDirectory $workingPath
            rustup = Invoke-SteinPackageBoundedVersionCommand `
                -Executable $commands["rustup"] `
                -Arguments @("--version") `
                -WorkingDirectory $workingPath `
                -AllowStandardError
            node = Invoke-SteinPackageBoundedVersionCommand `
                -Executable $commands["node"] `
                -Arguments @("--version") `
                -WorkingDirectory $workingPath
            pnpm = Invoke-SteinPackageBoundedVersionCommand `
                -Executable $commands["node"] `
                -Arguments @($pnpmEntrypointLock.Path, "--version") `
                -WorkingDirectory $workingPath
            git = Invoke-SteinPackageBoundedVersionCommand `
                -Executable $resolvedGitLock.Path `
                -Arguments @("--version") `
                -WorkingDirectory $workingPath
        }
        foreach ($versionCheck in @(
                [pscustomobject]@{ Name = "cargo"; Expected = $SourceBinding.CargoVersion },
                [pscustomobject]@{ Name = "rustc"; Expected = $SourceBinding.RustcVersion },
                [pscustomobject]@{ Name = "rustup"; Expected = $SourceBinding.RustupVersion },
                [pscustomobject]@{ Name = "node"; Expected = $SourceBinding.NodeVersion },
                [pscustomobject]@{ Name = "pnpm"; Expected = $SourceBinding.PnpmVersion },
                [pscustomobject]@{ Name = "git"; Expected = $SourceBinding.GitVersion })) {
            if ([string]$actualVersions[[string]$versionCheck.Name] -cne
                [string]$versionCheck.Expected) {
                throw "A resolved build-tool version differs from source provenance."
            }
        }
        return [pscustomobject]@{
            Git = [string]$resolvedGitLock.Path
            GitLauncher = [string]$commands["git"]
            CargoLauncher = [string]$commands["cargo"]
            RustcLauncher = [string]$commands["rustc"]
            Rustup = [string]$commands["rustup"]
            Cargo = [string]$resolvedRust["cargo"]
            Rustc = [string]$resolvedRust["rustc"]
            Node = [string]$commands["node"]
            PnpmLauncher = [string]$commands["pnpm"]
            PnpmEntrypoint = [string]$pnpmEntrypointLock.Path
            Locks = $locks
        }
    }
    catch {
        foreach ($locked in $locks) {
            $locked.Stream.Dispose()
        }
        throw
    }
}

function Assert-SteinVerifiedBuildToolchainLocks {
    param([Parameter(Mandatory = $true)] $Toolchain)

    foreach ($locked in $Toolchain.Locks) {
        if ($locked.Stream.Length -ne [long]$locked.Size -or
            (Get-SteinPackageStreamSha256 -Stream $locked.Stream) -cne
                [string]$locked.Sha256) {
            throw "A provenance-bound build tool changed during release generation."
        }
    }
    return $true
}

function ConvertTo-SteinPackageExtendedLengthPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        return $fullPath
    }
    if ($fullPath.StartsWith('\\', [StringComparison]::Ordinal)) {
        return '\\?\UNC\' + $fullPath.Substring(2)
    }
    return '\\?\' + $fullPath
}

function ConvertFrom-SteinPackageExtendedLengthPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    if ($Path.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        return [IO.Path]::GetFullPath('\\' + $Path.Substring(8))
    }
    if ($Path.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        return [IO.Path]::GetFullPath($Path.Substring(4))
    }
    return [IO.Path]::GetFullPath($Path)
}

function Initialize-SteinPackagePrivateCleanupNativeApi {
    if ($null -ne ('Stein.PackagePrivateCleanupNative' -as [type])) {
        return
    }
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Stein {
    public static class PackagePrivateCleanupNative {
        private const UInt32 DeleteAccess = 0x00010000;
        private const UInt32 ListDirectoryAccess = 0x00000001;
        private const UInt32 ReadAttributesAccess = 0x00000080;
        private const UInt32 ShareRead = 0x00000001;
        private const UInt32 ShareReadWriteDelete = 0x00000007;
        private const UInt32 OpenExisting = 3;
        private const UInt32 BackupSemantics = 0x02000000;
        private const UInt32 OpenReparsePoint = 0x00200000;
        private const UInt32 DirectoryAttribute = 0x00000010;
        private const UInt32 ReparsePointAttribute = 0x00000400;
        private const Int32 FileAttributeTagInfo = 9;
        private const Int32 FileDispositionInfoEx = 21;
        private const UInt32 DispositionDelete = 0x00000001;
        private const UInt32 DispositionIgnoreReadOnly = 0x00000010;
        private const Int32 ErrorFileNotFound = 2;

        [StructLayout(LayoutKind.Sequential)]
        private struct FileDispositionInfoExValue {
            public UInt32 Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileAttributeTagInfoValue {
            public UInt32 FileAttributes;
            public UInt32 ReparseTag;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            Int32 informationClass,
            ref FileDispositionInfoExValue information,
            UInt32 bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file,
            Int32 informationClass,
            out FileAttributeTagInfoValue information,
            UInt32 bufferSize);

        private static void SetDeleteDisposition(SafeFileHandle file) {
            if (file == null || file.IsInvalid || file.IsClosed) {
                throw new ArgumentException("A private cleanup handle is invalid.");
            }
            FileDispositionInfoExValue disposition =
                new FileDispositionInfoExValue();
            disposition.Flags = DispositionDelete | DispositionIgnoreReadOnly;
            if (!SetFileInformationByHandle(
                    file,
                    FileDispositionInfoEx,
                    ref disposition,
                    (UInt32)Marshal.SizeOf(disposition))) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        private static SafeFileHandle OpenDirectory(
                string path,
                bool requireReparsePoint) {
            SafeFileHandle directory = CreateFileW(
                path,
                DeleteAccess | ListDirectoryAccess | ReadAttributesAccess,
                ShareRead,
                IntPtr.Zero,
                OpenExisting,
                BackupSemantics | OpenReparsePoint,
                IntPtr.Zero);
            if (directory.IsInvalid) {
                Int32 error = Marshal.GetLastWin32Error();
                directory.Dispose();
                throw new Win32Exception(error);
            }
            FileAttributeTagInfoValue attributes;
            if (!GetFileInformationByHandleEx(
                    directory,
                    FileAttributeTagInfo,
                    out attributes,
                    (UInt32)Marshal.SizeOf(typeof(FileAttributeTagInfoValue)))) {
                Int32 error = Marshal.GetLastWin32Error();
                directory.Dispose();
                throw new Win32Exception(error);
            }
            bool isDirectory =
                (attributes.FileAttributes & DirectoryAttribute) != 0;
            bool isReparsePoint =
                (attributes.FileAttributes & ReparsePointAttribute) != 0;
            if (!isDirectory || isReparsePoint != requireReparsePoint) {
                directory.Dispose();
                throw new IOException(
                    "A private cleanup directory changed filesystem identity.");
            }
            return directory;
        }

        public static SafeFileHandle OpenRegularDirectory(string path) {
            return OpenDirectory(path, false);
        }

        public static void DeleteDirectoryHandle(SafeFileHandle directory) {
            SetDeleteDisposition(directory);
        }

        public static void DeleteDirectoryLink(string path) {
            using (SafeFileHandle directory = OpenDirectory(path, true)) {
                SetDeleteDisposition(directory);
            }
        }

        public static void DeleteFileLink(string path) {
            SafeFileHandle file = CreateFileW(
                path,
                DeleteAccess,
                ShareReadWriteDelete,
                IntPtr.Zero,
                OpenExisting,
                OpenReparsePoint,
                IntPtr.Zero);
            if (file.IsInvalid) {
                Int32 error = Marshal.GetLastWin32Error();
                file.Dispose();
                if (error == ErrorFileNotFound) {
                    return;
                }
                throw new Win32Exception(error);
            }
            using (file) {
                SetDeleteDisposition(file);
            }
        }
    }
}
"@
}

function Remove-SteinPackagePrivateTemporaryDirectory {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet("build", "verify")]
        [string] $Purpose
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $root = Assert-SteinPackagePrivateTemporaryDirectory `
        -Path $Path `
        -Purpose $Purpose
    Initialize-SteinPackagePrivateCleanupNativeApi
    $pending = New-Object Collections.Generic.Stack[object]
    $directories = New-Object Collections.Generic.List[object]
    $rootHandle = [Stein.PackagePrivateCleanupNative]::OpenRegularDirectory(
        (ConvertTo-SteinPackageExtendedLengthPath -Path $root))
    $rootRecord = [pscustomobject]@{
        Path = $root
        Handle = $rootHandle
    }
    $directories.Add($rootRecord)
    $pending.Push($rootRecord)
    $rootPrefix = "$root$([IO.Path]::DirectorySeparatorChar)"
    $entryCount = 0
    try {
        $confirmedRoot = Assert-SteinPackagePrivateTemporaryDirectory `
            -Path $root `
            -Purpose $Purpose
        if (-not [string]::Equals(
                $confirmedRoot,
                $root,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "The private packaging temporary root changed during cleanup."
        }
        while ($pending.Count -gt 0) {
            $directory = $pending.Pop()
            $directoryPath = [string]$directory.Path
            foreach ($entry in @(Get-ChildItem `
                        -LiteralPath (ConvertTo-SteinPackageExtendedLengthPath `
                            -Path $directoryPath) `
                        -Force `
                        -ErrorAction Stop)) {
                $entryPath = ConvertFrom-SteinPackageExtendedLengthPath `
                    -Path ([string]$entry.FullName)
                if (-not $entryPath.StartsWith(
                        $rootPrefix,
                        [StringComparison]::OrdinalIgnoreCase) -or
                    -not [string]::Equals(
                        (Split-Path -Parent $entryPath),
                        $directoryPath,
                        [StringComparison]::OrdinalIgnoreCase)) {
                    throw "The private packaging temporary tree escaped during cleanup."
                }
                $entryCount++
                if ($entryCount -gt 500000) {
                    throw "The private packaging temporary tree is unsafe to delete."
                }
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    # Delete the identity-bound link itself and never traverse its target.
                    $entryDeletePath = ConvertTo-SteinPackageExtendedLengthPath `
                        -Path $entryPath
                    if ($entry.PSIsContainer) {
                        [Stein.PackagePrivateCleanupNative]::DeleteDirectoryLink(
                            $entryDeletePath)
                    }
                    else {
                        [Stein.PackagePrivateCleanupNative]::DeleteFileLink(
                            $entryDeletePath)
                    }
                }
                elseif ($entry.PSIsContainer) {
                    $childHandle = $null
                    try {
                        $childHandle = [Stein.PackagePrivateCleanupNative]::OpenRegularDirectory(
                            (ConvertTo-SteinPackageExtendedLengthPath -Path $entryPath))
                        $childRecord = [pscustomobject]@{
                            Path = $entryPath
                            Handle = $childHandle
                        }
                        $directories.Add($childRecord)
                        $pending.Push($childRecord)
                        $childHandle = $null
                    }
                    finally {
                        if ($null -ne $childHandle) {
                            $childHandle.Dispose()
                        }
                    }
                }
                else {
                    # The handle is opened on the exact link without following a
                    # reparse target. The disposition is long-path-safe, ignores
                    # this link's ReadOnly deletion barrier without changing shared
                    # hardlink metadata, and treats only a missing leaf as idempotent.
                    [Stein.PackagePrivateCleanupNative]::DeleteFileLink(
                        (ConvertTo-SteinPackageExtendedLengthPath -Path $entryPath))
                }
            }
        }
        for ($index = $directories.Count - 1; $index -ge 0; $index--) {
            $directory = $directories[$index]
            [Stein.PackagePrivateCleanupNative]::DeleteDirectoryHandle(
                $directory.Handle)
            $directory.Handle.Dispose()
            $directory.Handle = $null
        }
    }
    finally {
        foreach ($directory in $directories) {
            if ($null -ne $directory.Handle) {
                $directory.Handle.Dispose()
                $directory.Handle = $null
            }
        }
    }
    if (Test-Path -LiteralPath $root) {
        throw "The private packaging temporary directory was not deleted."
    }
}

function Resolve-SteinPackagePrimaryAndCleanupFailure {
    param(
        [AllowNull()][Management.Automation.ErrorRecord] $PrimaryFailure,
        [AllowNull()][Management.Automation.ErrorRecord] $CleanupFailure
    )

    if ($null -eq $PrimaryFailure) {
        return $CleanupFailure
    }
    if ($null -ne $CleanupFailure) {
        $PrimaryFailure.Exception.Data['SteinPrivateTemporaryCleanupFailure'] =
            [string]$CleanupFailure
        $PrimaryFailure.Exception.Data['SteinPrivateTemporaryCleanupFailureId'] =
            [string]$CleanupFailure.FullyQualifiedErrorId
    }
    return $PrimaryFailure
}

function Read-SteinPackageLockedJson {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][long] $MaximumBytes
    )

    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $bytes = $null
    try {
        if ($stream.Length -le 0 -or
            $stream.Length -gt $MaximumBytes -or
            $stream.Length -gt [int]::MaxValue) {
            throw "A build evidence JSON file is outside its size bound."
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "A build evidence JSON file could not be read exactly."
            }
            $offset += $read
        }
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = [BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace(
                "-",
                "").ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
        $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        try {
            $value = $json | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "A build evidence input is not valid strict UTF-8 JSON."
        }
        return [pscustomobject]@{
            Path = $Path
            Size = [long]$bytes.Length
            Sha256 = $digest
            Value = $value
        }
    }
    finally {
        $stream.Dispose()
        if ($null -ne $bytes) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
}

function ConvertTo-SteinPackageCanonicalSourceTimestamp {
    param([Parameter(Mandatory = $true)] $Value)

    if ($Value -is [DateTime]) {
        $timestamp = [DateTime]$Value
        if ($timestamp.Kind -ne [DateTimeKind]::Utc) {
            throw "A source-verification timestamp is not exact UTC."
        }
        return $timestamp.ToString("o", [Globalization.CultureInfo]::InvariantCulture)
    }
    $text = [string]$Value
    if ($text -cnotmatch
        '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z$') {
        throw "A source-verification timestamp is not exact UTC."
    }
    $parsed = [DateTime]::MinValue
    if (-not [DateTime]::TryParseExact(
            $text,
            "o",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$parsed)) {
        throw "A source-verification timestamp is invalid."
    }
    return $text
}

function Get-SteinPackageSourceFixtureRegistryContract {
    param(
        [Parameter(Mandatory = $true)][string] $CandidateRoot,
        [Parameter(Mandatory = $true)] $EvidenceSpecification
    )

    $candidatePath = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path $CandidateRoot
    $registryPath = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $candidatePath `
        -Path (Join-Path $candidatePath `
            "scripts\windows\phase2\Source-Fixture-Registry.json")
    $registryFile = Read-SteinPackageLockedJson `
        -Path $registryPath `
        -MaximumBytes 1048576
    $expectedRegistrySha256 =
        'd2414e552dfbc00b3ecf5837cfc431c64f670508ae4e8696b9fce4f85a75c5c5'
    if ([string]$registryFile.Sha256 -cne $expectedRegistrySha256 -or
        [string]$EvidenceSpecification.source_report_contract.source_fixture_registry_sha256 `
            -cne $expectedRegistrySha256) {
        throw "The signer source-fixture registry differs from the frozen contract."
    }
    $registry = $registryFile.Value
    Assert-SteinPackageJsonShape -Value $registry `
        -Description "The signer source-fixture registry" `
        -ExpectedProperties @(
            "schema_version", "registry_id", "receipt_schema_version", "fixtures")
    $fixtures = @($registry.fixtures)
    if ([long]$registry.schema_version -ne 1 -or
        [string]$registry.registry_id -cne
            "stein.phase2.source-fixture.registry.v1" -or
        [long]$registry.receipt_schema_version -ne 1 -or
        $fixtures.Count -ne 13) {
        throw "The signer source-fixture registry is invalid."
    }
    $byCheckId = @{}
    $checkIds = New-Object Collections.Generic.List[string]
    foreach ($fixture in $fixtures) {
        Assert-SteinPackageJsonShape -Value $fixture `
            -Description "A signer source-fixture definition" `
            -ExpectedProperties @(
                "source_check_id", "source_fixture_id", "source_runner_id",
                "gate_id", "gate_fixture_id", "gate_runner_id",
                "semantic_source_paths", "subchecks")
        $checkId = [string]$fixture.source_check_id
        if ($checkId -cnotmatch '^phase2-source-fixture-[a-z0-9-]{2,64}$' -or
            $byCheckId.ContainsKey($checkId)) {
            throw "The signer source-fixture registry check set is invalid."
        }
        $slug = $checkId.Substring('phase2-source-fixture-'.Length)
        if ([string]$fixture.source_fixture_id -cne "$checkId-v1" -or
            [string]$fixture.source_runner_id -cne
                "stein.phase2.source-fixture.$slug.v1") {
            throw "A signer source-fixture identity is invalid."
        }
        $gates = @($EvidenceSpecification.gates | Where-Object {
                $sourceCheckProperty =
                    $_.PSObject.Properties['source_report_check_ids']
                $null -ne $sourceCheckProperty -and
                    $checkId -cin @($sourceCheckProperty.Value)
            })
        if ($gates.Count -ne 1 -or
            [string]$fixture.gate_id -cne [string]$gates[0].gate_id -or
            [string]$fixture.gate_fixture_id -cne [string]$gates[0].fixture_id -or
            [string]$fixture.gate_runner_id -cne [string]$gates[0].runner_id) {
            throw "A signer source-fixture gate binding is invalid."
        }
        $byCheckId[$checkId] = $fixture
        $checkIds.Add($checkId)
    }
    $contractCheckIds = @(
        @($EvidenceSpecification.source_report_contract.required_pass_check_ids) +
        @($EvidenceSpecification.source_report_contract.allowed_not_run_check_ids) |
            Where-Object { [string]$_ -clike 'phase2-source-fixture-*' })
    $expectedCheckIds = @($checkIds | ForEach-Object { $_ })
    [Array]::Sort($contractCheckIds, [StringComparer]::Ordinal)
    [Array]::Sort($expectedCheckIds, [StringComparer]::Ordinal)
    if ($contractCheckIds.Count -ne $expectedCheckIds.Count -or
        @(Compare-Object `
                -ReferenceObject $expectedCheckIds `
                -DifferenceObject $contractCheckIds `
                -CaseSensitive).Count -ne 0) {
        throw "The signer fixture registry and source-report contract disagree."
    }
    return [pscustomobject]@{
        Registry = $registry
        RegistrySha256 = [string]$registryFile.Sha256
        FixturesByCheckId = $byCheckId
        CheckIds = @($checkIds | ForEach-Object { $_ })
    }
}

function Get-SteinPackageCanonicalSourceChecksDigest {
    param(
        [Parameter(Mandatory = $true)][object[]] $Checks,
        [string[]] $FixtureCheckIds = @()
    )

    $canonical = New-Object Collections.Generic.List[object]
    $fixtureSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($fixtureCheckId in $FixtureCheckIds) {
        if (-not $fixtureSet.Add([string]$fixtureCheckId)) {
            throw "The canonical source-fixture check set contains a duplicate."
        }
    }
    foreach ($check in $Checks) {
        if ([string]$check.id -ceq "source-provenance-stability") {
            $canonical.Add([ordered]@{
                    id = [string]$check.id
                    status = [string]$check.status
                    initial_provenance_sha256 = [string]$check.initial_provenance_sha256
                    completed_provenance_sha256 = [string]$check.completed_provenance_sha256
                    failure_summary = $check.failure_summary
                })
            continue
        }
        if ([string]$check.status -ceq "not_run") {
            $canonical.Add([ordered]@{
                    id = [string]$check.id
                    status = [string]$check.status
                    reason = [string]$check.reason
                })
            continue
        }
        $canonicalCheck = [ordered]@{
                id = [string]$check.id
                status = [string]$check.status
                executable = [string]$check.executable
                arguments = @($check.arguments)
                working_directory = [string]$check.working_directory
                started_at = ConvertTo-SteinPackageCanonicalSourceTimestamp `
                    -Value $check.started_at
                completed_at = ConvertTo-SteinPackageCanonicalSourceTimestamp `
                    -Value $check.completed_at
                duration_ms = $check.duration_ms
                exit_code = $check.exit_code
                failure_summary = $check.failure_summary
                stdout = [ordered]@{
                    path = [string]$check.stdout.path
                    size = $check.stdout.size
                    sha256 = [string]$check.stdout.sha256
                }
                stderr = [ordered]@{
                    path = [string]$check.stderr.path
                    size = $check.stderr.size
                    sha256 = [string]$check.stderr.sha256
                }
            }
        if ($fixtureSet.Contains([string]$check.id)) {
            $canonicalCheck.source_fixture_receipt = $check.source_fixture_receipt
            $canonicalCheck.source_fixture_receipt_artifact = [ordered]@{
                path = [string]$check.source_fixture_receipt_artifact.path
                size = $check.source_fixture_receipt_artifact.size
                sha256 = [string]$check.source_fixture_receipt_artifact.sha256
            }
            $canonicalCheck.source_fixture_suite_index = [ordered]@{
                path = [string]$check.source_fixture_suite_index.path
                size = $check.source_fixture_suite_index.size
                sha256 = [string]$check.source_fixture_suite_index.sha256
            }
        }
        $canonical.Add($canonicalCheck)
    }
    return Get-SteinPackageTextSha256 `
        -Value ($canonical.ToArray() | ConvertTo-Json -Depth 40 -Compress)
}

function Assert-SteinPackageSourceFixtureCheckContract {
    param(
        [Parameter(Mandatory = $true)] $Check,
        [Parameter(Mandatory = $true)] $Fixture,
        [Parameter(Mandatory = $true)] $FixtureContract,
        [Parameter(Mandatory = $true)] $SourceReport,
        [Parameter(Mandatory = $true)] $EvidenceSpecification,
        [string] $CandidateRoot,
        $CandidateSnapshot,
        $CandidateTreeBinding,
        [Parameter(Mandatory = $true)][bool] $RequireCandidateGrounding,
        [Parameter(Mandatory = $true)][string] $ExpectedCandidateGitCommit,
        [Parameter(Mandatory = $true)][string] $ExpectedCandidateGitTree,
        [Parameter(Mandatory = $true)][string] $ReportDirectory
    )

    $checkId = [string]$Check.id
    if ([string]$Check.executable -cne 'powershell.exe' -or
        [string]$Check.working_directory -cne '.') {
        throw "A signer source-fixture process identity is invalid."
    }
    $arguments = @($Check.arguments | ForEach-Object { [string]$_ })
    $expectedArguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        'scripts/windows/phase2/Run-Source-Fixture.ps1', '-OutputDirectory')
    if ($arguments.Count -ne 8 -or
        @(Compare-Object `
                -ReferenceObject $expectedArguments `
                -DifferenceObject @($arguments[0..6]) `
                -CaseSensitive `
                -SyncWindow 0).Count -ne 0 -or
        $arguments[7] -cnotmatch
            '^artifacts/evidence/phase-2/source-[A-Za-z0-9._-]{1,96}/source-fixtures$') {
        throw "A signer source-fixture process command is invalid."
    }

    $matchingGates = @($EvidenceSpecification.gates | Where-Object {
            [string]$_.gate_id -ceq [string]$Fixture.gate_id
        })
    if ($matchingGates.Count -ne 1) {
        throw "A signer source-fixture gate binding is invalid."
    }
    $candidateEvidenceBinding = [pscustomobject]@{
        bindings = [pscustomobject]@{
            commit = [pscustomobject]@{
                object_id = $ExpectedCandidateGitCommit
                tree_id = $ExpectedCandidateGitTree
            }
        }
    }
    try {
        $null = Assert-SteinPhase2SourceFixtureReceiptCheck `
            -Check $Check `
            -Gate $matchingGates[0] `
            -SourceReport $SourceReport `
            -EvidenceResult $candidateEvidenceBinding `
            -RegistrySha256 ([string]$FixtureContract.RegistrySha256) `
            -Fixture $Fixture
    }
    catch {
        throw "A signer source-fixture nested receipt contract is invalid."
    }
    $receipt = $Check.source_fixture_receipt
    if ($RequireCandidateGrounding) {
        if ([string]::IsNullOrWhiteSpace($CandidateRoot) -or
            $null -eq $CandidateSnapshot -or
            $null -eq $CandidateTreeBinding) {
            throw "The signer source-fixture candidate grounding is unavailable."
        }
        $candidatePath = Resolve-SteinPackageRegularDirectoryWithAncestors `
            -Path $CandidateRoot
        if (-not [string]::Equals(
                $candidatePath,
                [IO.Path]::GetFullPath([string]$CandidateSnapshot.Root).TrimEnd(
                    [IO.Path]::DirectorySeparatorChar,
                    [IO.Path]::AltDirectorySeparatorChar),
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "The signer source-fixture candidate root binding is invalid."
        }
        if ([string]$CandidateSnapshot.Commit -cne $ExpectedCandidateGitCommit -or
            [string]$CandidateSnapshot.Tree -cne $ExpectedCandidateGitTree) {
            throw "The signer source-fixture candidate Git binding is invalid."
        }
        if ([long]$receipt.bindings.candidate_tree_file_count -ne
                [long]$CandidateTreeBinding.FileCount -or
            [string]$receipt.bindings.candidate_tree_manifest_sha256 -cne
                [string]$CandidateTreeBinding.ManifestSha256) {
            throw "The signer source-fixture candidate tree binding is invalid."
        }
        $candidateFilesByPath = @{}
        foreach ($candidateFile in @($CandidateSnapshot.Files)) {
            $candidateRelativePath = [string]$candidateFile.RelativePath
            if ($candidateFilesByPath.ContainsKey($candidateRelativePath)) {
                throw "The signer source-fixture candidate tree contains a duplicate."
            }
            $candidateFilesByPath[$candidateRelativePath] = $candidateFile
        }
        foreach ($semanticSource in @($receipt.semantic_sources)) {
            $semanticRelativePath = [string]$semanticSource.path
            if (-not $candidateFilesByPath.ContainsKey($semanticRelativePath) -or
                [string]$candidateFilesByPath[$semanticRelativePath].RelativePath -cne
                    $semanticRelativePath) {
                throw "A signer source-fixture semantic source is absent from the candidate tree."
            }
            $semanticPath = Resolve-SteinPackageRegularFileUnderRoot `
                -Root $candidatePath `
                -Path (Join-Path $candidatePath (
                        $semanticRelativePath.Replace(
                            '/',
                            [IO.Path]::DirectorySeparatorChar)))
            $semanticItem = Get-Item `
                -LiteralPath $semanticPath `
                -Force `
                -ErrorAction Stop
            $candidateObjectId = [string]$candidateFilesByPath[
                $semanticRelativePath].ObjectId
            if ([long]$semanticSource.size -ne [long]$semanticItem.Length -or
                [string]$semanticSource.sha256 -cne
                    (Get-SteinPackageFileSha256 -Path $semanticPath) -or
                [string]$semanticSource.git_blob_object_id -cne
                    $candidateObjectId -or
                (Get-SteinPackageGitBlobObjectId `
                    -Path $semanticPath `
                    -ObjectFormat ([string]$CandidateSnapshot.ObjectFormat)) -cne
                    $candidateObjectId) {
                throw "A signer source-fixture semantic source differs from candidate bytes."
            }
        }
    }

    $fixtureDirectory = [IO.Path]::GetFullPath(
        (Join-Path $ReportDirectory 'source-fixtures')).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $descriptorCases = @(
        [pscustomobject]@{
            Value = $Check.source_fixture_receipt_artifact
            Path = "source-fixtures/$checkId.receipt.json"
            MaximumBytes = 4194304
        },
        [pscustomobject]@{
            Value = $Check.source_fixture_suite_index
            Path = 'source-fixtures/index.json'
            MaximumBytes = 1048576
        })
    $artifactReads = @{}
    foreach ($descriptorCase in $descriptorCases) {
        $descriptor = $descriptorCase.Value
        Assert-SteinPackageJsonShape -Value $descriptor `
            -Description "A signer source-fixture artifact descriptor" `
            -ExpectedProperties @('path', 'size', 'sha256')
        if ([string]$descriptor.path -cne [string]$descriptorCase.Path -or
            -not (Test-SteinPackageSafeWindowsRelativePath `
                -Value ([string]$descriptor.path)) -or
            ($descriptor.size -isnot [int] -and $descriptor.size -isnot [long]) -or
            [long]$descriptor.size -lt 1 -or
            [long]$descriptor.size -gt [long]$descriptorCase.MaximumBytes -or
            -not (Test-SteinPackageSha256Value -Value ([string]$descriptor.sha256))) {
            throw "A signer source-fixture artifact descriptor is invalid."
        }
        $artifactPath = [IO.Path]::GetFullPath((Join-Path $ReportDirectory (
                    ([string]$descriptor.path).Replace(
                        '/',
                        [IO.Path]::DirectorySeparatorChar))))
        if (-not [string]::Equals(
                (Split-Path -Parent $artifactPath),
                $fixtureDirectory,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "A signer source-fixture artifact escaped its exact directory."
        }
        $artifactPath = Resolve-SteinPackageRegularFileUnderRoot `
            -Root $ReportDirectory `
            -Path $artifactPath
        $artifactRead = Read-SteinPackageLockedJson `
            -Path $artifactPath `
            -MaximumBytes ([int]$descriptorCase.MaximumBytes)
        if ([long]$artifactRead.Size -ne [long]$descriptor.size -or
            [string]$artifactRead.Sha256 -cne [string]$descriptor.sha256) {
            throw "A signer source-fixture artifact differs from its descriptor."
        }
        $artifactReads[[string]$descriptor.path] = $artifactRead
    }

    $receiptRead = $artifactReads[
        "source-fixtures/$checkId.receipt.json"]
    if (($receiptRead.Value | ConvertTo-Json -Depth 40 -Compress) -cne
        ($receipt | ConvertTo-Json -Depth 40 -Compress)) {
        throw "The embedded signer source-fixture receipt differs from retained bytes."
    }
    $indexRead = $artifactReads['source-fixtures/index.json']
    $index = $indexRead.Value
    Assert-SteinPackageJsonShape -Value $index `
        -Description "The signer source-fixture suite index" `
        -ExpectedProperties @(
            'schema_version', 'suite_id', 'result', 'candidate_git_commit',
            'candidate_git_tree', 'registry_sha256', 'git', 'rustup', 'receipts')
    Assert-SteinPackageJsonShape -Value $index.git `
        -Description "The signer source-fixture suite Git binding" `
        -ExpectedProperties @(
            'launcher_version', 'launcher_sha256', 'resolved_version',
            'resolved_sha256')
    Assert-SteinPackageJsonShape -Value $index.rustup `
        -Description "The signer source-fixture suite rustup binding" `
        -ExpectedProperties @('version', 'sha256', 'toolchain')
    if ([long]$index.schema_version -ne 1 -or
        [string]$index.suite_id -cne 'stein.phase2.source-fixture-suite.v1' -or
        [string]$index.result -cne 'pass' -or
        [string]$index.candidate_git_commit -cne $ExpectedCandidateGitCommit -or
        [string]$index.candidate_git_tree -cne $ExpectedCandidateGitTree -or
        [string]$index.registry_sha256 -cne
            [string]$FixtureContract.RegistrySha256 -or
        [string]$index.git.launcher_version -cne
            [string]$receipt.bindings.git_launcher_version -or
        [string]$index.git.launcher_sha256 -cne
            [string]$receipt.bindings.git_launcher_sha256 -or
        [string]$index.git.resolved_version -cne
            [string]$receipt.bindings.git_resolved_version -or
        [string]$index.git.resolved_sha256 -cne
            [string]$receipt.bindings.git_resolved_sha256 -or
        [string]$index.rustup.version -cne
            [string]$receipt.bindings.rustup_version -or
        [string]$index.rustup.sha256 -cne
            [string]$receipt.bindings.rustup_sha256 -or
        [string]$index.rustup.toolchain -cne
            [string]$receipt.bindings.rustup_toolchain) {
        throw "The signer source-fixture suite index binding is invalid."
    }
    $indexReceipts = @($index.receipts)
    if ($indexReceipts.Count -ne @($FixtureContract.CheckIds).Count) {
        throw "The signer source-fixture suite index is incomplete."
    }
    $matchingDescriptors = @($indexReceipts | Where-Object {
            [string]$_.source_check_id -ceq $checkId
        })
    if ($matchingDescriptors.Count -ne 1) {
        throw "The signer source-fixture suite index omits a receipt."
    }
    $indexDescriptor = $matchingDescriptors[0]
    Assert-SteinPackageJsonShape -Value $indexDescriptor `
        -Description "A signer source-fixture suite receipt descriptor" `
        -ExpectedProperties @(
            'source_check_id', 'source_fixture_id', 'source_runner_id', 'gate_id',
            'gate_fixture_id', 'gate_runner_id', 'path', 'size', 'sha256')
    if ([string]$indexDescriptor.source_fixture_id -cne
            [string]$Fixture.source_fixture_id -or
        [string]$indexDescriptor.source_runner_id -cne
            [string]$Fixture.source_runner_id -or
        [string]$indexDescriptor.gate_id -cne [string]$Fixture.gate_id -or
        [string]$indexDescriptor.gate_fixture_id -cne
            [string]$Fixture.gate_fixture_id -or
        [string]$indexDescriptor.gate_runner_id -cne
            [string]$Fixture.gate_runner_id -or
        [string]$indexDescriptor.path -cne "$checkId.receipt.json" -or
        [long]$indexDescriptor.size -ne
            [long]$Check.source_fixture_receipt_artifact.size -or
        [string]$indexDescriptor.sha256 -cne
            [string]$Check.source_fixture_receipt_artifact.sha256) {
        throw "A signer source-fixture suite receipt descriptor is invalid."
    }
    return $true
}

function Assert-SteinPackageSourceReportCheckContract {
    param(
        [Parameter(Mandatory = $true)] $Checks,
        [Parameter(Mandatory = $true)] $Contract,
        [Parameter(Mandatory = $true)] $FixtureContract,
        [Parameter(Mandatory = $true)] $SourceReport,
        [Parameter(Mandatory = $true)] $EvidenceSpecification,
        [string] $CandidateRoot,
        $CandidateSnapshot,
        $CandidateTreeBinding,
        [Parameter(Mandatory = $true)][bool] $RequireCandidateGrounding,
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $ReportDirectory,
        [Parameter(Mandatory = $true)][string] $ExpectedCandidateGitCommit,
        [Parameter(Mandatory = $true)][string] $ExpectedCandidateGitTree
    )

    Assert-SteinPackageJsonShape -Value $Contract `
        -Description "The signer source-report check contract" `
        -ExpectedProperties @(
            "source_fixture_registry_sha256", "required_pass_check_ids",
            "allowed_not_run_check_ids", "required_generator_paths")
    if ([string]$Contract.source_fixture_registry_sha256 -cne
        [string]$FixtureContract.RegistrySha256) {
        throw "The signer source-report contract has an invalid fixture-registry binding."
    }
    $requiredIds = @($Contract.required_pass_check_ids)
    $allowedNotRunIds = @($Contract.allowed_not_run_check_ids)
    if ($requiredIds.Count -le 0 -or
        $requiredIds.Count -gt 128 -or
        $allowedNotRunIds.Count -gt 64) {
        throw "The signer source-report check contract is outside its bound."
    }
    $requiredSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $allowedNotRunSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($entry in @(
            @($requiredIds | ForEach-Object {
                    [pscustomobject]@{ Id = $_; Set = $requiredSet }
                }) +
            @($allowedNotRunIds | ForEach-Object {
                    [pscustomobject]@{ Id = $_; Set = $allowedNotRunSet }
                }))) {
        $id = [string]$entry.Id
        if ($id -cnotmatch "^[a-z][a-z0-9-]{2,95}$" -or
            -not $entry.Set.Add($id)) {
            throw "The signer source-report check contract contains an invalid identifier."
        }
    }
    foreach ($id in $requiredSet) {
        if ($allowedNotRunSet.Contains($id)) {
            throw "The signer source-report check contract overlaps status classes."
        }
    }

    $checkArray = @($Checks)
    if ($checkArray.Count -ne ($requiredSet.Count + $allowedNotRunSet.Count)) {
        throw "The source-verification report omits or adds a signer check."
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $fixtureSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($fixtureCheckId in @($FixtureContract.CheckIds)) {
        if (-not $fixtureSet.Add([string]$fixtureCheckId)) {
            throw "The signer source-fixture check set contains a duplicate."
        }
    }
    foreach ($check in $checkArray) {
        if ($null -eq $check -or
            $null -eq $check.PSObject.Properties["id"] -or
            $null -eq $check.PSObject.Properties["status"]) {
            throw "The source-verification check set is invalid."
        }
        $id = [string]$check.id
        $status = [string]$check.status
        if ($id -cnotmatch "^[a-z][a-z0-9-]{2,95}$" -or
            -not $seen.Add($id) -or
            (-not $requiredSet.Contains($id) -and
                -not $allowedNotRunSet.Contains($id)) -or
            ($requiredSet.Contains($id) -and $status -cne "pass") -or
            ($allowedNotRunSet.Contains($id) -and $status -cne "not_run")) {
            throw "The source-verification report violates the signer check contract."
        }
        if ($id -ceq "source-provenance-stability") {
            Assert-SteinPackageJsonShape -Value $check `
                -Description "The source provenance stability check" `
                -ExpectedProperties @(
                    "id", "status", "initial_provenance_sha256",
                    "completed_provenance_sha256", "failure_summary")
            if (-not (Test-SteinPackageSha256Value `
                    -Value ([string]$check.initial_provenance_sha256)) -or
                [string]$check.completed_provenance_sha256 -cne
                    [string]$check.initial_provenance_sha256 -or
                $null -ne $check.failure_summary) {
                throw "The source provenance stability check is invalid."
            }
            continue
        }
        if ($status -ceq "not_run") {
            Assert-SteinPackageJsonShape -Value $check `
                -Description "A source-verification not-run check" `
                -ExpectedProperties @("id", "status", "reason")
            $expectedNotRunReasons = [ordered]@{
                "native-toolchain-provenance" = "Authenticated Rust/rustup/Git/VS/MSVC/Windows SDK/package-tool payload, runtime, sysroot, library, and linker provenance is not implemented."
                "no-leaks-producer-workflow" = "Candidate-owned installed artifact producer is not implemented."
                "pinned-clean-build-environment" = "Authenticated immutable candidate input and fresh dependency, build, and output isolation are not implemented for every source check."
                "portable-runner-attestation" = "Authenticated GitHub artifact attestation tied to repository, workflow, commit, and artifact digest is not implemented."
                "source-report-command-provenance" = "Independent closed command/argument/working-directory provenance for every source-report check is not implemented."
                "windows-native-ignored-fixtures" = "Requires explicit native-fixture workflow support; interactive native fixtures remain unimplemented source evidence."
            }
            $reason = [string]$check.reason
            if (-not $expectedNotRunReasons.Contains($id) -or
                $reason -cne [string]$expectedNotRunReasons[$id]) {
                throw "A source-verification not-run reason is invalid."
            }
            continue
        }

        $expectedPassingProperties = @(
            "id", "status", "executable", "arguments", "working_directory",
            "started_at", "completed_at", "duration_ms", "exit_code",
            "failure_summary", "stdout", "stderr")
        $isFixtureCheck = $fixtureSet.Contains($id)
        if ($isFixtureCheck) {
            $expectedPassingProperties += @(
                "source_fixture_receipt", "source_fixture_receipt_artifact",
                "source_fixture_suite_index")
        }
        Assert-SteinPackageJsonShape -Value $check `
            -Description "A source-verification passing process check" `
            -ExpectedProperties $expectedPassingProperties
        if (($check.exit_code -isnot [int] -and
                $check.exit_code -isnot [long]) -or
            [long]$check.exit_code -ne 0 -or
            ($check.duration_ms -isnot [int] -and
                $check.duration_ms -isnot [long]) -or
            [long]$check.duration_ms -lt 0 -or
            $null -ne $check.failure_summary -or
            [string]::IsNullOrWhiteSpace([string]$check.executable) -or
            [string]$check.executable -ne
                [IO.Path]::GetFileName([string]$check.executable) -or
            $null -eq $check.arguments) {
            throw "A source-verification passing process check is invalid."
        }
        $null = ConvertTo-SteinPackageCanonicalSourceTimestamp `
            -Value $check.started_at
        $null = ConvertTo-SteinPackageCanonicalSourceTimestamp `
            -Value $check.completed_at
        $logPaths = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        foreach ($logProperty in @("stdout", "stderr")) {
            $log = $check.$logProperty
            if ($null -eq $log) {
                throw "A source-verification passing process log is missing."
            }
            Assert-SteinPackageJsonShape -Value $log `
                -Description "A source-verification process log" `
                -ExpectedProperties @("path", "size", "sha256")
            $logRelativePath = [string]$log.path
            if (-not (Test-SteinPackageSafeWindowsRelativePath `
                    -Value $logRelativePath) -or
                ($log.size -isnot [int] -and $log.size -isnot [long]) -or
                [long]$log.size -lt 0 -or
                -not (Test-SteinPackageSha256Value -Value ([string]$log.sha256)) -or
                -not $logPaths.Add($logRelativePath)) {
                throw "A source-verification process log is invalid."
            }
            $logPath = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot (
                        $logRelativePath.Replace(
                            '/',
                            [IO.Path]::DirectorySeparatorChar))))
            if (-not [string]::Equals(
                    (Split-Path -Parent $logPath),
                    $ReportDirectory,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "A source-verification process log escaped its report directory."
            }
            $logPath = Resolve-SteinPackageRegularFileUnderRoot `
                -Root $ReportDirectory `
                -Path $logPath `
                -AllowEmpty
            $logItem = Get-Item -LiteralPath $logPath -Force -ErrorAction Stop
            if ($logItem.Length -ne [long]$log.size -or
                (Get-SteinPackageFileSha256 -Path $logPath) -cne
                    [string]$log.sha256) {
                throw "A source-verification process log differs from its report record."
            }
        }
        if ($isFixtureCheck) {
            $null = Assert-SteinPackageSourceFixtureCheckContract `
                -Check $check `
                -Fixture $FixtureContract.FixturesByCheckId[$id] `
                -FixtureContract $FixtureContract `
                -SourceReport $SourceReport `
                -EvidenceSpecification $EvidenceSpecification `
                -CandidateRoot $CandidateRoot `
                -CandidateSnapshot $CandidateSnapshot `
                -CandidateTreeBinding $CandidateTreeBinding `
                -RequireCandidateGrounding $RequireCandidateGrounding `
                -ExpectedCandidateGitCommit $ExpectedCandidateGitCommit `
                -ExpectedCandidateGitTree $ExpectedCandidateGitTree `
                -ReportDirectory $ReportDirectory
        }
    }
    return [pscustomobject]@{
        RequiredPassCount = $requiredSet.Count
        AllowedNotRunCount = $allowedNotRunSet.Count
        ExactCheckCount = $seen.Count
    }
}

function Get-SteinVerifiedSourceBuildBinding {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $SourceVerificationReportPath,
        [Parameter(Mandatory = $true)][string] $SourceRootAnchorPath,
        [Parameter(Mandatory = $true)][string] $ExpectedSourceVerificationSha256,
        [Parameter(Mandatory = $true)][string] $ExpectedSourceRootAnchorSha256,
        [Parameter(Mandatory = $true)][string] $ExpectedCandidateGitCommit,
        [Parameter(Mandatory = $true)][string] $ExpectedCandidateGitTree,
        [string] $CandidateRoot,
        $CandidateSnapshot,
        [switch] $BootstrapOnly
    )

    if (-not (Test-SteinPackageSha256Value -Value $ExpectedSourceVerificationSha256) -or
        -not (Test-SteinPackageSha256Value -Value $ExpectedSourceRootAnchorSha256) -or
        -not (Test-SteinPackageGitObjectId -Value $ExpectedCandidateGitCommit) -or
        -not (Test-SteinPackageGitObjectId -Value $ExpectedCandidateGitTree) -or
        $ExpectedCandidateGitCommit.Length -ne $ExpectedCandidateGitTree.Length) {
        throw "The pinned candidate or source-evidence digest is invalid."
    }

    $repositoryPath = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path $RepositoryRoot
    $requireCandidateGrounding = -not $BootstrapOnly
    if ($BootstrapOnly) {
        if (-not [string]::IsNullOrWhiteSpace($CandidateRoot) -or
            $null -ne $CandidateSnapshot) {
            throw "A bootstrap-only source binding cannot claim a candidate snapshot."
        }
        $CandidateRoot = $repositoryPath
    }
    elseif ([string]::IsNullOrWhiteSpace($CandidateRoot) -or
        $null -eq $CandidateSnapshot) {
        throw "An authoritative source binding requires the locked candidate snapshot."
    }
    $candidatePath = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path $CandidateRoot
    $candidateTreeBinding = $null
    if ($requireCandidateGrounding) {
        $snapshotPath = Resolve-SteinPackageRegularDirectoryWithAncestors `
            -Path ([string]$CandidateSnapshot.Root)
        if (-not [string]::Equals(
                $candidatePath,
                $snapshotPath,
                [StringComparison]::OrdinalIgnoreCase) -or
            [string]$CandidateSnapshot.Commit -cne $ExpectedCandidateGitCommit -or
            [string]$CandidateSnapshot.Tree -cne $ExpectedCandidateGitTree) {
            throw "The authoritative candidate snapshot identity is invalid."
        }
        $candidateTreeBinding = Get-SteinPackageSourceFixtureTreeBinding `
            -Snapshot $CandidateSnapshot
    }
    $evidenceRoot = Join-Path $repositoryPath "artifacts\evidence\phase-2"
    $repositoryItem = Get-Item -LiteralPath $repositoryPath -Force -ErrorAction Stop
    if (-not $repositoryItem.PSIsContainer -or
        (($repositoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "The source-evidence repository root is invalid."
    }
    $evidenceProbe = $evidenceRoot
    while ($evidenceProbe.Length -ge $repositoryPath.Length) {
        $evidenceDirectory = Get-Item -LiteralPath $evidenceProbe -Force -ErrorAction Stop
        if (-not $evidenceDirectory.PSIsContainer -or
            (($evidenceDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "The source-evidence directory has an invalid ancestor."
        }
        if ([string]::Equals(
                $evidenceProbe,
                $repositoryPath,
                [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $evidenceProbe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $evidenceProbe) {
            throw "The source-evidence directory escaped the repository."
        }
        $evidenceProbe = $parent
    }
    $reportPath = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $evidenceRoot `
        -Path $SourceVerificationReportPath
    $anchorPath = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $evidenceRoot `
        -Path $SourceRootAnchorPath
    if ((Split-Path -Leaf $reportPath) -cne "source-verification.json" -or
        (Split-Path -Leaf $anchorPath) -cne "root-anchor.json" -or
        -not [string]::Equals(
            (Split-Path -Parent $reportPath),
            (Split-Path -Parent $anchorPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "The source report and root anchor are not one exact evidence pair."
    }

    $reportFile = Read-SteinPackageLockedJson -Path $reportPath -MaximumBytes 16777216
    $anchorFile = Read-SteinPackageLockedJson -Path $anchorPath -MaximumBytes 65536
    if ($reportFile.Sha256 -cne $ExpectedSourceVerificationSha256 -or
        $anchorFile.Sha256 -cne $ExpectedSourceRootAnchorSha256) {
        throw "A source-evidence file differs from its operator-pinned digest."
    }

    $evidenceSpecPath = Resolve-SteinPackageRegularFileUnderRoot `
        -Root $candidatePath `
        -Path (Join-Path $candidatePath "scripts\windows\phase2\Evidence-Spec.json")
    $evidenceSpecFile = Read-SteinPackageLockedJson `
        -Path $evidenceSpecPath `
        -MaximumBytes 1048576
    $evidenceSpec = $evidenceSpecFile.Value
    if (($evidenceSpec.schema_version -isnot [int] -and
            $evidenceSpec.schema_version -isnot [long]) -or
        [long]$evidenceSpec.schema_version -ne 1 -or
        [string]$evidenceSpec.contract_id -cne "stein-phase2-gate-evidence-v1" -or
        $null -eq $evidenceSpec.PSObject.Properties["source_report_contract"]) {
        throw "The checked-in signer source-report contract is invalid."
    }

    $report = $reportFile.Value
    Assert-SteinPackageJsonShape -Value $report -Description "The source-verification report" `
        -ExpectedProperties @(
            "schema_version", "claim", "installed_or_signed_evidence", "passed",
            "complete_acceptance", "started_at", "completed_at", "host", "provenance",
            "integrity", "checks", "summary")
    Assert-SteinPackageJsonShape -Value $report.provenance `
        -Description "The source-verification provenance" `
        -ExpectedProperties @(
            "schema_version", "classification", "repository", "toolchain", "build_versions",
            "contract_versions", "dependency_locks")
    Assert-SteinPackageJsonShape -Value $report.provenance.repository `
        -Description "The source-verification repository state" `
        -ExpectedProperties @(
            "head_commit", "object_format", "clean", "has_staged_changes",
            "has_unstaged_changes", "tracked_changed_path_count", "untracked_path_count",
            "porcelain_status_sha256", "raw_diff_sha256", "tracked_manifest_sha256",
            "untracked_manifest_sha256", "state_sha256")
    Assert-SteinPackageJsonShape -Value $report.provenance.toolchain `
        -Description "The source-verification toolchain" `
        -ExpectedProperties @("cargo", "rustc", "rustup", "node", "pnpm", "git", "pwsh")
    Assert-SteinPackageJsonShape -Value $report.integrity `
        -Description "The source-verification integrity record" `
        -ExpectedProperties @(
            "semantics", "generator", "provenance_sha256", "checks_sha256",
            "root_anchor_path")
    Assert-SteinPackageJsonShape -Value $report.integrity.generator `
        -Description "The source-verification generator" `
        -ExpectedProperties @("schema_version", "files", "digest_sha256")
    Assert-SteinPackageJsonShape -Value $report.summary `
        -Description "The source-verification summary" `
        -ExpectedProperties @("pass", "fail", "not_run")

    $requiredGeneratorPaths = @(
        $evidenceSpec.source_report_contract.required_generator_paths)
    $generatorFiles = @($report.integrity.generator.files)
    if ($requiredGeneratorPaths.Count -le 0 -or
        $requiredGeneratorPaths.Count -gt 64 -or
        $generatorFiles.Count -ne $requiredGeneratorPaths.Count) {
        throw "The source-verification generator set is incomplete."
    }
    $generatorPathSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $normalizedGeneratorFiles = New-Object Collections.Generic.List[object]
    for ($generatorIndex = 0;
        $generatorIndex -lt $requiredGeneratorPaths.Count;
        $generatorIndex++) {
        $requiredGeneratorPath = [string]$requiredGeneratorPaths[$generatorIndex]
        $generatorFile = $generatorFiles[$generatorIndex]
        Assert-SteinPackageJsonShape -Value $generatorFile `
            -Description "A source-verification generator file" `
            -ExpectedProperties @("path", "size", "sha256")
        if ($requiredGeneratorPath -cnotmatch
                "^(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$" -or
            -not $generatorPathSet.Add($requiredGeneratorPath) -or
            [string]$generatorFile.path -cne $requiredGeneratorPath -or
            ($generatorFile.size -isnot [int] -and
                $generatorFile.size -isnot [long]) -or
            [long]$generatorFile.size -le 0 -or
            -not (Test-SteinPackageSha256Value -Value ([string]$generatorFile.sha256))) {
            throw "A source-verification generator file record is invalid."
        }
        $candidateGeneratorPath = Resolve-SteinPackageRegularFileUnderRoot `
            -Root $candidatePath `
            -Path (Join-Path $candidatePath $requiredGeneratorPath.Replace(
                    "/",
                    [IO.Path]::DirectorySeparatorChar))
        $candidateGeneratorItem = Get-Item `
            -LiteralPath $candidateGeneratorPath `
            -Force `
            -ErrorAction Stop
        if ([long]$candidateGeneratorItem.Length -ne [long]$generatorFile.size -or
            (Get-SteinPackageFileSha256 -Path $candidateGeneratorPath) -cne
                [string]$generatorFile.sha256) {
            throw "The signer source-verification generator differs from candidate bytes."
        }
        if ($requiredGeneratorPath -ceq
                "scripts/windows/phase2/Evidence-Contract.ps1" -and
            [string]$generatorFile.sha256 -cne
                [string]$script:SteinPackageEvidenceContractSha256) {
            throw "The executing signer evidence contract differs from candidate bytes."
        }
        $normalizedGeneratorFiles.Add([ordered]@{
                path = $requiredGeneratorPath
                size = [long]$generatorFile.size
                sha256 = [string]$generatorFile.sha256
            })
    }
    $computedGeneratorDigest = Get-SteinPackageTextSha256 `
        -Value ($normalizedGeneratorFiles.ToArray() |
            ConvertTo-Json -Depth 16 -Compress)
    if ($computedGeneratorDigest -cne
        [string]$report.integrity.generator.digest_sha256) {
        throw "The source-verification generator digest is invalid."
    }
    $fixtureContract = Get-SteinPackageSourceFixtureRegistryContract `
        -CandidateRoot $candidatePath `
        -EvidenceSpecification $evidenceSpec

    $requiredDependencyLocks = @(
        "Cargo.lock",
        "apps/desktop/pnpm-lock.yaml",
        "extensions/edge/pnpm-lock.yaml",
        "apps/edge-native-host/Cargo.lock")
    $dependencyLocks = @($report.provenance.dependency_locks)
    if ($dependencyLocks.Count -ne $requiredDependencyLocks.Count) {
        throw "The source-verification dependency-lock set is incomplete."
    }
    for ($lockIndex = 0;
        $lockIndex -lt $requiredDependencyLocks.Count;
        $lockIndex++) {
        $lockRecord = $dependencyLocks[$lockIndex]
        $requiredLockPath = $requiredDependencyLocks[$lockIndex]
        Assert-SteinPackageJsonShape -Value $lockRecord `
            -Description "A source-verification dependency lock" `
            -ExpectedProperties @("path", "size", "sha256")
        if ([string]$lockRecord.path -cne $requiredLockPath -or
            ($lockRecord.size -isnot [int] -and $lockRecord.size -isnot [long]) -or
            [long]$lockRecord.size -le 0 -or
            -not (Test-SteinPackageSha256Value -Value ([string]$lockRecord.sha256))) {
            throw "A source-verification dependency-lock record is invalid."
        }
        $lockPath = Resolve-SteinPackageRegularFileUnderRoot `
            -Root $candidatePath `
            -Path (Join-Path $candidatePath (
                    $requiredLockPath.Replace(
                        '/',
                        [IO.Path]::DirectorySeparatorChar)))
        $lockItem = Get-Item -LiteralPath $lockPath -Force -ErrorAction Stop
        if ($lockItem.Length -ne [long]$lockRecord.size -or
            (Get-SteinPackageFileSha256 -Path $lockPath) -cne
                [string]$lockRecord.sha256) {
            throw "A verified dependency lock differs from the exact candidate."
        }
    }

    $repository = $report.provenance.repository
    $expectedObjectFormat = if ($ExpectedCandidateGitCommit.Length -eq 40) { "sha1" } else { "sha256" }
    if (($report.schema_version -isnot [int] -and
            $report.schema_version -isnot [long]) -or
        [long]$report.schema_version -ne 2 -or
        [string]$report.claim -cne "source_verification_only" -or
        $report.installed_or_signed_evidence -isnot [bool] -or
        [bool]$report.installed_or_signed_evidence -or
        $report.passed -isnot [bool] -or
        -not [bool]$report.passed -or
        $report.complete_acceptance -isnot [bool] -or
        [bool]$report.complete_acceptance -or
        ($report.provenance.schema_version -isnot [int] -and
            $report.provenance.schema_version -isnot [long]) -or
        [long]$report.provenance.schema_version -ne 2 -or
        [string]$report.provenance.classification -cne "bounded_content_free_source_provenance" -or
        [string]$repository.head_commit -cne $ExpectedCandidateGitCommit -or
        [string]$repository.object_format -cne $expectedObjectFormat -or
        $repository.clean -isnot [bool] -or
        -not [bool]$repository.clean -or
        $repository.has_staged_changes -isnot [bool] -or
        [bool]$repository.has_staged_changes -or
        $repository.has_unstaged_changes -isnot [bool] -or
        [bool]$repository.has_unstaged_changes -or
        ($repository.tracked_changed_path_count -isnot [int] -and
            $repository.tracked_changed_path_count -isnot [long]) -or
        [long]$repository.tracked_changed_path_count -ne 0 -or
        ($repository.untracked_path_count -isnot [int] -and
            $repository.untracked_path_count -isnot [long]) -or
        [long]$repository.untracked_path_count -ne 0 -or
        ($report.integrity.generator.schema_version -isnot [int] -and
            $report.integrity.generator.schema_version -isnot [long]) -or
        [long]$report.integrity.generator.schema_version -ne 1 -or
        [string]$report.integrity.semantics -cne "content_integrity_only_not_authentication" -or
        [string]$report.integrity.root_anchor_path -cne "root-anchor.json") {
        throw "The source-verification report is not a passing clean candidate record."
    }

    foreach ($summaryProperty in @("pass", "fail", "not_run")) {
        $summaryValue = $report.summary.$summaryProperty
        if (($summaryValue -isnot [int] -and $summaryValue -isnot [long]) -or
            [long]$summaryValue -lt 0) {
            throw "The source-verification summary contains an invalid count."
        }
    }

    $checks = @($report.checks)
    $null = Assert-SteinPackageSourceReportCheckContract `
        -Checks $checks `
        -Contract $evidenceSpec.source_report_contract `
        -FixtureContract $fixtureContract `
        -SourceReport $report `
        -EvidenceSpecification $evidenceSpec `
        -CandidateRoot $candidatePath `
        -CandidateSnapshot $CandidateSnapshot `
        -CandidateTreeBinding $candidateTreeBinding `
        -RequireCandidateGrounding $requireCandidateGrounding `
        -RepositoryRoot $repositoryPath `
        -ReportDirectory (Split-Path -Parent $reportPath) `
        -ExpectedCandidateGitCommit $ExpectedCandidateGitCommit `
        -ExpectedCandidateGitTree $ExpectedCandidateGitTree
    $computedProvenanceDigest = Get-SteinPackageTextSha256 `
        -Value ($report.provenance | ConvertTo-Json -Depth 16 -Compress)
    $computedChecksDigest = Get-SteinPackageCanonicalSourceChecksDigest `
        -Checks $checks `
        -FixtureCheckIds @($fixtureContract.CheckIds)
    if ($computedProvenanceDigest -cne
        [string]$report.integrity.provenance_sha256) {
        throw "The source-verification provenance digest is inconsistent."
    }
    if ($computedChecksDigest -cne [string]$report.integrity.checks_sha256) {
        throw "The source-verification checks digest is inconsistent."
    }
    $passCount = @($checks | Where-Object { [string]$_.status -ceq "pass" }).Count
    $failCount = @($checks | Where-Object { [string]$_.status -ceq "fail" }).Count
    $notRunCount = @($checks | Where-Object { [string]$_.status -ceq "not_run" }).Count
    $stability = @($checks | Where-Object {
            [string]$_.id -ceq "source-provenance-stability"
        })
    if ($checks.Count -le 0 -or
        $failCount -ne 0 -or
        $passCount -ne [int]$report.summary.pass -or
        $failCount -ne [int]$report.summary.fail -or
        $notRunCount -ne [int]$report.summary.not_run -or
        $stability.Count -ne 1 -or
        [string]$stability[0].status -cne "pass" -or
        [string]$stability[0].initial_provenance_sha256 -cne
            [string]$report.integrity.provenance_sha256 -or
        [string]$stability[0].completed_provenance_sha256 -cne
            [string]$report.integrity.provenance_sha256 -or
        $null -ne $stability[0].failure_summary) {
        throw "The source-verification check set is not a stable passing run."
    }

    $toolchain = $report.provenance.toolchain
    foreach ($rustToolName in @("cargo", "rustc")) {
        Assert-SteinPackageJsonShape -Value $toolchain.$rustToolName `
            -Description "A rustup-selected source toolchain record" `
            -ExpectedProperties @(
                "version", "executable_sha256", "rustup_toolchain",
                "resolved_version", "resolved_executable_sha256")
        $rustTool = $toolchain.$rustToolName
        if ([string]::IsNullOrWhiteSpace([string]$rustTool.version) -or
            [string]$rustTool.resolved_version -cne [string]$rustTool.version -or
            [string]$rustTool.rustup_toolchain -cnotmatch
                "^[0-9A-Za-z][0-9A-Za-z._-]{2,127}$") {
            throw "A rustup-selected source toolchain record is invalid."
        }
    }
    foreach ($basicToolName in @("rustup", "node")) {
        Assert-SteinPackageJsonShape -Value $toolchain.$basicToolName `
            -Description "A source toolchain record" `
            -ExpectedProperties @("version", "executable_sha256")
        if ([string]::IsNullOrWhiteSpace([string]$toolchain.$basicToolName.version)) {
            throw "A source toolchain version is invalid."
        }
    }
    Assert-SteinPackageJsonShape -Value $toolchain.pnpm `
        -Description "The resolved pnpm source toolchain record" `
        -ExpectedProperties @(
            "version", "executable_sha256", "resolved_entrypoint_sha256")
    Assert-SteinPackageJsonShape -Value $toolchain.pwsh `
        -Description "The source-verification PowerShell record" `
        -ExpectedProperties @(
            "version", "executable_sha256", "authenticode_status", "signer_subject")
    Assert-SteinPackageJsonShape -Value $toolchain.git `
        -Description "The resolved Git source toolchain record" `
        -ExpectedProperties @(
            "version", "executable_sha256", "resolved_version",
            "resolved_executable_sha256")
    if ([string]$toolchain.cargo.rustup_toolchain -cne
            [string]$toolchain.rustc.rustup_toolchain -or
        [string]::IsNullOrWhiteSpace([string]$toolchain.git.version) -or
        [string]$toolchain.git.resolved_version -cne
            [string]$toolchain.git.version -or
        [string]::IsNullOrWhiteSpace([string]$toolchain.pnpm.version) -or
        [string]$toolchain.pwsh.authenticode_status -cne "valid" -or
        [string]::IsNullOrWhiteSpace([string]$toolchain.pwsh.signer_subject)) {
        throw "The source-verification toolchain record is invalid."
    }

    foreach ($digest in @(
            [string]$report.integrity.generator.digest_sha256,
            [string]$report.integrity.provenance_sha256,
            [string]$report.integrity.checks_sha256,
            [string]$toolchain.git.executable_sha256,
            [string]$toolchain.git.resolved_executable_sha256,
            [string]$toolchain.cargo.executable_sha256,
            [string]$toolchain.cargo.resolved_executable_sha256,
            [string]$toolchain.rustc.executable_sha256,
            [string]$toolchain.rustc.resolved_executable_sha256,
            [string]$toolchain.rustup.executable_sha256,
            [string]$toolchain.node.executable_sha256,
            [string]$toolchain.pnpm.executable_sha256,
            [string]$toolchain.pnpm.resolved_entrypoint_sha256,
            [string]$toolchain.pwsh.executable_sha256)) {
        if (-not (Test-SteinPackageSha256Value -Value $digest)) {
            throw "The source-verification report contains an invalid chain digest."
        }
    }

    $anchor = $anchorFile.Value
    Assert-SteinPackageJsonShape -Value $anchor -Description "The source root anchor" `
        -ExpectedProperties @(
            "schema_version", "claim", "integrity_semantics", "source_verification",
            "generator_sha256", "provenance_sha256", "checks_sha256", "root_digest_sha256")
    Assert-SteinPackageJsonShape -Value $anchor.source_verification `
        -Description "The anchored source-verification file" `
        -ExpectedProperties @("path", "size", "sha256")
    if (($anchor.schema_version -isnot [int] -and
            $anchor.schema_version -isnot [long]) -or
        [long]$anchor.schema_version -ne 1 -or
        [string]$anchor.claim -cne "source_verification_only" -or
        [string]$anchor.integrity_semantics -cne "content_integrity_only_not_authentication" -or
        [string]$anchor.source_verification.path -cne "source-verification.json" -or
        ($anchor.source_verification.size -isnot [int] -and
            $anchor.source_verification.size -isnot [long]) -or
        [long]$anchor.source_verification.size -ne $reportFile.Size -or
        [string]$anchor.source_verification.sha256 -cne $reportFile.Sha256 -or
        [string]$anchor.generator_sha256 -cne [string]$report.integrity.generator.digest_sha256 -or
        [string]$anchor.provenance_sha256 -cne [string]$report.integrity.provenance_sha256 -or
        [string]$anchor.checks_sha256 -cne [string]$report.integrity.checks_sha256 -or
        -not (Test-SteinPackageSha256Value -Value ([string]$anchor.root_digest_sha256))) {
        throw "The source root anchor does not bind the exact passing report."
    }

    $rootMaterial = @(
        "stein-phase2-source-evidence-root-v1",
        "source_verification_sha256=$($reportFile.Sha256)",
        "generator_sha256=$([string]$anchor.generator_sha256)",
        "provenance_sha256=$([string]$anchor.provenance_sha256)",
        "checks_sha256=$([string]$anchor.checks_sha256)"
    ) -join "`n"
    if ((Get-SteinPackageTextSha256 -Value $rootMaterial) -cne
        [string]$anchor.root_digest_sha256) {
        throw "The source root digest is invalid."
    }

    return [pscustomobject]@{
        CandidateBindingScope = if ($requireCandidateGrounding) {
            "authoritative_locked_snapshot"
        }
        else { "bootstrap_only" }
        CandidateTreeFileCount = if ($requireCandidateGrounding) {
            [long]$candidateTreeBinding.FileCount
        }
        else { $null }
        CandidateTreeManifestSha256 = if ($requireCandidateGrounding) {
            [string]$candidateTreeBinding.ManifestSha256
        }
        else { $null }
        CandidateGitCommit = $ExpectedCandidateGitCommit
        CandidateGitTree = $ExpectedCandidateGitTree
        SourceVerificationSha256 = $reportFile.Sha256
        SourceRootAnchorSha256 = $anchorFile.Sha256
        SourceRootDigestSha256 = [string]$anchor.root_digest_sha256
        GitVersion = [string]$toolchain.git.version
        GitExecutableSha256 = [string]$toolchain.git.executable_sha256
        GitResolvedExecutableSha256 = [string]$toolchain.git.resolved_executable_sha256
        CargoVersion = [string]$toolchain.cargo.version
        CargoExecutableSha256 = [string]$toolchain.cargo.executable_sha256
        CargoResolvedExecutableSha256 = [string]$toolchain.cargo.resolved_executable_sha256
        RustcVersion = [string]$toolchain.rustc.version
        RustcExecutableSha256 = [string]$toolchain.rustc.executable_sha256
        RustcResolvedExecutableSha256 = [string]$toolchain.rustc.resolved_executable_sha256
        RustupToolchain = [string]$toolchain.cargo.rustup_toolchain
        RustupVersion = [string]$toolchain.rustup.version
        RustupExecutableSha256 = [string]$toolchain.rustup.executable_sha256
        NodeVersion = [string]$toolchain.node.version
        NodeExecutableSha256 = [string]$toolchain.node.executable_sha256
        PnpmVersion = [string]$toolchain.pnpm.version
        PnpmExecutableSha256 = [string]$toolchain.pnpm.executable_sha256
        PnpmResolvedEntrypointSha256 = [string]$toolchain.pnpm.resolved_entrypoint_sha256
    }
}

function Get-SteinCleanGitCandidateState {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $GitExecutable,
        [Parameter(Mandatory = $true)][string] $ExpectedGitExecutableSha256
    )

    $repositoryPath = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path $RepositoryRoot
    $repositoryItem = Get-Item -LiteralPath $repositoryPath -Force -ErrorAction Stop
    if (-not $repositoryItem.PSIsContainer -or
        (($repositoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "The candidate repository root is invalid."
    }
    $gitPath = Resolve-SteinPackageRegularFileWithAncestors -Path $GitExecutable
    if (-not (Test-SteinPackageSha256Value -Value $ExpectedGitExecutableSha256) -or
        (Get-SteinPackageFileSha256 -Path $gitPath) -cne $ExpectedGitExecutableSha256) {
        throw "The Git executable differs from the verified source toolchain."
    }

    $invokeGit = {
        param([string[]] $Arguments)
        $output = @(& $gitPath `
                -c core.fsmonitor=false `
                -c core.untrackedCache=false `
                -C $repositoryPath `
                @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
        $characterCount = [long](($output | ForEach-Object { ([string]$_).Length } |
                    Measure-Object -Sum).Sum)
        if ($exitCode -ne 0 -or $characterCount -gt 1048576) {
            throw "Git could not verify the exact candidate state."
        }
        return @($output | ForEach-Object { [string]$_ })
    }

    $topLevel = @(& $invokeGit @("rev-parse", "--show-toplevel"))
    if ($topLevel.Count -ne 1 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($topLevel[0]).TrimEnd(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar),
            $repositoryPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Git resolved a different repository root."
    }
    $status = @(& $invokeGit @(
            "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"))
    if ($status.Count -ne 0) {
        throw "The candidate repository must be clean before signing."
    }
    $commit = @(& $invokeGit @("rev-parse", "--verify", "HEAD"))
    $tree = @(& $invokeGit @("rev-parse", "--verify", "HEAD^{tree}"))
    if ($commit.Count -ne 1 -or
        $tree.Count -ne 1 -or
        -not (Test-SteinPackageGitObjectId -Value $commit[0]) -or
        -not (Test-SteinPackageGitObjectId -Value $tree[0]) -or
        $commit[0].Length -ne $tree[0].Length) {
        throw "Git returned an invalid candidate commit or tree."
    }
    return [pscustomobject]@{
        Commit = $commit[0]
        Tree = $tree[0]
        GitExecutable = $gitPath
        GitExecutableSha256 = $ExpectedGitExecutableSha256
    }
}

function Publish-SteinVerifiedReleaseArtifactSet {
    param(
        [Parameter(Mandatory = $true)][string] $OutputRoot,
        [Parameter(Mandatory = $true)][object[]] $Entries
    )

    $root = [IO.Path]::GetFullPath($OutputRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $Entries.Count -le 0 -or
        $Entries.Count -gt 16) {
        throw "The release publication root or artifact set is invalid."
    }
    $volumeRoot = [IO.Path]::GetPathRoot($root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $rootProbe = $root
    while (-not [string]::IsNullOrWhiteSpace($rootProbe)) {
        $directory = Get-Item -LiteralPath $rootProbe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "The release publication root has an invalid ancestor."
        }
        if ([string]::Equals(
                $rootProbe.TrimEnd(
                    [IO.Path]::DirectorySeparatorChar,
                    [IO.Path]::AltDirectorySeparatorChar),
                $volumeRoot,
                [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $rootProbe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $rootProbe) {
            throw "The release publication root has no exact filesystem root."
        }
        $rootProbe = $parent
    }

    $seenPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $normalizedEntries = New-Object Collections.Generic.List[object]
    foreach ($suppliedEntry in $Entries) {
        Assert-SteinPackageJsonShape -Value $suppliedEntry `
            -ExpectedProperties @(
                "Temporary", "Final", "Backup", "ExpectedSize", "ExpectedSha256") `
            -Description "A release publication entry"
        $paths = @{}
        foreach ($property in @("Temporary", "Final", "Backup")) {
            $path = [IO.Path]::GetFullPath([string]$suppliedEntry.$property)
            if (-not [string]::Equals(
                    (Split-Path -Parent $path),
                    $root,
                    [StringComparison]::OrdinalIgnoreCase) -or
                -not $seenPaths.Add($path)) {
                throw "A release publication path is outside its exact root or duplicated."
            }
            $paths[$property] = $path
        }

        $expectedSha256 = [string]$suppliedEntry.ExpectedSha256
        $expectedSize = 0L
        if (-not [long]::TryParse(
                [string]$suppliedEntry.ExpectedSize,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$expectedSize) -or
            $expectedSize -le 0 -or
            -not (Test-SteinPackageSha256Value -Value $expectedSha256)) {
            throw "A release publication byte identity is invalid."
        }
        $entry = [pscustomobject]@{
            Temporary = [string]$paths["Temporary"]
            Final = [string]$paths["Final"]
            Backup = [string]$paths["Backup"]
            ExpectedSize = $expectedSize
            ExpectedSha256 = $expectedSha256
        }
        $temporaryItem = Get-Item -LiteralPath $entry.Temporary -Force -ErrorAction Stop
        if ($temporaryItem.PSIsContainer -or
            (($temporaryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $temporaryItem.Length -ne $expectedSize -or
            (Get-SteinPackageFileSha256 -Path $temporaryItem.FullName) -cne
                [string]$entry.ExpectedSha256 -or
            (Test-Path -LiteralPath $entry.Backup)) {
            throw "A temporary release artifact is unsafe to publish."
        }
        if (Test-Path -LiteralPath $entry.Final) {
            $finalItem = Get-Item -LiteralPath $entry.Final -Force -ErrorAction Stop
            if ($finalItem.PSIsContainer -or
                (($finalItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw "An existing release artifact is unsafe to replace."
            }
        }
        $normalizedEntries.Add($entry)
    }
    $Entries = $normalizedEntries.ToArray()

    $backedUpEntries = New-Object Collections.Generic.List[object]
    $publishedEntries = New-Object Collections.Generic.List[object]
    $lockedFinalStreams = New-Object Collections.Generic.List[IO.FileStream]
    try {
        foreach ($entry in $Entries) {
            if (Test-Path -LiteralPath $entry.Final) {
                Move-Item `
                    -LiteralPath $entry.Final `
                    -Destination $entry.Backup `
                    -ErrorAction Stop
                $backedUpEntries.Add($entry)
            }
        }
        foreach ($entry in $Entries) {
            Move-Item `
                -LiteralPath $entry.Temporary `
                -Destination $entry.Final `
                -ErrorAction Stop
            $publishedEntries.Add($entry)
        }
        foreach ($entry in $Entries) {
            $finalItem = Get-Item -LiteralPath $entry.Final -Force -ErrorAction Stop
            if ($finalItem.PSIsContainer -or
                (($finalItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
                $finalItem.Length -ne [long]$entry.ExpectedSize) {
                throw "A published release artifact differs from the verified temporary bytes."
            }
            $stream = [IO.FileStream]::new(
                $finalItem.FullName,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read)
            $lockedFinalStreams.Add($stream)
            $sha256 = [Security.Cryptography.SHA256]::Create()
            try {
                $digest = [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace(
                    "-",
                    "").ToLowerInvariant()
            }
            finally {
                $sha256.Dispose()
            }
            if ($digest -cne [string]$entry.ExpectedSha256) {
                throw "A published release artifact differs from the verified temporary bytes."
            }
        }
    }
    catch {
        foreach ($stream in $lockedFinalStreams) {
            $stream.Dispose()
        }
        $lockedFinalStreams.Clear()
        $rollbackFailed = $false
        for ($index = $publishedEntries.Count - 1; $index -ge 0; $index--) {
            $entry = $publishedEntries[$index]
            if (Test-Path -LiteralPath $entry.Final) {
                try {
                    Remove-Item -LiteralPath $entry.Final -Force -ErrorAction Stop
                }
                catch {
                    $rollbackFailed = $true
                }
            }
        }
        for ($index = $backedUpEntries.Count - 1; $index -ge 0; $index--) {
            $entry = $backedUpEntries[$index]
            if (Test-Path -LiteralPath $entry.Backup) {
                if (Test-Path -LiteralPath $entry.Final) {
                    $rollbackFailed = $true
                    continue
                }
                try {
                    Move-Item `
                        -LiteralPath $entry.Backup `
                        -Destination $entry.Final `
                        -ErrorAction Stop
                }
                catch {
                    $rollbackFailed = $true
                }
            }
        }
        if ($rollbackFailed) {
            throw "Release publication failed; previous bytes remain in explicit backup paths and require recovery."
        }
        throw
    }

    $backupCleanupFailed = $false
    foreach ($entry in $backedUpEntries) {
        try {
            Remove-Item -LiteralPath $entry.Backup -Force -ErrorAction Stop
        }
        catch {
            $backupCleanupFailed = $true
        }
    }
    foreach ($stream in $lockedFinalStreams) {
        $stream.Dispose()
    }
    if ($backupCleanupFailed) {
        throw "The verified release is published, but old-backup cleanup is incomplete."
    }
    return $true
}

function Test-SteinCoreBindingContract {
    param(
        [Parameter(Mandatory = $true)]
        [string] $BindingPath,
        [Parameter(Mandatory = $true)]
        [string] $ExpectedCoreSha256,
        [Parameter(Mandatory = $true)]
        [long] $ExpectedCliSize,
        [Parameter(Mandatory = $true)]
        [string] $ExpectedCliSha256,
        [Parameter(Mandatory = $true)]
        [long] $ExpectedDesktopSize,
        [Parameter(Mandatory = $true)]
        [string] $ExpectedDesktopSha256,
        [Parameter(Mandatory = $true)]
        [int] $ExpectedDesktopDistFileCount,
        [Parameter(Mandatory = $true)]
        [string] $ExpectedDesktopDistManifestSha256,
        [Parameter(Mandatory = $true)]
        [string] $ExpectedCandidateGitCommit,
        [Parameter(Mandatory = $true)]
        [string] $ExpectedCandidateGitTree,
        [Parameter(Mandatory = $true)]
        [string] $ExpectedSourceVerificationSha256,
        [Parameter(Mandatory = $true)]
        [string] $ExpectedSourceRootAnchorSha256,
        [Parameter(Mandatory = $true)]
        [string] $ExpectedSourceRootDigestSha256
    )

    foreach ($digest in @(
            $ExpectedCoreSha256,
            $ExpectedCliSha256,
            $ExpectedDesktopSha256,
            $ExpectedDesktopDistManifestSha256,
            $ExpectedSourceVerificationSha256,
            $ExpectedSourceRootAnchorSha256,
            $ExpectedSourceRootDigestSha256)) {
        if (-not (Test-SteinPackageSha256Value -Value $digest)) {
            throw "A signed package binding digest is invalid."
        }
    }
    if (-not (Test-SteinPackageGitObjectId -Value $ExpectedCandidateGitCommit) -or
        -not (Test-SteinPackageGitObjectId -Value $ExpectedCandidateGitTree) -or
        $ExpectedCandidateGitCommit.Length -ne $ExpectedCandidateGitTree.Length) {
        throw "A signed package candidate Git object identifier is invalid."
    }
    if ($ExpectedCliSize -le 0 -or $ExpectedDesktopSize -le 0 -or
        $ExpectedDesktopDistFileCount -le 0 -or
        $ExpectedDesktopDistFileCount -gt 10000) {
        throw "A signed package executable or renderer size is invalid."
    }
    $binding = (Read-SteinPackageLockedJson `
            -Path (Resolve-SteinPackageRegularFileWithAncestors -Path $BindingPath) `
            -MaximumBytes 65536).Value
    $properties = @($binding.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    $expectedProperties = @(
        "schema_version",
        "core_executable_sha256",
        "cli_executable_size",
        "cli_executable_sha256",
        "desktop_executable_size",
        "desktop_executable_sha256",
        "desktop_dist_file_count",
        "desktop_dist_manifest_sha256",
        "candidate_git_commit",
        "candidate_git_tree",
        "source_verification_sha256",
        "source_root_anchor_sha256",
        "source_root_digest_sha256") | Sort-Object
    if ($properties.Count -ne $expectedProperties.Count -or
        @(Compare-Object `
            -ReferenceObject $expectedProperties `
            -DifferenceObject $properties `
            -CaseSensitive).Count -ne 0 -or
        ($binding.schema_version -isnot [int] -and
            $binding.schema_version -isnot [long]) -or
        [long]$binding.schema_version -ne 3 -or
        [string]$binding.core_executable_sha256 -cne $ExpectedCoreSha256 -or
        ($binding.cli_executable_size -isnot [int] -and
            $binding.cli_executable_size -isnot [long]) -or
        [long]$binding.cli_executable_size -ne $ExpectedCliSize -or
        [string]$binding.cli_executable_sha256 -cne $ExpectedCliSha256 -or
        ($binding.desktop_executable_size -isnot [int] -and
            $binding.desktop_executable_size -isnot [long]) -or
        [long]$binding.desktop_executable_size -ne $ExpectedDesktopSize -or
        [string]$binding.desktop_executable_sha256 -cne $ExpectedDesktopSha256 -or
        ($binding.desktop_dist_file_count -isnot [int] -and
            $binding.desktop_dist_file_count -isnot [long]) -or
        [long]$binding.desktop_dist_file_count -ne $ExpectedDesktopDistFileCount -or
        [string]$binding.desktop_dist_manifest_sha256 -cne
            $ExpectedDesktopDistManifestSha256 -or
        [string]$binding.candidate_git_commit -cne $ExpectedCandidateGitCommit -or
        [string]$binding.candidate_git_tree -cne $ExpectedCandidateGitTree -or
        [string]$binding.source_verification_sha256 -cne $ExpectedSourceVerificationSha256 -or
        [string]$binding.source_root_anchor_sha256 -cne $ExpectedSourceRootAnchorSha256 -or
        [string]$binding.source_root_digest_sha256 -cne $ExpectedSourceRootDigestSha256) {
        throw "The signed package binding does not match the broker or source candidate."
    }
    return [pscustomobject]@{
        CoreExecutableSha256 = [string]$binding.core_executable_sha256
        CliExecutableSize = [long]$binding.cli_executable_size
        CliExecutableSha256 = [string]$binding.cli_executable_sha256
        DesktopExecutableSize = [long]$binding.desktop_executable_size
        DesktopExecutableSha256 = [string]$binding.desktop_executable_sha256
        DesktopDistFileCount = [int]$binding.desktop_dist_file_count
        DesktopDistManifestSha256 = [string]$binding.desktop_dist_manifest_sha256
        CandidateGitCommit = [string]$binding.candidate_git_commit
        CandidateGitTree = [string]$binding.candidate_git_tree
        SourceVerificationSha256 = [string]$binding.source_verification_sha256
        SourceRootAnchorSha256 = [string]$binding.source_root_anchor_sha256
        SourceRootDigestSha256 = [string]$binding.source_root_digest_sha256
    }
}

function Get-SteinFixedApplicationPayloadRelativePaths {
    return @(
        "AppxManifest.xml",
        "Assets\Square150x150Logo.png",
        "Assets\Square44x44Logo.png",
        "Assets\StoreLogo.png",
        "Metadata\CoreBinding.json",
        "bin\stein-desktop.exe",
        "bin\stein-edge-native-host.exe",
        "bin\stein-private-broker.exe"
    )
}

function Assert-SteinFixedApplicationPayloadMapsEqual {
    param(
        [Parameter(Mandatory = $true)][object[]] $ExpectedFiles,
        [Parameter(Mandatory = $true)][object[]] $ActualFiles
    )

    $fixedPaths = @(
        Get-SteinFixedApplicationPayloadRelativePaths |
            ForEach-Object { ([string]$_).Replace("\", "/") } |
            Sort-Object
    )
    if ($ExpectedFiles.Count -ne $fixedPaths.Count -or
        $ActualFiles.Count -ne $fixedPaths.Count) {
        throw "A fixed application payload map has an invalid file count."
    }
    $maps = New-Object Collections.Generic.List[object]
    foreach ($records in @($ExpectedFiles, $ActualFiles)) {
        $map = [Collections.Generic.Dictionary[string,object]]::new(
            [StringComparer]::Ordinal)
        foreach ($record in $records) {
            Assert-SteinPackageJsonShape `
                -Value $record `
                -ExpectedProperties @("relative_path", "size", "sha256") `
                -Description "A fixed application payload record"
            $relativePath = ([string]$record.relative_path).Replace("\", "/")
            if ($relativePath -cnotin $fixedPaths -or
                $record.size -isnot [long] -or
                [long]$record.size -le 0 -or
                -not (Test-SteinPackageSha256Value -Value ([string]$record.sha256)) -or
                $map.ContainsKey($relativePath)) {
                throw "A fixed application payload record is invalid."
            }
            $map.Add($relativePath, [pscustomobject]@{
                    Size = [long]$record.size
                    Sha256 = [string]$record.sha256
                })
        }
        $maps.Add($map)
    }
    foreach ($relativePath in $fixedPaths) {
        if (-not $maps[0].ContainsKey($relativePath) -or
            -not $maps[1].ContainsKey($relativePath) -or
            $maps[0][$relativePath].Size -ne $maps[1][$relativePath].Size -or
            $maps[0][$relativePath].Sha256 -cne $maps[1][$relativePath].Sha256) {
            throw "The signed package payload differs from the locked pre-pack staging map."
        }
    }
    return $true
}

function Assert-SteinFixedApplicationPayloadFileIdentity {
    param(
        [Parameter(Mandatory = $true)][object[]] $Files,
        [Parameter(Mandatory = $true)][string] $RelativePath,
        [Parameter(Mandatory = $true)][long] $ExpectedSize,
        [Parameter(Mandatory = $true)][string] $ExpectedSha256
    )

    $canonicalPath = $RelativePath.Replace("\", "/")
    $fixedPaths = @(
        Get-SteinFixedApplicationPayloadRelativePaths |
            ForEach-Object { ([string]$_).Replace("\", "/") })
    if ($canonicalPath -cnotin $fixedPaths -or
        $ExpectedSize -le 0 -or
        -not (Test-SteinPackageSha256Value -Value $ExpectedSha256)) {
        throw "A fixed application payload identity is invalid."
    }
    $matches = @($Files | Where-Object {
            ([string]$_.relative_path).Replace("\", "/") -ceq $canonicalPath
        })
    if ($matches.Count -ne 1) {
        throw "A fixed application payload identity is missing or duplicated."
    }
    Assert-SteinPackageJsonShape `
        -Value $matches[0] `
        -ExpectedProperties @("relative_path", "size", "sha256") `
        -Description "A fixed application payload record"
    if ($matches[0].size -isnot [long] -or
        [long]$matches[0].size -ne $ExpectedSize -or
        [string]$matches[0].sha256 -cne $ExpectedSha256) {
        throw "A staged executable differs from its locked build output identity."
    }
    return $true
}

function New-SteinPackageLockedMakeAppxMapping {
    param(
        [Parameter(Mandatory = $true)] $StagingManifest,
        [Parameter(Mandatory = $true)][string] $MappingPath
    )

    $null = Assert-SteinFixedApplicationPayloadMapsEqual `
        -ExpectedFiles @($StagingManifest.Files) `
        -ActualFiles @($StagingManifest.Files)
    $stagingRoot = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path ([string]$StagingManifest.Root)
    $mappingFullPath = [IO.Path]::GetFullPath($MappingPath)
    $mappingParent = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path (Split-Path -Parent $mappingFullPath)
    if (-not [string]::Equals(
            (Split-Path -Parent $mappingFullPath),
            $mappingParent,
            [StringComparison]::OrdinalIgnoreCase) -or
        (Test-Path -LiteralPath $mappingFullPath)) {
        throw "The closed MakeAppx mapping path is invalid."
    }
    $lines = New-Object Collections.Generic.List[string]
    $lines.Add("[Files]")
    foreach ($relativePath in @(
            Get-SteinFixedApplicationPayloadRelativePaths | Sort-Object)) {
        $sourcePath = Resolve-SteinPackageRegularFileUnderRoot `
            -Root $stagingRoot `
            -Path (Join-Path $stagingRoot $relativePath)
        if ($sourcePath.Contains('"') -or ([string]$relativePath).Contains('"')) {
            throw "A closed MakeAppx mapping path is invalid."
        }
        $lines.Add("`"$sourcePath`" `"$relativePath`"")
    }
    [IO.File]::WriteAllText(
        $mappingFullPath,
        (($lines.ToArray() -join "`r`n") + "`r`n"),
        [Text.UTF8Encoding]::new($false))
    $mappingDigest = Get-SteinPackageFileSha256 -Path $mappingFullPath
    return Open-SteinPackageVerifiedFileLock `
        -Path $mappingFullPath `
        -ExpectedSha256 $mappingDigest
}

function Assert-SteinClosedUnpackedPackageLayout {
    param([Parameter(Mandatory = $true)][string] $PackageRoot)

    $root = [IO.Path]::GetFullPath($PackageRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "The unpacked package root is not a regular directory."
    }
    $required = @(Get-SteinFixedApplicationPayloadRelativePaths) + @("AppxBlockMap.xml")
    $required = @($required | Sort-Object)
    $optional = @(
        "[Content_Types].xml",
        "AppxMetadata\CodeIntegrity.cat",
        "AppxSignature.p7x"
    )
    $items = @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop)
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The unpacked package contains a reparse point."
        }
    }
    $actual = @(
        $items |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object { $_.FullName.Substring($root.Length + 1) } |
            Sort-Object
    )
    $unexpected = @($actual | Where-Object { $_ -cnotin $required -and $_ -cnotin $optional })
    $missing = @($required | Where-Object { $_ -cnotin $actual })
    if ($unexpected.Count -ne 0 -or $missing.Count -ne 0) {
        throw "The MSIX does not contain the exact closed production file layout."
    }
    return $actual
}

function Initialize-PackageIdentityNativeApi {
    if ($null -ne ("Stein.PackageIdentityNative" -as [type])) {
        return
    }
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Stein {
    public static class PackageIdentityNative {
        [StructLayout(LayoutKind.Sequential)]
        public struct PackageVersion {
            public UInt64 Value;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PackageId {
            public UInt32 Reserved;
            public UInt32 ProcessorArchitecture;
            public PackageVersion Version;
            [MarshalAs(UnmanagedType.LPWStr)] public string Name;
            [MarshalAs(UnmanagedType.LPWStr)] public string Publisher;
            [MarshalAs(UnmanagedType.LPWStr)] public string ResourceId;
            [MarshalAs(UnmanagedType.LPWStr)] public string PublisherId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern Int32 PackageFamilyNameFromId(
            ref PackageId packageId,
            ref UInt32 packageFamilyNameLength,
            StringBuilder packageFamilyName);
    }
}
"@
}

function Get-ExactPackageFamilyName {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PackageName,
        [Parameter(Mandatory = $true)]
        [string] $Publisher
    )

    Initialize-PackageIdentityNativeApi
    $identity = [Stein.PackageIdentityNative+PackageId]::new()
    $identity.Name = $PackageName
    $identity.Publisher = $Publisher
    $capacity = [uint32] 130
    $value = [Text.StringBuilder]::new([int] $capacity)
    $result = [Stein.PackageIdentityNative]::PackageFamilyNameFromId(
        [ref] $identity,
        [ref] $capacity,
        $value)
    if ($result -ne 0) {
        throw "Windows rejected the requested package identity."
    }
    return $value.ToString()
}

function Test-SteinManifestContract {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ManifestPath,
        [string] $ExpectedPublisher,
        [string] $ExpectedVersion,
        [string] $PackageRoot
    )

    $resolvedManifest = (Resolve-Path -LiteralPath $ManifestPath -ErrorAction Stop).Path
    [xml] $manifest = Get-Content -LiteralPath $resolvedManifest -Raw -Encoding UTF8
    $namespaces = [Xml.XmlNamespaceManager]::new($manifest.NameTable)
    $namespaces.AddNamespace("f", $script:FoundationNamespace)
    $namespaces.AddNamespace("uap", $script:UapNamespace)
    $namespaces.AddNamespace("uap10", $script:Uap10Namespace)
    $namespaces.AddNamespace("com", $script:ComNamespace)
    $namespaces.AddNamespace("desktop", $script:DesktopNamespace)
    $namespaces.AddNamespace("rescap", $script:RestrictedCapabilityNamespace)

    $package = $manifest.SelectSingleNode("/f:Package", $namespaces)
    if ($null -eq $package -or $package.IgnorableNamespaces -cne "uap uap10 com desktop rescap") {
        throw "Manifest namespaces are not the pinned production set."
    }
    $identity = $manifest.SelectSingleNode("/f:Package/f:Identity", $namespaces)
    if ($null -eq $identity -or
        $identity.Name -cne $script:ProductionPackageName -or
        $identity.ProcessorArchitecture -cne "x64") {
        throw "Manifest package identity is not the pinned production identity."
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedPublisher) -and
        $identity.Publisher -cne $ExpectedPublisher) {
        throw "Manifest Publisher does not match the selected certificate."
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedVersion) -and
        $identity.Version -cne $ExpectedVersion) {
        throw "Manifest version does not match the requested version."
    }

    $family = $manifest.SelectSingleNode(
        "/f:Package/f:Dependencies/f:TargetDeviceFamily",
        $namespaces)
    if ($null -eq $family -or
        $family.Name -cne "Windows.Desktop" -or
        ([version] $family.MinVersion) -lt ([version] "10.0.19041.0")) {
        throw "Manifest Windows target is outside the supported AppContainer profile."
    }

    $applications = @($manifest.SelectNodes("/f:Package/f:Applications/f:Application", $namespaces))
    if ($applications.Count -ne 3) {
        throw "Manifest must contain exactly the desktop, private broker, and browser producer applications."
    }
    $expectedApplications = @{
        Desktop = @{
            Executable = "bin\stein-desktop.exe"
            RuntimeBehavior = "packagedClassicApp"
            TrustLevel = "mediumIL"
            AppListEntry = "default"
        }
        PrivateBroker = @{
            Executable = "bin\stein-private-broker.exe"
            RuntimeBehavior = "packagedClassicApp"
            TrustLevel = "appContainer"
            AppListEntry = "none"
        }
        BrowserObservationProducer = @{
            Executable = "bin\stein-edge-native-host.exe"
            RuntimeBehavior = "packagedClassicApp"
            TrustLevel = "mediumIL"
            AppListEntry = "none"
        }
    }
    foreach ($application in $applications) {
        if (-not $expectedApplications.ContainsKey($application.Id)) {
            throw "Manifest contains an unapproved application identity."
        }
        $expected = $expectedApplications[$application.Id]
        $visual = $application.SelectSingleNode("uap:VisualElements", $namespaces)
        if ($application.Executable -cne $expected.Executable -or
            $application.GetAttribute("RuntimeBehavior", $script:Uap10Namespace) -cne $expected.RuntimeBehavior -or
            $application.GetAttribute("TrustLevel", $script:Uap10Namespace) -cne $expected.TrustLevel -or
            $application.HasAttribute("EntryPoint") -or
            $null -eq $visual -or
            $visual.AppListEntry -cne $expected.AppListEntry) {
            throw "Manifest application execution identity is not the pinned profile."
        }
        $extensions = @($application.SelectNodes("f:Extensions/*", $namespaces))
        if ($application.Id -ceq $script:DesktopApplicationId) {
            if ($extensions.Count -ne 2) {
                throw "The desktop must declare exactly the toast COM server and activation extension."
            }
            $comExtension = $application.SelectSingleNode(
                "f:Extensions/com:Extension[@Category='windows.comServer']",
                $namespaces)
            $desktopExtension = $application.SelectSingleNode(
                "f:Extensions/desktop:Extension[@Category='windows.toastNotificationActivation']",
                $namespaces)
            $exeServer = if ($null -ne $comExtension) {
                $comExtension.SelectSingleNode("com:ComServer/com:ExeServer", $namespaces)
            }
            $comClass = if ($null -ne $exeServer) {
                $exeServer.SelectSingleNode("com:Class", $namespaces)
            }
            $toastActivation = if ($null -ne $desktopExtension) {
                $desktopExtension.SelectSingleNode(
                    "desktop:ToastNotificationActivation",
                    $namespaces)
            }
            if ($null -eq $comExtension -or
                $null -eq $desktopExtension -or
                $null -eq $exeServer -or
                $null -eq $comClass -or
                $null -eq $toastActivation -or
                $exeServer.Executable -cne "bin\stein-desktop.exe" -or
                $exeServer.Arguments -cne "-ToastActivated" -or
                $exeServer.DisplayName -cne "STEIN toast activator" -or
                @($exeServer.SelectNodes("com:Class", $namespaces)).Count -ne 1 -or
                $comClass.Id -cne $script:ToastActivatorClsid -or
                $comClass.DisplayName -cne "STEIN toast activator" -or
                $toastActivation.ToastActivatorCLSID -cne $script:ToastActivatorClsid) {
                throw "Manifest toast activation identity is not the pinned profile."
            }
        }
        elseif ($extensions.Count -ne 0) {
            throw "Non-desktop package applications must not declare activation extensions."
        }
    }

    $capabilities = @($manifest.SelectNodes("/f:Package/f:Capabilities/*", $namespaces))
    if ($capabilities.Count -ne 1 -or
        $capabilities[0].LocalName -cne "Capability" -or
        $capabilities[0].NamespaceURI -cne $script:RestrictedCapabilityNamespace -or
        $capabilities[0].Name -cne "runFullTrust") {
        throw "Manifest capabilities exceed the single required full-trust declaration."
    }
    if (@($manifest.SelectNodes("//f:DeviceCapability | //f:Extension | //uap:Extension", $namespaces)).Count -ne 0) {
        throw "Manifest contains an unapproved device capability or extension."
    }

    if (-not [string]::IsNullOrWhiteSpace($PackageRoot)) {
        $requiredFiles = @(
            "bin\stein-desktop.exe",
            "bin\stein-private-broker.exe",
            "bin\stein-edge-native-host.exe",
            "Metadata\CoreBinding.json",
            "Assets\StoreLogo.png",
            "Assets\Square44x44Logo.png",
            "Assets\Square150x150Logo.png"
        )
        foreach ($relative in $requiredFiles) {
            if (-not (Test-Path -LiteralPath (Join-Path $PackageRoot $relative) -PathType Leaf)) {
                throw "Package is missing a required file."
            }
        }
        if (Get-ChildItem -LiteralPath $PackageRoot -Recurse -File |
            Where-Object { $_.Name -ieq "stein-core.exe" }) {
            throw "The Task-Scheduler CORE daemon must remain outside the MSIX package."
        }
    }

    return [pscustomobject] @{
        PackageName = $identity.Name
        Publisher = $identity.Publisher
        Version = $identity.Version
        DesktopApplicationId = $script:DesktopApplicationId
        BrokerApplicationId = $script:BrokerApplicationId
        BrowserProducerApplicationId = $script:BrowserProducerApplicationId
    }
}
