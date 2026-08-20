Set-StrictMode -Version 3.0

$script:SteinPhase2PackageName = "STEIN.PersonalIntelligence"
$script:SteinPhase2DesktopApplicationId = "Desktop"
$script:SteinPhase2BrokerApplicationId = "PrivateBroker"
$script:SteinPhase2TaskPrefix = "STEIN Core SID-"
$script:SteinPhase2InstallSchemaVersion = 2
$script:SteinPhase2IdentitySchemaVersion = 1
$script:SteinPhase2CredentialPrefix = "STEIN:model-route:"
$script:SteinPhase2RestartCount = 10
$script:SteinPhase2RestartInterval = "PT1M"
$script:SteinPhase2ReadyTimeoutMilliseconds = 30000
$script:SteinPhase2MigrationReadiness = "durable_persistence_healthy_startup_integrity_gate"

$script:SteinPhase2PackagingRoot = (Resolve-Path -LiteralPath (
    Join-Path $PSScriptRoot "..\..\..\packaging\windows-msix") -ErrorAction Stop).Path
. (Join-Path $script:SteinPhase2PackagingRoot "PackageTools.ps1")

function Assert-SteinPhase2WindowsHost {
    if ($env:OS -cne "Windows_NT") {
        throw "The Phase 2 lifecycle is available only on native Windows."
    }
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
        throw "The x64 Phase 2 lifecycle requires a 64-bit Windows PowerShell process."
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User -or $identity.IsSystem) {
        throw "The Phase 2 lifecycle requires a normal interactive user token."
    }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run the Phase 2 lifecycle from a non-elevated PowerShell session."
    }
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is unavailable for the current user."
    }
}

function Get-SteinPhase2CurrentUserSid {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $sid) {
        throw "The current Windows user SID is unavailable."
    }
    return $sid.Value
}

function Get-SteinPhase2KnownLocalAppData {
    $path = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($path)) {
        throw "Windows did not return the current user's Local AppData known folder."
    }
    return ConvertTo-SteinPhase2CanonicalPath -Path $path
}

function Get-SteinPhase2TaskName {
    return "$script:SteinPhase2TaskPrefix$(Get-SteinPhase2CurrentUserSid)"
}

function Resolve-SteinPhase2IdentitySid {
    param([Parameter(Mandatory = $true)][string] $Identity)

    if ($Identity -match "^S-1-[0-9-]+$") {
        return [Security.Principal.SecurityIdentifier]::new($Identity).Value
    }
    try {
        return [Security.Principal.NTAccount]::new($Identity).
            Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw "A Windows task identity could not be resolved to an exact SID."
    }
}

function ConvertTo-SteinPhase2CanonicalPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "A non-empty path is required."
    }
    return [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
}

function Test-SteinPhase2PathEqual {
    param(
        [Parameter(Mandatory = $true)][string] $Left,
        [Parameter(Mandatory = $true)][string] $Right
    )

    return [string]::Equals(
        (ConvertTo-SteinPhase2CanonicalPath -Path $Left),
        (ConvertTo-SteinPhase2CanonicalPath -Path $Right),
        [StringComparison]::OrdinalIgnoreCase)
}

function Assert-SteinPhase2InstallRoot {
    param(
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [string] $KnownLocalAppData = (Get-SteinPhase2KnownLocalAppData)
    )

    $canonical = ConvertTo-SteinPhase2CanonicalPath -Path $InstallRoot
    $knownRoot = ConvertTo-SteinPhase2CanonicalPath -Path $KnownLocalAppData
    $expected = ConvertTo-SteinPhase2CanonicalPath -Path (Join-Path $knownRoot "STEIN")
    if (-not (Test-SteinPhase2PathEqual -Left $canonical -Right $expected)) {
        throw "InstallRoot must be exactly the current user's LOCALAPPDATA\STEIN directory."
    }
    if (Test-Path -LiteralPath $canonical) {
        $item = Get-Item -LiteralPath $canonical -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "InstallRoot must be a regular, non-reparse directory."
        }
    }
    return $canonical
}

function Assert-SteinPhase2NoReparseTree {
    param([Parameter(Mandatory = $true)][string] $Root)

    if (-not (Test-Path -LiteralPath $Root)) {
        return
    }
    $items = @((Get-Item -LiteralPath $Root -Force -ErrorAction Stop)) + @(
        Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop
    )
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "A reparse point exists inside the protected STEIN lifecycle tree."
        }
    }
}

function Resolve-SteinPhase2RegularFile {
    param([Parameter(Mandatory = $true)][string] $Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0) {
        throw "A regular, non-empty, non-reparse release file is required."
    }
    return $resolved
}

function Assert-SteinPhase2LeafName {
    param([Parameter(Mandatory = $true)][string] $Name)

    if ([string]::IsNullOrWhiteSpace($Name) -or
        [IO.Path]::GetFileName($Name) -cne $Name -or
        $Name.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
        throw "A release identity contains an unsafe companion filename."
    }
}

function Get-SteinPhase2Sha256 {
    param([Parameter(Mandatory = $true)][string] $Path)

    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha256.ComputeHash($stream)
            return [BitConverter]::ToString($digest).Replace("-", "").ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-SteinPhase2Hash {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $ExpectedSha256
    )

    if ($ExpectedSha256 -notmatch "^[0-9a-f]{64}$") {
        throw "A release identity contains an invalid SHA-256 value."
    }
    $actual = Get-SteinPhase2Sha256 -Path $Path
    if ($actual -cne $ExpectedSha256) {
        throw "A release artifact SHA-256 does not match its identity record."
    }
}

function Assert-SteinPhase2Size {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $ExpectedSize
    )

    $parsed = 0L
    if (-not [long]::TryParse(
            [string]$ExpectedSize,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsed) -or
        $parsed -le 0) {
        throw "A release identity contains an invalid file size."
    }
    if ((Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Length -ne $parsed) {
        throw "A release artifact size does not match its identity record."
    }
}

function Assert-SteinPhase2JsonShape {
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
        @(Compare-Object -ReferenceObject $expected -DifferenceObject $actual -CaseSensitive).Count -ne 0) {
        throw "$Description does not use the closed expected schema."
    }
}

function ConvertTo-SteinPhase2Version {
    param([Parameter(Mandatory = $true)][string] $Version)

    if ($Version -notmatch "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$") {
        throw "Version must contain exactly four numeric components."
    }
    try {
        return [version]$Version
    }
    catch {
        throw "Version is not a valid Windows package version."
    }
}

function Get-SteinPhase2ReleaseBundle {
    param(
        [Parameter(Mandatory = $true)][string] $PackagePath,
        [Parameter(Mandatory = $true)][string] $Publisher,
        [Parameter(Mandatory = $true)][string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)][string] $Version
    )

    if ([string]::IsNullOrWhiteSpace($Publisher) -or $Publisher.Contains("{{")) {
        throw "An exact operator-pinned Publisher distinguished name is required."
    }
    $normalizedThumbprint = ConvertTo-SteinCertificateThumbprint -Thumbprint $CertificateThumbprint
    $null = ConvertTo-SteinPhase2Version -Version $Version
    $resolvedPackage = Resolve-SteinPhase2RegularFile -Path $PackagePath
    if ([IO.Path]::GetExtension($resolvedPackage) -ine ".msix") {
        throw "PackagePath must identify an MSIX release artifact."
    }

    $identityPath = Resolve-SteinPhase2RegularFile -Path "$resolvedPackage.identity.json"
    $rawIdentity = Get-Content -LiteralPath $identityPath -Raw -Encoding UTF8
    try {
        $identity = $rawIdentity | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "The release identity record is not valid JSON."
    }
    Assert-SteinPhase2JsonShape -Value $identity -Description "The release identity record" `
        -ExpectedProperties @(
            "identity_schema_version",
            "package_name",
            "publisher",
            "package_family_name",
            "desktop_aumid",
            "broker_aumid",
            "version",
            "architecture",
            "signing_certificate_thumbprint",
            "core_executable_file",
            "core_executable_size",
            "core_executable_sha256",
            "cli_executable_file",
            "cli_executable_size",
            "cli_executable_sha256",
            "msix_size",
            "msix_sha256"
        )

    $packageLeaf = Split-Path -Leaf $resolvedPackage
    $expectedCoreLeaf = "$packageLeaf.core.exe"
    $expectedCliLeaf = "$packageLeaf.cli.exe"
    Assert-SteinPhase2LeafName -Name ([string]$identity.core_executable_file)
    Assert-SteinPhase2LeafName -Name ([string]$identity.cli_executable_file)
    if ([string]$identity.core_executable_file -cne $expectedCoreLeaf -or
        [string]$identity.cli_executable_file -cne $expectedCliLeaf) {
        throw "The companion filenames are not bound to the exact MSIX filename."
    }

    $derivedFamily = Get-ExactPackageFamilyName `
        -PackageName $script:SteinPhase2PackageName `
        -Publisher $Publisher
    $expectedDesktopAumid = "$derivedFamily!$script:SteinPhase2DesktopApplicationId"
    $expectedBrokerAumid = "$derivedFamily!$script:SteinPhase2BrokerApplicationId"
    if ([int]$identity.identity_schema_version -ne $script:SteinPhase2IdentitySchemaVersion -or
        [string]$identity.package_name -cne $script:SteinPhase2PackageName -or
        [string]$identity.publisher -cne $Publisher -or
        [string]$identity.package_family_name -cne $derivedFamily -or
        [string]$identity.desktop_aumid -cne $expectedDesktopAumid -or
        [string]$identity.broker_aumid -cne $expectedBrokerAumid -or
        [string]$identity.version -cne $Version -or
        [string]$identity.architecture -cne "x64" -or
        ([string]$identity.signing_certificate_thumbprint).ToUpperInvariant() -cne $normalizedThumbprint) {
        throw "The release identity does not match the exact operator-pinned production identity."
    }

    $parent = Split-Path -Parent $resolvedPackage
    $corePath = Resolve-SteinPhase2RegularFile -Path (
        Join-Path $parent ([string]$identity.core_executable_file))
    $cliPath = Resolve-SteinPhase2RegularFile -Path (
        Join-Path $parent ([string]$identity.cli_executable_file))
    Assert-SteinPhase2Size -Path $resolvedPackage -ExpectedSize $identity.msix_size
    Assert-SteinPhase2Size -Path $corePath -ExpectedSize $identity.core_executable_size
    Assert-SteinPhase2Size -Path $cliPath -ExpectedSize $identity.cli_executable_size
    Assert-SteinPhase2Hash -Path $resolvedPackage -ExpectedSha256 ([string]$identity.msix_sha256)
    Assert-SteinPhase2Hash -Path $corePath -ExpectedSha256 ([string]$identity.core_executable_sha256)
    Assert-SteinPhase2Hash -Path $cliPath -ExpectedSha256 ([string]$identity.cli_executable_sha256)

    $null = Assert-SteinExactAuthenticodeSignature `
        -Path $corePath `
        -CertificateThumbprint $normalizedThumbprint `
        -Publisher $Publisher
    $null = Assert-SteinExactAuthenticodeSignature `
        -Path $cliPath `
        -CertificateThumbprint $normalizedThumbprint `
        -Publisher $Publisher
    $verification = & (Join-Path $script:SteinPhase2PackagingRoot "Verify-Msix.ps1") `
        -PackagePath $resolvedPackage `
        -CertificateThumbprint $normalizedThumbprint `
        -Publisher $Publisher `
        -Version $Version `
        -ExpectedCoreSha256 ([string]$identity.core_executable_sha256)
    if ($null -eq $verification -or
        $verification.PackageFamilyName -cne $derivedFamily -or
        $verification.DesktopAumid -cne $expectedDesktopAumid -or
        $verification.BrokerAumid -cne $expectedBrokerAumid -or
        $verification.BrokerPinnedCoreSha256 -cne [string]$identity.core_executable_sha256 -or
        $verification.Sha256 -cne [string]$identity.msix_sha256) {
        throw "Independent MSIX verification did not reproduce the identity record."
    }

    return [pscustomobject]@{
        PackagePath = $resolvedPackage
        PackageLeaf = $packageLeaf
        IdentityPath = $identityPath
        IdentityLeaf = (Split-Path -Leaf $identityPath)
        CorePath = $corePath
        CoreLeaf = [string]$identity.core_executable_file
        CliPath = $cliPath
        CliLeaf = [string]$identity.cli_executable_file
        PackageName = $script:SteinPhase2PackageName
        Publisher = $Publisher
        PackageFamilyName = $derivedFamily
        DesktopAumid = $expectedDesktopAumid
        BrokerAumid = $expectedBrokerAumid
        Version = $Version
        CertificateThumbprint = $normalizedThumbprint
        MsixSize = [long]$identity.msix_size
        MsixSha256 = [string]$identity.msix_sha256
        CoreSize = [long]$identity.core_executable_size
        CoreSha256 = [string]$identity.core_executable_sha256
        CliSize = [long]$identity.cli_executable_size
        CliSha256 = [string]$identity.cli_executable_sha256
    }
}

function Get-SteinPhase2FileSystemSecurity {
    param([Parameter(Mandatory = $true)][IO.FileSystemInfo] $Item)

    $sections = [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    if ($Item.PSIsContainer) {
        return [IO.Directory]::GetAccessControl(
            $Item.FullName,
            $sections)
    }
    return [IO.File]::GetAccessControl(
        $Item.FullName,
        $sections)
}

function Set-SteinPhase2FileSystemSecurity {
    param(
        [Parameter(Mandatory = $true)][IO.FileSystemInfo] $Item,
        [Parameter(Mandatory = $true)][Security.AccessControl.FileSystemSecurity] $Security
    )

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

function Protect-SteinPhase2OwnerOnlyPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to protect a reparse point."
    }
    try {
        Assert-SteinPhase2OwnerOnlyPath -Path $Path
        return
    }
    catch {
        # Replace any broader or malformed ACL below.
    }
    $sid = [Security.Principal.SecurityIdentifier]::new((Get-SteinPhase2CurrentUserSid))
    $security = Get-SteinPhase2FileSystemSecurity -Item $item
    $security.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($security.GetAccessRules(
                $true,
                $false,
                [Security.Principal.SecurityIdentifier]))) {
        $security.RemoveAccessRuleSpecific($existingRule)
    }
    try {
        $currentOwnerSid = ([Security.Principal.NTAccount]$security.Owner).
            Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        $currentOwnerSid = [Security.Principal.SecurityIdentifier]::new($security.Owner).Value
    }
    if ($currentOwnerSid -cne $sid.Value) {
        $security.SetOwner($sid)
    }
    if ($item.PSIsContainer) {
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    else {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    Set-SteinPhase2FileSystemSecurity -Item $item -Security $security
}

function Protect-SteinPhase2OwnerOnlyTree {
    param([Parameter(Mandatory = $true)][string] $Root)

    Assert-SteinPhase2NoReparseTree -Root $Root
    $children = @(Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop |
        Sort-Object { $_.FullName.Length } -Descending)
    foreach ($child in $children) {
        Protect-SteinPhase2OwnerOnlyPath -Path $child.FullName
    }
    Protect-SteinPhase2OwnerOnlyPath -Path $Root
}

function Assert-SteinPhase2OwnerOnlyPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "A protected STEIN path is a reparse point."
    }
    $expectedSid = Get-SteinPhase2CurrentUserSid
    $acl = Get-SteinPhase2FileSystemSecurity -Item $item
    try {
        $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).
            Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        $ownerSid = [Security.Principal.SecurityIdentifier]::new($acl.Owner).Value
    }
    if ($ownerSid -cne $expectedSid -or -not $acl.AreAccessRulesProtected) {
        throw "A protected STEIN path does not have the exact owner/protection boundary."
    }
    $rules = @($acl.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -lt 1) {
        throw "A protected STEIN path has no owner access rule."
    }
    $hasFullControl = $false
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -cne $expectedSid -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw "A protected STEIN path grants access outside the owning SID."
        }
        if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
            [Security.AccessControl.FileSystemRights]::FullControl) {
            $hasFullControl = $true
        }
    }
    if (-not $hasFullControl) {
        throw "The owning SID lacks full control of a protected STEIN path."
    }
}

function Assert-SteinPhase2OwnerOnlyTree {
    param([Parameter(Mandatory = $true)][string] $Root)

    Assert-SteinPhase2NoReparseTree -Root $Root
    Assert-SteinPhase2OwnerOnlyPath -Path $Root
    foreach ($child in @(Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop)) {
        Assert-SteinPhase2OwnerOnlyPath -Path $child.FullName
    }
}

function Copy-SteinPhase2BundleToDirectory {
    param(
        [Parameter(Mandatory = $true)] $Bundle,
        [Parameter(Mandatory = $true)][string] $Destination,
        [Parameter(Mandatory = $true)][string] $Publisher,
        [Parameter(Mandatory = $true)][string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)][string] $Version
    )

    if (Test-Path -LiteralPath $Destination) {
        throw "The protected release staging directory already exists."
    }
    $null = New-Item -ItemType Directory -Path $Destination -ErrorAction Stop
    Protect-SteinPhase2OwnerOnlyPath -Path $Destination
    foreach ($source in @(
            $Bundle.PackagePath,
            $Bundle.IdentityPath,
            $Bundle.CorePath,
            $Bundle.CliPath)) {
        Copy-Item -LiteralPath $source -Destination $Destination -ErrorAction Stop
    }
    Protect-SteinPhase2OwnerOnlyTree -Root $Destination

    # Re-verify the protected copy. All later mutation consumes these bytes,
    # never the operator's potentially changing source directory.
    return Get-SteinPhase2ReleaseBundle `
        -PackagePath (Join-Path $Destination $Bundle.PackageLeaf) `
        -Publisher $Publisher `
        -CertificateThumbprint $CertificateThumbprint `
        -Version $Version
}

function Get-SteinPhase2ProcessByPath {
    param([Parameter(Mandatory = $true)][string] $ExecutablePath)

    $canonical = ConvertTo-SteinPhase2CanonicalPath -Path $ExecutablePath
    $name = [IO.Path]::GetFileName($canonical).Replace("'", "''")
    return @(
        Get-CimInstance Win32_Process -Filter "Name = '$name'" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ExecutablePath -and
                (Test-SteinPhase2PathEqual -Left $_.ExecutablePath -Right $canonical)
            }
    )
}

function Wait-SteinPhase2ProcessExit {
    param(
        [Parameter(Mandatory = $true)][string] $ExecutablePath,
        [int] $TimeoutMilliseconds = 10000
    )

    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        if (@(Get-SteinPhase2ProcessByPath -ExecutablePath $ExecutablePath).Count -eq 0) {
            return $true
        }
        Start-Sleep -Milliseconds 100
    }
    return (@(Get-SteinPhase2ProcessByPath -ExecutablePath $ExecutablePath).Count -eq 0)
}

function Stop-SteinPhase2ProcessByPath {
    param(
        [Parameter(Mandatory = $true)][string] $ExecutablePath,
        [int] $TimeoutMilliseconds = 5000
    )

    $processes = @(Get-SteinPhase2ProcessByPath -ExecutablePath $ExecutablePath)
    foreach ($process in $processes) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
    if ($processes.Count -eq 0) {
        return $true
    }
    return Wait-SteinPhase2ProcessExit `
        -ExecutablePath $ExecutablePath `
        -TimeoutMilliseconds $TimeoutMilliseconds
}

function Invoke-SteinPhase2Process {
    param(
        [Parameter(Mandatory = $true)][string] $FilePath,
        [string] $Arguments = "",
        [int] $TimeoutMilliseconds = 3000
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "The diagnostic process did not start."
        }
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            try { $process.Kill() } catch { }
            $process.WaitForExit()
            return [pscustomobject]@{
                Succeeded = $false
                TimedOut = $true
                ExitCode = $null
                Stdout = $process.StandardOutput.ReadToEnd()
                Stderr = $process.StandardError.ReadToEnd()
            }
        }
        $process.WaitForExit()
        return [pscustomobject]@{
            Succeeded = ($process.ExitCode -eq 0)
            TimedOut = $false
            ExitCode = $process.ExitCode
            Stdout = $process.StandardOutput.ReadToEnd()
            Stderr = $process.StandardError.ReadToEnd()
        }
    }
    catch {
        return [pscustomobject]@{
            Succeeded = $false
            TimedOut = $false
            ExitCode = $null
            Stdout = ""
            Stderr = "The diagnostic process could not run."
        }
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-SteinPhase2CliJson {
    param(
        [Parameter(Mandatory = $true)][string] $CliPath,
        [Parameter(Mandatory = $true)][string] $Arguments,
        [int] $TimeoutMilliseconds = 3000
    )

    $result = Invoke-SteinPhase2Process `
        -FilePath $CliPath `
        -Arguments $Arguments `
        -TimeoutMilliseconds $TimeoutMilliseconds
    $json = $null
    if ($result.Succeeded -and -not [string]::IsNullOrWhiteSpace($result.Stdout)) {
        try {
            $json = $result.Stdout | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            $result.Succeeded = $false
            $result.Stderr = "The diagnostic CLI returned invalid JSON."
        }
    }
    $result | Add-Member -NotePropertyName Json -NotePropertyValue $json
    return $result
}

function Assert-SteinPhase2PersistenceReadyStatus {
    param([Parameter(Mandatory = $true)] $Status)

    if ($null -eq $Status.runtime -or
        [string]$Status.runtime.health -cne "healthy") {
        throw "CORE diagnostic runtime health is unavailable or unhealthy."
    }
    $capabilitiesProperty = $Status.PSObject.Properties["capabilities"]
    if ($null -eq $capabilitiesProperty -or $null -eq $capabilitiesProperty.Value) {
        throw "CORE diagnostic status does not expose capability health."
    }
    $persistence = @(
        $capabilitiesProperty.Value | Where-Object {
            [string]$_.capability -ceq "durable_persistence"
        }
    )
    if ($persistence.Count -ne 1) {
        throw "CORE diagnostic status must contain exactly one durable_persistence capability."
    }
    $capability = $persistence[0]
    if ($null -eq $capability.PSObject.Properties["schema_version"] -or
        [int]$capability.schema_version -ne 1 -or
        [string]$capability.state -cne "healthy") {
        throw "CORE durable persistence did not pass its startup migration and integrity gate."
    }
    $reason = $capability.PSObject.Properties["unavailable_reason"]
    if ($null -ne $reason -and $null -ne $reason.Value) {
        throw "A healthy durable_persistence capability must not have an unavailable reason."
    }
    return $capability
}

function Get-SteinPhase2InstalledPackages {
    return @(
        Get-AppxPackage -Name $script:SteinPhase2PackageName -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ceq $script:SteinPhase2PackageName }
    )
}

function Assert-SteinPhase2InstalledPackage {
    param([Parameter(Mandatory = $true)] $Bundle)

    $packages = @(Get-SteinPhase2InstalledPackages)
    if ($packages.Count -ne 1) {
        throw "Expected exactly one current-user STEIN production package."
    }
    $package = $packages[0]
    if ([string]$package.PackageFamilyName -cne $Bundle.PackageFamilyName -or
        [string]$package.Publisher -cne $Bundle.Publisher -or
        [string]$package.Version -cne $Bundle.Version -or
        [string]$package.Architecture -cne "X64" -or
        [bool]$package.IsFramework) {
        throw "The installed MSIX identity does not match the verified release bundle."
    }

    $manifest = Get-AppxPackageManifest -Package $package.PackageFullName -ErrorAction Stop
    $applications = @($manifest.Package.Applications.Application)
    if ($applications.Count -ne 2) {
        throw "The installed package does not contain the exact two-application topology."
    }
    $applicationIds = @($applications | ForEach-Object { [string]$_.Id } | Sort-Object)
    $expectedIds = @(
        $script:SteinPhase2BrokerApplicationId,
        $script:SteinPhase2DesktopApplicationId
    ) | Sort-Object
    if (@(Compare-Object -ReferenceObject $expectedIds -DifferenceObject $applicationIds -CaseSensitive).Count -ne 0) {
        throw "The installed package application identities do not match the production AUMIDs."
    }
    return $package
}

function Register-SteinPhase2Task {
    param(
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)][string] $CorePath
    )

    $taskName = Get-SteinPhase2TaskName
    $sid = Get-SteinPhase2CurrentUserSid
    $action = New-ScheduledTaskAction `
        -Execute $CorePath `
        -Argument "--installed" `
        -WorkingDirectory $InstallRoot
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $sid
    $principal = New-ScheduledTaskPrincipal `
        -UserId $sid `
        -LogonType Interactive `
        -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -RestartCount $script:SteinPhase2RestartCount `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
        -MultipleInstances IgnoreNew
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Presentation-independent per-user STEIN CORE daemon ($sid)" `
        -Force `
        -ErrorAction Stop | Out-Null
    return $taskName
}

function Assert-SteinPhase2Task {
    param(
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)][string] $CorePath
    )

    $taskName = Get-SteinPhase2TaskName
    $sid = Get-SteinPhase2CurrentUserSid
    $tasks = @(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
    if ($tasks.Count -ne 1) {
        throw "Expected exactly one SID-qualified Phase 2 CORE task."
    }
    $task = $tasks[0]
    $actions = @($task.Actions)
    $triggers = @($task.Triggers)
    if ($actions.Count -ne 1 -or $triggers.Count -ne 1) {
        throw "The CORE task must have exactly one action and one logon trigger."
    }
    $action = $actions[0]
    if (-not (Test-SteinPhase2PathEqual -Left ([string]$action.Execute) -Right $CorePath) -or
        [string]$action.Arguments -cne "--installed" -or
        -not (Test-SteinPhase2PathEqual `
            -Left ([string]$action.WorkingDirectory) `
            -Right $InstallRoot)) {
        throw "The CORE task action is not the exact installed binary with only --installed."
    }
    if ((Resolve-SteinPhase2IdentitySid -Identity ([string]$triggers[0].UserId)) -cne $sid -or
        (Resolve-SteinPhase2IdentitySid -Identity ([string]$task.Principal.UserId)) -cne $sid -or
        [string]$task.Principal.LogonType -cne "Interactive" -or
        [string]$task.Principal.RunLevel -cne "Limited") {
        throw "The CORE task is not bound to the exact limited interactive user SID."
    }
    if ([bool]$task.Settings.DisallowStartIfOnBatteries -or
        [bool]$task.Settings.StopIfGoingOnBatteries -or
        [string]$task.Settings.MultipleInstances -cne "IgnoreNew" -or
        [int]$task.Settings.RestartCount -ne $script:SteinPhase2RestartCount -or
        [string]$task.Settings.RestartInterval -cne $script:SteinPhase2RestartInterval -or
        [string]$task.Settings.ExecutionTimeLimit -cne "PT0S") {
        throw "The CORE task does not match the bounded battery-safe supervision policy."
    }
    return $task
}

function Wait-SteinPhase2Ready {
    param(
        [Parameter(Mandatory = $true)] $Bundle,
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)][string] $CorePath,
        [Parameter(Mandatory = $true)][string] $CliPath,
        [int] $TimeoutMilliseconds = $script:SteinPhase2ReadyTimeoutMilliseconds
    )

    $timer = [Diagnostics.Stopwatch]::StartNew()
    $lastStatus = $null
    while ($timer.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        try {
            $null = Assert-SteinPhase2InstalledPackage -Bundle $Bundle
            $null = Assert-SteinPhase2Task -InstallRoot $InstallRoot -CorePath $CorePath
            $processes = @(Get-SteinPhase2ProcessByPath -ExecutablePath $CorePath)
            if ($processes.Count -eq 1) {
                $attempt = Invoke-SteinPhase2CliJson `
                    -CliPath $CliPath `
                    -Arguments "status --json" `
                    -TimeoutMilliseconds 1500
                if ($attempt.Succeeded -and
                    $null -ne $attempt.Json) {
                    $null = Assert-SteinPhase2PersistenceReadyStatus -Status $attempt.Json
                    $lastStatus = $attempt.Json
                    return $lastStatus
                }
            }
        }
        catch {
            # Readiness polling intentionally retries bounded transient states.
        }
        Start-Sleep -Milliseconds 250
    }
    throw "CORE did not reach verified package/task/process/runtime/persistence readiness within the bounded deadline."
}

function Write-SteinPhase2JsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $Value
    )

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "The destination directory for lifecycle metadata is unavailable."
    }
    $temporary = Join-Path $parent ("." + (Split-Path -Leaf $Path) + "." +
        [Guid]::NewGuid().ToString("N") + ".tmp")
    try {
        $Value | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $temporary -Encoding UTF8 -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyPath -Path $temporary
        Move-Item -LiteralPath $temporary -Destination $Path -Force -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyPath -Path $Path
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function New-SteinPhase2InstallRecord {
    param(
        [Parameter(Mandatory = $true)] $Bundle,
        [Parameter(Mandatory = $true)] $InstalledPackage,
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)][string] $State,
        [string] $InstalledAtUtc = ([DateTime]::UtcNow.ToString("o"))
    )

    return [ordered]@{
        schema_version = $script:SteinPhase2InstallSchemaVersion
        lifecycle = "phase2-windows-msix"
        state = $State
        installed_at_utc = $InstalledAtUtc
        updated_at_utc = [DateTime]::UtcNow.ToString("o")
        installed_by_sid = Get-SteinPhase2CurrentUserSid
        install_root = $InstallRoot
        task_name = Get-SteinPhase2TaskName
        task_executable = (Join-Path $InstallRoot "bin\stein-core.exe")
        task_arguments = "--installed"
        package_name = $Bundle.PackageName
        package_full_name = [string]$InstalledPackage.PackageFullName
        publisher = $Bundle.Publisher
        package_family_name = $Bundle.PackageFamilyName
        desktop_aumid = $Bundle.DesktopAumid
        broker_aumid = $Bundle.BrokerAumid
        version = $Bundle.Version
        architecture = "x64"
        signing_certificate_thumbprint = $Bundle.CertificateThumbprint
        release_directory = "lifecycle\current"
        msix_file = $Bundle.PackageLeaf
        msix_size = $Bundle.MsixSize
        msix_sha256 = $Bundle.MsixSha256
        core_executable_size = $Bundle.CoreSize
        core_executable_sha256 = $Bundle.CoreSha256
        cli_executable_size = $Bundle.CliSize
        cli_executable_sha256 = $Bundle.CliSha256
        migration_readiness = $script:SteinPhase2MigrationReadiness
    }
}

function Read-SteinPhase2InstallRecord {
    param(
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [switch] $AllowUninstalled
    )

    $path = Join-Path $InstallRoot "install.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The Phase 2 install record is missing."
    }
    $record = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    Assert-SteinPhase2JsonShape -Value $record -Description "The Phase 2 install record" `
        -ExpectedProperties @(
            "schema_version",
            "lifecycle",
            "state",
            "installed_at_utc",
            "updated_at_utc",
            "installed_by_sid",
            "install_root",
            "task_name",
            "task_executable",
            "task_arguments",
            "package_name",
            "package_full_name",
            "publisher",
            "package_family_name",
            "desktop_aumid",
            "broker_aumid",
            "version",
            "architecture",
            "signing_certificate_thumbprint",
            "release_directory",
            "msix_file",
            "msix_size",
            "msix_sha256",
            "core_executable_size",
            "core_executable_sha256",
            "cli_executable_size",
            "cli_executable_sha256",
            "migration_readiness"
        )
    if ([int]$record.schema_version -ne $script:SteinPhase2InstallSchemaVersion -or
        [string]$record.lifecycle -cne "phase2-windows-msix" -or
        [string]$record.installed_by_sid -cne (Get-SteinPhase2CurrentUserSid) -or
        -not (Test-SteinPhase2PathEqual -Left ([string]$record.install_root) -Right $InstallRoot) -or
        [string]$record.task_name -cne (Get-SteinPhase2TaskName) -or
        [string]$record.task_arguments -cne "--installed" -or
        [string]$record.release_directory -cne "lifecycle\current" -or
        [string]$record.migration_readiness -cne $script:SteinPhase2MigrationReadiness) {
        throw "The Phase 2 install record does not belong to this exact user/root/lifecycle."
    }
    if ([string]$record.state -cne "installed" -and
        (-not $AllowUninstalled -or [string]$record.state -cne "uninstalled")) {
        throw "The Phase 2 install record is not in an allowed lifecycle state."
    }
    return $record
}

function Get-SteinPhase2InstalledBundle {
    param(
        [Parameter(Mandatory = $true)][string] $InstallRoot,
        [Parameter(Mandatory = $true)][string] $Publisher,
        [Parameter(Mandatory = $true)][string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)][string] $Version
    )

    $record = Read-SteinPhase2InstallRecord -InstallRoot $InstallRoot
    $normalizedThumbprint = ConvertTo-SteinCertificateThumbprint -Thumbprint $CertificateThumbprint
    if ([string]$record.publisher -cne $Publisher -or
        ([string]$record.signing_certificate_thumbprint).ToUpperInvariant() -cne $normalizedThumbprint -or
        [string]$record.version -cne $Version) {
        throw "Operator pins do not match the current Phase 2 install record."
    }
    Assert-SteinPhase2LeafName -Name ([string]$record.msix_file)
    $releaseRoot = Join-Path $InstallRoot "lifecycle\current"
    $bundle = Get-SteinPhase2ReleaseBundle `
        -PackagePath (Join-Path $releaseRoot ([string]$record.msix_file)) `
        -Publisher $Publisher `
        -CertificateThumbprint $normalizedThumbprint `
        -Version $Version
    if ($bundle.MsixSize -ne [long]$record.msix_size -or
        $bundle.MsixSha256 -cne [string]$record.msix_sha256 -or
        $bundle.CoreSize -ne [long]$record.core_executable_size -or
        $bundle.CoreSha256 -cne [string]$record.core_executable_sha256 -or
        $bundle.CliSize -ne [long]$record.cli_executable_size -or
        $bundle.CliSha256 -cne [string]$record.cli_executable_sha256) {
        throw "The protected current release bundle differs from the install record."
    }

    $corePath = Resolve-SteinPhase2RegularFile -Path (Join-Path $InstallRoot "bin\stein-core.exe")
    $cliPath = Resolve-SteinPhase2RegularFile -Path (Join-Path $InstallRoot "bin\stein-cli.exe")
    Assert-SteinPhase2Size -Path $corePath -ExpectedSize $bundle.CoreSize
    Assert-SteinPhase2Hash -Path $corePath -ExpectedSha256 $bundle.CoreSha256
    Assert-SteinPhase2Size -Path $cliPath -ExpectedSize $bundle.CliSize
    Assert-SteinPhase2Hash -Path $cliPath -ExpectedSha256 $bundle.CliSha256
    $null = Assert-SteinExactAuthenticodeSignature `
        -Path $corePath `
        -CertificateThumbprint $bundle.CertificateThumbprint `
        -Publisher $bundle.Publisher
    $null = Assert-SteinExactAuthenticodeSignature `
        -Path $cliPath `
        -CertificateThumbprint $bundle.CertificateThumbprint `
        -Publisher $bundle.Publisher

    return [pscustomobject]@{
        Record = $record
        Bundle = $bundle
        CorePath = $corePath
        CliPath = $cliPath
    }
}

function Stop-SteinPhase2DaemonCleanly {
    param(
        [Parameter(Mandatory = $true)][string] $CorePath,
        [Parameter(Mandatory = $true)][string] $CliPath
    )

    $processes = @(Get-SteinPhase2ProcessByPath -ExecutablePath $CorePath)
    if ($processes.Count -gt 1) {
        throw "Multiple installed CORE processes make clean shutdown ambiguous."
    }
    if ($processes.Count -eq 1) {
        $result = Invoke-SteinPhase2Process `
            -FilePath $CliPath `
            -Arguments "shutdown --timeout-ms 5000" `
            -TimeoutMilliseconds 7000
        if (-not $result.Succeeded -or
            -not (Wait-SteinPhase2ProcessExit -ExecutablePath $CorePath -TimeoutMilliseconds 10000)) {
            throw "CORE did not acknowledge and complete a clean diagnostic shutdown."
        }
    }
    $taskName = Get-SteinPhase2TaskName
    if (@(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).Count -eq 1) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }
    if (@(Get-SteinPhase2ProcessByPath -ExecutablePath $CorePath).Count -ne 0) {
        throw "CORE remained active after clean shutdown."
    }
}

function New-SteinPhase2ColdRecoveryCopy {
    param(
        [Parameter(Mandatory = $true)][string] $DatabasePath,
        [Parameter(Mandatory = $true)][string] $RecoveryPath
    )

    if (-not (Test-Path -LiteralPath $DatabasePath -PathType Leaf)) {
        return $null
    }
    foreach ($suffix in @("-journal", "-wal", "-shm")) {
        if (Test-Path -LiteralPath "$DatabasePath$suffix") {
            throw "A SQLite journal/sidecar remains after clean shutdown; recovery copy is unsafe."
        }
    }
    if (Test-Path -LiteralPath $RecoveryPath) {
        throw "The requested recovery-copy path already exists."
    }

    $source = [IO.File]::Open(
        $DatabasePath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::None)
    try {
        $header = New-Object byte[] 16
        if ($source.Read($header, 0, $header.Length) -ne $header.Length -or
            [Text.Encoding]::ASCII.GetString($header) -cne "SQLite format 3`0") {
            throw "The stopped database does not have the SQLite format header."
        }
        $source.Position = 0
        $destination = [IO.File]::Open(
            $RecoveryPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None)
        try {
            $source.CopyTo($destination)
            $destination.Flush($true)
        }
        finally {
            $destination.Dispose()
        }
    }
    finally {
        $source.Dispose()
    }
    Protect-SteinPhase2OwnerOnlyPath -Path $RecoveryPath
    $sourceHash = Get-SteinPhase2Sha256 -Path $DatabasePath
    $copyHash = Get-SteinPhase2Sha256 -Path $RecoveryPath
    if ($sourceHash -cne $copyHash) {
        throw "The cold SQLite recovery copy does not match the stopped database."
    }
    return [pscustomobject]@{
        Path = $RecoveryPath
        Sha256 = $copyHash
        Size = (Get-Item -LiteralPath $RecoveryPath).Length
    }
}

function Restore-SteinPhase2ColdRecoveryCopy {
    param(
        [Parameter(Mandatory = $true)][string] $DatabasePath,
        [Parameter(Mandatory = $true)] $Recovery
    )

    if ($null -eq $Recovery) {
        return
    }
    Assert-SteinPhase2Hash -Path $Recovery.Path -ExpectedSha256 $Recovery.Sha256
    Assert-SteinPhase2Size -Path $Recovery.Path -ExpectedSize $Recovery.Size
    $temporary = "$DatabasePath.restore.$([Guid]::NewGuid().ToString('N')).tmp"
    $failed = "$DatabasePath.failed.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        Copy-Item -LiteralPath $Recovery.Path -Destination $temporary -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyPath -Path $temporary
        Assert-SteinPhase2Hash -Path $temporary -ExpectedSha256 $Recovery.Sha256
        if (Test-Path -LiteralPath $DatabasePath -PathType Leaf) {
            [IO.File]::Replace($temporary, $DatabasePath, $failed, $true)
            if (Test-Path -LiteralPath $failed) {
                Remove-Item -LiteralPath $failed -Force -ErrorAction Stop
            }
        }
        else {
            Move-Item -LiteralPath $temporary -Destination $DatabasePath -ErrorAction Stop
        }
        Protect-SteinPhase2OwnerOnlyPath -Path $DatabasePath
        Assert-SteinPhase2Hash -Path $DatabasePath -ExpectedSha256 $Recovery.Sha256
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Initialize-SteinPhase2CredentialNativeApi {
    if ($null -ne ("Stein.Phase2CredentialNative" -as [type])) {
        return
    }
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Stein {
    public static class Phase2CredentialNative {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct Credential {
            public UInt32 Flags;
            public UInt32 Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public UInt32 CredentialBlobSize;
            public IntPtr CredentialBlob;
            public UInt32 Persist;
            public UInt32 AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredEnumerateW(
            string filter, UInt32 flags, out UInt32 count, out IntPtr credentials);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredDeleteW(string target, UInt32 type, UInt32 flags);

        [DllImport("advapi32.dll")]
        private static extern void CredFree(IntPtr buffer);

        public static int DeleteGenericByPrefix(string prefix) {
            UInt32 count;
            IntPtr array;
            if (!CredEnumerateW(prefix + "*", 0, out count, out array)) {
                int error = Marshal.GetLastWin32Error();
                if (error == 1168) return 0;
                throw new Win32Exception(error, "Credential enumeration failed.");
            }
            string[] targets = new string[count];
            try {
                for (int index = 0; index < count; index++) {
                    IntPtr pointer = Marshal.ReadIntPtr(array, index * IntPtr.Size);
                    Credential credential = (Credential)Marshal.PtrToStructure(
                        pointer, typeof(Credential));
                    string target = Marshal.PtrToStringUni(credential.TargetName);
                    if (credential.Type != 1 || target == null ||
                        !target.StartsWith(prefix, StringComparison.Ordinal)) {
                        throw new InvalidOperationException(
                            "Credential enumeration escaped the exact STEIN namespace.");
                    }
                    targets[index] = target;
                    if (credential.CredentialBlob != IntPtr.Zero &&
                        credential.CredentialBlobSize <= 2560) {
                        for (int offset = 0; offset < credential.CredentialBlobSize; offset++) {
                            Marshal.WriteByte(credential.CredentialBlob, offset, 0);
                        }
                    }
                }
            }
            finally {
                CredFree(array);
            }
            foreach (string target in targets) {
                if (!CredDeleteW(target, 1, 0)) {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(), "Credential deletion failed.");
                }
            }
            return targets.Length;
        }
    }
}
"@
}

function Remove-SteinPhase2Credentials {
    Initialize-SteinPhase2CredentialNativeApi
    return [Stein.Phase2CredentialNative]::DeleteGenericByPrefix(
        $script:SteinPhase2CredentialPrefix)
}
