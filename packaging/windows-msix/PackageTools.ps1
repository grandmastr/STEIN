Set-StrictMode -Version Latest

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

function Test-SteinCoreBindingContract {
    param(
        [Parameter(Mandatory = $true)]
        [string] $BindingPath,
        [Parameter(Mandatory = $true)]
        [string] $ExpectedCoreSha256
    )

    if ($ExpectedCoreSha256 -notmatch "^[0-9a-f]{64}$" -or
        $ExpectedCoreSha256 -eq ("0" * 64)) {
        throw "The expected broker CORE binding must be a non-zero lowercase SHA-256 digest."
    }
    $binding = Get-Content -LiteralPath $BindingPath -Raw -Encoding UTF8 |
        ConvertFrom-Json -ErrorAction Stop
    $properties = @($binding.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    $expectedProperties = @("core_executable_sha256", "schema_version") | Sort-Object
    if ($properties.Count -ne $expectedProperties.Count -or
        @(Compare-Object `
            -ReferenceObject $expectedProperties `
            -DifferenceObject $properties `
            -CaseSensitive).Count -ne 0 -or
        [int]$binding.schema_version -ne 1 -or
        [string]$binding.core_executable_sha256 -cne $ExpectedCoreSha256) {
        throw "The signed package CORE binding does not match the broker-pinned executable."
    }
    return [string]$binding.core_executable_sha256
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
