[CmdletBinding()]
param(
    [switch] $WindowsPowerShellCompatibilityChild
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

if ($WindowsPowerShellCompatibilityChild) {
    . (Join-Path $PSScriptRoot "Common.ps1")
    if ([string]$PSVersionTable.PSEdition -cne "Desktop") {
        throw "The ACL compatibility fixture must execute in Windows PowerShell."
    }
    $fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
        "stein-phase2-ps51-" + [Guid]::NewGuid().ToString("N"))
    try {
        $null = New-Item -ItemType Directory -Path $fixtureRoot -ErrorAction Stop
        Protect-SteinPhase2OwnerOnlyPath -Path $fixtureRoot
        foreach ($relativePath in @(Get-SteinPhase2InstalledPayloadRelativePaths)) {
            $path = Join-Path $fixtureRoot $relativePath
            $parent = Split-Path -Parent $path
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                $null = New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop
            }
            [IO.File]::WriteAllBytes(
                $path,
                [Text.Encoding]::UTF8.GetBytes("synthetic-installed-payload:$relativePath"))
        }
        foreach ($relativePath in @("AppxBlockMap.xml", "AppxSignature.p7x")) {
            [IO.File]::WriteAllBytes(
                (Join-Path $fixtureRoot $relativePath),
                [Text.Encoding]::UTF8.GetBytes("synthetic-deployment-metadata:$relativePath"))
        }
        Protect-SteinPhase2OwnerOnlyTree -Root $fixtureRoot
        Assert-SteinPhase2OwnerOnlyTree -Root $fixtureRoot
        $payload = @(
            foreach ($relativePath in @(Get-SteinPhase2InstalledPayloadRelativePaths)) {
                $item = Get-Item -LiteralPath (Join-Path $fixtureRoot $relativePath) `
                    -Force `
                    -ErrorAction Stop
                [pscustomobject]@{
                    relative_path = $relativePath
                    size = [long]$item.Length
                    sha256 = Get-SteinPhase2Sha256 -Path $item.FullName
                }
            }
        )
        $null = Assert-SteinPhase2InstalledPayloadFiles `
            -InstallLocation $fixtureRoot `
            -ExpectedFiles $payload

        [IO.File]::WriteAllText(
            (Join-Path $fixtureRoot "bin\unexpected.exe"),
            "synthetic-unreviewed-installed-payload")
        $extraFileRejected = $false
        try {
            $null = Assert-SteinPhase2InstalledPayloadFiles `
                -InstallLocation $fixtureRoot `
                -ExpectedFiles $payload
        }
        catch {
            $extraFileRejected = $true
        }
        Remove-Item -LiteralPath (Join-Path $fixtureRoot "bin\unexpected.exe") -Force
        if (-not $extraFileRejected) {
            throw "The installed payload fixture accepted an extra executable."
        }

        [IO.File]::AppendAllText(
            (Join-Path $fixtureRoot "bin\stein-desktop.exe"),
            "tampered")
        $tamperRejected = $false
        try {
            $null = Assert-SteinPhase2InstalledPayloadFiles `
                -InstallLocation $fixtureRoot `
                -ExpectedFiles $payload
        }
        catch {
            $tamperRejected = $true
        }
        if (-not $tamperRejected) {
            throw "The installed payload fixture accepted changed bytes."
        }
        [pscustomobject]@{
            verified = $true
            powershell_edition = [string]$PSVersionTable.PSEdition
            payload_file_count = $payload.Count
            extra_file_rejected = $extraFileRejected
            tamper_rejected = $tamperRejected
            get_acl_module_autoloaded = $null -ne (Get-Module Microsoft.PowerShell.Security)
        } | ConvertTo-Json -Compress
    }
    finally {
        if (Test-Path -LiteralPath $fixtureRoot) {
            Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    return
}

$harnessPath = Join-Path $PSScriptRoot "Verify-Installed.ps1"
$launcherPath = Join-Path $PSScriptRoot "Verify-Installed.cmd"
foreach ($path in @($harnessPath, $launcherPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The installed evidence harness is incomplete."
    }
}

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $harnessPath,
    [ref]$tokens,
    [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    throw "Verify-Installed.ps1 does not parse."
}

$parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
foreach ($requiredParameter in @(
        "PackagePath", "Publisher", "CertificateThumbprint", "Version",
        "InstallRoot", "EvidenceRoot", "AttachmentManifest")) {
    if ($requiredParameter -cnotin $parameterNames) {
        throw "Verify-Installed.ps1 is missing a required exact-input parameter."
    }
}
foreach ($mandatoryParameter in @("PackagePath", "Publisher", "CertificateThumbprint", "Version")) {
    $parameter = @($ast.ParamBlock.Parameters | Where-Object {
        $_.Name.VariablePath.UserPath -ceq $mandatoryParameter
    })[0]
    if ($parameter.Extent.Text.IndexOf(
            "Mandatory = `$true",
            [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "An exact bundle/trust input is no longer mandatory."
    }
}

$source = Get-Content -LiteralPath $harnessPath -Raw
$gateMatch = [regex]::Match(
    $source,
    '(?ms)\$script:SteinPhase2GateIds\s*=\s*@\((?<body>.*?)^\s*\)')
if (-not $gateMatch.Success) {
    throw "Verify-Installed.ps1 has no statically readable Phase 2 gate set."
}
$actualGates = @(
    [regex]::Matches($gateMatch.Groups["body"].Value, '"(?<gate>P2-[A-Z0-9-]+)"') |
        ForEach-Object { $_.Groups["gate"].Value }
)
$expectedGates = @(
    "P2-BUILD",
    "P2-PHASE1-REGRESSION",
    "P2-PRIVATE-CLIENT",
    "P2-PERSISTENCE",
    "P2-UPGRADE",
    "P2-SECRETS",
    "P2-IDENTITY",
    "P2-GOALS",
    "P2-GRANTS",
    "P2-CONSENT",
    "P2-PRESENCE",
    "P2-APPLICATION",
    "P2-DOCUMENT",
    "P2-BROWSER",
    "P2-UIA",
    "P2-PIXELS",
    "P2-MODEL-CONTRACT",
    "P2-MODEL-LIVE",
    "P2-SILENCE",
    "P2-INTERVENTION",
    "P2-POLICY-FAILSAFE",
    "P2-NATIVE-CONTROL",
    "P2-NOTIFICATION",
    "P2-OUTBOX-RECOVERY",
    "P2-OUTBOX-EXPIRY",
    "P2-FEEDBACK",
    "P2-REVOCATION-RACE",
    "P2-DESKTOP-CLOSED",
    "P2-DAEMON-RESTART",
    "P2-RETENTION",
    "P2-NO-LEAKS",
    "P2-PORTABLE-FIXTURE"
)
if ($actualGates.Count -ne $expectedGates.Count -or
    @(Compare-Object `
        -ReferenceObject ($expectedGates | Sort-Object) `
        -DifferenceObject ($actualGates | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "Verify-Installed.ps1 does not emit every exact Phase 2 ledger row."
}

$gateFunction = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq "Set-SteinInstalledGateState"
}, $true))[0]
if ($null -eq $gateFunction -or $null -eq $gateFunction.Body.ParamBlock) {
    throw "Verify-Installed.ps1 has no statically verifiable gate reducer."
}
$statusParameter = @($gateFunction.Body.ParamBlock.Parameters | Where-Object {
    $_.Name.VariablePath.UserPath -ceq "Status"
})[0]
$statusValidateSet = @($statusParameter.Attributes | Where-Object {
    $_.TypeName.FullName -ceq "ValidateSet"
})[0]
$allowedGateStates = @($statusValidateSet.PositionalArguments | ForEach-Object {
    [string]$_.SafeGetValue()
})
if ($allowedGateStates.Count -ne 3 -or
    @(Compare-Object `
        -ReferenceObject @("blocked", "fail", "not_run") `
        -DifferenceObject ($allowedGateStates | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "The installed gate reducer can promote a row outside fail/blocked/not_run."
}
foreach ($command in @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq "Set-SteinInstalledGateState"
        }, $true))) {
    $elements = @($command.CommandElements)
    for ($index = 0; $index -lt $elements.Count; $index++) {
        if ($elements[$index].Extent.Text -cne "-Status") {
            continue
        }
        if ($index + 1 -ge $elements.Count -or
            $elements[$index + 1] -isnot [Management.Automation.Language.StringConstantExpressionAst] -or
            [string]$elements[$index + 1].Value -cnotin @("fail", "blocked", "not_run")) {
            throw "A gate transition uses a dynamic or pass-producing status."
        }
    }
}

$commandNames = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst]
}, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $null -ne $_ })
foreach ($forbiddenCommand in @(
        "Add-AppxPackage", "Remove-AppxPackage",
        "Register-ScheduledTask", "Unregister-ScheduledTask",
        "Start-ScheduledTask", "Stop-ScheduledTask",
        "Start-Process", "Stop-Process",
        "Get-Credential", "Read-Host", "Invoke-Expression")) {
    if ($commandNames -icontains $forbiddenCommand) {
        throw "Verify-Installed.ps1 contains an installed-state mutation or secret-input command."
    }
}

foreach ($required in @(
        "Get-SteinPhase2ReleaseBundle",
        "Get-SteinPhase2InstalledBundle",
        "Assert-SteinPhase2InstalledPackage",
        "Status.ps1",
        "installed_machine_verification_only",
        "complete_acceptance",
        "pass", "fail", "blocked", "not_run",
        "Get-SteinInstalledPathToken",
        "Resolve-SteinInstalledWindowsPowerShell",
        "[Environment+SpecialFolder]::System",
        "windows_powershell_host_unavailable",
        "Get-SteinInstalledBootstrapFileRecord",
        "runtime_source_files",
        "evidence-generator-stability",
        "An evidence output escaped its timestamped directory.",
        "generator_provenance",
        "root-anchor.json",
        "root_digest_sha256",
        "content_integrity_only_not_authentication",
        "Installed evidence directory (repository-relative):",
        "host_provenance",
        "row_artifact",
        "output_artifacts",
        "privacy_reviewed",
        "synthetic_only",
        "redacted_screenshot",
        "native_fixture_result",
        "native-fixture-result-template.json",
        "closed_content_free_schema_verified = `$true",
        "semantic_result_verified_by_harness = `$false",
        "attached_pass_promoted_by_harness = `$false",
        "attachment_files_copied = `$false",
        "provider_credentials_accessed = `$false",
        "private_protocol_snapshot_requested = `$false",
        "installed_state_mutated = `$false")) {
    if ($source.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "Verify-Installed.ps1 is missing a fail-closed evidence invariant."
    }
}
if ($source.IndexOf('Get-Command "powershell.exe"', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "Verify-Installed.ps1 still permits PATH-based Windows PowerShell resolution."
}

$commonPath = Join-Path $PSScriptRoot "Common.ps1"
$commonSource = Get-Content -LiteralPath $commonPath -Raw
foreach ($required in @(
        "System.IO.FileSystemAclExtensions",
        "[IO.Directory]::GetAccessControl",
        "[IO.File]::GetAccessControl",
        "Assert-SteinPhase2InstalledPayloadFiles",
        "Get-SteinPhase2RequiredInstalledPackageRelativePaths",
        "AppxMetadata\CodeIntegrity.cat",
        "The installed package does not contain the exact closed deployed file layout.",
        "An installed package payload file differs from the operator-pinned signed MSIX.")) {
    if ($commonSource.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "Common.ps1 is missing a dual-runtime ACL or installed-payload invariant."
    }
}
foreach ($forbiddenAclCommand in @("Get-Acl", "Set-Acl")) {
    if ($commonSource.IndexOf($forbiddenAclCommand, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Common.ps1 reintroduced module-autoloading ACL commands."
    }
}

$verifySourcePath = Join-Path $PSScriptRoot "Verify-Source.ps1"
$verifySource = Get-Content -LiteralPath $verifySourcePath -Raw
if ($verifySource.IndexOf(
        '"--features", "production-private-endpoint,production-edge-producer"',
        [StringComparison]::Ordinal) -lt 0 -or
    $verifySource.IndexOf("STEIN_EDGE_EXTENSION_VERSION", [StringComparison]::Ordinal) -lt 0 -or
    $verifySource.IndexOf("Resolve-SteinSourceWindowsPowerShell", [StringComparison]::Ordinal) -lt 0 -or
    $verifySource.IndexOf("[Environment+SpecialFolder]::System", [StringComparison]::Ordinal) -lt 0 -or
    $verifySource.IndexOf('Get-Command "powershell.exe"', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "Verify-Source.ps1 is missing an exact production feature or trusted-host invariant."
}

$windowsPowerShellRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$windowsPowerShell = Join-Path $windowsPowerShellRoot "WindowsPowerShell\v1.0\powershell.exe"
$windowsPowerShellItem = Get-Item -LiteralPath $windowsPowerShell -Force -ErrorAction Stop
if ($windowsPowerShellItem.PSIsContainer -or
    (($windowsPowerShellItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
    $windowsPowerShellItem.Length -le 0) {
    throw "The exact Windows PowerShell 5.1 compatibility host is unavailable."
}
$windowsPowerShell = $windowsPowerShellItem.FullName
$compatibilityOutput = @(& $windowsPowerShell `
    -NoLogo `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File $PSCommandPath `
    -WindowsPowerShellCompatibilityChild 2>&1)
$compatibilityExitCode = $LASTEXITCODE
$compatibilityLines = @($compatibilityOutput | ForEach-Object { [string]$_ } |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($compatibilityExitCode -ne 0 -or $compatibilityLines.Count -eq 0) {
    throw "The Windows PowerShell 5.1 ACL/payload compatibility fixture failed."
}
$compatibility = $compatibilityLines[$compatibilityLines.Count - 1] |
    ConvertFrom-Json -ErrorAction Stop
if (-not [bool]$compatibility.verified -or
    [string]$compatibility.powershell_edition -cne "Desktop" -or
    [int]$compatibility.payload_file_count -ne 8 -or
    -not [bool]$compatibility.extra_file_rejected -or
    -not [bool]$compatibility.tamper_rejected -or
    [bool]$compatibility.get_acl_module_autoloaded) {
    throw "The Windows PowerShell 5.1 ACL/payload compatibility result is invalid."
}
foreach ($forbiddenLiteral in @(
        '"Install.ps1"', '"Upgrade.ps1"', '"Uninstall.ps1"', '"Lifecycle.ps1"',
        '"proof --json"', '"snapshot --json"', '"create-goal"', '"shutdown --')) {
    if ($source.IndexOf($forbiddenLiteral, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Verify-Installed.ps1 invokes a mutating or private fixture path by default."
    }
}

$launcher = Get-Content -LiteralPath $launcherPath -Raw
foreach ($required in @(
        'set "STEIN_WINDOWS_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"',
        'if defined PROCESSOR_ARCHITEW6432 set "STEIN_WINDOWS_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"',
        'if not exist "%STEIN_WINDOWS_POWERSHELL%" goto :host_unavailable',
        'STEIN_WINDOWS_POWERSHELL_ATTRIBUTES=%%~aI',
        'STEIN_WINDOWS_POWERSHELL_SIZE=%%~zI',
        'if not defined STEIN_WINDOWS_POWERSHELL_ATTRIBUTES goto :host_unavailable',
        'if not defined STEIN_WINDOWS_POWERSHELL_SIZE goto :host_unavailable',
        'STEIN_WINDOWS_POWERSHELL_ATTRIBUTES:l=',
        'if "%STEIN_WINDOWS_POWERSHELL_SIZE%"=="0" goto :host_unavailable',
        '"%STEIN_WINDOWS_POWERSHELL%" -NoLogo -NoProfile -ExecutionPolicy Bypass',
        '-File "%~dp0Verify-Installed.ps1" %*',
        'exit /b %ERRORLEVEL%',
        ':host_unavailable',
        'exit /b 1')) {
    if ($launcher.IndexOf($required, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Verify-Installed.cmd no longer uses the validated exact Windows PowerShell forwarder."
    }
}
if ($launcher -match '(?im)^\s*powershell\.exe(?:\s|$)' -or
    $launcher.IndexOf("%PATH%", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "Verify-Installed.cmd permits PATH-based Windows PowerShell resolution."
}

[pscustomobject]@{
    verified = $true
    harness = Split-Path -Leaf $harnessPath
    launcher = Split-Path -Leaf $launcherPath
    ledger_gate_count = $actualGates.Count
    installed_mutation_commands = 0
    pass_attachment_auto_promotion = $false
    path_based_executable_resolution = $false
    windows_powershell_acl_compatibility = $true
    installed_extra_file_rejected = $true
    installed_payload_tamper_rejected = $true
}
