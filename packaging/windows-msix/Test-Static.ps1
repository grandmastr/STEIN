[CmdletBinding()]
param([switch] $CleanupTestsOnly)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "PackageTools.ps1")

function Remove-SteinStaticTemporaryLeaf {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $temporaryRoot = Resolve-SteinPackageRegularDirectoryWithAncestors `
        -Path ([IO.Path]::GetTempPath())
    $fullPath = [IO.Path]::GetFullPath($Path)
    $parentPath = [IO.Path]::GetFullPath((Split-Path -Parent $fullPath)).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $leafName = Split-Path -Leaf $fullPath
    if (-not [string]::Equals(
            $parentPath,
            $temporaryRoot,
            [StringComparison]::OrdinalIgnoreCase) -or
        $leafName -notmatch '^stein-[A-Za-z0-9.-]+$') {
        throw "A static-test cleanup target escaped the exact temporary leaf boundary."
    }

    $rootItem = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    $rootIsReparse = (($rootItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0)
    if ($rootIsReparse) {
        if ($rootItem.PSIsContainer) {
            [IO.Directory]::Delete($fullPath, $false)
        }
        else {
            [IO.File]::Delete($fullPath)
        }
        return
    }
    if (-not $rootItem.PSIsContainer) {
        [IO.File]::SetAttributes($fullPath, [IO.FileAttributes]::Normal)
        [IO.File]::Delete($fullPath)
        return
    }

    $pending = New-Object Collections.Generic.Stack[string]
    $directories = New-Object Collections.Generic.List[string]
    $pending.Push($fullPath)
    while ($pending.Count -gt 0) {
        $directoryPath = $pending.Pop()
        $directoryItem = Get-Item `
            -LiteralPath $directoryPath `
            -Force `
            -ErrorAction Stop
        if (-not $directoryItem.PSIsContainer) {
            throw "A static-test cleanup directory changed type."
        }
        if (($directoryItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            [IO.Directory]::Delete($directoryPath, $false)
            continue
        }
        $directories.Add($directoryPath)
        foreach ($candidate in @(Get-ChildItem `
                    -LiteralPath $directoryPath `
                    -Force `
                    -ErrorAction Stop)) {
            $candidatePath = [IO.Path]::GetFullPath($candidate.FullName)
            if (-not $candidatePath.StartsWith(
                    "$fullPath$([IO.Path]::DirectorySeparatorChar)",
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "A static-test cleanup entry escaped its exact temporary leaf."
            }
            $item = Get-Item `
                -LiteralPath $candidatePath `
                -Force `
                -ErrorAction Stop
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                if ($item.PSIsContainer) {
                    [IO.Directory]::Delete($candidatePath, $false)
                }
                else {
                    [IO.File]::Delete($candidatePath)
                }
            }
            elseif ($item.PSIsContainer) {
                $pending.Push($candidatePath)
            }
            else {
                [IO.File]::SetAttributes(
                    $candidatePath,
                    [IO.FileAttributes]::Normal)
                [IO.File]::Delete($candidatePath)
            }
        }
    }
    for ($index = $directories.Count - 1; $index -ge 0; $index--) {
        $directoryPath = $directories[$index]
        $directoryItem = Get-Item `
            -LiteralPath $directoryPath `
            -Force `
            -ErrorAction Stop
        if (-not $directoryItem.PSIsContainer) {
            throw "A static-test cleanup directory changed type."
        }
        [IO.Directory]::Delete($directoryPath, $false)
    }
}

function New-SteinStaticSourceCommandEvidence {
    param(
        [Parameter(Mandatory = $true)][string] $EvidenceRoot,
        [Parameter(Mandatory = $true)] $Registry,
        [Parameter(Mandatory = $true)][string] $RegistrySha256,
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $RunnerPath,
        [Parameter(Mandatory = $true)][string] $CandidateCommit,
        [Parameter(Mandatory = $true)][string] $CandidateTree,
        [Parameter(Mandatory = $true)] $CandidateCommandBinding,
        [Parameter(Mandatory = $true)][string] $GitLauncherSha256,
        [Parameter(Mandatory = $true)][string] $GitResolvedSha256,
        [Parameter(Mandatory = $true)][Collections.IDictionary] $ToolDescriptors,
        [Parameter(Mandatory = $true)][Collections.IDictionary] $FixtureByCheck,
        [Parameter(Mandatory = $true)] $FixtureSuite
    )

    $repositoryPath = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $evidencePath = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $repositoryPrefix = "$repositoryPath$([IO.Path]::DirectorySeparatorChar)"
    if (-not $evidencePath.StartsWith(
            $repositoryPrefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "The synthetic source-command evidence root escaped its repository."
    }
    $evidenceRootRelative = $evidencePath.Substring(
        $repositoryPrefix.Length).Replace('\', '/')
    if ($evidenceRootRelative -cnotmatch
        '^artifacts/evidence/phase-2/source-[A-Za-z0-9._-]{1,96}$') {
        throw "The synthetic source-command evidence root is invalid."
    }

    $receiptDirectory = Join-Path $evidencePath 'source-command-receipts'
    $logDirectory = Join-Path $evidencePath 'source-command-logs'
    foreach ($directory in @($receiptDirectory, $logDirectory)) {
        $null = New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    }
    $runnerSha256 = Get-SteinPackageFileSha256 -Path $RunnerPath
    $commonBindings = [ordered]@{
        candidate_commit = $CandidateCommit
        candidate_tree = $CandidateTree
        candidate_file_count = [long]$CandidateCommandBinding.FileCount
        candidate_manifest_sha256 =
            [string]$CandidateCommandBinding.ManifestSha256
        registry_sha256 = $RegistrySha256
        runner_sha256 = $runnerSha256
        evidence_root_sha256 = Get-SteinPackageTextSha256 `
            -Value $evidenceRootRelative
        git_launcher_sha256 = $GitLauncherSha256
        git_resolved_sha256 = $GitResolvedSha256
    }
    $emptyLogSha256 = Get-SteinPackageTextSha256 -Value ''
    $recordsById = @{}
    $indexDescriptors = New-Object Collections.Generic.List[object]
    foreach ($definition in @($Registry.checks | Where-Object {
                [string]$_.category -cin @(
                    'direct_execution', 'grouped_fixture_execution')
            })) {
        $id = [string]$definition.id
        $category = [string]$definition.category
        $isGrouped = $category -ceq 'grouped_fixture_execution'
        $tool = $ToolDescriptors[[string]$definition.executable_role]
        if ($null -eq $tool) {
            throw "The synthetic source-command executable role is unknown."
        }
        $arguments = @(Get-SteinPhase2SourceCommandExpectedArguments `
                -RegistryCheck $definition `
                -EvidenceRootRelative $evidenceRootRelative)
        $command = [ordered]@{
            executable_role = [string]$definition.executable_role
            executable_name = [string]$tool.Name
            executable_size = [long]$tool.Size
            executable_sha256 = [string]$tool.Sha256
            arguments = @($arguments)
            arguments_sha256 = Get-SteinPhase2SourceCommandArgumentSha256 `
                -Arguments @($arguments)
            working_directory = [string]$definition.working_directory
            environment_profile = [string]$definition.environment_profile
            environment_profile_sha256 =
                Get-SteinPhase2SourceCommandEnvironmentSha256 `
                    -Profile ([string]$definition.environment_profile)
            timeout_seconds = [long]$definition.timeout_seconds
        }
        $executionGroupId = if ($isGrouped) {
            'closed-source-fixture-suite'
        }
        else {
            "direct:$id"
        }
        $logLeaf = if ($isGrouped) {
            'closed-source-fixture-suite'
        }
        else {
            $id
        }
        $logDescriptors = @{}
        foreach ($streamName in @('stdout', 'stderr')) {
            $logName = "$logLeaf.$streamName.txt"
            $logPath = Join-Path $logDirectory $logName
            if (-not (Test-Path -LiteralPath $logPath -PathType Leaf)) {
                [IO.File]::WriteAllText(
                    $logPath,
                    '',
                    [Text.UTF8Encoding]::new($false))
            }
            $logDescriptors[$streamName] = [ordered]@{
                path = "source-command-logs/$logName"
                size = 0L
                sha256 = $emptyLogSha256
            }
        }
        $startedAt = '2026-08-24T00:00:00.0000000Z'
        $completedAt = $startedAt
        $execution = [ordered]@{
            execution_group_id = $executionGroupId
            execution_id = $null
            started_at = $startedAt
            completed_at = $completedAt
            duration_ms = 0L
            exit_code = 0
            failure_code = $null
            stdout = $logDescriptors.stdout
            stderr = $logDescriptors.stderr
        }
        $executionMaterial = [ordered]@{
            execution_group_id = $executionGroupId
            executable_role = [string]$command.executable_role
            executable_sha256 = [string]$command.executable_sha256
            arguments_sha256 = [string]$command.arguments_sha256
            working_directory = [string]$command.working_directory
            environment_profile_sha256 =
                [string]$command.environment_profile_sha256
            started_at = $startedAt
            completed_at = $completedAt
            exit_code = 0L
            failure_code = $null
            stdout = $execution.stdout
            stderr = $execution.stderr
        }
        $execution.execution_id = Get-SteinPhase2EvidenceObjectSha256 `
            -Value $executionMaterial

        $artifacts = @()
        if ($isGrouped) {
            if (-not $FixtureByCheck.Contains($id)) {
                throw "The grouped source-command fixture is unavailable."
            }
            $fixtureRecord = $FixtureByCheck[$id]
            $artifacts = @(
                [ordered]@{
                    role = 'source_fixture_suite_index'
                    size = [long]$FixtureSuite.IndexSize
                    sha256 = [string]$FixtureSuite.IndexSha256
                },
                [ordered]@{
                    role = 'source_fixture_receipt'
                    size = [long]$fixtureRecord.Size
                    sha256 = [string]$fixtureRecord.Sha256
                })
        }
        $bindings = [ordered]@{}
        foreach ($bindingName in $commonBindings.Keys) {
            $bindings[$bindingName] = $commonBindings[$bindingName]
        }
        $bindings.check_definition_sha256 =
            Get-SteinPhase2EvidenceObjectSha256 -Value $definition
        $bindings.execution_group_count = 25
        $receipt = [ordered]@{
            schema_version = 1
            claim = 'closed_source_command_execution_only'
            check_id = $id
            category = $category
            status = 'pass'
            bindings = $bindings
            command = $command
            execution = $execution
            artifacts = @($artifacts)
            obligation_code = $null
            derivation = $null
        }
        $receiptPath = Join-Path $receiptDirectory "$id.receipt.json"
        [IO.File]::WriteAllText(
            $receiptPath,
            ($receipt | ConvertTo-Json -Depth 40),
            [Text.UTF8Encoding]::new($false))
        $receiptItem = Get-Item -LiteralPath $receiptPath -Force -ErrorAction Stop
        $receiptSha256 = Get-SteinPackageFileSha256 -Path $receiptPath
        $receiptDescriptor = [ordered]@{
            check_id = $id
            category = $category
            path = "$id.receipt.json"
            size = [long]$receiptItem.Length
            sha256 = $receiptSha256
        }
        $indexDescriptors.Add($receiptDescriptor)
        $recordsById[$id] = [pscustomobject]@{
            Definition = $definition
            Receipt = $receipt
            ReceiptDescriptor = [ordered]@{
                path = "source-command-receipts/$id.receipt.json"
                size = [long]$receiptItem.Length
                sha256 = $receiptSha256
            }
        }
    }
    $index = [ordered]@{
        schema_version = 1
        claim = 'closed_source_command_receipt_index'
        registry_id = 'stein.phase2.source-command-registry.v1'
        bindings = $commonBindings
        executed_check_count = 37
        execution_group_count = 25
        receipts = $indexDescriptors.ToArray()
    }
    $indexPath = Join-Path $receiptDirectory 'index.json'
    [IO.File]::WriteAllText(
        $indexPath,
        ($index | ConvertTo-Json -Depth 40),
        [Text.UTF8Encoding]::new($false))
    $indexItem = Get-Item -LiteralPath $indexPath -Force -ErrorAction Stop
    return [pscustomobject]@{
        RecordsById = $recordsById
        Index = $index
        IndexDescriptor = [ordered]@{
            path = 'source-command-receipts/index.json'
            size = [long]$indexItem.Length
            sha256 = Get-SteinPackageFileSha256 -Path $indexPath
        }
        RegistrySha256 = $RegistrySha256
        RunnerSha256 = $runnerSha256
        EvidenceRootRelative = $evidenceRootRelative
    }
}

function Copy-SteinStaticJsonValue {
    param([Parameter(Mandatory = $true)] $Value)

    $json = $Value | ConvertTo-Json -Depth 60 -Compress
    $converter = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
    if ($converter.Parameters.ContainsKey('DateKind')) {
        return $json | ConvertFrom-Json -DateKind String -ErrorAction Stop
    }
    return $json | ConvertFrom-Json -ErrorAction Stop
}

function Set-SteinStaticSourceCommandExecutionTimestamp {
    param(
        [Parameter(Mandatory = $true)] $Row,
        [Parameter(Mandatory = $true)][string] $Timestamp
    )

    $receipt = $Row.source_command_receipt
    $execution = $receipt.execution
    $execution.started_at = $Timestamp
    $execution.completed_at = $Timestamp
    $execution.duration_ms = 0L
    $Row.started_at = $Timestamp
    $Row.completed_at = $Timestamp
    $Row.duration_ms = 0L
    $executionMaterial = [ordered]@{
        execution_group_id = [string]$execution.execution_group_id
        executable_role = [string]$receipt.command.executable_role
        executable_sha256 = [string]$receipt.command.executable_sha256
        arguments_sha256 = [string]$receipt.command.arguments_sha256
        working_directory = [string]$receipt.command.working_directory
        environment_profile_sha256 =
            [string]$receipt.command.environment_profile_sha256
        started_at = $Timestamp
        completed_at = $Timestamp
        exit_code = [long]$execution.exit_code
        failure_code = $execution.failure_code
        stdout = $execution.stdout
        stderr = $execution.stderr
    }
    $execution.execution_id = Get-SteinPhase2EvidenceObjectSha256 `
        -Value $executionMaterial
}

function Initialize-SteinCleanupMutationProbe {
    if ($null -ne ('Stein.PackagePrivateCleanupMutationProbe' -as [type])) {
        return
    }
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Stein {
    public static class PackagePrivateCleanupMutationProbe {
        private const UInt32 GenericWrite = 0x40000000;
        private const UInt32 ShareAll = 0x00000007;
        private const UInt32 OpenExisting = 3;
        private const UInt32 BackupSemantics = 0x02000000;
        private const UInt32 OpenReparsePoint = 0x00200000;
        private const UInt32 SetReparsePoint = 0x000900A4;
        private const UInt32 MountPointTag = 0xA0000003;

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
        private static extern bool DeviceIoControl(
            SafeFileHandle device,
            UInt32 controlCode,
            byte[] input,
            UInt32 inputSize,
            IntPtr output,
            UInt32 outputSize,
            out UInt32 bytesReturned,
            IntPtr overlapped);

        private static void PutUInt16(byte[] buffer, int offset, UInt16 value) {
            buffer[offset] = (byte)(value & 0xff);
            buffer[offset + 1] = (byte)(value >> 8);
        }

        private static void PutUInt32(byte[] buffer, int offset, UInt32 value) {
            buffer[offset] = (byte)(value & 0xff);
            buffer[offset + 1] = (byte)((value >> 8) & 0xff);
            buffer[offset + 2] = (byte)((value >> 16) & 0xff);
            buffer[offset + 3] = (byte)((value >> 24) & 0xff);
        }

        public static bool TrySetMountPoint(
                string directoryPath,
                string targetPath,
                out Int32 error) {
            error = 0;
            SafeFileHandle directory = CreateFileW(
                directoryPath,
                GenericWrite,
                ShareAll,
                IntPtr.Zero,
                OpenExisting,
                BackupSemantics | OpenReparsePoint,
                IntPtr.Zero);
            if (directory.IsInvalid) {
                error = Marshal.GetLastWin32Error();
                directory.Dispose();
                return false;
            }
            using (directory) {
                string normalTarget = targetPath.TrimEnd('\\');
                string substituteName = "\\??\\" + normalTarget;
                byte[] substitute = Encoding.Unicode.GetBytes(substituteName);
                byte[] printName = Encoding.Unicode.GetBytes(normalTarget);
                int pathBytes = substitute.Length + 2 + printName.Length + 2;
                int reparseDataLength = 8 + pathBytes;
                if (reparseDataLength > UInt16.MaxValue) {
                    throw new ArgumentException("The mutation target is too long.");
                }
                byte[] buffer = new byte[8 + reparseDataLength];
                PutUInt32(buffer, 0, MountPointTag);
                PutUInt16(buffer, 4, (UInt16)reparseDataLength);
                PutUInt16(buffer, 6, 0);
                PutUInt16(buffer, 8, 0);
                PutUInt16(buffer, 10, (UInt16)substitute.Length);
                PutUInt16(buffer, 12, (UInt16)(substitute.Length + 2));
                PutUInt16(buffer, 14, (UInt16)printName.Length);
                Buffer.BlockCopy(substitute, 0, buffer, 16, substitute.Length);
                Buffer.BlockCopy(
                    printName,
                    0,
                    buffer,
                    16 + substitute.Length + 2,
                    printName.Length);
                UInt32 returned;
                if (!DeviceIoControl(
                        directory,
                        SetReparsePoint,
                        buffer,
                        (UInt32)buffer.Length,
                        IntPtr.Zero,
                        0,
                        out returned,
                        IntPtr.Zero)) {
                    error = Marshal.GetLastWin32Error();
                    return false;
                }
                return true;
            }
        }
    }
}
"@
}

foreach ($unsafeSnapshotPath in @(
        "source/foo:bar.rs",
        "source/CON/file.rs",
        "source/trailing-dot./file.rs",
        "source/trailing-space /file.rs")) {
    if (Test-SteinPackageSafeWindowsRelativePath -Value $unsafeSnapshotPath) {
        throw "The exact candidate snapshot accepted a Windows-unsafe path."
    }
}

$aclFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-acl-static-" + [Guid]::NewGuid().ToString("N"))
try {
    $aclRootItem = New-Item `
        -ItemType Directory `
        -Path $aclFixtureRoot `
        -ErrorAction Stop
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $everyoneSid = [Security.Principal.SecurityIdentifier]::new("S-1-1-0")
    $aclSecurity = Get-SteinPackageFileSystemSecurity -Item $aclRootItem
    $aclSecurity.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($aclSecurity.GetAccessRules(
                $true,
                $true,
                [Security.Principal.SecurityIdentifier]))) {
        $aclSecurity.RemoveAccessRuleSpecific($rule)
    }
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $aclSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $currentSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    $aclSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $everyoneSid,
            [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    Set-SteinPackageFileSystemSecurity `
        -Item $aclRootItem `
        -Security $aclSecurity
    $inheritedBroadDirectory = Join-Path $aclFixtureRoot "inherited-broad"
    $null = New-Item `
        -ItemType Directory `
        -Path $inheritedBroadDirectory `
        -ErrorAction Stop
    $inheritedBroadAclRejected = $false
    try {
        $null = Assert-SteinPackageOwnerOnlyDirectory `
            -Path $inheritedBroadDirectory
    }
    catch { $inheritedBroadAclRejected = $true }
    if (-not $inheritedBroadAclRejected) {
        throw "The private temporary-root ACL contract accepted inherited broad access."
    }
}
finally {
    if (Test-Path -LiteralPath $aclFixtureRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $aclFixtureRoot
    }
}

$hardlinkTargetRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-hardlink-target-" + [Guid]::NewGuid().ToString("N"))
$hardlinkCleanupRoot = $null
$readOnlyHardlinkCleanupRoot = $null
$missingHardlinkPath = $null
$script:SteinMissingHardlinkRaceTriggered = $false
try {
    $null = New-Item `
        -ItemType Directory `
        -Path $hardlinkTargetRoot `
        -ErrorAction Stop
    $hardlinkTarget = Join-Path $hardlinkTargetRoot "survives.lib"
    [IO.File]::WriteAllText(
        $hardlinkTarget,
        "synthetic external hardlink target",
        [Text.UTF8Encoding]::new($false))
    $hardlinkCleanupRoot = New-SteinPackagePrivateTemporaryDirectory `
        -Purpose "build"
    $missingHardlinkPath = Join-Path $hardlinkCleanupRoot "vanishes.lib"
    $null = New-Item `
        -ItemType HardLink `
        -Path $missingHardlinkPath `
        -Target $hardlinkTarget `
        -ErrorAction Stop

    function Get-ChildItem {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)][string] $LiteralPath,
            [switch] $Force
        )

        $entries = @(Microsoft.PowerShell.Management\Get-ChildItem `
                -LiteralPath $LiteralPath `
                -Force:$Force `
                -ErrorAction Stop)
        if (-not $script:SteinMissingHardlinkRaceTriggered -and
            [string]::Equals(
                (ConvertFrom-SteinPackageExtendedLengthPath -Path $LiteralPath),
                [IO.Path]::GetFullPath($hardlinkCleanupRoot),
                [StringComparison]::OrdinalIgnoreCase)) {
            $script:SteinMissingHardlinkRaceTriggered = $true
            [IO.File]::Delete(
                (ConvertTo-SteinPackageExtendedLengthPath `
                    -Path $missingHardlinkPath))
        }
        return $entries
    }

    Remove-SteinPackagePrivateTemporaryDirectory `
        -Path $hardlinkCleanupRoot `
        -Purpose "build"
    $hardlinkCleanupRoot = $null
    if (-not $script:SteinMissingHardlinkRaceTriggered) {
        throw "The private temporary cleanup did not exercise the missing-entry race."
    }
    if ([IO.File]::ReadAllText($hardlinkTarget) -cne
        "synthetic external hardlink target") {
        throw "Private temporary cleanup changed an external hardlink target."
    }

    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath Function:\Get-ChildItem `
        -Force `
        -ErrorAction Stop
    [IO.File]::SetAttributes($hardlinkTarget, [IO.FileAttributes]::ReadOnly)
    $readOnlyHardlinkCleanupRoot = New-SteinPackagePrivateTemporaryDirectory `
        -Purpose "build"
    $readOnlyHardlinkPath = Join-Path `
        $readOnlyHardlinkCleanupRoot `
        "readonly.lib"
    $null = New-Item `
        -ItemType HardLink `
        -Path $readOnlyHardlinkPath `
        -Target $hardlinkTarget `
        -ErrorAction Stop
    Remove-SteinPackagePrivateTemporaryDirectory `
        -Path $readOnlyHardlinkCleanupRoot `
        -Purpose "build"
    $readOnlyHardlinkCleanupRoot = $null
    $hardlinkTargetItem = Get-Item `
        -LiteralPath $hardlinkTarget `
        -Force `
        -ErrorAction Stop
    if (($hardlinkTargetItem.Attributes -band [IO.FileAttributes]::ReadOnly) -eq 0 -or
        [IO.File]::ReadAllText($hardlinkTarget) -cne
            "synthetic external hardlink target") {
        throw "Private temporary cleanup mutated shared hardlink metadata or bytes."
    }
}
finally {
    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath Function:\Get-ChildItem `
        -Force `
        -ErrorAction SilentlyContinue
    if ($null -ne $hardlinkCleanupRoot -and
        (Test-Path -LiteralPath $hardlinkCleanupRoot)) {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $hardlinkCleanupRoot `
            -Purpose "build"
    }
    if ($null -ne $readOnlyHardlinkCleanupRoot -and
        (Test-Path -LiteralPath $readOnlyHardlinkCleanupRoot)) {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $readOnlyHardlinkCleanupRoot `
            -Purpose "build"
    }
    if (Test-Path -LiteralPath $hardlinkTargetRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $hardlinkTargetRoot
    }
    $script:SteinMissingHardlinkRaceTriggered = $false
}

$longPathCleanupRoot = $null
try {
    $longPathCleanupRoot = New-SteinPackagePrivateTemporaryDirectory `
        -Purpose "build"
    $desiredParentLength = 264
    $longDirectorySegmentLength = $desiredParentLength -
        $longPathCleanupRoot.Length - 1
    if ($longDirectorySegmentLength -lt 16 -or
        $longDirectorySegmentLength -gt 200) {
        throw "The long-path cleanup fixture cannot create its bounded parent."
    }
    $longParent = Join-Path `
        $longPathCleanupRoot `
        ("p" * $longDirectorySegmentLength)
    $null = [IO.Directory]::CreateDirectory(
        (ConvertTo-SteinPackageExtendedLengthPath -Path $longParent))
    $longLeafLength = 274 - $longParent.Length - 1
    $longLeaf = ("f" * ($longLeafLength - 4)) + ".lib"
    $longFile = Join-Path $longParent $longLeaf
    if ($longParent.Length -ne 264 -or $longFile.Length -ne 274) {
        throw "The long-path cleanup fixture did not select its exact deep paths."
    }
    $longFileDeletePath = ConvertTo-SteinPackageExtendedLengthPath -Path $longFile
    [IO.File]::WriteAllText(
        $longFileDeletePath,
        "synthetic file under a 264-character directory path",
        [Text.UTF8Encoding]::new($false))
    [IO.File]::SetAttributes(
        $longFileDeletePath,
        [IO.FileAttributes]::ReadOnly)
    if (-not [IO.File]::Exists($longFileDeletePath)) {
        throw "The long-path cleanup fixture was not created."
    }
    Remove-SteinPackagePrivateTemporaryDirectory `
        -Path $longPathCleanupRoot `
        -Purpose "build"
    $longPathCleanupRoot = $null
    if ([IO.File]::Exists($longFileDeletePath)) {
        throw "Private temporary cleanup retained a deep extended-length path."
    }
}
finally {
    if ($null -ne $longPathCleanupRoot -and
        (Test-Path -LiteralPath $longPathCleanupRoot)) {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $longPathCleanupRoot `
            -Purpose "build"
    }
}

$ancestorSwapTargetRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-ancestor-swap-target-" + [Guid]::NewGuid().ToString("N"))
$ancestorSwapCleanupRoot = $null
$script:SteinAncestorSwapAttempted = $false
$script:SteinAncestorSwapRejected = $false
$script:SteinAncestorWriteRejected = $false
try {
    Initialize-SteinCleanupMutationProbe
    $null = New-Item `
        -ItemType Directory `
        -Path $ancestorSwapTargetRoot `
        -ErrorAction Stop
    $externalVictim = Join-Path $ancestorSwapTargetRoot "survives.txt"
    [IO.File]::WriteAllText(
        $externalVictim,
        "synthetic external ancestor-swap victim",
        [Text.UTF8Encoding]::new($false))
    $ancestorSwapCleanupRoot = New-SteinPackagePrivateTemporaryDirectory `
        -Purpose "build"
    $ancestorSwapChild = Join-Path $ancestorSwapCleanupRoot "subdirectory"
    $ancestorSwapBackup = Join-Path $ancestorSwapCleanupRoot "moved-subdirectory"
    $null = New-Item `
        -ItemType Directory `
        -Path $ancestorSwapChild `
        -ErrorAction Stop

    function Get-ChildItem {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)][string] $LiteralPath,
            [switch] $Force
        )

        if (-not $script:SteinAncestorSwapAttempted -and
            [string]::Equals(
                (ConvertFrom-SteinPackageExtendedLengthPath -Path $LiteralPath),
                [IO.Path]::GetFullPath($ancestorSwapChild),
                [StringComparison]::OrdinalIgnoreCase)) {
            $script:SteinAncestorSwapAttempted = $true
            $mutationError = 0
            $mutated = [Stein.PackagePrivateCleanupMutationProbe]::TrySetMountPoint(
                (ConvertTo-SteinPackageExtendedLengthPath -Path $ancestorSwapChild),
                $ancestorSwapTargetRoot,
                [ref]$mutationError)
            if (-not $mutated) {
                if ($mutationError -ne 32) {
                    throw "The in-place reparse mutation failed unexpectedly: $mutationError."
                }
                $script:SteinAncestorWriteRejected = $true
            }
            try {
                [IO.Directory]::Move($ancestorSwapChild, $ancestorSwapBackup)
                $null = New-Item `
                    -ItemType Junction `
                    -Path $ancestorSwapChild `
                    -Target $ancestorSwapTargetRoot `
                    -ErrorAction Stop
            }
            catch {
                $script:SteinAncestorSwapRejected = $true
            }
        }
        $entries = @(Microsoft.PowerShell.Management\Get-ChildItem `
                -LiteralPath $LiteralPath `
                -Force:$Force `
                -ErrorAction Stop)
        return $entries
    }

    Remove-SteinPackagePrivateTemporaryDirectory `
        -Path $ancestorSwapCleanupRoot `
        -Purpose "build"
    $ancestorSwapCleanupRoot = $null
    if (-not $script:SteinAncestorSwapAttempted -or
        -not $script:SteinAncestorSwapRejected -or
        -not $script:SteinAncestorWriteRejected) {
        throw "Private temporary cleanup did not reject an ancestor replacement."
    }
    if ([IO.File]::ReadAllText($externalVictim) -cne
        "synthetic external ancestor-swap victim") {
        throw "Private temporary cleanup followed a replaced ancestor."
    }
}
finally {
    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath Function:\Get-ChildItem `
        -Force `
        -ErrorAction SilentlyContinue
    if ($null -ne $ancestorSwapCleanupRoot -and
        (Test-Path -LiteralPath $ancestorSwapCleanupRoot)) {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $ancestorSwapCleanupRoot `
            -Purpose "build"
    }
    if (Test-Path -LiteralPath $ancestorSwapTargetRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $ancestorSwapTargetRoot
    }
    $script:SteinAncestorSwapAttempted = $false
    $script:SteinAncestorSwapRejected = $false
    $script:SteinAncestorWriteRejected = $false
}

$primaryFailureCleanupRoot = $null
$primaryFailureLock = $null
try {
    $primaryFailureCleanupRoot = New-SteinPackagePrivateTemporaryDirectory `
        -Purpose "build"
    $primaryFailureLockedPath = Join-Path `
        $primaryFailureCleanupRoot `
        "locked.tmp"
    [IO.File]::WriteAllText(
        $primaryFailureLockedPath,
        "synthetic locked cleanup leaf",
        [Text.UTF8Encoding]::new($false))
    $primaryFailureLock = [IO.FileStream]::new(
        $primaryFailureLockedPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $syntheticPrimary = $null
    try {
        throw "STEIN_SYNTHETIC_PRIMARY_FAILURE"
    }
    catch {
        $syntheticPrimary = $_
    }
    $syntheticCleanup = $null
    try {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $primaryFailureCleanupRoot `
            -Purpose "build"
    }
    catch {
        $syntheticCleanup = $_
    }
    if ($null -eq $syntheticCleanup) {
        throw "The primary-error regression did not force cleanup failure."
    }
    $resolvedPrimary = Resolve-SteinPackagePrimaryAndCleanupFailure `
        -PrimaryFailure $syntheticPrimary `
        -CleanupFailure $syntheticCleanup
    if (-not [object]::ReferenceEquals($resolvedPrimary, $syntheticPrimary) -or
        $resolvedPrimary.Exception.Message -cne
            "STEIN_SYNTHETIC_PRIMARY_FAILURE" -or
        [string]::IsNullOrWhiteSpace([string]$resolvedPrimary.Exception.Data[
                'SteinPrivateTemporaryCleanupFailure']) -or
        [string]::IsNullOrWhiteSpace([string]$resolvedPrimary.Exception.Data[
                'SteinPrivateTemporaryCleanupFailureId'])) {
        throw "Private temporary cleanup replaced or failed to attach to the primary error."
    }
    $resolvedCleanupOnly = Resolve-SteinPackagePrimaryAndCleanupFailure `
        -PrimaryFailure $null `
        -CleanupFailure $syntheticCleanup
    if (-not [object]::ReferenceEquals($resolvedCleanupOnly, $syntheticCleanup)) {
        throw "A cleanup-only failure was not retained as authoritative."
    }
}
finally {
    if ($null -ne $primaryFailureLock) {
        $primaryFailureLock.Dispose()
    }
    if ($null -ne $primaryFailureCleanupRoot -and
        (Test-Path -LiteralPath $primaryFailureCleanupRoot)) {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $primaryFailureCleanupRoot `
            -Purpose "build"
    }
}

$junctionTargetRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-junction-target-" + [Guid]::NewGuid().ToString("N"))
$privateCleanupRoot = $null
try {
    $null = New-Item `
        -ItemType Directory `
        -Path $junctionTargetRoot `
        -ErrorAction Stop
    $junctionMarker = Join-Path $junctionTargetRoot "survives.txt"
    [IO.File]::WriteAllText(
        $junctionMarker,
        "external junction target",
        [Text.UTF8Encoding]::new($false))
    $privateCleanupRoot = New-SteinPackagePrivateTemporaryDirectory `
        -Purpose "build"
    $null = New-Item `
        -ItemType Junction `
        -Path (Join-Path $privateCleanupRoot "external-link") `
        -Target $junctionTargetRoot `
        -ErrorAction Stop
    Remove-SteinPackagePrivateTemporaryDirectory `
        -Path $privateCleanupRoot `
        -Purpose "build"
    $privateCleanupRoot = $null
    if (-not (Test-Path -LiteralPath $junctionMarker -PathType Leaf)) {
        throw "Private temporary cleanup traversed an external junction target."
    }
}
finally {
    if ($null -ne $privateCleanupRoot -and
        (Test-Path -LiteralPath $privateCleanupRoot)) {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $privateCleanupRoot `
            -Purpose "build"
    }
    if (Test-Path -LiteralPath $junctionTargetRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $junctionTargetRoot
    }
}

if ($CleanupTestsOnly) {
    Write-Output "Windows MSIX private temporary cleanup tests are valid."
    return
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
. (Join-Path $repoRoot "scripts\windows\phase2\Test-SourceFixture.ps1") `
    -FixtureTestLibraryOnly
$manifestPath = Join-Path $PSScriptRoot "AppxManifest.xml.in"
$contract = Test-SteinManifestContract -ManifestPath $manifestPath
if ($contract.Publisher -cne "{{PUBLISHER}}" -or $contract.Version -cne "{{VERSION}}") {
    throw "Source manifest must require explicit Publisher and version rendering."
}
$staticFamily = Get-ExactPackageFamilyName `
    -PackageName $script:ProductionPackageName `
    -Publisher "CN=STEIN Static Validation"
if ($staticFamily -notmatch "^STEIN\.PersonalIntelligence_[a-hj-km-np-tv-z0-9]{13}$" -or
    "$staticFamily!$script:DesktopApplicationId" -notmatch "!Desktop$" -or
    "$staticFamily!$script:BrokerApplicationId" -notmatch "!PrivateBroker$" -or
    "$staticFamily!$script:BrowserProducerApplicationId" -notmatch "!BrowserObservationProducer$") {
    throw "Windows could not derive the stable PFN/AUMID shape."
}

Add-Type -AssemblyName System.Drawing
$expectedAssets = @{
    "StoreLogo" = 50
    "Square44x44Logo" = 44
    "Square150x150Logo" = 150
}
foreach ($asset in $expectedAssets.GetEnumerator()) {
    $encodedPath = Join-Path $PSScriptRoot "assets\$($asset.Key).png.base64"
    $bytes = [Convert]::FromBase64String((Get-Content -LiteralPath $encodedPath -Raw).Trim())
    $stream = [IO.MemoryStream]::new($bytes, $false)
    try {
        $image = [Drawing.Image]::FromStream($stream, $true, $true)
        try {
            if ($image.RawFormat.Guid -ne [Drawing.Imaging.ImageFormat]::Png.Guid -or
                $image.Width -ne $asset.Value -or
                $image.Height -ne $asset.Value) {
                throw "A package asset is not the required PNG dimension."
            }
        }
        finally {
            $image.Dispose()
        }
    }
    finally {
        $stream.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

$buildScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot "Build-Msix.ps1") -Raw
$cliManifest = Get-Content -LiteralPath (Join-Path $repoRoot "apps\core-cli\Cargo.toml") -Raw
$cliPackageMatch = [regex]::Match(
    $cliManifest,
    '(?m)^name\s*=\s*"(?<name>[a-z0-9_-]+)"\s*$')
if (-not $cliPackageMatch.Success -or
    $cliPackageMatch.Groups["name"].Value -cne "stein-cli" -or
    $buildScript.IndexOf("--package stein-cli", [StringComparison]::Ordinal) -lt 0 -or
    $buildScript.IndexOf("--package stein-core-cli", [StringComparison]::Ordinal) -ge 0 -or
    ([regex]::Matches($buildScript, '(?m)^\s*--locked\b')).Count -ne 3) {
    throw "The signed build does not select the exact Cargo package/lockfile set."
}
$forbiddenCertificateMutations = @(
    "New-SelfSignedCertificate",
    "Import-Certificate",
    "Import-PfxCertificate",
    "certutil -addstore",
    "Add-AppxPackage"
)
foreach ($forbidden in $forbiddenCertificateMutations) {
    if ($buildScript.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Build script contains a forbidden certificate/install mutation."
    }
}
foreach ($required in @(
    "makeappx",
    "signtool",
    "STEIN_CORE_EXECUTABLE_SHA256",
    "STEIN_PRODUCTION_PACKAGE_FAMILY_NAME",
    "STEIN_PRODUCTION_BROKER_AUMID",
    "stein-core-daemon/production-private-endpoint",
    "stein-core-daemon/production-edge-producer",
    "STEIN_EDGE_EXTENSION_ID",
    "STEIN_EDGE_EXTENSION_VERSION",
    "stein-edge-native-host.exe",
    "not_run_requires_direct_edge_launch_fixture",
    "core_executable_file",
    "coreCompanionPath",
    "cli_executable_file",
    "cliCompanionPath",
    "identity_schema_version",
    "msix_size",
    "ExpectedCandidateGitCommit",
    "ExpectedCandidateGitTree",
    "SourceVerificationReportPath",
    "SourceRootAnchorPath",
    "ExpectedSourceVerificationSha256",
    "ExpectedSourceRootAnchorSha256",
    "Get-SteinVerifiedSourceBuildBinding",
    "Get-SteinVerifiedBuildToolchain",
    "New-SteinExactGitCandidateSnapshot",
    "Open-SteinExactCandidateSnapshotLocks",
    "Open-SteinPackageDirectoryManifestLock",
    "Assert-SteinFixedApplicationPayloadMapsEqual",
    "Assert-SteinFixedApplicationPayloadFileIdentity",
    "New-SteinPackageLockedMakeAppxMapping",
    "stein-msix-staging-manifest-v1",
    "stagingLocks",
    "workspaceTargetRoot",
    "desktopDistRoot",
    "candidateRoot",
    "packaging\windows-msix\Verify-Msix.ps1",
    "Publish-SteinVerifiedReleaseArtifactSet",
    "ExpectedSize",
    "ExpectedSha256",
    "packageVerificationResults",
    "verifiedPackageSha256",
    "identityExpectedSha256",
    "browserIdentityExpectedSha256",
    "GitResolvedExecutableSha256",
    "CargoExecutableSha256",
    "RustcExecutableSha256"
)) {
    if ($buildScript.IndexOf($required, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Build script is missing a required fail-closed packaging step."
    }
}

$identityProperties = @(
    "identity_schema_version",
    "package_name",
    "publisher",
    "package_family_name",
    "desktop_aumid",
    "broker_aumid",
    "browser_producer_aumid",
    "version",
    "architecture",
    "signing_certificate_thumbprint",
    "core_executable_file",
    "core_executable_size",
    "core_executable_sha256",
    "browser_host_sha256",
    "candidate_git_commit",
    "candidate_git_tree",
    "source_verification_sha256",
    "source_root_anchor_sha256",
    "source_root_digest_sha256",
    "desktop_executable_size",
    "desktop_executable_sha256",
    "desktop_dist_file_count",
    "desktop_dist_manifest_sha256",
    "cli_executable_file",
    "cli_executable_size",
    "cli_executable_sha256",
    "msix_size",
    "msix_sha256"
)
$identityRecordMatch = [regex]::Match(
    $buildScript,
    '(?ms)\$identityRecord\s*=\s*\[ordered\]\s*@\{(?<body>.*?)^\s*\}')
if (-not $identityRecordMatch.Success) {
    throw "Build script does not contain the expected ordered release identity record."
}
$buildIdentityProperties = @(
    [regex]::Matches(
        $identityRecordMatch.Groups["body"].Value,
        '(?m)^\s*(?<key>[a-z0-9_]+)\s*=') |
        ForEach-Object { $_.Groups["key"].Value }
)
if ($buildIdentityProperties.Count -ne $identityProperties.Count -or
    @(Compare-Object `
        -ReferenceObject ($identityProperties | Sort-Object) `
        -DifferenceObject ($buildIdentityProperties | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "Build-Msix.ps1 does not emit the exact Phase 2 identity schema."
}

$verifyScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot "Verify-Msix.ps1") -Raw
$sourceFixtureRunnerScript = Get-Content `
    -LiteralPath (Join-Path $repoRoot "scripts\windows\phase2\Run-Source-Fixture.ps1") `
    -Raw
foreach ($cleanupFailureContract in @(
        [pscustomobject]@{
            Name = "Build-Msix.ps1"
            Source = $buildScript
            MinimumCount = 2
        },
        [pscustomobject]@{
            Name = "Verify-Msix.ps1"
            Source = $verifyScript
            MinimumCount = 1
        },
        [pscustomobject]@{
            Name = "Run-Source-Fixture.ps1"
            Source = $sourceFixtureRunnerScript
            MinimumCount = 1
        })) {
    if ([regex]::Matches(
            [string]$cleanupFailureContract.Source,
            'Resolve-SteinPackagePrimaryAndCleanupFailure').Count -lt
        [int]$cleanupFailureContract.MinimumCount) {
        throw "$($cleanupFailureContract.Name) does not preserve primary cleanup errors."
    }
}
$bootstrapScriptContracts = @(
    [pscustomobject]@{
        Path = Join-Path $PSScriptRoot "Build-Msix.ps1"
        Source = $buildScript
        Prefix = "Build"
    },
    [pscustomobject]@{
        Path = Join-Path $PSScriptRoot "Verify-Msix.ps1"
        Source = $verifyScript
        Prefix = "Verify"
    }
)
foreach ($bootstrapContract in $bootstrapScriptContracts) {
    $openToken = "Open-Stein$($bootstrapContract.Prefix)BootstrapScriptBinding"
    $assertToken = "Assert-Stein$($bootstrapContract.Prefix)BootstrapScriptBindingStable"
    $dotSourceToken = '. $packageToolsBootstrapBinding.FullPath'
    $openIndex = $bootstrapContract.Source.IndexOf(
        "`$packageToolsBootstrapBinding = $openToken",
        [StringComparison]::Ordinal)
    $dotSourceIndex = $bootstrapContract.Source.IndexOf(
        $dotSourceToken,
        [StringComparison]::Ordinal)
    $finalAssertionIndex = $bootstrapContract.Source.LastIndexOf(
        $assertToken,
        [StringComparison]::Ordinal)
    if ($openIndex -lt 0 -or
        $dotSourceIndex -le $openIndex -or
        $finalAssertionIndex -le $dotSourceIndex) {
        throw "A packaging entrypoint loads PackageTools outside its retained bootstrap lock."
    }

    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $bootstrapContract.Path,
        [ref]$tokens,
        [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) {
        throw "A packaging bootstrap contract did not parse."
    }
    foreach ($functionName in @(
            "Get-Stein$($bootstrapContract.Prefix)BootstrapStreamSha256",
            $openToken,
            $assertToken)) {
        $definition = @($ast.FindAll({
                    param($node)
                    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $functionName
                }, $true))
        if ($definition.Count -ne 1) {
            throw "A packaging bootstrap contract does not define its exact lock helper."
        }
        Invoke-Expression $definition[0].Extent.Text
    }
}

$bootstrapFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-msix-bootstrap-" + [Guid]::NewGuid().ToString("N"))
try {
    $null = New-Item `
        -ItemType Directory `
        -Path $bootstrapFixtureRoot `
        -ErrorAction Stop
    foreach ($prefix in @("Build", "Verify")) {
        $fixturePath = Join-Path $bootstrapFixtureRoot (
            "$($prefix.ToLowerInvariant()).ps1")
        [IO.File]::WriteAllText(
            $fixturePath,
            "Set-StrictMode -Version Latest`n",
            [Text.UTF8Encoding]::new($false))
        $openCommand = Get-Command `
            -Name "Open-Stein${prefix}BootstrapScriptBinding" `
            -CommandType Function `
            -ErrorAction Stop
        $assertCommand = Get-Command `
            -Name "Assert-Stein${prefix}BootstrapScriptBindingStable" `
            -CommandType Function `
            -ErrorAction Stop
        $hashCommand = Get-Command `
            -Name "Get-Stein${prefix}BootstrapStreamSha256" `
            -CommandType Function `
            -ErrorAction Stop

        $binding = & $openCommand -Path $fixturePath
        try {
            $writeWasDenied = $false
            try {
                [IO.File]::WriteAllText(
                    $fixturePath,
                    "throw 'swapped'`n",
                    [Text.UTF8Encoding]::new($false))
            }
            catch {
                $writeWasDenied = $true
            }
            if (-not $writeWasDenied) {
                throw "A packaging bootstrap binding allowed its loaded script to be replaced."
            }
            $null = & $assertCommand -Binding $binding
        }
        finally {
            $binding.Stream.Dispose()
        }

        $mutableStream = [IO.FileStream]::new(
            $fixturePath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite)
        try {
            $mutableBinding = [pscustomobject]@{
                FullPath = $fixturePath
                Length = [long]$mutableStream.Length
                Sha256 = & $hashCommand -Stream $mutableStream
                Stream = $mutableStream
            }
            $writer = [IO.FileStream]::new(
                $fixturePath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Write,
                [IO.FileShare]::ReadWrite)
            try {
                $writer.Position = 0
                $writer.WriteByte(0x58)
                $writer.Flush()
            }
            finally {
                $writer.Dispose()
            }
            $mutationWasRejected = $false
            try {
                $null = & $assertCommand -Binding $mutableBinding
            }
            catch {
                $mutationWasRejected = $true
            }
            if (-not $mutationWasRejected) {
                throw "A packaging bootstrap finalization accepted changed loaded bytes."
            }
        }
        finally {
            $mutableStream.Dispose()
        }
    }
}
finally {
    Remove-SteinStaticTemporaryLeaf -Path $bootstrapFixtureRoot
}
if ($verifyScript.IndexOf("Get-ExactSigningCertificate", [StringComparison]::Ordinal) -ge 0 -or
    $verifyScript.IndexOf("Assert-SteinExactAuthenticodeSignature", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedCoreSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedHostSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedCliSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedDesktopSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedDesktopDistManifestSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedCandidateGitCommit", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedCandidateGitTree", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedSourceVerificationSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedSourceRootAnchorSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("ExpectedSourceRootDigestSha256", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("packageReadLock", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("[IO.FileShare]::Read", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf("Test-SteinCoreBindingContract", [StringComparison]::Ordinal) -lt 0 -or
    $verifyScript.IndexOf(
        "Open-SteinVerifyBootstrapScriptBinding",
        [StringComparison]::Ordinal) -lt 0) {
    throw "MSIX verification must pin the signature without requiring the signing private key."
}
if ($buildScript -cnotmatch '(?m)^\s*identity_schema_version\s*=\s*3\s*$' -or
    $buildScript.IndexOf(
        "New-SteinExactGitCandidateSnapshot",
        [StringComparison]::Ordinal) -lt 0 -or
    $buildScript.IndexOf("--frozen-lockfile", [StringComparison]::Ordinal) -lt 0 -or
    $buildScript.IndexOf(
        "Open-SteinPackageDirectoryManifestLock",
        [StringComparison]::Ordinal) -lt 0 -or
    $buildScript -cnotmatch '(?ms)-GitExecutable\s+\$toolchain\.Git\s*`?\r?\n\s*-ExpectedGitExecutableSha256\s+`?\r?\n\s*\$bootstrapSourceBinding\.GitResolvedExecutableSha256' -or
    ([regex]::Matches(
            $buildScript,
            '--target-dir',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant)).Count -lt 3 -or
    $buildScript.IndexOf('$toolchain.Cargo build', [StringComparison]::Ordinal) -lt 0 -or
    $buildScript.IndexOf('$toolchain.PnpmEntrypoint', [StringComparison]::Ordinal) -lt 0 -or
    $buildScript.IndexOf('--package stein-cli', [StringComparison]::Ordinal) -lt 0 -or
    $buildScript.IndexOf(
        "Open-SteinBuildBootstrapScriptBinding",
        [StringComparison]::Ordinal) -lt 0 -or
    $buildScript -cnotmatch '(?ms)buildScriptBootstrapBinding\.Sha256.*candidateBuildScriptHash.*packageToolsBootstrapBinding\.Sha256.*candidatePackageToolsHash') {
    throw "The signed build does not use schema-3 identity and the private pinned-tree build boundary."
}
$packageToolsSource = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot "PackageTools.ps1") -Raw
$publicationFunctionMatch = [regex]::Match(
    $packageToolsSource,
    '(?ms)^function Publish-SteinVerifiedReleaseArtifactSet\s*\{(?<body>.*?)^function Test-SteinCoreBindingContract')
if (-not $publicationFunctionMatch.Success) {
    throw "The closed release publication helper is unavailable."
}
$publicationFunctionSource = $publicationFunctionMatch.Groups["body"].Value
$publicationLockIndex = $publicationFunctionSource.IndexOf(
    "[IO.FileShare]::Read)",
    [StringComparison]::Ordinal)
$publicationCleanupIndex = $publicationFunctionSource.IndexOf(
    'Remove-Item -LiteralPath $entry.Backup',
    [StringComparison]::Ordinal)
if ($publicationLockIndex -lt 0 -or
    $publicationCleanupIndex -le $publicationLockIndex -or
    $publicationFunctionSource.IndexOf(
        "A published release artifact differs from the verified temporary bytes.",
        [StringComparison]::Ordinal) -lt 0 -or
    $publicationFunctionSource.IndexOf(
        "The verified release is published, but old-backup cleanup is incomplete.",
        [StringComparison]::Ordinal) -lt 0) {
    throw "Release publication does not verify and lock every final before backup cleanup."
}

$provenanceFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-msix-provenance-static-" + [Guid]::NewGuid().ToString("N"))
$groundingSnapshotRoot = $null
$groundingSnapshotLocks = $null
try {
    $null = New-Item -ItemType Directory -Path $provenanceFixtureRoot -ErrorAction Stop
    $nonJsonWhitespaceRejected = $false
    try {
        Assert-SteinPackageJsonUniqueObjectKeys `
            -Text ("{" + [char]0x00A0 + '"value":1}')
    }
    catch {
        $nonJsonWhitespaceRejected = $true
    }
    if (-not $nonJsonWhitespaceRejected) {
        throw "The strict JSON scanner accepted non-JSON Unicode whitespace."
    }
    $sourceReportSpecPath = Join-Path $repoRoot "scripts\windows\phase2\Evidence-Spec.json"
    $sourceReportSpecText = Get-Content -LiteralPath $sourceReportSpecPath -Raw
    $sourceReportSpec = $sourceReportSpecText | ConvertFrom-Json -ErrorAction Stop
    [IO.File]::WriteAllText(
        (Join-Path $provenanceFixtureRoot ".gitignore"),
        "artifacts/`n",
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(
        (Join-Path $provenanceFixtureRoot "candidate.txt"),
        "synthetic-candidate`n",
        [Text.UTF8Encoding]::new($false))
    $syntheticDependencyLocks = @(
        "Cargo.lock",
        "apps/desktop/pnpm-lock.yaml",
        "extensions/edge/pnpm-lock.yaml",
        "apps/edge-native-host/Cargo.lock")
    foreach ($dependencyLockRelativePath in $syntheticDependencyLocks) {
        $dependencyLockPath = Join-Path $provenanceFixtureRoot (
            $dependencyLockRelativePath.Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar))
        $dependencyLockParent = Split-Path -Parent $dependencyLockPath
        if (-not (Test-Path -LiteralPath $dependencyLockParent)) {
            $null = New-Item -ItemType Directory -Path $dependencyLockParent -Force
        }
        [IO.File]::WriteAllText(
            $dependencyLockPath,
            "synthetic lock: $dependencyLockRelativePath`n",
            [Text.UTF8Encoding]::new($false))
    }
    foreach ($generatorRelativePath in @(
            $sourceReportSpec.source_report_contract.required_generator_paths)) {
        $generatorPath = Join-Path $provenanceFixtureRoot (
            ([string]$generatorRelativePath).Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar))
        $generatorParent = Split-Path -Parent $generatorPath
        if (-not (Test-Path -LiteralPath $generatorParent)) {
            $null = New-Item -ItemType Directory -Path $generatorParent -Force
        }
        $generatorText = if ([string]$generatorRelativePath -ceq
            "scripts/windows/phase2/Evidence-Spec.json") {
            $sourceReportSpecText
        }
        elseif ([string]$generatorRelativePath -cin @(
                "scripts/windows/phase2/Source-Command-Registry.json",
                "scripts/windows/phase2/Run-Source-Check.ps1",
                "scripts/windows/phase2/Source-Fixture-Registry.json")) {
            Get-Content -LiteralPath (Join-Path $repoRoot `
                ([string]$generatorRelativePath).Replace(
                    '/',
                    [IO.Path]::DirectorySeparatorChar)) -Raw
        }
        elseif ([string]$generatorRelativePath -cin @(
                "scripts/windows/phase2/Evidence-Contract.ps1",
                "packaging/windows-msix/PackageTools.ps1")) {
            Get-Content -LiteralPath (Join-Path $repoRoot (
                    ([string]$generatorRelativePath).Replace(
                        '/',
                        [IO.Path]::DirectorySeparatorChar))) -Raw
        }
        else {
            "synthetic generator: $generatorRelativePath`n"
        }
        [IO.File]::WriteAllText(
            $generatorPath,
            $generatorText,
            [Text.UTF8Encoding]::new($false))
    }
    $syntheticRegistry = Get-Content `
        -LiteralPath (Join-Path $provenanceFixtureRoot `
            "scripts\windows\phase2\Source-Fixture-Registry.json") `
        -Raw `
        -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $syntheticCommandRegistryPath = Join-Path $provenanceFixtureRoot `
        "scripts\windows\phase2\Source-Command-Registry.json"
    $expectedSourceCommandRegistrySha256 = [string](
        $sourceReportSpec.source_report_contract.source_command_registry_sha256)
    $syntheticCommandRegistryRead = Read-SteinPhase2SourceCommandRegistry `
        -Path $syntheticCommandRegistryPath `
        -ExpectedSha256 $expectedSourceCommandRegistrySha256
    $semanticSourcePaths = @(
        $syntheticRegistry.fixtures | ForEach-Object {
            @($_.semantic_source_paths)
        } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    foreach ($semanticRelativePath in $semanticSourcePaths) {
        $semanticPath = Join-Path $provenanceFixtureRoot (
            $semanticRelativePath.Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar))
        if (Test-Path -LiteralPath $semanticPath) {
            continue
        }
        $semanticParent = Split-Path -Parent $semanticPath
        if (-not (Test-Path -LiteralPath $semanticParent)) {
            $null = New-Item `
                -ItemType Directory `
                -Path $semanticParent `
                -Force `
                -ErrorAction Stop
        }
        [IO.File]::WriteAllText(
            $semanticPath,
            "synthetic semantic source: $semanticRelativePath`n",
            [Text.UTF8Encoding]::new($false))
    }
    $gitCommand = Get-Command git.exe -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    & $gitCommand.Source -C $provenanceFixtureRoot init --quiet
    Assert-NativeCommandSucceeded -Operation "provenance fixture Git initialization"
    & $gitCommand.Source -C $provenanceFixtureRoot config user.name "STEIN Synthetic Fixture"
    Assert-NativeCommandSucceeded -Operation "provenance fixture Git name configuration"
    & $gitCommand.Source -C $provenanceFixtureRoot config user.email "synthetic@example.invalid"
    Assert-NativeCommandSucceeded -Operation "provenance fixture Git email configuration"
    & $gitCommand.Source -C $provenanceFixtureRoot add -- .
    Assert-NativeCommandSucceeded -Operation "provenance fixture Git staging"
    & $gitCommand.Source -C $provenanceFixtureRoot `
        -c commit.gpgsign=false commit --quiet -m "synthetic provenance fixture"
    Assert-NativeCommandSucceeded -Operation "provenance fixture Git commit"

    $gitExecutableDigest = Get-SteinPackageFileSha256 -Path $gitCommand.Source
    $gitFixtureState = Get-SteinCleanGitCandidateState `
        -RepositoryRoot $provenanceFixtureRoot `
        -GitExecutable $gitCommand.Source `
        -ExpectedGitExecutableSha256 $gitExecutableDigest
    $groundingSnapshotRoot = New-SteinPackagePrivateTemporaryDirectory `
        -Purpose "build"
    $groundingSnapshot = New-SteinExactGitCandidateSnapshot `
        -RepositoryRoot $provenanceFixtureRoot `
        -GitExecutable $gitCommand.Source `
        -ExpectedGitExecutableSha256 $gitExecutableDigest `
        -ExpectedCommit $gitFixtureState.Commit `
        -ExpectedTree $gitFixtureState.Tree `
        -BuildRoot $groundingSnapshotRoot
    $groundingSnapshotLocks = Open-SteinExactCandidateSnapshotLocks `
        -Snapshot $groundingSnapshot
    $groundingTreeBinding = Get-SteinPackageSourceFixtureTreeBinding `
        -Snapshot $groundingSnapshot
    $groundingCommandBinding = Get-SteinPackageSourceCommandCandidateBinding `
        -Snapshot $groundingSnapshot
    if ([long]$groundingCommandBinding.FileCount -ne
            [long]$groundingTreeBinding.FileCount -or
        [string]$groundingCommandBinding.ManifestSha256 -cne
            [string]$groundingTreeBinding.ManifestSha256) {
        throw "The signer source-command binding is not the canonical Git tree binding."
    }
    $lineEndingVariantRoots = @(
        (Join-Path ([IO.Path]::GetTempPath()) (
                'stein-command-binding-lf-' + [Guid]::NewGuid().ToString('N')))
        (Join-Path ([IO.Path]::GetTempPath()) (
                'stein-command-binding-crlf-' + [Guid]::NewGuid().ToString('N')))
    )
    try {
        foreach ($variantRoot in $lineEndingVariantRoots) {
            $null = New-Item `
                -ItemType Directory `
                -Path $variantRoot `
                -ErrorAction Stop
        }
        [IO.File]::WriteAllText(
            (Join-Path $lineEndingVariantRoots[0] 'candidate.txt'),
            "synthetic`nline-ending`n",
            [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText(
            (Join-Path $lineEndingVariantRoots[1] 'candidate.txt'),
            "synthetic`r`nline-ending`r`n",
            [Text.UTF8Encoding]::new($false))
        foreach ($variantRoot in $lineEndingVariantRoots) {
            $variantSnapshot = Copy-SteinStaticJsonValue `
                -Value $groundingSnapshot
            $variantSnapshot.Root = $variantRoot
            $variantBinding = Get-SteinPackageSourceCommandCandidateBinding `
                -Snapshot $variantSnapshot
            if ([long]$variantBinding.FileCount -ne
                    [long]$groundingCommandBinding.FileCount -or
                [string]$variantBinding.ManifestSha256 -cne
                    [string]$groundingCommandBinding.ManifestSha256) {
                throw "Raw LF/CRLF checkout bytes changed the canonical Git source-command binding."
            }
        }
    }
    finally {
        foreach ($variantRoot in $lineEndingVariantRoots) {
            if (Test-Path -LiteralPath $variantRoot) {
                Remove-SteinStaticTemporaryLeaf -Path $variantRoot
            }
        }
    }
    $runnerGroundingTreeBinding = Get-SteinSourceFixtureTreeBinding `
        -Snapshot $groundingSnapshot
    if ([long]$runnerGroundingTreeBinding.file_count -ne
            [long]$groundingTreeBinding.FileCount -or
        [string]$runnerGroundingTreeBinding.manifest_sha256 -cne
            [string]$groundingTreeBinding.ManifestSha256) {
        throw "Source-fixture runner and signer candidate-tree bindings diverged."
    }

    $evidenceDirectory = Join-Path $provenanceFixtureRoot "artifacts\evidence\phase-2\source-static"
    $null = New-Item -ItemType Directory -Path $evidenceDirectory -Force -ErrorAction Stop
    $reportPath = Join-Path $evidenceDirectory "source-verification.json"
    $anchorPath = Join-Path $evidenceDirectory "root-anchor.json"
    $chainDigest = "a1" * 32
    $generatorFiles = @(
        $sourceReportSpec.source_report_contract.required_generator_paths |
            ForEach-Object {
                $relative = [string]$_
                $path = Join-Path $provenanceFixtureRoot (
                    $relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
                $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                [ordered]@{
                    path = $relative
                    size = [long]$item.Length
                    sha256 = Get-SteinPackageFileSha256 -Path $item.FullName
                }
            })
    $generatorDigest = Get-SteinPackageTextSha256 `
        -Value ($generatorFiles | ConvertTo-Json -Depth 16 -Compress)
    $rustToolchainId = "synthetic-x86_64-pc-windows-msvc"
    $report = [ordered]@{
        schema_version = 2
        claim = "source_verification_only"
        installed_or_signed_evidence = $false
        passed = $true
        complete_acceptance = $false
        started_at = "2026-08-24T00:00:00.0000000Z"
        completed_at = "2026-08-24T00:01:00.0000000Z"
        host = [ordered]@{}
        provenance = [ordered]@{
            schema_version = 2
            classification = "bounded_content_free_source_provenance"
            repository = [ordered]@{
                head_commit = $gitFixtureState.Commit
                object_format = if ($gitFixtureState.Commit.Length -eq 40) { "sha1" } else { "sha256" }
                clean = $true
                has_staged_changes = $false
                has_unstaged_changes = $false
                tracked_changed_path_count = 0
                untracked_path_count = 0
                porcelain_status_sha256 = $chainDigest
                raw_diff_sha256 = $chainDigest
                tracked_manifest_sha256 = $chainDigest
                untracked_manifest_sha256 = $chainDigest
                state_sha256 = $chainDigest
            }
            toolchain = [ordered]@{
                cargo = [ordered]@{
                    version = "cargo synthetic"
                    executable_sha256 = $gitExecutableDigest
                    rustup_toolchain = $rustToolchainId
                    resolved_version = "cargo synthetic"
                    resolved_executable_sha256 = $gitExecutableDigest
                }
                rustc = [ordered]@{
                    version = "rustc synthetic"
                    executable_sha256 = $gitExecutableDigest
                    rustup_toolchain = $rustToolchainId
                    resolved_version = "rustc synthetic"
                    resolved_executable_sha256 = $gitExecutableDigest
                }
                rustup = [ordered]@{
                    version = "rustup synthetic"
                    executable_sha256 = $gitExecutableDigest
                }
                node = [ordered]@{
                    version = "node synthetic"
                    executable_sha256 = $gitExecutableDigest
                }
                pnpm = [ordered]@{
                    version = "pnpm synthetic"
                    executable_sha256 = $gitExecutableDigest
                    resolved_entrypoint_sha256 = $gitExecutableDigest
                }
                git = [ordered]@{
                    version = "git version synthetic"
                    executable_sha256 = $gitExecutableDigest
                    resolved_version = "git version synthetic"
                    resolved_executable_sha256 = $gitExecutableDigest
                }
                pwsh = [ordered]@{
                    version = "pwsh synthetic"
                    executable_sha256 = $gitExecutableDigest
                    authenticode_status = "valid"
                    signer_subject = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                }
            }
            build_versions = [ordered]@{}
            contract_versions = [ordered]@{}
            dependency_locks = @($syntheticDependencyLocks | ForEach-Object {
                    $relative = [string]$_
                    $path = Join-Path $provenanceFixtureRoot (
                        $relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
                    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    [ordered]@{
                        path = $relative
                        size = [long]$item.Length
                        sha256 = Get-SteinPackageFileSha256 -Path $item.FullName
                    }
                })
        }
        integrity = [ordered]@{
            semantics = "content_integrity_only_not_authentication"
            generator = [ordered]@{
                schema_version = 1
                files = @()
                digest_sha256 = $generatorDigest
            }
            provenance_sha256 = $null
            checks_sha256 = $null
            root_anchor_path = "root-anchor.json"
        }
        checks = @()
        summary = [ordered]@{
            pass = 0
            fail = 0
            not_run = 0
        }
    }
    $report.integrity.generator.files = $generatorFiles
    $provenanceDigest = Get-SteinPackageTextSha256 `
        -Value ($report.provenance | ConvertTo-Json -Depth 16 -Compress)
    $syntheticRegistryPath = Join-Path $provenanceFixtureRoot `
        "scripts\windows\phase2\Source-Fixture-Registry.json"
    $syntheticRegistryRead = Read-SteinSourceFixtureLockedJson `
        -Path $syntheticRegistryPath `
        -MaximumBytes 1048576
    $syntheticFixtureDirectory = Join-Path $evidenceDirectory "source-fixtures"
    $syntheticFixtureSuite = New-SteinSourceFixtureSyntheticSuiteArtifacts `
        -Registry $syntheticRegistryRead.value `
        -RegistrySha256 ([string]$syntheticRegistryRead.sha256) `
        -OutputDirectory $syntheticFixtureDirectory `
        -CandidateGitCommit ([string]$gitFixtureState.Commit) `
        -CandidateGitTree ([string]$gitFixtureState.Tree) `
        -RustupToolchain $rustToolchainId `
        -CargoLauncherSha256 $gitExecutableDigest `
        -CargoResolvedSha256 $gitExecutableDigest `
        -RustcLauncherSha256 $gitExecutableDigest `
        -RustcResolvedSha256 $gitExecutableDigest `
        -RustupVersion "rustup synthetic" `
        -RustupSha256 $gitExecutableDigest `
        -GitLauncherVersion "git version synthetic" `
        -GitLauncherSha256 $gitExecutableDigest `
        -GitResolvedVersion "git version synthetic" `
        -GitResolvedSha256 $gitExecutableDigest `
        -CandidateSnapshot $groundingSnapshot
    foreach ($syntheticFixtureRecord in @($syntheticFixtureSuite.Records)) {
        if ([long]$syntheticFixtureRecord.Receipt.bindings.candidate_tree_file_count -ne
                [long]$groundingTreeBinding.FileCount -or
            [string]$syntheticFixtureRecord.Receipt.bindings.
                candidate_tree_manifest_sha256 -cne
                [string]$groundingTreeBinding.ManifestSha256) {
            throw "A synthetic source-fixture receipt has a divergent candidate-tree binding."
        }
    }
    $syntheticFixtureByCheck = @{}
    foreach ($fixtureRecord in @($syntheticFixtureSuite.Records)) {
        $syntheticFixtureByCheck[
            [string]$fixtureRecord.Fixture.source_check_id] = $fixtureRecord
    }
    $syntheticToolSize = [long](Get-Item `
            -LiteralPath $gitCommand.Source `
            -Force `
            -ErrorAction Stop).Length
    $syntheticSourceCommandTools = @{
        cargo = [pscustomobject]@{
            Name = 'cargo.exe'
            Size = $syntheticToolSize
            Sha256 = $gitExecutableDigest
        }
        pnpm = [pscustomobject]@{
            Name = 'pnpm.cmd'
            Size = $syntheticToolSize
            Sha256 = $gitExecutableDigest
        }
        windows_powershell = [pscustomobject]@{
            Name = 'powershell.exe'
            Size = $syntheticToolSize
            Sha256 = $gitExecutableDigest
        }
        pwsh = [pscustomobject]@{
            Name = 'pwsh.exe'
            Size = $syntheticToolSize
            Sha256 = $gitExecutableDigest
        }
    }
    $syntheticSourceCommandSuite = New-SteinStaticSourceCommandEvidence `
        -EvidenceRoot $evidenceDirectory `
        -Registry $syntheticCommandRegistryRead.value `
        -RegistrySha256 ([string]$syntheticCommandRegistryRead.sha256) `
        -RepositoryRoot $provenanceFixtureRoot `
        -RunnerPath (Join-Path $provenanceFixtureRoot `
            'scripts\windows\phase2\Run-Source-Check.ps1') `
        -CandidateCommit $gitFixtureState.Commit `
        -CandidateTree $gitFixtureState.Tree `
        -CandidateCommandBinding $groundingCommandBinding `
        -GitLauncherSha256 $gitExecutableDigest `
        -GitResolvedSha256 $gitExecutableDigest `
        -ToolDescriptors $syntheticSourceCommandTools `
        -FixtureByCheck $syntheticFixtureByCheck `
        -FixtureSuite $syntheticFixtureSuite
    $frozenSourceCheckReasons = [ordered]@{
        "native-toolchain-provenance" = "Authenticated Rust/rustup/Git/VS/MSVC/Windows SDK/package-tool payload, runtime, sysroot, library, and linker provenance is not implemented."
        "no-leaks-producer-workflow" = "Candidate-owned installed artifact producer is not implemented."
        "pinned-clean-build-environment" = "Authenticated immutable candidate input and fresh dependency, build, and output isolation are not implemented for every source check."
        "portable-runner-attestation" = "Authenticated GitHub artifact attestation tied to repository, workflow, commit, and artifact digest is not implemented."
        "windows-native-ignored-fixtures" = "Requires explicit native-fixture workflow support; interactive native fixtures remain unimplemented source evidence."
    }
    $checks = New-Object Collections.Generic.List[object]
    foreach ($definition in @($syntheticCommandRegistryRead.value.checks)) {
        $checkId = [string]$definition.id
        $category = [string]$definition.category
        if ($category -ceq 'retained_obligation') {
            if (-not $frozenSourceCheckReasons.Contains($checkId)) {
                throw "The static source-report fixture encountered an unknown frozen check."
            }
            $checks.Add([ordered]@{
                    id = $checkId
                    status = 'not_run'
                    reason = [string]$frozenSourceCheckReasons[$checkId]
                })
            continue
        }
        if ($category -ceq 'derived') {
            if ($checkId -ceq 'source-report-command-provenance') {
                $checks.Add([ordered]@{
                        id = $checkId
                        status = 'pass'
                        derivation = 'exact_registry_and_receipt_coverage'
                        registry_sha256 = [string]$syntheticSourceCommandSuite.
                            RegistrySha256
                        runner_sha256 = [string]$syntheticSourceCommandSuite.RunnerSha256
                        executed_check_count = 37
                        execution_group_count = 25
                        source_command_receipt_index =
                            $syntheticSourceCommandSuite.Index
                        source_command_receipt_index_artifact =
                            $syntheticSourceCommandSuite.IndexDescriptor
                        failure_summary = $null
                    })
            }
            elseif ($checkId -ceq 'source-provenance-stability') {
                $checks.Add([ordered]@{
                        id = $checkId
                        status = 'pass'
                        initial_provenance_sha256 = $provenanceDigest
                        completed_provenance_sha256 = $provenanceDigest
                        failure_summary = $null
                    })
            }
            else {
                throw "The static source-report fixture encountered an unknown derived check."
            }
            continue
        }
        $commandRecord = $syntheticSourceCommandSuite.RecordsById[$checkId]
        if ($null -eq $commandRecord) {
            throw "The static source-report fixture is missing a command receipt."
        }
        $receipt = $commandRecord.Receipt
        $row = [ordered]@{
            id = $checkId
            status = 'pass'
            executable = [string]$receipt.command.executable_name
            arguments = @($receipt.command.arguments)
            working_directory = [string]$receipt.command.working_directory
            started_at = [string]$receipt.execution.started_at
            completed_at = [string]$receipt.execution.completed_at
            duration_ms = [long]$receipt.execution.duration_ms
            exit_code = [long]$receipt.execution.exit_code
            failure_summary = $null
            stdout = [ordered]@{
                path = "$([string]$syntheticSourceCommandSuite.EvidenceRootRelative)/$([string]$receipt.execution.stdout.path)"
                size = [long]$receipt.execution.stdout.size
                sha256 = [string]$receipt.execution.stdout.sha256
            }
            stderr = [ordered]@{
                path = "$([string]$syntheticSourceCommandSuite.EvidenceRootRelative)/$([string]$receipt.execution.stderr.path)"
                size = [long]$receipt.execution.stderr.size
                sha256 = [string]$receipt.execution.stderr.sha256
            }
            source_command_receipt = $receipt
            source_command_receipt_artifact = $commandRecord.ReceiptDescriptor
        }
        if ($category -ceq 'grouped_fixture_execution') {
            $fixtureRecord = $syntheticFixtureByCheck[$checkId]
            $row['source_fixture_receipt'] = $fixtureRecord.Receipt
            $row['source_fixture_receipt_artifact'] = [ordered]@{
                path = "source-fixtures/$([string]$fixtureRecord.Name)"
                size = [long]$fixtureRecord.Size
                sha256 = [string]$fixtureRecord.Sha256
            }
            $row['source_fixture_suite_index'] = [ordered]@{
                path = 'source-fixtures/index.json'
                size = [long]$syntheticFixtureSuite.IndexSize
                sha256 = [string]$syntheticFixtureSuite.IndexSha256
            }
        }
        $checks.Add($row)
    }
    $report.checks = $checks.ToArray()
    $report.summary.pass = @($report.checks | Where-Object status -ceq "pass").Count
    $report.summary.not_run = @(
        $report.checks | Where-Object status -ceq "not_run").Count
    if (@($report.checks).Count -ne 44 -or
        [long]$report.summary.pass -ne 39 -or
        [long]$report.summary.fail -ne 0 -or
        [long]$report.summary.not_run -ne 5 -or
        @($report.integrity.generator.files).Count -ne 20) {
        throw "The static source-report fixture has invalid exact coverage."
    }
    $preflightSourceCommandContract = Get-SteinPackageSourceCommandRegistryContract `
        -CandidateRoot $provenanceFixtureRoot `
        -EvidenceSpecification $sourceReportSpec
    $preflightGeneratorByPath = @{}
    foreach ($generatorFile in @($report.integrity.generator.files)) {
        $preflightGeneratorByPath[[string]$generatorFile.path] = $generatorFile
    }
    $preflightSourceCommandBinding = [pscustomobject]@{
        bindings = [pscustomobject]@{
            commit = [pscustomobject]@{
                object_id = $gitFixtureState.Commit
                tree_id = $gitFixtureState.Tree
            }
        }
    }
    $preflightSourceReport = Copy-SteinStaticJsonValue -Value $report
    $null = Assert-SteinPhase2SourceCommandEvidence `
        -EvidenceResult $preflightSourceCommandBinding `
        -SourceReport $preflightSourceReport `
        -EvidenceSpecification $sourceReportSpec `
        -SourceCommandRegistry $preflightSourceCommandContract.Registry `
        -SourceCommandRegistrySha256 `
            ([string]$preflightSourceCommandContract.RegistrySha256) `
        -SourceGeneratorByPath $preflightGeneratorByPath
    $checksDigest = Get-SteinPackageCanonicalSourceChecksDigest `
        -Checks @($report.checks) `
        -FixtureCheckIds @($syntheticFixtureByCheck.Keys)
    $report.integrity.provenance_sha256 = $provenanceDigest
    $report.integrity.checks_sha256 = $checksDigest
    [IO.File]::WriteAllText(
        $reportPath,
        ($report | ConvertTo-Json -Depth 40),
        [Text.UTF8Encoding]::new($false))
    $reportItem = Get-Item -LiteralPath $reportPath -Force -ErrorAction Stop
    $reportDigest = Get-SteinPackageFileSha256 -Path $reportPath
    $rootMaterial = @(
        "stein-phase2-source-evidence-root-v1",
        "source_verification_sha256=$reportDigest",
        "generator_sha256=$generatorDigest",
        "provenance_sha256=$provenanceDigest",
        "checks_sha256=$checksDigest"
    ) -join "`n"
    $rootDigest = Get-SteinPackageTextSha256 -Value $rootMaterial
    $anchor = [ordered]@{
        schema_version = 1
        claim = "source_verification_only"
        integrity_semantics = "content_integrity_only_not_authentication"
        source_verification = [ordered]@{
            path = "source-verification.json"
            size = [long]$reportItem.Length
            sha256 = $reportDigest
        }
        generator_sha256 = $generatorDigest
        provenance_sha256 = $provenanceDigest
        checks_sha256 = $checksDigest
        root_digest_sha256 = $rootDigest
    }
    [IO.File]::WriteAllText(
        $anchorPath,
        ($anchor | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false))
    $anchorDigest = Get-SteinPackageFileSha256 -Path $anchorPath
    $verifiedSourceBinding = Get-SteinVerifiedSourceBuildBinding `
        -RepositoryRoot $provenanceFixtureRoot `
        -CandidateRoot ([string]$groundingSnapshot.Root) `
        -CandidateSnapshot $groundingSnapshot `
        -SourceVerificationReportPath $reportPath `
        -SourceRootAnchorPath $anchorPath `
        -ExpectedSourceVerificationSha256 $reportDigest `
        -ExpectedSourceRootAnchorSha256 $anchorDigest `
        -ExpectedCandidateGitCommit $gitFixtureState.Commit `
        -ExpectedCandidateGitTree $gitFixtureState.Tree
    if ([string]$verifiedSourceBinding.CandidateBindingScope -cne
            "authoritative_locked_snapshot" -or
        $verifiedSourceBinding.CandidateGitCommit -cne $gitFixtureState.Commit -or
        $verifiedSourceBinding.CandidateGitTree -cne $gitFixtureState.Tree -or
        [long]$verifiedSourceBinding.CandidateTreeFileCount -ne
            [long]$groundingTreeBinding.FileCount -or
        [string]$verifiedSourceBinding.CandidateTreeManifestSha256 -cne
            [string]$groundingTreeBinding.ManifestSha256 -or
        $verifiedSourceBinding.SourceRootDigestSha256 -cne $rootDigest) {
        throw "The signed-build source provenance fixture did not reproduce its exact binding."
    }
    $fixtureContract = Get-SteinPackageSourceFixtureRegistryContract `
        -CandidateRoot $provenanceFixtureRoot `
        -EvidenceSpecification $sourceReportSpec
    $commandContract = Get-SteinPackageSourceCommandRegistryContract `
        -CandidateRoot $provenanceFixtureRoot `
        -EvidenceSpecification $sourceReportSpec
    $sourceReportForValidation = Copy-SteinStaticJsonValue -Value $report
    $syntheticGeneratorByPath = @{}
    foreach ($generatorFile in @(
            $sourceReportForValidation.integrity.generator.files)) {
        $syntheticGeneratorByPath[[string]$generatorFile.path] = $generatorFile
    }
    $commandEvidenceArguments = @{
        EvidenceSpecification = $sourceReportSpec
        CommandContract = $commandContract
        SourceGeneratorByPath = $syntheticGeneratorByPath
        RepositoryRoot = $provenanceFixtureRoot
        ReportDirectory = $evidenceDirectory
        ExpectedCandidateGitCommit = $gitFixtureState.Commit
        ExpectedCandidateGitTree = $gitFixtureState.Tree
        CandidateCommandBinding = $groundingCommandBinding
        RequireCandidateGrounding = $true
    }
    $null = Assert-SteinPackageSourceCommandEvidenceFiles `
        -SourceReport $sourceReportForValidation `
        @commandEvidenceArguments
    $wrongCommandBindingArguments = @{}
    foreach ($argumentName in $commandEvidenceArguments.Keys) {
        $wrongCommandBindingArguments[$argumentName] =
            $commandEvidenceArguments[$argumentName]
    }
    $wrongCommandBindingArguments.CandidateCommandBinding = [pscustomobject]@{
        FileCount = [long]$groundingCommandBinding.FileCount
        ManifestSha256 = 'd' * 64
    }
    $wrongCommandBindingRejected = $false
    try {
        $null = Assert-SteinPackageSourceCommandEvidenceFiles `
            -SourceReport $sourceReportForValidation `
            @wrongCommandBindingArguments
    }
    catch {
        $wrongCommandBindingRejected = $true
    }
    if (-not $wrongCommandBindingRejected) {
        throw "The signer accepted a divergent authoritative source-command candidate binding."
    }
    foreach ($gitHashMutation in @(
            [pscustomobject]@{
                Property = 'executable_sha256'
                Value = 'e' * 64
                Description = 'Git launcher hash'
            },
            [pscustomobject]@{
                Property = 'resolved_executable_sha256'
                Value = 'f' * 64
                Description = 'resolved Git payload hash'
            })) {
        $wrongGitSourceReport = Copy-SteinStaticJsonValue `
            -Value $sourceReportForValidation
        $gitHashProperty = [string]$gitHashMutation.Property
        $wrongGitSourceReport.provenance.toolchain.git.$gitHashProperty =
            [string]$gitHashMutation.Value
        $wrongGitHashRejected = $false
        try {
            $null = Assert-SteinPackageSourceCommandEvidenceFiles `
                -SourceReport $wrongGitSourceReport `
                @commandEvidenceArguments
        }
        catch {
            $wrongGitHashRejected = $true
        }
        if (-not $wrongGitHashRejected) {
            throw "The signer accepted a divergent authoritative $([string]$gitHashMutation.Description)."
        }
    }

    $assertSourceCommandMutationRejected = {
        param(
            [Parameter(Mandatory = $true)] $MutatedReport,
            [Parameter(Mandatory = $true)][string] $Description
        )

        $mutatedDigest = Get-SteinPackageCanonicalSourceChecksDigest `
            -Checks @($MutatedReport.checks) `
            -FixtureCheckIds @($fixtureContract.CheckIds)
        if ($mutatedDigest -ceq $checksDigest) {
            throw "A source-command $Description did not change the canonical checks digest."
        }
        $rejected = $false
        try {
            $null = Assert-SteinPackageSourceCommandEvidenceFiles `
                -SourceReport $MutatedReport `
                @commandEvidenceArguments
        }
        catch {
            $rejected = $true
        }
        if (-not $rejected) {
            throw "The signer accepted a source-command $Description."
        }
    }
    $sourceCommandMutationCases = @(
        [pscustomobject]@{
            Description = 'receipt mutation'
            Apply = {
                param($mutated)
                $row = @($mutated.checks | Where-Object {
                        [string]$_.id -ceq 'rust-format'
                    })[0]
                $row.source_command_receipt.command.executable_sha256 = 'e' * 64
            }
        },
        [pscustomobject]@{
            Description = 'argument-vector mutation'
            Apply = {
                param($mutated)
                $row = @($mutated.checks | Where-Object {
                        [string]$_.id -ceq 'rust-format'
                    })[0]
                $row.source_command_receipt.command.arguments[0] = 'check'
            }
        },
        [pscustomobject]@{
            Description = 'group-identity mutation'
            Apply = {
                param($mutated)
                $rows = @($mutated.checks | Where-Object {
                        [string]$_.id -clike 'phase2-source-fixture-*'
                    })
                $rows[1].source_command_receipt.execution.execution_id = 'f' * 64
            }
        },
        [pscustomobject]@{
            Description = 'execution before report start mutation'
            Apply = {
                param($mutated)
                $row = @($mutated.checks | Where-Object {
                        [string]$_.id -ceq 'rust-format'
                    })[0]
                Set-SteinStaticSourceCommandExecutionTimestamp `
                    -Row $row `
                    -Timestamp '2026-08-23T23:59:00.0000000Z'
            }
        },
        [pscustomobject]@{
            Description = 'execution after report completion mutation'
            Apply = {
                param($mutated)
                $row = @($mutated.checks | Where-Object {
                        [string]$_.id -ceq 'rust-format'
                    })[0]
                Set-SteinStaticSourceCommandExecutionTimestamp `
                    -Row $row `
                    -Timestamp '2026-08-24T00:02:00.0000000Z'
            }
        },
        [pscustomobject]@{
            Description = 'candidate binding mutation'
            Apply = {
                param($mutated)
                $row = @($mutated.checks | Where-Object {
                        [string]$_.id -ceq 'rust-format'
                    })[0]
                $row.source_command_receipt.bindings.candidate_manifest_sha256 =
                    'c' * 64
            }
        },
        [pscustomobject]@{
            Description = 'receipt Git launcher binding mutation'
            Apply = {
                param($mutated)
                $row = @($mutated.checks | Where-Object {
                        [string]$_.id -ceq 'rust-format'
                    })[0]
                $row.source_command_receipt.bindings.git_launcher_sha256 =
                    'd' * 64
            }
        },
        [pscustomobject]@{
            Description = 'receipt resolved Git binding mutation'
            Apply = {
                param($mutated)
                $row = @($mutated.checks | Where-Object {
                        [string]$_.id -ceq 'rust-format'
                    })[0]
                $row.source_command_receipt.bindings.git_resolved_sha256 =
                    'c' * 64
            }
        },
        [pscustomobject]@{
            Description = 'receipt-index mutation'
            Apply = {
                param($mutated)
                $row = @($mutated.checks | Where-Object {
                        [string]$_.id -ceq 'source-report-command-provenance'
                    })[0]
                $row.source_command_receipt_index.receipts[0].sha256 = 'b' * 64
            }
        },
        [pscustomobject]@{
            Description = 'oversized-log descriptor mutation'
            Apply = {
                param($mutated)
                $row = @($mutated.checks | Where-Object {
                        [string]$_.id -ceq 'rust-format'
                    })[0]
                $row.source_command_receipt.execution.stdout.size = 16777217L
            }
        })
    foreach ($mutationCase in $sourceCommandMutationCases) {
        $mutatedReport = Copy-SteinStaticJsonValue `
            -Value $sourceReportForValidation
        & $mutationCase.Apply $mutatedReport
        & $assertSourceCommandMutationRejected `
            -MutatedReport $mutatedReport `
            -Description ([string]$mutationCase.Description)
    }

    $sourceCommandFileTamperCases = @(
        [pscustomobject]@{
            Description = 'receipt file tamper'
            Path = Join-Path $evidenceDirectory `
                'source-command-receipts\rust-format.receipt.json'
        },
        [pscustomobject]@{
            Description = 'receipt-index file tamper'
            Path = Join-Path $evidenceDirectory `
                'source-command-receipts\index.json'
        },
        [pscustomobject]@{
            Description = 'log file tamper'
            Path = Join-Path $evidenceDirectory `
                'source-command-logs\rust-format.stdout.txt'
        })
    foreach ($tamperCase in $sourceCommandFileTamperCases) {
        $originalBytes = [IO.File]::ReadAllBytes([string]$tamperCase.Path)
        try {
            [IO.File]::WriteAllText(
                [string]$tamperCase.Path,
                'synthetic-tamper',
                [Text.UTF8Encoding]::new($false))
            $rejected = $false
            try {
                $null = Assert-SteinPackageSourceCommandEvidenceFiles `
                    -SourceReport $sourceReportForValidation `
                    @commandEvidenceArguments
            }
            catch {
                $rejected = $true
            }
            if (-not $rejected) {
                throw "The signer accepted a $([string]$tamperCase.Description)."
            }
        }
        finally {
            [IO.File]::WriteAllBytes([string]$tamperCase.Path, $originalBytes)
            [Array]::Clear($originalBytes, 0, $originalBytes.Length)
        }
    }
    $null = Assert-SteinPackageSourceCommandEvidenceFiles `
        -SourceReport $sourceReportForValidation `
        @commandEvidenceArguments

    $extraFixturePath = Join-Path $syntheticFixtureDirectory `
        'unregistered-extra.json'
    [IO.File]::WriteAllText(
        $extraFixturePath,
        '{}',
        [Text.UTF8Encoding]::new($false))
    try {
        $extraFixtureRejected = $false
        try {
            $null = Assert-SteinPackageSourceCommandEvidenceFiles `
                -SourceReport $sourceReportForValidation `
                @commandEvidenceArguments
        }
        catch {
            $extraFixtureRejected = $true
        }
        if (-not $extraFixtureRejected) {
            throw "The signer accepted an extra source-fixture artifact."
        }
    }
    finally {
        $resolvedExtraFixturePath = [IO.Path]::GetFullPath($extraFixturePath)
        if (-not [string]::Equals(
                (Split-Path -Parent $resolvedExtraFixturePath),
                [IO.Path]::GetFullPath($syntheticFixtureDirectory).TrimEnd(
                    [IO.Path]::DirectorySeparatorChar,
                    [IO.Path]::AltDirectorySeparatorChar),
                [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolvedExtraFixturePath) -cne
                'unregistered-extra.json') {
            throw "The synthetic extra source-fixture cleanup path escaped its directory."
        }
        if (Test-Path -LiteralPath $resolvedExtraFixturePath) {
            [IO.File]::Delete($resolvedExtraFixturePath)
        }
    }

    $sourceFixtureDuplicateKeyCases = @(
        [pscustomobject]@{
            Description = 'source-fixture receipt duplicate key'
            Path = Join-Path $evidenceDirectory (
                "source-fixtures\$([string]$syntheticFixtureSuite.Records[0].Name)")
            MaximumBytes = 4194304L
        },
        [pscustomobject]@{
            Description = 'source-fixture index duplicate key'
            Path = Join-Path $evidenceDirectory 'source-fixtures\index.json'
            MaximumBytes = 1048576L
        })
    foreach ($duplicateKeyCase in $sourceFixtureDuplicateKeyCases) {
        $duplicatePath = [string]$duplicateKeyCase.Path
        $originalBytes = [IO.File]::ReadAllBytes($duplicatePath)
        try {
            $originalJson = [Text.UTF8Encoding]::new($false, $true).GetString(
                $originalBytes)
            $duplicateJson = [regex]::new('^\s*\{').Replace(
                $originalJson,
                "{`n  `"schema_version`": 1,",
                1)
            if ($duplicateJson -ceq $originalJson) {
                throw "A synthetic source-fixture duplicate-key mutation was not applied."
            }
            [IO.File]::WriteAllText(
                $duplicatePath,
                $duplicateJson,
                [Text.UTF8Encoding]::new($false))

            # Duplicate-key rejection precedes descriptor/hash comparison in
            # the locked JSON reader, so unchanged outer descriptors ensure
            # this negative reaches the parser rather than a later hash gate.
            $directParserRejected = $false
            try {
                $null = Read-SteinPackageLockedJson `
                    -Path $duplicatePath `
                    -MaximumBytes ([long]$duplicateKeyCase.MaximumBytes) `
                    -RejectDuplicateKeys `
                    -PreserveDateStrings
            }
            catch {
                $directParserRejected = $true
            }
            $signerRejected = $false
            try {
                $null = Assert-SteinPackageSourceReportCheckContract `
                    -Checks @($sourceReportForValidation.checks) `
                    -Contract $sourceReportSpec.source_report_contract `
                    -FixtureContract $fixtureContract `
                    -CommandContract $commandContract `
                    -SourceReport $sourceReportForValidation `
                    -EvidenceSpecification $sourceReportSpec `
                    -CandidateRoot ([string]$groundingSnapshot.Root) `
                    -CandidateSnapshot $groundingSnapshot `
                    -CandidateTreeBinding $groundingTreeBinding `
                    -RequireCandidateGrounding $true `
                    -RepositoryRoot $provenanceFixtureRoot `
                    -ReportDirectory $evidenceDirectory `
                    -ExpectedCandidateGitCommit $gitFixtureState.Commit `
                    -ExpectedCandidateGitTree $gitFixtureState.Tree
            }
            catch {
                $signerRejected = $true
            }
            if (-not $directParserRejected -or -not $signerRejected) {
                throw "The signer accepted a $([string]$duplicateKeyCase.Description)."
            }
        }
        finally {
            [IO.File]::WriteAllBytes($duplicatePath, $originalBytes)
            [Array]::Clear($originalBytes, 0, $originalBytes.Length)
        }
    }

    $missingCheckRejected = $false
    try {
        $null = Assert-SteinPackageSourceReportCheckContract `
            -Checks @($report.checks | Select-Object -Skip 1) `
            -Contract $sourceReportSpec.source_report_contract `
            -FixtureContract $fixtureContract `
            -CommandContract $commandContract `
            -SourceReport $report `
            -EvidenceSpecification $sourceReportSpec `
            -CandidateRoot ([string]$groundingSnapshot.Root) `
            -CandidateSnapshot $groundingSnapshot `
            -CandidateTreeBinding $groundingTreeBinding `
            -RequireCandidateGrounding $true `
            -RepositoryRoot $provenanceFixtureRoot `
            -ReportDirectory $evidenceDirectory `
            -ExpectedCandidateGitCommit $gitFixtureState.Commit `
            -ExpectedCandidateGitTree $gitFixtureState.Tree
    }
    catch { $missingCheckRejected = $true }
    $duplicateCheckRejected = $false
    try {
        $null = Assert-SteinPackageSourceReportCheckContract `
            -Checks @($report.checks + @($report.checks[0])) `
            -Contract $sourceReportSpec.source_report_contract `
            -FixtureContract $fixtureContract `
            -CommandContract $commandContract `
            -SourceReport $report `
            -EvidenceSpecification $sourceReportSpec `
            -CandidateRoot ([string]$groundingSnapshot.Root) `
            -CandidateSnapshot $groundingSnapshot `
            -CandidateTreeBinding $groundingTreeBinding `
            -RequireCandidateGrounding $true `
            -RepositoryRoot $provenanceFixtureRoot `
            -ReportDirectory $evidenceDirectory `
            -ExpectedCandidateGitCommit $gitFixtureState.Commit `
            -ExpectedCandidateGitTree $gitFixtureState.Tree
    }
    catch { $duplicateCheckRejected = $true }
    $requiredNotRunChecks = @($report.checks | ForEach-Object {
            if ([string]$_.id -ceq
                [string]$sourceReportSpec.source_report_contract.required_pass_check_ids[0]) {
                [ordered]@{
                    id = [string]$_.id
                    status = "not_run"
                    reason = "Synthetic required-check bypass."
                }
            }
            else { $_ }
        })
    $requiredNotRunRejected = $false
    try {
        $null = Assert-SteinPackageSourceReportCheckContract `
            -Checks $requiredNotRunChecks `
            -Contract $sourceReportSpec.source_report_contract `
            -FixtureContract $fixtureContract `
            -CommandContract $commandContract `
            -SourceReport $report `
            -EvidenceSpecification $sourceReportSpec `
            -CandidateRoot ([string]$groundingSnapshot.Root) `
            -CandidateSnapshot $groundingSnapshot `
            -CandidateTreeBinding $groundingTreeBinding `
            -RequireCandidateGrounding $true `
            -RepositoryRoot $provenanceFixtureRoot `
            -ReportDirectory $evidenceDirectory `
            -ExpectedCandidateGitCommit $gitFixtureState.Commit `
            -ExpectedCandidateGitTree $gitFixtureState.Tree
    }
    catch { $requiredNotRunRejected = $true }
    if (-not $missingCheckRejected -or -not $duplicateCheckRejected -or
        -not $requiredNotRunRejected) {
        throw "The signed-build source check catalog accepted an incomplete or downgraded run."
    }
    foreach ($frozenCheckId in @(
            $sourceReportSpec.source_report_contract.allowed_not_run_check_ids)) {
        $forgedChecks = @($report.checks | ForEach-Object {
                if ([string]$_.id -ceq [string]$frozenCheckId) {
                    [ordered]@{
                        id = [string]$frozenCheckId
                        status = 'pass'
                        exit_code = 0
                    }
                }
                else { $_ }
            })
        $frozenPassRejected = $false
        try {
            $null = Assert-SteinPackageSourceReportCheckContract `
                -Checks $forgedChecks `
                -Contract $sourceReportSpec.source_report_contract `
                -FixtureContract $fixtureContract `
                -CommandContract $commandContract `
                -SourceReport $report `
                -EvidenceSpecification $sourceReportSpec `
                -CandidateRoot ([string]$groundingSnapshot.Root) `
                -CandidateSnapshot $groundingSnapshot `
                -CandidateTreeBinding $groundingTreeBinding `
                -RequireCandidateGrounding $true `
                -RepositoryRoot $provenanceFixtureRoot `
                -ReportDirectory $evidenceDirectory `
                -ExpectedCandidateGitCommit $gitFixtureState.Commit `
                -ExpectedCandidateGitTree $gitFixtureState.Tree
        }
        catch { $frozenPassRejected = $true }
        if (-not $frozenPassRejected) {
            throw "The signer accepted a generic PASS for a frozen source check."
        }
    }

    $nestedReceiptChecks = $report.checks |
        ConvertTo-Json -Depth 40 -Compress |
        ConvertFrom-Json -ErrorAction Stop
    $nestedReceiptChecks = @($nestedReceiptChecks)
    $nestedReceiptCheck = @($nestedReceiptChecks | Where-Object {
            [string]$_.id -clike 'phase2-source-fixture-*'
        })[0]
    $nestedReceiptCheck.source_fixture_receipt.bindings.registry_sha256 = "f" * 64
    $nestedReceiptDigest = Get-SteinPackageCanonicalSourceChecksDigest `
        -Checks $nestedReceiptChecks `
        -FixtureCheckIds @($fixtureContract.CheckIds)
    if ($nestedReceiptDigest -ceq $checksDigest) {
        throw "A nested source-fixture mutation did not change the source checks digest."
    }
    $nestedReceiptMutationRejected = $false
    try {
        $null = Assert-SteinPackageSourceReportCheckContract `
            -Checks $nestedReceiptChecks `
            -Contract $sourceReportSpec.source_report_contract `
            -FixtureContract $fixtureContract `
            -CommandContract $commandContract `
            -SourceReport $report `
            -EvidenceSpecification $sourceReportSpec `
            -CandidateRoot ([string]$groundingSnapshot.Root) `
            -CandidateSnapshot $groundingSnapshot `
            -CandidateTreeBinding $groundingTreeBinding `
            -RequireCandidateGrounding $true `
            -RepositoryRoot $provenanceFixtureRoot `
            -ReportDirectory $evidenceDirectory `
            -ExpectedCandidateGitCommit $gitFixtureState.Commit `
            -ExpectedCandidateGitTree $gitFixtureState.Tree
    }
    catch { $nestedReceiptMutationRejected = $true }
    if (-not $nestedReceiptMutationRejected) {
        throw "The signed-build source contract accepted a nested receipt mutation."
    }

    $assertGroundedReceiptMutationRejected = {
        param(
            [Parameter(Mandatory = $true)] $MutatedChecks,
            $Snapshot = $groundingSnapshot,
            $TreeBinding = $groundingTreeBinding
        )
        $rejected = $false
        try {
            $null = Assert-SteinPackageSourceReportCheckContract `
                -Checks $MutatedChecks `
                -Contract $sourceReportSpec.source_report_contract `
                -FixtureContract $fixtureContract `
                -CommandContract $commandContract `
                -SourceReport $report `
                -EvidenceSpecification $sourceReportSpec `
                -CandidateRoot ([string]$groundingSnapshot.Root) `
                -CandidateSnapshot $Snapshot `
                -CandidateTreeBinding $TreeBinding `
                -RequireCandidateGrounding $true `
                -RepositoryRoot $provenanceFixtureRoot `
                -ReportDirectory $evidenceDirectory `
                -ExpectedCandidateGitCommit $gitFixtureState.Commit `
                -ExpectedCandidateGitTree $gitFixtureState.Tree
        }
        catch { $rejected = $true }
        if (-not $rejected) {
            throw "The signed-build source contract accepted a grounded receipt mutation."
        }
    }
    foreach ($nestedMutation in @(
            [pscustomobject]@{
                Description = 'qualified test substitution'
                Apply = {
                    param($check)
                    $check.source_fixture_receipt.executions[0].qualified_test_name =
                        'repository::tests::unrelated_trivial_pass'
                }
            },
            [pscustomobject]@{
                Description = 'zero exact-test matches'
                Apply = {
                    param($check)
                    $check.source_fixture_receipt.executions[0].preflight.exact_test_matches = 0
                }
            },
            [pscustomobject]@{
                Description = 'an empty execution set'
                Apply = {
                    param($check)
                    $check.source_fixture_receipt.executions = @()
                }
            })) {
        $mutatedChecks = $report.checks |
            ConvertTo-Json -Depth 40 -Compress |
            ConvertFrom-Json -ErrorAction Stop
        $mutatedChecks = @($mutatedChecks)
        $mutatedFixtureCheck = @($mutatedChecks | Where-Object {
                [string]$_.id -clike 'phase2-source-fixture-*'
            })[0]
        & $nestedMutation.Apply $mutatedFixtureCheck
        & $assertGroundedReceiptMutationRejected -MutatedChecks $mutatedChecks
    }

    foreach ($groundingMutation in @('semantic_sha256', 'semantic_blob',
            'tree_count', 'tree_manifest')) {
        $mutatedChecks = $report.checks |
            ConvertTo-Json -Depth 40 -Compress |
            ConvertFrom-Json -ErrorAction Stop
        $mutatedChecks = @($mutatedChecks)
        $mutatedFixtureCheck = @($mutatedChecks | Where-Object {
                [string]$_.id -clike 'phase2-source-fixture-*'
            })[0]
        switch ($groundingMutation) {
            'semantic_sha256' {
                $mutatedFixtureCheck.source_fixture_receipt.semantic_sources[0].sha256 =
                    'e' * 64
                $mutatedFixtureCheck.source_fixture_receipt.bindings.semantic_source_manifest_sha256 =
                    Get-SteinPackageTextSha256 -Value (
                        $mutatedFixtureCheck.source_fixture_receipt.semantic_sources |
                            ConvertTo-Json -Depth 16 -Compress)
            }
            'semantic_blob' {
                $mutatedFixtureCheck.source_fixture_receipt.semantic_sources[0].git_blob_object_id =
                    'd' * $gitFixtureState.Commit.Length
                $mutatedFixtureCheck.source_fixture_receipt.bindings.semantic_source_manifest_sha256 =
                    Get-SteinPackageTextSha256 -Value (
                        $mutatedFixtureCheck.source_fixture_receipt.semantic_sources |
                            ConvertTo-Json -Depth 16 -Compress)
            }
            'tree_count' {
                $mutatedFixtureCheck.source_fixture_receipt.bindings.candidate_tree_file_count =
                    [long]$groundingTreeBinding.FileCount + 1
            }
            'tree_manifest' {
                $mutatedFixtureCheck.source_fixture_receipt.bindings.candidate_tree_manifest_sha256 =
                    'c' * 64
            }
        }
        & $assertGroundedReceiptMutationRejected -MutatedChecks $mutatedChecks
    }
    $missingSemanticSnapshot = ($groundingSnapshot |
            ConvertTo-Json -Depth 16 -Compress) |
        ConvertFrom-Json -ErrorAction Stop
    $firstSemanticPath = [string]@(
        $syntheticRegistry.fixtures[0].semantic_source_paths)[0]
    $missingSemanticSnapshot.Files = @($missingSemanticSnapshot.Files | Where-Object {
            [string]$_.RelativePath -cne $firstSemanticPath
        })
    & $assertGroundedReceiptMutationRejected `
        -MutatedChecks @($report.checks) `
        -Snapshot $missingSemanticSnapshot `
        -TreeBinding $groundingTreeBinding

    $wrongEvidenceDigestRejected = $false
    try {
        $null = Get-SteinVerifiedSourceBuildBinding `
            -RepositoryRoot $provenanceFixtureRoot `
            -CandidateRoot ([string]$groundingSnapshot.Root) `
            -CandidateSnapshot $groundingSnapshot `
            -SourceVerificationReportPath $reportPath `
            -SourceRootAnchorPath $anchorPath `
            -ExpectedSourceVerificationSha256 ("f6" * 32) `
            -ExpectedSourceRootAnchorSha256 $anchorDigest `
            -ExpectedCandidateGitCommit $gitFixtureState.Commit `
            -ExpectedCandidateGitTree $gitFixtureState.Tree
    }
    catch {
        $wrongEvidenceDigestRejected = $true
    }
    if (-not $wrongEvidenceDigestRejected) {
        throw "The signed-build source provenance contract accepted a substituted report digest."
    }

    & $gitCommand.Source -C $provenanceFixtureRoot update-index `
        --assume-unchanged candidate.txt
    Assert-NativeCommandSucceeded -Operation "provenance fixture hidden-index setup"
    [IO.File]::WriteAllText(
        (Join-Path $provenanceFixtureRoot "candidate.txt"),
        "hidden-worktree-mutation`n",
        [Text.UTF8Encoding]::new($false))
    $snapshotRoot = New-SteinPackagePrivateTemporaryDirectory -Purpose "build"
    try {
        $snapshotFixture = New-SteinExactGitCandidateSnapshot `
            -RepositoryRoot $provenanceFixtureRoot `
            -GitExecutable $gitCommand.Source `
            -ExpectedGitExecutableSha256 $gitExecutableDigest `
            -ExpectedCommit $gitFixtureState.Commit `
            -ExpectedTree $gitFixtureState.Tree `
            -BuildRoot $snapshotRoot
        if ([IO.File]::ReadAllText(
                (Join-Path $snapshotFixture.Root "candidate.txt")) -cne
            "synthetic-candidate`n") {
            throw "The exact candidate snapshot consumed hidden worktree bytes."
        }
        $snapshotLocks = Open-SteinExactCandidateSnapshotLocks -Snapshot $snapshotFixture
        try {
            [IO.File]::WriteAllText(
                (Join-Path $snapshotFixture.Root "injected.rs"),
                "synthetic insertion",
                [Text.UTF8Encoding]::new($false))
            $insertedFileRejected = $false
            try {
                $unexpectedSnapshot = Open-SteinExactCandidateSnapshotLocks `
                    -Snapshot $snapshotFixture
                foreach ($stream in $unexpectedSnapshot.Streams) { $stream.Dispose() }
            }
            catch { $insertedFileRejected = $true }
            if (-not $insertedFileRejected) {
                throw "The exact candidate snapshot accepted an inserted source file."
            }
        }
        finally {
            foreach ($stream in $snapshotLocks.Streams) { $stream.Dispose() }
        }
    }
    finally {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $snapshotRoot `
            -Purpose "build"
    }
}
finally {
    if ($null -ne $groundingSnapshotLocks) {
        foreach ($stream in @($groundingSnapshotLocks.Streams)) {
            $stream.Dispose()
        }
    }
    if ($null -ne $groundingSnapshotRoot -and
        (Test-Path -LiteralPath $groundingSnapshotRoot)) {
        Remove-SteinPackagePrivateTemporaryDirectory `
            -Path $groundingSnapshotRoot `
            -Purpose "build"
    }
    if (Test-Path -LiteralPath $provenanceFixtureRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $provenanceFixtureRoot
    }
}

$publicationFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-msix-publication-static-" + [Guid]::NewGuid().ToString("N"))
try {
    $null = New-Item -ItemType Directory -Path $publicationFixtureRoot -ErrorAction Stop
    $finalOne = Join-Path $publicationFixtureRoot "one.msix"
    $finalTwo = Join-Path $publicationFixtureRoot "two.json"
    $temporaryOne = Join-Path $publicationFixtureRoot "one.tmp.msix"
    $temporaryTwo = Join-Path $publicationFixtureRoot "two.tmp.json"
    $backupOne = Join-Path $publicationFixtureRoot "one.backup"
    $backupTwo = Join-Path $publicationFixtureRoot "two.backup"
    $publicationEntries = @(
        [pscustomobject]@{
            Temporary = $temporaryOne
            Final = $finalOne
            Backup = $backupOne
            ExpectedSize = $null
            ExpectedSha256 = $null
        },
        [pscustomobject]@{
            Temporary = $temporaryTwo
            Final = $finalTwo
            Backup = $backupTwo
            ExpectedSize = $null
            ExpectedSha256 = $null
        }
    )
    [IO.File]::WriteAllText($finalOne, "old-one", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($finalTwo, "old-two", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($temporaryOne, "new-one", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($temporaryTwo, "new-two", [Text.UTF8Encoding]::new($false))
    foreach ($entry in $publicationEntries) {
        $entry.ExpectedSize = (Get-Item -LiteralPath $entry.Temporary).Length
        $entry.ExpectedSha256 = Get-SteinPackageFileSha256 -Path $entry.Temporary
    }
    $null = Publish-SteinVerifiedReleaseArtifactSet `
        -OutputRoot $publicationFixtureRoot `
        -Entries $publicationEntries
    if ([IO.File]::ReadAllText($finalOne) -cne "new-one" -or
        [IO.File]::ReadAllText($finalTwo) -cne "new-two" -or
        (Test-Path -LiteralPath $temporaryOne) -or
        (Test-Path -LiteralPath $temporaryTwo) -or
        (Test-Path -LiteralPath $backupOne) -or
        (Test-Path -LiteralPath $backupTwo)) {
        throw "Verified release publication did not replace the exact artifact set."
    }

    [IO.File]::WriteAllText($finalOne, "old-one", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($finalTwo, "old-two", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($temporaryOne, "new-one", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($temporaryTwo, "new-two", [Text.UTF8Encoding]::new($false))
    foreach ($entry in $publicationEntries) {
        $entry.ExpectedSize = (Get-Item -LiteralPath $entry.Temporary).Length
        $entry.ExpectedSha256 = Get-SteinPackageFileSha256 -Path $entry.Temporary
    }
    $expectedTemporaryOneSha256 = $publicationEntries[0].ExpectedSha256
    $publicationEntries[0].ExpectedSha256 = "f7" * 32
    $wrongPublicationBytesRejected = $false
    try {
        $null = Publish-SteinVerifiedReleaseArtifactSet `
            -OutputRoot $publicationFixtureRoot `
            -Entries $publicationEntries
    }
    catch {
        $wrongPublicationBytesRejected = $true
    }
    $publicationEntries[0].ExpectedSha256 = $expectedTemporaryOneSha256
    if (-not $wrongPublicationBytesRejected -or
        [IO.File]::ReadAllText($finalOne) -cne "old-one" -or
        [IO.File]::ReadAllText($finalTwo) -cne "old-two") {
        throw "Release publication accepted unverified temporary bytes."
    }
    $lockedTemporary = [IO.FileStream]::new(
        $temporaryTwo,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $publicationFailureRejected = $false
    try {
        $null = Publish-SteinVerifiedReleaseArtifactSet `
            -OutputRoot $publicationFixtureRoot `
            -Entries $publicationEntries
    }
    catch {
        $publicationFailureRejected = $true
    }
    finally {
        $lockedTemporary.Dispose()
    }
    if (-not $publicationFailureRejected -or
        [IO.File]::ReadAllText($finalOne) -cne "old-one" -or
        [IO.File]::ReadAllText($finalTwo) -cne "old-two" -or
        (Test-Path -LiteralPath $backupOne) -or
        (Test-Path -LiteralPath $backupTwo)) {
        throw "Controlled release publication failure did not restore the previous artifact set."
    }
}
finally {
    if (Test-Path -LiteralPath $publicationFixtureRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $publicationFixtureRoot
    }
}

$toastActivationSource = Get-Content -LiteralPath (
    Join-Path $repoRoot "apps\desktop\src-tauri\src\toast_activation.rs") -Raw
foreach ($required in @(
        "3DB3B5B0-1BA5-49D1-A8F0-CF2B3EA6D781",
        "0x3db3b5b0_1ba5_49d1_a8f0_cf2b3ea6d781",
        "INotificationActivationCallback",
        "current_desktop_aumid",
        "action=open&intervention=",
        "resolve_toast_activation",
        "-ToastActivated")) {
    if ($toastActivationSource.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The packaged toast activator source is missing a pinned identity or routing invariant."
    }
}
foreach ($forbidden in @(
        "std::env::args().nth",
        "activationType=protocol",
        "GetCurrentPackageFullName")) {
    if ($toastActivationSource.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The packaged toast activator contains an unapproved argument or identity path."
    }
}
$notificationSource = Get-Content -LiteralPath (
    Join-Path $repoRoot "crates\stein-platform-windows\src\notification.rs") -Raw
foreach ($required in @(
        'action=open&intervention={intervention_id}',
        'activationType=\"foreground\"')) {
    if ($notificationSource.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The native notification payload no longer matches the packaged activation contract."
    }
}
foreach ($forbidden in @('activationType=\"protocol\"', 'stein://')) {
    if ($notificationSource.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The native notification payload contains an unapproved activation route."
    }
}

$pixelSource = Get-Content -LiteralPath (
    Join-Path $repoRoot "crates\stein-platform-windows\src\pixel.rs") -Raw
$observationSource = Get-Content -LiteralPath (
    Join-Path $repoRoot "crates\stein-platform-windows\src\observation.rs") -Raw
foreach ($required in @(
        "GraphicsCapturePicker",
        "IInitializeWithWindow",
        "PeekMessageW",
        'PIXEL_BINDING_PREFIX: &str = "winpixel:v1:"',
        "CreateFreeThreaded",
        "SetIsCursorCaptureEnabled(false)",
        "MAXIMUM_TRANSIENT_PIXEL_BYTES",
        "current_native_presence",
        "CaptureWorkerLease")) {
    if ($pixelSource.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The native pixel adapter is missing a picker, boundary, or transient-lifetime invariant."
    }
}
foreach ($required in @(
        "ObserveScreenPixels",
        "ResourceKind::ScreenRegion",
        "ObservationRetention::SingleOperation",
        "structured_scope_precedes_pixels",
        "mark_external_structured_source_active")) {
    if ($observationSource.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The Windows observation adapter is missing a pixel authority or minimization invariant."
    }
}
foreach ($forbidden in @(
        "TryCreateFromWindowId",
        "TryCreateFromDisplayId",
        "SetIsBorderRequired(false)",
        "GraphicsCaptureAccessKind::Programmatic",
        ".DisplayName()")) {
    if (($pixelSource + $observationSource).IndexOf(
            $forbidden,
            [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The pixel adapter contains an unapproved programmatic, borderless, or label-bearing capture path."
    }
}
$manifestSource = Get-Content -LiteralPath $manifestPath -Raw
foreach ($forbidden in @(
        "graphicsCaptureProgrammatic",
        "graphicsCaptureWithoutBorder")) {
    if ($manifestSource.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The package requests a broader graphics-capture capability than the picker-only daemon path."
    }
}

$phase2LifecycleRoot = Join-Path $repoRoot "scripts\windows\phase2"
$phase2PowerShell = @(
    "Common.ps1",
    "Lifecycle.ps1",
    "Install.ps1",
    "Upgrade.ps1",
    "Status.ps1",
    "Uninstall.ps1",
    "Source-Evidence.ps1",
    "Evidence-Contract.ps1",
    "Run-Source-Check.ps1",
    "Run-Source-Fixture.ps1",
    "Scan-NoLeaks.ps1",
    "Verify-Source.ps1",
    "Verify-Installed.ps1",
    "Review-Installed.ps1",
    "Test-SourceCommand.ps1",
    "Test-VerifySource.ps1",
    "Test-VerifyInstalled.ps1",
    "Test-SourceFixture.ps1",
    "Test-ScanNoLeaks.ps1",
    "Test-ReviewInstalled.ps1"
)
$phase2Launchers = @(
    "Install.cmd",
    "Upgrade.cmd",
    "Status.cmd",
    "Uninstall.cmd",
    "Verify-Source.cmd",
    "Verify-Installed.cmd",
    "Review-Installed.cmd"
)
$phase2EvidenceFiles = @(
    "Evidence-Spec.json",
    "Source-Command-Registry.json",
    "Source-Fixture-Registry.json",
    "Scan-NoLeaks.cmd"
)
foreach ($leaf in $phase2PowerShell + $phase2Launchers + $phase2EvidenceFiles + @("README.md")) {
    if (-not (Test-Path -LiteralPath (Join-Path $phase2LifecycleRoot $leaf) -PathType Leaf)) {
        throw "The Phase 2 lifecycle is missing $leaf."
    }
}
foreach ($leaf in $phase2PowerShell) {
    $path = Join-Path $phase2LifecycleRoot $leaf
    $tokens = $null
    $parseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$parseErrors)
    if (@($parseErrors).Count -ne 0) {
        throw "A Phase 2 lifecycle PowerShell script does not parse."
    }
    $source = Get-Content -LiteralPath $path -Raw
    foreach ($forbidden in @(
            "New-SelfSignedCertificate",
            "Import-Certificate",
            "Import-PfxCertificate",
            "certutil -addstore",
            "Set-ExecutionPolicy",
            "-AllUsers",
            "RunLevel Highest",
            "ServiceAccount")) {
        if ($source.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "A Phase 2 lifecycle script contains a forbidden privilege/certificate mutation."
        }
    }
}
foreach ($leaf in $phase2Launchers) {
    $source = Get-Content -LiteralPath (Join-Path $phase2LifecycleRoot $leaf) -Raw
    $scriptLeaf = [IO.Path]::ChangeExtension($leaf, ".ps1")
    foreach ($requiredLauncherFragment in @(
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
            "-File `"%~dp0$scriptLeaf`" %*",
            'exit /b %ERRORLEVEL%',
            ':host_unavailable',
            'exit /b 1')) {
        if ($source.IndexOf(
                $requiredLauncherFragment,
                [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "A Phase 2 launcher does not use the validated exact Windows PowerShell host."
        }
    }
    if ($source -match '(?im)^\s*powershell\.exe(?:\s|$)' -or
        $source.IndexOf("%PATH%", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "A Phase 2 launcher permits PATH-based Windows PowerShell resolution."
    }
}
$noLeaksLauncherSource = Get-Content `
    -LiteralPath (Join-Path $phase2LifecycleRoot "Scan-NoLeaks.cmd") `
    -Raw
foreach ($requiredNoLeaksLauncherFragment in @(
        'set "STEIN_NO_LEAKS_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"',
        'if defined PROCESSOR_ARCHITEW6432 set "STEIN_NO_LEAKS_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"',
        'if not exist "%STEIN_NO_LEAKS_POWERSHELL%" goto :host_unavailable',
        'STEIN_NO_LEAKS_POWERSHELL_ATTRIBUTES=%%~aI',
        'STEIN_NO_LEAKS_POWERSHELL_SIZE=%%~zI',
        'if not defined STEIN_NO_LEAKS_POWERSHELL_ATTRIBUTES goto :host_unavailable',
        'if not defined STEIN_NO_LEAKS_POWERSHELL_SIZE goto :host_unavailable',
        'STEIN_NO_LEAKS_POWERSHELL_ATTRIBUTES:l=',
        'if "%STEIN_NO_LEAKS_POWERSHELL_SIZE%"=="0" goto :host_unavailable',
        '"%STEIN_NO_LEAKS_POWERSHELL%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scan-NoLeaks.ps1" %*',
        'exit /b %ERRORLEVEL%',
        ':host_unavailable',
        'exit /b 1')) {
    if ($noLeaksLauncherSource.IndexOf(
            $requiredNoLeaksLauncherFragment,
            [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "The no-leaks scanner launcher does not use the validated exact Windows PowerShell host."
    }
}
if ($noLeaksLauncherSource -match '(?im)^\s*powershell\.exe(?:\s|$)' -or
    $noLeaksLauncherSource.IndexOf("%PATH%", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "The no-leaks scanner launcher permits PATH-based Windows PowerShell resolution."
}

$launcherPathPoisonRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-launcher-path-poison-" + [Guid]::NewGuid().ToString("N"))
$originalLauncherPath = $env:PATH
try {
    $null = New-Item -ItemType Directory -Path $launcherPathPoisonRoot -ErrorAction Stop
    $fakePowerShell = Join-Path $launcherPathPoisonRoot "powershell.exe"
    [IO.File]::WriteAllText($fakePowerShell, "synthetic-path-poison")
    $env:PATH = "$launcherPathPoisonRoot$([IO.Path]::PathSeparator)$originalLauncherPath"
    $discoveredPowerShell = (Get-Command `
        "powershell.exe" `
        -CommandType Application `
        -ErrorAction Stop | Select-Object -First 1).Source
    if (-not [string]::Equals(
            $discoveredPowerShell,
            $fakePowerShell,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "The launcher PATH-poisoning negative fixture did not control command discovery."
    }
    $commandHost = Join-Path (
        [Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "cmd.exe"
    foreach ($leaf in $phase2Launchers) {
        $launcherPath = Join-Path $phase2LifecycleRoot $leaf
        $launcherArguments = '"' + $launcherPath + '" -?'
        $null = @(& $commandHost /d /c $launcherArguments 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "A Phase 2 launcher executed a PATH-poisoned Windows PowerShell host."
        }
    }
}
finally {
    $env:PATH = $originalLauncherPath
    if (Test-Path -LiteralPath $launcherPathPoisonRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $launcherPathPoisonRoot
    }
}

$installedEvidenceStatic = & (Join-Path $phase2LifecycleRoot "Test-VerifyInstalled.ps1")
if ($null -eq $installedEvidenceStatic -or
    -not [bool]$installedEvidenceStatic.verified -or
    [int]$installedEvidenceStatic.ledger_gate_count -ne 32 -or
    [int]$installedEvidenceStatic.installed_mutation_commands -ne 0 -or
    [bool]$installedEvidenceStatic.pass_attachment_auto_promotion -or
    [bool]$installedEvidenceStatic.path_based_executable_resolution -or
    -not [bool]$installedEvidenceStatic.windows_powershell_acl_compatibility -or
    -not [bool]$installedEvidenceStatic.installed_extra_file_rejected -or
    -not [bool]$installedEvidenceStatic.installed_payload_tamper_rejected -or
    -not [bool]$installedEvidenceStatic.generic_zero_exit_json_rejected -or
    -not [bool]$installedEvidenceStatic.evidence_spec_swap_rejected -or
    -not [bool]$installedEvidenceStatic.closed_runner_order_enforced -or
    -not [bool]$installedEvidenceStatic.no_leaks_pair_mismatch_rejected -or
    -not [bool]$installedEvidenceStatic.runtime_source_swap_rejected -or
    -not [bool]$installedEvidenceStatic.exact_gate_evidence_contract) {
    throw "The Phase 2 installed-evidence harness failed its static contract."
}

$noLeaksScannerTestHost = Join-Path (
    [Environment]::GetFolderPath([Environment+SpecialFolder]::System)) (
    "WindowsPowerShell\v1.0\powershell.exe")
$noLeaksScannerStatic = @(& $noLeaksScannerTestHost `
        -NoLogo `
        -NoProfile `
        -ExecutionPolicy Bypass `
        -File (Join-Path $phase2LifecycleRoot "Test-ScanNoLeaks.ps1") 2>&1)
$noLeaksScannerExitCode = $LASTEXITCODE
$noLeaksScannerStaticText = ($noLeaksScannerStatic | Out-String).Trim()
if ($noLeaksScannerExitCode -ne 0 -or $noLeaksScannerStaticText -cne
    "P2-NO-LEAKS synthetic scanner contract tests passed on both PowerShell hosts.") {
    throw "The Phase 2 no-leaks scanner failed its static contract."
}

$reviewerStaticJson = (& (Join-Path $phase2LifecycleRoot "Test-ReviewInstalled.ps1") |
        Out-String).Trim()
$reviewerStatic = $reviewerStaticJson | ConvertFrom-Json -ErrorAction Stop
if ($null -eq $reviewerStatic -or
    -not [bool]$reviewerStatic.verified -or
    [int]$reviewerStatic.exact_gate_count -ne 32 -or
    -not [bool]$reviewerStatic.frozen_baseline_incomplete -or
    -not [bool]$reviewerStatic.reviewer_runtime_source_swap_rejected -or
    [int]$reviewerStatic.negative_case_count -lt 28 -or
    [int]$reviewerStatic.installed_state_mutations -ne 0) {
    throw "The Phase 2 installed-evidence reviewer failed its static contract."
}

$sourceEvidenceStatic = & (Join-Path $phase2LifecycleRoot "Test-VerifySource.ps1")
if ($null -eq $sourceEvidenceStatic -or
    -not [bool]$sourceEvidenceStatic.verified -or
    [int]$sourceEvidenceStatic.report_schema_version -ne 2 -or
    [int]$sourceEvidenceStatic.provenance_schema_version -ne 2 -or
    [int]$sourceEvidenceStatic.generator_file_count -ne 20 -or
    [int]$sourceEvidenceStatic.source_report_check_count -ne 44 -or
    [int]$sourceEvidenceStatic.source_report_required_pass_count -ne 39 -or
    [int]$sourceEvidenceStatic.source_report_allowed_not_run_count -ne 5 -or
    -not [bool]$sourceEvidenceStatic.source_report_contract_bound -or
    [string]$sourceEvidenceStatic.source_command_registry_sha256 -cne
        "9a1bb265a11a3b7ca18d1e8b67a2b1c47f9cb090910a458ca3d41fb221b50cbc" -or
    [int]$sourceEvidenceStatic.source_command_registry_row_count -ne 44 -or
    [int]$sourceEvidenceStatic.source_command_executed_receipt_count -ne 37 -or
    [int]$sourceEvidenceStatic.source_command_execution_group_count -ne 25 -or
    -not [bool]$sourceEvidenceStatic.source_command_tamper_contracts_bound -or
    -not [bool]$sourceEvidenceStatic.source_command_runner_library_bound -or
    -not [bool]$sourceEvidenceStatic.source_command_test_parsed -or
    -not [bool]$sourceEvidenceStatic.gate_specific_source_mapping_bound -or
    -not [bool]$sourceEvidenceStatic.repository_state_content_free -or
    -not [bool]$sourceEvidenceStatic.generated_outputs_ignored -or
    [int]$sourceEvidenceStatic.toolchain_version_count -ne 7 -or
    -not [bool]$sourceEvidenceStatic.dual_reviewer_shell_contract -or
    -not [bool]$sourceEvidenceStatic.pwsh_path_poison_rejected -or
    -not [bool]$sourceEvidenceStatic.trusted_pwsh_resolved -or
    -not [bool]$sourceEvidenceStatic.generator_reparse_ancestor_rejected -or
    -not [bool]$sourceEvidenceStatic.tool_reparse_ancestor_rejected -or
    [int]$sourceEvidenceStatic.migration_identifier_count -lt 11 -or
    [string]$sourceEvidenceStatic.protocol_version -notmatch '^[0-9]+\.[0-9]+$' -or
    [string]::IsNullOrWhiteSpace([string]$sourceEvidenceStatic.policy_profile) -or
    -not [bool]$sourceEvidenceStatic.deterministic_root_anchor -or
    -not [bool]$sourceEvidenceStatic.bootstrap_source_swap_rejected -or
    -not [bool]$sourceEvidenceStatic.bootstrap_role_set_closed) {
    throw "The Phase 2 source-evidence harness failed its static contract."
}

$phase2Common = Get-Content -LiteralPath (Join-Path $phase2LifecycleRoot "Common.ps1") -Raw
$phase2Lifecycle = Get-Content -LiteralPath (Join-Path $phase2LifecycleRoot "Lifecycle.ps1") -Raw
$phase2Uninstall = Get-Content -LiteralPath (Join-Path $phase2LifecycleRoot "Uninstall.ps1") -Raw
$commonIdentityMatch = [regex]::Match(
    $phase2Common,
    '(?ms)Description\s+"The release identity record"\s+`?\s*-ExpectedProperties\s+@\((?<body>.*?)^\s*\)')
if (-not $commonIdentityMatch.Success) {
    throw "Common.ps1 does not contain the closed release identity schema."
}
$commonIdentityProperties = @(
    [regex]::Matches($commonIdentityMatch.Groups["body"].Value, '"(?<key>[a-z0-9_]+)"') |
        ForEach-Object { $_.Groups["key"].Value }
)
if ($commonIdentityProperties.Count -ne $identityProperties.Count -or
    @(Compare-Object `
        -ReferenceObject ($identityProperties | Sort-Object) `
        -DifferenceObject ($commonIdentityProperties | Sort-Object) `
        -CaseSensitive).Count -ne 0) {
    throw "Build-Msix.ps1 and Common.ps1 do not share the exact release identity schema."
}
foreach ($required in @(
        "Get-SteinPhase2ReleaseBundle",
        "Assert-SteinExactAuthenticodeSignature",
        "Get-ExactPackageFamilyName",
        "desktop_aumid",
        "broker_aumid",
        "Assert-SteinPhase2OwnerOnlyTree",
        "Assert-SteinPhase2PersistenceReadyStatus",
        "durable_persistence",
        "STEIN:model-route:",
        "New-SteinPhase2ColdRecoveryCopy")) {
    if (($phase2Common + $phase2Lifecycle).IndexOf(
            $required,
            [StringComparison]::Ordinal) -lt 0) {
        throw "The Phase 2 lifecycle is missing a required trust/recovery invariant."
    }
}
foreach ($required in @(
        "Add-AppxPackage",
        "ForceApplicationShutdown",
        "ForceUpdateFromAnyVersion",
        "Register-SteinPhase2Task",
        '-Argument "--installed"',
        "AllowStartIfOnBatteries",
        "DontStopIfGoingOnBatteries",
        "MultipleInstances IgnoreNew")) {
    if (($phase2Common + $phase2Lifecycle).IndexOf(
            $required,
            [StringComparison]::Ordinal) -lt 0) {
        throw "The Phase 2 lifecycle is missing a required package/task invariant."
    }
}
if ($phase2Uninstall.IndexOf("Remove-AppxPackage", [StringComparison]::Ordinal) -lt 0 -and
    $phase2Lifecycle.IndexOf("Remove-AppxPackage", [StringComparison]::Ordinal) -lt 0) {
    throw "The Phase 2 lifecycle has no exact current-user package removal path."
}

# Temp-only path checks exercise the safety guard without installing a package,
# changing a task, stopping a process, or touching a certificate store.
$phase2TemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-phase2-static-" + [Guid]::NewGuid().ToString("N"))
try {
    $fakeLocalAppData = Join-Path $phase2TemporaryRoot "LocalAppData"
    $safeRoot = Join-Path $fakeLocalAppData "STEIN"
    $null = New-Item -ItemType Directory -Path $safeRoot -Force
    . (Join-Path $phase2LifecycleRoot "Common.ps1")
    $resolvedSafeRoot = Assert-SteinPhase2InstallRoot `
        -InstallRoot $safeRoot `
        -KnownLocalAppData $fakeLocalAppData
    if (-not (Test-SteinPhase2PathEqual -Left $resolvedSafeRoot -Right $safeRoot)) {
        throw "The Phase 2 safe-root fixture did not preserve the exact path."
    }
    $unsafeRejected = $false
    try {
        $null = Assert-SteinPhase2InstallRoot `
            -InstallRoot $fakeLocalAppData `
            -KnownLocalAppData $fakeLocalAppData
    }
    catch {
        $unsafeRejected = $true
    }
    if (-not $unsafeRejected) {
        throw "The Phase 2 safe-root guard accepted a broad LOCALAPPDATA target."
    }
    $dataRoot = Join-Path $safeRoot "data"
    $null = New-Item -ItemType Directory -Path $dataRoot -Force
    $databasePath = Join-Path $dataRoot "stein.db"
    [IO.File]::WriteAllBytes(
        $databasePath,
        [Text.Encoding]::ASCII.GetBytes("SQLite format 3`0synthetic-page"))
    Protect-SteinPhase2OwnerOnlyTree -Root $safeRoot
    Assert-SteinPhase2OwnerOnlyTree -Root $safeRoot
    $recovery = New-SteinPhase2ColdRecoveryCopy `
        -DatabasePath $databasePath `
        -RecoveryPath (Join-Path $dataRoot ".phase2-upgrade-recovery-static.db")
    [IO.File]::WriteAllText($databasePath, "changed")
    Restore-SteinPhase2ColdRecoveryCopy `
        -DatabasePath $databasePath `
        -Recovery $recovery
    Assert-SteinPhase2Hash -Path $databasePath -ExpectedSha256 $recovery.Sha256
    $healthyPersistenceStatus = [pscustomobject]@{
        runtime = [pscustomobject]@{ health = "healthy" }
        capabilities = @(
            [pscustomobject]@{
                capability = "durable_persistence"
                schema_version = 1
                state = "healthy"
            }
        )
    }
    $null = Assert-SteinPhase2PersistenceReadyStatus -Status $healthyPersistenceStatus
    $unavailablePersistenceRejected = $false
    try {
        $null = Assert-SteinPhase2PersistenceReadyStatus -Status ([pscustomobject]@{
            runtime = [pscustomobject]@{ health = "healthy" }
            capabilities = @(
                [pscustomobject]@{
                    capability = "durable_persistence"
                    schema_version = 1
                    state = "unavailable"
                    unavailable_reason = "dependency_unavailable"
                }
            )
        })
    }
    catch {
        $unavailablePersistenceRejected = $true
    }
    if (-not $unavailablePersistenceRejected) {
        throw "The Phase 2 readiness gate accepted unavailable durable persistence."
    }
    Initialize-SteinPhase2CredentialNativeApi
    if ($null -eq ("Stein.Phase2CredentialNative" -as [type])) {
        throw "The exact-prefix Credential Manager cleanup binding did not compile."
    }
}
finally {
    if (Test-Path -LiteralPath $phase2TemporaryRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $phase2TemporaryRoot
    }
}

$brokerManifest = Get-Content -LiteralPath (Join-Path $repoRoot "apps\private-broker\Cargo.toml") -Raw
foreach ($forbiddenDependency in @("serde", "serde_json", "stein-protocol", "stein-ipc")) {
    if ($brokerManifest -match "(?m)^\s*$([regex]::Escape($forbiddenDependency))\s*=") {
        throw "The blind broker acquired a protocol-decoding dependency."
    }
}

$brokerSource = Get-Content -LiteralPath (Join-Path $repoRoot "apps\private-broker\src\windows.rs") -Raw
foreach ($requiredSource in @(
    "admit_named_pipe_peer",
    "PackagePeerClass::PackagedDesktop",
    "verify_core_pipe_server",
    "first_pipe_instance(true)",
    "max_instances(1)"
)) {
    if ($brokerSource.IndexOf($requiredSource, [StringComparison]::Ordinal) -lt 0) {
        throw "Broker source is missing a required native admission or one-client invariant."
    }
}
$librarySource = Get-Content -LiteralPath (Join-Path $repoRoot "apps\private-broker\src\lib.rs") -Raw
$sharedBrokerSource = Get-Content -LiteralPath (
    Join-Path $repoRoot "crates\stein-broker-windows\src\lib.rs") -Raw
foreach ($endpoint in @(
    '\\.\pipe\LOCAL\stein-private-broker-v1',
    '\\.\pipe\LOCAL\stein-core-private-v1'
)) {
    if ($sharedBrokerSource.IndexOf($endpoint, [StringComparison]::Ordinal) -lt 0) {
        throw "Broker source is missing a fixed LOCAL endpoint."
    }
}
foreach ($sharedConstant in @("BROKER_RELAY_PIPE", "CORE_PRIVATE_PIPE")) {
    if ($librarySource.IndexOf(
            "stein_broker_windows::$sharedConstant",
            [StringComparison]::Ordinal) -lt 0) {
        throw "Broker application is not using the shared endpoint contract."
    }
}

$sdkPathPoisonRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "stein-sdk-path-poison-" + [Guid]::NewGuid().ToString("N"))
$originalExecutablePath = $env:PATH
try {
    $null = New-Item -ItemType Directory -Path $sdkPathPoisonRoot -ErrorAction Stop
    foreach ($toolName in @("makeappx.exe", "signtool.exe")) {
        [IO.File]::WriteAllText(
            (Join-Path $sdkPathPoisonRoot $toolName),
            "synthetic-path-poison")
    }
    $env:PATH = "$sdkPathPoisonRoot$([IO.Path]::PathSeparator)$originalExecutablePath"
    foreach ($toolName in @("makeappx.exe", "signtool.exe")) {
        $poisonedPath = (Get-Command $toolName -CommandType Application -ErrorAction Stop |
            Select-Object -First 1).Source
        $expectedPoisonedPath = (Get-Item `
            -LiteralPath (Join-Path $sdkPathPoisonRoot $toolName) `
            -Force `
            -ErrorAction Stop).FullName
        if (-not [string]::Equals(
                $poisonedPath,
                $expectedPoisonedPath,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "The SDK PATH-poisoning negative fixture did not control command discovery."
        }
        $trustedTool = Resolve-WindowsSdkTool -Name $toolName
        if ($trustedTool.StartsWith(
                "$sdkPathPoisonRoot$([IO.Path]::DirectorySeparatorChar)",
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows SDK tool resolution accepted a PATH-poisoned executable."
        }
        $trustedItem = Get-Item -LiteralPath $trustedTool -Force -ErrorAction Stop
        if ($trustedItem.PSIsContainer -or
            (($trustedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $trustedItem.Length -le 0) {
            throw "Windows SDK tool resolution returned a non-regular executable."
        }
    }
}
finally {
    $env:PATH = $originalExecutablePath
    if (Test-Path -LiteralPath $sdkPathPoisonRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $sdkPathPoisonRoot
    }
}

$packageToolsSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot "PackageTools.ps1") -Raw
foreach ($requiredSdkResolverInvariant in @(
        "Microsoft\Windows Kits\Installed Roots",
        "KitsRoot10",
        "FileAttributes]::ReparsePoint")) {
    if ($packageToolsSource.IndexOf(
            $requiredSdkResolverInvariant,
            [StringComparison]::Ordinal) -lt 0) {
        throw "Windows SDK tool resolution is missing a trusted-root invariant."
    }
}
if ($packageToolsSource.IndexOf("Get-Command `$Name", [StringComparison]::Ordinal) -ge 0) {
    throw "Windows SDK tool resolution still consults PATH."
}

$makeAppx = Resolve-WindowsSdkTool -Name "makeappx.exe"
$schemaRoot = Join-Path ([IO.Path]::GetTempPath()) ("stein-msix-static-" + [Guid]::NewGuid().ToString("N"))
$schemaPackage = "$schemaRoot.msix"
$schemaUnpack = "$schemaRoot.unpack"
$schemaMapping = "$schemaRoot.mapping.txt"
$staticStagingLocks = $null
$staticMappingLock = $null
try {
    $null = New-Item -ItemType Directory -Path (Join-Path $schemaRoot "bin") -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $schemaRoot "Assets") -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $schemaRoot "Metadata") -Force
    $fixtureExecutable = Join-Path $env:WINDIR "System32\where.exe"
    Copy-Item -LiteralPath $fixtureExecutable -Destination (Join-Path $schemaRoot "bin\stein-desktop.exe")
    Copy-Item -LiteralPath $fixtureExecutable -Destination (Join-Path $schemaRoot "bin\stein-private-broker.exe")
    Copy-Item -LiteralPath $fixtureExecutable -Destination (Join-Path $schemaRoot "bin\stein-edge-native-host.exe")
    foreach ($asset in $expectedAssets.GetEnumerator()) {
        $encodedPath = Join-Path $PSScriptRoot "assets\$($asset.Key).png.base64"
        [IO.File]::WriteAllBytes(
            (Join-Path $schemaRoot "Assets\$($asset.Key).png"),
            [Convert]::FromBase64String((Get-Content -LiteralPath $encodedPath -Raw).Trim()))
    }
    $staticCoreDigest = "ab" * 32
    $staticCandidateCommit = "1a" * 20
    $staticCandidateTree = "2b" * 20
    $staticSourceVerificationDigest = "3c" * 32
    $staticSourceAnchorDigest = "4d" * 32
    $staticSourceRootDigest = "5e" * 32
    $staticCliSize = 12345L
    $staticCliDigest = "6f" * 32
    $staticDesktopSize = (Get-Item `
            -LiteralPath (Join-Path $schemaRoot "bin\stein-desktop.exe") `
            -Force).Length
    $staticDesktopDigest = Get-SteinPackageFileSha256 `
        -Path (Join-Path $schemaRoot "bin\stein-desktop.exe")
    $staticDesktopDistCount = 2
    $staticDesktopDistDigest = "7a" * 32
    $staticCoreBinding = [ordered]@{
        schema_version = 3
        core_executable_sha256 = $staticCoreDigest
        cli_executable_size = $staticCliSize
        cli_executable_sha256 = $staticCliDigest
        desktop_executable_size = $staticDesktopSize
        desktop_executable_sha256 = $staticDesktopDigest
        desktop_dist_file_count = $staticDesktopDistCount
        desktop_dist_manifest_sha256 = $staticDesktopDistDigest
        candidate_git_commit = $staticCandidateCommit
        candidate_git_tree = $staticCandidateTree
        source_verification_sha256 = $staticSourceVerificationDigest
        source_root_anchor_sha256 = $staticSourceAnchorDigest
        source_root_digest_sha256 = $staticSourceRootDigest
    }
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($staticCoreBinding | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $null = Test-SteinCoreBindingContract `
        -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
        -ExpectedCoreSha256 $staticCoreDigest `
        -ExpectedCliSize $staticCliSize `
        -ExpectedCliSha256 $staticCliDigest `
        -ExpectedDesktopSize $staticDesktopSize `
        -ExpectedDesktopSha256 $staticDesktopDigest `
        -ExpectedDesktopDistFileCount $staticDesktopDistCount `
        -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
        -ExpectedCandidateGitCommit $staticCandidateCommit `
        -ExpectedCandidateGitTree $staticCandidateTree `
        -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
        -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
        -ExpectedSourceRootDigestSha256 $staticSourceRootDigest
    $staticCoreBinding["schema_version"] = 2
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($staticCoreBinding | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $legacySchemaRejected = $false
    try {
        $null = Test-SteinCoreBindingContract `
            -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
            -ExpectedCoreSha256 $staticCoreDigest `
            -ExpectedCliSize $staticCliSize `
            -ExpectedCliSha256 $staticCliDigest `
            -ExpectedDesktopSize $staticDesktopSize `
            -ExpectedDesktopSha256 $staticDesktopDigest `
            -ExpectedDesktopDistFileCount $staticDesktopDistCount `
            -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
            -ExpectedCandidateGitCommit $staticCandidateCommit `
            -ExpectedCandidateGitTree $staticCandidateTree `
            -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
            -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
            -ExpectedSourceRootDigestSha256 $staticSourceRootDigest
    }
    catch { $legacySchemaRejected = $true }
    if (-not $legacySchemaRejected) {
        throw "The signed package binding accepted legacy schema 2 metadata."
    }
    $staticCoreBinding["schema_version"] = "3"
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($staticCoreBinding | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $textSchemaVersionRejected = $false
    try {
        $null = Test-SteinCoreBindingContract `
            -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
            -ExpectedCoreSha256 $staticCoreDigest `
            -ExpectedCliSize $staticCliSize `
            -ExpectedCliSha256 $staticCliDigest `
            -ExpectedDesktopSize $staticDesktopSize `
            -ExpectedDesktopSha256 $staticDesktopDigest `
            -ExpectedDesktopDistFileCount $staticDesktopDistCount `
            -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
            -ExpectedCandidateGitCommit $staticCandidateCommit `
            -ExpectedCandidateGitTree $staticCandidateTree `
            -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
            -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
            -ExpectedSourceRootDigestSha256 $staticSourceRootDigest
    }
    catch {
        $textSchemaVersionRejected = $true
    }
    $staticCoreBinding["schema_version"] = 3
    if (-not $textSchemaVersionRejected) {
        throw "The signed package binding accepted a textual schema version."
    }
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($staticCoreBinding | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $wrongSignedSourceBindingRejected = $false
    try {
        $null = Test-SteinCoreBindingContract `
            -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
            -ExpectedCoreSha256 $staticCoreDigest `
            -ExpectedCliSize $staticCliSize `
            -ExpectedCliSha256 $staticCliDigest `
            -ExpectedDesktopSize $staticDesktopSize `
            -ExpectedDesktopSha256 $staticDesktopDigest `
            -ExpectedDesktopDistFileCount $staticDesktopDistCount `
            -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
            -ExpectedCandidateGitCommit $staticCandidateCommit `
            -ExpectedCandidateGitTree $staticCandidateTree `
            -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
            -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
            -ExpectedSourceRootDigestSha256 ("6f" * 32)
    }
    catch {
        $wrongSignedSourceBindingRejected = $true
    }
    if (-not $wrongSignedSourceBindingRejected) {
        throw "The signed package binding accepted a different source root digest."
    }

    $wrongSignedCliBindingRejected = $false
    try {
        $null = Test-SteinCoreBindingContract `
            -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
            -ExpectedCoreSha256 $staticCoreDigest `
            -ExpectedCliSize $staticCliSize `
            -ExpectedCliSha256 ("9c" * 32) `
            -ExpectedDesktopSize $staticDesktopSize `
            -ExpectedDesktopSha256 $staticDesktopDigest `
            -ExpectedDesktopDistFileCount $staticDesktopDistCount `
            -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
            -ExpectedCandidateGitCommit $staticCandidateCommit `
            -ExpectedCandidateGitTree $staticCandidateTree `
            -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
            -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
            -ExpectedSourceRootDigestSha256 $staticSourceRootDigest
    }
    catch { $wrongSignedCliBindingRejected = $true }
    if (-not $wrongSignedCliBindingRejected) {
        throw "The signed package binding accepted substituted companion CLI bytes."
    }

    $bindingWithExtraProperty = [ordered]@{}
    foreach ($entry in $staticCoreBinding.GetEnumerator()) {
        $bindingWithExtraProperty[$entry.Key] = $entry.Value
    }
    $bindingWithExtraProperty["unexpected"] = "synthetic"
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($bindingWithExtraProperty | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $openSignedBindingRejected = $false
    try {
        $null = Test-SteinCoreBindingContract `
            -BindingPath (Join-Path $schemaRoot "Metadata\CoreBinding.json") `
            -ExpectedCoreSha256 $staticCoreDigest `
            -ExpectedCliSize $staticCliSize `
            -ExpectedCliSha256 $staticCliDigest `
            -ExpectedDesktopSize $staticDesktopSize `
            -ExpectedDesktopSha256 $staticDesktopDigest `
            -ExpectedDesktopDistFileCount $staticDesktopDistCount `
            -ExpectedDesktopDistManifestSha256 $staticDesktopDistDigest `
            -ExpectedCandidateGitCommit $staticCandidateCommit `
            -ExpectedCandidateGitTree $staticCandidateTree `
            -ExpectedSourceVerificationSha256 $staticSourceVerificationDigest `
            -ExpectedSourceRootAnchorSha256 $staticSourceAnchorDigest `
            -ExpectedSourceRootDigestSha256 $staticSourceRootDigest
    }
    catch {
        $openSignedBindingRejected = $true
    }
    if (-not $openSignedBindingRejected) {
        throw "The signed package binding accepted an open metadata schema."
    }
    [IO.File]::WriteAllText(
        (Join-Path $schemaRoot "Metadata\CoreBinding.json"),
        ($staticCoreBinding | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    $schemaManifest = (Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8).
        Replace("{{PUBLISHER}}", "CN=STEIN Static Validation").
        Replace("{{PUBLISHER_DISPLAY_NAME}}", "STEIN Static Validation").
        Replace("{{VERSION}}", "0.0.0.1")
    Set-Content -LiteralPath (Join-Path $schemaRoot "AppxManifest.xml") -Value $schemaManifest -Encoding UTF8
    $staticStagingLocks = Open-SteinPackageDirectoryManifestLock `
        -Root $schemaRoot `
        -Domain "stein-msix-staging-manifest-v1"
    $null = Assert-SteinFixedApplicationPayloadMapsEqual `
        -ExpectedFiles @($staticStagingLocks.Files) `
        -ActualFiles @($staticStagingLocks.Files)
    $staticBrokerPath = Join-Path $schemaRoot "bin\stein-private-broker.exe"
    $staticBrokerItem = Get-Item `
        -LiteralPath $staticBrokerPath `
        -Force `
        -ErrorAction Stop
    $staticBrokerDigest = Get-SteinPackageFileSha256 -Path $staticBrokerPath
    $null = Assert-SteinFixedApplicationPayloadFileIdentity `
        -Files @($staticStagingLocks.Files) `
        -RelativePath "bin\stein-private-broker.exe" `
        -ExpectedSize ([long]$staticBrokerItem.Length) `
        -ExpectedSha256 $staticBrokerDigest
    $stagedBrokerSubstitutionRejected = $false
    try {
        $null = Assert-SteinFixedApplicationPayloadFileIdentity `
            -Files @($staticStagingLocks.Files) `
            -RelativePath "bin\stein-private-broker.exe" `
            -ExpectedSize ([long]$staticBrokerItem.Length) `
            -ExpectedSha256 ("8c" * 32)
    }
    catch { $stagedBrokerSubstitutionRejected = $true }
    if (-not $stagedBrokerSubstitutionRejected) {
        throw "The pre-pack staging map accepted substituted broker output bytes."
    }
    $stagingMutationRejected = $false
    try {
        [IO.File]::WriteAllText(
            (Join-Path $schemaRoot "bin\stein-private-broker.exe"),
            "synthetic staging mutation",
            [Text.UTF8Encoding]::new($false))
    }
    catch {
        $stagingMutationRejected = $true
    }
    if (-not $stagingMutationRejected) {
        throw "The pre-pack staging locks allowed a fixed payload mutation."
    }
    $staticMappingLock = New-SteinPackageLockedMakeAppxMapping `
        -StagingManifest $staticStagingLocks `
        -MappingPath $schemaMapping
    $lateOptionalRoot = Join-Path $schemaRoot "AppxMetadata"
    $null = New-Item `
        -ItemType Directory `
        -Path $lateOptionalRoot `
        -ErrorAction Stop
    [IO.File]::WriteAllText(
        (Join-Path $lateOptionalRoot "CodeIntegrity.cat"),
        "synthetic late optional injection",
        [Text.UTF8Encoding]::new($false))
    & $makeAppx pack /f $staticMappingLock.Path /p $schemaPackage /o *> $null
    Assert-NativeCommandSucceeded -Operation "MakeAppx static schema validation"
    & $makeAppx unpack /p $schemaPackage /d $schemaUnpack /o *> $null
    Assert-NativeCommandSucceeded -Operation "MakeAppx static closed-layout validation"
    $actualUnsignedPackageFiles = @(
        Get-ChildItem -LiteralPath $schemaUnpack -Recurse -File | ForEach-Object {
            $_.FullName.Substring($schemaUnpack.Length + 1).Replace("\", "/")
        } | Sort-Object
    )
    $expectedUnsignedPackageFiles = @(
        "AppxBlockMap.xml",
        "AppxManifest.xml",
        "Assets/Square150x150Logo.png",
        "Assets/Square44x44Logo.png",
        "Assets/StoreLogo.png",
        "Metadata/CoreBinding.json",
        "bin/stein-desktop.exe",
        "bin/stein-edge-native-host.exe",
        "bin/stein-private-broker.exe"
    ) | Sort-Object
    if ($actualUnsignedPackageFiles.Count -ne $expectedUnsignedPackageFiles.Count -or
        @(Compare-Object `
            -ReferenceObject $expectedUnsignedPackageFiles `
            -DifferenceObject $actualUnsignedPackageFiles `
            -CaseSensitive).Count -ne 0) {
        throw "MakeAppx emitted a file outside the exact unsigned package layout: $($actualUnsignedPackageFiles -join ', ')."
    }
    $null = Assert-SteinClosedUnpackedPackageLayout -PackageRoot $schemaUnpack
    $unpackedPayloadMap = @(
        foreach ($relativePath in @(Get-SteinFixedApplicationPayloadRelativePaths)) {
            $payloadPath = Join-Path $schemaUnpack $relativePath
            $payload = Get-Item -LiteralPath $payloadPath -Force -ErrorAction Stop
            [pscustomobject]@{
                relative_path = $relativePath
                size = [long]$payload.Length
                sha256 = Get-SteinPackageFileSha256 -Path $payload.FullName
            }
        })
    $null = Assert-SteinFixedApplicationPayloadMapsEqual `
        -ExpectedFiles @($staticStagingLocks.Files) `
        -ActualFiles $unpackedPayloadMap
    $substitutedPayloadMap = @($unpackedPayloadMap | ForEach-Object {
            if ([string]$_.relative_path -ceq "bin\stein-private-broker.exe") {
                [pscustomobject]@{
                    relative_path = [string]$_.relative_path
                    size = [long]$_.size
                    sha256 = "8b" * 32
                }
            }
            else { $_ }
        })
    $substitutedPayloadRejected = $false
    try {
        $null = Assert-SteinFixedApplicationPayloadMapsEqual `
            -ExpectedFiles @($staticStagingLocks.Files) `
            -ActualFiles $substitutedPayloadMap
    }
    catch { $substitutedPayloadRejected = $true }
    if (-not $substitutedPayloadRejected) {
        throw "The signed package comparison accepted a substituted staging payload."
    }

    $hiddenMetadataRoot = Join-Path $schemaUnpack "AppxMetadata"
    $null = New-Item -ItemType Directory -Path $hiddenMetadataRoot -Force -ErrorAction Stop
    [IO.File]::WriteAllText(
        (Join-Path $hiddenMetadataRoot "hidden.exe"),
        "synthetic-unreviewed-package-payload")
    $hiddenMetadataRejected = $false
    try {
        $null = Assert-SteinClosedUnpackedPackageLayout -PackageRoot $schemaUnpack
    }
    catch {
        $hiddenMetadataRejected = $true
    }
    if (-not $hiddenMetadataRejected) {
        throw "The closed package layout accepted an unreviewed AppxMetadata payload."
    }
}
finally {
    if ($null -ne $staticMappingLock) {
        $staticMappingLock.Stream.Dispose()
    }
    if ($null -ne $staticStagingLocks) {
        foreach ($stream in $staticStagingLocks.Streams) { $stream.Dispose() }
    }
    if (Test-Path -LiteralPath $schemaRoot) {
        Remove-SteinStaticTemporaryLeaf -Path $schemaRoot
    }
    if (Test-Path -LiteralPath $schemaPackage) {
        Remove-SteinStaticTemporaryLeaf -Path $schemaPackage
    }
    if (Test-Path -LiteralPath $schemaUnpack) {
        Remove-SteinStaticTemporaryLeaf -Path $schemaUnpack
    }
    if (Test-Path -LiteralPath $schemaMapping) {
        Remove-SteinStaticTemporaryLeaf -Path $schemaMapping
    }
}

Write-Output "Windows MSIX source manifest, MakeAppx schema, assets, signing discipline, and broker boundaries are valid."
