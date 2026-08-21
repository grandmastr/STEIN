[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version 3.0

$script:ScannerPath = (Resolve-Path -LiteralPath (
    Join-Path $PSScriptRoot "Scan-NoLeaks.ps1") -ErrorAction Stop).Path
$script:TestSentinel = "STEIN_PHASE2_PUBLIC_NO_LEAKS_SENTINEL_V1_7F4C2A91"
$script:PackageSha256 = "1" * 64
$script:CandidateCommit = "2" * 40
$script:SourceVerificationSha256 = "3" * 64
$script:ProducerSourceSha256 = "4" * 64
$script:ExpectedSubchecks = @(
    "audit_clean",
    "crash_output_clean",
    "credential_metadata_clean",
    "database_clean",
    "errors_clean",
    "evidence_clean",
    "logs_clean",
    "outbox_clean",
    "package_clean",
    "protocol_clean",
    "recovery_copy_clean",
    "traces_clean"
)
$script:ProducerSubchecks = @(
    "audit_sentinel_roundtrip",
    "crash_output_sentinel_roundtrip",
    "credential_metadata_sentinel_roundtrip",
    "database_sentinel_roundtrip",
    "errors_sentinel_roundtrip",
    "evidence_sentinel_roundtrip",
    "logs_sentinel_roundtrip",
    "outbox_sentinel_roundtrip",
    "package_sentinel_roundtrip",
    "protocol_sentinel_roundtrip",
    "recovery_copy_sentinel_roundtrip",
    "traces_sentinel_roundtrip"
)
$script:PayloadPaths = @(
    "AppxManifest.xml",
    "Assets\Square150x150Logo.png",
    "Assets\Square44x44Logo.png",
    "Assets\StoreLogo.png",
    "Metadata\CoreBinding.json",
    "bin\stein-desktop.exe",
    "bin\stein-edge-native-host.exe",
    "bin\stein-private-broker.exe",
    "AppxBlockMap.xml"
)
$script:ProducerSlots = @(
    [pscustomobject]@{ id = "crash_output"; relative_path = "artifacts\crash-output.bin" },
    [pscustomobject]@{ id = "errors"; relative_path = "artifacts\errors.bin" },
    [pscustomobject]@{ id = "evidence_receipt"; relative_path = "artifacts\evidence-receipt.json" },
    [pscustomobject]@{ id = "logs"; relative_path = "artifacts\logs.bin" },
    [pscustomobject]@{ id = "protocol_receipt"; relative_path = "artifacts\protocol-receipt.json" },
    [pscustomobject]@{ id = "recovery_copy"; relative_path = "artifacts\recovery-copy.db" },
    [pscustomobject]@{ id = "traces"; relative_path = "artifacts\traces.bin" }
)

function Assert-TestCondition {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if (-not $Condition) {
        throw $FailureCode
    }
}

function Assert-TestJsonShape {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string[]] $ExpectedProperties,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )

    if ($null -eq $Value) {
        throw $FailureCode
    }
    $actual = @($Value.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    $expected = @($ExpectedProperties | Sort-Object)
    if ($actual.Count -ne $expected.Count -or
        @(Compare-Object `
            -ReferenceObject $expected `
            -DifferenceObject $actual `
            -CaseSensitive).Count -ne 0) {
        throw $FailureCode
    }
}

function Get-TestSha256 {
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

function Get-TestSha256Bytes {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha256.ComputeHash($Bytes)).Replace(
            "-",
            "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Add-TestCatalogFile {
    param(
        [Parameter(Mandatory = $true)] $Lines,
        [Parameter(Mandatory = $true)][string] $Class,
        [Parameter(Mandatory = $true)][string] $Id,
        [Parameter(Mandatory = $true)][string] $Path
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $Lines.Add("$Class|$Id|$($item.Length)|$(Get-TestSha256 -Path $item.FullName)")
}

function Get-TestCatalogBinding {
    param([Parameter(Mandatory = $true)][string] $Root)

    $lines = New-Object "Collections.Generic.List[string]"
    $counts = @{
        audit_clean = 0
        crash_output_clean = 0
        credential_metadata_clean = 0
        database_clean = 0
        errors_clean = 0
        evidence_clean = 0
        logs_clean = 0
        outbox_clean = 0
        package_clean = 0
        protocol_clean = 0
        recovery_copy_clean = 0
        traces_clean = 0
    }

    $databaseFiles = @(
        [pscustomobject]@{ leaf = "stein.db"; id = "main" },
        [pscustomobject]@{ leaf = "stein.db-journal"; id = "journal" },
        [pscustomobject]@{ leaf = "stein.db-shm"; id = "shm" },
        [pscustomobject]@{ leaf = "stein.db-wal"; id = "wal" }
    )
    foreach ($role in @("audit", "database", "outbox")) {
        foreach ($file in $databaseFiles) {
            Add-TestCatalogFile `
                -Lines $lines `
                -Class $role `
                -Id $file.id `
                -Path (Join-Path $Root "install\data\$($file.leaf)")
            $counts["${role}_clean"]++
        }
    }

    $slotMap = @{
        crash_output = [pscustomobject]@{ class = "crash_output"; subcheck = "crash_output_clean" }
        errors = [pscustomobject]@{ class = "errors"; subcheck = "errors_clean" }
        evidence_receipt = [pscustomobject]@{ class = "evidence"; subcheck = "evidence_clean" }
        logs = [pscustomobject]@{ class = "logs"; subcheck = "logs_clean" }
        protocol_receipt = [pscustomobject]@{ class = "protocol"; subcheck = "protocol_clean" }
        recovery_copy = [pscustomobject]@{ class = "recovery_copy"; subcheck = "recovery_copy_clean" }
        traces = [pscustomobject]@{ class = "traces"; subcheck = "traces_clean" }
    }
    foreach ($slot in $script:ProducerSlots) {
        $mapping = $slotMap[[string]$slot.id]
        Add-TestCatalogFile `
            -Lines $lines `
            -Class $mapping.class `
            -Id $slot.id `
            -Path (Join-Path $Root "evidence\no-leaks-input\$($slot.relative_path)")
        $counts[$mapping.subcheck]++
    }
    Add-TestCatalogFile `
        -Lines $lines `
        -Class "evidence" `
        -Id "producer_manifest" `
        -Path (Join-Path $Root "evidence\no-leaks-input\producer-manifest.json")
    $counts.evidence_clean++
    foreach ($log in @(
            [pscustomobject]@{ leaf = "core.stderr.log"; id = "installed_stderr" },
            [pscustomobject]@{ leaf = "core.stdout.log"; id = "installed_stdout" })) {
        Add-TestCatalogFile `
            -Lines $lines `
            -Class "logs" `
            -Id $log.id `
            -Path (Join-Path $Root "install\logs\$($log.leaf)")
        $counts.logs_clean++
    }

    $credentialPath = Join-Path $Root "credential-metadata.json"
    $credential = [IO.File]::ReadAllText($credentialPath) | ConvertFrom-Json -ErrorAction Stop
    $entry = @($credential.entries)[0]
    $value = "target=$([string]$entry.target_name)`nusername=$([string]$entry.user_name)`ntype=$([uint32]$entry.type)`npersist=$([uint32]$entry.persist)"
    $canonical = "$($value.Length):$value"
    $utf8 = [Text.Encoding]::UTF8.GetBytes($canonical)
    $utf16 = [Text.Encoding]::Unicode.GetBytes($canonical)
    $metadataBytes = New-Object byte[] ($utf8.Length + 1 + $utf16.Length)
    [Buffer]::BlockCopy($utf8, 0, $metadataBytes, 0, $utf8.Length)
    $metadataBytes[$utf8.Length] = 10
    [Buffer]::BlockCopy($utf16, 0, $metadataBytes, $utf8.Length + 1, $utf16.Length)
    $lines.Add(
        "credential_metadata|metadata_set|$($metadataBytes.Length)|$(Get-TestSha256Bytes -Bytes $metadataBytes)")
    $credentialItem = Get-Item -LiteralPath $credentialPath -Force -ErrorAction Stop
    $lines.Add(
        "credential_metadata|synthetic_fixture_document|$($credentialItem.Length)|$(Get-TestSha256 -Path $credentialPath)")
    $counts.credential_metadata_clean += 2

    foreach ($top in @(
            [pscustomobject]@{ leaf = "candidate.msix"; id = "msix" },
            [pscustomobject]@{ leaf = "candidate.identity.json"; id = "release_identity" },
            [pscustomobject]@{ leaf = "release-core.exe"; id = "release_core" },
            [pscustomobject]@{ leaf = "release-cli.exe"; id = "release_cli" })) {
        Add-TestCatalogFile `
            -Lines $lines `
            -Class "package" `
            -Id $top.id `
            -Path (Join-Path $Root "package\$($top.leaf)")
        $counts.package_clean++
    }
    foreach ($relativePath in @($script:PayloadPaths | Sort-Object)) {
        $id = "payload/" + $relativePath.Replace("\", "/").ToLowerInvariant()
        Add-TestCatalogFile `
            -Lines $lines `
            -Class "package" `
            -Id $id `
            -Path (Join-Path $Root "package\unpacked\$relativePath")
        $counts.package_clean++
    }

    $lines.Sort([StringComparer]::Ordinal)
    $catalogBytes = [Text.Encoding]::UTF8.GetBytes([string]::Join("`n", $lines.ToArray()))
    return [pscustomobject]@{
        sha256 = Get-TestSha256Bytes -Bytes $catalogBytes
        count = $lines.Count
        subcheck_counts = $counts
    }
}

function Update-TestProducerReceipt {
    param([Parameter(Mandatory = $true)][string] $Root)

    $catalog = Get-TestCatalogBinding -Root $Root
    $scannerIds = $script:ExpectedSubchecks
    $subchecks = @()
    $produced = 0
    for ($index = 0; $index -lt $script:ProducerSubchecks.Count; $index++) {
        $count = [int]$catalog.subcheck_counts[$scannerIds[$index]]
        $produced += $count
        $subchecks += [ordered]@{
            id = $script:ProducerSubchecks[$index]
            result = "pass"
            artifacts_produced = $count
        }
    }
    Assert-TestCondition `
        -Condition ($produced -eq $catalog.count) `
        -FailureCode "producer_fixture_catalog_count_invalid"
    $manifestPath = Join-Path $Root "evidence\no-leaks-input\producer-manifest.json"
    $receipt = [ordered]@{
        schema_version = 1
        gate_id = "P2-NO-LEAKS"
        fixture_id = "phase2-no-leaks-sentinel-producer-v1"
        runner_id = "stein-phase2-no-leaks-producer-v1"
        result = "pass"
        bindings = [ordered]@{
            package_msix_sha256 = $script:PackageSha256
            candidate_git_commit = $script:CandidateCommit
            source_verification_sha256 = $script:SourceVerificationSha256
            producer_manifest_sha256 = Get-TestSha256 -Path $manifestPath
            producer_source_sha256 = $script:ProducerSourceSha256
            artifact_catalog_sha256 = $catalog.sha256
            artifact_count = $catalog.count
        }
        summary = [ordered]@{
            required = $script:ProducerSubchecks.Count
            passed = $script:ProducerSubchecks.Count
            failed = 0
            not_run = 0
            artifacts_produced = $produced
        }
        subchecks = $subchecks
    }
    Write-TestUtf8Json `
        -Path (Join-Path $Root "evidence\no-leaks-input\producer-receipt.json") `
        -Value $receipt
}

function Write-TestBytes {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent -ErrorAction Stop
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)
}

function Write-TestUtf8Json {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $Value
    )

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent -ErrorAction Stop
    }
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 8 -Compress),
        $encoding)
}

function Write-TestCredentialMetadata {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $UserName
    )

    $document = [ordered]@{
        schema_version = 1
        entries = @(
            [ordered]@{
                target_name = "STEIN:model-route:synthetic-route-v1"
                user_name = $UserName
                type = 1
                persist = 2
            }
        )
    }
    Write-TestUtf8Json `
        -Path (Join-Path $Root "credential-metadata.json") `
        -Value $document
}

function Update-TestProducerManifest {
    param([Parameter(Mandatory = $true)][string] $Root)

    $inputRoot = Join-Path $Root "evidence\no-leaks-input"
    $entries = @(
        $script:ProducerSlots | ForEach-Object {
            $path = Join-Path $inputRoot $_.relative_path
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            [ordered]@{
                id = $_.id
                expected_present = $true
                size_bytes = [long]$item.Length
                sha256 = Get-TestSha256 -Path $item.FullName
            }
        }
    )
    $manifest = [ordered]@{
        schema_version = 1
        producer_id = "stein-phase2-no-leaks-artifact-producer-v1"
        command_id = "collect-closed-installed-artifacts-v1"
        artifacts = $entries
    }
    Write-TestUtf8Json `
        -Path (Join-Path $inputRoot "producer-manifest.json") `
        -Value $manifest
}

function Get-TestBase {
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $base = [IO.Path]::GetFullPath(
        (Join-Path $temporaryRoot "STEIN-phase2-no-leaks-selftest"))
    if (-not (Test-Path -LiteralPath $base)) {
        $null = New-Item -ItemType Directory -Path $base -ErrorAction Stop
    }
    $item = Get-Item -LiteralPath $base -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "selftest_base_invalid"
    }
    return $base
}

function New-TestFixture {
    $base = Get-TestBase
    $root = Join-Path $base ([Guid]::NewGuid().ToString("N"))
    $null = New-Item -ItemType Directory -Path $root -ErrorAction Stop

    $plainFiles = @(
        "install\data\stein.db",
        "install\data\stein.db-journal",
        "install\data\stein.db-shm",
        "install\data\stein.db-wal",
        "install\logs\core.stderr.log",
        "install\logs\core.stdout.log",
        "package\candidate.identity.json",
        "package\candidate.msix",
        "package\release-cli.exe",
        "package\release-core.exe"
    )
    foreach ($relativePath in $plainFiles) {
        Write-TestBytes `
            -Path (Join-Path $root $relativePath) `
            -Bytes ([Text.Encoding]::UTF8.GetBytes("synthetic:$relativePath"))
    }
    foreach ($relativePath in $script:PayloadPaths) {
        Write-TestBytes `
            -Path (Join-Path $root "package\unpacked\$relativePath") `
            -Bytes ([Text.Encoding]::UTF8.GetBytes("synthetic-payload:$relativePath"))
    }
    foreach ($slot in $script:ProducerSlots) {
        Write-TestBytes `
            -Path (Join-Path $root "evidence\no-leaks-input\$($slot.relative_path)") `
            -Bytes ([Text.Encoding]::UTF8.GetBytes("synthetic-producer:$($slot.id)"))
    }
    Write-TestCredentialMetadata -Root $root -UserName "synthetic-user"
    Update-TestProducerManifest -Root $root
    Update-TestProducerReceipt -Root $root
    return $root
}

function Assert-TestRootTarget {
    param([Parameter(Mandatory = $true)][string] $Root)

    $base = Get-TestBase
    $canonical = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $prefix = "$base$([IO.Path]::DirectorySeparatorChar)"
    if (-not $canonical.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $canonical) -cnotmatch "^[0-9a-f]{32}$") {
        throw "selftest_cleanup_target_invalid"
    }
    return $canonical
}

function Remove-TestFixture {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [string] $JunctionTarget
    )

    $canonical = Assert-TestRootTarget -Root $Root
    $logRoot = Join-Path $canonical "install\logs"
    if (Test-Path -LiteralPath $logRoot) {
        $logItem = Get-Item -LiteralPath $logRoot -Force -ErrorAction Stop
        if (($logItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            if ([string]::IsNullOrWhiteSpace($JunctionTarget)) {
                throw "selftest_cleanup_reparse_invalid"
            }
            $base = Get-TestBase
            $target = [IO.Path]::GetFullPath($JunctionTarget)
            $prefix = "$base$([IO.Path]::DirectorySeparatorChar)"
            if (-not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
                (Split-Path -Leaf $target) -cnotmatch "^junction-target-[0-9a-f]{32}$") {
                throw "selftest_cleanup_target_invalid"
            }
            [IO.Directory]::Delete($logRoot, $false)
            if (-not (Test-Path -LiteralPath $target -PathType Container)) {
                throw "selftest_cleanup_target_followed"
            }
        }
    }
    if (Test-Path -LiteralPath $canonical) {
        $reparse = @(
            Get-ChildItem -LiteralPath $canonical -Force -Recurse -ErrorAction Stop |
                Where-Object {
                    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
                }
        )
        if ($reparse.Count -ne 0) {
            throw "selftest_cleanup_reparse_invalid"
        }
        Remove-Item -LiteralPath $canonical -Recurse -Force -ErrorAction Stop
    }
    if (-not [string]::IsNullOrWhiteSpace($JunctionTarget) -and
        (Test-Path -LiteralPath $JunctionTarget)) {
        $base = Get-TestBase
        $target = [IO.Path]::GetFullPath($JunctionTarget)
        $prefix = "$base$([IO.Path]::DirectorySeparatorChar)"
        if (-not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $target) -cnotmatch "^junction-target-[0-9a-f]{32}$") {
            throw "selftest_cleanup_target_invalid"
        }
        Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
    }
}

function ConvertTo-TestQuotedArgument {
    param([Parameter(Mandatory = $true)][string] $Value)

    if ($Value.Contains('"')) {
        throw "selftest_argument_invalid"
    }
    return '"' + $Value + '"'
}

function Invoke-TestDatabaseMutationAfterProducerReadBegins {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process] $Process,
        [Parameter(Mandatory = $true)][string] $Root
    )

    $producerPath = Join-Path $Root (
        "evidence\no-leaks-input\artifacts\crash-output.bin")
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    $producerReadObserved = $false
    while ($deadline.ElapsedMilliseconds -lt 20000) {
        if ($Process.HasExited) {
            throw "scanner_process_exited_before_mutation"
        }
        $probe = $null
        try {
            $probe = [IO.FileStream]::new(
                $producerPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None)
        }
        catch [IO.IOException] {
            # The scanner opens the producer artifact with FileShare.Read. The
            # first sharing violation therefore proves its earlier database
            # pass is complete while this later artifact is still in flight.
            $producerReadObserved = $true
        }
        finally {
            if ($null -ne $probe) {
                $probe.Dispose()
            }
        }
        if ($producerReadObserved) {
            break
        }
        [Threading.Thread]::Sleep(1)
    }
    $deadline.Stop()
    if (-not $producerReadObserved) {
        throw "scanner_producer_read_not_observed"
    }

    $databasePath = Join-Path $Root "install\data\stein.db"
    $database = [IO.FileStream]::new(
        $databasePath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $first = $database.ReadByte()
        if ($first -lt 0) {
            throw "scanner_mutation_database_empty"
        }
        $database.Position = 0
        $database.WriteByte([byte]($first -bxor 1))
        $database.Flush()
    }
    finally {
        $database.Dispose()
    }
}

function Invoke-TestScanner {
    param(
        [Parameter(Mandatory = $true)][string] $HostPath,
        [Parameter(Mandatory = $true)][string] $Root,
        [scriptblock] $DuringExecution
    )

    $arguments = @(
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        (ConvertTo-TestQuotedArgument -Value $script:ScannerPath),
        "-SyntheticFixtureRoot",
        (ConvertTo-TestQuotedArgument -Value $Root),
        "-PackageMsixSha256",
        $script:PackageSha256,
        "-CandidateGitCommit",
        $script:CandidateCommit,
        "-SourceVerificationSha256",
        $script:SourceVerificationSha256
    )
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $HostPath
    $startInfo.Arguments = [string]::Join(" ", $arguments)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $started = $false
    try {
        if (-not $process.Start()) {
            throw "scanner_process_start_failed"
        }
        $started = $true
        if ($null -ne $DuringExecution) {
            & $DuringExecution $process $Root
        }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        if (-not $process.WaitForExit(60000)) {
            $process.Kill()
            throw "scanner_process_timeout"
        }
        return [pscustomobject]@{
            exit_code = $process.ExitCode
            stdout = $stdout
            stderr = $stderr
        }
    }
    finally {
        if ($started -and -not $process.HasExited) {
            try {
                $process.Kill()
                $process.WaitForExit()
            }
            catch {
                # Preserve the original test failure while still making a
                # best-effort attempt to stop the synthetic child process.
            }
        }
        $process.Dispose()
    }
}

function Read-AndAssertTestReceipt {
    param(
        [Parameter(Mandatory = $true)] $Invocation,
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][ValidateSet("pass", "fail")][string] $ExpectedResult,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]] $ExpectedFailedSubchecks
    )

    foreach ($output in @([string]$Invocation.stdout, [string]$Invocation.stderr)) {
        Assert-TestCondition `
            -Condition ($output.IndexOf($script:TestSentinel, [StringComparison]::Ordinal) -lt 0) `
            -FailureCode "scanner_output_disclosed_sentinel"
        Assert-TestCondition `
            -Condition ($output.IndexOf($Root, [StringComparison]::OrdinalIgnoreCase) -lt 0) `
            -FailureCode "scanner_output_disclosed_path"
    }
    Assert-TestCondition `
        -Condition ([string]::IsNullOrWhiteSpace([string]$Invocation.stderr)) `
        -FailureCode "scanner_receipt_wrote_stderr"
    Assert-TestCondition `
        -Condition (($ExpectedResult -ceq "pass" -and $Invocation.exit_code -eq 0) -or
            ($ExpectedResult -ceq "fail" -and $Invocation.exit_code -eq 1)) `
        -FailureCode "scanner_exit_code_invalid"

    try {
        $receipt = ([string]$Invocation.stdout).Trim() | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "scanner_receipt_json_invalid"
    }
    Assert-TestJsonShape `
        -Value $receipt `
        -ExpectedProperties @(
            "schema_version", "gate_id", "fixture_id", "runner_id", "result",
            "bindings", "summary", "subchecks") `
        -FailureCode "scanner_receipt_shape_invalid"
    Assert-TestJsonShape `
        -Value $receipt.bindings `
        -ExpectedProperties @(
            "package_msix_sha256", "candidate_git_commit", "source_verification_sha256",
            "artifact_catalog_sha256", "artifact_count") `
        -FailureCode "scanner_binding_shape_invalid"
    Assert-TestJsonShape `
        -Value $receipt.summary `
        -ExpectedProperties @("required", "passed", "failed", "not_run", "files_inspected") `
        -FailureCode "scanner_summary_shape_invalid"

    Assert-TestCondition `
        -Condition ([int]$receipt.schema_version -eq 1 -and
            [string]$receipt.gate_id -ceq "P2-NO-LEAKS" -and
            [string]$receipt.fixture_id -ceq "phase2-no-leaks-sentinel-scan-v1" -and
            [string]$receipt.runner_id -ceq "stein-phase2-no-leaks-scan-v1" -and
            [string]$receipt.result -ceq $ExpectedResult) `
        -FailureCode "scanner_receipt_identity_invalid"
    Assert-TestCondition `
        -Condition ([string]$receipt.bindings.package_msix_sha256 -ceq $script:PackageSha256 -and
            [string]$receipt.bindings.candidate_git_commit -ceq $script:CandidateCommit -and
            [string]$receipt.bindings.source_verification_sha256 -ceq
                $script:SourceVerificationSha256 -and
            [string]$receipt.bindings.artifact_catalog_sha256 -cmatch "^[0-9a-f]{64}$" -and
            [int]$receipt.bindings.artifact_count -ge 0) `
        -FailureCode "scanner_receipt_binding_invalid"

    $subchecks = @($receipt.subchecks)
    Assert-TestCondition `
        -Condition ($subchecks.Count -eq $script:ExpectedSubchecks.Count -and
            [int]$receipt.summary.required -eq $script:ExpectedSubchecks.Count -and
            ([int]$receipt.summary.passed + [int]$receipt.summary.failed +
                [int]$receipt.summary.not_run) -eq $script:ExpectedSubchecks.Count -and
            [int]$receipt.summary.not_run -eq 0 -and
            [int]$receipt.bindings.artifact_count -eq [int]$receipt.summary.files_inspected) `
        -FailureCode "scanner_receipt_summary_invalid"

    $actualFailed = @()
    for ($index = 0; $index -lt $subchecks.Count; $index++) {
        $subcheck = $subchecks[$index]
        Assert-TestJsonShape `
            -Value $subcheck `
            -ExpectedProperties @("id", "result", "files_inspected", "matches_found") `
            -FailureCode "scanner_subcheck_shape_invalid"
        Assert-TestCondition `
            -Condition ([string]$subcheck.id -ceq $script:ExpectedSubchecks[$index] -and
                [string]$subcheck.result -cin @("pass", "fail") -and
                [int]$subcheck.files_inspected -ge 0 -and
                [int]$subcheck.matches_found -ge 0) `
            -FailureCode "scanner_subcheck_value_invalid"
        if ([string]$subcheck.result -ceq "pass") {
            Assert-TestCondition `
                -Condition ([int]$subcheck.files_inspected -gt 0 -and
                    [int]$subcheck.matches_found -eq 0) `
                -FailureCode "scanner_pass_subcheck_invalid"
        }
        else {
            $actualFailed += [string]$subcheck.id
        }
    }
    $expectedFailed = @($ExpectedFailedSubchecks | Sort-Object)
    $actualFailed = @($actualFailed | Sort-Object)
    if ($actualFailed.Count -ne $expectedFailed.Count -or
        @(Compare-Object `
            -ReferenceObject $expectedFailed `
            -DifferenceObject $actualFailed `
            -CaseSensitive).Count -ne 0) {
        throw "scanner_failed_subcheck_set_invalid_expected_$([string]::Join('-', $expectedFailed))_actual_$([string]::Join('-', $actualFailed))"
    }
    return $receipt
}

function Invoke-TestCase {
    param(
        [Parameter(Mandatory = $true)][string] $HostPath,
        [Parameter(Mandatory = $true)][ValidateSet("pass", "fail")][string] $ExpectedResult,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]] $ExpectedFailedSubchecks,
        [scriptblock] $Mutation,
        [switch] $HoldDatabaseOpen,
        [switch] $CreateLogJunction,
        [switch] $MutateDatabaseDuringScan,
        [switch] $SkipProducerReceiptRefresh
    )

    $root = New-TestFixture
    $junctionTarget = $null
    $heldStream = $null
    try {
        if ($null -ne $Mutation) {
            & $Mutation $root
        }
        if ($MutateDatabaseDuringScan) {
            $producerBytes = [Text.Encoding]::ASCII.GetBytes("A" * 262144)
            Write-TestBytes `
                -Path (Join-Path $root (
                    "evidence\no-leaks-input\artifacts\crash-output.bin")) `
                -Bytes $producerBytes
            Update-TestProducerManifest -Root $root
        }
        if (-not $SkipProducerReceiptRefresh) {
            Update-TestProducerReceipt -Root $root
        }
        if ($CreateLogJunction) {
            $base = Get-TestBase
            $junctionTarget = Join-Path $base (
                "junction-target-$([Guid]::NewGuid().ToString('N'))")
            $null = New-Item -ItemType Directory -Path $junctionTarget -ErrorAction Stop
            Write-TestBytes `
                -Path (Join-Path $junctionTarget "core.stderr.log") `
                -Bytes ([Text.Encoding]::UTF8.GetBytes("synthetic-junction-stderr"))
            Write-TestBytes `
                -Path (Join-Path $junctionTarget "core.stdout.log") `
                -Bytes ([Text.Encoding]::UTF8.GetBytes("synthetic-junction-stdout"))
            $logRoot = Join-Path $root "install\logs"
            Remove-Item -LiteralPath $logRoot -Recurse -Force -ErrorAction Stop
            $null = New-Item `
                -ItemType Junction `
                -Path $logRoot `
                -Target $junctionTarget `
                -ErrorAction Stop
        }
        if ($HoldDatabaseOpen) {
            $heldStream = [IO.FileStream]::new(
                (Join-Path $root "install\data\stein.db"),
                [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None)
        }
        $invocation = if ($MutateDatabaseDuringScan) {
            Invoke-TestScanner `
                -HostPath $HostPath `
                -Root $root `
                -DuringExecution {
                    param($process, $fixtureRoot)
                    Invoke-TestDatabaseMutationAfterProducerReadBegins `
                        -Process $process `
                        -Root $fixtureRoot
                }
        }
        else {
            Invoke-TestScanner -HostPath $HostPath -Root $root
        }
        $null = Read-AndAssertTestReceipt `
            -Invocation $invocation `
            -Root $root `
            -ExpectedResult $ExpectedResult `
            -ExpectedFailedSubchecks $ExpectedFailedSubchecks
    }
    finally {
        if ($null -ne $heldStream) {
            $heldStream.Dispose()
        }
        Remove-TestFixture -Root $root -JunctionTarget $junctionTarget
    }
}

function Set-TestSentinelFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][ValidateSet("utf8", "utf16")][string] $Encoding,
        [switch] $CrossChunkBoundary
    )

    [byte[]]$sentinelBytes = if ($Encoding -ceq "utf8") {
        [Text.Encoding]::UTF8.GetBytes($script:TestSentinel)
    }
    else {
        [Text.Encoding]::Unicode.GetBytes($script:TestSentinel)
    }
    $prefixLength = if ($CrossChunkBoundary) { 65520 } else { 23 }
    $bytes = New-Object byte[] ($prefixLength + $sentinelBytes.Length + 17)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = 65
    }
    [Buffer]::BlockCopy($sentinelBytes, 0, $bytes, $prefixLength, $sentinelBytes.Length)
    Write-TestBytes -Path $Path -Bytes $bytes
}

function Invoke-HostTestMatrix {
    param([Parameter(Mandatory = $true)][string] $HostPath)

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "pass" `
        -ExpectedFailedSubchecks @()

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "pass" `
        -ExpectedFailedSubchecks @() `
        -Mutation {
            param($root)
            foreach ($relativePath in @(
                    "install\data\stein.db-journal",
                    "install\data\stein.db-shm",
                    "install\data\stein.db-wal",
                    "install\logs\core.stderr.log",
                    "install\logs\core.stdout.log")) {
                Write-TestBytes -Path (Join-Path $root $relativePath) -Bytes (New-Object byte[] 0)
            }
        }

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks @("audit_clean", "database_clean", "outbox_clean") `
        -Mutation {
            param($root)
            Set-TestSentinelFile `
                -Path (Join-Path $root "install\data\stein.db") `
                -Encoding "utf8" `
                -CrossChunkBoundary
        }

    $slotFailureMap = @{
        crash_output = "crash_output_clean"
        errors = "errors_clean"
        evidence_receipt = "evidence_clean"
        logs = "logs_clean"
        protocol_receipt = "protocol_clean"
        recovery_copy = "recovery_copy_clean"
        traces = "traces_clean"
    }
    foreach ($slot in $script:ProducerSlots) {
        $slotId = [string]$slot.id
        $relativePath = [string]$slot.relative_path
        $script:CurrentProducerRelativePath = $relativePath
        Invoke-TestCase `
            -HostPath $HostPath `
            -ExpectedResult "fail" `
            -ExpectedFailedSubchecks @([string]$slotFailureMap[$slotId]) `
            -Mutation {
                param($root)
                Set-TestSentinelFile `
                    -Path (Join-Path $root (
                        "evidence\no-leaks-input\$script:CurrentProducerRelativePath")) `
                    -Encoding "utf16"
                Update-TestProducerManifest -Root $root
            }
    }
    Remove-Variable -Name CurrentProducerRelativePath -Scope Script -ErrorAction SilentlyContinue

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks @("credential_metadata_clean") `
        -Mutation {
            param($root)
            Write-TestCredentialMetadata -Root $root -UserName $script:TestSentinel
        }

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks @("package_clean") `
        -Mutation {
            param($root)
            Set-TestSentinelFile `
                -Path (Join-Path $root "package\unpacked\AppxManifest.xml") `
                -Encoding "utf8"
        }

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks $script:ExpectedSubchecks `
        -Mutation {
            param($root)
            Remove-Item `
                -LiteralPath (Join-Path $root "evidence\no-leaks-input\artifacts\traces.bin") `
                -Force `
                -ErrorAction Stop
        } `
        -SkipProducerReceiptRefresh

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks $script:ExpectedSubchecks `
        -Mutation {
            param($root)
            Write-TestBytes `
                -Path (Join-Path $root "unexpected.bin") `
                -Bytes ([Text.Encoding]::UTF8.GetBytes("synthetic-extra"))
        }

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks $script:ExpectedSubchecks `
        -CreateLogJunction

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks $script:ExpectedSubchecks `
        -HoldDatabaseOpen

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks $script:ExpectedSubchecks `
        -MutateDatabaseDuringScan

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks $script:ExpectedSubchecks `
        -Mutation {
            param($root)
            Write-TestBytes `
                -Path (Join-Path $root "evidence\no-leaks-input\artifacts\errors.bin") `
                -Bytes ([Text.Encoding]::UTF8.GetBytes("synthetic-binding-mismatch"))
        }

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks $script:ExpectedSubchecks `
        -Mutation {
            param($root)
            $path = Join-Path $root "evidence\no-leaks-input\producer-receipt.json"
            $receipt = [IO.File]::ReadAllText($path) | ConvertFrom-Json -ErrorAction Stop
            $receipt.bindings.producer_source_sha256 = "0" * 64
            Write-TestUtf8Json -Path $path -Value $receipt
        } `
        -SkipProducerReceiptRefresh

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks $script:ExpectedSubchecks `
        -Mutation {
            param($root)
            $path = Join-Path $root "evidence\no-leaks-input\producer-manifest.json"
            $original = [IO.File]::ReadAllBytes($path)
            $expanded = New-Object byte[] 270000
            [Buffer]::BlockCopy($original, 0, $expanded, 0, $original.Length)
            for ($index = $original.Length; $index -lt $expanded.Length; $index++) {
                $expanded[$index] = 32
            }
            Write-TestBytes -Path $path -Bytes $expanded
        }

    Invoke-TestCase `
        -HostPath $HostPath `
        -ExpectedResult "fail" `
        -ExpectedFailedSubchecks $script:ExpectedSubchecks `
        -Mutation {
            param($root)
            Write-TestCredentialMetadata -Root $root -UserName ("x" * 66000)
        }
}

$windowsPowerShell = Join-Path (
    [Environment]::GetFolderPath([Environment+SpecialFolder]::System)) (
    "WindowsPowerShell\v1.0\powershell.exe")
$pwshCommand = Get-Command pwsh.exe -ErrorAction Stop
$pwsh = [string]$pwshCommand.Source
foreach ($hostPath in @($windowsPowerShell, $pwsh)) {
    $hostItem = Get-Item -LiteralPath $hostPath -Force -ErrorAction Stop
    Assert-TestCondition `
        -Condition (-not $hostItem.PSIsContainer -and
            (($hostItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) -and
            $hostItem.Length -gt 0) `
        -FailureCode "required_test_host_invalid"
    Invoke-HostTestMatrix -HostPath $hostItem.FullName
}

$base = Get-TestBase
if (@(Get-ChildItem -LiteralPath $base -Force -ErrorAction Stop).Count -eq 0) {
    Remove-Item -LiteralPath $base -Force -ErrorAction Stop
}

[Console]::Out.WriteLine("P2-NO-LEAKS synthetic scanner contract tests passed on both PowerShell hosts.")
