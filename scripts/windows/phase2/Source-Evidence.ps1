$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

function Get-SteinSourceEvidenceSha256 {
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

function Get-SteinSourceEvidenceTextSha256 {
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
    }
}

function Get-SteinSourceEvidenceRegularFileItem {
    param([Parameter(Mandatory = $true)][string] $Path)

    $candidate = [IO.Path]::GetFullPath($Path)
    $probe = Split-Path -Parent $candidate
    while (-not [string]::IsNullOrWhiteSpace($probe)) {
        $ancestor = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $ancestor.PSIsContainer -or
            (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "A source tool path has an invalid ancestor."
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $probe, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $probe = $parent
    }
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -le 0) {
        throw "A source tool path is not a regular non-empty file."
    }
    return $item
}

function Read-SteinSourceEvidenceLockedUtf8File {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [int] $MaximumBytes = 65536
    )

    $item = Get-SteinSourceEvidenceRegularFileItem -Path $Path
    if ($item.Length -gt $MaximumBytes) {
        throw "A source-evidence UTF-8 file is invalid."
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $item.Length -or
            $stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "A source-evidence UTF-8 file changed during capture."
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "A source-evidence UTF-8 file could not be captured."
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
        try {
            $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
            if ($text.Length -gt 0 -and [int][char]$text[0] -eq 0xFEFF) {
                $text = $text.Substring(1)
            }
        }
        catch {
            throw "A source-evidence UTF-8 file has invalid encoding."
        }
        return [pscustomobject]@{
            text = $text
            size = [long]$bytes.Length
            sha256 = $digest
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Write-SteinSourceEvidenceJson {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $Value,
        [int] $Depth = 16
    )

    $json = $Value | ConvertTo-Json -Depth $Depth
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

function ConvertTo-SteinSourceProcessArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value)

    if ($Value.Length -gt 4096) {
        throw "A source-evidence process argument exceeds its bound."
    }
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
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

function Invoke-SteinSourceEvidenceProcess {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory,
        [int[]] $AllowedExitCodes = @(0),
        [int] $MaximumStandardOutputCharacters = 4096,
        [int] $MaximumStandardErrorCharacters = 4096
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.Arguments = (@($Arguments | ForEach-Object {
                ConvertTo-SteinSourceProcessArgument -Value $_
            }) -join " ")
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $startInfo.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "A source-evidence process could not be launched."
        }
        # Materialize the native handle before waiting so Windows PowerShell
        # 5.1 cannot release it before ExitCode is observed.
        $null = $process.Handle
        $standardOutputTask = $process.StandardOutput.ReadToEndAsync()
        $standardErrorTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $standardOutput = $standardOutputTask.GetAwaiter().GetResult()
        $standardError = $standardErrorTask.GetAwaiter().GetResult()
        if ($standardOutput.Length -gt $MaximumStandardOutputCharacters -or
            $standardError.Length -gt $MaximumStandardErrorCharacters) {
            throw "A source-evidence process exceeded its bounded output contract."
        }
        if ($process.ExitCode -notin $AllowedExitCodes) {
            throw "A source-evidence process returned an unexpected exit code."
        }
        return [pscustomobject]@{
            exit_code = [int]$process.ExitCode
            stdout = [string]$standardOutput
            stderr = [string]$standardError
        }
    }
    finally {
        $process.Dispose()
    }
}

function Get-SteinSourceEvidenceFileRecord {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $Path
    )

    $repositoryPath = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $candidate = [IO.Path]::GetFullPath($Path)
    $prefix = "$repositoryPath$([IO.Path]::DirectorySeparatorChar)"
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "A source-evidence file escaped the repository."
    }
    $probe = Split-Path -Parent $candidate
    while ($true) {
        if ($probe.Length -lt $repositoryPath.Length) {
            throw "A source-evidence file escaped the repository."
        }
        $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "A source-evidence file has an invalid ancestor."
        }
        if ([string]::Equals(
                $probe,
                $repositoryPath,
                [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            throw "A source-evidence file escaped the repository."
        }
        $probe = $parent
    }
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -lt 0) {
        throw "A source-evidence file is not a regular file."
    }
    return [ordered]@{
        path = $candidate.Substring($prefix.Length).Replace("\", "/")
        size = [long]$item.Length
        sha256 = Get-SteinSourceEvidenceSha256 -Path $candidate
    }
}

function Get-SteinSourceEvidenceUniqueCapture {
    param(
        [Parameter(Mandatory = $true)][string] $Source,
        [Parameter(Mandatory = $true)][string] $Pattern,
        [Parameter(Mandatory = $true)][string] $GroupName,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $matches = [regex]::Matches(
        $Source,
        $Pattern,
        [Text.RegularExpressions.RegexOptions]::Multiline)
    if ($matches.Count -ne 1) {
        throw "The $Description source identifier is not unique."
    }
    $value = [string]$matches[0].Groups[$GroupName].Value
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 128) {
        throw "The $Description source identifier is outside its bound."
    }
    return $value
}

function Get-SteinSourceEvidenceTomlPackageVersion {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Section
    )

    $source = [IO.File]::ReadAllText($Path)
    $escapedSection = [regex]::Escape($Section)
    $sectionMatch = [regex]::Match(
        $source,
        "(?ms)^\[$escapedSection\]\s*(?<body>.*?)(?=^\[|\z)")
    if (-not $sectionMatch.Success) {
        throw "A required TOML package section is unavailable."
    }
    $version = Get-SteinSourceEvidenceUniqueCapture `
        -Source $sectionMatch.Groups["body"].Value `
        -Pattern '^version\s*=\s*"(?<value>[^"]+)"\s*$' `
        -GroupName "value" `
        -Description "TOML package version"
    if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
        throw "A TOML package version is invalid."
    }
    return $version
}

function Get-SteinSourceEvidenceBuildVersions {
    param([Parameter(Mandatory = $true)][string] $RepositoryRoot)

    $cargoManifest = Join-Path $RepositoryRoot "Cargo.toml"
    $edgeHostManifest = Join-Path $RepositoryRoot "apps\edge-native-host\Cargo.toml"
    $desktopManifest = Join-Path $RepositoryRoot "apps\desktop\package.json"
    $edgeManifest = Join-Path $RepositoryRoot "extensions\edge\package.json"
    $workspaceSource = [IO.File]::ReadAllText($cargoManifest)
    $workspaceSection = [regex]::Match(
        $workspaceSource,
        '(?ms)^\[workspace\.package\]\s*(?<body>.*?)(?=^\[|\z)')
    if (-not $workspaceSection.Success) {
        throw "The Rust workspace package section is unavailable."
    }
    $rustVersion = Get-SteinSourceEvidenceUniqueCapture `
        -Source $workspaceSection.Groups["body"].Value `
        -Pattern '^rust-version\s*=\s*"(?<value>[^"]+)"\s*$' `
        -GroupName "value" `
        -Description "workspace Rust version"
    if ($rustVersion -notmatch '^[0-9]+\.[0-9]+(?:\.[0-9]+)?$') {
        throw "The workspace Rust version is invalid."
    }

    $desktop = [IO.File]::ReadAllText($desktopManifest) | ConvertFrom-Json
    $edge = [IO.File]::ReadAllText($edgeManifest) | ConvertFrom-Json
    foreach ($manifest in @($desktop, $edge)) {
        if ($null -eq $manifest.PSObject.Properties["version"] -or
            [string]$manifest.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
            throw "A Node package version is invalid."
        }
    }

    return [ordered]@{
        rust_workspace_package = Get-SteinSourceEvidenceTomlPackageVersion `
            -Path $cargoManifest `
            -Section "workspace.package"
        minimum_rust = $rustVersion
        desktop_package = [string]$desktop.version
        edge_extension_package = [string]$edge.version
        edge_native_host_package = Get-SteinSourceEvidenceTomlPackageVersion `
            -Path $edgeHostManifest `
            -Section "package"
        manifest_files = @(
            Get-SteinSourceEvidenceFileRecord -RepositoryRoot $RepositoryRoot -Path $cargoManifest
            Get-SteinSourceEvidenceFileRecord -RepositoryRoot $RepositoryRoot -Path $desktopManifest
            Get-SteinSourceEvidenceFileRecord -RepositoryRoot $RepositoryRoot -Path $edgeManifest
            Get-SteinSourceEvidenceFileRecord -RepositoryRoot $RepositoryRoot -Path $edgeHostManifest
        )
    }
}

function Get-SteinSourceEvidenceContractVersions {
    param([Parameter(Mandatory = $true)][string] $RepositoryRoot)

    $storePath = Join-Path $RepositoryRoot "crates\stein-store-sqlite\src\lib.rs"
    $domainPath = Join-Path $RepositoryRoot "crates\stein-core\src\phase2_domain.rs"
    $policyPath = Join-Path $RepositoryRoot "crates\stein-core\src\second_mind.rs"
    $protocolPath = Join-Path $RepositoryRoot "crates\stein-protocol\src\version.rs"
    $storeSource = [IO.File]::ReadAllText($storePath)
    $domainSource = [IO.File]::ReadAllText($domainPath)
    $policySource = [IO.File]::ReadAllText($policyPath)
    $protocolSource = [IO.File]::ReadAllText($protocolPath)

    $databaseSchema = [int](Get-SteinSourceEvidenceUniqueCapture `
            -Source $storeSource `
            -Pattern '^const SCHEMA_VERSION:\s*i64\s*=\s*(?<value>[0-9]+);\s*$' `
            -GroupName "value" `
            -Description "SQLite application schema")
    $identitySchema = [int](Get-SteinSourceEvidenceUniqueCapture `
            -Source $domainSource `
            -Pattern '^pub const STEIN_IDENTITY_SCHEMA_V1:\s*u16\s*=\s*(?<value>[0-9]+);\s*$' `
            -GroupName "value" `
            -Description "identity schema")
    $preferencesSchema = [int](Get-SteinSourceEvidenceUniqueCapture `
            -Source $domainSource `
            -Pattern '^pub const USER_PREFERENCES_SCHEMA_V1:\s*u16\s*=\s*(?<value>[0-9]+);\s*$' `
            -GroupName "value" `
            -Description "preferences schema")
    $policyInputSchema = [int](Get-SteinSourceEvidenceUniqueCapture `
            -Source $domainSource `
            -Pattern '^\s*pub const INPUT_SCHEMA_V1:\s*u16\s*=\s*(?<value>[0-9]+);\s*$' `
            -GroupName "value" `
            -Description "policy input schema")
    $policyProfile = Get-SteinSourceEvidenceUniqueCapture `
        -Source $policySource `
        -Pattern '^const POLICY_PROFILE_ID:\s*&str\s*=\s*"(?<value>[a-z0-9-]+)";\s*$' `
        -GroupName "value" `
        -Description "policy profile"
    $protocolMajor = [int](Get-SteinSourceEvidenceUniqueCapture `
            -Source $protocolSource `
            -Pattern '^pub const PROTOCOL_MAJOR:\s*u16\s*=\s*(?<value>[0-9]+);\s*$' `
            -GroupName "value" `
            -Description "protocol major")
    $protocolMinor = [int](Get-SteinSourceEvidenceUniqueCapture `
            -Source $protocolSource `
            -Pattern '^pub const PROTOCOL_MINOR:\s*u16\s*=\s*(?<value>[0-9]+);\s*$' `
            -GroupName "value" `
            -Description "protocol minor")
    $messageSchema = [int](Get-SteinSourceEvidenceUniqueCapture `
            -Source $protocolSource `
            -Pattern '^pub const SCHEMA_VERSION_V1:\s*u16\s*=\s*(?<value>[0-9]+);\s*$' `
            -GroupName "value" `
            -Description "protocol message schema")

    $migrationBlock = [regex]::Match(
        $storeSource,
        '(?ms)^const MIGRATIONS:\s*&\[MigrationDefinition\]\s*=\s*&\[(?<body>.*?)^\];')
    if (-not $migrationBlock.Success) {
        throw "The SQLite migration catalog is unavailable."
    }
    $migrationMatches = [regex]::Matches(
        $migrationBlock.Groups["body"].Value,
        '(?ms)MigrationDefinition\s*\{\s*schema_version:\s*(?<schema>[0-9]+),\s*owner:\s*"(?<owner>[a-z0-9_]+)",\s*migration_id:\s*"(?<id>[a-z0-9-]+)",')
    if ($migrationMatches.Count -le 0 -or $migrationMatches.Count -gt 128) {
        throw "The SQLite migration catalog is outside its bound."
    }
    $migrationIdentifiers = @(
        foreach ($migrationMatch in $migrationMatches) {
            [ordered]@{
                schema_version = [int]$migrationMatch.Groups["schema"].Value
                owner = [string]$migrationMatch.Groups["owner"].Value
                migration_id = [string]$migrationMatch.Groups["id"].Value
            }
        }
    )
    $identitySet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($migration in $migrationIdentifiers) {
        $key = "$($migration.owner)|$($migration.migration_id)"
        if (-not $identitySet.Add($key) -or
            $migration.schema_version -le 0 -or
            $migration.schema_version -gt $databaseSchema) {
            throw "The SQLite migration catalog identifiers are invalid."
        }
    }
    $maximumMigrationSchema = @($migrationIdentifiers | ForEach-Object {
            [int]$_["schema_version"]
        } | Measure-Object -Maximum)[0].Maximum
    if ([int]$maximumMigrationSchema -ne $databaseSchema) {
        throw "The SQLite schema and migration catalog disagree."
    }
    $migrationIdentifierJson = $migrationIdentifiers | ConvertTo-Json -Depth 4 -Compress

    return [ordered]@{
        schemas = [ordered]@{
            sqlite_application = $databaseSchema
            stein_identity = $identitySchema
            user_preferences = $preferencesSchema
            protocol_message = $messageSchema
        }
        migrations = [ordered]@{
            count = $migrationIdentifiers.Count
            identifiers = $migrationIdentifiers
            identifiers_sha256 = Get-SteinSourceEvidenceTextSha256 -Value $migrationIdentifierJson
            implementation_sha256 = Get-SteinSourceEvidenceSha256 -Path $storePath
        }
        protocol = [ordered]@{
            major = $protocolMajor
            minimum_minor = 0
            maximum_minor = $protocolMinor
            current = "$protocolMajor.$protocolMinor"
            message_schema = $messageSchema
            implementation_sha256 = Get-SteinSourceEvidenceSha256 -Path $protocolPath
        }
        policy = [ordered]@{
            profile_id = $policyProfile
            input_schema = $policyInputSchema
            implementation_sha256 = Get-SteinSourceEvidenceSha256 -Path $policyPath
            domain_schema_implementation_sha256 = Get-SteinSourceEvidenceSha256 -Path $domainPath
        }
    }
}

function Get-SteinSourceEvidencePathManifest {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]] $RelativePaths,
        [switch] $AllowMissing
    )

    $repositoryPath = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $prefix = "$repositoryPath$([IO.Path]::DirectorySeparatorChar)"
    $unique = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($relativePath in $RelativePaths) {
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            [IO.Path]::IsPathRooted($relativePath) -or
            $relativePath.IndexOf([char]0) -ge 0) {
            throw "A Git source path is invalid."
        }
        $null = $unique.Add($relativePath.Replace("\", "/"))
    }
    $paths = @($unique)
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $builder = [Text.StringBuilder]::new()
    foreach ($relativePath in $paths) {
        $nativeRelativePath = $relativePath.Replace("/", [IO.Path]::DirectorySeparatorChar)
        $candidate = [IO.Path]::GetFullPath((Join-Path $repositoryPath $nativeRelativePath))
        if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "A Git source path escaped the repository."
        }
        $pathByteCount = [Text.UTF8Encoding]::new($false).GetByteCount($relativePath)
        if (-not (Test-Path -LiteralPath $candidate)) {
            if (-not $AllowMissing) {
                throw "An untracked Git source path is unavailable."
            }
            $null = $builder.Append("$pathByteCount`:$relativePath|missing|0|`n")
            continue
        }
        $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "A Git source path is not a regular file."
        }
        $digest = Get-SteinSourceEvidenceSha256 -Path $candidate
        $null = $builder.Append(
            "$pathByteCount`:$relativePath|file|$([long]$item.Length)|$digest|`n")
    }
    return [ordered]@{
        path_count = $paths.Count
        manifest_sha256 = Get-SteinSourceEvidenceTextSha256 -Value $builder.ToString()
    }
}

function Get-SteinSourceEvidenceRepositoryState {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $GitExecutable
    )

    $invoke = {
        param([string[]] $Arguments, [int[]] $AllowedExitCodes = @(0), [int] $MaximumOutput = 1048576)
        Invoke-SteinSourceEvidenceProcess `
            -Executable $GitExecutable `
            -Arguments $Arguments `
            -WorkingDirectory $RepositoryRoot `
            -AllowedExitCodes $AllowedExitCodes `
            -MaximumStandardOutputCharacters $MaximumOutput `
            -MaximumStandardErrorCharacters 8192
    }
    $headResult = & $invoke @("rev-parse", "--verify", "HEAD") @(0) 256
    $headCommit = $headResult.stdout.Trim()
    if ($headCommit -notmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
        throw "The Git HEAD commit identifier is invalid."
    }
    $objectFormat = if ($headCommit.Length -eq 40) { "sha1" } else { "sha256" }

    $status = & $invoke @(
        "-c", "core.quotepath=false", "status", "--porcelain=v1", "-z", "--untracked-files=all")
    $rawDiff = & $invoke @(
        "-c", "core.quotepath=false", "diff", "--raw", "--full-index", "--no-ext-diff", "-z", "HEAD", "--")
    $trackedNames = & $invoke @(
        "-c", "core.quotepath=false", "diff", "--name-only", "--no-ext-diff", "-z", "HEAD", "--")
    $untrackedNames = & $invoke @(
        "-c", "core.quotepath=false", "ls-files", "--others", "--exclude-standard", "-z")
    $staged = & $invoke @("diff", "--cached", "--quiet", "--exit-code", "--") @(0, 1) 0
    $unstaged = & $invoke @("diff", "--quiet", "--exit-code", "--") @(0, 1) 0

    $trackedPaths = @($trackedNames.stdout.Split([char]0) | Where-Object { $_.Length -gt 0 })
    $untrackedPaths = @($untrackedNames.stdout.Split([char]0) | Where-Object { $_.Length -gt 0 })
    $trackedManifest = Get-SteinSourceEvidencePathManifest `
        -RepositoryRoot $RepositoryRoot `
        -RelativePaths $trackedPaths `
        -AllowMissing
    $untrackedManifest = Get-SteinSourceEvidencePathManifest `
        -RepositoryRoot $RepositoryRoot `
        -RelativePaths $untrackedPaths
    $statusDigest = Get-SteinSourceEvidenceTextSha256 -Value $status.stdout
    $rawDiffDigest = Get-SteinSourceEvidenceTextSha256 -Value $rawDiff.stdout
    $stateMaterial = @(
        "stein-source-worktree-v1",
        "head=$headCommit",
        "status=$statusDigest",
        "raw_diff=$rawDiffDigest",
        "tracked_manifest=$($trackedManifest.manifest_sha256)",
        "untracked_manifest=$($untrackedManifest.manifest_sha256)"
    ) -join "`n"
    $hasStagedChanges = $staged.exit_code -eq 1
    $hasUnstagedChanges = $unstaged.exit_code -eq 1
    $isClean = -not $hasStagedChanges -and
        -not $hasUnstagedChanges -and
        $untrackedManifest.path_count -eq 0

    return [ordered]@{
        head_commit = $headCommit
        object_format = $objectFormat
        clean = $isClean
        has_staged_changes = $hasStagedChanges
        has_unstaged_changes = $hasUnstagedChanges
        tracked_changed_path_count = $trackedManifest.path_count
        untracked_path_count = $untrackedManifest.path_count
        porcelain_status_sha256 = $statusDigest
        raw_diff_sha256 = $rawDiffDigest
        tracked_manifest_sha256 = $trackedManifest.manifest_sha256
        untracked_manifest_sha256 = $untrackedManifest.manifest_sha256
        state_sha256 = Get-SteinSourceEvidenceTextSha256 -Value $stateMaterial
    }
}

function Get-SteinSourceEvidenceToolRecord {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string[]] $VersionArguments,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory,
        [switch] $AllowStandardError
    )

    $item = Get-SteinSourceEvidenceRegularFileItem -Path $Executable
    $initialHash = Get-SteinSourceEvidenceSha256 -Path $item.FullName
    $result = Invoke-SteinSourceEvidenceProcess `
        -Executable $item.FullName `
        -Arguments $VersionArguments `
        -WorkingDirectory $WorkingDirectory `
        -MaximumStandardOutputCharacters 512 `
        -MaximumStandardErrorCharacters 512
    $version = $result.stdout.Trim()
    if ($version.Length -le 0 -or
        $version.Length -gt 160 -or
        $version -notmatch '^[\x20-\x7e]+$' -or
        $version.Contains("`r") -or
        $version.Contains("`n") -or
        (-not $AllowStandardError -and
            -not [string]::IsNullOrWhiteSpace([string]$result.stderr))) {
        throw "A source tool returned an invalid bounded version."
    }
    $completedHash = Get-SteinSourceEvidenceSha256 -Path $item.FullName
    if ($initialHash -cne $completedHash) {
        throw "A source tool executable changed during provenance capture."
    }
    return [ordered]@{
        version = $version
        executable_sha256 = $completedHash
    }
}

function Get-SteinSourceEvidenceRustupToolchainId {
    param(
        [Parameter(Mandatory = $true)][string] $RustupExecutable,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )

    $result = Invoke-SteinSourceEvidenceProcess `
        -Executable $RustupExecutable `
        -Arguments @("show", "active-toolchain") `
        -WorkingDirectory $WorkingDirectory `
        -MaximumStandardOutputCharacters 4096 `
        -MaximumStandardErrorCharacters 512
    if (-not [string]::IsNullOrWhiteSpace([string]$result.stderr)) {
        throw "The active Rust toolchain emitted unexpected diagnostics."
    }
    $active = $result.stdout.Trim()
    if ($active.Length -le 0 -or $active.Length -gt 4096 -or
        $active.Contains("`r") -or $active.Contains("`n")) {
        throw "The active Rust toolchain identity is invalid."
    }
    $toolchain = @($active -split '\s+', 2)[0]
    if ($toolchain -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]{2,127}$') {
        throw "The active Rust toolchain identity is invalid."
    }
    return $toolchain
}

function Get-SteinSourceEvidenceRustToolRecord {
    param(
        [Parameter(Mandatory = $true)][string] $LauncherExecutable,
        [Parameter(Mandatory = $true)][string] $RustupExecutable,
        [Parameter(Mandatory = $true)][ValidateSet("cargo", "rustc")][string] $ToolName,
        [Parameter(Mandatory = $true)][string] $RustupToolchain,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )

    $launcher = Get-SteinSourceEvidenceToolRecord `
        -Executable $LauncherExecutable `
        -VersionArguments @("--version") `
        -WorkingDirectory $WorkingDirectory
    $whichResult = Invoke-SteinSourceEvidenceProcess `
        -Executable $RustupExecutable `
        -Arguments @("which", "--toolchain", $RustupToolchain, $ToolName) `
        -WorkingDirectory $WorkingDirectory `
        -MaximumStandardOutputCharacters 4096 `
        -MaximumStandardErrorCharacters 512
    $resolvedPath = $whichResult.stdout.Trim()
    if (-not [string]::IsNullOrWhiteSpace([string]$whichResult.stderr) -or
        $resolvedPath.Length -le 0 -or $resolvedPath.Length -gt 4096 -or
        $resolvedPath.Contains("`r") -or $resolvedPath.Contains("`n") -or
        -not [IO.Path]::IsPathRooted($resolvedPath) -or
        [IO.Path]::GetFileName($resolvedPath) -cne "$ToolName.exe") {
        throw "A rustup-selected tool executable is invalid."
    }
    $resolved = Get-SteinSourceEvidenceToolRecord `
        -Executable ([IO.Path]::GetFullPath($resolvedPath)) `
        -VersionArguments @("--version") `
        -WorkingDirectory $WorkingDirectory
    if ([string]$launcher.version -cne [string]$resolved.version) {
        throw "A Rust launcher and rustup-selected payload disagree."
    }
    return [ordered]@{
        version = [string]$launcher.version
        executable_sha256 = [string]$launcher.executable_sha256
        rustup_toolchain = $RustupToolchain
        resolved_version = [string]$resolved.version
        resolved_executable_sha256 = [string]$resolved.executable_sha256
    }
}

function Get-SteinSourceEvidencePnpmToolRecord {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string] $NodeExecutable,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )

    $record = Get-SteinSourceEvidenceToolRecord `
        -Executable $Executable `
        -VersionArguments @("--version") `
        -WorkingDirectory $WorkingDirectory
    $shim = Read-SteinSourceEvidenceLockedUtf8File `
        -Path $Executable `
        -MaximumBytes 65536
    if ([string]$shim.sha256 -cne [string]$record.executable_sha256) {
        throw "The pnpm launcher changed during provenance capture."
    }
    $entrypointMatches = [regex]::Matches(
        [string]$shim.text,
        '"%dp0%\\(?<relative>node_modules\\pnpm\\bin\\pnpm\.(?:cjs|mjs|js))"\s+%\*',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($entrypointMatches.Count -ne 1) {
        throw "The pnpm launcher entrypoint contract is invalid."
    }
    $relativeEntrypoint = [string]$entrypointMatches[0].Groups['relative'].Value
    if ($relativeEntrypoint.Length -le 0 -or $relativeEntrypoint.Length -gt 256 -or
        $relativeEntrypoint.Contains('..') -or
        [IO.Path]::IsPathRooted($relativeEntrypoint)) {
        throw "The pnpm launcher entrypoint contract is invalid."
    }
    $shimRoot = [IO.Path]::GetFullPath((Split-Path -Parent $Executable)).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $entrypointPath = [IO.Path]::GetFullPath((Join-Path $shimRoot $relativeEntrypoint))
    if (-not $entrypointPath.StartsWith(
            "$shimRoot$([IO.Path]::DirectorySeparatorChar)",
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "The pnpm launcher entrypoint escaped its installation root."
    }
    $entrypointItem = Get-SteinSourceEvidenceRegularFileItem -Path $entrypointPath
    $siblingNode = Join-Path $shimRoot "node.exe"
    if (Test-Path -LiteralPath $siblingNode -PathType Leaf) {
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath($siblingNode),
                [IO.Path]::GetFullPath($NodeExecutable),
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "The pnpm launcher selects a different Node runtime."
        }
    }
    return [ordered]@{
        version = [string]$record.version
        executable_sha256 = [string]$record.executable_sha256
        resolved_entrypoint_sha256 = Get-SteinSourceEvidenceSha256 `
            -Path $entrypointItem.FullName
    }
}

function Get-SteinSourceEvidenceGitToolRecord {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )

    $launcherItem = Get-SteinSourceEvidenceRegularFileItem -Path $Executable
    $launcherDirectory = Split-Path -Parent $launcherItem.FullName
    if ([IO.Path]::GetFileName($launcherItem.FullName) -cne "git.exe" -or
        [IO.Path]::GetFileName($launcherDirectory) -cne "cmd") {
        throw "The Git for Windows launcher location is invalid."
    }
    $installationRoot = [IO.Path]::GetFullPath(
        (Split-Path -Parent $launcherDirectory))
    $resolvedPath = [IO.Path]::GetFullPath(
        (Join-Path $installationRoot "mingw64\bin\git.exe"))
    if (-not $resolvedPath.StartsWith(
            "$installationRoot$([IO.Path]::DirectorySeparatorChar)",
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "The resolved Git payload escaped its installation root."
    }
    $launcher = Get-SteinSourceEvidenceToolRecord `
        -Executable $launcherItem.FullName `
        -VersionArguments @("--version") `
        -WorkingDirectory $WorkingDirectory
    $resolved = Get-SteinSourceEvidenceToolRecord `
        -Executable $resolvedPath `
        -VersionArguments @("--version") `
        -WorkingDirectory $WorkingDirectory
    if ([string]$launcher.version -cne [string]$resolved.version) {
        throw "The Git launcher and resolved payload disagree."
    }
    return [ordered]@{
        version = [string]$launcher.version
        executable_sha256 = [string]$launcher.executable_sha256
        resolved_version = [string]$resolved.version
        resolved_executable_sha256 = [string]$resolved.executable_sha256
    }
}

function Get-SteinSourceEvidencePwshToolRecord {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )

    $record = Get-SteinSourceEvidenceToolRecord `
        -Executable $Executable `
        -VersionArguments @("--version") `
        -WorkingDirectory $WorkingDirectory
    $signature = Get-AuthenticodeSignature -LiteralPath $Executable -ErrorAction Stop
    $expectedSubject =
        "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
    if ([string]$signature.Status -cne "Valid" -or
        $null -eq $signature.SignerCertificate -or
        [string]$signature.SignerCertificate.Subject -cne $expectedSubject) {
        throw "The pwsh source-verification host has an invalid publisher signature."
    }
    return [ordered]@{
        version = [string]$record.version
        executable_sha256 = [string]$record.executable_sha256
        authenticode_status = "valid"
        signer_subject = $expectedSubject
    }
}

function Get-SteinSourceEvidenceToolchain {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][Collections.IDictionary] $ToolExecutables
    )

    foreach ($requiredTool in @("cargo", "rustc", "rustup", "node", "pnpm", "git", "pwsh")) {
        if (-not $ToolExecutables.Contains($requiredTool) -or
            [string]::IsNullOrWhiteSpace([string]$ToolExecutables[$requiredTool])) {
            throw "A required source tool executable is unavailable."
        }
    }
    $rustupExecutable = [string]$ToolExecutables["rustup"]
    $rustup = Get-SteinSourceEvidenceToolRecord `
        -Executable $rustupExecutable `
        -VersionArguments @("--version") `
        -WorkingDirectory $RepositoryRoot `
        -AllowStandardError
    $rustupToolchain = Get-SteinSourceEvidenceRustupToolchainId `
        -RustupExecutable $rustupExecutable `
        -WorkingDirectory $RepositoryRoot
    return [ordered]@{
        cargo = Get-SteinSourceEvidenceRustToolRecord `
            -LauncherExecutable ([string]$ToolExecutables["cargo"]) `
            -RustupExecutable $rustupExecutable `
            -ToolName "cargo" `
            -RustupToolchain $rustupToolchain `
            -WorkingDirectory $RepositoryRoot
        rustc = Get-SteinSourceEvidenceRustToolRecord `
            -LauncherExecutable ([string]$ToolExecutables["rustc"]) `
            -RustupExecutable $rustupExecutable `
            -ToolName "rustc" `
            -RustupToolchain $rustupToolchain `
            -WorkingDirectory $RepositoryRoot
        rustup = $rustup
        node = Get-SteinSourceEvidenceToolRecord `
            -Executable ([string]$ToolExecutables["node"]) `
            -VersionArguments @("--version") `
            -WorkingDirectory $RepositoryRoot
        pnpm = Get-SteinSourceEvidencePnpmToolRecord `
            -Executable ([string]$ToolExecutables["pnpm"]) `
            -NodeExecutable ([string]$ToolExecutables["node"]) `
            -WorkingDirectory $RepositoryRoot
        git = Get-SteinSourceEvidenceGitToolRecord `
            -Executable ([string]$ToolExecutables["git"]) `
            -WorkingDirectory $RepositoryRoot
        pwsh = Get-SteinSourceEvidencePwshToolRecord `
            -Executable ([string]$ToolExecutables["pwsh"]) `
            -WorkingDirectory $RepositoryRoot
    }
}

function Get-SteinSourceEvidenceProvenance {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][Collections.IDictionary] $ToolExecutables
    )

    $repositoryPath = [IO.Path]::GetFullPath($RepositoryRoot)
    $dependencyLocks = @(
        "Cargo.lock",
        "apps\desktop\pnpm-lock.yaml",
        "extensions\edge\pnpm-lock.yaml",
        "apps\edge-native-host\Cargo.lock"
    )
    return [ordered]@{
        schema_version = 2
        classification = "bounded_content_free_source_provenance"
        repository = Get-SteinSourceEvidenceRepositoryState `
            -RepositoryRoot $repositoryPath `
            -GitExecutable ([string]$ToolExecutables["git"])
        toolchain = Get-SteinSourceEvidenceToolchain `
            -RepositoryRoot $repositoryPath `
            -ToolExecutables $ToolExecutables
        build_versions = Get-SteinSourceEvidenceBuildVersions -RepositoryRoot $repositoryPath
        contract_versions = Get-SteinSourceEvidenceContractVersions -RepositoryRoot $repositoryPath
        dependency_locks = @($dependencyLocks | ForEach-Object {
                Get-SteinSourceEvidenceFileRecord `
                    -RepositoryRoot $repositoryPath `
                    -Path (Join-Path $repositoryPath $_)
            })
    }
}

function Get-SteinSourceEvidenceObjectDigest {
    param([Parameter(Mandatory = $true)] $Value)

    return Get-SteinSourceEvidenceTextSha256 `
        -Value ($Value | ConvertTo-Json -Depth 40 -Compress)
}

function Get-SteinSourceEvidenceGenerator {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string[]] $Paths
    )

    $files = @($Paths | ForEach-Object {
            Get-SteinSourceEvidenceFileRecord -RepositoryRoot $RepositoryRoot -Path $_
        })
    return [ordered]@{
        schema_version = 1
        files = $files
        digest_sha256 = Get-SteinSourceEvidenceObjectDigest -Value $files
    }
}

function New-SteinSourceEvidenceRootAnchor {
    param(
        [Parameter(Mandatory = $true)][string] $ReportPath,
        [Parameter(Mandatory = $true)][string] $GeneratorDigest,
        [Parameter(Mandatory = $true)][string] $ProvenanceDigest,
        [Parameter(Mandatory = $true)][string] $ChecksDigest
    )

    foreach ($digest in @($GeneratorDigest, $ProvenanceDigest, $ChecksDigest)) {
        if ($digest -notmatch '^[0-9a-f]{64}$') {
            throw "A source-evidence chain digest is invalid."
        }
    }
    $reportItem = Get-Item -LiteralPath $ReportPath -Force -ErrorAction Stop
    if ($reportItem.PSIsContainer -or
        (($reportItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $reportItem.Length -le 0) {
        throw "The source-verification report is invalid."
    }
    $reportDigest = Get-SteinSourceEvidenceSha256 -Path $reportItem.FullName
    $rootMaterial = @(
        "stein-phase2-source-evidence-root-v1",
        "source_verification_sha256=$reportDigest",
        "generator_sha256=$GeneratorDigest",
        "provenance_sha256=$ProvenanceDigest",
        "checks_sha256=$ChecksDigest"
    ) -join "`n"
    return [ordered]@{
        schema_version = 1
        claim = "source_verification_only"
        integrity_semantics = "content_integrity_only_not_authentication"
        source_verification = [ordered]@{
            path = $reportItem.Name
            size = [long]$reportItem.Length
            sha256 = $reportDigest
        }
        generator_sha256 = $GeneratorDigest
        provenance_sha256 = $ProvenanceDigest
        checks_sha256 = $ChecksDigest
        root_digest_sha256 = Get-SteinSourceEvidenceTextSha256 -Value $rootMaterial
    }
}
