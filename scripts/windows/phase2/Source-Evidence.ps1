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

function Assert-SteinSourceEvidenceExactProperties {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string[]] $Expected,
        [string] $FailureMessage = "A source-evidence object has an invalid shape."
    )

    if ($null -eq $Value -or $Value -is [string] -or
        $null -eq $Value.PSObject) {
        throw $FailureMessage
    }
    $actual = @($Value.PSObject.Properties | ForEach-Object {
            [string]$_.Name
        })
    if ($actual.Count -ne $Expected.Count) {
        throw $FailureMessage
    }
    foreach ($name in $Expected) {
        if ($name -cnotin $actual) {
            throw $FailureMessage
        }
    }
}

function Test-SteinSourceEvidenceInteger {
    param([AllowNull()] $Value)

    return $Value -is [int] -or $Value -is [long]
}

function Test-SteinSourceEvidenceCommandToken {
    param([AllowNull()] $Value)

    if ($Value -isnot [string] -or $Value.Length -lt 1 -or
        $Value.Length -gt 512 -or
        $Value -cnotmatch '^[A-Za-z0-9._/,+@=-]+$' -or
        $Value -match '[\s"''&|;<>`$(){}\[\]!?*\\:]' -or
        $Value.StartsWith('/')) {
        return $false
    }
    foreach ($segment in $Value.Split('/')) {
        if ($segment -cin @('.', '..')) {
            return $false
        }
    }
    return $true
}

function Test-SteinSourceEvidenceCommandRelativePath {
    param(
        [AllowNull()] $Value,
        [switch] $AllowRepositoryRoot
    )

    if ($Value -is [string] -and $Value -ceq '.') {
        return [bool]$AllowRepositoryRoot
    }
    if ($Value -isnot [string] -or
        -not (Test-SteinSourceEvidenceCommandToken -Value $Value) -or
        [IO.Path]::IsPathRooted($Value) -or $Value -match '^[A-Za-z]:' -or
        $Value.Contains('\') -or $Value.StartsWith('/') -or
        $Value.EndsWith('/')) {
        return $false
    }
    foreach ($segment in $Value.Split('/')) {
        if ([string]::IsNullOrWhiteSpace($segment) -or
            $segment -cin @('.', '..') -or $segment.EndsWith('.') -or
            $segment.EndsWith(' ') -or
            $segment -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') {
            return $false
        }
    }
    return $true
}

function Resolve-SteinSourceEvidenceCommandPath {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $RelativePath,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Leaf', 'Container')][string] $Kind,
        [switch] $AllowMissingLeaf
    )

    if (-not (Test-SteinSourceEvidenceCommandRelativePath `
            -Value $RelativePath `
            -AllowRepositoryRoot:($Kind -ceq 'Container'))) {
        throw "A source-command relative path is invalid."
    }
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $rootItem = Get-Item -LiteralPath $rootPath -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "A source-command root is unsafe."
    }
    $candidate = if ($RelativePath -ceq '.') {
        $rootPath
    }
    else {
        [IO.Path]::GetFullPath((Join-Path $rootPath (
                    $RelativePath.Replace(
                        '/', [IO.Path]::DirectorySeparatorChar))))
    }
    $prefix = "$rootPath$([IO.Path]::DirectorySeparatorChar)"
    if ($candidate -cne $rootPath -and -not $candidate.StartsWith(
            $prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "A source-command path escaped its root."
    }

    $probe = if ($Kind -ceq 'Leaf') {
        Split-Path -Parent $candidate
    }
    else {
        $candidate
    }
    while ($probe.Length -ge $rootPath.Length) {
        if (-not (Test-Path -LiteralPath $probe)) {
            if (-not $AllowMissingLeaf) {
                throw "A source-command path is unavailable."
            }
            $parent = Split-Path -Parent $probe
            if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
                throw "A source-command path is unsafe."
            }
            $probe = $parent
            continue
        }
        $directory = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "A source-command path is unsafe."
        }
        if ([string]::Equals(
                $probe, $rootPath, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $probe) {
            throw "A source-command path is unsafe."
        }
        $probe = $parent
    }

    if (-not (Test-Path -LiteralPath $candidate)) {
        if ($AllowMissingLeaf) {
            return $candidate
        }
        throw "A source-command path is unavailable."
    }
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ((($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        ($Kind -ceq 'Leaf' -and $item.PSIsContainer) -or
        ($Kind -ceq 'Container' -and -not $item.PSIsContainer)) {
        throw "A source-command path is unsafe."
    }
    return $item.FullName
}

function Open-SteinSourceEvidenceCommandFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [long] $MaximumBytes = 16777216L,
        [switch] $AllowEmpty
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $minimum = if ($AllowEmpty) { 0L } else { 1L }
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.Length -lt $minimum -or $item.Length -gt $MaximumBytes) {
        throw "A source-command evidence file is invalid."
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $item.Length -or $stream.Length -lt $minimum -or
            $stream.Length -gt $MaximumBytes) {
            throw "A source-command evidence file changed during capture."
        }
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = [BitConverter]::ToString(
                $sha256.ComputeHash($stream)).Replace(
                '-', '').ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
            $stream.Position = 0
        }
        return [pscustomobject]@{
            Path = $item.FullName
            Size = [long]$stream.Length
            Sha256 = $digest
            Stream = $stream
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function ConvertFrom-SteinSourceEvidenceCommandJson {
    param([Parameter(Mandatory = $true)][string] $Text)

    $convert = Get-Command -Name ConvertFrom-Json -CommandType Cmdlet `
        -ErrorAction Stop
    if ($convert.Parameters.ContainsKey('DateKind')) {
        return $Text | ConvertFrom-Json -DateKind String -ErrorAction Stop
    }
    if ($PSVersionTable.PSEdition -ceq 'Core') {
        throw "PowerShell Core 7.5 or newer is required for stable JSON dates."
    }
    return $Text | ConvertFrom-Json -ErrorAction Stop
}

function MoveTo-SteinSourceEvidenceJsonToken {
    param(
        [Parameter(Mandatory = $true)][string] $Text,
        [Parameter(Mandatory = $true)][ref] $Position
    )

    while ($Position.Value -lt $Text.Length -and
        [char]::IsWhiteSpace($Text[$Position.Value])) {
        $Position.Value++
    }
}

function Read-SteinSourceEvidenceJsonStringToken {
    param(
        [Parameter(Mandatory = $true)][string] $Text,
        [Parameter(Mandatory = $true)][ref] $Position
    )

    if ($Position.Value -ge $Text.Length -or
        $Text[$Position.Value] -cne '"') {
        throw "A source-command JSON string is invalid."
    }
    $start = [int]$Position.Value
    $Position.Value++
    $closed = $false
    while ($Position.Value -lt $Text.Length) {
        $character = $Text[$Position.Value]
        if ([int][char]$character -lt 0x20) {
            throw "A source-command JSON string contains a control character."
        }
        if ($character -ceq '"') {
            $Position.Value++
            $closed = $true
            break
        }
        if ($character -ceq '\') {
            $Position.Value++
            if ($Position.Value -ge $Text.Length) {
                throw "A source-command JSON escape is incomplete."
            }
            $escape = $Text[$Position.Value]
            if ($escape -ceq 'u') {
                if ($Position.Value + 4 -ge $Text.Length) {
                    throw "A source-command JSON Unicode escape is incomplete."
                }
                $hex = $Text.Substring($Position.Value + 1, 4)
                if ($hex -cnotmatch '^[0-9a-fA-F]{4}$') {
                    throw "A source-command JSON Unicode escape is invalid."
                }
                $Position.Value += 5
                continue
            }
            if ($escape -cnotin @('"', '\', '/', 'b', 'f', 'n', 'r', 't')) {
                throw "A source-command JSON escape is invalid."
            }
            $Position.Value++
            continue
        }
        $Position.Value++
    }
    if (-not $closed) {
        throw "A source-command JSON string is unterminated."
    }
    $raw = $Text.Substring($start, $Position.Value - $start)
    if ($raw.IndexOf('\') -lt 0) {
        return $raw.Substring(1, $raw.Length - 2)
    }
    $value = ConvertFrom-SteinSourceEvidenceCommandJson -Text $raw
    if ($value -isnot [string]) {
        throw "A source-command JSON string is invalid."
    }
    return [string]$value
}

function Assert-SteinSourceEvidenceJsonValue {
    param(
        [Parameter(Mandatory = $true)][string] $Text,
        [Parameter(Mandatory = $true)][ref] $Position,
        [int] $Depth = 0
    )

    if ($Depth -gt 64) {
        throw "A source-command JSON document is nested too deeply."
    }
    MoveTo-SteinSourceEvidenceJsonToken -Text $Text -Position $Position
    if ($Position.Value -ge $Text.Length) {
        throw "A source-command JSON value is missing."
    }
    $character = $Text[$Position.Value]
    if ($character -ceq '"') {
        $null = Read-SteinSourceEvidenceJsonStringToken `
            -Text $Text `
            -Position $Position
        return
    }
    if ($character -ceq '{') {
        $Position.Value++
        $keys = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        MoveTo-SteinSourceEvidenceJsonToken -Text $Text -Position $Position
        if ($Position.Value -lt $Text.Length -and
            $Text[$Position.Value] -ceq '}') {
            $Position.Value++
            return
        }
        while ($true) {
            MoveTo-SteinSourceEvidenceJsonToken `
                -Text $Text `
                -Position $Position
            $key = Read-SteinSourceEvidenceJsonStringToken `
                -Text $Text `
                -Position $Position
            if (-not $keys.Add($key)) {
                throw "A source-command JSON object contains a duplicate key."
            }
            MoveTo-SteinSourceEvidenceJsonToken `
                -Text $Text `
                -Position $Position
            if ($Position.Value -ge $Text.Length -or
                $Text[$Position.Value] -cne ':') {
                throw "A source-command JSON object is missing a colon."
            }
            $Position.Value++
            Assert-SteinSourceEvidenceJsonValue `
                -Text $Text `
                -Position $Position `
                -Depth ($Depth + 1)
            MoveTo-SteinSourceEvidenceJsonToken `
                -Text $Text `
                -Position $Position
            if ($Position.Value -ge $Text.Length) {
                throw "A source-command JSON object is unterminated."
            }
            if ($Text[$Position.Value] -ceq '}') {
                $Position.Value++
                return
            }
            if ($Text[$Position.Value] -cne ',') {
                throw "A source-command JSON object delimiter is invalid."
            }
            $Position.Value++
        }
    }
    if ($character -ceq '[') {
        $Position.Value++
        MoveTo-SteinSourceEvidenceJsonToken -Text $Text -Position $Position
        if ($Position.Value -lt $Text.Length -and
            $Text[$Position.Value] -ceq ']') {
            $Position.Value++
            return
        }
        while ($true) {
            Assert-SteinSourceEvidenceJsonValue `
                -Text $Text `
                -Position $Position `
                -Depth ($Depth + 1)
            MoveTo-SteinSourceEvidenceJsonToken `
                -Text $Text `
                -Position $Position
            if ($Position.Value -ge $Text.Length) {
                throw "A source-command JSON array is unterminated."
            }
            if ($Text[$Position.Value] -ceq ']') {
                $Position.Value++
                return
            }
            if ($Text[$Position.Value] -cne ',') {
                throw "A source-command JSON array delimiter is invalid."
            }
            $Position.Value++
        }
    }

    $start = [int]$Position.Value
    while ($Position.Value -lt $Text.Length -and
        $Text[$Position.Value] -cnotin @(',', '}', ']') -and
        -not [char]::IsWhiteSpace($Text[$Position.Value])) {
        $Position.Value++
    }
    if ($Position.Value -le $start) {
        throw "A source-command JSON primitive is invalid."
    }
    $primitive = $Text.Substring($start, $Position.Value - $start)
    if ($primitive -cnotmatch
        '^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)$') {
        throw "A source-command JSON primitive is invalid."
    }
}

function Assert-SteinSourceEvidenceJsonUniqueObjectKeys {
    param([Parameter(Mandatory = $true)][string] $Text)

    $position = 0
    Assert-SteinSourceEvidenceJsonValue `
        -Text $Text `
        -Position ([ref]$position)
    MoveTo-SteinSourceEvidenceJsonToken `
        -Text $Text `
        -Position ([ref]$position)
    if ($position -ne $Text.Length) {
        throw "A source-command JSON document has trailing content."
    }
}

function Read-SteinSourceEvidenceCommandJsonFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [long] $MaximumBytes = 1048576L
    )

    $lock = Open-SteinSourceEvidenceCommandFile `
        -Path $Path `
        -MaximumBytes $MaximumBytes
    try {
        $bytes = New-Object byte[] ([int]$lock.Size)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $lock.Stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "A source-command JSON file could not be captured."
            }
            $offset += $read
        }
        $lock.Stream.Position = 0
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        if ($text.Length -lt 2 -or [int][char]$text[0] -eq 0xFEFF) {
            throw "A source-command JSON file is not canonical UTF-8."
        }
        Assert-SteinSourceEvidenceJsonUniqueObjectKeys -Text $text
        $value = ConvertFrom-SteinSourceEvidenceCommandJson -Text $text
        if ($null -eq $value) {
            throw "A source-command JSON file is empty."
        }
        return [pscustomobject]@{
            Value = $value
            Lock = $lock
        }
    }
    catch {
        $lock.Stream.Dispose()
        throw
    }
    finally {
        if ($null -ne $bytes) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
}

function Get-SteinSourceEvidenceCommandCatalog {
    return [ordered]@{
        direct = @(
            'rust-format', 'rust-check', 'rust-clippy', 'rust-tests',
            'desktop-typecheck', 'desktop-lint', 'desktop-tests',
            'desktop-build', 'edge-extension-tests', 'edge-host-format',
            'edge-host-check', 'edge-host-clippy', 'edge-host-tests',
            'boundary-contract', 'source-evidence-contract',
            'installed-evidence-harness-static', 'no-leaks-scanner-static',
            'installed-reviewer-windows-powershell-contract',
            'installed-reviewer-pwsh-contract', 'msix-static-contract',
            'release-workspace', 'release-production-core',
            'release-edge-host', 'release-tauri-no-bundle')
        grouped = @(
            'phase2-source-fixture-upgrade',
            'phase2-source-fixture-secrets',
            'phase2-source-fixture-identity',
            'phase2-source-fixture-phase1-regression',
            'phase2-source-fixture-goals',
            'phase2-source-fixture-pixels',
            'phase2-source-fixture-model-contract',
            'phase2-source-fixture-intervention',
            'phase2-source-fixture-policy-failsafe',
            'phase2-source-fixture-notification',
            'phase2-source-fixture-outbox-recovery',
            'phase2-source-fixture-revocation-race',
            'phase2-source-fixture-retention')
        derived = @(
            'source-report-command-provenance',
            'source-provenance-stability')
        retained = @(
            'no-leaks-producer-workflow', 'native-toolchain-provenance',
            'pinned-clean-build-environment',
            'portable-runner-attestation',
            'windows-native-ignored-fixtures')
        ordered = @(
            'rust-format', 'rust-check', 'rust-clippy', 'rust-tests',
            'desktop-typecheck', 'desktop-lint', 'desktop-tests',
            'desktop-build', 'edge-extension-tests', 'edge-host-format',
            'edge-host-check', 'edge-host-clippy', 'edge-host-tests',
            'boundary-contract', 'source-evidence-contract',
            'installed-evidence-harness-static', 'no-leaks-scanner-static',
            'no-leaks-producer-workflow', 'native-toolchain-provenance',
            'pinned-clean-build-environment',
            'portable-runner-attestation',
            'source-report-command-provenance',
            'phase2-source-fixture-upgrade',
            'phase2-source-fixture-secrets',
            'phase2-source-fixture-identity',
            'phase2-source-fixture-phase1-regression',
            'phase2-source-fixture-goals',
            'phase2-source-fixture-pixels',
            'phase2-source-fixture-model-contract',
            'phase2-source-fixture-intervention',
            'phase2-source-fixture-policy-failsafe',
            'phase2-source-fixture-notification',
            'phase2-source-fixture-outbox-recovery',
            'phase2-source-fixture-revocation-race',
            'phase2-source-fixture-retention',
            'installed-reviewer-windows-powershell-contract',
            'installed-reviewer-pwsh-contract', 'msix-static-contract',
            'release-workspace', 'release-production-core',
            'release-edge-host', 'release-tauri-no-bundle',
            'windows-native-ignored-fixtures',
            'source-provenance-stability')
    }
}

function Assert-SteinSourceEvidenceCommandRegistry {
    param([Parameter(Mandatory = $true)] $Registry)

    $catalog = Get-SteinSourceEvidenceCommandCatalog
    Assert-SteinSourceEvidenceExactProperties `
        -Value $Registry `
        -Expected @('schema_version', 'registry_id', 'checks') `
        -FailureMessage "The source-command registry shape is invalid."
    if (-not (Test-SteinSourceEvidenceInteger -Value $Registry.schema_version) -or
        [long]$Registry.schema_version -ne 1 -or
        $Registry.registry_id -isnot [string] -or
        [string]$Registry.registry_id -cne
            'stein.phase2.source-command-registry.v1') {
        throw "The source-command registry identity is invalid."
    }
    $checks = @($Registry.checks)
    if ($checks.Count -ne 44 -or $catalog.direct.Count -ne 24 -or
        $catalog.grouped.Count -ne 13 -or $catalog.derived.Count -ne 2 -or
        $catalog.retained.Count -ne 5 -or $catalog.ordered.Count -ne 44) {
        throw "The source-command registry coverage is invalid."
    }

    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $executionGroups = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $groupDefinition = $null
    $expectedReasons = @{
        'no-leaks-producer-workflow' =
            'candidate_owned_installed_artifact_producer_unimplemented'
        'native-toolchain-provenance' =
            'authenticated_native_toolchain_provenance_unimplemented'
        'pinned-clean-build-environment' =
            'immutable_candidate_and_fresh_build_isolation_unimplemented'
        'portable-runner-attestation' =
            'authenticated_portable_artifact_attestation_unimplemented'
        'windows-native-ignored-fixtures' =
            'versioned_closed_native_fixture_receipts_unimplemented'
    }
    for ($index = 0; $index -lt $checks.Count; $index++) {
        $check = $checks[$index]
        if ($null -eq $check -or $check.id -isnot [string] -or
            [string]$check.id -cne [string]$catalog.ordered[$index] -or
            -not $seen.Add([string]$check.id)) {
            throw "The source-command registry order is invalid."
        }
        $id = [string]$check.id
        $category = if ($id -cin $catalog.direct) {
            'direct_execution'
        }
        elseif ($id -cin $catalog.grouped) {
            'grouped_fixture_execution'
        }
        elseif ($id -cin $catalog.derived) {
            'derived'
        }
        elseif ($id -cin $catalog.retained) {
            'retained_obligation'
        }
        else {
            throw "The source-command registry contains an unknown check."
        }
        if ($check.category -isnot [string] -or
            [string]$check.category -cne $category) {
            throw "The source-command registry category is invalid."
        }

        if ($category -ceq 'retained_obligation') {
            Assert-SteinSourceEvidenceExactProperties `
                -Value $check `
                -Expected @('id', 'category', 'reason_code') `
                -FailureMessage "A retained source-command obligation is invalid."
            if ($check.reason_code -isnot [string] -or
                [string]$check.reason_code -cne [string]$expectedReasons[$id]) {
                throw "A retained source-command reason is invalid."
            }
            continue
        }
        if ($category -ceq 'derived') {
            Assert-SteinSourceEvidenceExactProperties `
                -Value $check `
                -Expected @('id', 'category', 'derivation') `
                -FailureMessage "A derived source-command check is invalid."
            $expectedDerivation = if ($id -ceq
                    'source-report-command-provenance') {
                'exact_registry_and_receipt_coverage'
            }
            else {
                'candidate_and_registry_streams_stable'
            }
            if ($check.derivation -isnot [string] -or
                [string]$check.derivation -cne $expectedDerivation) {
                throw "A source-command derivation is invalid."
            }
            continue
        }

        $expectedProperties = @(
            'id', 'category', 'executable_role', 'arguments',
            'working_directory', 'environment_profile', 'timeout_seconds')
        if ($category -ceq 'grouped_fixture_execution') {
            $expectedProperties = @(
                'id', 'category', 'group_id', 'executable_role', 'arguments',
                'working_directory', 'environment_profile', 'timeout_seconds',
                'fixture_receipt_path')
        }
        Assert-SteinSourceEvidenceExactProperties `
            -Value $check `
            -Expected $expectedProperties `
            -FailureMessage "An executable source-command check is invalid."
        if ($check.executable_role -isnot [string] -or
            [string]$check.executable_role -cnotin @(
                'cargo', 'pnpm', 'windows_powershell', 'pwsh') -or
            $check.working_directory -isnot [string] -or
            -not (Test-SteinSourceEvidenceCommandRelativePath `
                -Value $check.working_directory `
                -AllowRepositoryRoot) -or
            $check.environment_profile -isnot [string] -or
            [string]$check.environment_profile -cnotin @(
                'phase2_synthetic_compile_v1',
                'phase2_source_fixture_v1') -or
            -not (Test-SteinSourceEvidenceInteger `
                -Value $check.timeout_seconds) -or
            [long]$check.timeout_seconds -lt 30 -or
            [long]$check.timeout_seconds -gt 14400) {
            throw "An executable source-command definition is invalid."
        }
        if ($category -ceq 'direct_execution' -and
            [string]$check.environment_profile -cne
                'phase2_synthetic_compile_v1') {
            throw "A direct source-command profile is invalid."
        }
        if ($category -ceq 'grouped_fixture_execution' -and
            [string]$check.environment_profile -cne
                'phase2_source_fixture_v1') {
            throw "A grouped source-command profile is invalid."
        }

        $arguments = @($check.arguments)
        if ($arguments.Count -lt 1 -or $arguments.Count -gt 24) {
            throw "A source-command argument vector is outside its bound."
        }
        foreach ($argument in $arguments) {
            Assert-SteinSourceEvidenceExactProperties `
                -Value $argument `
                -Expected @('kind', 'value') `
                -FailureMessage "A source-command argument is invalid."
            if ($argument.kind -isnot [string] -or
                [string]$argument.kind -cnotin @(
                    'literal', 'repository_relative_path',
                    'evidence_relative_path') -or
                $argument.value -isnot [string] -or
                -not (Test-SteinSourceEvidenceCommandToken `
                    -Value $argument.value)) {
                throw "A source-command argument is invalid."
            }
            if ([string]$argument.kind -ceq 'literal') {
                if ([string]$argument.value -cin @(
                        '-Command', '-EncodedCommand', '/c', '/k')) {
                    throw "A source-command shell argument is forbidden."
                }
            }
            elseif (-not (Test-SteinSourceEvidenceCommandRelativePath `
                    -Value $argument.value)) {
                throw "A source-command path argument is invalid."
            }
            if ([string]$argument.kind -ceq 'evidence_relative_path' -and
                [string]$argument.value -cne 'source-fixtures') {
                throw "A source-command evidence argument is invalid."
            }
        }

        if ($category -ceq 'grouped_fixture_execution') {
            if ($check.group_id -isnot [string] -or
                [string]$check.group_id -cne 'closed-source-fixture-suite' -or
                $check.fixture_receipt_path -isnot [string] -or
                [string]$check.fixture_receipt_path -cne
                    "source-fixtures/$id.receipt.json") {
                throw "A grouped source-command definition is invalid."
            }
            $material = [ordered]@{
                executable_role = [string]$check.executable_role
                arguments = @($check.arguments)
                working_directory = [string]$check.working_directory
                environment_profile = [string]$check.environment_profile
                timeout_seconds = [long]$check.timeout_seconds
            }
            $digest = Get-SteinSourceEvidenceObjectDigest -Value $material
            if ($null -eq $groupDefinition) {
                $groupDefinition = $digest
            }
            elseif ([string]$groupDefinition -cne $digest) {
                throw "The grouped source-command definitions disagree."
            }
            $null = $executionGroups.Add('closed-source-fixture-suite')
        }
        else {
            $null = $executionGroups.Add("direct:$id")
        }
    }
    if ($executionGroups.Count -ne 25 -or $seen.Count -ne 44) {
        throw "The source-command execution-group coverage is invalid."
    }

    $executed = @($checks | Where-Object {
            [string]$_.category -cin @(
                'direct_execution', 'grouped_fixture_execution')
        })
    if ($executed.Count -ne 37) {
        throw "The source-command executable-check coverage is invalid."
    }
    return [pscustomobject]@{
        DirectIds = @($catalog.direct)
        GroupedIds = @($catalog.grouped)
        DerivedIds = @($catalog.derived)
        RetainedIds = @($catalog.retained)
        OrderedIds = @($catalog.ordered)
        ExecutedChecks = $executed
        ExecutionGroupCount = 25
    }
}

function Read-SteinSourceEvidenceCommandRegistry {
    param(
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [string] $RegistryPath = ''
    )

    $repositoryPath = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $expectedPath = Join-Path $repositoryPath `
        'scripts\windows\phase2\Source-Command-Registry.json'
    if ([string]::IsNullOrWhiteSpace($RegistryPath)) {
        $RegistryPath = $expectedPath
    }
    if (-not [string]::Equals(
            [IO.Path]::GetFullPath($RegistryPath),
            [IO.Path]::GetFullPath($expectedPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "The source-command registry path is invalid."
    }
    $resolved = Resolve-SteinSourceEvidenceCommandPath `
        -Root $repositoryPath `
        -RelativePath 'scripts/windows/phase2/Source-Command-Registry.json' `
        -Kind Leaf
    $read = Read-SteinSourceEvidenceCommandJsonFile `
        -Path $resolved `
        -MaximumBytes 1048576
    try {
        $contract = Assert-SteinSourceEvidenceCommandRegistry `
            -Registry $read.Value
        return [pscustomobject]@{
            Registry = $read.Value
            Contract = $contract
            Path = $read.Lock.Path
            Size = [long]$read.Lock.Size
            Sha256 = [string]$read.Lock.Sha256
            Stream = $read.Lock.Stream
        }
    }
    catch {
        $read.Lock.Stream.Dispose()
        throw
    }
}

function Get-SteinSourceEvidenceCommandArgumentDigest {
    param(
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)][string[]] $Arguments
    )

    $records = New-Object Collections.Generic.List[string]
    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        if (-not (Test-SteinSourceEvidenceCommandToken `
                -Value $Arguments[$index])) {
            throw "A normalized source-command argument is invalid."
        }
        $length = [Text.UTF8Encoding]::new($false).GetByteCount(
            [string]$Arguments[$index])
        $records.Add("$index|$length`:$([string]$Arguments[$index])")
    }
    return Get-SteinSourceEvidenceTextSha256 `
        -Value ($records.ToArray() -join "`n")
}

function Get-SteinSourceEvidenceCommandDefinitionDigest {
    param([Parameter(Mandatory = $true)] $Check)

    return Get-SteinSourceEvidenceObjectDigest -Value $Check
}

function Expand-SteinSourceEvidenceCommandDefinition {
    param(
        [Parameter(Mandatory = $true)] $Check,
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $EvidenceRoot
    )

    $repositoryPath = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $evidencePath = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $prefix = "$repositoryPath$([IO.Path]::DirectorySeparatorChar)"
    if (-not $evidencePath.StartsWith(
            $prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The source-command evidence root escaped the repository."
    }
    $evidenceRelative = $evidencePath.Substring($prefix.Length).Replace('\', '/')
    if (-not (Test-SteinSourceEvidenceCommandRelativePath `
            -Value $evidenceRelative)) {
        throw "The source-command evidence root is not a safe token."
    }
    $null = Resolve-SteinSourceEvidenceCommandPath `
        -Root $repositoryPath `
        -RelativePath $evidenceRelative `
        -Kind Container
    $workingDirectory = Resolve-SteinSourceEvidenceCommandPath `
        -Root $repositoryPath `
        -RelativePath ([string]$Check.working_directory) `
        -Kind Container

    $normalized = New-Object Collections.Generic.List[string]
    foreach ($argument in @($Check.arguments)) {
        $kind = [string]$argument.kind
        $value = [string]$argument.value
        if ($kind -ceq 'literal') {
            $normalized.Add($value)
            continue
        }
        if ($kind -ceq 'repository_relative_path') {
            $null = Resolve-SteinSourceEvidenceCommandPath `
                -Root $repositoryPath `
                -RelativePath $value `
                -Kind Leaf
            $normalized.Add($value)
            continue
        }
        if ($kind -ceq 'evidence_relative_path') {
            $combined = "$evidenceRelative/$value"
            if (-not (Test-SteinSourceEvidenceCommandRelativePath `
                    -Value $combined)) {
                throw "A normalized source-command evidence argument is invalid."
            }
            $null = Resolve-SteinSourceEvidenceCommandPath `
                -Root $repositoryPath `
                -RelativePath $combined `
                -Kind Container `
                -AllowMissingLeaf
            $normalized.Add($combined)
            continue
        }
        throw "A source-command argument kind is invalid."
    }
    $arguments = $normalized.ToArray()
    foreach ($argument in $arguments) {
        if (-not (Test-SteinSourceEvidenceCommandToken -Value $argument)) {
            throw "A normalized source-command argument is invalid."
        }
    }
    return [pscustomobject]@{
        NormalizedArguments = $arguments
        LaunchArguments = $arguments
        ArgumentsSha256 = Get-SteinSourceEvidenceCommandArgumentDigest `
            -Arguments $arguments
        WorkingDirectory = $workingDirectory
        WorkingDirectoryRelative = [string]$Check.working_directory
        EvidenceRelative = $evidenceRelative
    }
}

function Get-SteinSourceEvidenceCommandEnvironmentProfileDigest {
    param([Parameter(Mandatory = $true)][string] $Profile)

    if ($Profile -cnotin @(
            'phase2_synthetic_compile_v1', 'phase2_source_fixture_v1')) {
        throw "A source-command environment profile is invalid."
    }
    $values = [ordered]@{
        STEIN_CORE_EXECUTABLE_SHA256 =
            '1111111111111111111111111111111111111111111111111111111111111111'
        STEIN_PRODUCTION_PACKAGE_FAMILY_NAME =
            'STEIN.PersonalIntelligence_123456789abcd'
        STEIN_PRODUCTION_BROKER_AUMID =
            'STEIN.PersonalIntelligence_123456789abcd!PrivateBroker'
        STEIN_EDGE_EXTENSION_ID =
            'abcdefghijklmnopabcdefghijklmnop'
        STEIN_EDGE_EXTENSION_VERSION = '0.1.0'
        STEIN_EDGE_PUBLISHER_SHA256 =
            '2222222222222222222222222222222222222222222222222222222222222222'
        STEIN_EDGE_HOST_PUBLISHER_SHA256 =
            '3333333333333333333333333333333333333333333333333333333333333333'
    }
    return Get-SteinSourceEvidenceObjectDigest -Value ([ordered]@{
            profile = $Profile
            values = $values
        })
}

function ConvertFrom-SteinSourceEvidenceCommandTimestamp {
    param([AllowNull()] $Value)

    if ($Value -isnot [string] -or
        $Value -cnotmatch
            '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$') {
        throw "A source-command timestamp is invalid."
    }
    $parsed = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$Value,
            "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            $styles,
            [ref]$parsed)) {
        throw "A source-command timestamp is invalid."
    }
    return $parsed
}

function Get-SteinSourceEvidenceCommandExecutionId {
    param(
        [Parameter(Mandatory = $true)] $Command,
        [Parameter(Mandatory = $true)] $Execution
    )

    $material = [ordered]@{
        execution_group_id = [string]$Execution.execution_group_id
        executable_role = [string]$Command.executable_role
        executable_sha256 = [string]$Command.executable_sha256
        arguments_sha256 = [string]$Command.arguments_sha256
        working_directory = [string]$Command.working_directory
        environment_profile_sha256 =
            [string]$Command.environment_profile_sha256
        started_at = [string]$Execution.started_at
        completed_at = [string]$Execution.completed_at
        exit_code = [long]$Execution.exit_code
        failure_code = $Execution.failure_code
        stdout = $Execution.stdout
        stderr = $Execution.stderr
    }
    return Get-SteinSourceEvidenceObjectDigest -Value $material
}

function Close-SteinSourceEvidenceCommandEvidence {
    param([AllowNull()] $Evidence)

    if ($null -eq $Evidence -or
        $null -eq $Evidence.PSObject.Properties['Locks']) {
        return
    }
    foreach ($lock in @($Evidence.Locks)) {
        if ($null -ne $lock -and
            $null -ne $lock.PSObject.Properties['Stream'] -and
            $null -ne $lock.Stream) {
            $lock.Stream.Dispose()
        }
    }
}

function Assert-SteinSourceEvidenceCommandEvidenceStable {
    param([Parameter(Mandatory = $true)] $Evidence)

    if ($null -eq $Evidence.PSObject.Properties['Locks']) {
        throw "The source-command evidence lock set is missing."
    }
    foreach ($lock in @($Evidence.Locks)) {
        if ($null -eq $lock -or
            $null -eq $lock.PSObject.Properties['Stream'] -or
            $null -eq $lock.Stream -or
            -not $lock.Stream.CanRead -or -not $lock.Stream.CanSeek -or
            [long]$lock.Stream.Length -ne [long]$lock.Size) {
            throw "A source-command evidence file changed after validation."
        }
        $lock.Stream.Position = 0
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = [BitConverter]::ToString(
                $sha256.ComputeHash($lock.Stream)).Replace(
                '-', '').ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
            $lock.Stream.Position = 0
        }
        if ($digest -cne [string]$lock.Sha256) {
            throw "A source-command evidence file changed after validation."
        }
    }
    return $true
}

function Assert-SteinSourceEvidenceCommandReceiptIndex {
    param(
        [Parameter(Mandatory = $true)] $RegistryRead,
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [Parameter(Mandatory = $true)][string] $EvidenceRoot,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')]
        [string] $CandidateCommit,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')]
        [string] $CandidateTree,
        [Parameter(Mandatory = $true)][string] $RunnerPath,
        [Parameter(Mandatory = $true)]
        [Collections.IDictionary] $ToolExecutables,
        [string] $ExpectedCandidateManifestSha256 = '',
        [long] $ExpectedCandidateFileCount = 0
    )

    $validatedContract = Assert-SteinSourceEvidenceCommandRegistry `
        -Registry $RegistryRead.Registry
    $expectedRegistryPath = [IO.Path]::GetFullPath((Join-Path `
                ([IO.Path]::GetFullPath($RepositoryRoot)) `
                'scripts\windows\phase2\Source-Command-Registry.json'))
    if ($CandidateCommit.Length -ne $CandidateTree.Length -or
        $null -eq $RegistryRead.PSObject.Properties['Registry'] -or
        $null -eq $RegistryRead.PSObject.Properties['Contract'] -or
        $null -eq $RegistryRead.PSObject.Properties['Sha256'] -or
        $null -eq $RegistryRead.PSObject.Properties['Path'] -or
        $null -eq $RegistryRead.PSObject.Properties['Stream'] -or
        -not $RegistryRead.Stream.CanRead -or
        -not $RegistryRead.Stream.CanSeek -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$RegistryRead.Path),
            $expectedRegistryPath,
            [StringComparison]::OrdinalIgnoreCase) -or
        [string]$RegistryRead.Sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$RegistryRead.Sha256 -cne
            (Get-SteinSourceEvidenceSha256 -Path $expectedRegistryPath) -or
        @($validatedContract.ExecutedChecks).Count -ne 37 -or
        [long]$validatedContract.ExecutionGroupCount -ne 25) {
        throw "The source-command validation binding is invalid."
    }
    if ($ExpectedCandidateManifestSha256.Length -gt 0 -and
        $ExpectedCandidateManifestSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "The expected candidate manifest digest is invalid."
    }

    $repositoryPath = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $evidencePath = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $repositoryPrefix =
        "$repositoryPath$([IO.Path]::DirectorySeparatorChar)"
    if (-not $evidencePath.StartsWith(
            $repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The source-command evidence root escaped the repository."
    }
    $evidenceRelative = $evidencePath.Substring(
        $repositoryPrefix.Length).Replace('\', '/')
    if (-not (Test-SteinSourceEvidenceCommandRelativePath `
            -Value $evidenceRelative)) {
        throw "The source-command evidence root is invalid."
    }
    $null = Resolve-SteinSourceEvidenceCommandPath `
        -Root $repositoryPath `
        -RelativePath $evidenceRelative `
        -Kind Container

    $expectedRunnerPath = [IO.Path]::GetFullPath((Join-Path $repositoryPath `
                'scripts\windows\phase2\Run-Source-Check.ps1'))
    if (-not [string]::Equals(
            [IO.Path]::GetFullPath($RunnerPath),
            $expectedRunnerPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "The source-command runner path is invalid."
    }

    $locks = New-Object Collections.Generic.List[object]
    $toolLocks = @{}
    $fileLocks = @{}
    try {
        $runnerLock = Open-SteinSourceEvidenceCommandFile `
            -Path $expectedRunnerPath `
            -MaximumBytes 4194304
        $locks.Add($runnerLock)

        foreach ($gitRole in @('git_launcher', 'git_resolved')) {
            if (-not $ToolExecutables.Contains($gitRole) -or
                [string]::IsNullOrWhiteSpace(
                    [string]$ToolExecutables[$gitRole])) {
                throw "A source-command Git binding is unavailable."
            }
        }
        $gitLauncherItem = Get-SteinSourceEvidenceRegularFileItem `
            -Path ([string]$ToolExecutables['git_launcher'])
        $gitResolvedItem = Get-SteinSourceEvidenceRegularFileItem `
            -Path ([string]$ToolExecutables['git_resolved'])
        $gitLauncherDirectory = Split-Path -Parent $gitLauncherItem.FullName
        $gitInstallationRoot = [IO.Path]::GetFullPath(
            (Split-Path -Parent $gitLauncherDirectory))
        $expectedGitResolvedPath = [IO.Path]::GetFullPath((Join-Path `
                    $gitInstallationRoot 'mingw64\bin\git.exe'))
        if ([IO.Path]::GetFileName($gitLauncherItem.FullName) -cne 'git.exe' -or
            [IO.Path]::GetFileName($gitLauncherDirectory) -cne 'cmd' -or
            -not [string]::Equals(
                $gitResolvedItem.FullName,
                $expectedGitResolvedPath,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "A source-command Git binding is invalid."
        }
        $gitLauncherLock = Open-SteinSourceEvidenceCommandFile `
            -Path $gitLauncherItem.FullName `
            -MaximumBytes 268435456
        $locks.Add($gitLauncherLock)
        $gitResolvedLock = Open-SteinSourceEvidenceCommandFile `
            -Path $gitResolvedItem.FullName `
            -MaximumBytes 268435456
        $locks.Add($gitResolvedLock)

        $receiptDirectory = Resolve-SteinSourceEvidenceCommandPath `
            -Root $evidencePath `
            -RelativePath 'source-command-receipts' `
            -Kind Container
        $logDirectory = Resolve-SteinSourceEvidenceCommandPath `
            -Root $evidencePath `
            -RelativePath 'source-command-logs' `
            -Kind Container
        $indexPath = Resolve-SteinSourceEvidenceCommandPath `
            -Root $receiptDirectory `
            -RelativePath 'index.json' `
            -Kind Leaf
        $indexRead = Read-SteinSourceEvidenceCommandJsonFile `
            -Path $indexPath `
            -MaximumBytes 1048576
        $locks.Add($indexRead.Lock)
        $index = $indexRead.Value
        Assert-SteinSourceEvidenceExactProperties `
            -Value $index `
            -Expected @(
                'schema_version', 'claim', 'registry_id', 'bindings',
                'executed_check_count', 'execution_group_count', 'receipts') `
            -FailureMessage "The source-command receipt index is invalid."
        if (-not (Test-SteinSourceEvidenceInteger -Value $index.schema_version) -or
            [long]$index.schema_version -ne 1 -or
            $index.claim -isnot [string] -or
            [string]$index.claim -cne 'closed_source_command_receipt_index' -or
            $index.registry_id -isnot [string] -or
            [string]$index.registry_id -cne
                'stein.phase2.source-command-registry.v1' -or
            -not (Test-SteinSourceEvidenceInteger `
                -Value $index.executed_check_count) -or
            [long]$index.executed_check_count -ne 37 -or
            -not (Test-SteinSourceEvidenceInteger `
                -Value $index.execution_group_count) -or
            [long]$index.execution_group_count -ne 25) {
            throw "The source-command receipt index identity is invalid."
        }

        Assert-SteinSourceEvidenceExactProperties `
            -Value $index.bindings `
            -Expected @(
                'candidate_commit', 'candidate_tree', 'candidate_file_count',
                'candidate_manifest_sha256', 'git_launcher_sha256',
                'git_resolved_sha256', 'registry_sha256',
                'runner_sha256', 'evidence_root_sha256') `
            -FailureMessage "The source-command index bindings are invalid."
        $common = $index.bindings
        if ($common.candidate_commit -isnot [string] -or
            [string]$common.candidate_commit -cne $CandidateCommit -or
            $common.candidate_tree -isnot [string] -or
            [string]$common.candidate_tree -cne $CandidateTree -or
            -not (Test-SteinSourceEvidenceInteger `
                -Value $common.candidate_file_count) -or
            [long]$common.candidate_file_count -lt 1 -or
            [long]$common.candidate_file_count -gt 1000000 -or
            $common.candidate_manifest_sha256 -isnot [string] -or
            [string]$common.candidate_manifest_sha256 -cnotmatch
                '^[0-9a-f]{64}$' -or
            $common.git_launcher_sha256 -isnot [string] -or
            [string]$common.git_launcher_sha256 -cne
                [string]$gitLauncherLock.Sha256 -or
            $common.git_resolved_sha256 -isnot [string] -or
            [string]$common.git_resolved_sha256 -cne
                [string]$gitResolvedLock.Sha256 -or
            $common.registry_sha256 -isnot [string] -or
            [string]$common.registry_sha256 -cne
                [string]$RegistryRead.Sha256 -or
            $common.runner_sha256 -isnot [string] -or
            [string]$common.runner_sha256 -cne [string]$runnerLock.Sha256 -or
            $common.evidence_root_sha256 -isnot [string] -or
            [string]$common.evidence_root_sha256 -cne
                (Get-SteinSourceEvidenceTextSha256 -Value $evidenceRelative)) {
            throw "The source-command index bindings are invalid."
        }
        if ($ExpectedCandidateManifestSha256.Length -gt 0 -and
            [string]$common.candidate_manifest_sha256 -cne
                $ExpectedCandidateManifestSha256) {
            throw "The source-command candidate manifest binding is invalid."
        }
        if ($ExpectedCandidateFileCount -gt 0 -and
            [long]$common.candidate_file_count -ne
                $ExpectedCandidateFileCount) {
            throw "The source-command candidate file-count binding is invalid."
        }

        $actualReceiptEntries = @(
            Get-ChildItem -LiteralPath $receiptDirectory -Force `
                -ErrorAction Stop)
        if ($actualReceiptEntries.Count -ne 38 -or
            @($actualReceiptEntries | Where-Object {
                    $_.PSIsContainer -or
                    (($_.Attributes -band
                            [IO.FileAttributes]::ReparsePoint) -ne 0)
                }).Count -ne 0) {
            throw "The source-command receipt directory is not closed."
        }
        $expectedReceiptNames = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        $null = $expectedReceiptNames.Add('index.json')
        foreach ($check in @($validatedContract.ExecutedChecks)) {
            $null = $expectedReceiptNames.Add(
                "$([string]$check.id).receipt.json")
        }
        foreach ($entry in $actualReceiptEntries) {
            if (-not $expectedReceiptNames.Contains([string]$entry.Name)) {
                throw "The source-command receipt directory contains an extra file."
            }
        }

        $descriptors = @($index.receipts)
        $executedChecks = @($validatedContract.ExecutedChecks)
        if ($descriptors.Count -ne 37 -or
            $executedChecks.Count -ne 37) {
            throw "The source-command receipt descriptor coverage is invalid."
        }
        $expectedLogPaths = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        $executionGroups = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        $groupedIdentity = $null
        $receiptRecords = New-Object Collections.Generic.List[object]

        for ($position = 0; $position -lt $executedChecks.Count; $position++) {
            $check = $executedChecks[$position]
            $id = [string]$check.id
            $category = [string]$check.category
            $descriptor = $descriptors[$position]
            Assert-SteinSourceEvidenceExactProperties `
                -Value $descriptor `
                -Expected @('check_id', 'category', 'path', 'size', 'sha256') `
                -FailureMessage "A source-command receipt descriptor is invalid."
            $expectedReceiptLeaf = "$id.receipt.json"
            if ($descriptor.check_id -isnot [string] -or
                [string]$descriptor.check_id -cne $id -or
                $descriptor.category -isnot [string] -or
                [string]$descriptor.category -cne $category -or
                $descriptor.path -isnot [string] -or
                [string]$descriptor.path -cne $expectedReceiptLeaf -or
                -not (Test-SteinSourceEvidenceInteger `
                    -Value $descriptor.size) -or
                [long]$descriptor.size -lt 1 -or
                [long]$descriptor.size -gt 1048576 -or
                $descriptor.sha256 -isnot [string] -or
                [string]$descriptor.sha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw "A source-command receipt descriptor is invalid."
            }
            $receiptPath = Resolve-SteinSourceEvidenceCommandPath `
                -Root $receiptDirectory `
                -RelativePath $expectedReceiptLeaf `
                -Kind Leaf
            $receiptRead = Read-SteinSourceEvidenceCommandJsonFile `
                -Path $receiptPath `
                -MaximumBytes 1048576
            $locks.Add($receiptRead.Lock)
            if ([long]$receiptRead.Lock.Size -ne [long]$descriptor.size -or
                [string]$receiptRead.Lock.Sha256 -cne
                    [string]$descriptor.sha256) {
                throw "A source-command receipt descriptor does not match its file."
            }
            $receipt = $receiptRead.Value
            Assert-SteinSourceEvidenceExactProperties `
                -Value $receipt `
                -Expected @(
                    'schema_version', 'claim', 'check_id', 'category', 'status',
                    'bindings', 'command', 'execution', 'artifacts',
                    'obligation_code', 'derivation') `
                -FailureMessage "A source-command receipt is invalid."
            if (-not (Test-SteinSourceEvidenceInteger `
                    -Value $receipt.schema_version) -or
                [long]$receipt.schema_version -ne 1 -or
                $receipt.claim -isnot [string] -or
                [string]$receipt.claim -cne
                    'closed_source_command_execution_only' -or
                $receipt.check_id -isnot [string] -or
                [string]$receipt.check_id -cne $id -or
                $receipt.category -isnot [string] -or
                [string]$receipt.category -cne $category -or
                $receipt.status -isnot [string] -or
                [string]$receipt.status -cnotin @('pass', 'fail') -or
                $null -ne $receipt.obligation_code -or
                $null -ne $receipt.derivation) {
                throw "A source-command receipt identity is invalid."
            }

            Assert-SteinSourceEvidenceExactProperties `
                -Value $receipt.bindings `
                -Expected @(
                    'candidate_commit', 'candidate_tree',
                    'candidate_file_count', 'candidate_manifest_sha256',
                    'git_launcher_sha256', 'git_resolved_sha256',
                    'registry_sha256', 'runner_sha256',
                    'evidence_root_sha256', 'check_definition_sha256',
                    'execution_group_count') `
                -FailureMessage "A source-command receipt binding is invalid."
            $bindings = $receipt.bindings
            if ($bindings.candidate_commit -isnot [string] -or
                [string]$bindings.candidate_commit -cne
                    [string]$common.candidate_commit -or
                $bindings.candidate_tree -isnot [string] -or
                [string]$bindings.candidate_tree -cne
                    [string]$common.candidate_tree -or
                -not (Test-SteinSourceEvidenceInteger `
                    -Value $bindings.candidate_file_count) -or
                [long]$bindings.candidate_file_count -ne
                    [long]$common.candidate_file_count -or
                $bindings.candidate_manifest_sha256 -isnot [string] -or
                [string]$bindings.candidate_manifest_sha256 -cne
                    [string]$common.candidate_manifest_sha256 -or
                $bindings.git_launcher_sha256 -isnot [string] -or
                [string]$bindings.git_launcher_sha256 -cne
                    [string]$common.git_launcher_sha256 -or
                $bindings.git_resolved_sha256 -isnot [string] -or
                [string]$bindings.git_resolved_sha256 -cne
                    [string]$common.git_resolved_sha256 -or
                $bindings.registry_sha256 -isnot [string] -or
                [string]$bindings.registry_sha256 -cne
                    [string]$common.registry_sha256 -or
                $bindings.runner_sha256 -isnot [string] -or
                [string]$bindings.runner_sha256 -cne
                    [string]$common.runner_sha256 -or
                $bindings.evidence_root_sha256 -isnot [string] -or
                [string]$bindings.evidence_root_sha256 -cne
                    [string]$common.evidence_root_sha256 -or
                $bindings.check_definition_sha256 -isnot [string] -or
                [string]$bindings.check_definition_sha256 -cne
                    (Get-SteinSourceEvidenceCommandDefinitionDigest `
                        -Check $check) -or
                -not (Test-SteinSourceEvidenceInteger `
                    -Value $bindings.execution_group_count) -or
                [long]$bindings.execution_group_count -ne 25) {
                throw "A source-command receipt binding is invalid."
            }

            Assert-SteinSourceEvidenceExactProperties `
                -Value $receipt.command `
                -Expected @(
                    'executable_role', 'executable_name', 'executable_size',
                    'executable_sha256', 'arguments', 'arguments_sha256',
                    'working_directory', 'environment_profile',
                    'environment_profile_sha256', 'timeout_seconds') `
                -FailureMessage "A source-command receipt command is invalid."
            $command = $receipt.command
            $expanded = Expand-SteinSourceEvidenceCommandDefinition `
                -Check $check `
                -RepositoryRoot $repositoryPath `
                -EvidenceRoot $evidencePath
            $receiptArguments = @($command.arguments)
            $expectedArguments = @($expanded.NormalizedArguments)
            if ($receiptArguments.Count -ne $expectedArguments.Count) {
                throw "A source-command normalized argument vector is invalid."
            }
            for ($argumentIndex = 0;
                $argumentIndex -lt $expectedArguments.Count;
                $argumentIndex++) {
                if ($receiptArguments[$argumentIndex] -isnot [string] -or
                    [string]$receiptArguments[$argumentIndex] -cne
                        [string]$expectedArguments[$argumentIndex] -or
                    -not (Test-SteinSourceEvidenceCommandToken `
                        -Value $receiptArguments[$argumentIndex])) {
                    throw "A source-command normalized argument vector is invalid."
                }
            }
            if ($command.executable_role -isnot [string] -or
                [string]$command.executable_role -cne
                    [string]$check.executable_role -or
                $command.executable_name -isnot [string] -or
                ($command.executable_size -isnot [int] -and
                    $command.executable_size -isnot [long])) {
                throw "A source-command executable descriptor is invalid."
            }
            if ([long]$command.executable_size -lt 1 -or
                [long]$command.executable_size -gt 268435456 -or
                $command.executable_sha256 -isnot [string] -or
                [string]$command.executable_sha256 -cnotmatch
                    '^[0-9a-f]{64}$' -or
                $command.arguments_sha256 -isnot [string] -or
                [string]$command.arguments_sha256 -cne
                    [string]$expanded.ArgumentsSha256 -or
                $command.working_directory -isnot [string] -or
                [string]$command.working_directory -cne
                    [string]$check.working_directory -or
                $command.environment_profile -isnot [string] -or
                [string]$command.environment_profile -cne
                    [string]$check.environment_profile -or
                $command.environment_profile_sha256 -isnot [string] -or
                [string]$command.environment_profile_sha256 -cne
                    (Get-SteinSourceEvidenceCommandEnvironmentProfileDigest `
                        -Profile ([string]$check.environment_profile)) -or
                -not (Test-SteinSourceEvidenceInteger `
                    -Value $command.timeout_seconds) -or
                [long]$command.timeout_seconds -ne
                    [long]$check.timeout_seconds) {
                throw "A source-command receipt command is invalid."
            }

            $role = [string]$check.executable_role
            if (-not $ToolExecutables.Contains($role) -or
                [string]::IsNullOrWhiteSpace(
                    [string]$ToolExecutables[$role])) {
                throw "A source-command executable binding is unavailable."
            }
            if (-not $toolLocks.ContainsKey($role)) {
                $toolItem = Get-SteinSourceEvidenceRegularFileItem `
                    -Path ([string]$ToolExecutables[$role])
                $toolLock = Open-SteinSourceEvidenceCommandFile `
                    -Path $toolItem.FullName `
                    -MaximumBytes 268435456
                $toolLocks[$role] = $toolLock
                $locks.Add($toolLock)
            }
            $expectedToolNames = @{
                cargo = 'cargo.exe'
                pnpm = 'pnpm.cmd'
                windows_powershell = 'powershell.exe'
                pwsh = 'pwsh.exe'
            }
            $tool = $toolLocks[$role]
            if ([string]$command.executable_name -cne
                    [string]$expectedToolNames[$role] -or
                [IO.Path]::GetFileName([string]$tool.Path) -cne
                    [string]$expectedToolNames[$role] -or
                [long]$command.executable_size -ne [long]$tool.Size -or
                [string]$command.executable_sha256 -cne
                    [string]$tool.Sha256) {
                throw "A source-command executable descriptor is invalid."
            }

            Assert-SteinSourceEvidenceExactProperties `
                -Value $receipt.execution `
                -Expected @(
                    'execution_group_id', 'execution_id', 'started_at',
                    'completed_at', 'duration_ms', 'exit_code',
                    'failure_code', 'stdout', 'stderr') `
                -FailureMessage "A source-command execution record is invalid."
            $execution = $receipt.execution
            $expectedGroupId = if ($category -ceq
                    'grouped_fixture_execution') {
                'closed-source-fixture-suite'
            }
            else {
                "direct:$id"
            }
            if ($execution.execution_group_id -isnot [string] -or
                [string]$execution.execution_group_id -cne
                    $expectedGroupId -or
                -not $executionGroups.Add($expectedGroupId) -and
                    $category -cne 'grouped_fixture_execution' -or
                $execution.execution_id -isnot [string] -or
                [string]$execution.execution_id -cnotmatch '^[0-9a-f]{64}$' -or
                -not (Test-SteinSourceEvidenceInteger `
                    -Value $execution.duration_ms) -or
                [long]$execution.duration_ms -lt 0 -or
                -not (Test-SteinSourceEvidenceInteger `
                    -Value $execution.exit_code) -or
                [long]$execution.exit_code -lt -1 -or
                [long]$execution.exit_code -gt [int]::MaxValue) {
                throw "A source-command execution record is invalid."
            }
            $started = ConvertFrom-SteinSourceEvidenceCommandTimestamp `
                -Value $execution.started_at
            $completed = ConvertFrom-SteinSourceEvidenceCommandTimestamp `
                -Value $execution.completed_at
            if ($completed -lt $started -or
                [long]$execution.duration_ms -ne
                    [long]($completed - $started).TotalMilliseconds) {
                throw "A source-command execution duration is invalid."
            }
            $failureCodes = @(
                'timeout', 'cancelled', 'log_limit_exceeded', 'launch_failed',
                'nonzero_exit', 'candidate_changed', 'group_output_invalid')
            if ([string]$receipt.status -ceq 'pass') {
                if ([long]$execution.exit_code -ne 0 -or
                    $null -ne $execution.failure_code) {
                    throw "A passing source-command execution is inconsistent."
                }
            }
            elseif ($execution.failure_code -isnot [string] -or
                [string]$execution.failure_code -cnotin $failureCodes) {
                throw "A failed source-command execution is inconsistent."
            }

            $logLeaf = if ($category -ceq 'grouped_fixture_execution') {
                'closed-source-fixture-suite'
            }
            else {
                $id
            }
            foreach ($streamName in @('stdout', 'stderr')) {
                $log = $execution.$streamName
                Assert-SteinSourceEvidenceExactProperties `
                    -Value $log `
                    -Expected @('path', 'size', 'sha256') `
                    -FailureMessage "A source-command log descriptor is invalid."
                $expectedLogRelative =
                    "source-command-logs/$logLeaf.$streamName.txt"
                if ($log.path -isnot [string] -or
                    [string]$log.path -cne $expectedLogRelative -or
                    -not (Test-SteinSourceEvidenceInteger -Value $log.size) -or
                    [long]$log.size -lt 0 -or
                    [long]$log.size -gt 16777216 -or
                    $log.sha256 -isnot [string] -or
                    [string]$log.sha256 -cnotmatch '^[0-9a-f]{64}$') {
                    throw "A source-command log descriptor is invalid."
                }
                $null = $expectedLogPaths.Add($expectedLogRelative)
                if (-not $fileLocks.ContainsKey($expectedLogRelative)) {
                    $logPath = Resolve-SteinSourceEvidenceCommandPath `
                        -Root $evidencePath `
                        -RelativePath $expectedLogRelative `
                        -Kind Leaf
                    $logLock = Open-SteinSourceEvidenceCommandFile `
                        -Path $logPath `
                        -MaximumBytes 16777216 `
                        -AllowEmpty
                    $fileLocks[$expectedLogRelative] = $logLock
                    $locks.Add($logLock)
                }
                $capturedLog = $fileLocks[$expectedLogRelative]
                if ([long]$log.size -ne [long]$capturedLog.Size -or
                    [string]$log.sha256 -cne [string]$capturedLog.Sha256) {
                    throw "A source-command log descriptor does not match its file."
                }
            }
            if ([string]$execution.execution_id -cne
                (Get-SteinSourceEvidenceCommandExecutionId `
                    -Command $command `
                    -Execution $execution)) {
                throw "A source-command execution identity is invalid."
            }

            $artifacts = @($receipt.artifacts)
            if ($category -ceq 'direct_execution') {
                if ($artifacts.Count -ne 0) {
                    throw "A direct source-command receipt has unexpected artifacts."
                }
            }
            elseif ([string]$receipt.status -ceq 'pass') {
                if ($artifacts.Count -ne 2) {
                    throw "A grouped source-command receipt is missing artifacts."
                }
                $expectedArtifactRoles = @(
                    'source_fixture_suite_index', 'source_fixture_receipt')
                $expectedArtifactPaths = @(
                    'source-fixtures/index.json',
                    [string]$check.fixture_receipt_path)
                for ($artifactIndex = 0;
                    $artifactIndex -lt 2;
                    $artifactIndex++) {
                    $artifact = $artifacts[$artifactIndex]
                    Assert-SteinSourceEvidenceExactProperties `
                        -Value $artifact `
                        -Expected @('role', 'size', 'sha256') `
                        -FailureMessage "A grouped source-command artifact is invalid."
                    if ($artifact.role -isnot [string] -or
                        [string]$artifact.role -cne
                            $expectedArtifactRoles[$artifactIndex] -or
                        -not (Test-SteinSourceEvidenceInteger `
                            -Value $artifact.size) -or
                        [long]$artifact.size -lt 1 -or
                        [long]$artifact.size -gt 4194304 -or
                        $artifact.sha256 -isnot [string] -or
                        [string]$artifact.sha256 -cnotmatch '^[0-9a-f]{64}$') {
                        throw "A grouped source-command artifact is invalid."
                    }
                    $artifactRelative = $expectedArtifactPaths[$artifactIndex]
                    if (-not $fileLocks.ContainsKey($artifactRelative)) {
                        $artifactPath = Resolve-SteinSourceEvidenceCommandPath `
                            -Root $evidencePath `
                            -RelativePath $artifactRelative `
                            -Kind Leaf
                        $artifactLock = Open-SteinSourceEvidenceCommandFile `
                            -Path $artifactPath `
                            -MaximumBytes 4194304
                        $fileLocks[$artifactRelative] = $artifactLock
                        $locks.Add($artifactLock)
                    }
                    $capturedArtifact = $fileLocks[$artifactRelative]
                    if ([long]$artifact.size -ne
                            [long]$capturedArtifact.Size -or
                        [string]$artifact.sha256 -cne
                            [string]$capturedArtifact.Sha256) {
                        throw "A grouped artifact descriptor does not match its file."
                    }
                }
            }
            elseif ($artifacts.Count -ne 0) {
                throw "A failed grouped source-command receipt has artifacts."
            }

            if ($category -ceq 'grouped_fixture_execution') {
                $identity = Get-SteinSourceEvidenceObjectDigest -Value ([ordered]@{
                        command = $command
                        execution = $execution
                    })
                if ($null -eq $groupedIdentity) {
                    $groupedIdentity = $identity
                }
                elseif ([string]$groupedIdentity -cne $identity) {
                    throw "The grouped source-command receipts do not share execution."
                }
            }
            $receiptRecords.Add([ordered]@{
                    check_id = $id
                    category = $category
                    status = [string]$receipt.status
                    execution_group_id = $expectedGroupId
                    execution_id = [string]$execution.execution_id
                    path = [string]$descriptor.path
                    size = [long]$descriptor.size
                    sha256 = [string]$descriptor.sha256
                    descriptor = $descriptor
                    receipt = $receipt
                })
        }

        if ($executionGroups.Count -ne 25 -or
            $expectedLogPaths.Count -ne 50) {
            throw "The source-command execution coverage is invalid."
        }
        $actualLogs = @(Get-ChildItem -LiteralPath $logDirectory -Force `
                -ErrorAction Stop)
        if ($actualLogs.Count -ne 50 -or
            @($actualLogs | Where-Object {
                    $_.PSIsContainer -or
                    (($_.Attributes -band
                            [IO.FileAttributes]::ReparsePoint) -ne 0)
                }).Count -ne 0) {
            throw "The source-command log directory is not closed."
        }
        foreach ($logEntry in $actualLogs) {
            $relative = "source-command-logs/$([string]$logEntry.Name)"
            if (-not $expectedLogPaths.Contains($relative)) {
                throw "The source-command log directory contains an extra file."
            }
        }

        return [pscustomobject]@{
            SchemaVersion = 1
            Claim = 'closed_source_command_receipt_index'
            IndexPath = $indexRead.Lock.Path
            IndexSize = [long]$indexRead.Lock.Size
            IndexSha256 = [string]$indexRead.Lock.Sha256
            Index = $index
            RegistrySha256 = [string]$RegistryRead.Sha256
            RunnerSha256 = [string]$runnerLock.Sha256
            CandidateCommit = [string]$common.candidate_commit
            CandidateTree = [string]$common.candidate_tree
            CandidateFileCount = [long]$common.candidate_file_count
            CandidateManifestSha256 =
                [string]$common.candidate_manifest_sha256
            EvidenceRootSha256 = [string]$common.evidence_root_sha256
            ExecutedCheckCount = 37
            ExecutionGroupCount = 25
            Receipts = $receiptRecords.ToArray()
            Locks = $locks.ToArray()
        }
    }
    catch {
        foreach ($lock in $locks.ToArray()) {
            $lock.Stream.Dispose()
        }
        throw
    }
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
