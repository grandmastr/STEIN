[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$runnerPath = Join-Path $PSScriptRoot 'Run-Source-Check.ps1'
$registryPath = Join-Path $PSScriptRoot 'Source-Command-Registry.json'
. $runnerPath -LibraryOnly

if ([long]$script:SourceCommandMaximumLogBytes -ne 16777216L) {
    throw 'The source-command log bound differs from the downstream evidence contract.'
}

function Copy-SteinSourceCommandTestValue {
    param([Parameter(Mandatory = $true)] $Value)

    return ($Value | ConvertTo-Json -Depth 20 -Compress) |
        ConvertFrom-Json -ErrorAction Stop
}

function Assert-SteinSourceCommandTestRejected {
    param(
        [Parameter(Mandatory = $true)][scriptblock] $Action,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $rejected = $false
    try {
        & $Action
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "Source-command validation accepted $Description."
    }
}

function Assert-SteinSourceCommandTestSequence {
    param(
        [Parameter(Mandatory = $true)][object[]] $Actual,
        [Parameter(Mandatory = $true)][object[]] $Expected,
        [Parameter(Mandatory = $true)][string] $Description
    )

    if ($Actual.Count -ne $Expected.Count) {
        throw "$Description has the wrong length."
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ([string]$Actual[$index] -cne [string]$Expected[$index]) {
            throw "$Description differs at position $index."
        }
    }
}

function ConvertTo-SteinSourceCommandTestCrLfNormalizedBytes {
    param(
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [byte[]] $Bytes
    )

    $output = New-Object Collections.Generic.List[byte]
    for ($index = 0; $index -lt $Bytes.Length; $index++) {
        if ($Bytes[$index] -eq 13 -and $index + 1 -lt $Bytes.Length -and
            $Bytes[$index + 1] -eq 10) {
            continue
        }
        $output.Add($Bytes[$index])
    }
    return ,$output.ToArray()
}

function Get-SteinSourceCommandTestGitBlobObjectId {
    param(
        [Parameter(Mandatory = $true)][string] $GitExecutable,
        [Parameter(Mandatory = $true)][string] $RepositoryRoot,
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)][byte[]] $Bytes,
        [Parameter(Mandatory = $true)][ValidateSet(40, 64)][int] $ObjectIdLength
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $GitExecutable
    $startInfo.Arguments =
        '-c core.fsmonitor=false -c core.untrackedCache=false hash-object --stdin'
    $startInfo.WorkingDirectory = $RepositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $started = $false
    try {
        if (-not $process.Start()) {
            throw 'The Git blob test oracle could not start.'
        }
        $started = $true
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($Bytes.Length -gt 0) {
            $process.StandardInput.BaseStream.Write($Bytes, 0, $Bytes.Length)
        }
        $process.StandardInput.BaseStream.Flush()
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(60000)) {
            try { $process.Kill() } catch { }
            throw 'The Git blob test oracle timed out.'
        }
        $process.WaitForExit()
        $stdout = ([string]$stdoutTask.Result).Trim()
        $stderr = [string]$stderrTask.Result
        if ($process.ExitCode -ne 0 -or
            -not [string]::IsNullOrEmpty($stderr) -or
            $stdout -cnotmatch "^[0-9a-f]{$ObjectIdLength}$") {
            throw 'The Git blob test oracle returned an invalid result.'
        }
        return $stdout
    }
    finally {
        try { $process.StandardInput.Close() } catch { }
        if ($started) {
            try {
                if (-not $process.HasExited) {
                    $process.Kill()
                }
            }
            catch { }
        }
        $process.Dispose()
    }
}

function Test-SteinSourceCommandManagedGitBlobHashing {
    param(
        [Parameter(Mandatory = $true)][string] $GitExecutable,
        [Parameter(Mandatory = $true)][string] $TestRoot
    )

    $hashCases = New-Object Collections.Generic.List[object]
    $hashCases.Add([pscustomobject]@{
            Name = 'empty'
            Raw = [byte[]]@()
            Normalized = [byte[]]@()
        })
    $mixedRaw = [byte[]]@(
        0, 255, 65, 13, 10, 66, 10, 67, 13, 68, 13, 13, 10, 69, 13)
    $hashCases.Add([pscustomobject]@{
            Name = 'binary-mixed-eol-trailing-cr-and-cr-cr-lf'
            Raw = $mixedRaw
            Normalized = ConvertTo-SteinSourceCommandTestCrLfNormalizedBytes `
                -Bytes $mixedRaw
        })
    $boundaryRaw = New-Object byte[] 65537
    for ($index = 0; $index -lt 65535; $index++) {
        $boundaryRaw[$index] = 65
    }
    $boundaryRaw[65535] = 13
    $boundaryRaw[65536] = 10
    $hashCases.Add([pscustomobject]@{
            Name = 'buffer-boundary-crlf'
            Raw = $boundaryRaw
            Normalized = ConvertTo-SteinSourceCommandTestCrLfNormalizedBytes `
                -Bytes $boundaryRaw
        })
    $multiBufferRaw = New-Object byte[] 196650
    for ($index = 0; $index -lt $multiBufferRaw.Length; $index++) {
        $multiBufferRaw[$index] = 90
    }
    $multiBufferRaw[0] = 0
    $multiBufferRaw[1] = 255
    $multiBufferRaw[65535] = 13
    $multiBufferRaw[65536] = 10
    $multiBufferRaw[131071] = 13
    $multiBufferRaw[131072] = 13
    $multiBufferRaw[131073] = 10
    $multiBufferRaw[$multiBufferRaw.Length - 1] = 13
    $hashCases.Add([pscustomobject]@{
            Name = 'binary-multibuffer-boundaries'
            Raw = $multiBufferRaw
            Normalized = ConvertTo-SteinSourceCommandTestCrLfNormalizedBytes `
                -Bytes $multiBufferRaw
        })

    $formats = New-Object Collections.Generic.List[object]
    $sha1Root = Join-Path $TestRoot 'hash-sha1'
    $sha1Output = @(& $GitExecutable init --quiet --object-format=sha1 `
            -- $sha1Root 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "The SHA-1 Git blob test repository could not be created: $($sha1Output -join ' ')"
    }
    $formats.Add([pscustomobject]@{
            Name = 'sha1'
            ObjectIdLength = 40
            Root = $sha1Root
        })

    $sha256Root = Join-Path $TestRoot 'hash-sha256'
    $sha256Output = @(& $GitExecutable init --quiet --object-format=sha256 `
            -- $sha256Root 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $formats.Add([pscustomobject]@{
                Name = 'sha256'
                ObjectIdLength = 64
                Root = $sha256Root
            })
    }
    else {
        $sha256Failure = $sha256Output -join "`n"
        if ($sha256Failure -notmatch
            '(?i)(unknown option|unknown hash|unsupported hash|not supported|invalid.*object-format)') {
            throw "The SHA-256 Git blob test repository failed unexpectedly: $sha256Failure"
        }
        Write-Host '[SKIP] Local Git cannot initialize a SHA-256 repository.'
    }

    foreach ($format in $formats.ToArray()) {
        $actualFormat = (@(& $GitExecutable -C ([string]$format.Root) `
                    rev-parse --show-object-format 2>&1) -join "`n").Trim()
        if ($LASTEXITCODE -ne 0 -or
            $actualFormat -cne [string]$format.Name) {
            throw "The $([string]$format.Name) Git blob test repository has the wrong object format."
        }
        foreach ($case in $hashCases.ToArray()) {
            $rawBytes = [byte[]]$case.Raw
            $normalizedBytes = [byte[]]$case.Normalized
            $expectedCrLfPairCount = [long]$rawBytes.Length -
                [long]$normalizedBytes.Length
            $stream = [IO.MemoryStream]::new($rawBytes, $false)
            try {
                if ($stream.Length -gt 0) {
                    $stream.Position = $stream.Length
                }
                $rawState = Get-SteinSourceCommandGitBlobRawState `
                    -Stream $stream `
                    -ObjectIdLength ([int]$format.ObjectIdLength)
                $oracleRaw = Get-SteinSourceCommandTestGitBlobObjectId `
                    -GitExecutable $GitExecutable `
                    -RepositoryRoot ([string]$format.Root) `
                    -Bytes $rawBytes `
                    -ObjectIdLength ([int]$format.ObjectIdLength)
                if ([string]$rawState.ObjectId -cne $oracleRaw -or
                    [long]$rawState.CrLfPairCount -ne $expectedCrLfPairCount -or
                    $stream.Position -ne 0) {
                    throw "The $([string]$format.Name) $([string]$case.Name) raw Git blob hash is invalid."
                }
                if ([string]$format.Name -ceq 'sha1' -and
                    [string]$case.Name -ceq 'empty' -and
                    $oracleRaw -cne 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391') {
                    throw 'The empty SHA-1 Git blob oracle is invalid.'
                }
                if ($expectedCrLfPairCount -gt 0) {
                    if ($stream.Length -gt 0) {
                        $stream.Position = $stream.Length
                    }
                    $normalizedObjectId =
                        Get-SteinSourceCommandCrLfNormalizedGitBlobObjectId `
                            -Stream $stream `
                            -ObjectIdLength ([int]$format.ObjectIdLength) `
                            -CrLfPairCount $expectedCrLfPairCount
                    $oracleNormalized = Get-SteinSourceCommandTestGitBlobObjectId `
                        -GitExecutable $GitExecutable `
                        -RepositoryRoot ([string]$format.Root) `
                        -Bytes $normalizedBytes `
                        -ObjectIdLength ([int]$format.ObjectIdLength)
                    if ($normalizedObjectId -cne $oracleNormalized -or
                        $stream.Position -ne 0) {
                        throw "The $([string]$format.Name) $([string]$case.Name) normalized Git blob hash is invalid."
                    }
                }
            }
            finally {
                $stream.Dispose()
            }
        }

        $failureStream = [IO.MemoryStream]::new($mixedRaw, $false)
        try {
            $expectedCount = [long]$mixedRaw.Length -
                [long](ConvertTo-SteinSourceCommandTestCrLfNormalizedBytes `
                    -Bytes $mixedRaw).Length
            Assert-SteinSourceCommandTestRejected `
                -Description "an incorrect $([string]$format.Name) CRLF count" `
                -Action {
                    $null = Get-SteinSourceCommandCrLfNormalizedGitBlobObjectId `
                        -Stream $failureStream `
                        -ObjectIdLength ([int]$format.ObjectIdLength) `
                        -CrLfPairCount ($expectedCount + 1)
                }
            if ($failureStream.Position -ne 0) {
                throw 'A failed managed Git blob hash did not reset its stream.'
            }
        }
        finally {
            $failureStream.Dispose()
        }

        $changedRaw = [Text.Encoding]::UTF8.GetBytes("alpha`r`nBETA")
        $expectedBytes = [Text.Encoding]::UTF8.GetBytes("alpha`nbeta")
        $changedStream = [IO.MemoryStream]::new($changedRaw, $false)
        try {
            $changedState = Get-SteinSourceCommandGitBlobRawState `
                -Stream $changedStream `
                -ObjectIdLength ([int]$format.ObjectIdLength)
            $changedNormalized =
                Get-SteinSourceCommandCrLfNormalizedGitBlobObjectId `
                    -Stream $changedStream `
                    -ObjectIdLength ([int]$format.ObjectIdLength) `
                    -CrLfPairCount ([long]$changedState.CrLfPairCount)
            $expectedObjectId = Get-SteinSourceCommandTestGitBlobObjectId `
                -GitExecutable $GitExecutable `
                -RepositoryRoot ([string]$format.Root) `
                -Bytes $expectedBytes `
                -ObjectIdLength ([int]$format.ObjectIdLength)
            if ($changedNormalized -ceq $expectedObjectId) {
                throw 'CRLF normalization concealed a non-EOL content change.'
            }
        }
        finally {
            $changedStream.Dispose()
        }
    }
}

function Test-SteinSourceCommandCandidateBinding {
    param([Parameter(Mandatory = $true)][string] $GitExecutable)

    $originalRepositoryRoot = $script:SourceCommandRepositoryRoot
    $testRoot = Join-Path $repoRoot (
        'artifacts\evidence\phase-2\source-command-candidate-' +
        [Guid]::NewGuid().ToString('N'))
    $originRoot = Join-Path $testRoot 'origin'
    $cloneRoot = Join-Path $testRoot 'clone'
    $null = New-Item -ItemType Directory -Path $originRoot -ErrorAction Stop
    try {
        Test-SteinSourceCommandManagedGitBlobHashing `
            -GitExecutable $GitExecutable `
            -TestRoot $testRoot
        & $GitExecutable -C $originRoot init --quiet
        & $GitExecutable -C $originRoot config user.name 'STEIN Test'
        & $GitExecutable -C $originRoot config user.email 'stein-test@example.invalid'
        & $GitExecutable -C $originRoot config core.autocrlf false
        $sampleBytes = [Text.UTF8Encoding]::new($false).GetBytes(
            "alpha`nbeta`n")
        try {
            [IO.File]::WriteAllBytes(
                (Join-Path $originRoot 'sample.txt'),
                $sampleBytes)
        }
        finally {
            [Array]::Clear($sampleBytes, 0, $sampleBytes.Length)
        }
        & $GitExecutable -C $originRoot add -- sample.txt
        & $GitExecutable -C $originRoot commit --quiet -m baseline
        if ($LASTEXITCODE -ne 0) {
            throw 'The source-command test could not create its candidate commit.'
        }
        & $GitExecutable -c core.autocrlf=true clone --quiet --no-local `
            $originRoot $cloneRoot
        & $GitExecutable -C $cloneRoot config core.autocrlf true
        if ($LASTEXITCODE -ne 0) {
            throw 'The source-command test could not create its CRLF checkout.'
        }
        $commit = [string](@(& $GitExecutable -C $cloneRoot rev-parse HEAD)[0])
        $tree = [string](@(& $GitExecutable -C $cloneRoot `
                    rev-parse 'HEAD^{tree}')[0])
        $blob = [string](@(& $GitExecutable -C $cloneRoot `
                    rev-parse 'HEAD:sample.txt')[0])
        $commit = $commit.Trim()
        $tree = $tree.Trim()
        $blob = $blob.Trim()
        $status = (@(& $GitExecutable -C $cloneRoot `
                    status --porcelain=v1) -join "`n").Trim()
        $eol = @(& $GitExecutable -C $cloneRoot ls-files --eol) -join "`n"
        if ($LASTEXITCODE -ne 0 -or $status.Length -ne 0 -or
            $eol -notmatch 'w/crlf') {
            throw 'The source-command test CRLF checkout is not clean.'
        }

        $script:SourceCommandRepositoryRoot = [IO.Path]::GetFullPath($cloneRoot)
        $candidate = Open-SteinSourceCommandCandidate `
            -GitExecutable $GitExecutable `
            -ExpectedCommit $commit `
            -ExpectedTree $tree
        try {
            $pathByteCount = [Text.UTF8Encoding]::new($false).GetByteCount(
                'sample.txt')
            $expectedManifest = Get-SteinSourceCommandTextSha256 `
                -Value "$pathByteCount`:sample.txt|100644|$blob"
            if ([long]$candidate.FileCount -ne 1 -or
                [string]$candidate.ManifestSha256 -cne $expectedManifest -or
                [long]$candidate.EolConvertedFileCount -ne 1) {
                throw 'A clean CRLF checkout did not bind to its canonical Git tree.'
            }
            $null = Assert-SteinSourceCommandCandidateStable `
                -Candidate $candidate `
                -GitExecutable $GitExecutable

            $infoAttributes = Join-Path $cloneRoot '.git\info\attributes'
            foreach ($dangerousAttribute in @(
                    'sample.txt filter=stein-test',
                    'sample.txt ident',
                    'sample.txt working-tree-encoding=UTF-16')) {
                [IO.File]::WriteAllText(
                    $infoAttributes,
                    "$dangerousAttribute`n",
                    [Text.UTF8Encoding]::new($false))
                Assert-SteinSourceCommandTestRejected `
                    -Description "the active $dangerousAttribute attribute" `
                    -Action {
                        $null = Assert-SteinSourceCommandCandidateStable `
                            -Candidate $candidate `
                            -GitExecutable $GitExecutable
                    }
            }
            [IO.File]::Delete($infoAttributes)
            $null = Assert-SteinSourceCommandCandidateStable `
                -Candidate $candidate `
                -GitExecutable $GitExecutable
        }
        finally {
            foreach ($lock in $candidate.Locks.ToArray()) {
                $lock.Stream.Dispose()
            }
        }

        & $GitExecutable -C $cloneRoot update-index `
            --assume-unchanged -- sample.txt
        Assert-SteinSourceCommandTestRejected `
            -Description 'an assume-unchanged candidate file' `
            -Action {
                $null = Open-SteinSourceCommandCandidate `
                    -GitExecutable $GitExecutable `
                    -ExpectedCommit $commit `
                    -ExpectedTree $tree
            }
        & $GitExecutable -C $cloneRoot update-index `
            --no-assume-unchanged -- sample.txt
        & $GitExecutable -C $cloneRoot update-index `
            --skip-worktree -- sample.txt
        Assert-SteinSourceCommandTestRejected `
            -Description 'a skip-worktree candidate file' `
            -Action {
                $null = Open-SteinSourceCommandCandidate `
                    -GitExecutable $GitExecutable `
                    -ExpectedCommit $commit `
                    -ExpectedTree $tree
            }
        & $GitExecutable -C $cloneRoot update-index `
            --no-skip-worktree -- sample.txt
        & $GitExecutable -C $cloneRoot update-index --chmod=+x -- sample.txt
        Assert-SteinSourceCommandTestRejected `
            -Description 'an index/tree mode mismatch' `
            -Action {
                $null = Open-SteinSourceCommandCandidate `
                    -GitExecutable $GitExecutable `
                    -ExpectedCommit $commit `
                    -ExpectedTree $tree
            }
        & $GitExecutable -C $cloneRoot update-index --chmod=-x -- sample.txt
    }
    finally {
        $script:SourceCommandRepositoryRoot = $originalRepositoryRoot
        if (Test-Path -LiteralPath $testRoot) {
            Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop
        }
    }
}

$registry = Get-Content -LiteralPath $registryPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -ErrorAction Stop
$contract = Assert-SteinSourceCommandRegistry -Registry $registry
$checks = @($registry.checks)
if ($checks.Count -ne 44 -or
    @($checks | Where-Object { $_.category -ceq 'direct_execution' }).Count -ne 24 -or
    @($checks | Where-Object {
            $_.category -ceq 'grouped_fixture_execution'
        }).Count -ne 13 -or
    @($checks | Where-Object { $_.category -ceq 'derived' }).Count -ne 2 -or
    @($checks | Where-Object {
            $_.category -ceq 'retained_obligation'
        }).Count -ne 5 -or
    [long]$contract.ExecutionGroupCount -ne 25) {
    throw 'The source-command registry coverage counts are invalid.'
}

$singleArgumentCheck = @($checks | Where-Object {
        [string]$_.id -ceq 'desktop-typecheck'
    })
$singleArgumentVector = @(ConvertTo-SteinSourceCommandArgumentVector `
        -Check $singleArgumentCheck[0] `
        -ResolvedEvidenceRoot (Join-Path $repoRoot `
            'artifacts\evidence\phase-2\source-command-vector-contract'))
if ($singleArgumentCheck.Count -ne 1 -or
    $singleArgumentVector.Count -ne 1 -or
    [string]$singleArgumentVector[0] -cne 'typecheck') {
    throw 'A one-element source-command argument vector was not retained as an array.'
}

foreach ($mutation in @(
        [pscustomobject]@{ Value = 'contains space'; Description = 'a whitespace token' },
        [pscustomobject]@{ Value = '"quoted"'; Description = 'a quoted token' },
        [pscustomobject]@{ Value = ''; Description = 'an empty token' },
        [pscustomobject]@{ Value = 'C:/escape'; Description = 'an absolute token' },
        [pscustomobject]@{ Value = 'fmt:other'; Description = 'a colon token' },
        [pscustomobject]@{ Value = '%TEMP%'; Description = 'an environment-expansion token' },
        [pscustomobject]@{ Value = 'fmt&whoami'; Description = 'a shell token' })) {
    $candidate = Copy-SteinSourceCommandTestValue -Value $registry
    $candidate.checks[0].arguments[0].value = [string]$mutation.Value
    Assert-SteinSourceCommandTestRejected `
        -Description ([string]$mutation.Description) `
        -Action { $null = Assert-SteinSourceCommandRegistry -Registry $candidate }
}

$groupDrift = Copy-SteinSourceCommandTestValue -Value $registry
$groupDrift.checks[23].timeout_seconds = 60
Assert-SteinSourceCommandTestRejected `
    -Description 'divergent grouped execution material' `
    -Action { $null = Assert-SteinSourceCommandRegistry -Registry $groupDrift }

$profileDrift = Copy-SteinSourceCommandTestValue -Value $registry
$profileDrift.checks[0].environment_profile = 'phase2_source_fixture_v1'
Assert-SteinSourceCommandTestRejected `
    -Description 'a grouped profile on a direct check' `
    -Action { $null = Assert-SteinSourceCommandRegistry -Registry $profileDrift }

$reasonDrift = Copy-SteinSourceCommandTestValue -Value $registry
$reasonDrift.checks[17].reason_code = 'syntactically_valid_but_wrong'
Assert-SteinSourceCommandTestRejected `
    -Description 'a changed retained-obligation reason' `
    -Action { $null = Assert-SteinSourceCommandRegistry -Registry $reasonDrift }

$ordered = @('one', 'two', 'three')
$orderedDigest = Get-SteinSourceCommandArgumentDigest -Arguments $ordered
if ($orderedDigest -cne (Get-SteinSourceCommandArgumentDigest -Arguments $ordered) -or
    $orderedDigest -ceq (Get-SteinSourceCommandArgumentDigest `
        -Arguments @('three', 'two', 'one'))) {
    throw 'The source-command argument digest is not ordered and deterministic.'
}

$gitExecutable = [string](@(Get-Command git.exe -CommandType Application `
            -ErrorAction Stop)[0].Source)
Test-SteinSourceCommandCandidateBinding -GitExecutable $gitExecutable
$gitResolvedExecutable = [IO.Path]::GetFullPath((Join-Path `
            (Split-Path -Parent (Split-Path -Parent $gitExecutable)) `
            'mingw64\bin\git.exe'))
$gitLauncherSha256 = (Get-FileHash -LiteralPath $gitExecutable `
        -Algorithm SHA256).Hash.ToLowerInvariant()
$gitResolvedSha256 = (Get-FileHash -LiteralPath $gitResolvedExecutable `
        -Algorithm SHA256).Hash.ToLowerInvariant()

$commit = (& $gitExecutable rev-parse HEAD).Trim()
$tree = (& $gitExecutable rev-parse 'HEAD^{tree}').Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'The source-command test could not resolve the candidate tree.'
}
$registrySha256 = (Get-FileHash -LiteralPath $registryPath -Algorithm SHA256).
    Hash.ToLowerInvariant()
$testLeaf = "source-command-contract-$([Guid]::NewGuid().ToString('N'))"
$evidenceRelative = "artifacts/evidence/phase-2/$testLeaf"
$evidencePath = Join-Path $repoRoot $evidenceRelative.Replace(
    '/', [IO.Path]::DirectorySeparatorChar)
$powershell = Join-Path ([Environment]::GetFolderPath(
        [Environment+SpecialFolder]::System)) `
    'WindowsPowerShell\v1.0\powershell.exe'

$pwshExecutable = [string](@(Get-Command pwsh.exe -CommandType Application `
            -ErrorAction Stop)[0].Source)
$poisonedModuleRoot = Join-Path (Split-Path -Parent $pwshExecutable) 'Modules'
$poisonedSecurityManifest = Join-Path $poisonedModuleRoot `
    'Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
if (-not (Test-Path -LiteralPath $poisonedSecurityManifest -PathType Leaf)) {
    throw 'The source-command module-path regression fixture is unavailable.'
}
$escapedRunnerPath = $runnerPath.Replace("'", "''")
$escapedGitExecutable = $gitExecutable.Replace("'", "''")
$escapedEvidenceRelative = $evidenceRelative.Replace("'", "''")
$moduleBindingProbeTemplate = @'
$autoloadFailed = $false
try {
    Get-AuthenticodeSignature -LiteralPath (Join-Path $PSHOME 'powershell.exe') -ErrorAction Stop | Out-Null
}
catch {
    $autoloadFailed = [string]$_.FullyQualifiedErrorId -like '*CouldNotAutoloadMatchingModule*'
}
if (-not $autoloadFailed) {
    throw 'source_command_security_module_poison_fixture_invalid'
}
. '__STEIN_RUNNER_PATH__' -LibraryOnly
function global:Get-AuthenticodeSignature {
    [CmdletBinding()]
    param([string] $LiteralPath)
    return [pscustomobject]@{
        Status = 'Valid'
        SignerCertificate = [pscustomobject]@{
            Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
        }
    }
}
$shadowRejected = $false
try {
    Initialize-SteinSourceCommandSecurityModule
}
catch {
    $shadowRejected = [string]$_.Exception.Message -ceq
        'source_command_security_module_binding_invalid'
}
finally {
    Remove-Item -LiteralPath Function:\Get-AuthenticodeSignature `
        -Force -ErrorAction SilentlyContinue
}
if (-not $shadowRejected) {
    throw 'source_command_security_module_shadow_not_rejected'
}
Remove-Module -Name 'Microsoft.PowerShell.Security' `
    -Force -ErrorAction Stop
$env:PSModulePath = '__STEIN_POISONED_MODULE_ROOT__'
& '__STEIN_RUNNER_PATH__' `
    -CheckId 'rust-format' `
    -CandidateCommit '__STEIN_CANDIDATE_COMMIT__' `
    -CandidateTree '__STEIN_CANDIDATE_TREE__' `
    -ExpectedRegistrySha256 '__STEIN_REGISTRY_SHA256__' `
    -ExpectedGitLauncherPath '__STEIN_GIT_EXECUTABLE__' `
    -ExpectedGitLauncherSha256 '__STEIN_GIT_LAUNCHER_SHA256__' `
    -ExpectedGitResolvedSha256 '__STEIN_GIT_RESOLVED_SHA256__' `
    -EvidenceRoot '__STEIN_EVIDENCE_ROOT__'
'@
$moduleBindingProbe = $moduleBindingProbeTemplate.Replace(
    '__STEIN_RUNNER_PATH__',
    $escapedRunnerPath).Replace(
    '__STEIN_POISONED_MODULE_ROOT__',
    $poisonedModuleRoot.Replace("'", "''")).Replace(
    '__STEIN_CANDIDATE_COMMIT__',
    $commit).Replace(
    '__STEIN_CANDIDATE_TREE__',
    $tree).Replace(
    '__STEIN_REGISTRY_SHA256__',
    $registrySha256).Replace(
    '__STEIN_GIT_EXECUTABLE__',
    $escapedGitExecutable).Replace(
    '__STEIN_GIT_LAUNCHER_SHA256__',
    $gitLauncherSha256).Replace(
    '__STEIN_GIT_RESOLVED_SHA256__',
    $gitResolvedSha256).Replace(
    '__STEIN_EVIDENCE_ROOT__',
    $escapedEvidenceRelative)
$moduleBindingProbeEncoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($moduleBindingProbe))
$moduleBindingProbeStart = [Diagnostics.ProcessStartInfo]::new()
$moduleBindingProbeStart.FileName = $powershell
$moduleBindingProbeStart.Arguments =
    "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $moduleBindingProbeEncoded"
$moduleBindingProbeStart.WorkingDirectory = $repoRoot
$moduleBindingProbeStart.UseShellExecute = $false
$moduleBindingProbeStart.CreateNoWindow = $true
$moduleBindingProbeStart.RedirectStandardOutput = $true
$moduleBindingProbeStart.RedirectStandardError = $true
$moduleBindingProbeStart.EnvironmentVariables['PSModulePath'] =
    $poisonedModuleRoot
$moduleBindingProbeProcess = [Diagnostics.Process]::new()
$moduleBindingProbeProcess.StartInfo = $moduleBindingProbeStart
$moduleBindingProbeStarted = $false
try {
    if (-not $moduleBindingProbeProcess.Start()) {
        throw 'The source-command poisoned module-path probe could not start.'
    }
    $moduleBindingProbeStarted = $true
    $moduleBindingProbeStdoutTask =
        $moduleBindingProbeProcess.StandardOutput.ReadToEndAsync()
    $moduleBindingProbeStderrTask =
        $moduleBindingProbeProcess.StandardError.ReadToEndAsync()
    if (-not $moduleBindingProbeProcess.WaitForExit(660000)) {
        try { $moduleBindingProbeProcess.Kill() } catch { }
        throw 'The source-command poisoned module-path probe timed out.'
    }
    $moduleBindingProbeProcess.WaitForExit()
    $moduleBindingProbeStdout = [string]$moduleBindingProbeStdoutTask.Result
    $moduleBindingProbeStderr = [string]$moduleBindingProbeStderrTask.Result
    if ($moduleBindingProbeStdout.Length -gt 1048576 -or
        $moduleBindingProbeStderr.Length -gt 1048576 -or
        $moduleBindingProbeProcess.ExitCode -ne 0) {
        throw 'The source-command runner did not repair a poisoned inherited module path.'
    }
}
finally {
    if ($moduleBindingProbeStarted) {
        try {
            if (-not $moduleBindingProbeProcess.HasExited) {
                $moduleBindingProbeProcess.Kill()
            }
        }
        catch { }
    }
    $moduleBindingProbeProcess.Dispose()
}

$receiptPath = Join-Path $evidencePath `
    'source-command-receipts\rust-format.receipt.json'
$receiptRead = Read-SteinSourceCommandLockedJson `
    -Path $receiptPath `
    -MaximumBytes 1048576
try {
    $receipt = $receiptRead.Value
}
finally {
    $receiptRead.Lock.Stream.Dispose()
}
Assert-SteinSourceCommandExactProperties -Value $receipt `
    -Expected @(
        'schema_version', 'claim', 'check_id', 'category', 'status', 'bindings',
        'command', 'execution', 'artifacts', 'obligation_code', 'derivation') `
    -FailureCode 'source_command_test_receipt_invalid'
Assert-SteinSourceCommandExactProperties -Value $receipt.bindings `
    -Expected @(
        'candidate_commit', 'candidate_tree', 'candidate_file_count',
        'candidate_manifest_sha256', 'git_launcher_sha256',
        'git_resolved_sha256', 'registry_sha256', 'runner_sha256',
        'evidence_root_sha256', 'check_definition_sha256',
        'execution_group_count') `
    -FailureCode 'source_command_test_receipt_invalid'
Assert-SteinSourceCommandExactProperties -Value $receipt.command `
    -Expected @(
        'executable_role', 'executable_name', 'executable_size',
        'executable_sha256', 'arguments', 'arguments_sha256',
        'working_directory', 'environment_profile',
        'environment_profile_sha256', 'timeout_seconds') `
    -FailureCode 'source_command_test_receipt_invalid'
Assert-SteinSourceCommandExactProperties -Value $receipt.execution `
    -Expected @(
        'execution_group_id', 'execution_id', 'started_at', 'completed_at',
        'duration_ms', 'exit_code', 'failure_code', 'stdout', 'stderr') `
    -FailureCode 'source_command_test_receipt_invalid'
foreach ($streamName in @('stdout', 'stderr')) {
    Assert-SteinSourceCommandExactProperties `
        -Value $receipt.execution.$streamName `
        -Expected @('path', 'size', 'sha256') `
        -FailureCode 'source_command_test_receipt_invalid'
}

Assert-SteinSourceCommandTestSequence `
    -Actual @($receipt.command.arguments) `
    -Expected @('fmt', '--all', '--', '--check') `
    -Description 'the direct normalized argument vector'
$rustFormatDefinition = @($checks | Where-Object {
        [string]$_.id -ceq 'rust-format'
    })[0]
$executionMaterial = [ordered]@{
    execution_group_id = [string]$receipt.execution.execution_group_id
    executable_role = [string]$receipt.command.executable_role
    executable_sha256 = [string]$receipt.command.executable_sha256
    arguments_sha256 = [string]$receipt.command.arguments_sha256
    working_directory = [string]$receipt.command.working_directory
    environment_profile_sha256 =
        [string]$receipt.command.environment_profile_sha256
    started_at = [string]$receipt.execution.started_at
    completed_at = [string]$receipt.execution.completed_at
    exit_code = [long]$receipt.execution.exit_code
    failure_code = $receipt.execution.failure_code
    stdout = $receipt.execution.stdout
    stderr = $receipt.execution.stderr
}
if ([long]$receipt.schema_version -ne 1 -or
    [string]$receipt.claim -cne 'closed_source_command_execution_only' -or
    [string]$receipt.check_id -cne 'rust-format' -or
    [string]$receipt.category -cne 'direct_execution' -or
    [string]$receipt.status -cne 'pass' -or
    [string]$receipt.bindings.candidate_commit -cne $commit -or
    [string]$receipt.bindings.candidate_tree -cne $tree -or
    [string]$receipt.bindings.git_launcher_sha256 -cne $gitLauncherSha256 -or
    [string]$receipt.bindings.git_resolved_sha256 -cne $gitResolvedSha256 -or
    [string]$receipt.bindings.registry_sha256 -cne $registrySha256 -or
    [long]$receipt.bindings.execution_group_count -ne 25 -or
    [string]$receipt.bindings.check_definition_sha256 -cne
        (Get-SteinSourceCommandObjectSha256 -Value $rustFormatDefinition) -or
    [string]$receipt.command.arguments_sha256 -cne
        (Get-SteinSourceCommandArgumentDigest `
            -Arguments @($receipt.command.arguments | ForEach-Object { [string]$_ })) -or
    [string]$receipt.execution.execution_group_id -cne 'direct:rust-format' -or
    [string]$receipt.execution.execution_id -cne
        (Get-SteinSourceCommandObjectSha256 -Value $executionMaterial) -or
    $null -ne $receipt.execution.failure_code -or
    $null -ne $receipt.obligation_code -or
    $null -ne $receipt.derivation -or
    @($receipt.artifacts).Count -ne 0) {
    throw 'The direct source-command receipt is not closed and self-consistent.'
}

foreach ($streamName in @('stdout', 'stderr')) {
    $descriptor = $receipt.execution.$streamName
    $expectedRelative =
        "source-command-logs/rust-format.$streamName.txt"
    $path = Join-Path $evidencePath ([string]$descriptor.path).Replace(
        '/', [IO.Path]::DirectorySeparatorChar)
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ([string]$descriptor.path -cne $expectedRelative -or
        [long]$descriptor.size -ne [long]$item.Length -or
        [string]$descriptor.sha256 -cne
            (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).
                Hash.ToLowerInvariant()) {
        throw "The $streamName log descriptor is not bound to its exact artifact."
    }
}

$oversizedLogPath = Join-Path $evidencePath 'oversized-log-contract.txt'
[IO.File]::WriteAllBytes($oversizedLogPath, (New-Object byte[] 32))
if (-not (Reset-SteinSourceCommandOversizedLog `
        -Path $oversizedLogPath `
        -MaximumBytes 8) -or
    (Get-Item -LiteralPath $oversizedLogPath -Force).Length -gt 128 -or
    [IO.File]::ReadAllText($oversizedLogPath) -cne
        "source_command_log_limit_exceeded:8`n") {
    throw 'An oversized source-command log was not converted to bounded failure evidence.'
}

$wrongGitRoot =
    "artifacts/evidence/phase-2/source-command-wrong-git-$([Guid]::NewGuid().ToString('N'))"
$ErrorActionPreference = 'Continue'
& $powershell `
    -NoLogo `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File $runnerPath `
    -CheckId rust-format `
    -CandidateCommit $commit `
    -CandidateTree $tree `
    -ExpectedRegistrySha256 $registrySha256 `
    -ExpectedGitLauncherPath $gitExecutable `
    -ExpectedGitLauncherSha256 $gitLauncherSha256 `
    -ExpectedGitResolvedSha256 ('0' * 64) `
    -EvidenceRoot $wrongGitRoot *> $null
$wrongGitExitCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($wrongGitExitCode -eq 0 -or
    (Test-Path -LiteralPath (Join-Path $repoRoot $wrongGitRoot))) {
    throw 'The command runner accepted a mismatched resolved Git payload.'
}

$nonExecutableRoot =
    "artifacts/evidence/phase-2/source-command-nonexec-$([Guid]::NewGuid().ToString('N'))"
$ErrorActionPreference = 'Continue'
& $powershell `
    -NoLogo `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File $runnerPath `
    -CheckId source-provenance-stability `
    -CandidateCommit $commit `
    -CandidateTree $tree `
    -ExpectedRegistrySha256 $registrySha256 `
    -ExpectedGitLauncherPath $gitExecutable `
    -ExpectedGitLauncherSha256 $gitLauncherSha256 `
    -ExpectedGitResolvedSha256 $gitResolvedSha256 `
    -EvidenceRoot $nonExecutableRoot *> $null
$nonExecutableExitCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($nonExecutableExitCode -eq 0 -or
    (Test-Path -LiteralPath (Join-Path $repoRoot $nonExecutableRoot))) {
    throw 'A non-executable derived row was accepted by the command runner.'
}

$ErrorActionPreference = 'Continue'
& $powershell `
    -NoLogo `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File $runnerPath `
    -CheckId source-report-command-provenance `
    -CandidateCommit $commit `
    -CandidateTree $tree `
    -ExpectedRegistrySha256 $registrySha256 `
    -ExpectedGitLauncherPath $gitExecutable `
    -ExpectedGitLauncherSha256 $gitLauncherSha256 `
    -ExpectedGitResolvedSha256 $gitResolvedSha256 `
    -EvidenceRoot $evidenceRelative *> $null
$finalizerExitCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($finalizerExitCode -eq 0 -or
    (Test-Path -LiteralPath (Join-Path $evidencePath `
            'source-command-receipts\index.json'))) {
    throw 'The receipt-suite finalizer accepted incomplete 37-check coverage.'
}

Write-Host 'Source-command registry, runner, argv domain, receipt, and finalizer contracts are valid.'
