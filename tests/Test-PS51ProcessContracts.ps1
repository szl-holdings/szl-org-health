#requires -version 5.1
# Every child is NativeProbe.exe, compiled below in a unique owned directory.
# Production scripts are parsed as data; only explicitly named definitions load.
# This suite qualifies prospective shared/V13 definitions and source identity.
# Historical replay is retained as immutable evidence, never executed or relabeled.
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$ReceiptDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/ps51')
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw 'Native Windows PowerShell 5.1 is required.'
}
$Rows = New-Object Collections.Generic.List[object]
function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    $Caught = $false
    try { & $Action | Out-Null }
    catch { if ($_.Exception.Message -notmatch $Pattern) { throw }; $Caught = $true }
    Assert-True $Caught ('Expected rejection: ' + $Pattern)
}
function Test-Case([string]$Name, [scriptblock]$Action) {
    try { & $Action; $Rows.Add([pscustomobject]@{name=$Name;passed=$true}); Write-Host ('PASS ' + $Name) }
    catch { $Rows.Add([pscustomobject]@{name=$Name;passed=$false;error=$_.Exception.Message}); Write-Host ('FAIL ' + $Name + ': ' + $_.Exception.Message) }
}
function Read-Definitions([string]$Path, [string[]]$Names) {
    $Bytes = [IO.File]::ReadAllBytes($Path)
    $Decoder = New-Object Text.UTF8Encoding($false, $true)
    $Source = $Decoder.GetString($Bytes).TrimStart([char]0xFEFF)
    $Tokens = $null; $Errors = $null
    $Ast = [Management.Automation.Language.Parser]::ParseInput($Source, [ref]$Tokens, [ref]$Errors)
    Assert-True (@($Errors).Count -eq 0) ('Parse failed: ' + $Path)
    $Definitions = @($Ast.FindAll({param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst]}, $false))
    $Text = @()
    foreach ($Name in $Names) {
        $Matches = @($Definitions | Where-Object Name -ceq $Name)
        Assert-True ($Matches.Count -eq 1) ('Definition count: ' + $Name)
        $Text += $Matches[0].Extent.Text
    }
    return $Text -join "`n"
}
$LibraryPath = Join-Path $RepositoryRoot 'tools/SZL_PS51_PROCESS_LIBRARY.ps1'
$LibraryDefinitions = Read-Definitions $LibraryPath @('ConvertTo-SzlNativeArgument','Get-SzlObservedExitCode','Initialize-SzlNativePipe','Invoke-SzlNativeProcess','Get-SzlRemainingMilliseconds','Get-SzlRemainingTimeoutSeconds','Resolve-SzlPinnedOperator','Assert-SzlOperatorAdmission')
. ([scriptblock]::Create($LibraryDefinitions))
$LauncherPath = Join-Path $RepositoryRoot 'tools/RUN_SZL_CTO_RATE_AWARE.ps1'
. ([scriptblock]::Create((Read-Definitions $LauncherPath @('Get-GitHubBudgetObservation','Wait-SzlGitHubBudget'))))
$V13Path = Join-Path $RepositoryRoot 'tools/SZL_DISK_CLEAN_RESUME_PS51_V13.ps1'
. ([scriptblock]::Create((Read-Definitions $V13Path @('Invoke-NativeTool','Find-Operator'))))
$V12Path = Join-Path $RepositoryRoot 'tools/SZL_PARALLEL_FRONTIER_COORDINATOR_PS51_V12_1.ps1'
. ([scriptblock]::Create((Read-Definitions $V12Path @('Get-ResumeOperator'))))
$Reference = Join-Path $RepositoryRoot 'tests/fixtures/ps51/operator-23b1aaab.ps1.txt'
$ExpectedHash = '23B1AAABEF7AED9C2801C975BEAD79AC16084432537CFF26059952208B3D687B'
Assert-True ((Get-FileHash -LiteralPath $Reference -Algorithm SHA256).Hash -ceq $ExpectedHash) 'Recovered source bytes changed'
$RecoveredPath = Join-Path $RepositoryRoot 'tools/SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_RECOVERED_1.ps1'
$ManifestPath = Join-Path $RepositoryRoot 'tools/ps51-recovered-source.lineage.json'
$Manifest = [IO.File]::ReadAllText($ManifestPath) | ConvertFrom-Json
$RecoveredHash = (Get-FileHash -LiteralPath $RecoveredPath).Hash.ToLowerInvariant()
Assert-True ($RecoveredHash -ceq $Manifest.candidate_sha256) 'Candidate and lineage differ'
$HistoricalReceiptPath = Join-Path $RepositoryRoot 'tests/fixtures/ps51/historical-replay-b1b1c5df.json'
$HistoricalReceiptHash = '1c4956b577bfc43e6e341551f1347b902f0c90d77b4063f86acfbf2c7c16efcb'
Assert-True ((Get-FileHash -LiteralPath $HistoricalReceiptPath).Hash.ToLowerInvariant() -ceq $HistoricalReceiptHash) 'Historical replay evidence changed'
$HistoricalReceipt = [IO.File]::ReadAllText($HistoricalReceiptPath) | ConvertFrom-Json
Assert-True ($HistoricalReceipt.passed -eq 63 -and $HistoricalReceipt.failed -eq 2 -and @($HistoricalReceipt.tests).Count -eq 65) 'Historical replay counts changed'
Assert-True (@($HistoricalReceipt.tests | Where-Object { $_.passed -isnot [bool] }).Count -eq 0) 'Historical replay verdict types changed'
$HistoricalFailures = @($HistoricalReceipt.tests | Where-Object { $_.passed -eq $false })
Assert-True ($HistoricalFailures.Count -eq 2 -and ($HistoricalFailures[0].name -ceq 'legacy empty argv') -and ($HistoricalFailures[1].name -ceq 'legacy concurrent stdout stderr')) 'Historical failures changed'
$WorkRoot = Join-Path $env:TEMP ('szl-ps51-contract-' + [Guid]::NewGuid().ToString('N'))
$RunRoot = $WorkRoot
$TempRoot = Join-Path $WorkRoot 'legacy-io'
$LogRoot = Join-Path $WorkRoot 'logs'
$EstateRoot = Join-Path $WorkRoot 'estate'
$RuntimeRoot = Join-Path $EstateRoot 'Runtime'
$SourceToolsRoot = Join-Path $WorkRoot 'source tools'
New-Item -ItemType Directory -Path $WorkRoot,$TempRoot,$LogRoot,$RuntimeRoot,$SourceToolsRoot -Force | Out-Null
# Only the two named selector definitions enter this owned inert fixture. Loading
# it gives their actual default PSScriptRoot binding a real adjacent directory.
$SelectorFixture = Join-Path $SourceToolsRoot 'named-selectors.ps1'
$SelectorDefinitions = (Read-Definitions $V13Path @('Find-Operator')) + "`n" + (Read-Definitions $V12Path @('Get-ResumeOperator'))
[IO.File]::WriteAllText($SelectorFixture, $SelectorDefinitions, (New-Object Text.UTF8Encoding($false)))
. $SelectorFixture
$Probe = Join-Path $WorkRoot 'Native Probe.exe'
$ProbeSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'tests/fixtures/ps51/NativeProbe.cs'))
Add-Type -TypeDefinition $ProbeSource -OutputAssembly $Probe -OutputType ConsoleApplication
function Invoke-Probe {
    param([ValidateSet('new','v13')][string]$Lane, [AllowEmptyCollection()][AllowEmptyString()][string[]]$Values = @(), [int]$Timeout = 5, [switch]$AllowNonZero)
    if ($Lane -eq 'v13') { return Invoke-NativeTool -FilePath $Probe -ArgumentList $Values -TimeoutSeconds $Timeout -AllowNonZero:$AllowNonZero }
    return Invoke-SzlNativeProcess -FilePath $Probe -ArgumentList $Values -WorkingDirectory $WorkRoot -TimeoutSeconds $Timeout -AllowNonZero:$AllowNonZero
}
function Assert-ArgumentEcho([string]$Raw, [AllowEmptyCollection()][AllowEmptyString()][string[]]$Expected) {
    $Lines = $Raw.Replace("`r`n", "`n").Split([char]10)
    Assert-True ($Lines[0] -ceq [string]$Expected.Count) 'Argument count changed'
    Assert-True ($Lines.Count -eq ($Expected.Count + 2)) 'Output shape changed'
    for ($Index = 0; $Index -lt $Expected.Count; $Index++) {
        $Actual = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Lines[$Index + 1]))
        Assert-True ([string]::Equals($Actual, $Expected[$Index], [StringComparison]::Ordinal)) ('Argument changed at ' + $Index)
    }
}
function Invoke-SyntheticBudgetCase([scriptblock]$Action) {
    # These added cases cannot reach a native process, network, log file or sleep.
    $Fixture = [pscustomobject]@{
        Clock=[pscustomobject]@{ElapsedMilliseconds=0L}; Replies=(New-Object Collections.Queue)
        Calls=(New-Object Collections.Generic.List[object]); Sleeps=(New-Object Collections.Generic.List[int])
        LogAdvance=0L; SleepAdjustment=0L; UtcNow=([datetime]'2020-01-01T00:00:00Z').ToUniversalTime()
    }
    function Invoke-SzlNativeProcess {
        param($FilePath,$ArgumentList,$WorkingDirectory,$TimeoutSeconds,[switch]$AllowNonZero)
        $Fixture.Calls.Add([pscustomobject]@{File=$FilePath;Arguments=$ArgumentList;Timeout=$TimeoutSeconds})
        if ($Fixture.Replies.Count -eq 0) { throw 'UNEXPECTED_SYNTHETIC_PROBE' }
        $Reply=$Fixture.Replies.Dequeue(); $Fixture.Clock.ElapsedMilliseconds += $Reply.Advance
        if ($Reply.Throw) { throw 'SYNTHETIC_NATIVE_FAILURE' }
        return [pscustomobject]@{ExitCode=$Reply.Exit;Stdout=$Reply.Text;Stderr=''}
    }
    function Start-Sleep { param([int]$Milliseconds); $Fixture.Sleeps.Add($Milliseconds); $Fixture.Clock.ElapsedMilliseconds += $Milliseconds+$Fixture.SleepAdjustment }
    function Write-RunLog { param($Message,$Level); $Fixture.Clock.ElapsedMilliseconds += $Fixture.LogAdvance }
    function Get-Date { return $Fixture.UtcNow }
    & $Action $Fixture
}
function Add-SyntheticBudgetReply {
    param($Fixture,[AllowNull()]$Exit=0,[string]$Text="HTTP/2.0 200 OK`nX-Ratelimit-Remaining: 2000`nX-Ratelimit-Reset: 0",[long]$Advance=0,[switch]$Throw)
    $Fixture.Replies.Enqueue([pscustomobject]@{Exit=$Exit;Text=$Text;Advance=$Advance;Throw=[bool]$Throw})
}
try {
    Test-Case 'budget timeout uses cap and floors remaining seconds' {
        Assert-True ((Get-SzlRemainingTimeoutSeconds -BudgetSeconds 30 -ElapsedMilliseconds 2501 -OperationTimeoutSeconds 10) -eq 10) 'CAP_CHANGED'
        Assert-True ((Get-SzlRemainingTimeoutSeconds -BudgetSeconds 5 -ElapsedMilliseconds 2501 -OperationTimeoutSeconds 10) -eq 2) 'REMAINDER_ROUNDED_UP'
    }
    Test-Case 'budget refuses subsecond exact and exceeded expiry before launch' {
        foreach($Elapsed in @(1,1000,1001)) { Assert-Throws { Get-SzlRemainingTimeoutSeconds -BudgetSeconds 1 -ElapsedMilliseconds $Elapsed -OperationTimeoutSeconds 5 } 'SZL_DEADLINE_EXPIRED' }
    }
    Test-Case 'budget rejects negative and nonfinite elapsed observations' {
        foreach($Elapsed in @(-1,[double]::NaN,[double]::PositiveInfinity,[double]::NegativeInfinity)) { Assert-Throws { Get-SzlRemainingMilliseconds -BudgetSeconds 5 -ElapsedMilliseconds $Elapsed } 'SZL_DEADLINE_OBSERVATION_INVALID' }
    }
    Test-Case 'budget millisecond remainder never rounds upward' {
        Assert-True ((Get-SzlRemainingMilliseconds -BudgetSeconds 5 -ElapsedMilliseconds 3500.1) -eq 1499) 'MILLISECOND_REMAINDER_CHANGED'
        Assert-Throws { Get-SzlRemainingMilliseconds -BudgetSeconds 5 -ElapsedMilliseconds 5000 } 'SZL_DEADLINE_EXPIRED'
    }
    Test-Case 'synthetic GitHub probe binds argv and remaining timeout' {
        Invoke-SyntheticBudgetCase { param($F)
            $F.Clock.ElapsedMilliseconds=2501; Add-SyntheticBudgetReply $F
            $R=Get-GitHubBudgetObservation -Clock $F.Clock -BudgetSeconds 5 -ProbeTimeoutSeconds 9
            Assert-True ($R.Status -eq 200 -and $R.Remaining -eq 2000 -and $F.Calls.Count -eq 1 -and $F.Calls[0].Timeout -eq 2) 'PROBE_BUDGET_OR_RESULT'
            Assert-True ($F.Calls[0].File -ceq 'gh.exe' -and ($F.Calls[0].Arguments -join '|') -ceq 'api|--include|users/szl-holdings/repos?type=all&sort=full_name&per_page=1') 'PROBE_ARGV'
        }
    }
    Test-Case 'synthetic GitHub nonzero and unavailable exits cannot become ready' {
        foreach($Exit in @(7,$null,'0',$false)) {
            Invoke-SyntheticBudgetCase { param($F)
                Add-SyntheticBudgetReply $F -Exit $Exit
                $R=Get-GitHubBudgetObservation -Clock $F.Clock
                Assert-True ($R.Status -eq 0 -and $R.Remaining -eq -1 -and $F.Calls.Count -eq 1) 'UNAVAILABLE_EXIT_ACCEPTED'
            }
        }
    }
    Test-Case 'synthetic GitHub malformed observations cannot become ready' {
        foreach($Text in @('',"HTTP/2.0 200 OK`nX-Ratelimit-Reset: 0","HTTP/2.0 200 OK`nX-Ratelimit-Remaining: 2000","HTTP/2.0 200 OK`nX-Ratelimit-Remaining: 999999999999999999999`nX-Ratelimit-Reset: 0","HTTP/2.0 200 OK`nX-Ratelimit-Remaining: 2000`nX-Ratelimit-Reset: invalid")) {
            Invoke-SyntheticBudgetCase { param($F)
                Add-SyntheticBudgetReply $F -Text $Text
                $R=Get-GitHubBudgetObservation -Clock $F.Clock
                Assert-True ($R.Status -eq 0 -and $R.Remaining -eq -1) 'MALFORMED_OBSERVATION_ACCEPTED'
            }
        }
    }
    Test-Case 'synthetic GitHub native failure stays unavailable' {
        Invoke-SyntheticBudgetCase { param($F)
            Add-SyntheticBudgetReply $F -Throw
            $R=Get-GitHubBudgetObservation -Clock $F.Clock
            Assert-True ($R.Status -eq 0 -and $F.Calls.Count -eq 1) 'FAILED_PROBE_ACCEPTED'
        }
    }
    Test-Case 'synthetic GitHub completed probe cannot pass after expiry' {
        Invoke-SyntheticBudgetCase { param($F)
            Add-SyntheticBudgetReply $F -Advance 5000
            Assert-Throws { Get-GitHubBudgetObservation -Clock $F.Clock -BudgetSeconds 5 } 'SZL_DEADLINE_EXPIRED'
            Assert-True ($F.Calls.Count -eq 1) 'PROBE_RETRIED_AFTER_EXPIRY'
        }
    }
    Test-Case 'synthetic GitHub subsecond remainder launches nothing' {
        Invoke-SyntheticBudgetCase { param($F)
            $F.Clock.ElapsedMilliseconds=4001
            Assert-Throws { Get-GitHubBudgetObservation -Clock $F.Clock -BudgetSeconds 5 } 'SZL_DEADLINE_EXPIRED'
            Assert-True ($F.Calls.Count -eq 0) 'SUBSECOND_PROBE_LAUNCHED'
        }
    }
    Test-Case 'synthetic ready budget returns once without a second probe or sleep' {
        Invoke-SyntheticBudgetCase { param($F)
            Add-SyntheticBudgetReply $F
            $R=Wait-SzlGitHubBudget -Clock $F.Clock
            Assert-True ($R.Status -eq 200 -and $F.Calls.Count -eq 1 -and $F.Sleeps.Count -eq 0) 'READY_PROBED_AGAIN'
            Assert-Throws { Assert-SzlOperatorAdmission $R } 'SZL_SOURCE_ADMISSION_HOLD'
        }
    }
    Test-Case 'synthetic budget loop reuses clock and decreases next probe timeout' {
        Invoke-SyntheticBudgetCase { param($F)
            Add-SyntheticBudgetReply $F -Text "HTTP/2.0 200 OK`nX-Ratelimit-Remaining: 1`nX-Ratelimit-Reset: 0" -Advance 1500
            Add-SyntheticBudgetReply $F
            $R=Wait-SzlGitHubBudget -Clock $F.Clock -BudgetSeconds 300 -ProbeTimeoutSeconds 300
            Assert-True ($R.Remaining -eq 2000 -and $F.Calls.Count -eq 2 -and $F.Calls[0].Timeout -eq 300 -and $F.Calls[1].Timeout -eq 178 -and $F.Sleeps[0] -eq 120000) 'AGGREGATE_CLOCK_RESET'
        }
    }
    Test-Case 'synthetic budget sleep clamps and expiry permits no further probe' {
        Invoke-SyntheticBudgetCase { param($F)
            Add-SyntheticBudgetReply $F -Exit 1 -Advance 1250
            Assert-Throws { Wait-SzlGitHubBudget -Clock $F.Clock -BudgetSeconds 5 } 'SZL_DEADLINE_EXPIRED'
            Assert-True ($F.Calls.Count -eq 1 -and $F.Sleeps.Count -eq 1 -and $F.Sleeps[0] -eq 3750) 'SLEEP_OR_POST_DEADLINE_PROBE'
        }
    }
    Test-Case 'synthetic sleep boundary refuses a final subsecond probe' {
        Invoke-SyntheticBudgetCase { param($F)
            $F.SleepAdjustment=-1; Add-SyntheticBudgetReply $F -Exit 1
            Assert-Throws { Wait-SzlGitHubBudget -Clock $F.Clock -BudgetSeconds 5 } 'SZL_DEADLINE_EXPIRED'
            Assert-True ($F.Calls.Count -eq 1 -and $F.Clock.ElapsedMilliseconds -eq 4999) 'SUBSECOND_LOOP_PROBE'
        }
    }
    Test-Case 'synthetic logging delay cannot return a stale ready observation' {
        Invoke-SyntheticBudgetCase { param($F)
            $F.LogAdvance=4000; Add-SyntheticBudgetReply $F -Advance 1000
            Assert-Throws { Wait-SzlGitHubBudget -Clock $F.Clock -BudgetSeconds 5 } 'SZL_DEADLINE_EXPIRED'
            Assert-True ($F.Calls.Count -eq 1 -and $F.Sleeps.Count -eq 0) 'STALE_READY_OBSERVATION'
        }
    }
    Test-Case 'synthetic reset waits retain wall-clock clamps within monotonic budget' {
        foreach($Vector in @(@{Reset=1577836801L;Expected=30000},@{Reset=1577936799L;Expected=3600000})) {
            Invoke-SyntheticBudgetCase { param($F)
                Add-SyntheticBudgetReply $F -Text ("HTTP/2.0 200 OK`nX-Ratelimit-Remaining: 1`nX-Ratelimit-Reset: "+$Vector.Reset)
                Add-SyntheticBudgetReply $F
                $null=Wait-SzlGitHubBudget -Clock $F.Clock -BudgetSeconds 4000
                Assert-True ($F.Sleeps.Count -eq 1 -and $F.Sleeps[0] -eq $Vector.Expected -and $F.Calls.Count -eq 2) 'RESET_WAIT_CLAMP'
            }
        }
    }
    Test-Case 'fixture reference parses without running main' { Assert-True ($ExpectedHash -ceq (Get-FileHash -LiteralPath $Reference).Hash) 'Reference changed'; Read-Definitions $Reference @('Invoke-Native') | Out-Null }
    $Candidate = Join-Path $SourceToolsRoot 'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_RECOVERED_1.ps1'
    $OldCandidate = Join-Path $SourceToolsRoot 'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_HF_PREFLIGHT_ROBUST.ps1'
    [IO.File]::WriteAllText($OldCandidate, 'throw "OLD_HELPER_MAIN_MUST_NOT_RUN"')
    Copy-Item -LiteralPath $Reference -Destination (Join-Path $RuntimeRoot 'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_PS51_JSON.ps1')
    Test-Case 'missing recovered candidate rejects historical and older fallback' { Assert-Throws { Find-Operator } 'OPERATOR_IDENTITY_MISSING'; Assert-Throws { Get-ResumeOperator } 'OPERATOR_IDENTITY_MISSING' }
    [IO.File]::WriteAllText($Candidate, 'throw "WRONG_HELPER_MAIN_MUST_NOT_RUN"')
    Test-Case 'wrong helper refuses timestamp fallback' { Assert-Throws { Find-Operator } 'OPERATOR_IDENTITY_MISMATCH'; Assert-Throws { Get-ResumeOperator } 'OPERATOR_IDENTITY_MISMATCH' }
    Copy-Item -LiteralPath $RecoveredPath -Destination $Candidate -Force
    (Get-Item -LiteralPath $OldCandidate).LastWriteTimeUtc = [DateTime]::UtcNow.AddYears(1)
    Test-Case 'both selector defaults bind adjacent recovered identity without authority' {
        # Hosted Windows TEMP may use an 8.3 alias (RUNNER~1). Compare with
        # the filesystem's full name for this exact fixture, not its input alias.
        $ExpectedPath = (Get-Item -LiteralPath $Candidate -ErrorAction Stop).FullName
        $V13Selected = Find-Operator
        $V12Selected = Get-ResumeOperator
        Write-Host ('Fixture input path: {0}; filesystem path: {1}' -f $Candidate, $ExpectedPath)
        foreach ($Selected in @($V13Selected,$V12Selected)) {
            Assert-True ($Selected -isnot [string] -and $Selected.Path -ceq $ExpectedPath) 'Wrong recovered descriptor path'
            Assert-True ($Selected.SHA256 -ceq $RecoveredHash -and $Selected.Bytes -eq $Manifest.candidate_bytes -and $Selected.Version -ceq $Manifest.candidate_version) 'Wrong recovered identity'
            Assert-True ($Selected.HistoricalAdmission -ceq 'UNKNOWN' -and $Selected.ProspectiveAdmission -ceq 'BLOCKED' -and $Selected.RuntimeAdmission -ceq 'BLOCKED') 'Admission promoted'
            Assert-True ($Selected.CanInvoke -is [bool] -and $Selected.CanInvoke -eq $false) 'Invocation authority granted'
            Assert-True ((@($Selected.PSObject.Properties.Name) -join ',') -ceq 'Path,SHA256,Bytes,Version,HistoricalAdmission,ProspectiveAdmission,RuntimeAdmission,CanInvoke') 'Descriptor contract changed'
        }
    }
    [IO.File]::AppendAllText($Candidate, "`n# changed bytes")
    Test-Case 'post-selection change is refused on recheck' { Assert-Throws { Find-Operator } 'OPERATOR_IDENTITY_MISMATCH' }
    Copy-Item -LiteralPath $RecoveredPath -Destination $Candidate -Force
    Test-Case 'same-length byte change is refused' {
        try { $Changed=[IO.File]::ReadAllBytes($Candidate); $Changed[100]=$Changed[100] -bxor 1; [IO.File]::WriteAllBytes($Candidate,$Changed); Assert-Throws { Find-Operator } 'OPERATOR_IDENTITY_MISMATCH' }
        finally { Copy-Item -LiteralPath $RecoveredPath -Destination $Candidate -Force }
    }
    Test-Case 'malformed candidate is refused without fallback' {
        try { [IO.File]::WriteAllText($Candidate,'function {'); Assert-Throws { Get-ResumeOperator } 'OPERATOR_IDENTITY_MISMATCH' }
        finally { Copy-Item -LiteralPath $RecoveredPath -Destination $Candidate -Force }
    }
    Test-Case 'relative traversal wildcard and stream roots rejected' {
        foreach ($Root in @('relative',($SourceToolsRoot+'\..'),($SourceToolsRoot+'\.'),($SourceToolsRoot+'\.. '),($SourceToolsRoot+'\trailing.'),($SourceToolsRoot+'\*'),($SourceToolsRoot+':stream'))) {
            Assert-Throws { Resolve-SzlPinnedOperator -SourceRoot $Root } 'OPERATOR_SOURCE_ROOT_INVALID'
        }
    }
    Test-Case 'ordinary file cannot be a source root' { Assert-Throws { Resolve-SzlPinnedOperator -SourceRoot $Candidate } 'OPERATOR_SOURCE_ROOT_INVALID' }
    Test-Case 'foreign empty root has no timestamp or installed fallback' { Assert-Throws { Resolve-SzlPinnedOperator -SourceRoot $TempRoot } 'OPERATOR_IDENTITY_MISSING' }
    Test-Case 'source metadata read error fails closed' {
        function Get-Item { param($LiteralPath,[switch]$Force,$ErrorAction) throw 'SYNTHETIC_SOURCE_READ_FAILURE' }
        Assert-Throws { Find-Operator } 'SYNTHETIC_SOURCE_READ_FAILURE'
    }
    Test-Case 'source root junction rejected' {
        $Link=Join-Path $WorkRoot 'linked tools'
        New-Item -ItemType Junction -Path $Link -Value $SourceToolsRoot -ErrorAction Stop | Out-Null
        Assert-Throws { Resolve-SzlPinnedOperator -SourceRoot $Link } 'OPERATOR_REPARSE_POINT_REJECTED'
    }
    Test-Case 'ancestor junction rejected' {
        $Container=Join-Path $WorkRoot 'plain ancestor'; $Child=Join-Path $Container 'tools'
        New-Item -ItemType Directory -Path $Child -Force | Out-Null
        Copy-Item -LiteralPath $RecoveredPath -Destination (Join-Path $Child (Split-Path -Leaf $Candidate))
        $Link=Join-Path $WorkRoot 'linked ancestor'
        New-Item -ItemType Junction -Path $Link -Value $Container -ErrorAction Stop | Out-Null
        Assert-Throws { Resolve-SzlPinnedOperator -SourceRoot (Join-Path $Link 'tools') } 'OPERATOR_REPARSE_POINT_REJECTED'
    }
    Test-Case 'candidate leaf junction rejected' {
        $LeafRoot=Join-Path $WorkRoot 'leaf fixture'; New-Item -ItemType Directory -Path $LeafRoot | Out-Null
        New-Item -ItemType Junction -Path (Join-Path $LeafRoot (Split-Path -Leaf $Candidate)) -Value $SourceToolsRoot -ErrorAction Stop | Out-Null
        Assert-Throws { Resolve-SzlPinnedOperator -SourceRoot $LeafRoot } 'OPERATOR_REPARSE_POINT_REJECTED'
    }
    Test-Case 'genuine descriptor never admits execution' { Assert-Throws { Assert-SzlOperatorAdmission -Identity (Find-Operator) } 'SZL_SOURCE_ADMISSION_HOLD' }
    Test-Case 'adjacent forged admission manifest cannot grant authority' {
        [IO.File]::WriteAllText((Join-Path $SourceToolsRoot 'ps51-recovered-source.lineage.json'),'{"recovered_source_admission":"ADMITTED","selection":{"can_invoke":true,"runtime_admission":"ADMITTED"}}')
        $Identity=Find-Operator
        Assert-True ($Identity.CanInvoke -eq $false -and $Identity.RuntimeAdmission -ceq 'BLOCKED') 'Manifest granted authority'
        Assert-Throws { Assert-SzlOperatorAdmission -Identity $Identity } 'SZL_SOURCE_ADMISSION_HOLD'
    }
    Test-Case 'forged approval flags and null descriptor never admit execution' {
        $Forged=[pscustomobject]@{Path=$Candidate;SHA256=$RecoveredHash;CanInvoke=$true;ProspectiveAdmission='ADMITTED';RuntimeAdmission='ADMITTED';Force=$true;Environment=@{SZL_APPLY='1';SZL_CONFIRM='approved'}}
        Assert-Throws { Assert-SzlOperatorAdmission -Identity $Forged } 'SZL_SOURCE_ADMISSION_HOLD'
        Assert-Throws { Assert-SzlOperatorAdmission -Identity $null } 'SZL_SOURCE_ADMISSION_HOLD'
    }
    Test-Case 'launcher uses adjacent identity and no historical pin or invocation' {
        $Source = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'tools/RUN_SZL_CTO_RATE_AWARE.ps1'))
        Assert-True (-not $Source.Contains('c6ea52536a3a5c0562a8deb16de5a7db023bed802dff1029944317f12d1cda78')) 'Stale launcher pin'
        Assert-True (-not $Source.Contains($ExpectedHash.ToLowerInvariant())) 'Historical launcher identity'
        Assert-True ($Source.Contains('Resolve-SzlPinnedOperator -SourceRoot $PSScriptRoot')) 'Missing adjacent identity'
        Assert-True ($Source.Contains('Assert-SzlOperatorAdmission -Identity $OperatorIdentity')) 'Missing inactive admission'
        Assert-True ($Source -notmatch '(?m)^\s*&\s*\$Operator') 'Operator invocation remains'
    }
    Test-Case 'unavailable exit is not cast to zero' { Assert-Throws { Get-SzlObservedExitCode ([pscustomobject]@{ExitCode=$null}) } 'NATIVE_EXIT_UNAVAILABLE' }
    Test-Case 'non-native exit values rejected' { foreach ($Value in @('0',$false)) { Assert-Throws { Get-SzlObservedExitCode ([pscustomobject]@{ExitCode=$Value}) } 'NATIVE_EXIT_UNAVAILABLE' } }
    Test-Case 'throwing exit getter rejected' {
        $Unavailable = New-Object PSObject
        $Unavailable | Add-Member ScriptProperty ExitCode { throw 'lost handle' }
        Assert-Throws { Get-SzlObservedExitCode $Unavailable } 'NATIVE_EXIT_UNAVAILABLE'
    }
    Test-Case 'native invocation propagates unavailable exit even AllowNonZero' {
        $Original = (Get-Command Get-SzlObservedExitCode).ScriptBlock
        try {
            Set-Item Function:Get-SzlObservedExitCode { param($Process) throw 'NATIVE_EXIT_UNAVAILABLE' }
            Assert-Throws { Invoke-Probe 'new' @('exit7') -AllowNonZero } 'NATIVE_EXIT_UNAVAILABLE'
        }
        finally { Set-Item Function:Get-SzlObservedExitCode $Original }
    }
    $Unicode = ([char]0x03BB).ToString() + [char]0x4E16 + [char]0x754C
    $Vectors = @(
        [pscustomobject]@{name='zero';values=[string[]]@()},
        [pscustomobject]@{name='empty';values=[string[]]@('')},
        [pscustomobject]@{name='adjacent-empty';values=[string[]]@('','','tail')},
        [pscustomobject]@{name='spaces-tabs';values=[string[]]@('two words',' ',"a`tb")},
        [pscustomobject]@{name='unicode-spaces';values=[string[]]@($Unicode,('two ' + $Unicode))},
        [pscustomobject]@{name='quotes';values=[string[]]@('a"b','"','a""b')},
        [pscustomobject]@{name='trailing-slashes';values=[string[]]@('C:\directory with spaces\','C:\two words\\')},
        [pscustomobject]@{name='slash-quotes';values=[string[]]@('one\"two','one\\"two','\\"')},
        [pscustomobject]@{name='literal-shell';values=[string[]]@('$HOME','$(not-executed)','%PATH%','a&b|c>d','`')},
        [pscustomobject]@{name='newlines';values=[string[]]@("line1`nline2","line1`r`nline2")},
        [pscustomobject]@{name='mixed';values=[string[]]@('',$Unicode,'C:\a b\','a"b','tail')}
    )
    foreach ($Lane in @('new','v13')) {
        Test-Case "$Lane empty argv" { $Result = Invoke-Probe $Lane; Assert-True ($Result.ExitCode -eq 0 -and $Result.Stdout.Trim() -ceq 'NO_ARGUMENTS') 'No-argument invocation changed' }
        Test-Case "$Lane exit7 retained with both streams" { $Result = Invoke-Probe $Lane @('exit7') -AllowNonZero; Assert-True ($Result.ExitCode -eq 7 -and $Result.Stdout -ceq 'out-seven' -and $Result.Stderr -ceq 'err-seven') 'Exit or streams changed' }
        Test-Case "$Lane exit7 throws by default" { Assert-Throws { Invoke-Probe $Lane @('exit7') } 'exit (code )?7' }
        Test-Case "$Lane timeout bounded" { $Clock = [Diagnostics.Stopwatch]::StartNew(); Assert-Throws { Invoke-Probe $Lane @('sleep') -Timeout 1 -AllowNonZero } '(timed out|NATIVE_TIMEOUT)'; Assert-True ($Clock.Elapsed.TotalSeconds -lt 5) 'Timeout cleanup exceeded bound' }
        Test-Case "$Lane concurrent stdout stderr" { $Result = Invoke-Probe $Lane @('pipes'); Assert-True ($Result.Stdout.Length -eq 100000 -and $Result.Stderr.Length -eq 100000) 'Pipe output truncated' }
        foreach ($Vector in $Vectors) {
            Test-Case "$Lane argv $($Vector.name)" { $Result = Invoke-Probe $Lane ([string[]](@('argv') + @($Vector.values))); Assert-ArgumentEcho $Result.Stdout $Vector.values }
        }
        Test-Case "$Lane 20 rapid exits preserve 7" { for ($Attempt=0; $Attempt -lt 20; $Attempt++) { $Result = Invoke-Probe $Lane @('exit7') -AllowNonZero; Assert-True ($Result.ExitCode -eq 7) ('Rapid exit changed at ' + $Attempt) } }
    }
    Test-Case 'new Unicode output on both streams' { $Result = Invoke-Probe 'new' @('unicode'); Assert-True ($Result.Stdout -ceq $Unicode) 'Unicode stdout changed'; Assert-True ($Result.Stderr -ceq (([char]0x03B4).ToString() + [char]0x4E16 + [char]0x754C)) 'Unicode stderr changed' }
    Test-Case 'zero timeout rejected before launch' { Assert-Throws { Invoke-Probe 'new' @('sleep') -Timeout 0 } 'range|ValidateRange|greater' }
    Test-Case 'argument assertion rejects altered content' { Assert-Throws { Assert-ArgumentEcho "1`nYg==`n" @('a') } 'Argument changed' }
    Test-Case 'argument assertion rejects missing empty element' { Assert-Throws { Assert-ArgumentEcho "0`n" @('') } 'Argument count changed' }
}
finally {
    # Preserve this small owned fixture/evidence directory for diagnosis. Nothing
    # in production TEMP, operator roots, schedules, or source is cleaned here.
    $Failed = @($Rows | Where-Object { -not $_.passed }).Count
    $Receipt = [ordered]@{
        schema='szl.ps51-process-contracts/v1';powershell=$PSVersionTable.PSVersion.ToString()
        reference_sha256=$ExpectedHash.ToLowerInvariant();harness_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
        passed=$Rows.Count-$Failed;failed=$Failed;tests=$Rows.ToArray();fixture_class='SIMULATED'
        controller_main_executed=$false;production_subprocesses_executed=$false;work_root=$WorkRoot
    }
    $ReceiptPath = Join-Path $WorkRoot 'RESULTS.json'
    [IO.File]::WriteAllText($ReceiptPath, ($Receipt | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    # Publish only the fixture verdicts and source identifiers, never raw command
    # output, exception text, local paths, arguments, credentials, or environment.
    New-Item -ItemType Directory -Path $ReceiptDirectory -Force | Out-Null
    $PublicReceipt = [ordered]@{
        schema='szl.ps51-inert-ci/v1';suite='prospective-shared-and-v13';fixture_class='SIMULATED'
        qualification_scope='named-prospective-definitions-source-identity-and-synthetic-budget-contracts'
        powershell=$Receipt.powershell;reference_sha256=$Receipt.reference_sha256;harness_sha256=$Receipt.harness_sha256
        source_sha256=[ordered]@{
            shared=(Get-FileHash -LiteralPath $LibraryPath).Hash.ToLowerInvariant()
            v13=(Get-FileHash -LiteralPath $V13Path).Hash.ToLowerInvariant()
            v12_selectors=(Get-FileHash -LiteralPath $V12Path).Hash.ToLowerInvariant()
            launcher_inert_budget_and_identity=(Get-FileHash -LiteralPath $LauncherPath).Hash.ToLowerInvariant()
            recovered_candidate=$RecoveredHash
            lineage=(Get-FileHash -LiteralPath $ManifestPath).Hash.ToLowerInvariant()
        }
        historical_replay_sha256=$HistoricalReceiptHash;historical_definitions_executed=$false;runtime_admission='BLOCKED'
        passed=$Receipt.passed;failed=$Failed;tests=@($Rows | Select-Object name,passed)
        controller_main_executed=$false;production_subprocesses_executed=$false
    }
    [IO.File]::WriteAllText((Join-Path $ReceiptDirectory 'process-contracts.json'), ($PublicReceipt | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    # Preserve the original mixed-suite receipt byte for byte, including its two
    # false historical rows. This copy is archived evidence, not a current replay.
    Copy-Item -LiteralPath $HistoricalReceiptPath -Destination (Join-Path $ReceiptDirectory 'historical-replay-b1b1c5df.json')
    Write-Host 'Archived historical replay: 63 passed; 2 failed. Historical/runtime admission remains BLOCKED.'
    Write-Host ('Receipt: ' + $ReceiptPath)
    Write-Host ('Passed: {0}; failed: {1}' -f $Receipt.passed, $Failed)
}
if ($Failed -ne 0) { throw 'PS51_PROCESS_CONTRACT_FAILURE' }
