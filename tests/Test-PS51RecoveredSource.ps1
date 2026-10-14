#requires -version 5.1
# Reads source as data; executes only the named inert definitions and owned probe.
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$ReceiptDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/ps51')
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) { throw 'Native Windows PowerShell 5.1 required' }
$Rows = New-Object Collections.Generic.List[object]
function Assert-True([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action,[string]$Pattern) {
    $Caught=$false
    try { & $Action | Out-Null } catch { if ($_.Exception.Message -notmatch $Pattern) { throw }; $Caught=$true }
    Assert-True $Caught ('Expected rejection: '+$Pattern)
}
function Test-Case([string]$Name,[scriptblock]$Action) {
    try { & $Action; $Rows.Add([pscustomobject]@{name=$Name;passed=$true}); Write-Host ('PASS '+$Name) }
    catch { $Rows.Add([pscustomobject]@{name=$Name;passed=$false}); Write-Host ('FAIL '+$Name+': '+$_.Exception.Message) }
}
function Hash-Bytes([byte[]]$Bytes) {
    $Hasher=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($Hasher.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant() }
    finally { $Hasher.Dispose() }
}
function Slice-Bytes([byte[]]$Bytes,[int]$Start,[int]$Length) {
    if ($Start -lt 0 -or $Length -lt 0 -or [long]$Start+$Length -gt $Bytes.Length) { throw 'LINEAGE_RANGE' }
    $Result=New-Object byte[] $Length
    [Array]::Copy($Bytes,$Start,$Result,0,$Length)
    return ,$Result
}
function Assert-Lineage([byte[]]$Base,[byte[]]$Candidate,$Manifest) {
    Assert-True ((Hash-Bytes $Base) -ceq '23b1aaabef7aed9c2801c975bead79ac16084432537cff26059952208b3d687b') 'LINEAGE_BASE_HASH'
    Assert-True ($Base.Length -eq $Manifest.base_bytes -and (Hash-Bytes $Base) -ceq $Manifest.base_sha256) 'LINEAGE_BASE_METADATA'
    Assert-True ($Candidate.Length -eq $Manifest.candidate_bytes -and (Hash-Bytes $Candidate) -ceq $Manifest.candidate_sha256) 'LINEAGE_CANDIDATE_HASH'
    $OldCursor=0; $NewCursor=0
    foreach ($Region in $Manifest.regions) {
        $OldGap=Slice-Bytes $Base $OldCursor ($Region.old_start-$OldCursor)
        $NewGap=Slice-Bytes $Candidate $NewCursor ($Region.new_start-$NewCursor)
        Assert-True ((Hash-Bytes $OldGap) -ceq (Hash-Bytes $NewGap)) 'LINEAGE_UNDECLARED_CHANGE'
        Assert-True ((Hash-Bytes (Slice-Bytes $Base $Region.old_start $Region.old_length)) -ceq $Region.old_sha256) 'LINEAGE_OLD_REGION'
        Assert-True ((Hash-Bytes (Slice-Bytes $Candidate $Region.new_start $Region.new_length)) -ceq $Region.new_sha256) 'LINEAGE_NEW_REGION'
        $OldCursor=$Region.old_start+$Region.old_length; $NewCursor=$Region.new_start+$Region.new_length
    }
    Assert-True ((Hash-Bytes (Slice-Bytes $Base $OldCursor ($Base.Length-$OldCursor))) -ceq (Hash-Bytes (Slice-Bytes $Candidate $NewCursor ($Candidate.Length-$NewCursor)))) 'LINEAGE_UNDECLARED_TAIL'
}
function Parse-Source([string]$Source) {
    $Tokens=$null; $Errors=$null
    $Ast=[Management.Automation.Language.Parser]::ParseInput($Source,[ref]$Tokens,[ref]$Errors)
    Assert-True (@($Errors).Count -eq 0) 'SOURCE_PARSE_FAILED'
    return $Ast
}
function Get-Definition([string]$Source,[string]$Name) {
    $Ast=Parse-Source $Source
    $Nodes=@($Ast.FindAll({param($N) $N -is [Management.Automation.Language.FunctionDefinitionAst]},$false) | Where-Object Name -ceq $Name)
    Assert-True ($Nodes.Count -eq 1) ('DEFINITION_COUNT: '+$Name)
    return $Nodes[0].Extent.Text
}
function Assert-BoundedNative([string]$Source) {
    $Ast=Parse-Source $Source
    $Unbounded=@($Ast.FindAll({param($N) $N -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $N.Member.Value -eq 'WaitForExit' -and ($null -eq $N.Arguments -or $N.Arguments.Count -eq 0)},$true))
    Assert-True ($Unbounded.Count -eq 0) 'UNBOUNDED_NATIVE_WAIT'
}
function Embedded-Hash([string]$Source) {
    $Match=[regex]::Match($Source,'(?s)\$payloadBase64 = @''\r?\n(.*?)\r?\n''@')
    Assert-True $Match.Success 'EMBEDDED_PAYLOAD_MISSING'
    return Hash-Bytes ([Convert]::FromBase64String($Match.Groups[1].Value))
}
function Assert-InactiveEntry([string]$Text) {
    $Ast=Parse-Source ($Text.TrimStart([char]0xFEFF))
    Assert-True ($null -eq $Ast.ParamBlock -and $null -eq $Ast.BeginBlock -and $null -eq $Ast.ProcessBlock -and $null -eq $Ast.DynamicParamBlock) 'ENTRY_PRELUDE_REJECTED'
    Assert-True (@($Ast.UsingStatements).Count -eq 0) 'ENTRY_USING_REJECTED'
    if ($null -ne $Ast.ScriptRequirements) {
        Assert-True (@($Ast.ScriptRequirements.RequiredModules).Count -eq 0 -and @($Ast.ScriptRequirements.RequiredAssemblies).Count -eq 0) 'ENTRY_REQUIREMENT_LOAD_REJECTED'
    }
    Assert-True ($Text -notmatch '(?im)^\s*#requires\s+-PSSnapin\b') 'ENTRY_REQUIREMENT_LOAD_REJECTED'
    Assert-True ($null -ne $Ast.EndBlock -and $Ast.EndBlock.Statements.Count -gt 0) 'ENTRY_HOLD_MISSING'
    Assert-True ($null -eq $Ast.EndBlock.Traps -or $Ast.EndBlock.Traps.Count -eq 0) 'ENTRY_TRAP_REJECTED'
    $First=$Ast.EndBlock.Statements[0]
    Assert-True ($First -is [Management.Automation.Language.ThrowStatementAst] -and $First.Extent.Text -ceq "throw 'SZL_SOURCE_ADMISSION_HOLD'") 'ENTRY_HOLD_NOT_FIRST_LITERAL'
}
function Assert-NoOperatorInvocation([string]$Text) {
    $Ast=Parse-Source $Text
    $Calls=@($Ast.FindAll({param($N) $N -is [Management.Automation.Language.CommandAst] -and $N.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand -and $N.CommandElements[0].Extent.Text -match '^\$Operator(?:Path|Identity)?(?:\.|$)'},$true))
    Assert-True ($Calls.Count -eq 0) 'OPERATOR_INVOCATION_REJECTED'
}
$ManifestPath=Join-Path $RepositoryRoot 'tools/ps51-recovered-source.lineage.json'
$Manifest=[IO.File]::ReadAllText($ManifestPath) | ConvertFrom-Json
$Base=[IO.File]::ReadAllBytes((Join-Path $RepositoryRoot $Manifest.base_path))
$Candidate=[IO.File]::ReadAllBytes((Join-Path $RepositoryRoot $Manifest.candidate_path))
Assert-Lineage $Base $Candidate $Manifest
$Decoder=New-Object Text.UTF8Encoding($false,$true)
$Source=$Decoder.GetString($Candidate).TrimStart([char]0xFEFF)
$Library=[IO.File]::ReadAllText((Join-Path $RepositoryRoot $Manifest.library_path),$Decoder)
Assert-True ((Get-FileHash -LiteralPath (Join-Path $RepositoryRoot $Manifest.library_path)).Hash.ToLowerInvariant() -ceq $Manifest.library_sha256) 'LIBRARY_HASH_CHANGED'
$Names=@('Assert-SzlExecutionPolicy','ConvertTo-SzlNativeArgument','Get-SzlObservedExitCode','Initialize-SzlNativePipe','Invoke-SzlNativeProcess','Get-SzlRemainingMilliseconds','Get-SzlRemainingTimeoutSeconds','Resolve-PythonCommand','Invoke-Native','Redact-Text')
$Definitions=@($Names | ForEach-Object { Get-Definition $Source $_ }) -join "`n"
. ([scriptblock]::Create($Definitions))
$RunRoot=Join-Path $env:TEMP ('szl-v11-inert-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $RunRoot | Out-Null
$Probe=Join-Path $RunRoot 'Native Probe.exe'
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $RepositoryRoot 'tests/fixtures/ps51/NativeProbe.cs'))) -OutputAssembly $Probe -OutputType ConsoleApplication
function Invoke-Probe {
    param([AllowEmptyCollection()][AllowEmptyString()][string[]]$Values=@(),[int]$Timeout=5,[switch]$AllowNonZero,[switch]$Echo)
    return Invoke-Native -FilePath $Probe -ArgumentList $Values -WorkingDirectory $RunRoot -TimeoutSeconds $Timeout -AllowNonZero:$AllowNonZero -Echo:$Echo
}
function Assert-ArgumentEcho([string]$Raw,[AllowEmptyCollection()][AllowEmptyString()][string[]]$Expected) {
    $Lines=$Raw.Replace("`r`n","`n").Split([char]10)
    Assert-True ($Lines[0] -ceq [string]$Expected.Count -and $Lines.Count -eq $Expected.Count+2) 'Argument count changed'
    for ($I=0;$I -lt $Expected.Count;$I++) {
        $Actual=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Lines[$I+1]))
        Assert-True ([string]::Equals($Actual,$Expected[$I],[StringComparison]::Ordinal)) ('Argument changed at '+$I)
    }
}
function Invoke-SyntheticPythonCase([scriptblock]$Action) {
    # Registry/path discovery and every native probe are fixture stubs. No real
    # Python, auth, network, cleanup or controller entry point can be invoked.
    $Fixture=[pscustomobject]@{
        Clock=[pscustomobject]@{ElapsedMilliseconds=0L}; Replies=(New-Object Collections.Queue)
        Calls=(New-Object Collections.Generic.List[object]); Direct=@('C:\synthetic\python.exe'); Launchers=@()
    }
    function Test-Path { param($LiteralPath,$PathType); return ($LiteralPath -in @($Fixture.Direct+$Fixture.Launchers)) }
    function Get-Item { throw 'REGISTRY_READ_MUST_NOT_RUN' }
    function Get-Command {
        param($Name,[switch]$All,$ErrorAction)
        $Paths=if($Name -eq 'python.exe'){$Fixture.Direct}elseif($Name -eq 'py.exe'){$Fixture.Launchers}else{@()}
        foreach($Path in $Paths) { [pscustomobject]@{Source=$Path} }
    }
    function Invoke-SzlNativeProcess {
        param($FilePath,$ArgumentList,$WorkingDirectory,$TimeoutSeconds,[switch]$AllowNonZero,$Name)
        $Fixture.Calls.Add([pscustomobject]@{File=$FilePath;Arguments=$ArgumentList;Timeout=$TimeoutSeconds})
        if ($Fixture.Replies.Count -eq 0) { throw 'UNEXPECTED_SYNTHETIC_PYTHON_PROBE' }
        $Reply=$Fixture.Replies.Dequeue(); $Fixture.Clock.ElapsedMilliseconds += $Reply.Advance
        if ($Reply.Throw) { throw 'NATIVE_TIMEOUT' }
        return [pscustomobject]@{ExitCode=$Reply.Exit;Stdout='';Stderr=''}
    }
    & $Action $Fixture
}
function Add-SyntheticPythonReply {
    param($Fixture,[AllowNull()]$Exit=0,[long]$Advance=0,[switch]$Throw)
    $Fixture.Replies.Enqueue([pscustomobject]@{Exit=$Exit;Advance=$Advance;Throw=[bool]$Throw})
}
try {
    Test-Case 'synthetic Python direct probe preserves selection argv and cap' {
        Invoke-SyntheticPythonCase { param($F)
            Add-SyntheticPythonReply $F
            $R=Resolve-PythonCommand -Clock $F.Clock
            Assert-True ($R.File -ceq $F.Direct[0] -and $R.Prefix.Count -eq 0 -and $F.Calls.Count -eq 1 -and $F.Calls[0].Timeout -eq 5) 'DIRECT_SELECTION'
            Assert-True (($F.Calls[0].Arguments -join '|') -ceq '-c|import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 9)') 'DIRECT_ARGV'
        }
    }
    Test-Case 'synthetic Python launcher shares aggregate discovery budget' {
        Invoke-SyntheticPythonCase { param($F)
            $F.Launchers=@('C:\synthetic\py.exe'); Add-SyntheticPythonReply $F -Exit 9 -Advance 1100; Add-SyntheticPythonReply $F
            $R=Resolve-PythonCommand -Clock $F.Clock -ProbeTimeoutSeconds 40
            Assert-True ($R.File -ceq $F.Launchers[0] -and ($R.Prefix -join ',') -ceq '-3.12' -and $F.Calls.Count -eq 2 -and $F.Calls[0].Timeout -eq 30 -and $F.Calls[1].Timeout -eq 28) 'LAUNCHER_BUDGET_RESET'
            Assert-True (($F.Calls[1].Arguments -join '|') -ceq '-3.12|-c|import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 9)') 'LAUNCHER_ARGV'
        }
    }
    Test-Case 'synthetic Python consumed budget rejects next subsecond probe' {
        Invoke-SyntheticPythonCase { param($F)
            $F.Direct=@('C:\synthetic\first.exe','C:\synthetic\second.exe'); Add-SyntheticPythonReply $F -Exit 9 -Advance 2200
            Assert-Throws { Resolve-PythonCommand -Clock $F.Clock -DiscoveryTimeoutSeconds 3 } 'SZL_DEADLINE_EXPIRED'
            Assert-True ($F.Calls.Count -eq 1) 'SUBSECOND_SECOND_PROBE'
        }
    }
    Test-Case 'synthetic Python timeout can retry only within remaining budget' {
        Invoke-SyntheticPythonCase { param($F)
            $F.Direct=@('C:\synthetic\first.exe','C:\synthetic\second.exe'); Add-SyntheticPythonReply $F -Throw -Advance 1000; Add-SyntheticPythonReply $F
            $R=Resolve-PythonCommand -Clock $F.Clock -DiscoveryTimeoutSeconds 3 -ProbeTimeoutSeconds 2
            Assert-True ($R.File -ceq $F.Direct[1] -and $F.Calls.Count -eq 2 -and $F.Calls[0].Timeout -eq 2 -and $F.Calls[1].Timeout -eq 2) 'TIMEOUT_RETRY_BUDGET'
        }
    }
    Test-Case 'synthetic Python successful exit after expiry is rejected' {
        Invoke-SyntheticPythonCase { param($F)
            Add-SyntheticPythonReply $F -Advance 30000
            Assert-Throws { Resolve-PythonCommand -Clock $F.Clock } 'SZL_DEADLINE_EXPIRED'
            Assert-True ($F.Calls.Count -eq 1) 'EXPIRED_SUCCESS_ACCEPTED'
        }
    }
    Test-Case 'synthetic Python unavailable candidates retain expired budget' {
        Invoke-SyntheticPythonCase { param($F)
            $F.Direct=@(); $F.Clock.ElapsedMilliseconds=30000
            Assert-Throws { Resolve-PythonCommand -Clock $F.Clock } 'SZL_DEADLINE_EXPIRED'
            Assert-True ($F.Calls.Count -eq 0) 'MISSING_CANDIDATE_LAUNCHED'
        }
    }
    Test-Case 'synthetic Python nonzero and unavailable exits never select source' {
        foreach($Exit in @(9,$null,'0',$false)) {
            Invoke-SyntheticPythonCase { param($F)
                Add-SyntheticPythonReply $F -Exit $Exit
                Assert-Throws { Resolve-PythonCommand -Clock $F.Clock } 'Python 3.12\+ is unavailable'
                Assert-True ($F.Calls.Count -eq 1) 'INVALID_EXIT_SELECTED'
            }
        }
    }
    Test-Case 'synthetic Python first subsecond probe is never invoked' {
        Invoke-SyntheticPythonCase { param($F)
            $F.Clock.ElapsedMilliseconds=29501
            Assert-Throws { Resolve-PythonCommand -Clock $F.Clock } 'SZL_DEADLINE_EXPIRED'
            Assert-True ($F.Calls.Count -eq 0) 'FIRST_SUBSECOND_PROBE'
        }
    }
    Test-Case 'synthetic Python fractional remainder is floored before launch' {
        Invoke-SyntheticPythonCase { param($F)
            $F.Clock.ElapsedMilliseconds=1001; Add-SyntheticPythonReply $F
            $null=Resolve-PythonCommand -Clock $F.Clock -DiscoveryTimeoutSeconds 5 -ProbeTimeoutSeconds 9
            Assert-True ($F.Calls.Count -eq 1 -and $F.Calls[0].Timeout -eq 3) 'PYTHON_REMAINDER_ROUNDED_UP'
        }
    }
    Test-Case 'Python discovery uses monotonic clock and only bounded probe calls' {
        $Definition=Get-Definition $Source 'Resolve-PythonCommand'; $Ast=Parse-Source $Definition
        $Direct=@($Ast.FindAll({param($N) $N -is [Management.Automation.Language.CommandAst] -and $N.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand},$true))
        $Bounded=@($Ast.FindAll({param($N) $N -is [Management.Automation.Language.CommandAst] -and $N.GetCommandName() -ceq 'Invoke-SzlNativeProcess'},$true))
        Assert-True ($Direct.Count -eq 0 -and $Bounded.Count -eq 2 -and $Definition.Contains('[Diagnostics.Stopwatch]::StartNew()')) 'UNBOUNDED_DISCOVERY_PROBE'
    }
    Test-Case 'exact recovered lineage and unchanged payload' { Assert-Lineage $Base $Candidate $Manifest; Assert-True ((Embedded-Hash $Source) -ceq $Manifest.embedded_python_sha256) 'EMBEDDED_HASH' }
    Test-Case 'copied native definitions equal reviewed library' { foreach($Name in $Manifest.copied_definitions) { Assert-True ((Get-Definition $Source $Name) -ceq (Get-Definition $Library $Name)) ('Definition drift: '+$Name) } }
    Test-Case 'lineage declares prospective identity without admission' {
        Assert-True ($Manifest.original_admission -ceq 'UNKNOWN' -and $Manifest.recovered_source_admission -ceq 'BLOCKED') 'ADMISSION_PROMOTED'
        Assert-True ($Manifest.candidate_path -ceq 'tools/SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_RECOVERED_1.ps1' -and $Manifest.candidate_version -ceq '11.0.6-recovered-bounded.3') 'CANDIDATE_IDENTITY_CHANGED'
        Assert-True ($Manifest.selection.root -ceq 'repository-adjacent-tools' -and $Manifest.selection.historical_admission -ceq 'UNKNOWN' -and $Manifest.selection.prospective_admission -ceq 'BLOCKED' -and $Manifest.selection.runtime_admission -ceq 'BLOCKED' -and $Manifest.selection.can_invoke -is [bool] -and $Manifest.selection.can_invoke -eq $false -and $Manifest.selection.entry_hold -ceq 'SZL_SOURCE_ADMISSION_HOLD') 'SELECTION_ADMISSION_PROMOTED'
    }
    foreach($EntryPath in @($Manifest.candidate_path,'tools/SZL_DISK_CLEAN_RESUME_PS51_V13.ps1','tools/SZL_PARALLEL_FRONTIER_COORDINATOR_PS51_V12_1.ps1','tools/RUN_SZL_CTO_RATE_AWARE.ps1')) {
        $Entry=[IO.File]::ReadAllText((Join-Path $RepositoryRoot $EntryPath))
        Test-Case ('first executable statement holds '+(Split-Path -Leaf $EntryPath)) { Assert-InactiveEntry $Entry; Assert-NoOperatorInvocation $Entry }
        Test-Case ('removed guard rejected '+(Split-Path -Leaf $EntryPath)) { Assert-Throws { Assert-InactiveEntry ($Entry.Replace("throw 'SZL_SOURCE_ADMISSION_HOLD'",'# removed hold')) } 'ENTRY_HOLD_NOT_FIRST_LITERAL' }
    }
    Test-Case 'guard after a side effect is rejected without executing either' { Assert-Throws { Assert-InactiveEntry ("Write-Output 'SENTINEL_MUST_NOT_RUN'`n"+$Source.TrimStart([char]0xFEFF)) } 'ENTRY_HOLD_NOT_FIRST_LITERAL' }
    Test-Case 'guard in comment or conditional cannot admit entry' {
        Assert-Throws { Assert-InactiveEntry "# throw 'SZL_SOURCE_ADMISSION_HOLD'`nWrite-Output 'SENTINEL'" } 'ENTRY_HOLD_NOT_FIRST_LITERAL'
        Assert-Throws { Assert-InactiveEntry "if (`$env:SZL_APPLY -ne '1') { throw 'SZL_SOURCE_ADMISSION_HOLD' }" } 'ENTRY_HOLD_NOT_FIRST_LITERAL'
    }
    Test-Case 'trap cannot swallow the entry hold' { Assert-Throws { Assert-InactiveEntry "trap { continue }; throw 'SZL_SOURCE_ADMISSION_HOLD'" } 'ENTRY_TRAP_REJECTED' }
    Test-Case 'parameter default cannot run before the hold' { Assert-Throws { Assert-InactiveEntry "param(`$value=(Write-Output 'SENTINEL'))`nthrow 'SZL_SOURCE_ADMISSION_HOLD'" } 'ENTRY_PRELUDE_REJECTED' }
    Test-Case 'module requirement cannot load before the hold' { Assert-Throws { Assert-InactiveEntry "#requires -Modules SyntheticModuleMustNotLoad`nthrow 'SZL_SOURCE_ADMISSION_HOLD'" } 'ENTRY_REQUIREMENT_LOAD_REJECTED' }
    Test-Case 'operator invocation mutation rejected as data' { Assert-Throws { Assert-NoOperatorInvocation ($Source+"`n& `$OperatorIdentity.Path") } 'OPERATOR_INVOCATION_REJECTED' }
    Test-Case 'candidate mutation is rejected' { $Changed=[byte[]]$Candidate.Clone(); $Changed[100]=$Changed[100] -bxor 1; Assert-Throws { Assert-Lineage $Base $Changed $Manifest } 'LINEAGE_CANDIDATE_HASH' }
    Test-Case 'manifest region mutation is rejected' { $Changed=$Manifest | ConvertTo-Json -Depth 8 | ConvertFrom-Json; $Changed.regions[0].new_sha256='0'*64; Assert-Throws { Assert-Lineage $Base $Candidate $Changed } 'LINEAGE_NEW_REGION' }
    Test-Case 'undeclared byte mutation rejected even with updated candidate hash' { $Changed=[byte[]]$Candidate.Clone(); $Changed[100]=$Changed[100] -bxor 1; $M=$Manifest | ConvertTo-Json -Depth 8 | ConvertFrom-Json; $M.candidate_sha256=Hash-Bytes $Changed; Assert-Throws { Assert-Lineage $Base $Changed $M } 'LINEAGE_UNDECLARED_CHANGE' }
    Test-Case 'embedded mutation does not preserve payload identity' { $Changed=$Source.Replace('IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMw','IyEvdXNyL2Jpbi9lbnYgcHl0aG9uNA'); Assert-True ((Embedded-Hash $Changed) -cne $Manifest.embedded_python_sha256) 'EMBEDDED_NEGATIVE_CONTROL' }
    Test-Case 'no parameterless native wait remains' { Assert-BoundedNative $Source }
    Test-Case 'parameterless wait negative control rejected' { Assert-Throws { Assert-BoundedNative ($Source+"`n`$synthetic.WaitForExit()") } 'UNBOUNDED_NATIVE_WAIT' }
    Test-Case 'actual unchanged historical source rejected by bounded-wait validator' { Assert-Throws { Assert-BoundedNative ($Decoder.GetString($Base).TrimStart([char]0xFEFF)) } 'UNBOUNDED_NATIVE_WAIT' }
    Test-Case 'canonical executable sources have no policy setter or bypass launch' {
        foreach($Path in @($Manifest.candidate_path,'tools/SZL_DISK_CLEAN_RESUME_PS51_V13.ps1','tools/SZL_PARALLEL_FRONTIER_COORDINATOR_PS51_V12_1.ps1')) {
            $Text=[IO.File]::ReadAllText((Join-Path $RepositoryRoot $Path))
            Assert-True ($Text -notmatch '(?i)Set-ExecutionPolicy|-ExecutionPolicy\s+Bypass') 'POLICY_WEAKENING_SOURCE'
            Assert-True ($Text -match '(?m)^Assert-SzlExecutionPolicy\r?$') 'POLICY_PREFLIGHT_MISSING'
        }
    }
    Test-Case 'policy preflight allows permitted effective policies without mutations' {
        $script:PolicyMutations=0
        function Get-ExecutionPolicy { param($ErrorAction) return $script:ObservedPolicy }
        function Set-ExecutionPolicy { $script:PolicyMutations++; throw 'MUTATION_MUST_NOT_RUN' }
        foreach($script:ObservedPolicy in @('AllSigned','RemoteSigned','Unrestricted')) { Assert-SzlExecutionPolicy }
        Assert-True ($script:PolicyMutations -eq 0) 'POLICY_MUTATED'
    }
    Test-Case 'policy preflight holds restricted bypass and unknown without mutations' {
        $script:PolicyMutations=0
        function Get-ExecutionPolicy { param($ErrorAction) return $script:ObservedPolicy }
        function Set-ExecutionPolicy { $script:PolicyMutations++; throw 'MUTATION_MUST_NOT_RUN' }
        foreach($script:ObservedPolicy in @('Restricted','Bypass','Undefined','unknown','')) { Assert-Throws { Assert-SzlExecutionPolicy } 'EXECUTION_POLICY_HOLD' }
        Assert-True ($script:PolicyMutations -eq 0) 'POLICY_MUTATED'
    }
    Test-Case 'policy read failure holds' { function Get-ExecutionPolicy { param($ErrorAction) throw 'synthetic read failure' }; Assert-Throws { Assert-SzlExecutionPolicy } 'EXECUTION_POLICY_HOLD' }
    Test-Case 'unavailable and noninteger exit observations rejected' { foreach($Value in @($null,'0',$false)) { Assert-Throws { Get-SzlObservedExitCode ([pscustomobject]@{ExitCode=$Value}) } 'NATIVE_EXIT_UNAVAILABLE' } }
    Test-Case 'throwing exit observation rejected' { $P=New-Object PSObject; $P | Add-Member ScriptProperty ExitCode { throw 'synthetic unavailable' }; Assert-Throws { Get-SzlObservedExitCode $P } 'NATIVE_EXIT_UNAVAILABLE' }
    Test-Case 'V11 unavailable exit propagation even AllowNonZero' {
        $Original=(Get-Command Get-SzlObservedExitCode).ScriptBlock
        try { Set-Item Function:Get-SzlObservedExitCode { param($Process) throw 'NATIVE_EXIT_UNAVAILABLE' }; Assert-Throws { Invoke-Probe @('exit7') -AllowNonZero } 'NATIVE_EXIT_UNAVAILABLE' }
        finally { Set-Item Function:Get-SzlObservedExitCode $Original }
    }
    Test-Case 'V11 empty argv and legacy result shape' { $R=Invoke-Probe; Assert-True ($R.ExitCode -eq 0 -and $R.Stdout.Trim() -ceq 'NO_ARGUMENTS' -and $R.File -ceq $Probe) 'RESULT_SHAPE'; Assert-True ((@($R.PSObject.Properties.Name) -join ',') -ceq 'File,Arguments,ExitCode,Stdout,Stderr,Seconds') 'RESULT_FIELDS' }
    Test-Case 'V11 exit7 and streams retained' { $R=Invoke-Probe @('exit7') -AllowNonZero; Assert-True ($R.ExitCode -eq 7 -and $R.Stdout -ceq 'out-seven' -and $R.Stderr -ceq 'err-seven') 'EXIT_STREAMS' }
    Test-Case 'V11 exit7 throws by default' { Assert-Throws { Invoke-Probe @('exit7') } 'exit 7' }
    Test-Case 'V11 direct-child timeout bounded' { $C=[Diagnostics.Stopwatch]::StartNew(); Assert-Throws { Invoke-Probe @('sleep') -Timeout 1 -AllowNonZero } 'NATIVE_TIMEOUT'; Assert-True ($C.Elapsed.TotalSeconds -lt 4) 'CLEANUP_NOT_BOUNDED' }
    Test-Case 'V11 descendant-held pipes bounded and both read handles closed' {
        $Marker=Join-Path $RunRoot 'pipe-closure.txt'
        $C=[Diagnostics.Stopwatch]::StartNew()
        Assert-Throws { Invoke-Probe @('parent-with-pipe-child',$Marker) -Timeout 1 -AllowNonZero } 'NATIVE_OUTPUT_TIMEOUT'
        Assert-True ($C.Elapsed.TotalSeconds -lt 4) 'PIPE_CLEANUP_NOT_BOUNDED'
        while (-not (Test-Path -LiteralPath $Marker) -and $C.Elapsed.TotalSeconds -lt 6) { Start-Sleep -Milliseconds 50 }
        Assert-True (Test-Path -LiteralPath $Marker) 'PIPE_CLOSURE_EVIDENCE_MISSING'
        Assert-True ([IO.File]::ReadAllText($Marker) -ceq 'True,True') 'PIPE_READ_HANDLES_RETAINED'
    }
    Test-Case 'V11 concurrent stdout stderr complete' { $R=Invoke-Probe @('pipes'); Assert-True ($R.Stdout.Length -eq 100000 -and $R.Stderr.Length -eq 100000) 'PIPE_TRUNCATION' }
    Test-Case 'pipe-closure fixture recognizes both readers still open' {
        $Marker=Join-Path $RunRoot 'pipe-open-control.txt'
        $R=Invoke-Probe @('parent-with-pipe-child',$Marker) -Timeout 12
        Assert-True ($R.ExitCode -eq 0 -and [IO.File]::ReadAllText($Marker) -ceq 'False,False') 'PIPE_CLOSURE_NEGATIVE_CONTROL'
        Assert-True ($R.Stdout.Contains('owned-pipe-check') -and $R.Stderr.Contains('owned-pipe-check')) 'PIPE_CONTROL_OUTPUT_MISSING'
    }
    $Unicode=([char]0x03BB).ToString()+[char]0x4E16+[char]0x754C
    Test-Case 'V11 Unicode on both streams' { $R=Invoke-Probe @('unicode'); Assert-True ($R.Stdout -ceq $Unicode -and $R.Stderr -ceq (([char]0x03B4).ToString()+[char]0x4E16+[char]0x754C)) 'UNICODE_OUTPUT' }
    Test-Case 'V11 UTF8 BOM is stripped on both streams' { $R=Invoke-Probe @('utf8-bom'); Assert-True ($R.Stdout -ceq '{"ok":true}' -and $R.Stderr -ceq 'bom-error') 'UTF8_BOM_OUTPUT' }
    $Vectors=@(
        [pscustomobject]@{name='zero';values=[string[]]@()},[pscustomobject]@{name='empty';values=[string[]]@('')},
        [pscustomobject]@{name='adjacent-empty';values=[string[]]@('','','tail')},[pscustomobject]@{name='spaces-tabs';values=[string[]]@('two words',' ',"a`tb")},
        [pscustomobject]@{name='unicode-spaces';values=[string[]]@($Unicode,('two '+$Unicode))},[pscustomobject]@{name='quotes';values=[string[]]@('a"b','"','a""b')},
        [pscustomobject]@{name='trailing-slashes';values=[string[]]@('C:\directory with spaces\','C:\two words\\')},[pscustomobject]@{name='slash-quotes';values=[string[]]@('one\"two','one\\"two','\\"')},
        [pscustomobject]@{name='literal-shell';values=[string[]]@('$HOME','$(not-executed)','%PATH%','a&b|c>d','`')},[pscustomobject]@{name='newlines';values=[string[]]@("line1`nline2","line1`r`nline2")},
        [pscustomobject]@{name='mixed';values=[string[]]@('',$Unicode,'C:\a b\','a"b','tail')}
    )
    foreach($Vector in $Vectors) { Test-Case ('V11 argv '+$Vector.name) { $R=Invoke-Probe ([string[]](@('argv')+@($Vector.values))); Assert-ArgumentEcho $R.Stdout $Vector.values } }
    Test-Case 'V11 twenty rapid exits preserve7' { for($I=0;$I -lt 20;$I++) { $R=Invoke-Probe @('exit7') -AllowNonZero; Assert-True ($R.ExitCode -eq 7) 'RAPID_EXIT' } }
    Test-Case 'V11 invalid timeout rejected before start' { Assert-Throws { Invoke-Probe @('sleep') -Timeout 0 } 'range|ValidateRange|greater' }
    Test-Case 'V11 redaction preserved in results and Echo' {
        $R=Invoke-Probe @('sensitive')
        Assert-True ($R.Stdout -ceq '[REDACTED]' -and $R.Stderr -ceq '[REDACTED]') 'REDACTION_RESULT'
        $Rendered=(Invoke-Probe @('sensitive') -Echo 6>&1 3>&1 | Out-String)
        Assert-True ($Rendered.Contains('[REDACTED]') -and -not $Rendered.Contains('SYNTHETIC_VALUE')) 'REDACTION_ECHO'
    }
}
finally {
    $Failed=@($Rows | Where-Object { -not $_.passed }).Count
    $Receipt=[ordered]@{
        schema='szl.ps51-inert-ci/v1';suite='recovered-v11';fixture_class='SIMULATED';powershell=$PSVersionTable.PSVersion.ToString()
        qualification_scope='named-recovered-v11-definitions-static-entry-and-synthetic-discovery-contracts';historical_definitions_executed=$false;runtime_admission='BLOCKED'
        reference_sha256=$Manifest.base_sha256;candidate_sha256=$Manifest.candidate_sha256;manifest_sha256=(Get-FileHash -LiteralPath $ManifestPath).Hash.ToLowerInvariant()
        harness_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant();passed=$Rows.Count-$Failed;failed=$Failed;tests=$Rows.ToArray()
        controller_main_executed=$false;production_subprocesses_executed=$false;policy_settings_changed=$false
    }
    New-Item -ItemType Directory -Path $ReceiptDirectory -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $ReceiptDirectory 'recovered-v11.json'),($Receipt | ConvertTo-Json -Depth 7),(New-Object Text.UTF8Encoding($false)))
    Write-Host ('Passed: {0}; failed: {1}' -f $Receipt.passed,$Failed)
}
if ($Failed -ne 0) { throw 'RECOVERED_V11_CONTRACT_FAILURE' }
