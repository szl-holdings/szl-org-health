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
$ManifestPath=Join-Path $RepositoryRoot 'tools/ps51-recovered-source.lineage.json'
$Manifest=[IO.File]::ReadAllText($ManifestPath) | ConvertFrom-Json
$Base=[IO.File]::ReadAllBytes((Join-Path $RepositoryRoot $Manifest.base_path))
$Candidate=[IO.File]::ReadAllBytes((Join-Path $RepositoryRoot $Manifest.candidate_path))
Assert-Lineage $Base $Candidate $Manifest
$Decoder=New-Object Text.UTF8Encoding($false,$true)
$Source=$Decoder.GetString($Candidate).TrimStart([char]0xFEFF)
$Library=[IO.File]::ReadAllText((Join-Path $RepositoryRoot $Manifest.library_path),$Decoder)
Assert-True ((Get-FileHash -LiteralPath (Join-Path $RepositoryRoot $Manifest.library_path)).Hash.ToLowerInvariant() -ceq $Manifest.library_sha256) 'LIBRARY_HASH_CHANGED'
$Names=@('Assert-SzlExecutionPolicy','ConvertTo-SzlNativeArgument','Get-SzlObservedExitCode','Initialize-SzlNativePipe','Invoke-SzlNativeProcess','Invoke-Native','Redact-Text')
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
try {
    Test-Case 'exact recovered lineage and unchanged payload' { Assert-Lineage $Base $Candidate $Manifest; Assert-True ((Embedded-Hash $Source) -ceq $Manifest.embedded_python_sha256) 'EMBEDDED_HASH' }
    Test-Case 'copied native definitions equal reviewed library' { foreach($Name in $Manifest.copied_definitions) { Assert-True ((Get-Definition $Source $Name) -ceq (Get-Definition $Library $Name)) ('Definition drift: '+$Name) } }
    Test-Case 'candidate mutation is rejected' { $Changed=[byte[]]$Candidate.Clone(); $Changed[100]=$Changed[100] -bxor 1; Assert-Throws { Assert-Lineage $Base $Changed $Manifest } 'LINEAGE_CANDIDATE_HASH' }
    Test-Case 'manifest region mutation is rejected' { $Changed=$Manifest | ConvertTo-Json -Depth 8 | ConvertFrom-Json; $Changed.regions[0].new_sha256='0'*64; Assert-Throws { Assert-Lineage $Base $Candidate $Changed } 'LINEAGE_NEW_REGION' }
    Test-Case 'undeclared byte mutation rejected even with updated candidate hash' { $Changed=[byte[]]$Candidate.Clone(); $Changed[100]=$Changed[100] -bxor 1; $M=$Manifest | ConvertTo-Json -Depth 8 | ConvertFrom-Json; $M.candidate_sha256=Hash-Bytes $Changed; Assert-Throws { Assert-Lineage $Base $Changed $M } 'LINEAGE_UNDECLARED_CHANGE' }
    Test-Case 'embedded mutation does not preserve payload identity' { $Changed=$Source.Replace('IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMw','IyEvdXNyL2Jpbi9lbnYgcHl0aG9uNA'); Assert-True ((Embedded-Hash $Changed) -cne $Manifest.embedded_python_sha256) 'EMBEDDED_NEGATIVE_CONTROL' }
    Test-Case 'no parameterless native wait remains' { Assert-BoundedNative $Source }
    Test-Case 'parameterless wait negative control rejected' { Assert-Throws { Assert-BoundedNative ($Source+"`n`$synthetic.WaitForExit()") } 'UNBOUNDED_NATIVE_WAIT' }
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
        reference_sha256=$Manifest.base_sha256;candidate_sha256=$Manifest.candidate_sha256;manifest_sha256=(Get-FileHash -LiteralPath $ManifestPath).Hash.ToLowerInvariant()
        harness_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant();passed=$Rows.Count-$Failed;failed=$Failed;tests=$Rows.ToArray()
        controller_main_executed=$false;production_subprocesses_executed=$false;policy_settings_changed=$false
    }
    New-Item -ItemType Directory -Path $ReceiptDirectory -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $ReceiptDirectory 'recovered-v11.json'),($Receipt | ConvertTo-Json -Depth 7),(New-Object Text.UTF8Encoding($false)))
    Write-Host ('Passed: {0}; failed: {1}' -f $Receipt.passed,$Failed)
}
if ($Failed -ne 0) { throw 'RECOVERED_V11_CONTRACT_FAILURE' }
