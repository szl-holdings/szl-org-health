#requires -version 5.1
# Every child is NativeProbe.exe, compiled below in a unique owned directory.
# Production scripts are parsed as data; only explicitly named definitions load.
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
$LibraryDefinitions = Read-Definitions $LibraryPath @('ConvertTo-SzlNativeArgument','Get-SzlObservedExitCode','Initialize-SzlNativePipe','Invoke-SzlNativeProcess','Resolve-SzlPinnedOperator')
. ([scriptblock]::Create($LibraryDefinitions))
$V13Path = Join-Path $RepositoryRoot 'tools/SZL_DISK_CLEAN_RESUME_PS51_V13.ps1'
. ([scriptblock]::Create((Read-Definitions $V13Path @('Invoke-NativeTool','Find-Operator'))))
$V12Path = Join-Path $RepositoryRoot 'tools/SZL_PARALLEL_FRONTIER_COORDINATOR_PS51_V12_1.ps1'
. ([scriptblock]::Create((Read-Definitions $V12Path @('Get-ResumeOperator'))))
$Reference = Join-Path $RepositoryRoot 'tests/fixtures/ps51/operator-23b1aaab.ps1.txt'
$ExpectedHash = '23B1AAABEF7AED9C2801C975BEAD79AC16084432537CFF26059952208B3D687B'
Assert-True ((Get-FileHash -LiteralPath $Reference -Algorithm SHA256).Hash -ceq $ExpectedHash) 'Recovered source bytes changed'
. ([scriptblock]::Create((Read-Definitions $Reference @('Repeat-Backslash','ConvertTo-NativeArgument','Invoke-Native'))))
function Redact-Text([string]$Text) { return $Text } # Not testing legacy redaction.
$WorkRoot = Join-Path $env:TEMP ('szl-ps51-contract-' + [Guid]::NewGuid().ToString('N'))
$RunRoot = $WorkRoot
$TempRoot = Join-Path $WorkRoot 'legacy-io'
$LogRoot = Join-Path $WorkRoot 'logs'
$EstateRoot = Join-Path $WorkRoot 'estate'
$RuntimeRoot = Join-Path $EstateRoot 'Runtime'
New-Item -ItemType Directory -Path $WorkRoot,$TempRoot,$LogRoot,$RuntimeRoot -Force | Out-Null
$Probe = Join-Path $WorkRoot 'Native Probe.exe'
$ProbeSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'tests/fixtures/ps51/NativeProbe.cs'))
Add-Type -TypeDefinition $ProbeSource -OutputAssembly $Probe -OutputType ConsoleApplication
function Invoke-Probe {
    param([string]$Lane, [AllowEmptyCollection()][AllowEmptyString()][string[]]$Values = @(), [int]$Timeout = 5, [switch]$AllowNonZero)
    if ($Lane -eq 'legacy') { return Invoke-Native -FilePath $Probe -ArgumentList $Values -WorkingDirectory $WorkRoot -TimeoutSeconds $Timeout -AllowNonZero:$AllowNonZero }
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
try {
    Test-Case 'fixture reference parses without running main' { Assert-True ($ExpectedHash -ceq (Get-FileHash -LiteralPath $Reference).Hash) 'Reference changed' }
    $Candidate = Join-Path $RuntimeRoot 'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_PS51_JSON.ps1'
    $OldCandidate = Join-Path $RuntimeRoot 'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_HF_PREFLIGHT_ROBUST.ps1'
    [IO.File]::WriteAllText($OldCandidate, 'throw "OLD_HELPER_MAIN_MUST_NOT_RUN"')
    Test-Case 'missing PS51_JSON rejects available older helper' { Assert-Throws { Find-Operator } 'OPERATOR_IDENTITY_MISSING'; Assert-Throws { Get-ResumeOperator } 'OPERATOR_IDENTITY_MISSING' }
    [IO.File]::WriteAllText($Candidate, 'throw "WRONG_HELPER_MAIN_MUST_NOT_RUN"')
    Test-Case 'wrong helper refuses timestamp fallback' { Assert-Throws { Find-Operator } 'OPERATOR_IDENTITY_MISMATCH'; Assert-Throws { Get-ResumeOperator } 'OPERATOR_IDENTITY_MISMATCH' }
    Copy-Item -LiteralPath $Reference -Destination $Candidate -Force
    (Get-Item -LiteralPath $OldCandidate).LastWriteTimeUtc = [DateTime]::UtcNow.AddYears(1)
    Test-Case 'both selectors choose exact immutable PS51_JSON' {
        # Hosted Windows TEMP may use an 8.3 alias (RUNNER~1). Compare with
        # the filesystem's full name for this exact fixture, not its input alias.
        $ExpectedPath = (Get-Item -LiteralPath $Candidate -ErrorAction Stop).FullName
        $V13Selected = Find-Operator
        $V12Selected = Get-ResumeOperator
        Write-Host ('Fixture input path: {0}; filesystem path: {1}' -f $Candidate, $ExpectedPath)
        Assert-True ($V13Selected -ceq $ExpectedPath) ('Wrong V13 path: {0}; expected: {1}' -f $V13Selected, $ExpectedPath)
        Assert-True ($V12Selected -ceq $ExpectedPath) ('Wrong V12 path: {0}; expected: {1}' -f $V12Selected, $ExpectedPath)
    }
    [IO.File]::AppendAllText($Candidate, "`n# changed bytes")
    Test-Case 'post-selection change is refused on recheck' { Assert-Throws { Find-Operator } 'OPERATOR_IDENTITY_MISMATCH' }
    Copy-Item -LiteralPath $Reference -Destination $Candidate -Force
    Test-Case 'stale pin is absent from source launcher' {
        $Source = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'tools/RUN_SZL_CTO_RATE_AWARE.ps1'))
        Assert-True (-not $Source.Contains('c6ea52536a3a5c0562a8deb16de5a7db023bed802dff1029944317f12d1cda78')) 'Stale launcher pin'
        Assert-True ($Source.Contains($ExpectedHash.ToLowerInvariant())) 'Missing recovered identity'
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
    foreach ($Lane in @('legacy','new','v13')) {
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
        schema='szl.ps51-inert-ci/v1';suite='historical-and-v13';fixture_class='SIMULATED'
        powershell=$Receipt.powershell;reference_sha256=$Receipt.reference_sha256;harness_sha256=$Receipt.harness_sha256
        passed=$Receipt.passed;failed=$Failed;tests=@($Rows | Select-Object name,passed)
        controller_main_executed=$false;production_subprocesses_executed=$false
    }
    [IO.File]::WriteAllText((Join-Path $ReceiptDirectory 'process-contracts.json'), ($PublicReceipt | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    Write-Host ('Receipt: ' + $ReceiptPath)
    Write-Host ('Passed: {0}; failed: {1}' -f $Receipt.passed, $Failed)
}
if ($Failed -ne 0) { throw 'PS51_PROCESS_CONTRACT_FAILURE' }
