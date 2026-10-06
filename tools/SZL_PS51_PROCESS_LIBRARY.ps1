#requires -version 5.1
# Inert definitions only. Loading this file never starts an operator or process.

function ConvertTo-SzlNativeArgument {
    param([AllowNull()][AllowEmptyString()][string]$Argument)
    if ([string]::IsNullOrEmpty($Argument)) { return '""' }
    if ($Argument -notmatch '[\s"]') { return $Argument }
    $Builder = New-Object Text.StringBuilder
    [void]$Builder.Append('"')
    $Slashes = 0
    foreach ($Character in $Argument.ToCharArray()) {
        if ($Character -eq [char]92) { $Slashes++; continue }
        if ($Character -eq [char]34) {
            [void]$Builder.Append([char]92, (($Slashes * 2) + 1))
            [void]$Builder.Append('"')
            $Slashes = 0
            continue
        }
        if ($Slashes -gt 0) { [void]$Builder.Append([char]92, $Slashes); $Slashes = 0 }
        [void]$Builder.Append($Character)
    }
    if ($Slashes -gt 0) { [void]$Builder.Append([char]92, ($Slashes * 2)) }
    [void]$Builder.Append('"')
    return $Builder.ToString()
}

function Get-SzlObservedExitCode {
    param([Parameter(Mandatory = $true)]$Process)
    try { $Observed = $Process.ExitCode }
    catch { throw 'NATIVE_EXIT_UNAVAILABLE' }
    # Never coerce null, a string, or a Boolean into a successful native exit.
    if ($null -eq $Observed -or $Observed -isnot [int]) { throw 'NATIVE_EXIT_UNAVAILABLE' }
    return $Observed
}

function Invoke-SzlNativeProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [AllowEmptyCollection()][AllowEmptyString()][string[]]$ArgumentList = @(),
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [ValidateRange(1, 2147483)][int]$TimeoutSeconds = 3600,
        [switch]$AllowNonZero,
        [string]$Name = 'native-tool'
    )
    $Info = New-Object Diagnostics.ProcessStartInfo
    $Info.FileName = $FilePath
    $Info.Arguments = (@($ArgumentList | ForEach-Object { ConvertTo-SzlNativeArgument $_ }) -join ' ')
    $Info.WorkingDirectory = $WorkingDirectory
    $Info.UseShellExecute = $false
    $Info.CreateNoWindow = $true
    $Info.RedirectStandardOutput = $true
    $Info.RedirectStandardError = $true
    $Info.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $Info.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $Process = New-Object Diagnostics.Process
    $Process.StartInfo = $Info
    $Clock = [Diagnostics.Stopwatch]::StartNew()
    $Started = $false
    $BudgetMs = $TimeoutSeconds * 1000
    try {
        # Process.Start retains the original handle, including for rapid exits.
        $Started = $Process.Start()
        if (-not $Started -or $Process.Handle -eq [IntPtr]::Zero) { throw 'NATIVE_PROCESS_HANDLE_UNAVAILABLE' }
        # Read both pipes concurrently; waiting on one pipe first can deadlock.
        $StdoutTask = $Process.StandardOutput.ReadToEndAsync()
        $StderrTask = $Process.StandardError.ReadToEndAsync()
        $Remaining = [Math]::Max(0, $BudgetMs - [int]$Clock.ElapsedMilliseconds)
        if (-not $Process.WaitForExit($Remaining)) { throw 'NATIVE_TIMEOUT' }
        $ExitCode = Get-SzlObservedExitCode -Process $Process
        # A descendant can retain a pipe after the direct child exits. Pipe drain
        # shares the same deadline and never uses parameterless WaitForExit.
        foreach ($Task in @($StdoutTask, $StderrTask)) {
            $Remaining = [Math]::Max(0, $BudgetMs - [int]$Clock.ElapsedMilliseconds)
            if (-not $Task.Wait($Remaining)) { throw 'NATIVE_OUTPUT_TIMEOUT' }
        }
        $Result = [pscustomobject]@{
            Name = $Name
            FilePath = $FilePath
            Arguments = $ArgumentList
            ExitCode = $ExitCode
            Stdout = $StdoutTask.Result
            Stderr = $StderrTask.Result
            Seconds = [Math]::Round($Clock.Elapsed.TotalSeconds, 3)
        }
        if (-not $AllowNonZero -and $ExitCode -ne 0) { throw ('{0} failed with exit code {1}.' -f $Name, $ExitCode) }
        return $Result
    }
    finally {
        if ($Started) {
            try {
                if (-not $Process.HasExited) {
                    $Process.Kill()
                    [void]$Process.WaitForExit(1000)
                }
            }
            catch { } # Original failure is preserved; no unbounded cleanup wait.
        }
        $Process.Dispose()
        $Clock.Stop()
    }
}

function Resolve-SzlPinnedOperator {
    param([Parameter(Mandatory = $true)][string]$RuntimeRoot)
    # Exact recovered source bytes, preserved in tests/fixtures/ps51. This is an
    # identity boundary, not authorization to run the full historical controller.
    $FileName = 'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_PS51_JSON.ps1'
    $Expected = '23b1aaabef7aed9c2801c975bead79ac16084432537cff26059952208b3d687b'
    $Candidate = Join-Path $RuntimeRoot $FileName
    if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) { throw 'OPERATOR_IDENTITY_MISSING' }
    $Item = Get-Item -LiteralPath $Candidate -Force -ErrorAction Stop
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'OPERATOR_REPARSE_POINT_REJECTED' }
    # Hash and parse the same buffer. Never select by mtime or fall back to an
    # older family after a missing, changed, unreadable, or invalid candidate.
    $Bytes = [IO.File]::ReadAllBytes($Item.FullName)
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try { $Actual = [BitConverter]::ToString($Hasher.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $Hasher.Dispose() }
    if ($Actual -cne $Expected) { throw 'OPERATOR_IDENTITY_MISMATCH' }
    $Decoder = New-Object Text.UTF8Encoding($false, $true)
    $Source = $Decoder.GetString($Bytes).TrimStart([char]0xFEFF)
    $Tokens = $null
    $Errors = $null
    [void][Management.Automation.Language.Parser]::ParseInput($Source, [ref]$Tokens, [ref]$Errors)
    if (@($Errors).Count -ne 0) { throw 'OPERATOR_PARSE_FAILED' }
    return $Item.FullName
}
