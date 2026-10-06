#requires -version 5.1
# Inert definitions only. Loading this file never starts an operator or process.

function Assert-SzlExecutionPolicy {
    # This is a read-only preflight, never a policy setter. A permitted execution
    # policy is necessary but does not authorize this controller's other effects.
    try { $Policy = [string](Get-ExecutionPolicy -ErrorAction Stop) }
    catch { throw 'EXECUTION_POLICY_HOLD: effective policy unavailable' }
    if (@('AllSigned', 'RemoteSigned', 'Unrestricted') -notcontains $Policy) {
        throw ('EXECUTION_POLICY_HOLD: use an already policy-permitted runner; observed {0}' -f $Policy)
    }
}

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

function Initialize-SzlNativePipe {
    if ('Szl.NativePipeV1' -as [type]) { return }
    # The sole reader polls its owned anonymous pipe before each synchronous
    # read. There are no background reader tasks to retain handles after timeout.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Szl {
    public static class NativePipeV1 {
        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PeekNamedPipe(SafeFileHandle pipe, IntPtr buffer,
            uint size, IntPtr read, out uint available, IntPtr remaining);
        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReadFile(SafeFileHandle pipe, byte[] buffer,
            uint size, out uint read, IntPtr overlapped);
        public static bool Drain(FileStream pipe, MemoryStream output) {
            uint available;
            if (!PeekNamedPipe(pipe.SafeFileHandle, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero)) {
                int error = Marshal.GetLastWin32Error();
                if (error == 109) return true; // EOF: all inherited writers closed.
                throw new Win32Exception(error);
            }
            if (available == 0) return false;
            byte[] bytes = new byte[(int)Math.Min(available, 65536u)];
            // ReadFile avoids FileStream read-ahead hiding buffered bytes from
            // the next PeekNamedPipe observation. This is the only pipe reader.
            uint read;
            if (!ReadFile(pipe.SafeFileHandle, bytes, (uint)bytes.Length, out read, IntPtr.Zero)) {
                int error = Marshal.GetLastWin32Error();
                if (error == 109) return true;
                throw new Win32Exception(error);
            }
            if (read == 0) return true;
            output.Write(bytes, 0, (int)read);
            return false;
        }
    }
}
'@ -ErrorAction Stop
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
    Initialize-SzlNativePipe
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
    $StdoutReader = $null
    $StderrReader = $null
    $StdoutBytes = New-Object IO.MemoryStream
    $StderrBytes = New-Object IO.MemoryStream
    $BudgetMs = $TimeoutSeconds * 1000
    try {
        # Process.Start retains the original handle, including for rapid exits.
        $Started = $Process.Start()
        if (-not $Started -or $Process.Handle -eq [IntPtr]::Zero) { throw 'NATIVE_PROCESS_HANDLE_UNAVAILABLE' }
        $StdoutReader = $Process.StandardOutput
        $StderrReader = $Process.StandardError
        $StdoutClosed = $false
        $StderrClosed = $false
        # Alternate bounded chunks from both pipes; never wait for one pipe's EOF
        # before reading the other. No ReadToEndAsync task survives this call.
        while ($true) {
            $Exited = $Process.WaitForExit(0)
            if (-not $StdoutClosed) { $StdoutClosed = [Szl.NativePipeV1]::Drain($StdoutReader.BaseStream, $StdoutBytes) }
            if (-not $StderrClosed) { $StderrClosed = [Szl.NativePipeV1]::Drain($StderrReader.BaseStream, $StderrBytes) }
            if ($Exited -and $StdoutClosed -and $StderrClosed) { break }
            $Remaining = [Math]::Max(0, $BudgetMs - [int]$Clock.ElapsedMilliseconds)
            if ($Remaining -le 0) {
                if ($Exited) { throw 'NATIVE_OUTPUT_TIMEOUT' }
                throw 'NATIVE_TIMEOUT'
            }
            Start-Sleep -Milliseconds ([Math]::Min(10, $Remaining))
        }
        $ExitCode = Get-SzlObservedExitCode -Process $Process
        # Decode only completed in-memory buffers. StreamReader preserves the
        # prior UTF-8/BOM behavior without reading from a live pipe or waiting.
        $Buffers = @($StdoutBytes, $StderrBytes)
        $Decoded = @('', '')
        for ($Index = 0; $Index -lt 2; $Index++) {
            $Buffers[$Index].Position = 0
            $Reader = New-Object IO.StreamReader($Buffers[$Index], [Text.Encoding]::UTF8, $true)
            try { $Decoded[$Index] = $Reader.ReadToEnd() }
            finally { $Reader.Dispose() }
        }
        $Result = [pscustomobject]@{
            Name = $Name
            FilePath = $FilePath
            Arguments = $ArgumentList
            ExitCode = $ExitCode
            Stdout = $Decoded[0]
            Stderr = $Decoded[1]
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
        # Process.Dispose does not close these readers on .NET Framework.
        # These readers have no concurrent reads, so closing releases both owned
        # read handles even when a descendant still holds the write ends.
        if ($null -ne $StdoutReader) { $StdoutReader.Dispose() }
        if ($null -ne $StderrReader) { $StderrReader.Dispose() }
        $StdoutBytes.Dispose()
        $StderrBytes.Dispose()
        $Process.Dispose()
        $Clock.Stop()
    }
}

function Resolve-SzlPinnedOperator {
    param([Parameter(Mandatory = $true)][string]$SourceRoot)
    # Repository-adjacent recovered source only. Neither this descriptor nor a
    # manifest/environment value grants admission. These constants bind bytes.
    $FileName = 'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_RECOVERED_1.ps1'
    $Expected = 'a137d139c13362860cc1d91efb111c4f591152ac9ff8ed4b66d5ce9dfa612d1f'
    $ExpectedBytes = 249142 # RECOVERED_BYTE_COUNT
    $Version = '11.0.6-recovered-bounded.2'
    if ($SourceRoot -notmatch '^[A-Za-z]:[\\/]' -or
        $SourceRoot -match '[*?]' -or $SourceRoot.Substring(2).Contains(':') -or
        $SourceRoot -match '(^|[\\/])\.\.?([\\/]|$)' -or
        $SourceRoot -match '(^|[\\/])[^\\/]*[. ]([\\/]|$)') { throw 'OPERATOR_SOURCE_ROOT_INVALID' }
    $Root = [IO.Path]::GetFullPath($SourceRoot)
    if ($Root.Length -gt 3) { $Root = $Root.TrimEnd([char[]]@('\','/')) }
    # Inspect every component, including ancestors of the supplied tools root.
    # This is a static path check, not a lock against replacement after the read.
    $ProbePath = $Root
    $FirstPart = $true
    while (-not [string]::IsNullOrWhiteSpace($ProbePath)) {
        $Part = Get-Item -LiteralPath $ProbePath -Force -ErrorAction Stop
        if (($Part.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'OPERATOR_REPARSE_POINT_REJECTED' }
        if (-not $Part.PSIsContainer) { throw 'OPERATOR_SOURCE_ROOT_INVALID' }
        if ($FirstPart) { $Root = $Part.FullName; $FirstPart = $false }
        $ProbePath = Split-Path -Parent $Part.FullName
    }
    $Candidate = Join-Path $Root $FileName
    if (-not (Test-Path -LiteralPath $Candidate)) { throw 'OPERATOR_IDENTITY_MISSING' }
    $Item = Get-Item -LiteralPath $Candidate -Force -ErrorAction Stop
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'OPERATOR_REPARSE_POINT_REJECTED' }
    if ($Item.PSIsContainer -or $Item.Name -cne $FileName) { throw 'OPERATOR_SOURCE_PATH_INVALID' }
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($Item.FullName), $Root, [StringComparison]::OrdinalIgnoreCase)) { throw 'OPERATOR_SOURCE_PATH_INVALID' }
    if ($Item.Length -ne $ExpectedBytes) { throw 'OPERATOR_IDENTITY_MISMATCH' }
    # Hash and parse the same buffer. Never select by mtime or fall back to an
    # older family after a missing, changed, unreadable, or invalid candidate.
    $Bytes = [IO.File]::ReadAllBytes($Item.FullName)
    if ($Bytes.Length -ne $ExpectedBytes) { throw 'OPERATOR_IDENTITY_MISMATCH' }
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
    return [pscustomobject]@{
        Path = $Item.FullName; SHA256 = $Actual; Bytes = $Bytes.Length; Version = $Version
        HistoricalAdmission = 'UNKNOWN'; ProspectiveAdmission = 'BLOCKED'
        RuntimeAdmission = 'BLOCKED'; CanInvoke = $false
    }
}

function Assert-SzlOperatorAdmission {
    param([AllowNull()][object]$Identity)
    # Deliberately has no approval flag, environment override, or execution path.
    # Removing this HOLD requires a separately reviewed source-admission change.
    throw 'SZL_SOURCE_ADMISSION_HOLD'
}
