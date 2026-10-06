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
