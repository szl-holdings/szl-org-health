# SPDX-License-Identifier: Apache-2.0
# Read-only BETTERWITHAGE sensor. Emits ONLY sanitized JSON on stdout.
# No process command lines, providers, file contents, credentials, cleanup,
# persistence, Task Scheduler modifications, or receipt reconstruction.
[CmdletBinding()]
param(
    [ValidateRange(1, 10)] [int] $SampleSeconds = 5
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-CVolume {
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
    if ($null -eq $disk -or [int64]$disk.Size -le 0 -or
        [int64]$disk.FreeSpace -lt 0 -or [int64]$disk.FreeSpace -gt [int64]$disk.Size) {
        throw 'DISK_SENSOR_INVALID'
    }
    return [ordered]@{
        utc = [DateTime]::UtcNow.ToString('o')
        drive = 'C:'
        total_bytes = [int64]$disk.Size
        free_bytes = [int64]$disk.FreeSpace
    }
}

try {
    if ($env:COMPUTERNAME -ne 'BETTERWITHAGE') {
        throw 'DEVICE_NOT_AUTHORIZED'
    }
    $first = Read-CVolume
    Start-Sleep -Seconds $SampleSeconds
    $second = Read-CVolume
    if ($first.total_bytes -ne $second.total_bytes) {
        throw 'DISK_GEOMETRY_CHANGED'
    }

    $all = @(Get-Process -ErrorAction Stop)
    # Name, PID and working-set only; never read CommandLine, Path,
    # Environment, owner identity, process modules, or arguments.
    $names = '^(?:python.*|node|claude.*|llama-server|ollama|git|msedge|Docker Desktop|cloudflared|powershell|pwsh|cargo|rustc|uv|pytest|kimi|mistral)$'
    $observed = @($all | Where-Object { $_.ProcessName -match $names })
    if ($observed.Count -gt 256) {
        throw 'PROCESS_SENSOR_BUDGET_EXCEEDED'
    }
    $processes = @($observed | ForEach-Object {
        [ordered]@{
            name = [string]$_.ProcessName
            pid = [int]$_.Id
            working_set_bytes = [int64]$_.WorkingSet64
        }
    })

    $scratch = @()
    foreach ($entry in @(
        @{id='gh_scan_err'; file='C:\SZL\scratch\gh_scan_err.txt'},
        @{id='gh_scan_err2'; file='C:\SZL\scratch\gh_scan_err2.txt'},
        @{id='hf_scan_err'; file='C:\SZL\scratch\hf_scan_err.txt'}
    )) {
        $exists = $false
        $bytes = [int64]0
        try {
            $f = Get-Item -LiteralPath $entry.file -ErrorAction Stop
            if ($f.PSIsContainer) { throw 'SCRATCH_NOT_REGULAR' }
            $exists = $true
            $bytes = [int64]$f.Length
        } catch [System.Management.Automation.ItemNotFoundException] {
            $exists = $false
        }
        $scratch += [ordered]@{
            id = [string]$entry.id
            exists = $exists
            size_bytes = $bytes
            owner_state = 'UNVERIFIED'
        }
    }

    $payload = [ordered]@{
        schema = 'szl.disk-agent-hygiene-input/v1'
        device = 'BETTERWITHAGE'
        observations = @($first, $second)
        historical = [ordered]@{ state = 'UNAVAILABLE' }
        processes = $processes
        scratch = @($scratch)
        cache_growth = [ordered]@{ state = 'UNOBSERVED' }
    }
    $json = ConvertTo-Json -InputObject $payload -Depth 8 -Compress
    [Console]::Out.WriteLine($json)
    exit 0
} catch {
    # Suppress untrusted exception text: no paths or sensitive process data.
    [Console]::Error.WriteLine('DISK_AGENT_HYGIENE_OBSERVATION_HOLD')
    exit 3
}
