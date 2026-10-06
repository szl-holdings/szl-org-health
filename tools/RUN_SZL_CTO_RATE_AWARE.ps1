#requires -Version 5.1
#requires -RunAsAdministrator

throw 'SZL_SOURCE_ADMISSION_HOLD'

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'SZL_PS51_PROCESS_LIBRARY.ps1')
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$EvidenceRoot = 'C:\ProgramData\SZL\EstateOperator'
$ControllerRoot = 'C:\SZL-CTO-CONVERGENCE'
$LogPath = Join-Path $ControllerRoot ('RATE-AWARE-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
$Deadline = (Get-Date).AddHours(2)

function Write-RunLog {
    param([string]$Message,[string]$Level='INFO')
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Level,$Message
    Write-Host $line -ForegroundColor $(if($Level -eq 'ERROR'){'Red'}elseif($Level -eq 'WARN'){'Yellow'}elseif($Level -eq 'OK'){'Green'}else{'Cyan'})
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-GitHubBudgetObservation {
    $previousPreference = $ErrorActionPreference
    $lines = @()
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& gh.exe api --include 'users/szl-holdings/repos?type=all&sort=full_name&per_page=1' 2>&1)
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    $text = $lines -join [Environment]::NewLine
    $status = 0
    $remaining = -1
    $reset = 0L
    if ($text -match '(?im)^HTTP/\S+\s+(\d{3})') { $status = [int]$matches[1] }
    if ($text -match '(?im)^X-Ratelimit-Remaining:\s*(\d+)') { $remaining = [int]$matches[1] }
    if ($text -match '(?im)^X-Ratelimit-Reset:\s*(\d+)') { $reset = [int64]$matches[1] }
    return [pscustomobject]@{ Status=$status; Remaining=$remaining; Reset=$reset }
}

if (-not (Test-Administrator)) { throw 'Run this file from Windows PowerShell 5.1 as Administrator.' }
$OperatorIdentity = Resolve-SzlPinnedOperator -SourceRoot $PSScriptRoot

Write-RunLog ('Verified inactive recovered source SHA-256 {0}; admission remains blocked.' -f $OperatorIdentity.SHA256) 'OK'
$otherRunners = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ProcessId -ne $PID -and
    -not [string]::IsNullOrWhiteSpace([string]$_.CommandLine) -and
    $_.CommandLine -match 'RUN_SZL_CTO_RATE_AWARE\.ps1'
})
if ($otherRunners.Count -gt 0) {
    Write-RunLog ('A rate-aware convergence runner is already queued or active. PID(s): {0}. No duplicate was started.' -f (($otherRunners.ProcessId) -join ',')) 'WARN'
    exit 0
}
Write-RunLog 'Waiting for a real GitHub REST request to prove usable core budget. No blind API loop will run.' 'INFO'

while ((Get-Date) -lt $Deadline) {
    $observation = Get-GitHubBudgetObservation
    Write-RunLog ('GitHub probe: status={0}, remaining={1}, reset={2}' -f $observation.Status,$observation.Remaining,$observation.Reset) 'INFO'
    if ($observation.Status -eq 200 -and $observation.Remaining -gt 1000) { break }
    $sleepSeconds = 120
    if ($observation.Reset -gt 0) {
        $resetUtc = [DateTimeOffset]::FromUnixTimeSeconds($observation.Reset).UtcDateTime
        $sleepSeconds = [int][Math]::Ceiling(($resetUtc - [DateTime]::UtcNow).TotalSeconds) + 20
        if ($sleepSeconds -lt 30) { $sleepSeconds = 30 }
        if ($sleepSeconds -gt 3600) { $sleepSeconds = 3600 }
        Write-RunLog ('Rate budget unavailable. Waiting until approximately {0:u}.' -f $resetUtc) 'WARN'
    }
    Start-Sleep -Seconds $sleepSeconds
}

$ready = Get-GitHubBudgetObservation
if ($ready.Status -ne 200 -or $ready.Remaining -le 1000) {
    throw ('GitHub REST budget did not recover before the bounded deadline. Status={0}; remaining={1}.' -f $ready.Status,$ready.Remaining)
}

$active = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ProcessId -ne $PID -and -not [string]::IsNullOrWhiteSpace([string]$_.CommandLine) -and (
        $_.CommandLine -match 'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11[^\s]*\.ps1' -or
        $_.CommandLine -match 'SZL_RUN_FIXED_V11\.ps1' -or
        $_.CommandLine -match 'SZL_GO_NOW_PS51\.ps1' -or
        $_.CommandLine -match 'RUN_SZL_CTO_RATE_AWARE\.ps1'
    )
})
if ($active.Count -gt 0) {
    $detail = ($active | ForEach-Object { 'PID={0} {1}' -f $_.ProcessId,$_.CommandLine }) -join [Environment]::NewLine
    throw ('Another SZL operator/controller is active. Nothing new was started.' + [Environment]::NewLine + $detail)
}

$env:ProgramData='C:\ProgramData'
$env:SZL_MODE='FULL'
$env:SZL_APPLY='1'
$env:SZL_CONFIRM='APPLY-SZL-ESTATE-CONVERGENCE'
$env:SZL_USE_CODEX='0'
$env:SZL_INSTALL_CODEX='0'
$env:SZL_INSTALL_PREREQUISITES='1'
$env:SZL_MAX_CYCLES='1'
$env:SZL_MAX_WRITES_PER_CYCLE='1'
$env:SZL_MAX_CODEX_TASKS_PER_CYCLE='0'
$env:SZL_MAX_RUNTIME_MINUTES='180'
$env:SZL_MIN_FREE_GB='45'
$env:SZL_RESUME_LATEST='0'
$env:SZL_FIXED_POINT_CYCLES='1'
$env:SZL_POLL_SECONDS='30'
$env:SZL_AUTO_CLOSE_PROVEN_SUPERSEDED='1'
$env:SZL_MAX_SAFE_CLOSURES_PER_CYCLE='3'
$env:SZL_INSTALL_WATCHDOG='0'

$started = Get-Date
Write-RunLog 'GitHub budget recovered. Launching one bounded full convergence cycle with Codex disabled by the retained quota hold.' 'OK'
$OperatorIdentity = Resolve-SzlPinnedOperator -SourceRoot $PSScriptRoot
Assert-SzlOperatorAdmission -Identity $OperatorIdentity
$operatorExit = $LASTEXITCODE

$latest = Get-ChildItem -LiteralPath $EvidenceRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^\d{8}T\d{6}Z$' -and $_.LastWriteTime -ge $started.AddMinutes(-1) } |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if ($null -ne $latest) {
    $statePath = Join-Path $latest.FullName 'FINAL_STATE.json'
    $reportPath = Join-Path $latest.FullName 'FINAL_REPORT.md'
    Write-RunLog ('Latest run: {0}' -f $latest.FullName) 'INFO'
    if (Test-Path -LiteralPath $statePath) {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        Write-RunLog ('Final state: core_operational={0}; stop_reason={1}; critical_open_actions={2}; merge_candidates={3}' -f $state.core_operational,$state.stop_reason,$state.critical_open_actions,$state.merge_candidates_not_admitted) $(if($state.core_operational){'OK'}else{'WARN'})
    }
    if (Test-Path -LiteralPath $reportPath) { Write-RunLog ('Final report: {0}' -f $reportPath) 'INFO' }
}

$env:SZL_GITHUB_TOKEN=$null
$env:GITHUB_TOKEN=$null
$env:GH_TOKEN=$null
$env:HF_TOKEN=$null
$env:HUGGING_FACE_HUB_TOKEN=$null

if ($operatorExit -ne 0) { throw ('Estate operator returned exit code {0}. Retained evidence was preserved.' -f $operatorExit) }
Write-RunLog 'Rate-aware convergence runner completed.' 'OK'
exit 0
