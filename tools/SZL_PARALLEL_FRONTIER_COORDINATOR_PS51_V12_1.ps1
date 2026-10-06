#requires -version 5.1

throw 'SZL_SOURCE_ADMISSION_HOLD'

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'SZL_PS51_PROCESS_LIBRARY.ps1')
Assert-SzlExecutionPolicy
$ProgressPreference = 'SilentlyContinue'

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw 'Run this script in Windows PowerShell 5.1, not PowerShell 7.'
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $Identity
$AdminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $Principal.IsInRole($AdminRole)) {
    throw 'Open Windows PowerShell 5.1 with Run as administrator.'
}

$Org = 'szl-holdings'
$HfOrg = 'SZLHOLDINGS'
$EstateRoot = 'C:\ProgramData\SZL\EstateOperator'
$CoordinatorRoot = 'C:\ProgramData\SZL\ParallelFrontier'
$MinFreeGB = 50
$MaxHours = 24
$PollSeconds = 30

$RunId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$RunRoot = Join-Path $CoordinatorRoot $RunId
$EvidenceRoot = Join-Path $RunRoot 'evidence'
$LogRoot = Join-Path $RunRoot 'logs'
$EventLog = Join-Path $RunRoot 'events.jsonl'
$FinalState = Join-Path $RunRoot 'FINAL_PARALLEL_STATE.json'
$FinalReport = Join-Path $RunRoot 'FINAL_PARALLEL_REPORT.md'

New-Item -ItemType Directory -Path $RunRoot,$EvidenceRoot,$LogRoot -Force | Out-Null

function Write-JsonFile {
    param([string]$Path, $Value)
    $Json = $Value | ConvertTo-Json -Depth 40
    [System.IO.File]::WriteAllText($Path, $Json + [Environment]::NewLine, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
}

function Write-Event {
    param([string]$Event, [string]$Message, [hashtable]$Data = @{})
    $Row = [ordered]@{
        ts = [DateTime]::UtcNow.ToString('o')
        event = $Event
        message = $Message
        data = $Data
    }
    Add-Content -LiteralPath $EventLog -Value ($Row | ConvertTo-Json -Compress -Depth 12) -Encoding UTF8
    Write-Host ('[{0}] {1}: {2}' -f (Get-Date -Format 'HH:mm:ss'), $Event, $Message) -ForegroundColor Cyan
}

function Get-FreeGB {
    return [Math]::Round((Get-PSDrive -Name C -ErrorAction Stop).Free / 1GB, 2)
}

function Test-WriterActive {
    $Probe = New-Object -TypeName System.Threading.Mutex -ArgumentList $false, 'Global\SZL-Estate-Operator-PS51-V11'
    $Acquired = $false
    try {
        try { $Acquired = $Probe.WaitOne(0, $false) }
        catch [System.Threading.AbandonedMutexException] { $Acquired = $true }
        if ($Acquired) {
            try { $Probe.ReleaseMutex() | Out-Null } catch { }
            return $false
        }
        return $true
    }
    finally { $Probe.Dispose() }
}

function Get-LatestOperatorEventLog {
    if (-not (Test-Path -LiteralPath $EstateRoot -PathType Container)) { return $null }
    return Get-ChildItem -LiteralPath $EstateRoot -Filter 'operator-events.jsonl' -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
}

function Get-ResumeOperator {
    param([string]$SourceRoot = $PSScriptRoot)
    return Resolve-SzlPinnedOperator -SourceRoot $SourceRoot
}

function Read-SzlWorkerStates {
    param([AllowNull()][AllowEmptyCollection()][object[]]$Jobs)
    # Read only the supplied job objects; never discover, receive or stop jobs.
    try {
        $Rows = @()
        foreach ($Job in $Jobs) {
            if ($null -eq $Job) { throw 'WORKER_OBSERVATION_UNAVAILABLE' }
            $Name=$Job.Name; $InstanceId=$Job.InstanceId; $State=$Job.State
            if ($null -eq $Name -or $null -eq $InstanceId -or $null -eq $State) { throw 'WORKER_OBSERVATION_UNAVAILABLE' }
            $Rows += [pscustomobject]@{ Name=$Name; InstanceId=$InstanceId; State=[string]$State }
        }
        return [pscustomobject]@{ Available=$true; Workers=$Rows }
    }
    catch { return [pscustomobject]@{ Available=$false; Workers=@() } }
}

function Get-SzlWorkerClassification {
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$ExpectedWorkers,
        [AllowNull()][AllowEmptyCollection()][object[]]$ObservedWorkers
    )
    # PENDING is internal to polling; the wait function never returns it.
    try {
        if ($null -eq $ExpectedWorkers -or $ExpectedWorkers.Count -eq 0 -or
            $null -eq $ObservedWorkers -or $ObservedWorkers.Count -ne $ExpectedWorkers.Count) { return 'UNKNOWN' }
        $Names=@(); $Ids=@()
        foreach ($Expected in $ExpectedWorkers) {
            if ($Expected.Name -isnot [string] -or [string]::IsNullOrWhiteSpace($Expected.Name) -or
                $Expected.InstanceId -isnot [guid] -or $Expected.InstanceId -eq [guid]::Empty -or
                $Names -ccontains $Expected.Name -or $Ids -contains $Expected.InstanceId) { return 'UNKNOWN' }
            $Names += $Expected.Name; $Ids += $Expected.InstanceId
        }
        $SeenNames=@(); $SeenIds=@(); $Pending=$false; $Failed=$false; $Unknown=$false
        foreach ($Observed in $ObservedWorkers) {
            if ($Observed.Name -isnot [string] -or $Observed.InstanceId -isnot [guid] -or
                $SeenNames -ccontains $Observed.Name -or $SeenIds -contains $Observed.InstanceId) { return 'UNKNOWN' }
            $Match=@($ExpectedWorkers | Where-Object { $_.Name -ceq $Observed.Name -and $_.InstanceId -eq $Observed.InstanceId })
            if ($Match.Count -ne 1) { return 'UNKNOWN' }
            $SeenNames += $Observed.Name; $SeenIds += $Observed.InstanceId
            if ($Observed.State -isnot [string]) { $Unknown=$true }
            elseif ($Observed.State -ceq 'Completed') { }
            elseif ($Observed.State -cin @('Failed','Stopped')) { $Failed=$true }
            elseif ($Observed.State -cin @('NotStarted','Running')) { $Pending=$true }
            else { $Unknown=$true }
        }
        # Incomplete or unsupported observations take precedence over other states.
        if ($Unknown) { return 'UNKNOWN' }
        if ($Failed) { return 'FAILED' }
        if ($Pending) { return 'PENDING' }
        return 'COMPLETED'
    }
    catch { return 'UNKNOWN' }
}

function Wait-SzlWorkerCompletion {
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Jobs,
        [AllowNull()][AllowEmptyCollection()][object[]]$ExpectedWorkerNames,
        [ValidateRange(1,2147483)][int]$BudgetSeconds = 86400,
        [ValidateRange(1,2147483)][int]$PollSeconds = 30,
        $Clock = ([Diagnostics.Stopwatch]::StartNew())
    )
    try {
        $null = Get-SzlRemainingMilliseconds -BudgetSeconds $BudgetSeconds -ElapsedMilliseconds $Clock.ElapsedMilliseconds
        if ($null -eq $ExpectedWorkerNames -or $ExpectedWorkerNames.Count -eq 0) { return 'UNKNOWN' }
        $Names=@()
        foreach ($Name in $ExpectedWorkerNames) {
            if ($Name -isnot [string] -or [string]::IsNullOrWhiteSpace($Name) -or $Names -ccontains $Name) { return 'UNKNOWN' }
            $Names += $Name
        }
        $Observation = Read-SzlWorkerStates -Jobs $Jobs
        $null = Get-SzlRemainingMilliseconds -BudgetSeconds $BudgetSeconds -ElapsedMilliseconds $Clock.ElapsedMilliseconds
        if (-not $Observation.Available -or $Observation.Workers.Count -ne $Names.Count) { return 'UNKNOWN' }
        # Freeze the identity associated with each declared name once. Subsequent
        # observations must cover precisely this set, even if a job object changes.
        $Expected=@()
        foreach ($Name in $Names) {
            $Match=@($Observation.Workers | Where-Object { $_.Name -ceq $Name })
            if ($Match.Count -ne 1) { return 'UNKNOWN' }
            $Expected += [pscustomobject]@{ Name=$Name; InstanceId=$Match[0].InstanceId }
        }
        while ($true) {
            $null = Get-SzlRemainingMilliseconds -BudgetSeconds $BudgetSeconds -ElapsedMilliseconds $Clock.ElapsedMilliseconds
            if (-not $Observation.Available) { return 'UNKNOWN' }
            $Classification = Get-SzlWorkerClassification -ExpectedWorkers $Expected -ObservedWorkers $Observation.Workers
            $Remaining = Get-SzlRemainingMilliseconds -BudgetSeconds $BudgetSeconds -ElapsedMilliseconds $Clock.ElapsedMilliseconds
            if ($Classification -cne 'PENDING') { return $Classification }
            Start-Sleep -Milliseconds ([int][Math]::Min($PollSeconds * 1000.0, $Remaining))
            $null = Get-SzlRemainingMilliseconds -BudgetSeconds $BudgetSeconds -ElapsedMilliseconds $Clock.ElapsedMilliseconds
            $Observation = Read-SzlWorkerStates -Jobs $Jobs
        }
    }
    catch {
        if ($_.Exception.Message -ceq 'SZL_DEADLINE_EXPIRED') { return 'TIMED_OUT' }
        return 'UNKNOWN'
    }
}

function Assert-SzlWorkerCompletion {
    param([AllowNull()]$Outcome)
    if ($Outcome -is [string] -and $Outcome -ceq 'COMPLETED') { return }
    $Reason=if ($Outcome -is [string] -and $Outcome -cin @('FAILED','UNKNOWN','TIMED_OUT')) { $Outcome } else { 'UNKNOWN' }
    throw ('SZL_WORKER_WAIT_HOLD: '+$Reason)
}

$CoordinatorMutex = New-Object -TypeName System.Threading.Mutex -ArgumentList $false, 'Global\SZL-Parallel-Frontier-Coordinator-V12-1'
$CoordinatorLock = $false
try {
    try { $CoordinatorLock = $CoordinatorMutex.WaitOne(0, $false) }
    catch [System.Threading.AbandonedMutexException] { $CoordinatorLock = $true }
    if (-not $CoordinatorLock) { throw 'Another SZL parallel coordinator is already running.' }

    Write-Event 'coordinator_started' 'Parallel read-only audit and safe cleanup started.' @{
        run_root = $RunRoot
        writer_active = Test-WriterActive
        free_gb = Get-FreeGB
    }

    $Gh = Get-Command gh.exe -ErrorAction SilentlyContinue
    if (-not $Gh) { throw 'gh.exe is unavailable.' }

    $Jobs = @()

    $Jobs += Start-Job -Name 'github-observer' -ArgumentList $Gh.Source,$Org,$EvidenceRoot -ScriptBlock {
        param($GhExe,$Organization,$OutRoot)
        $ErrorActionPreference = 'Stop'
        function Invoke-GhJson {
            param([string[]]$Arguments)
            $Output = @(& $GhExe @Arguments 2>&1)
            if ($LASTEXITCODE -ne 0) { throw (($Output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine) }
            $Text = (($Output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine)
            if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
            return $Text | ConvertFrom-Json
        }
        $Repos = @(Invoke-GhJson @('repo','list',$Organization,'--limit','1000','--json','name,nameWithOwner,visibility,isArchived,defaultBranchRef,pushedAt,url'))
        if ($Repos.Count -eq 1 -and $Repos[0] -is [System.Array]) { $Repos = @($Repos[0]) }
        $PrSearch = Invoke-GhJson @('api','--method','GET','search/issues','-f',('q=org:{0} is:pr is:open' -f $Organization),'-f','per_page=100')
        $IssueSearch = Invoke-GhJson @('api','--method','GET','search/issues','-f',('q=org:{0} is:issue is:open' -f $Organization),'-f','per_page=1')
        $Pulls = @()
        foreach ($Item in @($PrSearch.items)) {
            $Repo = ([string]$Item.repository_url).Split('/')[-1]
            try {
                $Pulls += Invoke-GhJson @('pr','view',[string]$Item.number,'--repo',($Organization + '/' + $Repo),'--json','number,title,url,state,isDraft,headRefName,headRefOid,baseRefName,baseRefOid,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup,files,commits,reviews,updatedAt,author')
            }
            catch {
                $Pulls += [pscustomobject]@{ repository = $Repo; number = $Item.number; error = $_.Exception.Message }
            }
        }
        $Result = [ordered]@{
            schema = 'szl.parallel.github-observation/v1'
            observed_at = [DateTime]::UtcNow.ToString('o')
            organization = $Organization
            repository_count = @($Repos).Count
            open_pull_request_count = [int]$PrSearch.total_count
            open_issue_count = [int]$IssueSearch.total_count
            repositories = $Repos
            pull_requests = $Pulls
            mutation_performed = $false
            secret_values_recorded = $false
        }
        $Result | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath (Join-Path $OutRoot 'github-observation.json') -Encoding UTF8
    }

    $Jobs += Start-Job -Name 'hf-observer' -ArgumentList $HfOrg,$EvidenceRoot -ScriptBlock {
        param($Organization,$OutRoot)
        $ErrorActionPreference = 'Stop'
        $Token = $env:HF_TOKEN
        if ([string]::IsNullOrWhiteSpace($Token)) {
            foreach ($Path in @(
                (Join-Path $HOME '.cache\huggingface\token'),
                (Join-Path $HOME '.huggingface\token')
            )) {
                if (Test-Path -LiteralPath $Path -PathType Leaf) {
                    $Value = (Get-Content -LiteralPath $Path -Raw).Trim()
                    if (-not [string]::IsNullOrWhiteSpace($Value)) { $Token = $Value; break }
                }
            }
        }
        $Headers = @{ 'User-Agent' = 'szl-parallel-hf-observer/1' }
        if (-not [string]::IsNullOrWhiteSpace($Token)) { $Headers.Authorization = 'Bearer ' + $Token }
        function Get-HfJson {
            param([string]$Url)
            try { return Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get -TimeoutSec 45 -ErrorAction Stop }
            catch { return [pscustomobject]@{ error = $_.Exception.GetType().Name; message = $_.Exception.Message } }
        }
        $Models = @(Get-HfJson ('https://huggingface.co/api/models?author=' + $Organization + '&limit=1000&full=true'))
        $Datasets = @(Get-HfJson ('https://huggingface.co/api/datasets?author=' + $Organization + '&limit=1000&full=true'))
        $Spaces = @(Get-HfJson ('https://huggingface.co/api/spaces?author=' + $Organization + '&limit=1000&full=true'))
        $Flagships = @('a11oy','killinchu','immune','szl-atelier','llm-router-live','szl-command-lab')
        $Runtime = @()
        foreach ($Name in $Flagships) {
            $Id = $Organization + '/' + $Name
            $Runtime += [ordered]@{
                id = $Id
                detail = Get-HfJson ('https://huggingface.co/api/spaces/' + $Id)
                runtime = Get-HfJson ('https://huggingface.co/api/spaces/' + $Id + '/runtime')
            }
        }
        $Result = [ordered]@{
            schema = 'szl.parallel.hf-observation/v1'
            observed_at = [DateTime]::UtcNow.ToString('o')
            organization = $Organization
            authenticated_token_present = -not [string]::IsNullOrWhiteSpace($Token)
            model_count = @($Models | Where-Object { -not $_.error }).Count
            dataset_count = @($Datasets | Where-Object { -not $_.error }).Count
            space_count = @($Spaces | Where-Object { -not $_.error }).Count
            models = $Models
            datasets = $Datasets
            spaces = $Spaces
            flagship_runtime = $Runtime
            mutation_performed = $false
            secret_values_recorded = $false
        }
        $Result | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath (Join-Path $OutRoot 'huggingface-observation.json') -Encoding UTF8
        $Token = $null
    }

    $Jobs += Start-Job -Name 'domain-observer' -ArgumentList $EvidenceRoot -ScriptBlock {
        param($OutRoot)
        $ErrorActionPreference = 'Continue'
        $Targets = @(
            'https://a-11-oy.com/',
            'https://a-11-oy.com/api/a11oy/v1/honest',
            'https://a-11-oy.com/api/livez',
            'https://a-11-oy.com/api/readyz',
            'https://a11oy.net/',
            'https://a11oy.net/models.json',
            'https://szlholdings.com/'
        )
        $Rows = @()
        foreach ($Url in $Targets) {
            try {
                $Response = Invoke-WebRequest -Uri $Url -Method Get -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 30 -ErrorAction Stop
                $Rows += [ordered]@{
                    url = $Url
                    status = [int]$Response.StatusCode
                    final_url = [string]$Response.BaseResponse.ResponseUri
                    content_type = [string]$Response.Headers['Content-Type']
                    content_security_policy = -not [string]::IsNullOrWhiteSpace([string]$Response.Headers['Content-Security-Policy'])
                    referrer_policy = -not [string]::IsNullOrWhiteSpace([string]$Response.Headers['Referrer-Policy'])
                    hsts = -not [string]::IsNullOrWhiteSpace([string]$Response.Headers['Strict-Transport-Security'])
                }
            }
            catch {
                $Status = 0
                try { $Status = [int]$_.Exception.Response.StatusCode.value__ } catch { }
                $Rows += [ordered]@{ url = $Url; status = $Status; error = $_.Exception.GetType().Name }
            }
        }
        $Result = [ordered]@{
            schema = 'szl.parallel.domain-observation/v1'
            observed_at = [DateTime]::UtcNow.ToString('o')
            probes = $Rows
            mutation_performed = $false
            secret_values_recorded = $false
        }
        $Result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutRoot 'domain-observation.json') -Encoding UTF8
    }

    $Jobs += Start-Job -Name 'safe-cleanup' -ArgumentList $EstateRoot,$CoordinatorRoot,$RunRoot,$EvidenceRoot -ScriptBlock {
        param($OperatorRoot,$CoordRoot,$CurrentRun,$OutRoot)
        $ErrorActionPreference = 'Continue'
        function FreeGB { [Math]::Round((Get-PSDrive C).Free / 1GB, 2) }
        $Before = FreeGB
        try { Clear-RecycleBin -DriveLetter C -Force -ErrorAction Stop } catch { }
        $Cutoff = (Get-Date).AddDays(-7)
        foreach ($Root in @($env:TEMP,($env:WINDIR + '\Temp'),'C:\ProgramData\Microsoft\Windows\WER\ReportArchive','C:\ProgramData\Microsoft\Windows\WER\ReportQueue')) {
            if (Test-Path -LiteralPath $Root -PathType Container) {
                Get-ChildItem -LiteralPath $Root -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -lt $Cutoff } |
                    ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop } catch { } }
            }
        }
        try { Delete-DeliveryOptimizationCache -Force -ErrorAction Stop } catch { }
        foreach ($Root in @($OperatorRoot,$CoordRoot)) {
            if (Test-Path -LiteralPath $Root -PathType Container) {
                $Runs = @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\d{8}T\d{6}Z$' } | Sort-Object LastWriteTimeUtc -Descending)
                $Keep = @($Runs | Select-Object -First 8 | ForEach-Object { $_.FullName })
                foreach ($Run in $Runs) {
                    if ($Run.FullName -ne $CurrentRun -and $Keep -notcontains $Run.FullName -and $Run.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddDays(-1)) {
                        try { Remove-Item -LiteralPath $Run.FullName -Recurse -Force -ErrorAction Stop } catch { }
                    }
                }
            }
        }
        $After = FreeGB
        $Result = [ordered]@{
            schema = 'szl.parallel.safe-cleanup/v1'
            observed_at = [DateTime]::UtcNow.ToString('o')
            free_before_gb = $Before
            free_after_gb = $After
            recovered_gb = [Math]::Round($After - $Before, 2)
            active_run_touched = $false
            credentials_touched = $false
            personal_files_deleted = $false
        }
        $Result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutRoot 'safe-cleanup.json') -Encoding UTF8
    }

    Write-Event 'parallel_workers_started' 'GitHub, Hugging Face, domain, and cleanup workers are running.' @{
        jobs = @($Jobs | ForEach-Object { $_.Name })
        writer_active = Test-WriterActive
        free_gb = Get-FreeGB
    }

    $WorkerWaitOutcome = Wait-SzlWorkerCompletion -Jobs $Jobs -ExpectedWorkerNames @('github-observer','hf-observer','domain-observer','safe-cleanup') -BudgetSeconds ($MaxHours * 3600) -PollSeconds $PollSeconds
    Assert-SzlWorkerCompletion -Outcome $WorkerWaitOutcome

    $JobSummary = @()
    foreach ($Job in $Jobs) {
        $Output = @(Receive-Job -Job $Job -ErrorAction SilentlyContinue)
        $JobSummary += [ordered]@{
            name = $Job.Name
            state = [string]$Job.State
            output = @($Output | ForEach-Object { [string]$_ })
        }
        Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
    }
    Write-JsonFile (Join-Path $EvidenceRoot 'parallel-job-summary.json') $JobSummary
    Write-Event 'parallel_workers_complete' 'All read-only/cleanup workers returned control.' @{ free_gb = Get-FreeGB }

    $Deadline = (Get-Date).AddHours($MaxHours)
    while ((Test-WriterActive) -and (Get-Date) -lt $Deadline) {
        Write-Host ('[{0}] waiting for active mutation operator; free_gb={1}' -f (Get-Date -Format 'HH:mm:ss'), (Get-FreeGB)) -ForegroundColor Yellow
        Start-Sleep -Seconds 60
    }

    $ResumeDisposition = 'NOT_STARTED'
    if (Test-WriterActive) {
        $ResumeDisposition = 'BLOCKED_ACTIVE_WRITER_TIMEOUT'
    }
    elseif ((Get-FreeGB) -lt $MinFreeGB) {
        $ResumeDisposition = 'BLOCKED_DISK_FLOOR'
    }
    else {
        $OperatorIdentity = $null
        try { $OperatorIdentity = Get-ResumeOperator }
        catch { Write-Event -Event 'operator_identity_rejected' -Message $_.Exception.Message }
        if (-not $OperatorIdentity) {
            $ResumeDisposition = 'BLOCKED_OPERATOR_IDENTITY'
        }
        else {
            $Operator = $OperatorIdentity.Path
            $PythonExe = 'C:\Users\steph\AppData\Local\Programs\Python\Python312\python.exe'
            if (Test-Path -LiteralPath $PythonExe -PathType Leaf) {
                $env:SZL_PYTHON_EXE = $PythonExe
                $env:Path = (Split-Path -Parent $PythonExe) + ';' + (Join-Path (Split-Path -Parent $PythonExe) 'Scripts') + ';' + $env:Path
            }
            $env:SZL_MODE = 'FULL'
            $env:SZL_APPLY = '1'
            $env:SZL_CONFIRM = 'APPLY-SZL-ESTATE-CONVERGENCE'
            $env:SZL_INSTALL_PREREQUISITES = '1'
            $env:SZL_USE_CODEX = '0'
            $env:SZL_INSTALL_CODEX = '0'
            $env:SZL_MAX_CODEX_TASKS_PER_CYCLE = '0'
            $env:SZL_RESUME_LATEST = '1'
            $env:SZL_MAX_CYCLES = '12'
            $env:SZL_MAX_RUNTIME_MINUTES = '1440'
            $env:SZL_MAX_WRITES_PER_CYCLE = '1'
            $env:SZL_MAX_SAFE_CLOSURES_PER_CYCLE = '3'
            $env:SZL_FIXED_POINT_CYCLES = '3'
            $env:SZL_POLL_SECONDS = '60'
            $env:SZL_MIN_FREE_GB = [string]$MinFreeGB
            $env:SZL_AUTO_CLOSE_PROVEN_SUPERSEDED = '1'
            $env:SZL_INSTALL_WATCHDOG = '0'
            Write-Event 'serialized_resume_started' 'Active writer finished and disk floor is met; starting exactly one convergence resume.' @{ operator = $Operator; free_gb = Get-FreeGB }
            try {
                $OperatorIdentity = Get-ResumeOperator
                Assert-SzlOperatorAdmission -Identity $OperatorIdentity
                $ResumeDisposition = if ($?) { 'RETURNED_SUCCESS' } else { 'RETURNED_UNSUCCESSFUL' }
            }
            catch {
                $ResumeDisposition = 'EXCEPTION: ' + $_.Exception.Message
            }
        }
    }

    $State = [ordered]@{
        schema = 'szl.parallel.frontier-coordinator/v12.1'
        completed_at = [DateTime]::UtcNow.ToString('o')
        run_root = $RunRoot
        writer_active = Test-WriterActive
        free_gb = Get-FreeGB
        minimum_free_gb = $MinFreeGB
        resume_disposition = $ResumeDisposition
        github_observation = Join-Path $EvidenceRoot 'github-observation.json'
        huggingface_observation = Join-Path $EvidenceRoot 'huggingface-observation.json'
        domain_observation = Join-Path $EvidenceRoot 'domain-observation.json'
        cleanup_observation = Join-Path $EvidenceRoot 'safe-cleanup.json'
        direct_main_push = $false
        force_push = $false
        manual_hf_upload = $false
        secret_values_recorded = $false
    }
    Write-JsonFile $FinalState $State

    $Report = @(
        '# SZL Parallel Frontier Coordinator V12.1',
        '',
        ('- Run root: `{0}`' -f $RunRoot),
        ('- Free space: `{0} GB`' -f $State.free_gb),
        ('- Writer active: `{0}`' -f $State.writer_active),
        ('- Resume disposition: `{0}`' -f $ResumeDisposition),
        '',
        'Read-only GitHub, Hugging Face, and public-domain observations ran in parallel with safe cleanup. Exactly one serialized estate resume was permitted after the active writer exited and the disk floor was met.'
    )
    [System.IO.File]::WriteAllLines($FinalReport, $Report, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))

    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Green
    Write-Host ' SZL PARALLEL FRONTIER COORDINATOR RETURNED CONTROL' -ForegroundColor Green
    Write-Host '============================================================' -ForegroundColor Green
    Write-Host ('Evidence: {0}' -f $RunRoot) -ForegroundColor Cyan
    Write-Host ('Resume disposition: {0}' -f $ResumeDisposition) -ForegroundColor Cyan
    Write-Host ('Free space: {0} GB' -f (Get-FreeGB)) -ForegroundColor Cyan
}
finally {
    if ($CoordinatorLock) {
        try { $CoordinatorMutex.ReleaseMutex() | Out-Null } catch { }
    }
    $CoordinatorMutex.Dispose()
}
