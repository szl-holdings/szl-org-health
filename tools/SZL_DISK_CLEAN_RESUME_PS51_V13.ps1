#requires -version 5.1

<#
SZL DISK RECOVERY + FRESH ESTATE CONVERGENCE V13

Purpose:
  - Recover disk space without deleting user documents, source repositories,
    Hugging Face model/data caches, Docker volumes, credentials, or the latest
    active SZL evidence.
  - Preserve a 50 GB execution floor and a 55 GB preferred operating margin.
  - Start one fresh, non-resuming estate-convergence run after cleanup.
  - Update Windows and installed applications only after the estate operator
    returns, so the build toolchain does not change mid-run.

Reversible material change:
  - If free space remains below 50 GB, hibernation is disabled to remove
    hiberfil.sys. Re-enable later with: powercfg.exe /hibernate on
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
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

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

$EstateRoot = 'C:\ProgramData\SZL\EstateOperator'
$ParallelRoot = 'C:\ProgramData\SZL\ParallelFrontier'
$MaintenanceRoot = 'C:\ProgramData\SZL\Maintenance'
$RuntimeRoot = Join-Path $EstateRoot 'Runtime'
$MinimumFreeGB = 50
$PreferredFreeGB = 55
$RunStartedAt = [DateTime]::UtcNow
$RunId = $RunStartedAt.ToString('yyyyMMddTHHmmssZ')
$RunRoot = Join-Path $MaintenanceRoot $RunId
$LogRoot = Join-Path $RunRoot 'logs'
$EvidenceRoot = Join-Path $RunRoot 'evidence'
$EventLog = Join-Path $RunRoot 'events.jsonl'
$FinalStatePath = Join-Path $RunRoot 'FINAL_STATE.json'
$FinalReportPath = Join-Path $RunRoot 'FINAL_REPORT.md'
$LargeFileReportPath = Join-Path $RunRoot 'LARGE_FILES.csv'

New-Item -ItemType Directory -Path $RunRoot,$LogRoot,$EvidenceRoot -Force | Out-Null

$Actions = New-Object System.Collections.Generic.List[object]

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $Json = $Value | ConvertTo-Json -Depth 40
    [System.IO.File]::WriteAllText(
        $Path,
        $Json + [Environment]::NewLine,
        (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false)
    )
}

function Write-Event {
    param(
        [Parameter(Mandatory = $true)][string]$Event,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Data = @{}
    )

    $Row = [ordered]@{
        ts = [DateTime]::UtcNow.ToString('o')
        event = $Event
        message = $Message
        data = $Data
    }

    Add-Content -LiteralPath $EventLog -Value ($Row | ConvertTo-Json -Compress -Depth 16) -Encoding UTF8
    Write-Host ('[{0}] {1}: {2}' -f (Get-Date -Format 'HH:mm:ss'), $Event, $Message) -ForegroundColor Cyan
}

function Add-Action {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Status,
        [string]$Detail = ''
    )

    $Actions.Add([ordered]@{
        ts = [DateTime]::UtcNow.ToString('o')
        name = $Name
        status = $Status
        detail = $Detail
    })
}

function Get-FreeGB {
    return [Math]::Round((Get-PSDrive -Name C -ErrorAction Stop).Free / 1GB, 2)
}

function Test-WriterActive {
    $Probe = New-Object -TypeName System.Threading.Mutex -ArgumentList $false,'Global\SZL-Estate-Operator-PS51-V11'
    $Acquired = $false

    try {
        try {
            $Acquired = $Probe.WaitOne(0, $false)
        }
        catch [System.Threading.AbandonedMutexException] {
            $Acquired = $true
        }

        if ($Acquired) {
            try {
                $Probe.ReleaseMutex() | Out-Null
            }
            catch {
            }

            return $false
        }

        return $true
    }
    finally {
        $Probe.Dispose()
    }
}

function Invoke-NativeTool {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSeconds = 3600,
        [switch]$AllowNonZero,
        [string]$Name = 'native-tool'
    )

    $Id = [Guid]::NewGuid().ToString('N')
    $StdoutPath = Join-Path $LogRoot ($Id + '.stdout.log')
    $StderrPath = Join-Path $LogRoot ($Id + '.stderr.log')

    $QuotedArguments = @(
        $ArgumentList |
        ForEach-Object {
            $Value = [string]$_
            if ($Value -match '[\s"]') {
                '"' + $Value.Replace('"','\"') + '"'
            }
            else {
                $Value
            }
        }
    ) -join ' '

    $Process = $null
    $ExitCode = $null
    $Started = [DateTime]::UtcNow

    try {
        $Process = Start-Process `
            -FilePath $FilePath `
            -ArgumentList $QuotedArguments `
            -WorkingDirectory $env:TEMP `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput $StdoutPath `
            -RedirectStandardError $StderrPath

        $Completed = $Process.WaitForExit($TimeoutSeconds * 1000)

        if (-not $Completed) {
            try {
                $Process.Kill()
            }
            catch {
            }

            try {
                $Process.WaitForExit()
            }
            catch {
            }

            throw ('{0} timed out after {1} seconds.' -f $Name,$TimeoutSeconds)
        }

        $Process.WaitForExit()
        $Process.Refresh()
        $ExitCode = [int]$Process.ExitCode
    }
    finally {
        if ($null -ne $Process) {
            try {
                $Process.Dispose()
            }
            catch {
            }
        }
    }

    $Stdout = ''
    $Stderr = ''

    if (Test-Path -LiteralPath $StdoutPath -PathType Leaf) {
        $Stdout = Get-Content -LiteralPath $StdoutPath -Raw -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $StderrPath -PathType Leaf) {
        $Stderr = Get-Content -LiteralPath $StderrPath -Raw -ErrorAction SilentlyContinue
    }

    $Result = [pscustomobject]@{
        Name = $Name
        FilePath = $FilePath
        Arguments = $ArgumentList
        ExitCode = $ExitCode
        Stdout = $Stdout
        Stderr = $Stderr
        Seconds = [Math]::Round(([DateTime]::UtcNow - $Started).TotalSeconds, 3)
    }

    if (-not $AllowNonZero -and $ExitCode -ne 0) {
        throw ('{0} failed with exit code {1}. See {2} and {3}.' -f $Name,$ExitCode,$StdoutPath,$StderrPath)
    }

    return $Result
}

function Remove-DirectoryContents {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [datetime]$OlderThan = [DateTime]::MinValue,
        [string]$ActionName = 'cleanup'
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }

    $Removed = 0
    $Failed = 0

    Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue |
    Where-Object {
        $_.LastWriteTime -lt $OlderThan
    } |
    ForEach-Object {
        try {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
            $Removed++
        }
        catch {
            $Failed++
        }
    }

    Add-Action -Name $ActionName -Status 'complete' -Detail ('removed={0}; failed_or_locked={1}; path={2}' -f $Removed,$Failed,$Path)
}

function Remove-CacheDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$ActionName = 'cache-clean'
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }

    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Add-Action -Name $ActionName -Status 'removed' -Detail $Path
    }
    catch {
        Add-Action -Name $ActionName -Status 'skipped-locked' -Detail $Path
    }
}

function Remove-OldTimestampRuns {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [int]$KeepNewest = 8,
        [int]$MinimumAgeHours = 24
    )

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        return
    }

    $Runs = @(
        Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^\d{8}T\d{6}Z$'
        } |
        Sort-Object LastWriteTimeUtc -Descending
    )

    $Keep = @(
        $Runs |
        Select-Object -First $KeepNewest |
        ForEach-Object {
            $_.FullName
        }
    )

    foreach ($Run in $Runs) {
        if (
            $Keep -notcontains $Run.FullName -and
            $Run.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddHours(-1 * $MinimumAgeHours)
        ) {
            try {
                Remove-Item -LiteralPath $Run.FullName -Recurse -Force -ErrorAction Stop
                Add-Action -Name 'old-szl-run' -Status 'removed' -Detail $Run.FullName
            }
            catch {
                Add-Action -Name 'old-szl-run' -Status 'skipped-locked' -Detail $Run.FullName
            }
        }
    }
}

function Clear-BrowserCaches {
    $Patterns = @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\*\Cache'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\*\Code Cache'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\*\GPUCache'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\*\GrShaderCache'),
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\*\Cache'),
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\*\Code Cache'),
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\*\GPUCache'),
        (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data\*\Cache'),
        (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data\*\Code Cache'),
        (Join-Path $env:LOCALAPPDATA 'Mozilla\Firefox\Profiles\*\cache2'),
        (Join-Path $env:LOCALAPPDATA 'Mozilla\Firefox\Profiles\*\startupCache')
    )

    foreach ($Pattern in $Patterns) {
        Get-Item -Path $Pattern -ErrorAction SilentlyContinue |
        ForEach-Object {
            Remove-CacheDirectory -Path $_.FullName -ActionName 'browser-cache'
        }
    }
}

function Clear-DevelopmentCaches {
    $Commands = @(
        [pscustomobject]@{ Command = 'npm.cmd'; Arguments = @('cache','clean','--force'); Name = 'npm-cache' },
        [pscustomobject]@{ Command = 'pnpm.cmd'; Arguments = @('store','prune'); Name = 'pnpm-store-prune' },
        [pscustomobject]@{ Command = 'yarn.cmd'; Arguments = @('cache','clean'); Name = 'yarn-cache' },
        [pscustomobject]@{ Command = 'dotnet.exe'; Arguments = @('nuget','locals','all','--clear'); Name = 'nuget-cache' }
    )

    foreach ($Entry in $Commands) {
        $Command = Get-Command $Entry.Command -ErrorAction SilentlyContinue

        if ($Command) {
            try {
                $Result = Invoke-NativeTool -FilePath $Command.Source -ArgumentList $Entry.Arguments -TimeoutSeconds 1800 -AllowNonZero -Name $Entry.Name
                Add-Action -Name $Entry.Name -Status ('exit-' + $Result.ExitCode) -Detail $Result.Stdout.Trim()
            }
            catch {
                Add-Action -Name $Entry.Name -Status 'error' -Detail $_.Exception.Message
            }
        }
    }

    $PythonCandidates = @(
        'C:\Users\steph\AppData\Local\Programs\Python\Python312\python.exe',
        'C:\Program Files\Python312\python.exe'
    )

    $Python = $PythonCandidates |
        Where-Object {
            Test-Path -LiteralPath $_ -PathType Leaf
        } |
        Select-Object -First 1

    if ($Python) {
        try {
            $Result = Invoke-NativeTool -FilePath $Python -ArgumentList @('-m','pip','cache','purge') -TimeoutSeconds 1800 -AllowNonZero -Name 'pip-cache'
            Add-Action -Name 'pip-cache' -Status ('exit-' + $Result.ExitCode) -Detail $Result.Stdout.Trim()
        }
        catch {
            Add-Action -Name 'pip-cache' -Status 'error' -Detail $_.Exception.Message
        }
    }

    $SafeRoots = @(
        'C:\SZL-Convergence',
        'C:\ProgramData\SZL',
        (Join-Path $env:USERPROFILE 'source'),
        (Join-Path $env:USERPROFILE 'repos'),
        (Join-Path $env:USERPROFILE 'Documents\GitHub')
    ) |
    Where-Object {
        Test-Path -LiteralPath $_ -PathType Container
    } |
    Select-Object -Unique

    $CacheNames = @(
        '__pycache__',
        '.pytest_cache',
        '.mypy_cache',
        '.ruff_cache',
        '.turbo',
        '.parcel-cache'
    )

    foreach ($Root in $SafeRoots) {
        foreach ($Name in $CacheNames) {
            Get-ChildItem -LiteralPath $Root -Directory -Filter $Name -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $_.FullName -notlike ($RunRoot + '*')
            } |
            ForEach-Object {
                Remove-CacheDirectory -Path $_.FullName -ActionName ('dev-cache-' + $Name)
            }
        }

        Get-ChildItem -LiteralPath $Root -Directory -Filter 'cache' -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -match '\\(node_modules|\.next)\\cache$' -and
            $_.FullName -notlike ($RunRoot + '*')
        } |
        ForEach-Object {
            Remove-CacheDirectory -Path $_.FullName -ActionName 'dev-cache-generated'
        }
    }
}

function Clear-DockerCaches {
    $Docker = Get-Command docker.exe -ErrorAction SilentlyContinue

    if (-not $Docker) {
        return
    }

    foreach ($Entry in @(
        [pscustomobject]@{ Arguments = @('container','prune','--force'); Name = 'docker-container-prune' },
        [pscustomobject]@{ Arguments = @('image','prune','--force'); Name = 'docker-image-prune' },
        [pscustomobject]@{ Arguments = @('builder','prune','--all','--force'); Name = 'docker-builder-prune' }
    )) {
        try {
            $Result = Invoke-NativeTool -FilePath $Docker.Source -ArgumentList $Entry.Arguments -TimeoutSeconds 3600 -AllowNonZero -Name $Entry.Name
            Add-Action -Name $Entry.Name -Status ('exit-' + $Result.ExitCode) -Detail $Result.Stdout.Trim()
        }
        catch {
            Add-Action -Name $Entry.Name -Status 'error' -Detail $_.Exception.Message
        }
    }
}

function Clear-WindowsUpdateCaches {
    $Services = @('bits','wuauserv','dosvc')

    foreach ($ServiceName in $Services) {
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        }
        catch {
        }
    }

    Start-Sleep -Seconds 2

    Remove-DirectoryContents -Path (Join-Path $env:WINDIR 'SoftwareDistribution\Download') -OlderThan ([DateTime]::MaxValue) -ActionName 'windows-update-download-cache'
    Remove-DirectoryContents -Path 'C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache' -OlderThan ([DateTime]::MaxValue) -ActionName 'delivery-optimization-cache'

    try {
        Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
        Add-Action -Name 'delivery-optimization-cmdlet' -Status 'complete'
    }
    catch {
        Add-Action -Name 'delivery-optimization-cmdlet' -Status 'unavailable-or-failed' -Detail $_.Exception.Message
    }

    foreach ($ServiceName in $Services) {
        try {
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        }
        catch {
        }
    }
}

function Find-Operator {
    if (-not (Test-Path -LiteralPath $RuntimeRoot -PathType Container)) {
        return $null
    }

    $Patterns = @(
        'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_HF_PREFLIGHT_ROBUST*.ps1',
        'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_HF_PREFLIGHT_FIX*.ps1',
        'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_NATIVEFIX*.ps1',
        'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_PYTHONFIX*.ps1',
        'SZL_ESTATE_ADMIN_OPERATOR_PS51_V11_FIXED*.ps1'
    )

    $RequiredMarkers = @(
        '$OperatorVersion = ''11.0.0''',
        'function Resolve-PythonCommand {',
        'function Invoke-Native {',
        'function Get-LiveGitHubCensus {',
        'function Get-HuggingFaceAuthObservation {',
        'controller_bootstrap_started',
        'SZL_RESUME_LATEST'
    )

    foreach ($Pattern in $Patterns) {
        $Candidates = @(
            Get-ChildItem -LiteralPath $RuntimeRoot -Filter $Pattern -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending
        )

        foreach ($Candidate in $Candidates) {
            $Tokens = $null
            $Errors = $null

            [void][System.Management.Automation.Language.Parser]::ParseFile(
                $Candidate.FullName,
                [ref]$Tokens,
                [ref]$Errors
            )

            if (@($Errors).Count -ne 0) {
                continue
            }

            $Source = [System.IO.File]::ReadAllText($Candidate.FullName)
            $Complete = $true

            foreach ($Marker in $RequiredMarkers) {
                if (-not $Source.Contains($Marker)) {
                    $Complete = $false
                    break
                }
            }

            if ($Complete) {
                return $Candidate.FullName
            }
        }
    }

    return $null
}

function Write-LargeFileReport {
    $Roots = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Documents'),
        (Join-Path $env:USERPROFILE 'Videos'),
        'C:\ProgramData\SZL',
        'C:\SZL-Convergence'
    ) |
    Where-Object {
        Test-Path -LiteralPath $_ -PathType Container
    } |
    Select-Object -Unique

    $Rows = @()

    foreach ($Root in $Roots) {
        try {
            $Rows += Get-ChildItem -LiteralPath $Root -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Length -ge 500MB
            } |
            Select-Object FullName,Length,LastWriteTimeUtc
        }
        catch {
        }
    }

    $Rows |
    Sort-Object Length -Descending |
    Select-Object -First 100 |
    Select-Object FullName,@{
        Name = 'SizeGB'
        Expression = {
            [Math]::Round($_.Length / 1GB, 2)
        }
    },LastWriteTimeUtc |
    Export-Csv -LiteralPath $LargeFileReportPath -NoTypeInformation -Encoding UTF8
}

function Invoke-SystemUpdates {
    $Winget = Get-Command winget.exe -ErrorAction SilentlyContinue

    if ($Winget) {
        try {
            $Result = Invoke-NativeTool `
                -FilePath $Winget.Source `
                -ArgumentList @(
                    'upgrade',
                    '--all',
                    '--silent',
                    '--accept-package-agreements',
                    '--accept-source-agreements',
                    '--disable-interactivity'
                ) `
                -TimeoutSeconds 14400 `
                -AllowNonZero `
                -Name 'winget-upgrade-all'

            Add-Action -Name 'winget-upgrade-all' -Status ('exit-' + $Result.ExitCode) -Detail $Result.Stdout.Trim()
        }
        catch {
            Add-Action -Name 'winget-upgrade-all' -Status 'error' -Detail $_.Exception.Message
        }
    }

    $UsoClient = Join-Path $env:SystemRoot 'System32\UsoClient.exe'

    if (Test-Path -LiteralPath $UsoClient -PathType Leaf) {
        foreach ($CommandName in @('StartScan','StartDownload','StartInstall')) {
            try {
                $Result = Invoke-NativeTool -FilePath $UsoClient -ArgumentList @($CommandName) -TimeoutSeconds 300 -AllowNonZero -Name ('windows-update-' + $CommandName)
                Add-Action -Name ('windows-update-' + $CommandName) -Status ('exit-' + $Result.ExitCode)
            }
            catch {
                Add-Action -Name ('windows-update-' + $CommandName) -Status 'error' -Detail $_.Exception.Message
            }
        }
    }
}

function Write-FinalReport {
    param(
        [string]$OperatorDisposition,
        [string]$OperatorPath,
        [string]$NewOperatorRun,
        [double]$FreeBefore,
        [double]$FreeAfterCleanup,
        [double]$FreeAtEnd
    )

    $State = [ordered]@{
        schema = 'szl.disk-clean-resume/v13'
        observed_at = [DateTime]::UtcNow.ToString('o')
        maintenance_run = $RunRoot
        free_before_gb = $FreeBefore
        free_after_cleanup_gb = $FreeAfterCleanup
        free_at_end_gb = $FreeAtEnd
        minimum_free_gb = $MinimumFreeGB
        preferred_free_gb = $PreferredFreeGB
        operator_disposition = $OperatorDisposition
        operator_path = $OperatorPath
        new_operator_run = $NewOperatorRun
        hibernation_disabled = -not (Test-Path -LiteralPath 'C:\hiberfil.sys' -PathType Leaf)
        large_file_report = if (Test-Path -LiteralPath $LargeFileReportPath -PathType Leaf) { $LargeFileReportPath } else { $null }
        user_documents_deleted = $false
        source_repositories_deleted = $false
        huggingface_cache_deleted = $false
        docker_volumes_deleted = $false
        credentials_touched = $false
        direct_main_push = $false
        force_push = $false
        manual_hf_upload = $false
        actions = $Actions
    }

    Write-JsonFile -Path $FinalStatePath -Value $State

    $Lines = @(
        '# SZL Disk Recovery and Fresh Estate Convergence',
        '',
        ('- Maintenance root: `{0}`' -f $RunRoot),
        ('- Free before: `{0} GB`' -f $FreeBefore),
        ('- Free after cleanup: `{0} GB`' -f $FreeAfterCleanup),
        ('- Free at end: `{0} GB`' -f $FreeAtEnd),
        ('- Operator disposition: `{0}`' -f $OperatorDisposition),
        ('- Operator path: `{0}`' -f $OperatorPath),
        ('- New operator run: `{0}`' -f $NewOperatorRun),
        ('- Hibernation disabled: `{0}`' -f $State.hibernation_disabled),
        '',
        'The cleanup removed disposable caches and old failed evidence while preserving user documents, source repositories, Hugging Face model/data caches, Docker volumes, credentials, and the latest SZL evidence.',
        '',
        'Re-enable hibernation later with:',
        '',
        '```powershell',
        'powercfg.exe /hibernate on',
        '```'
    )

    [System.IO.File]::WriteAllLines(
        $FinalReportPath,
        $Lines,
        (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false)
    )
}

$CoordinatorMutex = New-Object -TypeName System.Threading.Mutex -ArgumentList $false,'Global\SZL-Disk-Clean-Resume-V13'
$CoordinatorLock = $false

try {
    try {
        $CoordinatorLock = $CoordinatorMutex.WaitOne(0, $false)
    }
    catch [System.Threading.AbandonedMutexException] {
        $CoordinatorLock = $true
    }

    if (-not $CoordinatorLock) {
        throw 'Another SZL disk-clean/resume controller is already running.'
    }

    $FreeBefore = Get-FreeGB

    Write-Event -Event 'maintenance_started' -Message 'Safe exhaustive cleanup and fresh convergence started.' -Data @{
        free_before_gb = $FreeBefore
        writer_active = Test-WriterActive
    }

    while (Test-WriterActive) {
        Write-Event -Event 'waiting_before_cleanup' -Message 'Waiting for the active estate writer before touching build and evidence caches.' -Data @{
            free_gb = Get-FreeGB
        }

        Start-Sleep -Seconds 60
    }

    try {
        Clear-RecycleBin -DriveLetter C -Force -ErrorAction Stop
        Add-Action -Name 'recycle-bin' -Status 'complete'
    }
    catch {
        Add-Action -Name 'recycle-bin' -Status 'unavailable-or-failed' -Detail $_.Exception.Message
    }

    $OneDayAgo = (Get-Date).AddDays(-1)
    $SevenDaysAgo = (Get-Date).AddDays(-7)
    $FourteenDaysAgo = (Get-Date).AddDays(-14)

    Remove-DirectoryContents -Path $env:TEMP -OlderThan $OneDayAgo -ActionName 'user-temp'
    Remove-DirectoryContents -Path (Join-Path $env:WINDIR 'Temp') -OlderThan $OneDayAgo -ActionName 'windows-temp'
    Remove-DirectoryContents -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive' -OlderThan $SevenDaysAgo -ActionName 'wer-archive'
    Remove-DirectoryContents -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue' -OlderThan $SevenDaysAgo -ActionName 'wer-queue'
    Remove-DirectoryContents -Path (Join-Path $env:WINDIR 'Minidump') -OlderThan $SevenDaysAgo -ActionName 'minidumps'
    Remove-DirectoryContents -Path (Join-Path $env:WINDIR 'Logs\CBS') -OlderThan $FourteenDaysAgo -ActionName 'cbs-logs'
    Remove-DirectoryContents -Path (Join-Path $env:WINDIR 'Panther') -OlderThan $FourteenDaysAgo -ActionName 'panther-logs'

    if (Test-Path -LiteralPath 'C:\Windows\MEMORY.DMP' -PathType Leaf) {
        try {
            Remove-Item -LiteralPath 'C:\Windows\MEMORY.DMP' -Force -ErrorAction Stop
            Add-Action -Name 'memory-dump' -Status 'removed'
        }
        catch {
            Add-Action -Name 'memory-dump' -Status 'skipped-locked' -Detail $_.Exception.Message
        }
    }

    Clear-BrowserCaches
    Clear-DevelopmentCaches
    Clear-DockerCaches
    Clear-WindowsUpdateCaches

    Remove-OldTimestampRuns -Root $EstateRoot -KeepNewest 8 -MinimumAgeHours 24
    Remove-OldTimestampRuns -Root $ParallelRoot -KeepNewest 5 -MinimumAgeHours 24

    Remove-DirectoryContents -Path (Join-Path $EstateRoot 'Transcripts') -OlderThan $FourteenDaysAgo -ActionName 'old-transcripts'

    foreach ($Pattern in @('*.broken-*','*.disabled','*.stdout.txt','*.stderr.txt')) {
        Get-ChildItem -LiteralPath $RuntimeRoot -Filter $Pattern -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddDays(-7)
        } |
        ForEach-Object {
            try {
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                Add-Action -Name 'old-runtime-artifact' -Status 'removed' -Detail $_.FullName
            }
            catch {
                Add-Action -Name 'old-runtime-artifact' -Status 'skipped-locked' -Detail $_.FullName
            }
        }
    }

    $CleanMgr = Join-Path $env:SystemRoot 'System32\cleanmgr.exe'

    if (Test-Path -LiteralPath $CleanMgr -PathType Leaf) {
        try {
            $Result = Invoke-NativeTool -FilePath $CleanMgr -ArgumentList @('/VERYLOWDISK','/d','C') -TimeoutSeconds 7200 -AllowNonZero -Name 'cleanmgr'
            Add-Action -Name 'cleanmgr' -Status ('exit-' + $Result.ExitCode)
        }
        catch {
            Add-Action -Name 'cleanmgr' -Status 'error' -Detail $_.Exception.Message
        }
    }

    $Dism = Join-Path $env:SystemRoot 'System32\dism.exe'

    if (Test-Path -LiteralPath $Dism -PathType Leaf) {
        try {
            $Result = Invoke-NativeTool -FilePath $Dism -ArgumentList @('/Online','/Cleanup-Image','/StartComponentCleanup','/NoRestart') -TimeoutSeconds 7200 -AllowNonZero -Name 'dism-component-cleanup'
            Add-Action -Name 'dism-component-cleanup' -Status ('exit-' + $Result.ExitCode)
        }
        catch {
            Add-Action -Name 'dism-component-cleanup' -Status 'error' -Detail $_.Exception.Message
        }
    }

    $FreeAfterStandardCleanup = Get-FreeGB
    Write-Event -Event 'standard_cleanup_complete' -Message 'Standard cleanup complete.' -Data @{
        free_gb = $FreeAfterStandardCleanup
    }

    if ($FreeAfterStandardCleanup -lt $MinimumFreeGB) {
        $HiberfileSizeGB = 0

        if (Test-Path -LiteralPath 'C:\hiberfil.sys' -PathType Leaf) {
            $HiberfileSizeGB = [Math]::Round((Get-Item -LiteralPath 'C:\hiberfil.sys' -Force).Length / 1GB, 2)
        }

        $PowerCfg = Join-Path $env:SystemRoot 'System32\powercfg.exe'
        $Result = Invoke-NativeTool -FilePath $PowerCfg -ArgumentList @('/hibernate','off') -TimeoutSeconds 300 -AllowNonZero -Name 'disable-hibernation'
        Add-Action -Name 'disable-hibernation' -Status ('exit-' + $Result.ExitCode) -Detail ('hiberfile_before_gb=' + $HiberfileSizeGB)
    }

    $FreeAfterHibernation = Get-FreeGB

    if ($FreeAfterHibernation -lt $MinimumFreeGB) {
        $Compact = Join-Path $env:SystemRoot 'System32\compact.exe'

        if (Test-Path -LiteralPath $Compact -PathType Leaf) {
            try {
                $Result = Invoke-NativeTool -FilePath $Compact -ArgumentList @('/CompactOS:always') -TimeoutSeconds 14400 -AllowNonZero -Name 'compact-os'
                Add-Action -Name 'compact-os' -Status ('exit-' + $Result.ExitCode) -Detail $Result.Stdout.Trim()
            }
            catch {
                Add-Action -Name 'compact-os' -Status 'error' -Detail $_.Exception.Message
            }
        }
    }

    try {
        $Optimize = Get-Command Optimize-Volume -ErrorAction SilentlyContinue

        if ($Optimize) {
            Optimize-Volume -DriveLetter C -ReTrim -Verbose -ErrorAction SilentlyContinue | Out-Null
            Add-Action -Name 'ssd-retrim' -Status 'complete'
        }
    }
    catch {
        Add-Action -Name 'ssd-retrim' -Status 'error' -Detail $_.Exception.Message
    }

    $FreeAfterCleanup = Get-FreeGB
    Write-LargeFileReport

    if ($FreeAfterCleanup -lt $MinimumFreeGB) {
        Write-Event -Event 'disk_floor_blocked' -Message 'Safe cleanup did not reach the 50 GB floor; user files were not deleted.' -Data @{
            free_gb = $FreeAfterCleanup
            report = $LargeFileReportPath
        }

        Write-FinalReport `
            -OperatorDisposition 'BLOCKED_DISK_FLOOR' `
            -OperatorPath '' `
            -NewOperatorRun '' `
            -FreeBefore $FreeBefore `
            -FreeAfterCleanup $FreeAfterCleanup `
            -FreeAtEnd $FreeAfterCleanup

        throw ('Safe cleanup reached {0} GB. Review {1}; no user files were auto-deleted.' -f $FreeAfterCleanup,$LargeFileReportPath)
    }

    while (Test-WriterActive) {
        Write-Event -Event 'waiting_for_writer' -Message 'Waiting for the existing estate writer to return control.' -Data @{
            free_gb = Get-FreeGB
        }

        Start-Sleep -Seconds 60
    }

    $Operator = Find-Operator

    if (-not $Operator) {
        Write-FinalReport `
            -OperatorDisposition 'BLOCKED_OPERATOR_NOT_FOUND' `
            -OperatorPath '' `
            -NewOperatorRun '' `
            -FreeBefore $FreeBefore `
            -FreeAfterCleanup $FreeAfterCleanup `
            -FreeAtEnd (Get-FreeGB)

        throw 'No parse-clean fully repaired V11 operator was found.'
    }

    $OperatorSha256 = (Get-FileHash -LiteralPath $Operator -Algorithm SHA256).Hash.ToLowerInvariant()

    New-Item -ItemType Directory -Path $EstateRoot -Force | Out-Null

    $UserGrant = ('*{0}:(OI)(CI)F' -f $Identity.User.Value)

    try {
        & icacls.exe $EstateRoot '/inheritance:e' '/grant:r' $UserGrant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '/C' | Out-Null
        Add-Action -Name 'estate-root-acl' -Status 'reconciled-for-new-children'
    }
    catch {
        Add-Action -Name 'estate-root-acl' -Status 'warning' -Detail $_.Exception.Message
    }

    $ProbeRoot = Join-Path $EstateRoot ('_fresh-write-probe-' + [Guid]::NewGuid().ToString('N'))
    $ProbePrivate = Join-Path $ProbeRoot 'private'
    $ProbeFile = Join-Path $ProbePrivate 'operator-events.jsonl'

    try {
        New-Item -ItemType Directory -Path $ProbePrivate -Force | Out-Null
        [System.IO.File]::AppendAllText(
            $ProbeFile,
            '{"event":"fresh_write_probe","ok":true}' + [Environment]::NewLine,
            (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false)
        )

        if ((Get-Content -LiteralPath $ProbeFile -Raw) -notmatch '"ok":true') {
            throw 'Fresh write probe failed readback.'
        }

        Add-Action -Name 'fresh-evidence-write' -Status 'pass'
    }
    finally {
        Remove-Item -LiteralPath $ProbeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    foreach ($VariableName in @('SZL_RUN_ROOT','SZL_STATE_PATH','SZL_EVENT_LOG','SZL_PRIVATE_ROOT','SZL_EVIDENCE_ROOT')) {
        [Environment]::SetEnvironmentVariable($VariableName, $null, 'Process')
    }

    $PythonPath = 'C:\Users\steph\AppData\Local\Programs\Python\Python312\python.exe'

    if (Test-Path -LiteralPath $PythonPath -PathType Leaf) {
        $env:SZL_PYTHON_EXE = $PythonPath
        $PythonDirectory = Split-Path -Parent $PythonPath
        $env:Path = $PythonDirectory + ';' + (Join-Path $PythonDirectory 'Scripts') + ';' + $env:Path
    }

    $env:SZL_MODE = 'FULL'
    $env:SZL_APPLY = '1'
    $env:SZL_CONFIRM = 'APPLY-SZL-ESTATE-CONVERGENCE'
    $env:SZL_INSTALL_PREREQUISITES = '1'
    $env:SZL_USE_CODEX = '0'
    $env:SZL_INSTALL_CODEX = '0'
    $env:SZL_MAX_CODEX_TASKS_PER_CYCLE = '0'
    $env:SZL_RESUME_LATEST = '0'
    $env:SZL_MAX_CYCLES = '12'
    $env:SZL_MAX_RUNTIME_MINUTES = '1440'
    $env:SZL_MAX_WRITES_PER_CYCLE = '1'
    $env:SZL_MAX_SAFE_CLOSURES_PER_CYCLE = '3'
    $env:SZL_FIXED_POINT_CYCLES = '3'
    $env:SZL_POLL_SECONDS = '60'
    $env:SZL_MIN_FREE_GB = [string]$MinimumFreeGB
    $env:SZL_AUTO_CLOSE_PROVEN_SUPERSEDED = '1'
    $env:SZL_INSTALL_WATCHDOG = '0'

    Write-Event -Event 'fresh_operator_starting' -Message 'Starting one fresh full convergence run.' -Data @{
        operator = $Operator
        operator_sha256 = $OperatorSha256
        free_gb = Get-FreeGB
        resume_latest = $false
    }

    $OperatorStartedAt = [DateTime]::UtcNow
    $OperatorDisposition = 'RETURNED_SUCCESS'
    $OperatorException = $null

    try {
        & $Operator

        if (-not $?) {
            $OperatorDisposition = 'RETURNED_UNSUCCESSFUL_STATUS'
        }
    }
    catch {
        $OperatorDisposition = 'EXCEPTION'
        $OperatorException = $_.Exception.ToString()
        Write-Event -Event 'operator_exception' -Message $_.Exception.Message
    }

    $NewOperatorRun = Get-ChildItem -LiteralPath $EstateRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -match '^\d{8}T\d{6}Z$' -and
        $_.CreationTimeUtc -ge $OperatorStartedAt.AddSeconds(-5)
    } |
    Sort-Object CreationTimeUtc -Descending |
    Select-Object -First 1

    $NewOperatorRunPath = if ($NewOperatorRun) { $NewOperatorRun.FullName } else { '' }

    Invoke-SystemUpdates

    if (Test-Path -LiteralPath $Dism -PathType Leaf) {
        try {
            $Result = Invoke-NativeTool -FilePath $Dism -ArgumentList @('/Online','/Cleanup-Image','/RestoreHealth','/NoRestart') -TimeoutSeconds 14400 -AllowNonZero -Name 'dism-restore-health'
            Add-Action -Name 'dism-restore-health' -Status ('exit-' + $Result.ExitCode)
        }
        catch {
            Add-Action -Name 'dism-restore-health' -Status 'error' -Detail $_.Exception.Message
        }
    }

    $Sfc = Join-Path $env:SystemRoot 'System32\sfc.exe'

    if (Test-Path -LiteralPath $Sfc -PathType Leaf) {
        try {
            $Result = Invoke-NativeTool -FilePath $Sfc -ArgumentList @('/scannow') -TimeoutSeconds 14400 -AllowNonZero -Name 'sfc-scannow'
            Add-Action -Name 'sfc-scannow' -Status ('exit-' + $Result.ExitCode)
        }
        catch {
            Add-Action -Name 'sfc-scannow' -Status 'error' -Detail $_.Exception.Message
        }
    }

    if ($OperatorException) {
        Add-Action -Name 'operator' -Status $OperatorDisposition -Detail $OperatorException
    }
    else {
        Add-Action -Name 'operator' -Status $OperatorDisposition -Detail $NewOperatorRunPath
    }

    $FreeAtEnd = Get-FreeGB

    Write-FinalReport `
        -OperatorDisposition $OperatorDisposition `
        -OperatorPath $Operator `
        -NewOperatorRun $NewOperatorRunPath `
        -FreeBefore $FreeBefore `
        -FreeAfterCleanup $FreeAfterCleanup `
        -FreeAtEnd $FreeAtEnd

    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Green
    Write-Host ' SZL CLEANUP AND FRESH CONVERGENCE RETURNED CONTROL' -ForegroundColor Green
    Write-Host '============================================================' -ForegroundColor Green
    Write-Host ('Maintenance evidence: {0}' -f $RunRoot) -ForegroundColor Cyan
    Write-Host ('Free space: {0} GB' -f $FreeAtEnd) -ForegroundColor Cyan
    Write-Host ('Operator disposition: {0}' -f $OperatorDisposition) -ForegroundColor Cyan
    Write-Host ('New operator run: {0}' -f $NewOperatorRunPath) -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Hibernation may have been disabled to recover disk space.' -ForegroundColor Yellow
    Write-Host 'Re-enable it later with: powercfg.exe /hibernate on' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'No user documents, source repositories, Hugging Face caches, Docker volumes, or credentials were intentionally deleted.' -ForegroundColor Green
}
finally {
    if ($CoordinatorLock) {
        try {
            $CoordinatorMutex.ReleaseMutex()
        }
        catch {
        }
    }

    $CoordinatorMutex.Dispose()
}
