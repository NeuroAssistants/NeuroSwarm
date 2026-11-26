# NeuroSwarm Lite Agent Installer for Windows PowerShell (5.1+ / 7+)
& {
param([bool]$InvokedAsFile)
# The NeuroSwarm mark (three slanted bars) in plain ASCII, so it renders in Windows PowerShell 5.1 consoles too.
Write-Host ''
Write-Host '       ____________' -ForegroundColor Green
Write-Host '      /___________/' -ForegroundColor Green -NoNewline; Write-Host '      N E U R O S W A R M' -ForegroundColor White
Write-Host '    ____________' -ForegroundColor Green -NoNewline; Write-Host '         see what your coding agents do' -ForegroundColor DarkGray
Write-Host '   /___________/' -ForegroundColor Green
Write-Host '   _________' -ForegroundColor Green -NoNewline; Write-Host '            Windows observer installer' -ForegroundColor White
Write-Host '  /________/' -ForegroundColor Green
Write-Host ''
$ErrorActionPreference = "Stop"

$InstallDir = if ($env:SWARMCONTROL_INSTALL_DIR) { $env:SWARMCONTROL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "SwarmControl" }
$FromRepo = if ($env:SWARMCONTROL_FROM_REPO) { $env:SWARMCONTROL_FROM_REPO } else { "" }
$NoService = if ($env:SWARMCONTROL_NO_SERVICE) { $env:SWARMCONTROL_NO_SERVICE } else { "0" }
$Upgrade = if ($env:SWARMCONTROL_UPGRADE) { $env:SWARMCONTROL_UPGRADE } else { "0" }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$InstallLog = Join-Path $InstallDir 'install.log'
function Write-Status([string]$Message) {
    Write-Host $Message
    Add-Content -LiteralPath $InstallLog -Encoding UTF8 -Value ("{0:u} {1}" -f [datetime]::UtcNow, $Message)
}
function Stop-Install([string]$Message, [int]$Code) {
    Write-Status "[FAILED] $Message"
    $failure = [InvalidOperationException]::new($Message)
    $failure.Data['InstallCode'] = $Code
    throw $failure
}
$Lock = $null
$StageDir = $null
$BackupDir = $null
$Replacing = $false
$CreatedTask = $false
$RestartPreviousTask = $false
$RestartPreviousProcess = $false
$ManagedFiles = @('detector.py', 'activity_shipper.py', 'activity_core.py', 'swarmcontrol_agent.py', 'agent.env', 'run-agent.ps1')
try {
try {
    $Lock = [IO.File]::Open((Join-Path $InstallDir 'install.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
} catch { Stop-Install 'Cannot lock the installation folder. Check write access or wait for the other installer to finish.' 4 }
Write-Status "[START] Installation log: $InstallLog"
$Saved = @{}
$EnvPath = Join-Path $InstallDir "agent.env"
if (-not $env:SWARMCONTROL_UPGRADE -and (Test-Path -LiteralPath $EnvPath)) { $Upgrade = "1" }
if ($Upgrade -eq "1") {
    if (-not (Test-Path $EnvPath)) {
        Stop-Install "SWARMCONTROL_UPGRADE=1 requires an existing agent.env in $InstallDir." 2
    }
    foreach ($line in Get-Content $EnvPath -Encoding UTF8) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#') -or -not $trimmed.Contains('=')) { continue }
        $parts = $trimmed.Split('=', 2)
        $Saved[$parts[0].Trim()] = $parts[1].Trim()
    }
}

$ServerUrl = if ($env:SWARMCONTROL_SERVER) { $env:SWARMCONTROL_SERVER.TrimEnd('/') } elseif ($Saved.ContainsKey('SWARMCONTROL_SERVER') -and $Saved['SWARMCONTROL_SERVER']) { $Saved['SWARMCONTROL_SERVER'].TrimEnd('/') } else { "http://127.0.0.1:8790" }
$Token = if ($env:SWARMCONTROL_TOKEN) { $env:SWARMCONTROL_TOKEN } elseif ($Saved.ContainsKey('SWARMCONTROL_TOKEN')) { $Saved['SWARMCONTROL_TOKEN'] } else { "" }
$Interval = if ($env:SWARMCONTROL_INTERVAL) { $env:SWARMCONTROL_INTERVAL } elseif ($Saved.ContainsKey('SWARMCONTROL_INTERVAL') -and $Saved['SWARMCONTROL_INTERVAL']) { $Saved['SWARMCONTROL_INTERVAL'] } else { "15" }
$HostId = if ($env:SWARMCONTROL_HOST_ID) { $env:SWARMCONTROL_HOST_ID } elseif ($Saved.ContainsKey('SWARMCONTROL_HOST_ID') -and $Saved['SWARMCONTROL_HOST_ID']) { $Saved['SWARMCONTROL_HOST_ID'] } else { $env:COMPUTERNAME }
$ActivityRoots = if ($env:SWARMCONTROL_ACTIVITY_ROOTS) { $env:SWARMCONTROL_ACTIVITY_ROOTS } elseif ($Saved.ContainsKey('SWARMCONTROL_ACTIVITY_ROOTS')) { $Saved['SWARMCONTROL_ACTIVITY_ROOTS'] } else { "" }
$AgentLabels = if ($env:SWARMCONTROL_AGENT_LABELS) { $env:SWARMCONTROL_AGENT_LABELS } elseif ($Saved.ContainsKey('SWARMCONTROL_AGENT_LABELS')) { $Saved['SWARMCONTROL_AGENT_LABELS'] } else { "" }
$ShareCommands = if ($env:SWARMCONTROL_SHARE_COMMANDS) { $env:SWARMCONTROL_SHARE_COMMANDS } elseif ($Saved.ContainsKey('SWARMCONTROL_SHARE_COMMANDS') -and $Saved['SWARMCONTROL_SHARE_COMMANDS']) { $Saved['SWARMCONTROL_SHARE_COMMANDS'] } else { "0" }
$ShareCommandOutput = if ($env:SWARMCONTROL_SHARE_COMMAND_OUTPUT) { $env:SWARMCONTROL_SHARE_COMMAND_OUTPUT } elseif ($Saved.ContainsKey('SWARMCONTROL_SHARE_COMMAND_OUTPUT') -and $Saved['SWARMCONTROL_SHARE_COMMAND_OUTPUT']) { $Saved['SWARMCONTROL_SHARE_COMMAND_OUTPUT'] } else { "0" }
$ShareFilePreviews = if ($env:SWARMCONTROL_SHARE_FILE_PREVIEWS) { $env:SWARMCONTROL_SHARE_FILE_PREVIEWS } elseif ($Saved.ContainsKey('SWARMCONTROL_SHARE_FILE_PREVIEWS') -and $Saved['SWARMCONTROL_SHARE_FILE_PREVIEWS']) { $Saved['SWARMCONTROL_SHARE_FILE_PREVIEWS'] } else { "0" }
$StateDir = if ($env:SWARMCONTROL_STATE_DIR) { $env:SWARMCONTROL_STATE_DIR } elseif ($Saved.ContainsKey('SWARMCONTROL_STATE_DIR')) { $Saved['SWARMCONTROL_STATE_DIR'] } else { "" }

if (-not $Token) {
    Stop-Install "Missing enrollment token. Set `$env:SWARMCONTROL_TOKEN='<TOKEN>' before running install.ps1." 2
}
if ($Token -notmatch '^[A-Za-z0-9_-]{8,128}$') {
    Stop-Install "Enrollment token has an unexpected format." 2
}
if ($ShareCommands -ne "0" -and $ShareCommands -ne "1") {
    Stop-Install "SWARMCONTROL_SHARE_COMMANDS must be 0 or 1." 2
}
if ($ShareCommandOutput -ne "0" -and $ShareCommandOutput -ne "1") {
    Stop-Install "SWARMCONTROL_SHARE_COMMAND_OUTPUT must be 0 or 1." 2
}
if ($ShareFilePreviews -ne "0" -and $ShareFilePreviews -ne "1") {
    Stop-Install "SWARMCONTROL_SHARE_FILE_PREVIEWS must be 0 or 1." 2
}
if ($AgentLabels -and $AgentLabels -notmatch '^[A-Za-z0-9._:@,/=+ -]{1,512}$') {
    Stop-Install "SWARMCONTROL_AGENT_LABELS contains unsupported characters." 2
}

function Find-ObserverPython {
    $probe = 'import sys, sqlite3, ssl; print(sys.executable) if sys.version_info >= (3,10) else sys.exit(1)'
    $apps = @(Get-Command -Name python, py, python3 -CommandType Application -ErrorAction SilentlyContinue)
    # A newly installed Python may be absent from this PowerShell session's PATH.
    $paths = @($apps | ForEach-Object { $_.Source })
    if ($env:LOCALAPPDATA) { $paths += Join-Path $env:LOCALAPPDATA 'Programs/Python/Python313/python.exe' }
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $probeArgs = @('-I', '-c', $probe)
        if ([IO.Path]::GetFileNameWithoutExtension($path) -eq 'py') { $probeArgs = @('-3') + $probeArgs }
        $ErrorActionPreference = "Continue"
        try {
            $exe = & $path @probeArgs 2>$null
            if ($LASTEXITCODE -eq 0 -and $exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) { return $exe }
        } catch { continue }
    }
}
Write-Status '[CHECK] Looking for Python 3.10+ with SQLite and TLS...'
$PyExe = Find-ObserverPython
if (-not $PyExe) {
    $winget = Get-Command winget -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $winget) { Stop-Install 'Python 3.10+ is required. Install Microsoft App Installer (WinGet) or Python from python.org, then rerun this command.' 3 }
    Write-Status '[INSTALL] Installing Python 3.13 for this Windows user through WinGet...'
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $winget.Source install --id Python.Python.3.13 --exact --source winget --scope user --silent --disable-interactivity --accept-package-agreements --accept-source-agreements
        $wingetCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    $PyExe = Find-ObserverPython
    if (-not $PyExe) { Stop-Install "WinGet returned $wingetCode and Python is still unavailable. Reopen PowerShell and retry, or install Python 3.10+ from python.org." 3 }
}
Write-Status '[OK] Python is ready.'

$ParentDir = Split-Path -Parent $InstallDir
if ($ParentDir) { New-Item -ItemType Directory -Force -Path $ParentDir | Out-Null }
$StageDir = "$InstallDir.staging.$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

function Fail-Stage([string]$Comp) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $StageDir
    Stop-Install "Required observer component $Comp could not be installed; existing configuration left untouched." 4
}

try {
    if ($FromRepo) {
        Write-Status "[COPY] Installing the local observer components..."
        foreach ($pair in @(
            @("agent\detector.py", "detector.py"),
            @("agent\activity_shipper.py", "activity_shipper.py"),
            @("backend\activity_inspector.py", "activity_core.py"),
            @("agent\swarmcontrol_agent.py", "swarmcontrol_agent.py")
        )) {
            $src = Join-Path $FromRepo $pair[0]
            if (-not (Test-Path $src) -or (Get-Item $src).Length -le 0) { Fail-Stage $pair[1] }
            Copy-Item $src (Join-Path $StageDir $pair[1]) -Force
        }
    } else {
        Write-Status "[DOWNLOAD] Fetching the observer components..."
        foreach ($pair in @(
            @("detector.py", "$ServerUrl/agent/detector.py"),
            @("activity_shipper.py", "$ServerUrl/agent/activity_shipper.py"),
            @("activity_core.py", "$ServerUrl/agent/activity_core.py"),
            @("swarmcontrol_agent.py", "$ServerUrl/agent/swarmcontrol_agent.py")
        )) {
            $dst = Join-Path $StageDir $pair[0]
            try {
                Invoke-WebRequest -UseBasicParsing -Uri $pair[1] -OutFile $dst -TimeoutSec 30
            } catch {
                Fail-Stage $pair[0]
            }
            if (-not (Test-Path $dst) -or (Get-Item $dst).Length -le 0) {
                Fail-Stage $pair[0]
            }
        }
    }
} finally {
    if (-not (Test-Path (Join-Path $StageDir "activity_core.py"))) {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $StageDir
    }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$BackupDir = ""
if (@($ManagedFiles | Where-Object { Test-Path -LiteralPath (Join-Path $InstallDir $_) }).Count) {
    Write-Status "[UPDATE] Backing up the previous NeuroSwarm runtime and applying the new version..."
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $suffix = [guid]::NewGuid().ToString("N").Substring(0, 6)
    $BackupDir = "$InstallDir.bak.$stamp.$suffix"
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    foreach ($f in $ManagedFiles) {
        $src = Join-Path $InstallDir $f
        if (Test-Path $src) { Copy-Item $src (Join-Path $BackupDir $f) -Force }
    }
}

$Replacing = $true
foreach ($f in @('detector.py', 'activity_shipper.py', 'activity_core.py', 'swarmcontrol_agent.py')) {
    Move-Item -Force (Join-Path $StageDir $f) (Join-Path $InstallDir $f)
}
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $StageDir

$HasOverrides = [bool]($env:SWARMCONTROL_SERVER -or $env:SWARMCONTROL_TOKEN -or $env:SWARMCONTROL_INTERVAL -or $env:SWARMCONTROL_HOST_ID -or $env:SWARMCONTROL_ACTIVITY_ROOTS -or $env:SWARMCONTROL_AGENT_LABELS -or $env:SWARMCONTROL_SHARE_COMMANDS -or $env:SWARMCONTROL_SHARE_COMMAND_OUTPUT -or $env:SWARMCONTROL_SHARE_FILE_PREVIEWS -or $env:SWARMCONTROL_STATE_DIR)
if ($Upgrade -ne "1" -or $HasOverrides -or -not (Test-Path $EnvPath)) {
    $EnvLines = @(
        "SWARMCONTROL_SERVER=$ServerUrl",
        "SWARMCONTROL_TOKEN=$Token",
        "SWARMCONTROL_INTERVAL=$Interval",
        "SWARMCONTROL_HOST_ID=$HostId",
        "SWARMCONTROL_ACTIVITY_ROOTS=$ActivityRoots",
        "SWARMCONTROL_AGENT_LABELS=$AgentLabels",
        "SWARMCONTROL_SHARE_COMMANDS=$ShareCommands",
        "SWARMCONTROL_SHARE_COMMAND_OUTPUT=$ShareCommandOutput",
        "SWARMCONTROL_SHARE_FILE_PREVIEWS=$ShareFilePreviews"
    )
    if ($StateDir) { $EnvLines += "SWARMCONTROL_STATE_DIR=$StateDir" }
    Set-Content -Path $EnvPath -Value ($EnvLines -join "`r`n") -Encoding UTF8
}

Write-Status "[CHECK] Checking the observer and sending the first heartbeat..."
$env:SWARMCONTROL_TOKEN = $Token
$env:SWARMCONTROL_AGENT_LABELS = $AgentLabels
$env:SWARMCONTROL_SHARE_COMMANDS = $ShareCommands
$env:SWARMCONTROL_SHARE_COMMAND_OUTPUT = $ShareCommandOutput
$env:SWARMCONTROL_SHARE_FILE_PREVIEWS = $ShareFilePreviews
if ($StateDir) { $env:SWARMCONTROL_STATE_DIR = $StateDir }
$DiagArgs = @((Join-Path $InstallDir "swarmcontrol_agent.py"), "--diagnose")
$AgentArgs = @((Join-Path $InstallDir "swarmcontrol_agent.py"), "--server", $ServerUrl, "--once")
if ($HostId) {
    $DiagArgs += @("--host-id", $HostId)
    $AgentArgs += @("--host-id", $HostId)
}
if ($ActivityRoots) {
    $DiagArgs += @("--activity-roots", $ActivityRoots)
    $AgentArgs += @("--activity-roots", $ActivityRoots)
}
$VerifyOk = $false
$Problem = 'Local observer diagnostics failed.'
try {
    $DiagRaw = & $PyExe @DiagArgs 2>$null
    if ($LASTEXITCODE -eq 0 -and $DiagRaw) {
        $DiagObj = ($DiagRaw -join "`n") | ConvertFrom-Json
        if ($DiagObj.activity_core_loaded -and ($DiagObj.capture_reader -eq 'core') -and (-not $DiagObj.dry_scan_error)) {
            $Problem = 'First heartbeat failed. Check the server address, network and enrollment key.'
            $ErrorActionPreference = "Continue"
            try { $Reply = @(& $PyExe @AgentArgs 2>&1); $HeartbeatExit = $LASTEXITCODE }
            finally { $ErrorActionPreference = "Stop" }
            if ($HeartbeatExit -eq 0) {
                $Heartbeat = (($Reply | Where-Object { $_ -is [string] }) -join "`n") | ConvertFrom-Json
                $VerifyOk = ($Heartbeat.ok -eq $true -and $Heartbeat.host_id -eq $DiagObj.host_id)
            } elseif (($Reply -join ' ') -match 'HTTP Error (401|403)') {
                $Problem = "Heartbeat rejected (HTTP $($Matches[1])). Check the enrollment key and its allowed host."
            }
        }
    }
} catch { $VerifyOk = $false }
if (-not $VerifyOk) { Stop-Install $Problem 1 }
if ($BackupDir) { Write-Status "[UPDATE] Previous runtime saved at $BackupDir" }

Write-Status "[OK] Heartbeat accepted for $($Heartbeat.host_id)."
if ($Heartbeat.activity_warning) { Write-Status '[WARN] The heartbeat arrived, but activity delivery reported a problem.' }
$RootCount = @($DiagObj.activity_roots).Count
if ($ActivityRoots -and $RootCount -eq 0) {
    Write-Status '[WARN] None of the configured project folders exists. Check the drive letter and folder path, then rerun.'
} elseif ($RootCount -eq 0) {
    Write-Status '[ACTIVITY] Host monitoring only: this machine appears in Hosts, but no agent sessions appear in Live until you choose a project folder.'
    # OpenBot keeps agent workspaces and shared projects in its own folder. Suggest them; never share one without consent.
    $OpenBotHome = @($env:USERPROFILE, $env:APPDATA) | Where-Object { $_ } | ForEach-Object { Join-Path $_ 'OpenBot' } | Where-Object { Test-Path -LiteralPath (Join-Path $_ 'Shared') } | Select-Object -First 1
    if ($OpenBotHome) {
        $Projects = @(Get-ChildItem -LiteralPath (Join-Path $OpenBotHome 'Shared') -Directory -ErrorAction SilentlyContinue | Where-Object { -not $_.Name.StartsWith('.') } | Select-Object -First 5)
        Write-Status "[ACTIVITY] OpenBot found. Its shared projects are in $(Join-Path $OpenBotHome 'Shared'):"
        foreach ($proj in $Projects) { Write-Host "             - $($proj.FullName)" -ForegroundColor DarkGray }
        $Example = if ($Projects.Count) { $Projects[0].FullName } else { Join-Path $OpenBotHome 'Shared' }
        Write-Host '  To share one, rerun with its folder (separate several with ;):' -ForegroundColor White
        Write-Host ('    $env:SWARMCONTROL_ACTIVITY_ROOTS=''' + $Example.Replace("'", "''") + '''; irm ' + $ServerUrl + '/install.ps1 | iex') -ForegroundColor Cyan
    } else {
        Write-Host '  To share a project, rerun with its folder (separate several with ;):' -ForegroundColor White
        Write-Host ('    $env:SWARMCONTROL_ACTIVITY_ROOTS="C:\path\to\project"; irm ' + $ServerUrl + '/install.ps1 | iex') -ForegroundColor Cyan
    }
} else {
    Write-Status "[ACTIVITY] Watching $RootCount project folder(s); $($DiagObj.dry_scan.sessions) matching session(s) found locally."
}
# This marker tests ingestion without opening or sharing the contents of a project.
$LiveUrl = "$ServerUrl/live?host=$([uri]::EscapeDataString($Heartbeat.host_id))"
$Marker = @{ host_id = $Heartbeat.host_id; harness = 'neuroswarm'; agent_name = 'windows-installer'; event_type = 'observer_install_check'; message = 'Windows observer connection verified' }
try {
    $Receipt = Invoke-RestMethod -Method Post -Uri "$ServerUrl/api/v1/ingest/event" -Headers @{ Authorization = "Bearer $Token" } -ContentType 'application/json' -Body ($Marker | ConvertTo-Json -Compress) -TimeoutSec 10 -MaximumRedirection 0
    if ($Receipt.ok -ne $true -or [long]$Receipt.event_id -le 0) { throw 'Missing event receipt' }
    Write-Status "[OK] Test event #$($Receipt.event_id) recorded. Live: $LiveUrl&event=event%3A$($Receipt.event_id)"
} catch {
    Write-Status "[WARN] Test event unconfirmed. Check Live in the organization that issued the key: $LiveUrl"
}

if ($NoService -eq "1") {
    Write-Status "[INSTALLED] One-time check complete; background monitoring disabled (no-service mode)."
    return
}

$RunnerPs1 = Join-Path $InstallDir "run-agent.ps1"
# Read configuration as data so quoted paths work and the launcher contains no enrollment key.
$RunnerBody = @'
$ErrorActionPreference = 'Stop'
foreach ($line in Get-Content -LiteralPath (Join-Path $PSScriptRoot 'agent.env') -Encoding UTF8) {
    if ($line -match '^(SWARMCONTROL_[A-Z_]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}
'@
$QuotedPython = "'" + $PyExe.Replace("'", "''") + "'"
$RunnerBody += "`r`n& $QuotedPython (Join-Path `$PSScriptRoot 'swarmcontrol_agent.py')"
Set-Content -Path $RunnerPs1 -Value $RunnerBody -Encoding UTF8

function Start-ObserverProcess {
    $arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$RunnerPs1`""
    Start-Process -PassThru -FilePath 'powershell.exe' -ArgumentList $arguments -WindowStyle Hidden
}
function Stop-PreviousDetachedObserver {
    if (-not $BackupDir -or [Environment]::OSVersion.Platform -ne 'Win32NT') { return }
    $launcher = [regex]::Escape($RunnerPs1)
    $agent = [regex]::Escape((Join-Path $InstallDir 'swarmcontrol_agent.py'))
    $filter = "Name='powershell.exe' OR Name='python.exe' OR Name='pythonw.exe'"
    foreach ($proc in Get-CimInstance Win32_Process -Filter $filter) {
        # Match only our exact launcher or long-running agent, never a Python executable by name alone.
        if ($proc.Name -eq 'powershell.exe') {
            $match = $proc.CommandLine -match ('^(?:"[^"]+"|\S+)\s+-NoProfile\s+-WindowStyle Hidden\s+-ExecutionPolicy Bypass\s+-File "' + $launcher + '"$')
        } else {
            $match = $proc.CommandLine -match ('^(?:"[^"]+"|\S+)\s+(?:"' + $agent + '"|' + $agent + ')$')
        }
        if ($match) {
            $stopped = Invoke-CimMethod -InputObject $proc -MethodName Terminate
            if ($stopped.ReturnValue -ne 0) { throw 'Previous observer process could not be stopped.' }
            if (-not $RestartPreviousTask) { Set-Variable -Name RestartPreviousProcess -Value $true -Scope 1 }
        }
    }
}
$UseBackground = $false
try {
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$RunnerPs1`""
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $previous = Get-ScheduledTask -TaskName 'SwarmControlAgent' -ErrorAction SilentlyContinue
    if ($previous.State -eq 'Running') {
        Write-Status '[CHECK] Restarting the running observer with the new configuration...'
        $RestartPreviousTask = $true
        Stop-ScheduledTask -TaskName 'SwarmControlAgent'
        for ($attempt = 0; $attempt -lt 5; $attempt++) {
            if ((Get-ScheduledTask -TaskName 'SwarmControlAgent').State -ne 'Running') { break }
            Start-Sleep -Seconds 1
        }
        if ((Get-ScheduledTask -TaskName 'SwarmControlAgent').State -eq 'Running') {
            throw 'Previous instance did not stop'
        }
    }
    Register-ScheduledTask -TaskName "SwarmControlAgent" -Action $Action -Trigger $Trigger -Force | Out-Null
    $CreatedTask = -not $previous
} catch {
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $previous = Get-ScheduledTask -TaskName 'SwarmControlAgent' -ErrorAction SilentlyContinue
        if ($previous) { Stop-Install 'Cannot update the existing scheduled task. Retry from the Windows account that installed the observer.' 1 }
    }
    $UseBackground = $true
}
if ($UseBackground) {
    Write-Status "[WARN] Scheduled task unavailable; trying a background process for this sign-in."
    Stop-PreviousDetachedObserver
    try { $ObserverProcess = Start-ObserverProcess }
    catch { Stop-Install 'Could not start the background observer. Check permission to run powershell.exe.' 1 }
    Start-Sleep -Seconds 1
    if ($ObserverProcess.HasExited) { Stop-Install "Background observer exited during startup. Check the Python installation and run-agent.ps1." 1 }
    Write-Status "[INSTALLED] Background process running for this sign-in (PID $($ObserverProcess.Id))."
    return
}
try {
    Stop-PreviousDetachedObserver
    Start-ScheduledTask -TaskName 'SwarmControlAgent'
} catch {
    Stop-Install 'Heartbeat accepted, but Windows could not restart or start SwarmControlAgent. Check this task in Windows Task Scheduler.' 1
}
for ($attempt = 0; $attempt -lt 5; $attempt++) {
    Start-Sleep -Seconds 1
    if ((Get-ScheduledTask -TaskName 'SwarmControlAgent').State -eq 'Running') {
        Write-Status '[INSTALLED] SwarmControlAgent is running and scheduled at sign-in.'
        return
    }
}
Stop-Install 'Heartbeat accepted, but SwarmControlAgent is not running. Check this task in Windows Task Scheduler.' 1
} catch {
    $code = 1
    $message = 'Unexpected installation error. Check write permissions, disk space and the previous step in install.log.'
    if ($_.Exception.Data.Contains('InstallCode')) {
        $code = $_.Exception.Data['InstallCode']
        $message = $_.Exception.Message
    } else { Write-Status "[FAILED] $message" }
    if ($Replacing) {
        if ($CreatedTask) {
            try { Unregister-ScheduledTask -TaskName 'SwarmControlAgent' -Confirm:$false -ErrorAction Stop }
            catch { Write-Status '[WARN] Could not remove the new scheduled task during recovery.' }
        }
        try {
            foreach ($f in $ManagedFiles) {
                $dst = Join-Path $InstallDir $f
                if ($BackupDir -and (Test-Path -LiteralPath (Join-Path $BackupDir $f))) {
                    Copy-Item -LiteralPath (Join-Path $BackupDir $f) -Destination $dst -Force
                } elseif (Test-Path -LiteralPath $dst -PathType Leaf) { Remove-Item -LiteralPath $dst -Force }
            }
            if ($BackupDir) { Write-Status "[ROLLBACK] Restored previous observer from $BackupDir." }
            if ($RestartPreviousTask -and $BackupDir) { Start-ScheduledTask -TaskName 'SwarmControlAgent' }
            if ($RestartPreviousProcess -and $BackupDir) { Start-ObserverProcess | Out-Null }
        } catch { Write-Status "[WARN] Automatic recovery was incomplete. Check the task and restore the runtime from $BackupDir." }
    }
    $global:LASTEXITCODE = $code
    if ($InvokedAsFile) { exit $code }
    throw $message
} finally {
    if ($StageDir -and (Test-Path -LiteralPath $StageDir)) { Remove-Item -LiteralPath $StageDir -Recurse -Force -ErrorAction SilentlyContinue }
    if ($Lock) { $Lock.Dispose() }
}
} ($MyInvocation.MyCommand -is [System.Management.Automation.ExternalScriptInfo])
