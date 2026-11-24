# NeuroSwarm Lite Agent Installer for Windows PowerShell (5.1+ / 7+)
$ErrorActionPreference = "Stop"

$InstallDir = if ($env:SWARMCONTROL_INSTALL_DIR) { $env:SWARMCONTROL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "SwarmControl" }
$FromRepo = if ($env:SWARMCONTROL_FROM_REPO) { $env:SWARMCONTROL_FROM_REPO } else { "" }
$NoService = if ($env:SWARMCONTROL_NO_SERVICE) { $env:SWARMCONTROL_NO_SERVICE } else { "0" }
$Upgrade = if ($env:SWARMCONTROL_UPGRADE) { $env:SWARMCONTROL_UPGRADE } else { "0" }

$Saved = @{}
$EnvPath = Join-Path $InstallDir "agent.env"
if ($Upgrade -eq "1") {
    if (-not (Test-Path $EnvPath)) {
        Write-Error -ErrorAction Continue "ERROR: SWARMCONTROL_UPGRADE=1 requires an existing agent.env in $InstallDir."
        exit 2
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
$StateDir = if ($env:SWARMCONTROL_STATE_DIR) { $env:SWARMCONTROL_STATE_DIR } elseif ($Saved.ContainsKey('SWARMCONTROL_STATE_DIR')) { $Saved['SWARMCONTROL_STATE_DIR'] } else { "" }

if (-not $Token) {
    Write-Error -ErrorAction Continue "ERROR: Missing enrollment token. Set `$env:SWARMCONTROL_TOKEN='<TOKEN>' before running install.ps1."
    exit 2
}
if ($Token -notmatch '^[A-Za-z0-9_-]{8,128}$') {
    Write-Error -ErrorAction Continue "ERROR: Enrollment token has an unexpected format."
    exit 2
}
if ($ShareCommands -ne "0" -and $ShareCommands -ne "1") {
    Write-Error -ErrorAction Continue "ERROR: SWARMCONTROL_SHARE_COMMANDS must be 0 or 1."
    exit 2
}
if ($AgentLabels -and $AgentLabels -notmatch '^[A-Za-z0-9._:@,/=+ -]{1,512}$') {
    Write-Error -ErrorAction Continue "ERROR: SWARMCONTROL_AGENT_LABELS contains unsupported characters."
    exit 2
}

$PyExe = ""
foreach ($cand in @("python", "python3")) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike "*\WindowsApps\*") {
        $PyExe = $cmd.Source
        break
    } elseif ($cmd) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & $cmd.Source --version >$null 2>&1
            if ($LASTEXITCODE -eq 0) {
                $PyExe = $cmd.Source
            }
        } catch {
        } finally {
            $ErrorActionPreference = $prevEap
        }
        if ($PyExe) {
            break
        }
    }
}
if (-not $PyExe) {
    Write-Error -ErrorAction Continue "ERROR: Python 3.10+ is required in PATH to run NeuroSwarm Lite Agent (Windows Store alias is not installed)."
    exit 3
}

$ParentDir = Split-Path -Parent $InstallDir
if ($ParentDir) { New-Item -ItemType Directory -Force -Path $ParentDir | Out-Null }
$StageDir = "$InstallDir.staging.$PID"
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

function Fail-Stage([string]$Comp) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $StageDir
    Write-Error -ErrorAction Continue "ERROR: Required observer component $Comp could not be installed; existing configuration left untouched."
    exit 4
}

try {
    if ($FromRepo) {
        Write-Host "[NeuroSwarm] Installing observer client from local repository $FromRepo ..."
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
        Write-Host "[NeuroSwarm] Downloading observer client from $ServerUrl ..."
        foreach ($pair in @(
            @("detector.py", "$ServerUrl/agent/detector.py"),
            @("activity_shipper.py", "$ServerUrl/agent/activity_shipper.py"),
            @("activity_core.py", "$ServerUrl/agent/activity_core.py"),
            @("swarmcontrol_agent.py", "$ServerUrl/agent/swarmcontrol_agent.py")
        )) {
            $dst = Join-Path $StageDir $pair[0]
            try {
                Invoke-WebRequest -UseBasicParsing -Uri $pair[1] -OutFile $dst
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
if ($Upgrade -eq "1" -or (Test-Path (Join-Path $InstallDir "swarmcontrol_agent.py"))) {
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $suffix = [guid]::NewGuid().ToString("N").Substring(0, 6)
    $BackupDir = "$InstallDir.bak.$stamp.$suffix"
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    foreach ($f in @("detector.py", "activity_shipper.py", "activity_core.py", "swarmcontrol_agent.py", "agent.env", "run-agent.ps1")) {
        $src = Join-Path $InstallDir $f
        if (Test-Path $src) { Copy-Item $src (Join-Path $BackupDir $f) -Force }
    }
}

foreach ($f in @("detector.py", "activity_shipper.py", "activity_core.py", "swarmcontrol_agent.py")) {
    Move-Item -Force (Join-Path $StageDir $f) (Join-Path $InstallDir $f)
}
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $StageDir

$HasOverrides = [bool]($env:SWARMCONTROL_SERVER -or $env:SWARMCONTROL_TOKEN -or $env:SWARMCONTROL_INTERVAL -or $env:SWARMCONTROL_HOST_ID -or $env:SWARMCONTROL_ACTIVITY_ROOTS -or $env:SWARMCONTROL_AGENT_LABELS -or $env:SWARMCONTROL_SHARE_COMMANDS -or $env:SWARMCONTROL_STATE_DIR)
if ($Upgrade -ne "1" -or $HasOverrides -or -not (Test-Path $EnvPath)) {
    $EnvLines = @(
        "SWARMCONTROL_SERVER=$ServerUrl",
        "SWARMCONTROL_TOKEN=$Token",
        "SWARMCONTROL_INTERVAL=$Interval",
        "SWARMCONTROL_HOST_ID=$HostId",
        "SWARMCONTROL_ACTIVITY_ROOTS=$ActivityRoots",
        "SWARMCONTROL_AGENT_LABELS=$AgentLabels",
        "SWARMCONTROL_SHARE_COMMANDS=$ShareCommands"
    )
    if ($StateDir) { $EnvLines += "SWARMCONTROL_STATE_DIR=$StateDir" }
    Set-Content -Path $EnvPath -Value ($EnvLines -join "`r`n") -Encoding UTF8
}

Write-Host "[NeuroSwarm] Running initial passive detection & heartbeat test..."
$env:SWARMCONTROL_TOKEN = $Token
$env:SWARMCONTROL_AGENT_LABELS = $AgentLabels
$env:SWARMCONTROL_SHARE_COMMANDS = $ShareCommands
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
try {
    $DiagRaw = & $PyExe @DiagArgs
    if ($LASTEXITCODE -eq 0 -and $DiagRaw) {
        $DiagObj = ($DiagRaw -join "`n") | ConvertFrom-Json
        if ($DiagObj.activity_core_loaded -and ($DiagObj.capture_reader -eq "core") -and (-not $DiagObj.dry_scan_error)) {
            & $PyExe @AgentArgs
            if ($LASTEXITCODE -eq 0) { $VerifyOk = $true }
        }
    }
} catch {
    $VerifyOk = $false
}
if (-not $VerifyOk) {
    if ($Upgrade -eq "1" -and $BackupDir -and (Test-Path $BackupDir)) {
        foreach ($f in @("detector.py", "activity_shipper.py", "activity_core.py", "swarmcontrol_agent.py", "agent.env", "run-agent.ps1")) {
            $bak = Join-Path $BackupDir $f
            $dst = Join-Path $InstallDir $f
            if (Test-Path $bak) {
                Copy-Item $bak $dst -Force
            } elseif ($f -in @("activity_core.py", "activity_shipper.py") -and (Test-Path $dst)) {
                Remove-Item -Force -ErrorAction SilentlyContinue $dst
            }
        }
        Write-Error -ErrorAction Continue "ERROR: Upgrade verification failed; restored previous observer from $BackupDir."
    } else {
        Write-Error -ErrorAction Continue "ERROR: Initial NeuroSwarm heartbeat failed."
    }
    exit 1
}
if ($BackupDir) { Write-Host "[NeuroSwarm] Rollback backup stored at $BackupDir" }

if ($NoService -eq "1") {
    Write-Host "[NeuroSwarm] Installed (no-service mode) at $InstallDir"
    exit 0
}

$RunnerPs1 = Join-Path $InstallDir "run-agent.ps1"
$RunnerBody = @"
`$env:SWARMCONTROL_SERVER = '$ServerUrl'
`$env:SWARMCONTROL_TOKEN = '$Token'
`$env:SWARMCONTROL_INTERVAL = '$Interval'
`$env:SWARMCONTROL_HOST_ID = '$HostId'
`$env:SWARMCONTROL_ACTIVITY_ROOTS = '$ActivityRoots'
`$env:SWARMCONTROL_AGENT_LABELS = '$AgentLabels'
`$env:SWARMCONTROL_SHARE_COMMANDS = '$ShareCommands'
$(if ($StateDir) { "`$env:SWARMCONTROL_STATE_DIR = '$StateDir'" } else { "" })
& '$PyExe' '$(Join-Path $InstallDir "swarmcontrol_agent.py")'
"@
Set-Content -Path $RunnerPs1 -Value $RunnerBody -Encoding UTF8

try {
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$RunnerPs1`""
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName "SwarmControlAgent" -Action $Action -Trigger $Trigger -Force | Out-Null
    Start-ScheduledTask -TaskName "SwarmControlAgent"
    Write-Host "[NeuroSwarm] Active Windows Scheduled Task: SwarmControlAgent"
} catch {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$RunnerPs1`"" -WindowStyle Hidden
    Write-Host "[NeuroSwarm] Started background observer process from $RunnerPs1"
}
