"""Dynamic URL & Repository Installer Generators for NeuroSwarm Lite Agent.

See REMOTE-CONTRACT.md for the observer protocol.
Supports:
- Linux (`systemd --user` with automatic background daemon fallback)
- macOS (`launchd` `~/Library/LaunchAgents/org.swarmcontrol.agent.plist`)
- WSL & container hosts (PID-tracked `nohup` background daemon + idempotent launcher)
- Windows PowerShell (`render_powershell_install_script`, Scheduled Task + background runner)
- Both URL download (`curl -fsSL <base>/install.sh | bash`) and local repo install (`--from-repo`)
- Atomic staging requiring `activity_core.py` and reversible `--upgrade` with automatic rollback
"""

from __future__ import annotations

import re

SAFE_BASE_URL = re.compile(
    r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$|^https?://\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$"
)


def render_install_script(base_url: str = "http://127.0.0.1:8790") -> str:
    clean_base = base_url.rstrip("/")
    if not SAFE_BASE_URL.match(clean_base):
        raise ValueError("Unsafe base URL for installer")
    return f"""#!/usr/bin/env bash
set -euo pipefail

# NeuroSwarm Lite Agent Installer for Linux / macOS / WSL
# Passive, non-intrusive observer + opt-in folder activity shipper for AI agent harnesses.

CLI_SERVER=""
CLI_TOKEN=""
CLI_INTERVAL=""
CLI_HOST_ID=""
CLI_ACTIVITY_ROOTS=""
CLI_AGENT_LABELS=""
CLI_SHARE_COMMANDS=""
HAS_CLI_SHARE=0
CLI_SHARE_COMMAND_OUTPUT=""
HAS_CLI_SHARE_OUTPUT=0
CLI_SHARE_FILE_PREVIEWS=""
HAS_CLI_SHARE_PREVIEWS=0
INSTALL_DIR="${{SWARMCONTROL_INSTALL_DIR:-$HOME/.local/share/swarmcontrol}}"
FROM_REPO=""
NO_SERVICE="0"
UPGRADE="${{SWARMCONTROL_UPGRADE:-0}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      CLI_SERVER="$2"
      shift 2
      ;;
    --token)
      CLI_TOKEN="$2"
      shift 2
      ;;
    --interval)
      CLI_INTERVAL="$2"
      shift 2
      ;;
    --host-id)
      CLI_HOST_ID="$2"
      shift 2
      ;;
    --activity-roots)
      CLI_ACTIVITY_ROOTS="$2"
      shift 2
      ;;
    --agent-labels)
      CLI_AGENT_LABELS="$2"
      shift 2
      ;;
    --share-commands)
      CLI_SHARE_COMMANDS="1"
      HAS_CLI_SHARE=1
      shift 1
      ;;
    --share-command-output)
      CLI_SHARE_COMMAND_OUTPUT="1"
      HAS_CLI_SHARE_OUTPUT=1
      shift 1
      ;;
    --share-file-previews)
      CLI_SHARE_FILE_PREVIEWS="1"
      HAS_CLI_SHARE_PREVIEWS=1
      shift 1
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --from-repo)
      FROM_REPO="${{2:-.}}"
      shift 2
      ;;
    --no-service)
      NO_SERVICE="1"
      shift 1
      ;;
    --upgrade)
      UPGRADE="1"
      shift 1
      ;;
    -h|--help)
      echo "Usage: curl -fsSL {clean_base}/install.sh | SWARMCONTROL_TOKEN=<TOKEN> bash -s -- [--interval 15] [--host-id name] [--activity-roots /path/a:/path/b] [--agent-labels folder=Name] [--share-commands] [--share-command-output] [--share-file-previews] [--from-repo /path/to/repo] [--upgrade] [--no-service]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

ENV_SERVER="${{SWARMCONTROL_SERVER:-}}"
ENV_TOKEN="${{SWARMCONTROL_TOKEN:-}}"
ENV_INTERVAL="${{SWARMCONTROL_INTERVAL:-}}"
ENV_HOST_ID="${{SWARMCONTROL_HOST_ID:-}}"
ENV_ACTIVITY_ROOTS="${{SWARMCONTROL_ACTIVITY_ROOTS:-}}"
ENV_AGENT_LABELS="${{SWARMCONTROL_AGENT_LABELS:-}}"
ENV_SHARE_COMMANDS="${{SWARMCONTROL_SHARE_COMMANDS:-}}"
ENV_SHARE_COMMAND_OUTPUT="${{SWARMCONTROL_SHARE_COMMAND_OUTPUT:-}}"
ENV_SHARE_FILE_PREVIEWS="${{SWARMCONTROL_SHARE_FILE_PREVIEWS:-}}"
ENV_STATE_DIR="${{SWARMCONTROL_STATE_DIR:-}}"

SAVED_SERVER=""
SAVED_TOKEN=""
SAVED_INTERVAL=""
SAVED_HOST_ID=""
SAVED_ACTIVITY_ROOTS=""
SAVED_AGENT_LABELS=""
SAVED_SHARE_COMMANDS=""
SAVED_SHARE_COMMAND_OUTPUT=""
SAVED_SHARE_FILE_PREVIEWS=""
SAVED_STATE_DIR=""

if [[ "$UPGRADE" == "1" ]]; then
  if [[ ! -f "$INSTALL_DIR/agent.env" ]]; then
    echo "ERROR: --upgrade requires an existing installation with agent.env in $INSTALL_DIR." >&2
    exit 2
  fi
  while IFS='=' read -r k v; do
    k="${{k#$'\\ufeff'}}"
    v="${{v%$'\\r'}}"
    case "$k" in
      ''|\\#*) continue ;;
      SWARMCONTROL_SERVER) SAVED_SERVER="$v" ;;
      SWARMCONTROL_TOKEN) SAVED_TOKEN="$v" ;;
      SWARMCONTROL_INTERVAL) SAVED_INTERVAL="$v" ;;
      SWARMCONTROL_HOST_ID) SAVED_HOST_ID="$v" ;;
      SWARMCONTROL_ACTIVITY_ROOTS) SAVED_ACTIVITY_ROOTS="$v" ;;
      SWARMCONTROL_AGENT_LABELS) SAVED_AGENT_LABELS="$v" ;;
      SWARMCONTROL_SHARE_COMMANDS) SAVED_SHARE_COMMANDS="$v" ;;
      SWARMCONTROL_SHARE_COMMAND_OUTPUT) SAVED_SHARE_COMMAND_OUTPUT="$v" ;;
      SWARMCONTROL_SHARE_FILE_PREVIEWS) SAVED_SHARE_FILE_PREVIEWS="$v" ;;
      SWARMCONTROL_STATE_DIR) SAVED_STATE_DIR="$v" ;;
    esac
  done < "$INSTALL_DIR/agent.env"
fi

SERVER_URL="${{SWARMCONTROL_SERVER:-{clean_base}}}"
if [[ -z "$ENV_SERVER" && -n "$SAVED_SERVER" ]]; then
  SERVER_URL="$SAVED_SERVER"
fi
if [[ -n "$CLI_SERVER" ]]; then
  SERVER_URL="$CLI_SERVER"
fi
TOKEN="${{CLI_TOKEN:-${{ENV_TOKEN:-$SAVED_TOKEN}}}}"
INTERVAL="${{CLI_INTERVAL:-${{ENV_INTERVAL:-${{SAVED_INTERVAL:-15}}}}}}"
HOST_ID="${{CLI_HOST_ID:-${{ENV_HOST_ID:-$SAVED_HOST_ID}}}}"
ACTIVITY_ROOTS="${{CLI_ACTIVITY_ROOTS:-${{ENV_ACTIVITY_ROOTS:-$SAVED_ACTIVITY_ROOTS}}}}"
AGENT_LABELS="${{CLI_AGENT_LABELS:-${{ENV_AGENT_LABELS:-$SAVED_AGENT_LABELS}}}}"
if [[ "$HAS_CLI_SHARE" == "1" ]]; then
  SHARE_COMMANDS="$CLI_SHARE_COMMANDS"
elif [[ -n "$ENV_SHARE_COMMANDS" ]]; then
  SHARE_COMMANDS="$ENV_SHARE_COMMANDS"
elif [[ -n "$SAVED_SHARE_COMMANDS" ]]; then
  SHARE_COMMANDS="$SAVED_SHARE_COMMANDS"
else
  SHARE_COMMANDS="0"
fi
if [[ "$HAS_CLI_SHARE_OUTPUT" == "1" ]]; then
  SHARE_COMMAND_OUTPUT="$CLI_SHARE_COMMAND_OUTPUT"
elif [[ -n "$ENV_SHARE_COMMAND_OUTPUT" ]]; then
  SHARE_COMMAND_OUTPUT="$ENV_SHARE_COMMAND_OUTPUT"
elif [[ -n "$SAVED_SHARE_COMMAND_OUTPUT" ]]; then
  SHARE_COMMAND_OUTPUT="$SAVED_SHARE_COMMAND_OUTPUT"
else
  SHARE_COMMAND_OUTPUT="0"
fi
if [[ "$HAS_CLI_SHARE_PREVIEWS" == "1" ]]; then
  SHARE_FILE_PREVIEWS="$CLI_SHARE_FILE_PREVIEWS"
elif [[ -n "$ENV_SHARE_FILE_PREVIEWS" ]]; then
  SHARE_FILE_PREVIEWS="$ENV_SHARE_FILE_PREVIEWS"
elif [[ -n "$SAVED_SHARE_FILE_PREVIEWS" ]]; then
  SHARE_FILE_PREVIEWS="$SAVED_SHARE_FILE_PREVIEWS"
else
  SHARE_FILE_PREVIEWS="0"
fi
STATE_DIR="${{ENV_STATE_DIR:-$SAVED_STATE_DIR}}"

HAS_OVERRIDES=0
if [[ -n "$CLI_SERVER$CLI_TOKEN$CLI_INTERVAL$CLI_HOST_ID$CLI_ACTIVITY_ROOTS$CLI_AGENT_LABELS" ]] || [[ "$HAS_CLI_SHARE$HAS_CLI_SHARE_OUTPUT$HAS_CLI_SHARE_PREVIEWS" != "000" ]] || [[ -n "$ENV_SERVER$ENV_TOKEN$ENV_INTERVAL$ENV_HOST_ID$ENV_ACTIVITY_ROOTS$ENV_AGENT_LABELS$ENV_SHARE_COMMANDS$ENV_SHARE_COMMAND_OUTPUT$ENV_SHARE_FILE_PREVIEWS$ENV_STATE_DIR" ]]; then
  HAS_OVERRIDES=1
fi

if [[ -z "$TOKEN" ]]; then
  echo "ERROR: Missing enrollment token. Set SWARMCONTROL_TOKEN=<TOKEN> (generated in the NeuroSwarm UI)." >&2
  exit 2
fi
if [[ ! "$TOKEN" =~ ^[A-Za-z0-9_-]{{8,128}}$ ]]; then
  echo "ERROR: Enrollment token has an unexpected format." >&2
  exit 2
fi
if [[ ! "$INTERVAL" =~ ^[0-9]{{1,5}}$ ]]; then
  echo "ERROR: --interval must be a whole number of seconds." >&2
  exit 2
fi
if [[ -n "$HOST_ID" && ! "$HOST_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:@-]{{0,127}}$ ]]; then
  echo "ERROR: --host-id may only contain letters, digits and . _ : @ - (max 128 chars)." >&2
  exit 2
fi
if [[ "$SHARE_COMMANDS" != "0" && "$SHARE_COMMANDS" != "1" ]]; then
  echo "ERROR: SWARMCONTROL_SHARE_COMMANDS must be 0 or 1." >&2
  exit 2
fi
if [[ "$SHARE_COMMAND_OUTPUT" != "0" && "$SHARE_COMMAND_OUTPUT" != "1" ]]; then
  echo "ERROR: SWARMCONTROL_SHARE_COMMAND_OUTPUT must be 0 or 1." >&2
  exit 2
fi
if [[ "$SHARE_FILE_PREVIEWS" != "0" && "$SHARE_FILE_PREVIEWS" != "1" ]]; then
  echo "ERROR: SWARMCONTROL_SHARE_FILE_PREVIEWS must be 0 or 1." >&2
  exit 2
fi
if [[ -n "$AGENT_LABELS" ]] && [[ "$AGENT_LABELS" == *$'\\n'* || ! "$AGENT_LABELS" =~ ^[A-Za-z0-9._:@,/=+[:blank:]-]{{1,512}}$ ]]; then
  echo "ERROR: --agent-labels may only contain safe label characters (max 512 chars)." >&2
  exit 2
fi
if [[ ! "$SERVER_URL" =~ ^https?://[][A-Za-z0-9.:/_~-]+$ ]]; then
  echo "ERROR: --server must be an http(s) URL." >&2
  exit 2
fi
case "$SERVER_URL" in
  https://*|http://127.0.0.1*|http://localhost*|http://\\[::1\\]*) ;;
  *) echo "WARNING: $SERVER_URL is not HTTPS; the enrollment token will travel in clear text." >&2 ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 (3.10+) is required to run NeuroSwarm Lite Agent." >&2
  exit 3
fi

umask 077
mkdir -p "$(dirname "$INSTALL_DIR")"
STAGE_DIR="$(mktemp -d "${{INSTALL_DIR}}.staging.XXXXXX")"
cleanup_stage() {{
  rm -rf "$STAGE_DIR"
}}
trap cleanup_stage EXIT

_stage_fail() {{
  echo "ERROR: Required observer component $1 could not be installed; existing configuration left untouched." >&2
  exit 4
}}

if [[ -n "$FROM_REPO" ]]; then
  echo "[NeuroSwarm] Installing observer client from local repository $FROM_REPO ..."
  [[ -d "$FROM_REPO/agent" ]] || _stage_fail "agent directory ($FROM_REPO/agent)"
  [[ -s "$FROM_REPO/agent/detector.py" ]] || _stage_fail "detector.py"
  cp "$FROM_REPO/agent/detector.py" "$STAGE_DIR/detector.py"
  [[ -s "$FROM_REPO/agent/activity_shipper.py" ]] || _stage_fail "activity_shipper.py"
  cp "$FROM_REPO/agent/activity_shipper.py" "$STAGE_DIR/activity_shipper.py"
  [[ -s "$FROM_REPO/backend/activity_inspector.py" ]] || _stage_fail "activity_core.py ($FROM_REPO/backend/activity_inspector.py)"
  cp "$FROM_REPO/backend/activity_inspector.py" "$STAGE_DIR/activity_core.py"
  [[ -s "$FROM_REPO/agent/swarmcontrol_agent.py" ]] || _stage_fail "swarmcontrol_agent.py"
  cp "$FROM_REPO/agent/swarmcontrol_agent.py" "$STAGE_DIR/swarmcontrol_agent.py"
else
  echo "[NeuroSwarm] Downloading observer client from $SERVER_URL ..."
  curl -fsSL "$SERVER_URL/agent/detector.py" -o "$STAGE_DIR/detector.py" && [[ -s "$STAGE_DIR/detector.py" ]] || _stage_fail "detector.py"
  curl -fsSL "$SERVER_URL/agent/activity_shipper.py" -o "$STAGE_DIR/activity_shipper.py" && [[ -s "$STAGE_DIR/activity_shipper.py" ]] || _stage_fail "activity_shipper.py"
  curl -fsSL "$SERVER_URL/agent/activity_core.py" -o "$STAGE_DIR/activity_core.py" && [[ -s "$STAGE_DIR/activity_core.py" ]] || _stage_fail "activity_core.py"
  curl -fsSL "$SERVER_URL/agent/swarmcontrol_agent.py" -o "$STAGE_DIR/swarmcontrol_agent.py" && [[ -s "$STAGE_DIR/swarmcontrol_agent.py" ]] || _stage_fail "swarmcontrol_agent.py"
fi

mkdir -p "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR"

BACKUP_DIR=""
if [[ "$UPGRADE" == "1" || -f "$INSTALL_DIR/swarmcontrol_agent.py" ]]; then
  BACKUP_DIR="$(mktemp -d "${{INSTALL_DIR}}.bak.$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"
  chmod 700 "$BACKUP_DIR"
  for f in detector.py activity_shipper.py activity_core.py swarmcontrol_agent.py agent.env; do
    if [[ -f "$INSTALL_DIR/$f" ]]; then
      cp -p "$INSTALL_DIR/$f" "$BACKUP_DIR/$f"
    fi
  done
fi

_rollback_backup() {{
  if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then
    for f in detector.py activity_shipper.py activity_core.py swarmcontrol_agent.py agent.env; do
      if [[ -f "$BACKUP_DIR/$f" ]]; then
        cp -p "$BACKUP_DIR/$f" "$INSTALL_DIR/$f"
      fi
    done
    [[ -f "$BACKUP_DIR/activity_core.py" ]] || rm -f "$INSTALL_DIR/activity_core.py"
    [[ -f "$BACKUP_DIR/activity_shipper.py" ]] || rm -f "$INSTALL_DIR/activity_shipper.py"
    chmod 700 "$INSTALL_DIR/swarmcontrol_agent.py" 2>/dev/null || true
    chmod 600 "$INSTALL_DIR/agent.env" 2>/dev/null || true
  fi
}}

for f in detector.py activity_shipper.py activity_core.py swarmcontrol_agent.py; do
  mv -f "$STAGE_DIR/$f" "$INSTALL_DIR/$f"
done
chmod 700 "$INSTALL_DIR/swarmcontrol_agent.py"

if [[ "$UPGRADE" != "1" || "$HAS_OVERRIDES" == "1" || ! -f "$INSTALL_DIR/agent.env" ]]; then
  cat > "$INSTALL_DIR/agent.env" <<EOF
SWARMCONTROL_SERVER=$SERVER_URL
SWARMCONTROL_TOKEN=$TOKEN
SWARMCONTROL_INTERVAL=$INTERVAL
SWARMCONTROL_HOST_ID=$HOST_ID
SWARMCONTROL_ACTIVITY_ROOTS=$ACTIVITY_ROOTS
SWARMCONTROL_AGENT_LABELS=$AGENT_LABELS
SWARMCONTROL_SHARE_COMMANDS=$SHARE_COMMANDS
SWARMCONTROL_SHARE_COMMAND_OUTPUT=$SHARE_COMMAND_OUTPUT
SWARMCONTROL_SHARE_FILE_PREVIEWS=$SHARE_FILE_PREVIEWS
EOF
  if [[ -n "$STATE_DIR" ]]; then
    echo "SWARMCONTROL_STATE_DIR=$STATE_DIR" >> "$INSTALL_DIR/agent.env"
  fi
  chmod 600 "$INSTALL_DIR/agent.env"
fi

echo "[NeuroSwarm] Running initial passive detection & heartbeat test..."
_run_verify() {{
  local run_env=(
    SWARMCONTROL_TOKEN="$TOKEN"
    SWARMCONTROL_ACTIVITY_ROOTS="$ACTIVITY_ROOTS"
    SWARMCONTROL_AGENT_LABELS="$AGENT_LABELS"
    SWARMCONTROL_SHARE_COMMANDS="$SHARE_COMMANDS"
    SWARMCONTROL_SHARE_COMMAND_OUTPUT="$SHARE_COMMAND_OUTPUT"
    SWARMCONTROL_SHARE_FILE_PREVIEWS="$SHARE_FILE_PREVIEWS"
  )
  if [[ -n "$STATE_DIR" ]]; then
    run_env+=(SWARMCONTROL_STATE_DIR="$STATE_DIR")
  fi
  local diag_cmd=(python3 "$INSTALL_DIR/swarmcontrol_agent.py" --diagnose)
  local verify_cmd=(python3 "$INSTALL_DIR/swarmcontrol_agent.py" --server "$SERVER_URL" --once)
  if [[ -n "$HOST_ID" ]]; then
    diag_cmd+=(--host-id "$HOST_ID")
    verify_cmd+=(--host-id "$HOST_ID")
  fi
  if [[ -n "$ACTIVITY_ROOTS" ]]; then
    diag_cmd+=(--activity-roots "$ACTIVITY_ROOTS")
    verify_cmd+=(--activity-roots "$ACTIVITY_ROOTS")
  fi
  local diag_json
  diag_json="$(env "${{run_env[@]}}" "${{diag_cmd[@]}}")" || return 1
  printf '%s' "$diag_json" | python3 -c "import json, sys; d = json.load(sys.stdin); sys.exit(0 if d.get('activity_core_loaded') is True and d.get('capture_reader') == 'core' and not d.get('dry_scan_error') else 1)" || return 1
  env "${{run_env[@]}}" "${{verify_cmd[@]}}" || return 1
}}

if ! _run_verify; then
  if [[ "$UPGRADE" == "1" && -n "$BACKUP_DIR" ]]; then
    _rollback_backup
    echo "ERROR: Upgrade verification failed; restored previous observer from $BACKUP_DIR." >&2
  fi
  exit 1
fi

if [[ -n "$BACKUP_DIR" ]]; then
  echo "[NeuroSwarm] Rollback backup stored at $BACKUP_DIR"
fi

if [[ "$NO_SERVICE" == "1" ]]; then
  echo "[NeuroSwarm] Installed (no-service mode). Run manually:"
  echo "  set -a; source $INSTALL_DIR/agent.env; set +a; python3 $INSTALL_DIR/swarmcontrol_agent.py"
  exit 0
fi

OS_NAME="$(uname -s 2>/dev/null || echo Unknown)"

# 1. macOS launchd user agent
if [[ "$OS_NAME" == "Darwin" ]]; then
  PLIST_DIR="$HOME/Library/LaunchAgents"
  PLIST_PATH="$PLIST_DIR/org.swarmcontrol.agent.plist"
  mkdir -p "$PLIST_DIR"
  PY_BIN="$(command -v python3)"
  cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>org.swarmcontrol.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PY_BIN</string>
    <string>$INSTALL_DIR/swarmcontrol_agent.py</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SWARMCONTROL_SERVER</key>
    <string>$SERVER_URL</string>
    <key>SWARMCONTROL_TOKEN</key>
    <string>$TOKEN</string>
    <key>SWARMCONTROL_INTERVAL</key>
    <string>$INTERVAL</string>
    <key>SWARMCONTROL_HOST_ID</key>
    <string>$HOST_ID</string>
    <key>SWARMCONTROL_ACTIVITY_ROOTS</key>
    <string>$ACTIVITY_ROOTS</string>
    <key>SWARMCONTROL_AGENT_LABELS</key>
    <string>$AGENT_LABELS</string>
    <key>SWARMCONTROL_SHARE_COMMANDS</key>
    <string>$SHARE_COMMANDS</string>
    <key>SWARMCONTROL_SHARE_COMMAND_OUTPUT</key>
    <string>$SHARE_COMMAND_OUTPUT</string>
    <key>SWARMCONTROL_SHARE_FILE_PREVIEWS</key>
    <string>$SHARE_FILE_PREVIEWS</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>Nice</key>
  <integer>15</integer>
  <key>StandardOutPath</key>
  <string>$INSTALL_DIR/agent.log</string>
  <key>StandardErrorPath</key>
  <string>$INSTALL_DIR/agent.log</string>
</dict>
</plist>
EOF
  chmod 600 "$PLIST_PATH"
  launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
  if launchctl load -w "$PLIST_PATH" >/dev/null 2>&1; then
    echo "[NeuroSwarm] Active macOS launchd agent: org.swarmcontrol.agent"
    exit 0
  fi
fi

# 2. Linux / WSL systemd user service
if command -v systemctl >/dev/null 2>&1; then
  UNIT_DIR="$HOME/.config/systemd/user"
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/swarmcontrol-agent.service" <<EOF
[Unit]
Description=NeuroSwarm Lite Agent (Passive AI Harness Observer)
After=network-online.target

[Service]
Type=simple
EnvironmentFile=$INSTALL_DIR/agent.env
ExecStart=$(command -v python3) $INSTALL_DIR/swarmcontrol_agent.py
Restart=always
RestartSec=10
Nice=15
MemoryMax=128M

[Install]
WantedBy=default.target
EOF
  if systemctl --user daemon-reload >/dev/null 2>&1 && systemctl --user enable --now swarmcontrol-agent.service >/dev/null 2>&1; then
    if [[ "$UPGRADE" == "1" ]]; then
      systemctl --user restart swarmcontrol-agent.service >/dev/null 2>&1 || true
    fi
    echo "[NeuroSwarm] Active systemd user service: swarmcontrol-agent.service (Nice=15, MemoryMax=128M)"
    if command -v loginctl >/dev/null 2>&1 && [[ "$(loginctl show-user "${{USER:-$(id -un)}}" -p Linger --value 2>/dev/null)" != "yes" ]]; then
      echo "[NeuroSwarm] Note: run 'loginctl enable-linger ${{USER:-$(id -un)}}' so the observer keeps running after you log out."
    fi
    exit 0
  fi
fi

# 3. Universal WSL / non-systemd fallback launcher
cat > "$INSTALL_DIR/run-daemon.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "$DIR/agent.pid" ]] && kill -0 "$(cat "$DIR/agent.pid")" 2>/dev/null; then
  exit 0
fi
set -a
source "$DIR/agent.env"
set +a
nohup python3 "$DIR/swarmcontrol_agent.py" >> "$DIR/agent.log" 2>&1 &
echo $! > "$DIR/agent.pid"
EOF
chmod 700 "$INSTALL_DIR/run-daemon.sh"
if [[ "$UPGRADE" == "1" && -f "$INSTALL_DIR/agent.pid" ]] && kill -0 "$(cat "$INSTALL_DIR/agent.pid")" 2>/dev/null; then
  kill "$(cat "$INSTALL_DIR/agent.pid")" 2>/dev/null || true
  sleep 1
fi
"$INSTALL_DIR/run-daemon.sh"
echo "[NeuroSwarm] Started background observer daemon (PID $(cat "$INSTALL_DIR/agent.pid"), launcher: $INSTALL_DIR/run-daemon.sh)"
"""


def render_powershell_install_script(base_url: str = "http://127.0.0.1:8790") -> str:
    clean_base = base_url.rstrip("/")
    if not SAFE_BASE_URL.match(clean_base):
        raise ValueError("Unsafe base URL for PowerShell installer")
    return f"""# NeuroSwarm Lite Agent Installer for Windows PowerShell (5.1+ / 7+)
& {{
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

$InstallDir = if ($env:SWARMCONTROL_INSTALL_DIR) {{ $env:SWARMCONTROL_INSTALL_DIR }} else {{ Join-Path $env:LOCALAPPDATA "SwarmControl" }}
$FromRepo = if ($env:SWARMCONTROL_FROM_REPO) {{ $env:SWARMCONTROL_FROM_REPO }} else {{ "" }}
$NoService = if ($env:SWARMCONTROL_NO_SERVICE) {{ $env:SWARMCONTROL_NO_SERVICE }} else {{ "0" }}
$Upgrade = if ($env:SWARMCONTROL_UPGRADE) {{ $env:SWARMCONTROL_UPGRADE }} else {{ "0" }}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$InstallLog = Join-Path $InstallDir 'install.log'
function Write-Status([string]$Message) {{
    Write-Host $Message
    Add-Content -LiteralPath $InstallLog -Encoding UTF8 -Value ("{{0:u}} {{1}}" -f [datetime]::UtcNow, $Message)
}}
function Stop-Install([string]$Message, [int]$Code) {{
    Write-Status "[FAILED] $Message"
    $failure = [InvalidOperationException]::new($Message)
    $failure.Data['InstallCode'] = $Code
    throw $failure
}}
$Lock = $null
$StageDir = $null
$BackupDir = $null
$Replacing = $false
$CreatedTask = $false
$RestartPreviousTask = $false
$RestartPreviousProcess = $false
$ManagedFiles = @('detector.py', 'activity_shipper.py', 'activity_core.py', 'swarmcontrol_agent.py', 'agent.env', 'run-agent.ps1')
try {{
try {{
    $Lock = [IO.File]::Open((Join-Path $InstallDir 'install.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
}} catch {{ Stop-Install 'Cannot lock the installation folder. Check write access or wait for the other installer to finish.' 4 }}
Write-Status "[START] Installation log: $InstallLog"
$Saved = @{{}}
$EnvPath = Join-Path $InstallDir "agent.env"
if (-not $env:SWARMCONTROL_UPGRADE -and (Test-Path -LiteralPath $EnvPath)) {{ $Upgrade = "1" }}
if ($Upgrade -eq "1") {{
    if (-not (Test-Path $EnvPath)) {{
        Stop-Install "SWARMCONTROL_UPGRADE=1 requires an existing agent.env in $InstallDir." 2
    }}
    foreach ($line in Get-Content $EnvPath -Encoding UTF8) {{
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#') -or -not $trimmed.Contains('=')) {{ continue }}
        $parts = $trimmed.Split('=', 2)
        $Saved[$parts[0].Trim()] = $parts[1].Trim()
    }}
}}

$ServerUrl = if ($env:SWARMCONTROL_SERVER) {{ $env:SWARMCONTROL_SERVER.TrimEnd('/') }} elseif ($Saved.ContainsKey('SWARMCONTROL_SERVER') -and $Saved['SWARMCONTROL_SERVER']) {{ $Saved['SWARMCONTROL_SERVER'].TrimEnd('/') }} else {{ "{clean_base}" }}
$Token = if ($env:SWARMCONTROL_TOKEN) {{ $env:SWARMCONTROL_TOKEN }} elseif ($Saved.ContainsKey('SWARMCONTROL_TOKEN')) {{ $Saved['SWARMCONTROL_TOKEN'] }} else {{ "" }}
$Interval = if ($env:SWARMCONTROL_INTERVAL) {{ $env:SWARMCONTROL_INTERVAL }} elseif ($Saved.ContainsKey('SWARMCONTROL_INTERVAL') -and $Saved['SWARMCONTROL_INTERVAL']) {{ $Saved['SWARMCONTROL_INTERVAL'] }} else {{ "15" }}
$HostId = if ($env:SWARMCONTROL_HOST_ID) {{ $env:SWARMCONTROL_HOST_ID }} elseif ($Saved.ContainsKey('SWARMCONTROL_HOST_ID') -and $Saved['SWARMCONTROL_HOST_ID']) {{ $Saved['SWARMCONTROL_HOST_ID'] }} else {{ $env:COMPUTERNAME }}
$ActivityRoots = if ($env:SWARMCONTROL_ACTIVITY_ROOTS) {{ $env:SWARMCONTROL_ACTIVITY_ROOTS }} elseif ($Saved.ContainsKey('SWARMCONTROL_ACTIVITY_ROOTS')) {{ $Saved['SWARMCONTROL_ACTIVITY_ROOTS'] }} else {{ "" }}
$AgentLabels = if ($env:SWARMCONTROL_AGENT_LABELS) {{ $env:SWARMCONTROL_AGENT_LABELS }} elseif ($Saved.ContainsKey('SWARMCONTROL_AGENT_LABELS')) {{ $Saved['SWARMCONTROL_AGENT_LABELS'] }} else {{ "" }}
$ShareCommands = if ($env:SWARMCONTROL_SHARE_COMMANDS) {{ $env:SWARMCONTROL_SHARE_COMMANDS }} elseif ($Saved.ContainsKey('SWARMCONTROL_SHARE_COMMANDS') -and $Saved['SWARMCONTROL_SHARE_COMMANDS']) {{ $Saved['SWARMCONTROL_SHARE_COMMANDS'] }} else {{ "0" }}
$ShareCommandOutput = if ($env:SWARMCONTROL_SHARE_COMMAND_OUTPUT) {{ $env:SWARMCONTROL_SHARE_COMMAND_OUTPUT }} elseif ($Saved.ContainsKey('SWARMCONTROL_SHARE_COMMAND_OUTPUT') -and $Saved['SWARMCONTROL_SHARE_COMMAND_OUTPUT']) {{ $Saved['SWARMCONTROL_SHARE_COMMAND_OUTPUT'] }} else {{ "0" }}
$ShareFilePreviews = if ($env:SWARMCONTROL_SHARE_FILE_PREVIEWS) {{ $env:SWARMCONTROL_SHARE_FILE_PREVIEWS }} elseif ($Saved.ContainsKey('SWARMCONTROL_SHARE_FILE_PREVIEWS') -and $Saved['SWARMCONTROL_SHARE_FILE_PREVIEWS']) {{ $Saved['SWARMCONTROL_SHARE_FILE_PREVIEWS'] }} else {{ "0" }}
$StateDir = if ($env:SWARMCONTROL_STATE_DIR) {{ $env:SWARMCONTROL_STATE_DIR }} elseif ($Saved.ContainsKey('SWARMCONTROL_STATE_DIR')) {{ $Saved['SWARMCONTROL_STATE_DIR'] }} else {{ "" }}

if (-not $Token) {{
    Stop-Install "Missing enrollment token. Set `$env:SWARMCONTROL_TOKEN='<TOKEN>' before running install.ps1." 2
}}
if ($Token -notmatch '^[A-Za-z0-9_-]{{8,128}}$') {{
    Stop-Install "Enrollment token has an unexpected format." 2
}}
if ($ShareCommands -ne "0" -and $ShareCommands -ne "1") {{
    Stop-Install "SWARMCONTROL_SHARE_COMMANDS must be 0 or 1." 2
}}
if ($ShareCommandOutput -ne "0" -and $ShareCommandOutput -ne "1") {{
    Stop-Install "SWARMCONTROL_SHARE_COMMAND_OUTPUT must be 0 or 1." 2
}}
if ($ShareFilePreviews -ne "0" -and $ShareFilePreviews -ne "1") {{
    Stop-Install "SWARMCONTROL_SHARE_FILE_PREVIEWS must be 0 or 1." 2
}}
if ($AgentLabels -and $AgentLabels -notmatch '^[A-Za-z0-9._:@,/=+ -]{{1,512}}$') {{
    Stop-Install "SWARMCONTROL_AGENT_LABELS contains unsupported characters." 2
}}

function Find-ObserverPython {{
    $probe = 'import sys, sqlite3, ssl; print(sys.executable) if sys.version_info >= (3,10) else sys.exit(1)'
    $apps = @(Get-Command -Name python, py, python3 -CommandType Application -ErrorAction SilentlyContinue)
    # A newly installed Python may be absent from this PowerShell session's PATH.
    $paths = @($apps | ForEach-Object {{ $_.Source }})
    if ($env:LOCALAPPDATA) {{ $paths += Join-Path $env:LOCALAPPDATA 'Programs/Python/Python313/python.exe' }}
    foreach ($path in $paths) {{
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {{ continue }}
        $probeArgs = @('-I', '-c', $probe)
        if ([IO.Path]::GetFileNameWithoutExtension($path) -eq 'py') {{ $probeArgs = @('-3') + $probeArgs }}
        $ErrorActionPreference = "Continue"
        try {{
            $exe = & $path @probeArgs 2>$null
            if ($LASTEXITCODE -eq 0 -and $exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {{ return $exe }}
        }} catch {{ continue }}
    }}
}}
Write-Status '[CHECK] Looking for Python 3.10+ with SQLite and TLS...'
$PyExe = Find-ObserverPython
if (-not $PyExe) {{
    $winget = Get-Command winget -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $winget) {{ Stop-Install 'Python 3.10+ is required. Install Microsoft App Installer (WinGet) or Python from python.org, then rerun this command.' 3 }}
    Write-Status '[INSTALL] Installing Python 3.13 for this Windows user through WinGet...'
    $savedPreference = $ErrorActionPreference
    try {{
        $ErrorActionPreference = 'Continue'
        & $winget.Source install --id Python.Python.3.13 --exact --source winget --scope user --silent --disable-interactivity --accept-package-agreements --accept-source-agreements
        $wingetCode = $LASTEXITCODE
    }} finally {{ $ErrorActionPreference = $savedPreference }}
    $PyExe = Find-ObserverPython
    if (-not $PyExe) {{ Stop-Install "WinGet returned $wingetCode and Python is still unavailable. Reopen PowerShell and retry, or install Python 3.10+ from python.org." 3 }}
}}
Write-Status '[OK] Python is ready.'

$ParentDir = Split-Path -Parent $InstallDir
if ($ParentDir) {{ New-Item -ItemType Directory -Force -Path $ParentDir | Out-Null }}
$StageDir = "$InstallDir.staging.$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

function Fail-Stage([string]$Comp) {{
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $StageDir
    Stop-Install "Required observer component $Comp could not be installed; existing configuration left untouched." 4
}}

try {{
    if ($FromRepo) {{
        Write-Status "[COPY] Installing the local observer components..."
        foreach ($pair in @(
            @("agent\\detector.py", "detector.py"),
            @("agent\\activity_shipper.py", "activity_shipper.py"),
            @("backend\\activity_inspector.py", "activity_core.py"),
            @("agent\\swarmcontrol_agent.py", "swarmcontrol_agent.py")
        )) {{
            $src = Join-Path $FromRepo $pair[0]
            if (-not (Test-Path $src) -or (Get-Item $src).Length -le 0) {{ Fail-Stage $pair[1] }}
            Copy-Item $src (Join-Path $StageDir $pair[1]) -Force
        }}
    }} else {{
        Write-Status "[DOWNLOAD] Fetching the observer components..."
        foreach ($pair in @(
            @("detector.py", "$ServerUrl/agent/detector.py"),
            @("activity_shipper.py", "$ServerUrl/agent/activity_shipper.py"),
            @("activity_core.py", "$ServerUrl/agent/activity_core.py"),
            @("swarmcontrol_agent.py", "$ServerUrl/agent/swarmcontrol_agent.py")
        )) {{
            $dst = Join-Path $StageDir $pair[0]
            try {{
                Invoke-WebRequest -UseBasicParsing -Uri $pair[1] -OutFile $dst -TimeoutSec 30
            }} catch {{
                Fail-Stage $pair[0]
            }}
            if (-not (Test-Path $dst) -or (Get-Item $dst).Length -le 0) {{
                Fail-Stage $pair[0]
            }}
        }}
    }}
}} finally {{
    if (-not (Test-Path (Join-Path $StageDir "activity_core.py"))) {{
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $StageDir
    }}
}}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$BackupDir = ""
if (@($ManagedFiles | Where-Object {{ Test-Path -LiteralPath (Join-Path $InstallDir $_) }}).Count) {{
    Write-Status "[UPDATE] Backing up the previous NeuroSwarm runtime and applying the new version..."
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $suffix = [guid]::NewGuid().ToString("N").Substring(0, 6)
    $BackupDir = "$InstallDir.bak.$stamp.$suffix"
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    foreach ($f in $ManagedFiles) {{
        $src = Join-Path $InstallDir $f
        if (Test-Path $src) {{ Copy-Item $src (Join-Path $BackupDir $f) -Force }}
    }}
}}

$Replacing = $true
foreach ($f in @('detector.py', 'activity_shipper.py', 'activity_core.py', 'swarmcontrol_agent.py')) {{
    Move-Item -Force (Join-Path $StageDir $f) (Join-Path $InstallDir $f)
}}
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $StageDir

$HasOverrides = [bool]($env:SWARMCONTROL_SERVER -or $env:SWARMCONTROL_TOKEN -or $env:SWARMCONTROL_INTERVAL -or $env:SWARMCONTROL_HOST_ID -or $env:SWARMCONTROL_ACTIVITY_ROOTS -or $env:SWARMCONTROL_AGENT_LABELS -or $env:SWARMCONTROL_SHARE_COMMANDS -or $env:SWARMCONTROL_SHARE_COMMAND_OUTPUT -or $env:SWARMCONTROL_SHARE_FILE_PREVIEWS -or $env:SWARMCONTROL_STATE_DIR)
if ($Upgrade -ne "1" -or $HasOverrides -or -not (Test-Path $EnvPath)) {{
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
    if ($StateDir) {{ $EnvLines += "SWARMCONTROL_STATE_DIR=$StateDir" }}
    Set-Content -Path $EnvPath -Value ($EnvLines -join "`r`n") -Encoding UTF8
}}

Write-Status "[CHECK] Checking the observer and sending the first heartbeat..."
$env:SWARMCONTROL_TOKEN = $Token
$env:SWARMCONTROL_AGENT_LABELS = $AgentLabels
$env:SWARMCONTROL_SHARE_COMMANDS = $ShareCommands
$env:SWARMCONTROL_SHARE_COMMAND_OUTPUT = $ShareCommandOutput
$env:SWARMCONTROL_SHARE_FILE_PREVIEWS = $ShareFilePreviews
if ($StateDir) {{ $env:SWARMCONTROL_STATE_DIR = $StateDir }}
$DiagArgs = @((Join-Path $InstallDir "swarmcontrol_agent.py"), "--diagnose")
$AgentArgs = @((Join-Path $InstallDir "swarmcontrol_agent.py"), "--server", $ServerUrl, "--once")
if ($HostId) {{
    $DiagArgs += @("--host-id", $HostId)
    $AgentArgs += @("--host-id", $HostId)
}}
if ($ActivityRoots) {{
    $DiagArgs += @("--activity-roots", $ActivityRoots)
    $AgentArgs += @("--activity-roots", $ActivityRoots)
}}
$VerifyOk = $false
$Problem = 'Local observer diagnostics failed.'
try {{
    $DiagRaw = & $PyExe @DiagArgs 2>$null
    if ($LASTEXITCODE -eq 0 -and $DiagRaw) {{
        $DiagObj = ($DiagRaw -join "`n") | ConvertFrom-Json
        if ($DiagObj.activity_core_loaded -and ($DiagObj.capture_reader -eq 'core') -and (-not $DiagObj.dry_scan_error)) {{
            $Problem = 'First heartbeat failed. Check the server address, network and enrollment key.'
            $ErrorActionPreference = "Continue"
            try {{ $Reply = @(& $PyExe @AgentArgs 2>&1); $HeartbeatExit = $LASTEXITCODE }}
            finally {{ $ErrorActionPreference = "Stop" }}
            if ($HeartbeatExit -eq 0) {{
                $Heartbeat = (($Reply | Where-Object {{ $_ -is [string] }}) -join "`n") | ConvertFrom-Json
                $VerifyOk = ($Heartbeat.ok -eq $true -and $Heartbeat.host_id -eq $DiagObj.host_id)
            }} elseif (($Reply -join ' ') -match 'HTTP Error (401|403)') {{
                $Problem = "Heartbeat rejected (HTTP $($Matches[1])). Check the enrollment key and its allowed host."
            }}
        }}
    }}
}} catch {{ $VerifyOk = $false }}
if (-not $VerifyOk) {{ Stop-Install $Problem 1 }}
if ($BackupDir) {{ Write-Status "[UPDATE] Previous runtime saved at $BackupDir" }}

Write-Status "[OK] Heartbeat accepted for $($Heartbeat.host_id)."
if ($Heartbeat.activity_warning) {{ Write-Status '[WARN] The heartbeat arrived, but activity delivery reported a problem.' }}
$RootCount = @($DiagObj.activity_roots).Count
if ($ActivityRoots -and $RootCount -eq 0) {{
    Write-Status '[WARN] None of the configured project folders exists. Check the drive letter and folder path, then rerun.'
}} elseif ($RootCount -eq 0) {{
    Write-Status '[ACTIVITY] Host monitoring only: this machine appears in Hosts, but no agent sessions appear in Live until you choose a project folder.'
    # OpenBot keeps agent workspaces and shared projects in its own folder. Suggest them; never share one without consent.
    $OpenBotHome = @($env:USERPROFILE, $env:APPDATA) | Where-Object {{ $_ }} | ForEach-Object {{ Join-Path $_ 'OpenBot' }} | Where-Object {{ Test-Path -LiteralPath (Join-Path $_ 'Shared') }} | Select-Object -First 1
    if ($OpenBotHome) {{
        $Projects = @(Get-ChildItem -LiteralPath (Join-Path $OpenBotHome 'Shared') -Directory -ErrorAction SilentlyContinue | Where-Object {{ -not $_.Name.StartsWith('.') }} | Select-Object -First 5)
        Write-Status "[ACTIVITY] OpenBot found. Its shared projects are in $(Join-Path $OpenBotHome 'Shared'):"
        foreach ($proj in $Projects) {{ Write-Host "             - $($proj.FullName)" -ForegroundColor DarkGray }}
        $Example = if ($Projects.Count) {{ $Projects[0].FullName }} else {{ Join-Path $OpenBotHome 'Shared' }}
        Write-Host '  To share one, rerun with its folder (separate several with ;):' -ForegroundColor White
        Write-Host ('    $env:SWARMCONTROL_ACTIVITY_ROOTS=''' + $Example.Replace("'", "''") + '''; irm ' + $ServerUrl + '/install.ps1 | iex') -ForegroundColor Cyan
    }} else {{
        Write-Host '  To share a project, rerun with its folder (separate several with ;):' -ForegroundColor White
        Write-Host ('    $env:SWARMCONTROL_ACTIVITY_ROOTS="C:\\path\\to\\project"; irm ' + $ServerUrl + '/install.ps1 | iex') -ForegroundColor Cyan
    }}
}} else {{
    Write-Status "[ACTIVITY] Watching $RootCount project folder(s); $($DiagObj.dry_scan.sessions) matching session(s) found locally."
}}
# This marker tests ingestion without opening or sharing the contents of a project.
$LiveUrl = "$ServerUrl/live?host=$([uri]::EscapeDataString($Heartbeat.host_id))"
$Marker = @{{ host_id = $Heartbeat.host_id; harness = 'neuroswarm'; agent_name = 'windows-installer'; event_type = 'observer_install_check'; message = 'Windows observer connection verified' }}
try {{
    $Receipt = Invoke-RestMethod -Method Post -Uri "$ServerUrl/api/v1/ingest/event" -Headers @{{ Authorization = "Bearer $Token" }} -ContentType 'application/json' -Body ($Marker | ConvertTo-Json -Compress) -TimeoutSec 10 -MaximumRedirection 0
    if ($Receipt.ok -ne $true -or [long]$Receipt.event_id -le 0) {{ throw 'Missing event receipt' }}
    Write-Status "[OK] Test event #$($Receipt.event_id) recorded. Live: $LiveUrl&event=event%3A$($Receipt.event_id)"
}} catch {{
    Write-Status "[WARN] Test event unconfirmed. Check Live in the organization that issued the key: $LiveUrl"
}}

if ($NoService -eq "1") {{
    Write-Status "[INSTALLED] One-time check complete; background monitoring disabled (no-service mode)."
    return
}}

$RunnerPs1 = Join-Path $InstallDir "run-agent.ps1"
# Read configuration as data so quoted paths work and the launcher contains no enrollment key.
$RunnerBody = @'
$ErrorActionPreference = 'Stop'
foreach ($line in Get-Content -LiteralPath (Join-Path $PSScriptRoot 'agent.env') -Encoding UTF8) {{
    if ($line -match '^(SWARMCONTROL_[A-Z_]+)=(.*)$') {{
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }}
}}
'@
$QuotedPython = "'" + $PyExe.Replace("'", "''") + "'"
$RunnerBody += "`r`n& $QuotedPython (Join-Path `$PSScriptRoot 'swarmcontrol_agent.py')"
Set-Content -Path $RunnerPs1 -Value $RunnerBody -Encoding UTF8

function Start-ObserverProcess {{
    $arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$RunnerPs1`""
    Start-Process -PassThru -FilePath 'powershell.exe' -ArgumentList $arguments -WindowStyle Hidden
}}
function Stop-PreviousDetachedObserver {{
    if (-not $BackupDir -or [Environment]::OSVersion.Platform -ne 'Win32NT') {{ return }}
    $launcher = [regex]::Escape($RunnerPs1)
    $agent = [regex]::Escape((Join-Path $InstallDir 'swarmcontrol_agent.py'))
    $filter = "Name='powershell.exe' OR Name='python.exe' OR Name='pythonw.exe'"
    foreach ($proc in Get-CimInstance Win32_Process -Filter $filter) {{
        # Match only our exact launcher or long-running agent, never a Python executable by name alone.
        if ($proc.Name -eq 'powershell.exe') {{
            $match = $proc.CommandLine -match ('^(?:"[^"]+"|\\S+)\\s+-NoProfile\\s+-WindowStyle Hidden\\s+-ExecutionPolicy Bypass\\s+-File "' + $launcher + '"$')
        }} else {{
            $match = $proc.CommandLine -match ('^(?:"[^"]+"|\\S+)\\s+(?:"' + $agent + '"|' + $agent + ')$')
        }}
        if ($match) {{
            $stopped = Invoke-CimMethod -InputObject $proc -MethodName Terminate
            if ($stopped.ReturnValue -ne 0) {{ throw 'Previous observer process could not be stopped.' }}
            if (-not $RestartPreviousTask) {{ Set-Variable -Name RestartPreviousProcess -Value $true -Scope 1 }}
        }}
    }}
}}
$UseBackground = $false
try {{
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$RunnerPs1`""
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $previous = Get-ScheduledTask -TaskName 'SwarmControlAgent' -ErrorAction SilentlyContinue
    if ($previous.State -eq 'Running') {{
        Write-Status '[CHECK] Restarting the running observer with the new configuration...'
        $RestartPreviousTask = $true
        Stop-ScheduledTask -TaskName 'SwarmControlAgent'
        for ($attempt = 0; $attempt -lt 5; $attempt++) {{
            if ((Get-ScheduledTask -TaskName 'SwarmControlAgent').State -ne 'Running') {{ break }}
            Start-Sleep -Seconds 1
        }}
        if ((Get-ScheduledTask -TaskName 'SwarmControlAgent').State -eq 'Running') {{
            throw 'Previous instance did not stop'
        }}
    }}
    Register-ScheduledTask -TaskName "SwarmControlAgent" -Action $Action -Trigger $Trigger -Force | Out-Null
    $CreatedTask = -not $previous
}} catch {{
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {{
        $previous = Get-ScheduledTask -TaskName 'SwarmControlAgent' -ErrorAction SilentlyContinue
        if ($previous) {{ Stop-Install 'Cannot update the existing scheduled task. Retry from the Windows account that installed the observer.' 1 }}
    }}
    $UseBackground = $true
}}
if ($UseBackground) {{
    Write-Status "[WARN] Scheduled task unavailable; trying a background process for this sign-in."
    Stop-PreviousDetachedObserver
    try {{ $ObserverProcess = Start-ObserverProcess }}
    catch {{ Stop-Install 'Could not start the background observer. Check permission to run powershell.exe.' 1 }}
    Start-Sleep -Seconds 1
    if ($ObserverProcess.HasExited) {{ Stop-Install "Background observer exited during startup. Check the Python installation and run-agent.ps1." 1 }}
    Write-Status "[INSTALLED] Background process running for this sign-in (PID $($ObserverProcess.Id))."
    return
}}
try {{
    Stop-PreviousDetachedObserver
    Start-ScheduledTask -TaskName 'SwarmControlAgent'
}} catch {{
    Stop-Install 'Heartbeat accepted, but Windows could not restart or start SwarmControlAgent. Check this task in Windows Task Scheduler.' 1
}}
for ($attempt = 0; $attempt -lt 5; $attempt++) {{
    Start-Sleep -Seconds 1
    if ((Get-ScheduledTask -TaskName 'SwarmControlAgent').State -eq 'Running') {{
        Write-Status '[INSTALLED] SwarmControlAgent is running and scheduled at sign-in.'
        return
    }}
}}
Stop-Install 'Heartbeat accepted, but SwarmControlAgent is not running. Check this task in Windows Task Scheduler.' 1
}} catch {{
    $code = 1
    $message = 'Unexpected installation error. Check write permissions, disk space and the previous step in install.log.'
    if ($_.Exception.Data.Contains('InstallCode')) {{
        $code = $_.Exception.Data['InstallCode']
        $message = $_.Exception.Message
    }} else {{ Write-Status "[FAILED] $message" }}
    if ($Replacing) {{
        if ($CreatedTask) {{
            try {{ Unregister-ScheduledTask -TaskName 'SwarmControlAgent' -Confirm:$false -ErrorAction Stop }}
            catch {{ Write-Status '[WARN] Could not remove the new scheduled task during recovery.' }}
        }}
        try {{
            foreach ($f in $ManagedFiles) {{
                $dst = Join-Path $InstallDir $f
                if ($BackupDir -and (Test-Path -LiteralPath (Join-Path $BackupDir $f))) {{
                    Copy-Item -LiteralPath (Join-Path $BackupDir $f) -Destination $dst -Force
                }} elseif (Test-Path -LiteralPath $dst -PathType Leaf) {{ Remove-Item -LiteralPath $dst -Force }}
            }}
            if ($BackupDir) {{ Write-Status "[ROLLBACK] Restored previous observer from $BackupDir." }}
            if ($RestartPreviousTask -and $BackupDir) {{ Start-ScheduledTask -TaskName 'SwarmControlAgent' }}
            if ($RestartPreviousProcess -and $BackupDir) {{ Start-ObserverProcess | Out-Null }}
        }} catch {{ Write-Status "[WARN] Automatic recovery was incomplete. Check the task and restore the runtime from $BackupDir." }}
    }}
    $global:LASTEXITCODE = $code
    if ($InvokedAsFile) {{ exit $code }}
    throw $message
}} finally {{
    if ($StageDir -and (Test-Path -LiteralPath $StageDir)) {{ Remove-Item -LiteralPath $StageDir -Recurse -Force -ErrorAction SilentlyContinue }}
    if ($Lock) {{ $Lock.Dispose() }}
}}
}} ($MyInvocation.MyCommand -is [System.Management.Automation.ExternalScriptInfo])
"""
