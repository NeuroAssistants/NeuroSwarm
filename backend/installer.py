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
$ErrorActionPreference = "Stop"

$InstallDir = if ($env:SWARMCONTROL_INSTALL_DIR) {{ $env:SWARMCONTROL_INSTALL_DIR }} else {{ Join-Path $env:LOCALAPPDATA "SwarmControl" }}
$FromRepo = if ($env:SWARMCONTROL_FROM_REPO) {{ $env:SWARMCONTROL_FROM_REPO }} else {{ "" }}
$NoService = if ($env:SWARMCONTROL_NO_SERVICE) {{ $env:SWARMCONTROL_NO_SERVICE }} else {{ "0" }}
$Upgrade = if ($env:SWARMCONTROL_UPGRADE) {{ $env:SWARMCONTROL_UPGRADE }} else {{ "0" }}

$Saved = @{{}}
$EnvPath = Join-Path $InstallDir "agent.env"
if ($Upgrade -eq "1") {{
    if (-not (Test-Path $EnvPath)) {{
        Write-Error -ErrorAction Continue "ERROR: SWARMCONTROL_UPGRADE=1 requires an existing agent.env in $InstallDir."
        exit 2
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
    Write-Error -ErrorAction Continue "ERROR: Missing enrollment token. Set `$env:SWARMCONTROL_TOKEN='<TOKEN>' before running install.ps1."
    exit 2
}}
if ($Token -notmatch '^[A-Za-z0-9_-]{{8,128}}$') {{
    Write-Error -ErrorAction Continue "ERROR: Enrollment token has an unexpected format."
    exit 2
}}
if ($ShareCommands -ne "0" -and $ShareCommands -ne "1") {{
    Write-Error -ErrorAction Continue "ERROR: SWARMCONTROL_SHARE_COMMANDS must be 0 or 1."
    exit 2
}}
if ($ShareCommandOutput -ne "0" -and $ShareCommandOutput -ne "1") {{
    Write-Error -ErrorAction Continue "ERROR: SWARMCONTROL_SHARE_COMMAND_OUTPUT must be 0 or 1."
    exit 2
}}
if ($ShareFilePreviews -ne "0" -and $ShareFilePreviews -ne "1") {{
    Write-Error -ErrorAction Continue "ERROR: SWARMCONTROL_SHARE_FILE_PREVIEWS must be 0 or 1."
    exit 2
}}
if ($AgentLabels -and $AgentLabels -notmatch '^[A-Za-z0-9._:@,/=+ -]{{1,512}}$') {{
    Write-Error -ErrorAction Continue "ERROR: SWARMCONTROL_AGENT_LABELS contains unsupported characters."
    exit 2
}}

$PyExe = ""
foreach ($cand in @("python", "python3")) {{
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike "*\\WindowsApps\\*") {{
        $PyExe = $cmd.Source
        break
    }} elseif ($cmd) {{
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {{
            & $cmd.Source --version >$null 2>&1
            if ($LASTEXITCODE -eq 0) {{
                $PyExe = $cmd.Source
            }}
        }} catch {{
        }} finally {{
            $ErrorActionPreference = $prevEap
        }}
        if ($PyExe) {{
            break
        }}
    }}
}}
if (-not $PyExe) {{
    Write-Error -ErrorAction Continue "ERROR: Python 3.10+ is required in PATH to run NeuroSwarm Lite Agent (Windows Store alias is not installed)."
    exit 3
}}

$ParentDir = Split-Path -Parent $InstallDir
if ($ParentDir) {{ New-Item -ItemType Directory -Force -Path $ParentDir | Out-Null }}
$StageDir = "$InstallDir.staging.$PID"
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

function Fail-Stage([string]$Comp) {{
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $StageDir
    Write-Error -ErrorAction Continue "ERROR: Required observer component $Comp could not be installed; existing configuration left untouched."
    exit 4
}}

try {{
    if ($FromRepo) {{
        Write-Host "[NeuroSwarm] Installing observer client from local repository $FromRepo ..."
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
        Write-Host "[NeuroSwarm] Downloading observer client from $ServerUrl ..."
        foreach ($pair in @(
            @("detector.py", "$ServerUrl/agent/detector.py"),
            @("activity_shipper.py", "$ServerUrl/agent/activity_shipper.py"),
            @("activity_core.py", "$ServerUrl/agent/activity_core.py"),
            @("swarmcontrol_agent.py", "$ServerUrl/agent/swarmcontrol_agent.py")
        )) {{
            $dst = Join-Path $StageDir $pair[0]
            try {{
                Invoke-WebRequest -UseBasicParsing -Uri $pair[1] -OutFile $dst
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
if ($Upgrade -eq "1" -or (Test-Path (Join-Path $InstallDir "swarmcontrol_agent.py"))) {{
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $suffix = [guid]::NewGuid().ToString("N").Substring(0, 6)
    $BackupDir = "$InstallDir.bak.$stamp.$suffix"
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    foreach ($f in @("detector.py", "activity_shipper.py", "activity_core.py", "swarmcontrol_agent.py", "agent.env", "run-agent.ps1")) {{
        $src = Join-Path $InstallDir $f
        if (Test-Path $src) {{ Copy-Item $src (Join-Path $BackupDir $f) -Force }}
    }}
}}

foreach ($f in @("detector.py", "activity_shipper.py", "activity_core.py", "swarmcontrol_agent.py")) {{
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

Write-Host "[NeuroSwarm] Running initial passive detection & heartbeat test..."
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
try {{
    $DiagRaw = & $PyExe @DiagArgs
    if ($LASTEXITCODE -eq 0 -and $DiagRaw) {{
        $DiagObj = ($DiagRaw -join "`n") | ConvertFrom-Json
        if ($DiagObj.activity_core_loaded -and ($DiagObj.capture_reader -eq "core") -and (-not $DiagObj.dry_scan_error)) {{
            & $PyExe @AgentArgs
            if ($LASTEXITCODE -eq 0) {{ $VerifyOk = $true }}
        }}
    }}
}} catch {{
    $VerifyOk = $false
}}
if (-not $VerifyOk) {{
    if ($Upgrade -eq "1" -and $BackupDir -and (Test-Path $BackupDir)) {{
        foreach ($f in @("detector.py", "activity_shipper.py", "activity_core.py", "swarmcontrol_agent.py", "agent.env", "run-agent.ps1")) {{
            $bak = Join-Path $BackupDir $f
            $dst = Join-Path $InstallDir $f
            if (Test-Path $bak) {{
                Copy-Item $bak $dst -Force
            }} elseif ($f -in @("activity_core.py", "activity_shipper.py") -and (Test-Path $dst)) {{
                Remove-Item -Force -ErrorAction SilentlyContinue $dst
            }}
        }}
        Write-Error -ErrorAction Continue "ERROR: Upgrade verification failed; restored previous observer from $BackupDir."
    }} else {{
        Write-Error -ErrorAction Continue "ERROR: Initial NeuroSwarm heartbeat failed."
    }}
    exit 1
}}
if ($BackupDir) {{ Write-Host "[NeuroSwarm] Rollback backup stored at $BackupDir" }}

if ($NoService -eq "1") {{
    Write-Host "[NeuroSwarm] Installed (no-service mode) at $InstallDir"
    exit 0
}}

$RunnerPs1 = Join-Path $InstallDir "run-agent.ps1"
$RunnerBody = @"
`$env:SWARMCONTROL_SERVER = '$ServerUrl'
`$env:SWARMCONTROL_TOKEN = '$Token'
`$env:SWARMCONTROL_INTERVAL = '$Interval'
`$env:SWARMCONTROL_HOST_ID = '$HostId'
`$env:SWARMCONTROL_ACTIVITY_ROOTS = '$ActivityRoots'
`$env:SWARMCONTROL_AGENT_LABELS = '$AgentLabels'
`$env:SWARMCONTROL_SHARE_COMMANDS = '$ShareCommands'
`$env:SWARMCONTROL_SHARE_COMMAND_OUTPUT = '$ShareCommandOutput'
`$env:SWARMCONTROL_SHARE_FILE_PREVIEWS = '$ShareFilePreviews'
$(if ($StateDir) {{ "`$env:SWARMCONTROL_STATE_DIR = '$StateDir'" }} else {{ "" }})
& '$PyExe' '$(Join-Path $InstallDir "swarmcontrol_agent.py")'
"@
Set-Content -Path $RunnerPs1 -Value $RunnerBody -Encoding UTF8

try {{
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$RunnerPs1`""
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName "SwarmControlAgent" -Action $Action -Trigger $Trigger -Force | Out-Null
    Start-ScheduledTask -TaskName "SwarmControlAgent"
    Write-Host "[NeuroSwarm] Active Windows Scheduled Task: SwarmControlAgent"
}} catch {{
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$RunnerPs1`"" -WindowStyle Hidden
    Write-Host "[NeuroSwarm] Started background observer process from $RunnerPs1"
}}
"""
