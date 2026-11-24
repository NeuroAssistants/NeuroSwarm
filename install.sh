#!/usr/bin/env bash
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
INSTALL_DIR="${SWARMCONTROL_INSTALL_DIR:-$HOME/.local/share/swarmcontrol}"
FROM_REPO=""
NO_SERVICE="0"
UPGRADE="${SWARMCONTROL_UPGRADE:-0}"

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
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --from-repo)
      FROM_REPO="${2:-.}"
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
      echo "Usage: curl -fsSL http://127.0.0.1:8790/install.sh | SWARMCONTROL_TOKEN=<TOKEN> bash -s -- [--interval 15] [--host-id name] [--activity-roots /path/a:/path/b] [--agent-labels folder=Name] [--share-commands] [--from-repo /path/to/repo] [--upgrade] [--no-service]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

ENV_SERVER="${SWARMCONTROL_SERVER:-}"
ENV_TOKEN="${SWARMCONTROL_TOKEN:-}"
ENV_INTERVAL="${SWARMCONTROL_INTERVAL:-}"
ENV_HOST_ID="${SWARMCONTROL_HOST_ID:-}"
ENV_ACTIVITY_ROOTS="${SWARMCONTROL_ACTIVITY_ROOTS:-}"
ENV_AGENT_LABELS="${SWARMCONTROL_AGENT_LABELS:-}"
ENV_SHARE_COMMANDS="${SWARMCONTROL_SHARE_COMMANDS:-}"
ENV_STATE_DIR="${SWARMCONTROL_STATE_DIR:-}"

SAVED_SERVER=""
SAVED_TOKEN=""
SAVED_INTERVAL=""
SAVED_HOST_ID=""
SAVED_ACTIVITY_ROOTS=""
SAVED_AGENT_LABELS=""
SAVED_SHARE_COMMANDS=""
SAVED_STATE_DIR=""

if [[ "$UPGRADE" == "1" ]]; then
  if [[ ! -f "$INSTALL_DIR/agent.env" ]]; then
    echo "ERROR: --upgrade requires an existing installation with agent.env in $INSTALL_DIR." >&2
    exit 2
  fi
  while IFS='=' read -r k v; do
    k="${k#$'\ufeff'}"
    v="${v%$'\r'}"
    case "$k" in
      ''|\#*) continue ;;
      SWARMCONTROL_SERVER) SAVED_SERVER="$v" ;;
      SWARMCONTROL_TOKEN) SAVED_TOKEN="$v" ;;
      SWARMCONTROL_INTERVAL) SAVED_INTERVAL="$v" ;;
      SWARMCONTROL_HOST_ID) SAVED_HOST_ID="$v" ;;
      SWARMCONTROL_ACTIVITY_ROOTS) SAVED_ACTIVITY_ROOTS="$v" ;;
      SWARMCONTROL_AGENT_LABELS) SAVED_AGENT_LABELS="$v" ;;
      SWARMCONTROL_SHARE_COMMANDS) SAVED_SHARE_COMMANDS="$v" ;;
      SWARMCONTROL_STATE_DIR) SAVED_STATE_DIR="$v" ;;
    esac
  done < "$INSTALL_DIR/agent.env"
fi

SERVER_URL="${SWARMCONTROL_SERVER:-http://127.0.0.1:8790}"
if [[ -z "$ENV_SERVER" && -n "$SAVED_SERVER" ]]; then
  SERVER_URL="$SAVED_SERVER"
fi
if [[ -n "$CLI_SERVER" ]]; then
  SERVER_URL="$CLI_SERVER"
fi
TOKEN="${CLI_TOKEN:-${ENV_TOKEN:-$SAVED_TOKEN}}"
INTERVAL="${CLI_INTERVAL:-${ENV_INTERVAL:-${SAVED_INTERVAL:-15}}}"
HOST_ID="${CLI_HOST_ID:-${ENV_HOST_ID:-$SAVED_HOST_ID}}"
ACTIVITY_ROOTS="${CLI_ACTIVITY_ROOTS:-${ENV_ACTIVITY_ROOTS:-$SAVED_ACTIVITY_ROOTS}}"
AGENT_LABELS="${CLI_AGENT_LABELS:-${ENV_AGENT_LABELS:-$SAVED_AGENT_LABELS}}"
if [[ "$HAS_CLI_SHARE" == "1" ]]; then
  SHARE_COMMANDS="$CLI_SHARE_COMMANDS"
elif [[ -n "$ENV_SHARE_COMMANDS" ]]; then
  SHARE_COMMANDS="$ENV_SHARE_COMMANDS"
elif [[ -n "$SAVED_SHARE_COMMANDS" ]]; then
  SHARE_COMMANDS="$SAVED_SHARE_COMMANDS"
else
  SHARE_COMMANDS="0"
fi
STATE_DIR="${ENV_STATE_DIR:-$SAVED_STATE_DIR}"

HAS_OVERRIDES=0
if [[ -n "$CLI_SERVER$CLI_TOKEN$CLI_INTERVAL$CLI_HOST_ID$CLI_ACTIVITY_ROOTS$CLI_AGENT_LABELS" ]] || [[ "$HAS_CLI_SHARE" == "1" ]] || [[ -n "$ENV_SERVER$ENV_TOKEN$ENV_INTERVAL$ENV_HOST_ID$ENV_ACTIVITY_ROOTS$ENV_AGENT_LABELS$ENV_SHARE_COMMANDS$ENV_STATE_DIR" ]]; then
  HAS_OVERRIDES=1
fi

if [[ -z "$TOKEN" ]]; then
  echo "ERROR: Missing enrollment token. Set SWARMCONTROL_TOKEN=<TOKEN> (generated in the NeuroSwarm UI)." >&2
  exit 2
fi
if [[ ! "$TOKEN" =~ ^[A-Za-z0-9_-]{8,128}$ ]]; then
  echo "ERROR: Enrollment token has an unexpected format." >&2
  exit 2
fi
if [[ ! "$INTERVAL" =~ ^[0-9]{1,5}$ ]]; then
  echo "ERROR: --interval must be a whole number of seconds." >&2
  exit 2
fi
if [[ -n "$HOST_ID" && ! "$HOST_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$ ]]; then
  echo "ERROR: --host-id may only contain letters, digits and . _ : @ - (max 128 chars)." >&2
  exit 2
fi
if [[ "$SHARE_COMMANDS" != "0" && "$SHARE_COMMANDS" != "1" ]]; then
  echo "ERROR: SWARMCONTROL_SHARE_COMMANDS must be 0 or 1." >&2
  exit 2
fi
if [[ -n "$AGENT_LABELS" ]] && [[ "$AGENT_LABELS" == *$'\n'* || ! "$AGENT_LABELS" =~ ^[A-Za-z0-9._:@,/=+[:blank:]-]{1,512}$ ]]; then
  echo "ERROR: --agent-labels may only contain safe label characters (max 512 chars)." >&2
  exit 2
fi
if [[ ! "$SERVER_URL" =~ ^https?://[][A-Za-z0-9.:/_~-]+$ ]]; then
  echo "ERROR: --server must be an http(s) URL." >&2
  exit 2
fi
case "$SERVER_URL" in
  https://*|http://127.0.0.1*|http://localhost*|http://\[::1\]*) ;;
  *) echo "WARNING: $SERVER_URL is not HTTPS; the enrollment token will travel in clear text." >&2 ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 (3.10+) is required to run NeuroSwarm Lite Agent." >&2
  exit 3
fi

umask 077
mkdir -p "$(dirname "$INSTALL_DIR")"
STAGE_DIR="$(mktemp -d "${INSTALL_DIR}.staging.XXXXXX")"
cleanup_stage() {
  rm -rf "$STAGE_DIR"
}
trap cleanup_stage EXIT

_stage_fail() {
  echo "ERROR: Required observer component $1 could not be installed; existing configuration left untouched." >&2
  exit 4
}

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
  BACKUP_DIR="$(mktemp -d "${INSTALL_DIR}.bak.$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"
  chmod 700 "$BACKUP_DIR"
  for f in detector.py activity_shipper.py activity_core.py swarmcontrol_agent.py agent.env; do
    if [[ -f "$INSTALL_DIR/$f" ]]; then
      cp -p "$INSTALL_DIR/$f" "$BACKUP_DIR/$f"
    fi
  done
fi

_rollback_backup() {
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
}

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
EOF
  if [[ -n "$STATE_DIR" ]]; then
    echo "SWARMCONTROL_STATE_DIR=$STATE_DIR" >> "$INSTALL_DIR/agent.env"
  fi
  chmod 600 "$INSTALL_DIR/agent.env"
fi

echo "[NeuroSwarm] Running initial passive detection & heartbeat test..."
_run_verify() {
  local run_env=(
    SWARMCONTROL_TOKEN="$TOKEN"
    SWARMCONTROL_ACTIVITY_ROOTS="$ACTIVITY_ROOTS"
    SWARMCONTROL_AGENT_LABELS="$AGENT_LABELS"
    SWARMCONTROL_SHARE_COMMANDS="$SHARE_COMMANDS"
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
  diag_json="$(env "${run_env[@]}" "${diag_cmd[@]}")" || return 1
  printf '%s' "$diag_json" | python3 -c "import json, sys; d = json.load(sys.stdin); sys.exit(0 if d.get('activity_core_loaded') is True and d.get('capture_reader') == 'core' and not d.get('dry_scan_error') else 1)" || return 1
  env "${run_env[@]}" "${verify_cmd[@]}" || return 1
}

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
    if command -v loginctl >/dev/null 2>&1 && [[ "$(loginctl show-user "${USER:-$(id -un)}" -p Linger --value 2>/dev/null)" != "yes" ]]; then
      echo "[NeuroSwarm] Note: run 'loginctl enable-linger ${USER:-$(id -un)}' so the observer keeps running after you log out."
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
