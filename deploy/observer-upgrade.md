# NeuroSwarm Observer Upgrade & D3/D6 Release Guide

This guide documents the **publication order**, **reversible upgrade procedure** (preserving `agent.env`, enrollment secrets, state directories, and `capture_offsets.json`), and **instant rollback** for upgrading installed observers from `v0.1.0` (legacy passive heartbeat/legacy-tail agent without `activity_core.py` or `activity_shipper.py`) or `v0.2.0` (existing `capture_offsets.json`) to `v0.3.0`.

---

## 1. Publication Order (Critical)

Deploy the updated NeuroSwarm console **before** upgrading any remote observers:

1. **Back up the console database** using `deploy/backup.py` before stopping or restarting services.
2. **Deploy the updated console** serving:
   - `GET /agent/activity_core.py` (shared `backend/activity_inspector.py` reader; HTTP 200).
   - `GET /install.sh` and `GET /install.ps1` (`--upgrade` / `SWARMCONTROL_UPGRADE=1` + mandatory 4-file atomic staging).
   - Updated `POST /api/v1/ingest/activity` and `POST /api/v1/ingest/heartbeat` with D3 clock-skew normalization / HTTP `422` (`commit_offsets: false`) and D6 `capture_reader` / `reader_fallback` telemetry.
3. **Verify the published console before touching observers:**
   ```bash
   python3 deploy/check_release.py https://<console-origin>
   curl -fsSI https://<console-origin>/agent/activity_core.py
   ```
   Confirm `check_release.py` passes all checks and `/agent/activity_core.py` returns `200 OK` (non-empty Python body). Do **not** upgrade observers until `/agent/activity_core.py` returns `200`; `install.sh`/`install.ps1` `v0.3.0` will fail safely with exit code `4` leaving the existing install untouched if any component is missing.

> **Backward compatibility during rolling upgrades:** Older `v0.1.0` / `v0.2.0` observers continue sending heartbeats and activity while the console runs `v0.3.0`. Un-upgraded observers that omit `collected_at` while having a forward clock (`> +60 s`) now receive HTTP `422`, a host `WARNING` `clock_skew`, and increment `gaps` in `capture_metrics` instead of a silent `200`.

---

## 2. Pre-Flight Check on the Observer Host

Locate the installed observer directory (`$INSTALL_DIR`) and state directory (`SWARMCONTROL_STATE_DIR`):

- **User-level install (Linux/macOS default):** `~/.local/share/swarmcontrol` (state in `~/.local/state/swarmcontrol`).
- **System `systemd` service install (e.g. `swarmcontrol-observer.service`):** check `WorkingDirectory`, `EnvironmentFile`, or `ExecStart` via `systemctl cat swarmcontrol-observer.service` to locate `$INSTALL_DIR/agent.env` and `SWARMCONTROL_STATE_DIR`.
- **Windows default:** `%LOCALAPPDATA%\SwarmControl\client` (state in `%LOCALAPPDATA%\SwarmControl\state`).

Verify permissions and existing config are readable before upgrading (do not modify `agent.env` or delete `.state` / `capture_offsets.json`).

---

## 3. Reversible Upgrade (`v0.1.0` / `v0.2.0` → `v0.3.0`)

Both `install.sh --upgrade` and `install.ps1` with `$env:SWARMCONTROL_UPGRADE="1"` perform the same safe sequence:
1. Read `SWARMCONTROL_SERVER`, `SWARMCONTROL_TOKEN`, `SWARMCONTROL_INTERVAL`, `SWARMCONTROL_HOST_ID`, `SWARMCONTROL_ACTIVITY_ROOTS`, `SWARMCONTROL_AGENT_LABELS`, `SWARMCONTROL_SHARE_COMMANDS`, and `SWARMCONTROL_STATE_DIR` directly from existing `$INSTALL_DIR/agent.env` (preserving secrets and custom settings unless explicit CLI/env overrides are passed).
2. Download or copy all 4 required components (`detector.py`, `activity_shipper.py`, `activity_core.py`, `swarmcontrol_agent.py`) into a temporary staging directory first. Missing any component exits with status `4` without altering `$INSTALL_DIR`.
3. Create a unique timestamped backup directory `${INSTALL_DIR}.bak.<UTC_TS>.<rand>` (mode `0700`) containing prior `.py` files and `agent.env`.
4. Atomically swap the 4 staged `.py` files into `$INSTALL_DIR` while leaving `agent.env` (`0600`) and `$SWARMCONTROL_STATE_DIR/capture_offsets.json` intact.
5. Verify with `--diagnose` (`activity_core_loaded == true`, `capture_reader == "core"`, no `dry_scan_error`) and `--once` heartbeat/activity cycle.
6. If verification fails, **automatically roll back** `$INSTALL_DIR` from `${INSTALL_DIR}.bak.<UTC_TS>.<rand>` (also removing newly added `activity_core.py`/`activity_shipper.py` when rolling back to `v0.1.0`) and exit `1`.

### A. Linux User `systemd` Unit (`swarmcontrol-agent.service`)
```bash
curl -fsSL https://<console-origin>/install.sh | bash -s -- --upgrade
```
*(Pass `--install-dir /custom/path` if installed outside `~/.local/share/swarmcontrol`. On success, the script reloads and restarts `swarmcontrol-agent.service`.)*

### B. Linux System `systemd` Unit (`swarmcontrol-observer.service`)
When the observer runs under a dedicated system unit (not `--user`):
```bash
# Run as the service account owning $INSTALL_DIR (preserve agent.env owner and 0600 mode):
sudo -u <service-user> env INSTALL_DIR="<install-dir>" bash -c '
  curl -fsSL "https://<console-origin>/install.sh" | bash -s -- --upgrade --install-dir "$INSTALL_DIR" --no-service
'
# Restart the system service once --upgrade prints "Rollback backup stored at ...":
sudo systemctl restart swarmcontrol-observer.service
sudo systemctl status --no-pager swarmcontrol-observer.service
```

### C. macOS (`launchd`)
```bash
curl -fsSL https://<console-origin>/install.sh | bash -s -- --upgrade
```
Unloads and reloads `~/Library/LaunchAgents/org.swarmcontrol.agent.plist`.

### D. Windows (`PowerShell`)
Run in the account where `SwarmControlAgent` is registered (add `$env:SWARMCONTROL_INSTALL_DIR = "..."` only if non-default):
```powershell
$env:SWARMCONTROL_UPGRADE = "1"
$env:SWARMCONTROL_SERVER = "https://<console-origin>"
irm https://<console-origin>/install.ps1 | iex
Remove-Item Env:SWARMCONTROL_UPGRADE -ErrorAction SilentlyContinue
```
*(Or download `install.ps1` and run `.\install.ps1 -Upgrade -Server https://<console-origin>`.)*

### E. Air-Gapped / Candidate Checkout (`--from-repo`)
```bash
bash ./install.sh --upgrade --from-repo "$PWD" --install-dir "$INSTALL_DIR" --no-service
```

---

## 4. Post-Upgrade Verification

1. **Read-only local diagnostic check (`--diagnose`):**
   ```bash
   (set -a; source "$INSTALL_DIR/agent.env"; set +a; python3 "$INSTALL_DIR/swarmcontrol_agent.py" --diagnose)
   ```
   Confirm JSON output shows:
   - `"agent_version": "0.3.0"`
   - `"activity_core_loaded": true`
   - `"capture_reader": "core"`
   - `"dry_scan_error"` is absent
   - `"offsets_count"` preserves prior tracked logs when upgrading from `v0.2.0`
2. **Console checks:**
   - `/api/v1/hosts` shows the host `online` within one interval.
   - `/api/v1/activity` reports `"capture_reader": "core"` for the host (no `reader_fallback` warning).
   - `/api/v1/event-feed` shows normal step capture across active runtimes (`codex`, `claude-code`, `opencode`, `antigravity`), or an explicit bounded `WARNING` `clock_skew` if the remote clock exceeds server time by `> 60 s` (and `capture_gap` only after `DEFAULT_MAX_REJECT_RETRIES=3` attempts on permanently poisoned records).

---

## 5. Manual Instant Rollback

If an issue is discovered **after** `--upgrade` has already completed, restore from the printed `${INSTALL_DIR}.bak.<UTC_TS>.<rand>` directory (`capture_offsets.json` and `agent.env` remain untouched):

### Linux / macOS
```bash
BAK="<install-dir>.bak.<UTC_TS>.<rand>"
INSTALL_DIR="<install-dir>"

for f in detector.py activity_shipper.py activity_core.py swarmcontrol_agent.py agent.env; do
  if [ -f "$BAK/$f" ]; then
    cp -p "$BAK/$f" "$INSTALL_DIR/$f"
  elif [ "$f" = "activity_core.py" ] || [ "$f" = "activity_shipper.py" ]; then
    rm -f "$INSTALL_DIR/$f"
  fi
done
chmod 700 "$INSTALL_DIR/swarmcontrol_agent.py"
chmod 600 "$INSTALL_DIR/agent.env"

# Restart whichever unit manages the host:
systemctl --user restart swarmcontrol-agent.service 2>/dev/null || sudo systemctl restart swarmcontrol-observer.service
```

### Windows PowerShell
```powershell
$Bak = "<install-dir>.bak.<UTC_TS>.<suffix>"
$InstallDir = "<install-dir>"
foreach ($f in @("detector.py", "activity_shipper.py", "activity_core.py", "swarmcontrol_agent.py", "agent.env", "run-agent.ps1")) {
    $src = Join-Path $Bak $f
    $dst = Join-Path $InstallDir $f
    if (Test-Path $src) {
        Copy-Item $src $dst -Force
    } elseif ($f -in @("activity_core.py", "activity_shipper.py") -and (Test-Path $dst)) {
        Remove-Item -Force $dst
    }
}
Restart-ScheduledTask -TaskName "SwarmControlAgent"
```
