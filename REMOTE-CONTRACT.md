# Remote Agent, Installers & Activity Ingestion Contract (v1)

## 1. Public Download & Installer Routes (No Operator Session Required)

All installer and agent source routes are public (`GET`, no cookie required) so any remote machine can install with a 1-line command:

| Method & Path | Content-Type | Handler / Source | Description |
| :--- | :--- | :--- | :--- |
| `GET /install.sh` | `text/x-shellscript; charset=utf-8` | `installer.render_install_script(base_url)` | POSIX shell installer (`--upgrade`, `--install-dir`, `--from-repo`, `--no-service`) with atomic 4-file staging and automatic rollback on verification failure. |
| `GET /install.ps1` | `text/plain; charset=utf-8` | `installer.render_powershell_install_script(base_url)` | Native **Windows PowerShell** installer (`-Upgrade` / `SWARMCONTROL_UPGRADE=1`) with atomic staging and rollback. |
| `GET /agent/detector.py` | `text/x-python; charset=utf-8` | `AGENT_DIR / "detector.py"` | Cross-platform (Linux, macOS, Windows, WSL) passive harness & resource detector. |
| `GET /agent/activity_shipper.py` | `text/x-python; charset=utf-8` | `AGENT_DIR / "activity_shipper.py"` | Opt-in, folder-scoped, locally-redacted session/plan/workspace activity collector (all 4 runtimes aligned with `activity_inspector`). |
| `GET /agent/activity_core.py` | `text/x-python; charset=utf-8` | `BACKEND_DIR / "activity_inspector.py"` | **Required** shared core incremental capture reader served to remote observers (missing/404 fails installation/upgrade with exit code `4` leaving existing config untouched). |
| `GET /agent/swarmcontrol_agent.py` | `text/x-python; charset=utf-8` | `AGENT_DIR / "swarmcontrol_agent.py"` | CLI observer (`--once`, `--dry-run`, `--diagnose`, `--preview-activity`, `--activity-roots`, `--emit-event`, `--state-dir`). |

### Installer CLI & Environment Variables
- **Opt-in privacy by default:** Activity shipping (`sessions`, `plans`, `workspaces`, `recent_files`) is **OFF by default** unless `SWARMCONTROL_ACTIVITY_ROOTS` (colon-separated on Unix, semicolon-separated on Windows) or `--activity-roots <dir1,dir2>` is explicitly provided by the operator.
- **Optional display labels & command lines:** `SWARMCONTROL_AGENT_LABELS` (`--agent-labels folder=Name,...`) maps workspace folder names or paths to display names; `SWARMCONTROL_SHARE_COMMANDS=1` (`--share-commands`) is **OFF by default** and opts in to locally-redacted shell command lines (≤160 chars, sensitive filenames and CLI secret flags masked).
- **Preview before sending:** `python3 swarmcontrol_agent.py --preview-activity --activity-roots /path/to/proj` prints the exact locally-redacted JSON payload to `stdout` without making any network call.
- **Install command returned by `POST /api/v1/tokens` (for `scope="ingest"`):**
  - Linux / macOS / WSL:
    ```bash
    curl -fsSL <public_url>/install.sh | SWARMCONTROL_TOKEN=<token> bash
    ```
  - With opt-in folder activity shipping:
    ```bash
    curl -fsSL <public_url>/install.sh | SWARMCONTROL_TOKEN=<token> SWARMCONTROL_ACTIVITY_ROOTS="/path/to/workspace" bash
    ```
  - Windows PowerShell:
    ```powershell
    $env:SWARMCONTROL_TOKEN="<token>"; irm <public_url>/install.ps1 | iex
    ```

---

## 2. Authenticated Agent Ingestion Routes (`Authorization: Bearer <ingest_token>`)

Every ingest token belongs to a single tenant/organization (resolved by `auth.verify_agent_token`) and binds to a single `host_id` on first use.

| Method & Path | Auth | Handler Helper | Purpose |
| :--- | :--- | :--- | :--- |
| `POST /api/v1/ingest/heartbeat` | `Bearer <ingest_token>` | `validation.sanitize_heartbeat` + `remote_activity.inspect_heartbeat_telemetry` | Stores host CPU/RAM, detected harnesses, `capture_reader` (`core`/`fallback`), and clock telemetry (`server_time`, `clock_skew_sec`, rate-limited `WARNING` events). |
| `POST /api/v1/ingest/event` | `Bearer <ingest_token>` | Existing event flow | Stores structured runtime events (`plan`, `work_started`, `work_done`, `tool_error`, `rate_limit`, etc.). |
| `POST /api/v1/ingest/activity` | `Bearer <ingest_token>` | `remote_activity.ingest_remote_activity(db, body)` | Stores redacted activity map (`host_activity`) + unified journal steps; returns HTTP `422` (`commit_offsets: false`) on non-expired clock/timestamp rejections. |

### `POST /api/v1/ingest/activity` Request Schema
```json
{
  "schema_version": "1.0",
  "host_id": "prod-worker-01",
  "hostname": "prod-worker-01",
  "os_name": "linux",
  "arch": "x86_64",
  "collected_at": 1795448000.0,
  "scan_ms": 42.5,
  "activity_roots": ["/home/dev/equipo-demo"],
  "harnesses": [
    {
      "id": "codex",
      "name": "Codex CLI",
      "version": "0.170.0",
      "status": "running",
      "process_count": 2,
      "cpu_pct": 1.4,
      "rss_mb": 85.2,
      "evidence": ["bin:/usr/local/bin/codex"]
    }
  ],
  "sessions": [
    {
      "session_id": "codex:019a8f12c3b4",
      "host_id": "prod-worker-01",
      "harness": "codex",
      "harness_name": "Codex CLI",
      "provider": "openai",
      "provider_label": "OpenAI",
      "provider_basis": "recorded",
      "agent_id": "equipo-demo",
      "agent_name": "equipo-demo",
      "owner_basis": "workspace",
      "workspace": "/home/dev/equipo-demo",
      "model": "gpt-5.4",
      "tokens_used": 12450,
      "updated_at": 1795447990.0,
      "status": "active",
      "what_done": "Implemented invoice CSV parser and verified unit tests.",
      "plan": [
        {"status": "completed", "text": "Parse CSV rows", "named_files": ["/home/dev/equipo-demo/parser.py"]}
      ],
      "how": {"file_edit": 2, "shell_exec": 3, "file_read": 4},
      "steps": [
        {
          "tool": "apply_patch",
          "category": "file_edit",
          "label": "Edit parser.py",
          "time": "2026-11-23T15:30:00Z",
          "status": "completed",
          "files": ["/home/dev/equipo-demo/parser.py"],
          "file_basis": "confirmed"
        }
      ],
      "latest_action": {
        "tool": "apply_patch",
        "category": "file_edit",
        "label": "Edit parser.py",
        "time": "2026-11-23T15:30:00Z",
        "status": "completed",
        "files": ["/home/dev/equipo-demo/parser.py"],
        "file_basis": "confirmed"
      },
      "files_edited": ["/home/dev/equipo-demo/parser.py"],
      "files_read": ["/home/dev/equipo-demo/README.md"],
      "files_delivered": []
    }
  ],
  "workspaces": [
    {
      "id": "workspace:equipo-demo",
      "host_id": "prod-worker-01",
      "label": "equipo-demo",
      "kind": "workspace",
      "agent_id": "",
      "path": "/home/dev/equipo-demo",
      "file_count": 14,
      "truncated": false,
      "last_modified": 1795447990.0,
      "folders": [{"name": "src", "files": 8}],
      "recent_files": [
        {
          "path": "/home/dev/equipo-demo/parser.py",
          "rel_path": "parser.py",
          "size_kb": 4.2,
          "mtime": 1795447990.0,
          "category": "code",
          "edited_by": ["equipo-demo · Codex CLI"]
        }
      ]
    }
  ]
}
```

---

## 3. Drop-In Backend Helper (`backend/remote_activity.py`)

The remote activity module provides four functions:

1. `ensure_remote_activity_table(db)`:
   Creates `host_activity` plus the unified journal tables (`observed_step_keys`, `capture_offsets`, `capture_metrics`) via `backend/step_journal.py`, migrating any pre-Paso-8 rows from `remote_observed_step_keys` idempotently.
2. `ingest_remote_activity(db, body: dict) -> dict`:
   Validates, sanitizes, and redacts an incoming `POST /api/v1/ingest/activity` payload (including v1.1 `steps[].program`, opt-in `steps[].command`, `sessions[].current_folder`, `capture_reader`, `fallback_reason`, and Paso 8 `capture_steps`, `steps[].src`, `capture_gaps`, `capture_metrics`, `capture_legacy_until`, `map_update`), upserts the lean overview map in `host_activity` (preserving `capture_reader` on host summary without bloating it with `capture_steps`), and delegates step persistence to unified `step_journal.persist_steps(..., remote_clock_check=True)` (7-day retention, root-relative file paths, `position_key` + legacy upgrade dedup, `ERROR`/`WARNING`/`INFO` severity, `capture_gap`, `clock_skew`, and `reader_fallback` `WARNING` events, `capture_metrics`, and `?session=` correlation). Returns `{"ok": commit_offsets, "host_id": host_id, "server_time": now, "sessions_ingested": len(sessions), "workspaces_ingested": len(workspaces), "harnesses_ingested": len(harnesses), "steps_persisted": count, "steps_duplicates": dup, "steps_pending": pending, "steps_rejected": rej, "steps_expired": exp, "steps_clock_adjusted": adj, "clock_skew_sec": skew, "capture_gaps": gaps, "capture_reader": reader, "commit_offsets": commit_offsets, "warnings": warnings}` (with HTTP `422` on `/api/v1/ingest/activity` whenever `commit_offsets` is `False`).
3. `build_tenant_activity_map(db, local_fallback: dict | None = None) -> dict`:
   Aggregates all stored `host_activity` snapshots in the current tenant's DB (merging `harnesses`, `agents`, `sessions`, `workspaces`, `hosts[].capture_reader`, and `summary` across all enrolled hosts in that tenant) into the exact JSON format expected by `GET /api/v1/activity` and `frontend/activity.js`.
   - **Tenant isolation guarantee:** For any tenant with ingested `host_activity` rows (or any non-default organization), `build_tenant_activity_map` returns **only** that tenant's ingested remote snapshots and **never** leaks local server files.
4. `inspect_heartbeat_telemetry(conn, host_id: str, body: dict, now: float) -> dict`:
   Called inside the heartbeat handler transaction to check `collected_at` clock skew (`> 60 s`) and explicit `capture_reader="fallback"`, emitting rate-limited `WARNING` events (`clock_skew` / `reader_fallback`, 1 per host per hour per event type) and returning `server_time`, `clock_skew_sec`, and `warnings`.

---

## 4. Incremental Remote Capture, Clock Skew (D3) & Shared Reader Enforcement (D6)

Per `ACTIVITY-CONTRACT.md` §6, `agent/activity_shipper.py` and `agent/swarmcontrol_agent.py` match local `backend/work_journal.py` semantics:

- **Shared projection (`backend/step_journal.py`):** Both local `work_journal` and remote `remote_activity` project steps through `project_rows` and `persist_steps`, producing identical `events` rows and `observed_step_keys` digests (`sha256(["src", host_id, src])`) independent of timestamp so mid-session NTP adjustments produce 0 duplicates.
- **No silent fallback (D6):** `collect_incremental_activity` requires `activity_core.py` (`activity_inspector.py`). Missing `activity_core.py` raises `RuntimeError` (holding offsets) unless `SWARMCONTROL_ALLOW_FALLBACK=1` is explicitly set; core runtime exceptions propagate without silently switching to fallback. Explicit fallback runs all 4 runtime parsers (`codex`, `claude-code`, `opencode`, `antigravity`) aligned with core, stamps `capture_reader: "fallback"` and `fallback_reason` on all chunks/heartbeats/`--diagnose`, and emits rate-limited `WARNING` `reader_fallback`.
- **Forward clock skew normalization & rejection signaling (D3):**
  - When a remote batch includes `collected_at` and future steps (`> now + 60 s`) with bounded skew `<= 24 h` (via `collected_at - now` or bounded step delta), `step_journal` subtracts the constant `skew` from every step in the batch so real relative intervals are preserved, sets `steps_clock_adjusted` + `clock_skew_sec`, and emits a host/hour rate-limited `WARNING` `clock_skew`.
  - Negative skew (`<= -60 s`, `-8 days` retention expiry) and queued delayed batches (`collected_at` in the past with 0 future steps) are never shifted.
  - Non-expired un-normalizable steps (`> 24 h` ahead, invalid timestamp, or legacy payloads omitting `collected_at` with `> +60 s` steps) return HTTP `422` with `ok: false`, `commit_offsets: false`, `steps_rejected > 0`, a `WARNING` `clock_skew`, and `capture_metrics.gaps >= 1`.
  - `swarmcontrol_agent.py` holds `capture_offsets.json` up to `DEFAULT_MAX_REJECT_RETRIES = 3` (`SWARMCONTROL_MAX_REJECT_RETRIES`) attempts on `RejectedStepsError`; on the 3rd attempt it emits a `capture_gap` `WARNING`, remembers the poisoned `src` keys (by file inode, cleared on rotation) so overlap re-reads never re-block subsequent valid steps, and advances offsets.
- **Payload bounds & chunking (`chunk_activity_payload`):** Enforces `MAX_ACTIVITY_SESSIONS = 200`, `MAX_CAPTURE_STEPS_TOTAL = 2000`, preserves `capture_reader`/`fallback_reason`, and splits oversized batches under `320 KiB` UTF-8 JSON.
- **Atomic offsets & reversible upgrades (`--state-dir`, `--diagnose`, `--upgrade`):** Stores `capture_offsets.json` and `pending_activity_queue.json` atomically; `--diagnose` prints read-only health/reader/skew status; reversible upgrades are documented in `deploy/observer-upgrade.md`.
