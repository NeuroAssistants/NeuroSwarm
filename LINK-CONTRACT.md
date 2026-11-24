# Explicit Assignment–Session–Step–File Link Contract (`LINK-CONTRACT` v1)

This contract defines how NeuroSwarm connects an **assignment/task**, a **runtime session**, its **latest observed step**, and any **confirmed file** across all three views (**Agent Work**, **Activity Map**, and **Live NOC Console**) — and how navigation returns with operator filters preserved.

## Core Invariant: Explicit Relationships Only

NeuroSwarm **never infers** a task-to-session or task-to-file link from matching agent names, similar titles, or nearby timestamps. When explicit evidence is missing or ambiguous, every API and UI surface must report **`unknown`**.

### Link Resolution Precedence (Tenant-Local)

For every assignment (`task_id`) in the active organization:

1. **`explicit_task_id`** (`status: "linked"`):
   - One or more `observed_step` rows in the active organization's SQLite database carry `metadata.task_id == task_id`.
   - Works identically for local and remote machines, with or without OpenBot.
   - If the same agent runs two simultaneous tasks (`T1` and `T2`) and only `T1` has steps carrying `task_id: "T1"`, **only `T1`** is linked; `T2` reports `status: "unknown"`.
2. **`explicit_turn_session`** (`status: "linked"`):
   - Optional OpenBot orchestrator adapter (legacy organization `1` only, configured channel only): reads explicit `projection_channel_assignments.turnId` → `projection_turns.(provider_session_id, started_at, completed_at)` → `projection_provider_sessions.(provider, external_session_id)`.
   - Only eligible when **no other task** overlaps the same `(session_id, started_at, completed_at)` window.
   - Steps in the tenant database matching that exact `session_id` within `[started_at - 1s, completed_at + 2s]` (and not tagged with a different `task_id`) are linked.
   - If two tasks overlap the same session window without per-step `task_id`, resolution **refuses to guess** and returns `status: "unknown"`, `basis: "ambiguous_concurrent_turn"`.
   - If the turn session is recorded but no steps exist in the database for that window, returns `status: "unknown"`, `basis: "session_recorded_no_steps"` (identifying `session_id` as recorded while clearly marking step/file evidence as missing).
3. **`none`** (`status: "unknown"`):
   - No explicit `task_id` on steps and no unambiguous orchestrator turn link.
   - `session_id`, `last_step`, and `confirmed_file` are empty/`null`.

### Confirmed File Rule

`confirmed_file` and `confirmed_files` include **only** relative paths from linked steps where `action == "file_edit"` or `file_basis == "confirmed"`. Paths merely mentioned in plans (`basis == "mentioned"`) or generic session metadata without a confirmed step are never reported as confirmed files.

## Backend API & Ingestion Fields

### Optional `task_id` Field on Activity & Steps

- `POST /api/v1/ingest/activity` accepts an optional validated `task_id` string (`[\w][\w.:-]{0,95}`, redacted, no secrets) on a `session` or individual `step`/`capture_steps` entry.
- `backend/step_journal.py` persists `metadata_json.task_id` when explicitly provided.
- `GET /api/v1/live-records` exposes `work.task_id` when present and supports `?task_id=<id>` (tenant-local exact match on `observed_step` rows).
- `GET /api/v1/event-feed` preserves `details.task_id` in event payloads.

### Explicit Link Index (`GET /api/v1/work-board` & `GET /api/v1/links`)

`GET /api/v1/work-board` appends a top-level `links` object (without altering existing `collaboration.changes` or `reports` keys), and `GET /api/v1/links` (optional `?task_id=<id>` or `?session=<session_id>`) returns the same tenant-scoped structure with `Cache-Control: no-store`:

```json
{
  "version": "1",
  "organization": 1,
  "by_task": {
    "task-123": {
      "task_id": "task-123",
      "change_id": "root-1",
      "status": "linked",
      "basis": "explicit_task_id",
      "reason": "Explicit task_id recorded on 2 observed step(s).",
      "session_id": "codex:example-session",
      "host_id": "build-01",
      "agent": "builder",
      "runtime": "codex",
      "step_count": 2,
      "last_step": {
        "event_id": 42,
        "key": "event:42",
        "ts": 1795460000.0,
        "action": "file_edit",
        "message": "File edit · src/billing.py",
        "program": "",
        "file": "src/billing.py",
        "file_basis": "confirmed"
      },
      "confirmed_file": "src/billing.py",
      "confirmed_files": ["src/billing.py"],
      "confirmed_file_event_id": 42
    }
  },
  "by_session": {
    "codex:example-session": [
      {
        "task_id": "task-123",
        "change_id": "root-1",
        "title": "Fix billing rounding",
        "agent": "builder",
        "status": "running",
        "basis": "explicit_task_id"
      }
    ]
  }
}
```

## Multi-Tenant Isolation

- Every query runs strictly inside the authenticated organization's database (`self.resources.db`).
- Optional OpenBot turn→session links are restricted to legacy organization `1` and the single server-configured channel. Other organizations always receive `{"changes": []}` and only links resolved from their own tenant database.
- Switching organizations in the browser clears `task`, `session`, and `file` scopes immediately.

## Cross-View URL & Filter-Preservation Contract

- **Control Room (`/`):** supports `?am_view`, `?am_host`, `?am_agent`, `?am_q`, `?am_span`, `?am_session`, `?task`, and `?return_to`.
- **Live NOC Console (`/live`):** supports `?task`, `?session`, `?host`, `?agent`, `?runtime`, `?file`, `?event`, `?persp`, `?sev`, `?kind`, `?cat`, `?status`, `?win`, `?group`, `?q`, and `?from`.
- **`from` / `return_to` safety:** both surfaces accept **only** same-origin relative paths starting with `/` (rejecting `//`, schemes, and control characters) so operators can jump **Assignment → Session → Last Step / Confirmed File** and return with all previous filters preserved, with zero open-redirect exposure.
