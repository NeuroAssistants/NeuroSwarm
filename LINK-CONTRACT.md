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

## Edit verification

Open a file edit in **Live Events**. Under **Verification after edit**, select a passed or failed test to open its recorded command and output. **No verification recorded** means the observer has no matching test result for that edit. A test result describes the command that ran on that revision. Line coverage requires separate evidence.

### Enable capture on a development machine

Use an enrolled observer or local journal that captures Claude Code transcripts. Keep a NeuroSwarm checkout on that machine for the optional hook and use the same server, host ID and ingest token as the observer. From the Git project being tested, set the task and agent explicitly for that session. Set different agent names for different workers.

```sh
export SWARMCONTROL_ACTIVITY_ROOTS="$PWD"
export SWARMCONTROL_TASK_ID=task-41
export SWARMCONTROL_AGENT_NAME=builder-a
python3 /path/to/NeuroSwarm/integrations/verification_hook.py --print-settings
```

Merge the printed entries into your Claude Code settings and start the session with those environment variables. The hook uses the existing enrollment environment or `agent.env`. On the observer, enable `SWARMCONTROL_SHARE_COMMANDS=1` for command arguments and `SWARMCONTROL_SHARE_COMMAND_OUTPUT=1` for redacted output. Each is a separate choice. [Observer settings](deploy/work-journal.md#command-output-and-image-previews) · [Claude Code hook events](https://code.claude.com/docs/en/hooks)

### What establishes the link

1. Before a native `Write` or `Edit`, the hook calculates the expected file contents. After success it checks that the file changed as requested and fingerprints the working tree.
2. Before a foreground test, the hook records the completed edit IDs in that same checkout, task, actor, session and revision. On completion it checks the revision again, together with file change times and identities. The resulting receipt names up to 32 edits. Clock proximity and shared filenames never establish a link.
3. The observer independently reads the native tool IDs from the transcript. The server matches both receipts to their own events in the enrolled host and organization. It checks their order using positions within the transcript, including when timestamps are identical. A conflict or an ambiguous tool ID leaves the edit unverified. Receipts and transcript events may arrive in either order. The hook retries unsent receipts on later calls or with `--flush`, using its private, enrollment-specific queue for up to seven days. Keep that queue outside the project.

The revision is a SHA-256 fingerprint of Git HEAD and the names, execute bits and exact bytes of tracked and unignored new files in the working tree. The hook samples the tree before and after the test. Temporary files created and removed between those snapshots, ignored build products, installed dependencies and external services are outside its scope. Capture requires a committed Git project within the selected roots. Protected files, symlinks, detected changes and projects over 2,048 files, 4 MiB per file or 32 MiB in total cause capture to skip the link.

The included producer handles Claude Code main sessions with native tool IDs and direct foreground commands such as `python3 -m unittest`, `pytest`, `go test`, `cargo test` and `npm test`. Compound shell commands, background runs, subagents and custom wrappers have no producer in this version. Older records and other runtimes continue to open normally with **No verification recorded**.

### HTTP contract and acceptance

`POST /api/v1/ingest/verification` accepts independent edit and test receipts with an ingest token bound to the host. Each has `host_id`, `session_id`, `actor`, `task_id`, `revision`, `role` and `call_ref`. Both identifiers are full lowercase SHA-256 digests. A test receipt adds `result` (`passed` or `failed`) and `edits` (the explicit edit references). Identical retries succeed. Changing the receipt for an existing call returns HTTP 400. The observer supplies the matching `native_call_ref` only on captured steps. Hook payloads contain IDs and digests. The existing observer controls file and command detail.

`GET /api/v1/events/{id}/evidence?organization_id={org}` adds a `verification` field on edits. Its `status` is `not_recorded` with an empty `tests` list, or `recorded` with the task, actor, revision and up to ten recent test events. Each result includes `event_id`, `result`, time, program and an exit code when the native record supplies one. Opening that exact event fetches the command and output under the active organization's permissions.

Run the two-agent browser and capture tests from the NeuroSwarm checkout.

```sh
python3 -m unittest discover -s tests -p test_edit_verification.py -v
```

With Claude Code installed, the following acceptance run uses two actual sessions, temporary Git projects and a scripted model on loopback. Claude runs its own tools and hooks and writes its normal transcripts.

```sh
python3 tests/run_native_edit_verification.py "$(command -v claude)"
```
