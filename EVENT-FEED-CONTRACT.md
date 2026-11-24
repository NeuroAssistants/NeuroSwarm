# Event feed contract (v1) · real-time data for the full-screen event console

## Route

`GET /api/v1/event-feed?cursor=<opaque>&limit=<1..1000, default 500>` · any role (viewer, operator, admin) and
`read` tokens · current organization only · `400 {"error":"invalid cursor"}` on a bad cursor or limit.

```python
# backend/server.py, inside the authenticated GET block
from event_feed import FeedError, feed as event_feed
if path == "/api/v1/event-feed":
    try:
        self._send_json(event_feed(self.resources.db, (qs.get("cursor") or [None])[0], (qs.get("limit") or [None])[0]))
    except FeedError as exc:
        self._send_json({"error": str(exc)}, status=400)
    return
```

## Response

```json
{"version": "1", "reset": true, "cursor": "1.e812.a1795450000.25.i44.c", "more": false, "server_time": 1795450001.0,
 "records": [{"key": "alert:44", "kind": "alert", "id": 44, "ts": 1795450000.25, "created_at": 1795449000.0,
              "updated_at": 1795450000.25, "severity": "CRITICAL", "state": "ACKED", "host_id": "worker-01",
              "harness": "", "agent": "", "source": "RUNAWAY_CPU", "title": "…", "summary": "…",
              "acked_by": "ana", "acked_at": 1795450000.25, "details": {"cpu": 97}}],
 "counts": {"alerts": {"OPEN": 2, "ACKED": 1, "RESOLVED": 0},
            "open_alerts_by_severity": {"CRITICAL": 1, "ERROR": 0, "WARNING": 1, "INFO": 0, "DEBUG": 0},
            "events_24h_by_severity": {"CRITICAL": 0, "ERROR": 1, "WARNING": 0, "INFO": 4, "DEBUG": 0}}}
```

- Events: `state = "RECORDED"`, `source = event_type`, `details = metadata`. Alerts: `state` OPEN/ACKED/RESOLVED,
  `source = rule_code`, `details = evidence`, `ts = updated_at` (time of the last change).
- Severities are normalized to CRITICAL, ERROR, WARNING, INFO, DEBUG. Text is stored text: **escape before rendering**.

## Client algorithm (the console)

1. First call without cursor → `reset: true`: replace the list with `records`.
2. Every 2 s call with the last `cursor`. **Upsert by `key`** (an alert's acknowledgement arrives as the same key).
3. While `more` is true, call again immediately (no wait) until it is false.
4. Pause freezes the screen, not the feed: keep reading and buffer, and show "N new while paused".
5. On organization switch or 401: drop records and cursor, start again at step 1. On 400: drop the cursor.
6. The console may cap what it keeps in memory (e.g. 5 000 newest); the feed itself never skips.

## Guarantees (tested in `tests/test_event_feed.py`)

- A burst of 1 200 events and 1 100 alert changes is delivered completely in ≤ 6 calls; nothing repeats afterwards.
- An acknowledgement after the cursor arrives as an update of the same key with `acked_by`.
- A write committed with the same timestamp as the cursor is still delivered (alerts of the last 2 s are re-sent).
- Bad or tampered cursors and limits are rejected; organizations are separate databases.

## Open one event

Each event keeps its numeric ID when it moves from the live stream into history. Its row contains the workspace and up to twelve file paths relative to the folders the operator shared. A relative source path requires a recorded working directory inside those folders.

A signed-in member or a read token can request `GET /api/v1/events/{id}/evidence?organization_id={org}`. The response includes `event_id`, `organization`, `files`, `session`, `workspace`, `program`, `command_input`, `command_output`, `exit_code`, `output_truncated`, `images`, and `text_previews`. Each text preview contains the recorded relative path, redacted plain text, its source and a truncation flag. Missing text or an unknown exit code is JSON `null`. An empty string means the collector recorded empty output. Clients should render command text as plain text and fetch evidence only after an operator opens the event.

Each image entry includes its relative `path`, `source`, `captured_at` (Unix seconds), `mime_type`, `size_bytes`, SHA-256 digest and a same-origin `url`. A `tool_result` contains the bytes recorded by the tool. A `workspace_snapshot` contains the bytes the collector found in a shared file after the read. The collector skips snapshots with a later modification or change time and refuses symlinks. The image URL retrieves stored bytes under the same event and organization. No request takes a filesystem path. Both responses use `Cache-Control: no-store`. A missing event or image returns 404. An explicit organization that differs from the active one returns 409.

The event and its evidence are written in the same transaction. If a later scan supplies a tool result, it may fill missing output on the same recorded call. Replaying a capture does not replace stored output or an existing image. Pruning the event also removes its command and images. Existing events keep their file lists and may have no detailed capture.


The activity map includes `event_id` and `event_org` on a step when its source record matches a journal entry. Both the map and the journal use the host, full session, log position and the action’s order within the record. Use these two fields to open the same detail endpoint. Steps from older collectors or before this release may have no link. In that case show the session history without choosing a nearby event. Two identical commands can run in the same second and return different results.
