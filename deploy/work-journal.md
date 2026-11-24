# Agent work in Live events

Open **Live events** and choose **Agent Work (All)**. Select a row for a summary. Double-click the row, or focus it and press Enter, to open the event. A command can show its input, output and exit code together. Escape returns you to the list.

To find a file, choose its name under **Files Touched & Viewed** or search its relative path. Open the read or edit that interests you. A captured image opens at full size when you select its thumbnail. Use **Correlations** to follow related steps and **Load older history** to look farther back.

The local journal scans agent logs every five seconds. It stores only actions from agents named in `SWARMCONTROL_JOURNAL_AGENTS` and displays file paths relative to `SWARMCONTROL_JOURNAL_PROJECT`. The inspector's configured roots determine which sessions it can see. Local journal rows belong to the original organization. Other machines report through the observer.

The journal keeps observed actions for up to seven days, subject to the instance's event retention. Older actions first seen during startup can also appear. With the default settings a shell step can show its tool, program and exit code when the agent recorded them. Command text, output and file previews each require an explicit choice on the machine that ran the agent. Private reasoning is excluded.

To include linked files from another shared project in the persisted history, explicitly set `SWARMCONTROL_JOURNAL_ROOTS` on the journal service. List absolute folders separated by the platform path separator (`:` on Linux). The inspector must also be configured to observe them. Secondary files display as `project-name/relative/path`; the primary project keeps its existing relative paths. Changes apply to newly recorded actions.

With `SWARMCONTROL_SHARE_COMMANDS=1`, the list can show a short operation such as `git diff`. Open the event to see its recorded command input with common secrets masked. The settings and limits for each kind of detail are listed below.

## Incremental capture

Each scan reads every agent log **from the byte where the previous scan stopped**. Nothing appended between scans is
skipped, however large the burst. The local journal and the remote observer use the same reader and the same rules.

- **Identity of an action:** its exact source position (`<log>:<byte>:<n-th step of that record>`; OpenCode uses
  message and part). Re-reading the same bytes never stores an action twice.
- **Atomic:** actions, read offsets (`capture_offsets`), gaps and metrics (`capture_metrics`) are committed in one
  transaction. A failed write (e.g. database locked) commits nothing; the journal retries with backoff
  (5 s → 60 s) and re-reads the same bytes. A crashed parser keeps its offsets for the next scan.
- **Restart:** offsets live in the database, so actions written while the journal was stopped are read on restart.
- **Unfinished steps** (`running`/`pending`) are stored once they finish, so an action is not stored twice.
- **Large records:** a record of any size up to 32 MB (a `Write` of a large file, a screenshot) is read whole, even
  past the per-scan budget. A record over 32 MB is skipped with a `capture_gap` WARNING ("record over 32 MB skipped")
  and the read continues after it. A backlog larger than 4 MB is consumed in order over several scans
  (`capture_metrics.backlog_files`). The Activity map (not the journal) hides lines of 400 kB or more.
- **Gaps are visible:** if a log is truncated or rotated, a `capture_gap` WARNING event is stored instead of a
  silent loss.
- **First scan and new logs:** the first scan ever stores a baseline (`capture_offsets` row `__baseline__`) and reads
  each existing log from its last 640 kB (older history predates the journal). Any log that appears after that is
  read from its first line, over several scans if needed.
- **Claude Code sub-agents:** `<project>/<session>/subagents/agent-*.jsonl` are read as their own sessions
  (`Claude Code · sub-agent`), owned by their own launch folder and linked by `parent_session`, which is also stored
  in each sub-agent step's metadata. Live events does not yet offer a jump from a sub-agent step to its parent.
- **Session ids:** sessions are stored as `runtime:<full id>` (up to 96 chars), so agents launched in the same second
  stay separate.
- **Codex plans:** `tools.update_plan` inside Codex `exec` is stored as a `plan` action, like the plan updates of the
  other runtimes.
- **Privacy.** The journal and the Activity map use the same shared folders. Only a member or read token for the event's organization can retrieve its captured output or previews.

### Upgrading from an earlier journal

Earlier journals sampled the latest ten steps per session, keyed actions by content and stored the first 12
characters of each session id. On the first incremental scan, bytes that existed before it (`legacy_until`) are also
checked against those earlier keys (`legacy_session_id`), so upgrading does not store the same action twice. Rows
whose earlier format lacked the program name are matched by host, agent, 12-character session, action and time
(±1 s); each stored row is matched at most once, so two real actions in the same second are both kept. The first
scan may still add older actions the earlier journal never saw; they keep their original time. In the session filter,
work from before the upgrade shows under the short id and later work under the full id.

Metrics per scan, for the last 7 days:

```sql
SELECT datetime(ts,'unixepoch') AS scan, steps_seen, inserted, duplicates, pending, gaps, files_read, bytes_read, backlog_files, ms
FROM capture_metrics ORDER BY ts DESC LIMIT 20;
```

Limits: OpenCode reads the latest 400 assistant messages / 2 000 tool parts of a changed session per scan; up to
200 sessions per runtime are considered per scan. Unchanged logs are not re-read. An OpenCode message over 32 MB is
read as empty, without a gap event.

### Command output and image previews

Set the choices below in the environment of the **collector on the machine running the coding agent**, then restart that collector. Settings take effect on newly observed steps.

| Setting | Captured when set to `1` |
| --- | --- |
| `SWARMCONTROL_SHARE_COMMANDS` | Redacted command input, up to 1,024 characters in event detail. The list keeps its short operation name. |
| `SWARMCONTROL_SHARE_COMMAND_OUTPUT` | Up to 4,096 characters of redacted output when the tool records a result. The detail shows when a longer excerpt was clipped. |
| `SWARMCONTROL_SHARE_FILE_PREVIEWS` | A PNG, JPEG, GIF or WebP up to 160 KiB, or a redacted text excerpt up to 4,096 characters from a recorded file read in a shared folder. |

All three settings default to off. File names and recorded exit codes can still appear. Enable detailed capture only in folders whose contents may be shared with the members and read tokens of that organization. Redaction covers common secret formats. Ordinary text and image content can contain private information.

An image marked **Tool result** contains the bytes the tool returned to the agent. A **Workspace snapshot** shows what the collector found in the file and carries its own timestamp. The path can still appear when a preview is unavailable. Source snapshots require a system with directory-relative, no-follow file opens.

Command detail depends on what the agent logged. An exit code of `0` means the command succeeded. Empty output means it produced no text. Missing output means the collector has no recorded result for that call. A result found on a later scan can fill in the original event when its call identifier matches.
