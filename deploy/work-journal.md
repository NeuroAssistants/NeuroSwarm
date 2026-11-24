# Agent work in Live events

Open **Live events**, select **Agent work only** and filter by agent. Select a row to see the runtime, observed tool, time, workspace and any project files linked directly to that step. **Follow this session** limits the history to the same session, runtime, host and agent. **Older records** pages backward through retained records. **Return to live** displays the newest page again.

The local journal scans agent logs every five seconds. It stores only actions from agents named in `SWARMCONTROL_JOURNAL_AGENTS` and displays file paths relative to `SWARMCONTROL_JOURNAL_PROJECT`. The inspector's configured roots determine which sessions it can see. Only the original organization's database receives local journal rows; other machines report through the observer. The live view polls every three seconds.

The journal persists observed actions for up to seven days, subject to the instance's event retention. Older actions first seen during startup can also appear. A shell step may have only a tool name or a command category. Command arguments, file contents and private reasoning are excluded. Related steps show shared session context; a recorded read or command alone does not establish a file edit.

To include linked files from another shared project in the persisted history, explicitly set `SWARMCONTROL_JOURNAL_ROOTS` on the journal service. List absolute folders separated by the platform path separator (`:` on Linux). The inspector must also be configured to observe them. Secondary files display as `project-name/relative/path`; the primary project keeps its existing relative paths. Changes apply to newly recorded actions.

With `SWARMCONTROL_SHARE_COMMANDS=1` on the journal, known operations such as `git diff`, `rg --files` and `python3 -m unittest discover` may also be recorded. The journal keeps the fixed operation name and omits positional values, inline code, and shell payloads. For other operations, the program name is the available detail.

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
- **Privacy:** same folder scope and redaction as the Activity map; command arguments are not stored.

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

An image marked **Tool result** is the recorded image. A **Workspace snapshot** comes from a file read on the source machine during collection and carries its own timestamp. If neither is available, the event has a path and no image. Source snapshots require a system with directory-relative, no-follow file opens. Command output depends on the format of the source log. For example, a Codex completed command can include both its output and exit code. A Claude result is linked only when its tool ID can be matched to the call in the scan.
