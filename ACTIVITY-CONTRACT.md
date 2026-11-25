# Activity map contract (v1)

## 1. One snapshot format for local and remote collectors

`activity_inspector.collect_activity(Scope(...))` returns the same JSON the remote agent posts to
`POST /api/v1/ingest/activity`, plus these fields (all optional for readers):

| Field | Meaning |
|---|---|
| `schema_version` | `"1.0"` |
| `host_id`, `hosts[]` | `hosts[i] = {host_id, hostname, updated_at, activity_roots[], activity_enabled}` |
| `activity_enabled` | `false` when the operator listed no folders; sessions and workspaces are then empty |
| `sessions[].provider`, `provider_label`, `provider_basis` | `recorded` (harness stored it), `model` (inferred from model name) or `unknown` |
| `sessions[].latest_action` | last recorded step |
| `sessions[].latest_work` | last substantive step (edit, command, read, web, image); falls back to `latest_action` |
| `steps[].file_basis` | `confirmed` = completed edit/read record names the file; `recorded` = file appears in the step record only |

Step categories: `file_edit`, `file_read`, `shell`, `think`, `plan`, `web`, `coordination`, `visual`, `other`.
The map also accepts the agent's `shell_exec`, `web_research`, `visual_asset` and maps them to these.

## 2. Same settings on both sides

| Variable | Rule |
|---|---|
| `SWARMCONTROL_ACTIVITY_ROOTS` | opt-in folders, `os.pathsep`- or comma-separated. Empty ⇒ nothing is read |
| `SWARMCONTROL_AGENT_LABELS` | `key=Name,…`; key = folder name or absolute folder path |
| `SWARMCONTROL_HOST_ID` | host id in the snapshot (default: hostname) |
| `SWARMCONTROL_ACTIVITY_ADAPTERS` | optional, e.g. `openbot`. Adapters add roots/labels; the core never needs them |

Identity rule: a session belongs to the **longest configured root** that contains its working folder.
`agent_id` = that root's folder name (a 6-hex path hash is appended only if two roots share a name);
`agent_name` = label for the absolute path, else for the folder name, else the folder name.
Sessions outside every root are not read. File paths outside every root are dropped.
Antigravity ownership comes from workspace URIs in the conversation's own metadata, never from transcript text.

## 5. v1.1 additions: commands and owner

| Field | Meaning |
|---|---|
| `steps[].program` | Program a shell step ran (`pytest`, `rg`, `systemctl`…), for Codex, Claude Code, Antigravity and OpenCode. Wrappers (`sudo`, `timeout`, `bash -lc`, `cd … &&`, `VAR=…`) and shell keywords are skipped. Never includes arguments. |
| `steps[].command` | **Opt-in only** (`SWARMCONTROL_SHARE_COMMANDS=1` on the collecting host): the command line, ≤160 chars, after secret redaction (`-u/-p/--token/--password/-H` values, bearer, keys, `password=`…), with sensitive file names shown as `[protected file]` and absolute paths shortened to `…/parent/name`. |
| `sessions[].current_folder` | Claude Code: latest working folder when it differs from the owner folder. |

Owner rule fix: a Claude Code session belongs to the folder where it **started** (first `cwd` in its log), not the folder it
`cd`'ed into. Before this, an agent working inside a shared project was attributed to that project and dropped by the journal.

## 6. Incremental capture contract

Local implementation: `activity_inspector.Capture` + `work_journal.capture_once`. The remote observer follows the
same rules, so local and remote actions are stored identically.

| Rule | Local journal | Remote observer / `remote_activity` |
|---|---|---|
| Read | from saved byte offset (minus 256 kB overlap) to EOF; ≤ 4 MB per scan, rest next scan | same `Capture` class (it is in `activity_core.py`) with offsets kept on the agent host |
| Steps sent | `sessions[].capture_steps` = all steps read in the scan | send `capture_steps` (not only `steps`, which stays the map's last 10) |
| Action identity | `steps[].src` = `<file key>:<byte offset>:<n>`; key = sha256(["src", host_id, src]) | dedupe by (host_id, src); keep the content key only for legacy rows |
| Unfinished | `status` running/pending/in_progress not stored until final | same |
| Atomicity | events + offsets + metrics in one transaction | agent advances its offsets only after HTTP 2xx from ingest; bounded retry queue |
| Gaps | rotated/truncated log ⇒ `capture_gap` WARNING event | send `capture_gaps: [{reason, file_key}]`; server stores the same event |
| Metrics | `capture_metrics` table per scan | include `capture_metrics` in the payload or expose them in `--diagnose` |

`file key` = first 20 hex chars of sha256(absolute log path); it never reveals the path.

### 6.1 Capture details · same in `activity_core.py` and the observer's fallback reader

| Field / rule | Meaning |
|---|---|
| `sessions[].session_id` | `runtime:<full id>`, at most 96 chars (earlier versions stored the first 12 chars of the id) |
| `sessions[].legacy_session_id` | `runtime:<first 12 chars>`; used only to recognise content keys stored by earlier versions. Ingest keeps it (redacted, ≤ 96) |
| `sessions[].parent_session` | Claude Code sub-agent sessions only: the `session_id` of the session that launched it. Also stored in each step's metadata (`parent_session`, redacted, ≤ 96) |
| Upgrade match | below `legacy_until`, a step also matches a stored row with same host, agent, `legacy_session_id`, action and time ±1 s (older rows can omit `program`). `legacy_until` covers only bytes present at the first scan; a remote payload without `capture_legacy_until` gets exact keys only, never this match |
| Record size | records up to 32 MB are read whole; larger ones ⇒ `capture_gaps: [{reason: "record over 32 MB skipped", file, bytes}]` |
| Offsets `__baseline__` | written on the first scan with no saved offsets. Saved offsets ⇒ logs not yet seen are read from byte 0; no saved offsets ⇒ last 640 kB. Not a file: never read |
| Codex plan | `tools.update_plan` in `exec` ⇒ a `plan` step (`tool: update_plan`) |

### 6.2 Line survival (opt-in, `SWARMCONTROL_SHARE_LINE_SURVIVAL=1`)

| Field | Meaning |
|---|---|
| `capture_steps[].git_commit` | 7–40 hex characters: the commit ID the session's own successful `git commit` printed. Only on that command's step |
| `line_survival[]` | Per recent commit and file in a shared folder: `sha`, `path` (absolute, projected like step files), `added`, `surviving` (lines `git blame -M HEAD` still assigns to the commit), `exists`, `commit_time`, `prev_time` (previous commit to the file), `head`, `measured_at`; since line ranges: `ranges` (`[[first, last], …]` HEAD line numbers whose `git blame -M` origin is `sha`, at most 100, must add up to `surviving` unless `ranges_truncated`), `repo_path` (path inside the repository, for the verification command) and `too_large` (file over 2 MB, not measured). Numbers only, at most 300 items |
| Event metadata `line_keys` | `<shared folder label>/<path>` for each file of an edit, used to join measurements; `git_commit` on the commit's event |
| `GET /api/v1/events/{id}/line-survival` | Members and read tokens of the event's organization. Takes no path. Returns per file a `status` (`attributed`, `no_commit`, `not_in_commit`, `earlier_commit`, `other_session`, `not_shared`, `not_tracked`, `too_large`), a plain reason, and counts only when `attributed`; then also `ranges`, `ranges_truncated`, `repo_path` and `head_commit` (null `ranges` from older observers) |

### 6.3 Where records are read, and the `sources` report

Each reader uses the runtime's own location setting when it is present in the collector's environment, then the
runtime's default. Set the same variable on the observer (or journal) service when an agent keeps its records
elsewhere; the observer does not read the variables of other processes.

| Runtime | Setting | Default | Notes |
|---|---|---|---|
| Codex CLI | `CODEX_HOME` | `~/.codex` | The newest `state_N.sqlite` whose `threads` table has the columns the reader uses. A newer file in an unknown format is reported, not guessed. |
| Claude Code | `CLAUDE_CONFIG_DIR` | `~/.claude` | `projects/` (including sub-agents) and `tasks/`. |
| OpenCode | `XDG_DATA_HOME` | `~/.local/share` | `opencode/opencode.db`. |
| Gemini / Antigravity | — | `~/.gemini/antigravity-acp`, `antigravity`, `antigravity-ide`, `antigravity-cli` | Every variant with the `brain/<id>/.system_generated` layout. |

`sources` (top level and on `hosts[]`): one entry per location looked at, `{runtime, location, origin, status}`.
`location` is `~/<path>` inside the home folder, otherwise `set by <VARIABLE>`; no other path is sent. `origin` is the
variable that chose it or `default`. `status` is `found`, `not found`, `no permission`, or
`unsupported format (<file>)` (optionally `; reading <older file>`). Remote ingest keeps at most 12 entries with these
statuses and shows them on the map's machine card; they are never stored as events.

### 6.4 Why evidence is missing, and web resources

Each step's event metadata may carry `output_reason` and `files_reason`, from a fixed vocabulary:

| Value | Meaning |
|---|---|
| `empty_output` | The command ran and printed nothing. |
| `capture_disabled` | The machine does not share command output (`SWARMCONTROL_SHARE_COMMAND_OUTPUT`). |
| `outside_scope` | The command ran, or named a file, outside the folders this journal may share. |
| `protected` | The command asked for credential files or the environment; its output is never kept. |
| `not_recorded` | The runtime did not report an output for this call. |
| `no_file_target` | The command names no file (`git status`, `python3 -c`, `curl https://…`). |

Events recorded before these fields existed have neither; Live shows them as "not recorded".

`web_resource` describes curl/wget calls and browser or web tools: `kind` (`http`, `visit`, `search`, `snapshot`, `interact`, `credential`), `method`, `url` (http/https only, without user, password, fragment or the values of secret-looking query parameters), `query`, `status_code`, `status_text` and `response_excerpt` (redacted, at most 1,200 characters). The address and the query need `SWARMCONTROL_SHARE_COMMANDS=1`; the status and the excerpt need `SWARMCONTROL_SHARE_COMMAND_OUTPUT=1`. A command outside the shared folders keeps only `kind` and `method`, and a credential step keeps only `kind`. The status comes from the response headers (`-i`, `-I`, `-v`) or from `-w '%{http_code}'`; a 401 is visible even when curl exits 0.

With `curl -L` (or `wget` following redirects), `hops` lists every recorded response in order, each with `status_code`, `status_text` and, with command sharing, its `location` (cleaned like `url`; a relative target keeps only its cleaned path). `status_code` and `response_excerpt` belong to the final response.

HTTP fields per agent runtime (verified by `tests/test_http_all_adapters.py` with a real `curl` against a local 302 → 401 fixture):

| Runtime | Method, address, hops, status, excerpt | Process exit code |
|---|---|---|
| Codex CLI | ✓ | ✓ |
| Claude Code | ✓ | — (its Bash result has no exit code) |
| OpenCode | ✓ | ✓ (`state.metadata.exit`) |
| Antigravity | ✓ when the transcript records the command output | ✓ when recorded |
| Hermes Agent | ✓ | ✓ when the tool result includes `exit_code` |
| Pi Coding Agent | ✓ | ✓ (`details.exitCode`) |

Web tools other than shell commands (browser visits, searches, page captures) carry `kind` for every runtime; their address and query are extracted for Codex and Claude Code only.

Which commands lose evidence most often:

```sql
SELECT json_extract(metadata_json, '$.program') AS program,
       COALESCE(json_extract(metadata_json, '$.output_reason'), 'kept or not recorded') AS reason, COUNT(*) AS steps
FROM events WHERE event_type = 'observed_step' AND json_extract(metadata_json, '$.action') = 'shell'
GROUP BY 1, 2 ORDER BY steps DESC;
```
