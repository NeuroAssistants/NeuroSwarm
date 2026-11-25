# What can I see?

NeuroSwarm reads the session records each runtime already writes on disk. It installs no hooks, wraps no commands and
changes nothing in the agent's configuration. Only sessions in folders you opt in to are shared.

| Runtime | Session activity source | First thing to verify |
| --- | --- | --- |
| Codex CLI | Local session records | A completed file change has a workspace-relative file. |
| Claude Code | Local project and subagent logs | The session and its parent remain distinct when the working folder changes. |
| OpenCode | Local session database | The tool outcome belongs to the selected session. |
| Antigravity | Conversation database and transcript | The displayed agent matches the session that produced the step. |
| Hermes Agent | Read-only profile session database | A completed tool call appears under its session and workspace. |
| Pi Coding Agent | Version 3 JSONL session files | A tool result for the selected file and session appears in Live Events. |

## Hermes and Pi in host inventory

The observer checks for the Hermes profile’s `state.db` and Pi’s `sessions` directory.
It uses `HERMES_HOME` or `PI_CODING_AGENT_DIR` when set in the observer environment;
the defaults are `~/.hermes` and `~/.pi/agent`. A marker shows **configured**. A
matching command on PATH plus its marker shows **installed**. A running
`hermes-gateway.service` visible to the system service scan shows **running**.
This check inspects file metadata. Both tools also have separate session readers. Hermes reads the default database and named profiles under the configured home.

## Pi sessions

Select the project folder in the observer's activity roots. Run Pi from that folder and complete a read, write, edit or bash command. Open the Pi session in the activity map or filter Live Events by the Pi runtime. Double-click a command to see the evidence shared by that observer.

The reader looks in `~/.pi/agent/sessions` or the profile set by `PI_CODING_AGENT_DIR`. Set `PI_CODING_AGENT_SESSION_DIR` on the observer to use a different sessions folder, including one passed to Pi with `--session-dir`. Both a flat directory and Pi's per-project directories are supported.

The session header must name a shared working folder. The reader pairs a tool call with its result on the same conversation branch. Failed edits remain failed attempts. Pending calls and results whose call is outside the read window have no recorded action. Prompts and patch text are omitted. Command input, output and file previews each use the existing opt-in settings. With file previews enabled, an eligible read can show the redacted text or raster image Pi returned. An exit code is shown only if Pi recorded it as a number. Custom tools and automatic edit-to-test verification for Pi are outside the current coverage.

[Pi session format](https://docs.pi.dev/latest/session-format) · [Pi environment variables](https://docs.pi.dev/latest/environment-variables)

## Actions captured per runtime

| Action | Codex CLI | Claude Code | OpenCode | Antigravity | Pi Coding Agent |
| --- | --- | --- | --- | --- | --- |
| File edit, with the file | ✓ | ✓ | ✓ | ✓ | ✓ |
| Command (program name; arguments only with `SWARMCONTROL_SHARE_COMMANDS=1`) | ✓ | ✓ | ✓ | ✓ | ✓ |
| File read or search | ✓ | ✓ | ✓ | ✓ | ✓ |
| Plan update | ✓ | ✓ | ✓ | ✓ | — |
| Coordination tool calls (MCP) | ✓ | ✓ | ✓ | ✓ | — |
| Sub-agents as their own sessions | — | ✓ | — | ✓ | — |
| Tokens and cost | — | — | — | — | — |

A dash means the action is not captured yet, not that the runtime lacks it. Pi captures the built-in `read` tool. Its tests are in `tests/test_pi_activity.py`. Hermes coverage is tested in `tests/test_hermes_sessions.py`. The four original runtimes, except Antigravity sub-agents
(checked on real logs only), are covered by the capture audit in
`tests/product_qa/` (`python3 tests/product_qa/capture_audit.py`). It writes a known script in each runtime's own
record format and compares what is stored with what was written, through the local journal and the remote observer.

A detected process can appear in host inventory before a session has any shared activity. On the observer, opt in to the relevant project folder and preview the payload. The journal starts with a bounded window of existing logs. It follows new records incrementally; rotation or unsupported record sizes can leave gaps. A file mention and a confirmed edit are labeled separately.

[Activity data contract](../ACTIVITY-CONTRACT.md) · [Remote observer and privacy settings](../REMOTE-CONTRACT.md) · [Capture limits](../deploy/work-journal.md#incremental-capture)
