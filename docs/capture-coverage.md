# What can I see?

NeuroSwarm reads the session records each runtime already writes on disk. It installs no hooks, wraps no commands and
changes nothing in the agent's configuration. Only folders you opt in to are read.

| Runtime | Session activity source | First thing to verify |
| --- | --- | --- |
| Codex CLI | Local session records | A completed file change has a workspace-relative file. |
| Claude Code | Local project and subagent logs | The session and its parent remain distinct when the working folder changes. |
| OpenCode | Local session database | The tool outcome belongs to the selected session. |
| Antigravity | Conversation database and transcript | The displayed agent matches the session that produced the step. |

## Actions captured per runtime

| Action | Codex CLI | Claude Code | OpenCode | Antigravity |
| --- | --- | --- | --- | --- |
| File edit, with the file | ✓ | ✓ | ✓ | ✓ |
| Command (program name; arguments only with `SWARMCONTROL_SHARE_COMMANDS=1`) | ✓ | ✓ | ✓ | ✓ |
| File read or search | ✓ | ✓ | ✓ | ✓ |
| Plan update | ✓ | ✓ | ✓ | ✓ |
| Coordination tool calls (MCP) | ✓ | ✓ | ✓ | ✓ |
| Sub-agents as their own sessions | — | ✓ | — | ✓ |
| Tokens and cost | — | — | — | — |

A dash means the action is not captured yet, not that the runtime lacks it. Every ✓ except Antigravity sub-agents
(checked on real logs only) is covered by the capture audit in
`tests/product_qa/` (`python3 tests/product_qa/capture_audit.py`). It writes a known script in each runtime's own
record format and compares what is stored with what was written, through the local journal and the remote observer.

A detected process can appear in host inventory before a session has any shared activity. On the observer, opt in to the relevant project folder and preview the payload. The journal starts with a bounded window of existing logs. It follows new records incrementally; rotation or unsupported record sizes can leave gaps. A file mention and a confirmed edit are labeled separately.

[Activity data contract](../ACTIVITY-CONTRACT.md) · [Remote observer and privacy settings](../REMOTE-CONTRACT.md) · [Capture limits](../deploy/work-journal.md#incremental-capture)
