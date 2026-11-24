# NeuroSwarm Structured Event Integrations

Zero-dependency (Python 3.10+ stdlib) emitters that feed real runtime failure, retry, recovery, and HTTP 429 rate-limit signals into `POST /api/v1/ingest/event` so `LOOP_SUSPECTED` and `QUOTA_EXHAUSTION_BURST` guardrails fire in real agent workloads.

## Security & Non-Interference Guarantees
- **No tokens in argv:** Credentials are loaded from `SWARMCONTROL_TOKEN` (env) or `~/.local/share/swarmcontrol/agent.env` (`SWARMCONTROL_ENV_FILE`).
- **Host-bound token alignment:** `host_id` defaults to `SWARMCONTROL_HOST_ID` or `socket.gethostname()`, matching `agent/detector.py`.
- **Local secret redaction:** Secret-like patterns (`sk-`, `sk-ant-`, `ghp_`, `AKIA`, `xox*`, Bearer tokens) are redacted locally before leaving the host.
- **Fail-open:** Short HTTP timeout (default `2.5s`). If NeuroSwarm is down, hooks still exit `0` with clean stdout and the CLI wrapper preserves the wrapped command's exact exit code (use `--strict` in tests/CI).

## 1. Claude Code Hook (`integrations/claude_code_hook.py`)

Reads Claude Code hook JSON from `stdin` and translates:
- `PostToolUseFailure` (or `PostToolUse` with error) -> `tool_error` with `metadata.task_id`, normalized error signature (strips timestamps/UUIDs/request IDs so loops match reliably), and `metadata.http_status: 429` when a rate limit is detected.
- `PostToolUse` (success) -> `success` (`metadata.progress: true`) to interrupt previous failure streaks on recovery.
- `Notification` / `Stop` / `SubagentStop` -> `rate_limit` (`http_status: 429`) on quota/429 messages, otherwise `info`.

Print a ready-to-merge `~/.claude/settings.json` snippet:
```bash
python3 integrations/claude_code_hook.py --print-settings
```

Test locally without sending anything:
```bash
echo '{"hook_event_name":"PostToolUseFailure","session_id":"s1","tool_name":"Bash","error":"HTTP 429 Too Many Requests"}' \
  | python3 integrations/claude_code_hook.py --dry-run
```

## 2. Generic CLI Wrapper (`integrations/cli_wrapper.py`)

Wraps any CLI agent or worker (`codex`, `claude`, `opencode`, `gemini`, custom scripts), streaming stdout/stderr transparently and preserving the exact exit code:

```bash
export SWARMCONTROL_SERVER="http://127.0.0.1:8790"
export SWARMCONTROL_TOKEN="<agent-token>"

python3 integrations/cli_wrapper.py \
  --harness codex \
  --agent-name worker-1 \
  --task-id pr-42 \
  -- codex exec "fix unit tests"
```

- Non-zero exit -> emits normalized `tool_error` (plus `metadata.http_status: 429` and earlier `retry` events if HTTP 429 lines were observed).
- Exit `0` -> emits `success` (`progress: true`) unless `--errors-only` is passed; still emits `rate_limit` events if 429 retries occurred before recovery.

## Running Integration Tests

Runs entirely against an ephemeral local server (`create_server(port=0)` + temporary SQLite DB; never touches `:8790` or production data):

```bash
python3 -m unittest discover -s integrations/tests -v
```

## Workspace activity

Use **Activity map** to inspect an enrolled host's sessions and **Live events** to follow recorded edits,
reads and commands. Select the project folders to share on the observer. The [capture coverage guide](../docs/capture-coverage.md) lists the available runtimes and which records they provide.

To record a readable plan, start, or result from any enrolled harness, use
the existing event client. Example (local preview; omit the final flag to send):

    python3 integrations/report_work.py plan --agent worker-1 --harness codex --workspace checkout --summary "Check the empty host list" --method "Run the integration suite" --file tests/test_e2e.py --dry-run

Use work_started or work_done for later updates. The task feed shows reports
from the latest 30 fleet events. Only supply details intended for operators.

**Agent work** also lists runtimes detected on the console host and the evidence used to identify each one. The [observer guide](../REMOTE-CONTRACT.md) explains how to see activity from other machines.

To see which test ran after an edit, enable the optional Claude Code hook on the development machine. It links a recorded test result to the edits in the same task, agent session and working-tree revision. [Setup and capture limits](../LINK-CONTRACT.md#edit-verification)
