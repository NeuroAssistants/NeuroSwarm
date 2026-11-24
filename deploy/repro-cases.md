# Reproducible cases from failed sessions

Open **Reproducible cases** (`#repro-cases`) on the console overview to turn a recorded session failure into a minimal, redacted test case and compare manual verification runs against the original baseline.

> **Manual execution only:** NeuroSwarm never runs commands or shell snippets extracted from agent logs. Exported commands and outputs remain inert redacted text for an operator to review and execute manually in an appropriate local environment.

## Convert a failed session

1. Failed sessions and errors appear under **Failed sessions** when telemetry records:
   - a non-zero `exit_code`,
   - an `observed_step` with `ERROR`/`CRITICAL` severity or a failing `outcome` (`failed`, `error`, `timeout`, `crashed`), or
   - an explicit failure event (`test_failed`, `tool_error`, `command_failed`, `session_failed`, `build_failed`, `run_failed`, `error`).
2. Select **Convert to repro case** on a failed session.
3. Review or complete the case title, optional code revision (commit SHA, tag, or branch), manual command, expected result, and operator notes, then select **Save repro case**.

Each saved case captures only minimal redacted context: host identifier, runtime harness, agent name, session ID, workspace label (absolute host prefixes stripped), sanitized relative file paths, explicit revision when recorded (otherwise `null` / `Not recorded`), redacted command, expected result, baseline exit code and bounded observed output, plus up to five preceding session steps.

## Privacy and missing-field rules

- **Secret redaction and path masking:** API tokens, passwords, inline secret assignments, authorization headers, PEM private keys, and sensitive file paths (such as `.env` or SSH/key files) are redacted before persistence and before export. Commands that read credential files or dump environment variables suppress captured command output automatically (`output_suppressed_reason: protected_command`).
- **Missing collector options:** When a host collector runs without `SWARMCONTROL_SHARE_COMMANDS=1` or `SWARMCONTROL_SHARE_COMMAND_OUTPUT=1`, or when no revision metadata was recorded, those fields stay explicitly `null` (`Not recorded`) rather than being guessed.

## Export and compare a new run

1. Select a saved case and export a redacted bundle via **Export JSON** (`GET /api/v1/repro-cases/<id>/export?format=json`) or **Export Markdown** (`format=markdown`). Both bundles include `execution_mode: "manual_only"`.
2. Execute the verified reproduction steps manually on your target environment.
3. Select **Record new run**, enter the observed status (`passed`, `failed`, or `inconclusive`), optional exit code, tested revision, command used, output excerpt, and notes, then select **Save run & compare**.

NeuroSwarm compares each new run deterministically against the baseline failure:

| Verdict | Meaning |
| --- | --- |
| `Fixed` | Run status is `passed` with exit code `0` (or omitted). |
| `Still failing` | Run failed with matching baseline exit code and normalized output. |
| `Changed failure` | Run still failed, with a different exit code or changed output excerpt. |
| `Inconclusive` | Operator marked `inconclusive`, or marked `passed` alongside a non-zero exit code. |

The comparison panel displays outcome, revision, exit code, and command side by side along with a unified text diff between the baseline failure output and the new run.

## Permissions and API routes

| Request | Role required | What it does |
| --- | --- | --- |
| `GET /api/v1/repro-cases` | Viewer, Operator, Admin, or `read` token | Lists detected failed sessions and saved cases for the active organization. |
| `GET /api/v1/repro-cases/<id>` | Viewer, Operator, Admin, or `read` token | Returns full redacted case details, baseline, runs, and comparisons (`404` if missing or another organization). |
| `GET /api/v1/repro-cases/<id>/export?format=json\|markdown` | Viewer, Operator, Admin, or `read` token | Downloads a redacted `manual_only` bundle (`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`). |
| `POST /api/v1/repro-cases` | Operator or Admin session (same-origin CSRF checked) | Converts a failed session event into a saved repro case and writes an audit hash-chain entry. |
| `POST /api/v1/repro-cases/<id>/runs` | Operator or Admin session (same-origin CSRF checked) | Records a manual verification run, computes the comparison diff, and writes an audit entry. |

All queries and mutations are isolated per organization (`409` on stale `organization_id`, `404` across tenants, `403` for `viewer`, `read` tokens, or cross-origin mutations).
