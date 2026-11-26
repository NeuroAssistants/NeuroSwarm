"""Output counts and the exact observed steps behind them, within one tenant database."""
from collections import Counter
import hashlib
import re
import time

from validation import ValidationError


STEPS = """
    WITH candidates AS (
        SELECT e.*, CASE WHEN json_valid(metadata_json) THEN metadata_json ELSE '{}' END AS meta
        FROM events e WHERE event_type = 'observed_step' AND created_at >= :start AND created_at < :end
    ), named AS (
        SELECT candidates.*, coalesce(nullif(json_extract(meta, '$.action'), ''), 'unknown') AS action,
               coalesce(nullif(json_extract(meta, '$.program'), ''),
                        nullif(json_extract(meta, '$.tool'), ''), 'unknown') AS name
        FROM candidates
    ), steps AS (
        SELECT named.*, CASE WHEN typeof(name) = 'text' AND length(name) BETWEEN 1 AND 160
                                  AND instr(name, char(0)) = 0
                                  AND name NOT GLOB '*[^-a-zA-Z0-9._:+]*'
                             THEN name ELSE 'unknown' END AS program FROM named
    )
"""
JOIN_EXECUTION = " FROM steps LEFT JOIN event_execution x ON x.event_id = steps.id "
HAS_PREVIEW = """(EXISTS (SELECT 1 FROM event_texts t WHERE t.event_id = steps.id)
               OR EXISTS (SELECT 1 FROM event_images i WHERE i.event_id = steps.id))"""


def coverage(conn, since):
    """The existing CLI report includes all observed steps and counts previews separately."""
    rows = conn.execute(STEPS + f"""
        SELECT action, name AS program, count(*) AS events, count(x.command_output) AS recorded_output,
               sum(CASE WHEN x.command_output = '' THEN 1 ELSE 0 END) AS recorded_empty,
               sum({HAS_PREVIEW}) AS with_file_preview,
               count(*) - count(x.command_output) AS without_recorded_output
        {JOIN_EXECUTION}
        GROUP BY action, name ORDER BY without_recorded_output DESC, action, name
    """, {"start": since, "end": float("inf")})
    columns = [column[0] for column in rows.description]
    return [dict(zip(columns, row)) for row in rows]


PAGE_SIZE = 50
MAX_WINDOW = 31 * 86400
PENDING = {"running", "pending", "in_progress"}
TERMINAL = {"completed", "complete", "done", "success", "succeeded", "passed",
            "error", "failed", "declined", "cancelled", "canceled", "aborted", "timeout", "timed_out"}
MISSING_REASONS = {"capture_disabled", "protected", "outside_scope", "not_recorded"}
BUCKETS = MISSING_REASONS | {"completed", "pending", "unconfirmed", "recorded_output",
                             "empty_output", "missing_output", "file_preview"}


class CoverageChanged(Exception):
    """The selected group has changed since the operator saw its counts."""


def _categories(outcome, has_result, has_output, empty, reason, preview):
    if outcome in PENDING:
        return ("pending",)
    categories = ["completed" if outcome in TERMINAL or has_result or has_output else "unconfirmed"]
    if has_output:
        categories.append("recorded_output")
        if empty:
            categories.append("empty_output")
    else:
        categories.extend(("missing_output", reason if reason in MISSING_REASONS else "not_recorded"))
    if preview:
        categories.append("file_preview")
    return tuple(categories)


def _number(query, key, default, maximum):
    if key not in query:
        return default
    values = query[key]
    if len(values) != 1 or not re.fullmatch(r"[0-9]{1,19}", values[0]) or int(values[0]) > maximum:
        raise ValidationError(f"Invalid {key}")
    return int(values[0])


def report(conn, organization, query):
    """Both views use the same stream of IDs and categories; no output or preview bodies leave SQLite."""
    if ("from_ts" in query) != ("to_ts" in query):
        raise ValidationError("Supply both time bounds")
    end = _number(query, "to_ts", int(time.time()) + 1, 253402300799)
    start = _number(query, "from_ts", end - 3600, 253402300799)
    if not 0 < end - start <= MAX_WINDOW:
        raise ValidationError("Choose a time window of up to 31 days")
    program = query.get("program", [None])[0]
    bucket = query.get("bucket", [None])[0]
    version = query.get("version", [None])[0]
    before = _number(query, "before", None, 2**63 - 1)
    selected = bucket is not None
    if ((program is not None and (not selected or not re.fullmatch(r"[-a-zA-Z0-9._:+]{1,160}", program)))
            or (selected and bucket not in BUCKETS)):
        raise ValidationError("Invalid program or output category")
    if (before is not None or version is not None) and not selected:
        raise ValidationError("A coverage category is required")
    if version is not None and not re.fullmatch(r"[a-f0-9]{32}", version):
        raise ValidationError("Invalid coverage version")

    params = {"start": start, "end": end, "program": program}
    sql = STEPS + f"""
        SELECT steps.id, created_at, host_id, program,
               lower(coalesce(json_extract(meta, '$.outcome'), json_extract(meta, '$.status'), '')),
               x.exit_code IS NOT NULL, x.command_output IS NOT NULL, x.command_output = '',
               coalesce(nullif(json_extract(meta, '$.output_reason'), ''),
                        nullif(json_extract(meta, '$.evidence_reason'), ''), json_extract(meta, '$.redaction_reason')),
               {HAS_PREVIEW}
        {JOIN_EXECUTION}
    """
    if program is not None:
        sql += " WHERE program = :program"
    groups = {None: (Counter(), hashlib.blake2b(digest_size=16))}
    events = []
    for ident, ts, host, name, outcome, result, output, empty, reason, preview in conn.execute(
            sql + " ORDER BY steps.id DESC", params):
        categories = _categories(outcome, result, output, empty, reason, preview)
        # A late result can change a bucket inside a fixed time window. A changed membership
        # invalidates the snapshot instead of opening a different set under the old count.
        membership = f"{ident}:{name}:{','.join(categories)}\n".encode("ascii")
        for group in ((None,) if selected else (None, name)):
            if group not in groups:
                groups[group] = (Counter(), hashlib.blake2b(digest_size=16))
            counts, digest = groups[group]
            counts.update(categories)
            digest.update(membership)
        if selected and bucket in categories and (before is None or ident < before) and len(events) <= PAGE_SIZE:
            events.append({"id": ident, "host": host, "ts": ts, "program": name})

    response = {"organization": organization, "from_ts": start, "to_ts": end}
    totals, revision = groups.pop(None)
    if selected:
        if version is not None and version != revision.hexdigest():
            raise CoverageChanged("Evidence changed in this window. Refresh counts to see the updated events.")
        return {**response, "events": events[:PAGE_SIZE], "count": totals[bucket], "version": revision.hexdigest(),
                "next_before": events[PAGE_SIZE - 1]["id"] if len(events) > PAGE_SIZE else None}
    programs = [{"program": name, "counts": counts, "version": digest.hexdigest()}
                for name, (counts, digest) in groups.items()]
    programs.sort(key=lambda row: (-row["counts"]["missing_output"], str(row["program"])))
    return {**response, "total": {"counts": totals, "version": revision.hexdigest()}, "programs": programs}
