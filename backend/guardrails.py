"""Passive early-warning guardrail engine, secret redaction, and swarm digest builder."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from db import Database
import incidents


RATE_LIMIT_MESSAGE = re.compile(
    r"(?i)\b(?:HTTP(?:/\d+(?:\.\d+)?)?\s+(?:status\s+)?429\b|429\s+too\s+many\s+requests\b)"
)


SECRET_PATTERNS = [
    # Anthropic first: the generic sk- pattern would otherwise classify sk-ant-* keys as OpenAI.
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b")),
    ("generic_bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{24,}")),
]


def redact_secrets(text: str) -> tuple[str, list[str]]:
    """Replace secret-like patterns with redacted markers and report matched types."""
    found: list[str] = []
    redacted = text
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(redacted):
            found.append(name)
            redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    return redacted, found


class GuardrailEngine:
    """Evaluates heartbeats and agent events without interfering with agent execution."""

    def __init__(
        self,
        db: Database,
        cpu_warn_pct: float = 85.0,
        mem_warn_mb: float = 2048.0,
        proc_storm_count: int = 40,
        loop_window_sec: int = 300,
        loop_repeat_threshold: int = 4,
        quota_window_sec: int = 300,
        quota_burst_threshold: int = 3,
        stale_host_sec: int = 90,
    ) -> None:
        self.db = db
        self.cpu_warn_pct = cpu_warn_pct
        self.mem_warn_mb = mem_warn_mb
        self.proc_storm_count = proc_storm_count
        self.loop_window_sec = loop_window_sec
        self.loop_repeat_threshold = loop_repeat_threshold
        self.quota_window_sec = quota_window_sec
        self.quota_burst_threshold = quota_burst_threshold
        self.stale_host_sec = stale_host_sec

    def evaluate_heartbeat(self, payload: dict[str, Any], *, measured=None) -> tuple[str, list[dict[str, Any]]]:
        """Inspect host telemetry and raise early-warning alerts when thresholds trip."""
        host_id = payload["host_id"]
        hostname = payload.get("hostname", host_id)
        processes = payload.get("processes", [])
        mem_total_mb = float(payload.get("mem_total_mb", 0.0))
        mem_used_mb = float(payload.get("mem_used_mb", 0.0))
        triggered: list[dict[str, Any]] = []

        # 1. Runaway CPU check on agent processes
        hot_procs = [p for p in processes if float(p.get("cpu_pct", 0.0)) >= self.cpu_warn_pct]
        if hot_procs:
            top = max(hot_procs, key=lambda p: float(p.get("cpu_pct", 0.0)))
            alert_id = self.db.upsert_open_alert(
                host_id=host_id,
                rule_code="RUNAWAY_CPU",
                severity="WARNING",
                title=f"High agent CPU on {hostname}",
                summary=(
                    f"Process '{top.get('comm')}' (PID {top.get('pid')}) reached "
                    f"{float(top.get('cpu_pct', 0)):.1f}% CPU (threshold {self.cpu_warn_pct:.0f}%)."
                ),
                evidence={"process": top, "hot_count": len(hot_procs)},
            )
            triggered.append({"id": alert_id, "rule_code": "RUNAWAY_CPU", "severity": "WARNING"})

        # 2. Agent memory spike check
        heavy_procs = [p for p in processes if float(p.get("rss_mb", 0.0)) >= self.mem_warn_mb]
        if heavy_procs:
            top = max(heavy_procs, key=lambda p: float(p.get("rss_mb", 0.0)))
            alert_id = self.db.upsert_open_alert(
                host_id=host_id,
                rule_code="MEMORY_SPIKE",
                severity="WARNING",
                title=f"High agent memory footprint on {hostname}",
                summary=(
                    f"Process '{top.get('comm')}' (PID {top.get('pid')}) uses "
                    f"{float(top.get('rss_mb', 0)):.0f} MB RSS (threshold {self.mem_warn_mb:.0f} MB)."
                ),
                evidence={"process": top},
            )
            triggered.append({"id": alert_id, "rule_code": "MEMORY_SPIKE", "severity": "WARNING"})

        # 3. Host RAM pressure check (>90%)
        if mem_total_mb > 0 and (mem_used_mb / mem_total_mb) >= 0.90:
            pct = (mem_used_mb / mem_total_mb) * 100.0
            alert_id = self.db.upsert_open_alert(
                host_id=host_id,
                rule_code="HOST_RAM_PRESSURE",
                severity="CRITICAL",
                title=f"Host memory critical on {hostname}",
                summary=f"Host RAM utilization reached {pct:.1f}% ({mem_used_mb:.0f}/{mem_total_mb:.0f} MB).",
                evidence={"mem_used_mb": mem_used_mb, "mem_total_mb": mem_total_mb},
            )
            triggered.append({"id": alert_id, "rule_code": "HOST_RAM_PRESSURE", "severity": "CRITICAL"})

        # 4. Process storm check (too many concurrent agent processes)
        if len(processes) >= self.proc_storm_count:
            alert_id = self.db.upsert_open_alert(
                host_id=host_id,
                rule_code="PROCESS_STORM",
                severity="WARNING",
                title=f"Agent process storm on {hostname}",
                summary=(
                    f"Detected {len(processes)} concurrent harness/agent processes "
                    f"(threshold {self.proc_storm_count}). Check for runaway subagent spawning."
                ),
                evidence={"process_count": len(processes)},
            )
            triggered.append({"id": alert_id, "rule_code": "PROCESS_STORM", "severity": "WARNING"})

        # Sanitizing a sparse heartbeat fills absent metrics with zeros. Only a supplied
        # measurement can prove recovery. Each rule evaluates its own sensor coverage.
        raw = measured if measured is not None else payload
        recovery = {}
        if mem_total_mb > 0 and raw.get("mem_used_mb") not in (None, "") and float(raw["mem_used_mb"]) >= 0:
            if mem_used_mb / mem_total_mb < 0.90:
                recovery["HOST_RAM_PRESSURE"] = {"mem_used_mb": mem_used_mb, "mem_total_mb": mem_total_mb}
        if isinstance(raw.get("processes"), list):
            if len(processes) < self.proc_storm_count:
                recovery["PROCESS_STORM"] = {"process_count": len(processes), "threshold": self.proc_storm_count}
            for rule, metric, threshold, label in (
                ("RUNAWAY_CPU", "cpu_pct", self.cpu_warn_pct, "max_cpu_pct"),
                ("MEMORY_SPIKE", "rss_mb", self.mem_warn_mb, "max_rss_mb"),
            ):
                if all(p.get(metric) not in (None, "") and float(p[metric]) >= 0 for p in raw["processes"]):
                    maximum = max((float(p[metric]) for p in processes), default=0.0)
                    if maximum < threshold:
                        recovery[rule] = {label: maximum, "threshold": threshold}
        self._recover(host_id, recovery, "measurement_recovered")
        status = self._compute_host_status(host_id)
        return status, triggered

    def evaluate_event(self, payload: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Sanitize incoming agent event, persist it, and evaluate loop/quota/secret guardrails."""
        host_id = payload["host_id"]
        harness = str(payload.get("harness", "unknown"))[:64]
        agent_name = str(payload.get("agent_name", "unknown"))[:128]
        event_type = str(payload.get("event_type", "info"))[:64]
        severity = str(payload.get("severity", "INFO")).upper()[:16]
        raw_message = str(payload.get("message", ""))[:1000]
        raw_meta = payload.get("metadata", {})
        if not isinstance(raw_meta, dict):
            raw_meta = {}

        # Always redact secret-like tokens BEFORE writing anything to SQLite
        safe_message, found_in_msg = redact_secrets(raw_message)
        meta_str = json.dumps(raw_meta)
        safe_meta_str, found_in_meta = redact_secrets(meta_str)
        found_secrets = sorted(set(found_in_msg + found_in_meta))

        now = time.time()
        event_id = self.db.execute(
            """
            INSERT INTO events(host_id, harness, agent_name, event_type, severity, message, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (host_id, harness, agent_name, event_type, severity, safe_message, safe_meta_str, now),
        )

        triggered: list[dict[str, Any]] = []

        # Guardrail A: Secret exposure signal
        if found_secrets:
            alert_id = self.db.upsert_open_alert(
                host_id=host_id,
                rule_code="SECRET_EXPOSURE_SIGNAL",
                severity="CRITICAL",
                title=f"Secret-like pattern redacted from {agent_name}",
                summary=(
                    f"Redacted pattern(s) {', '.join(found_secrets)} from {harness}/{agent_name} "
                    f"telemetry before storage. Inspect host secret hygiene."
                ),
                evidence={"patterns": found_secrets, "harness": harness, "agent_name": agent_name, "event_id": event_id},
            )
            triggered.append({"id": alert_id, "rule_code": "SECRET_EXPOSURE_SIGNAL", "severity": "CRITICAL"})

        # Repetition alone is expected for batches and successful polling.
        cnt = self._stall_streak(
            host_id, harness, agent_name, event_type, safe_message, safe_meta_str, event_id, now
        )
        if cnt >= self.loop_repeat_threshold:
            alert_id = self.db.upsert_open_alert(
                host_id=host_id,
                rule_code="LOOP_SUSPECTED",
                severity="CRITICAL",
                title=f"Possible agent loop in {agent_name}",
                summary=(
                    f"{harness}/{agent_name} repeated '{event_type}' at least {cnt} times in "
                    f"{self.loop_window_sec}s with identical signature."
                ),
                evidence={"agent_name": agent_name, "harness": harness, "count": cnt, "event_id": event_id},
            )
            triggered.append({"id": alert_id, "rule_code": "LOOP_SUSPECTED", "severity": "CRITICAL"})

        # Guardrail C: Quota / 429 burst across agents on the host
        if (
            event_type in {"quota_429", "rate_limit"}
            or raw_meta.get("http_status") in (429, "429")
            or RATE_LIMIT_MESSAGE.search(safe_message)
        ):
            cutoff_quota = now - self.quota_window_sec
            q_row = self.db.query_one(
                """
                SELECT COUNT(*) AS cnt, COUNT(DISTINCT agent_name) AS agents
                FROM events
                WHERE host_id = ? AND created_at >= ? AND (
                    event_type IN ('quota_429', 'rate_limit')
                    OR json_extract(metadata_json, '$.http_status') IN (429, '429')
                    OR (instr(message, '429') > 0 AND message REGEXP ?)
                )
                """,
                (host_id, cutoff_quota, RATE_LIMIT_MESSAGE.pattern),
            )
            if q_row and int(q_row["cnt"]) >= self.quota_burst_threshold:
                alert_id = self.db.upsert_open_alert(
                    host_id=host_id,
                    rule_code="QUOTA_EXHAUSTION_BURST",
                    severity="WARNING",
                    title=f"Provider quota/429 burst on {host_id}",
                    summary=(
                        f"{q_row['cnt']} rate-limit events across {q_row['agents']} agent(s) "
                        f"in the last {self.quota_window_sec // 60} min."
                    ),
                    evidence={"count": q_row["cnt"], "affected_agents": q_row["agents"], "event_id": event_id},
                )
                triggered.append({"id": alert_id, "rule_code": "QUOTA_EXHAUSTION_BURST", "severity": "WARNING"})

        new_status = self._compute_host_status(host_id)
        self.db.execute("UPDATE hosts SET status = ? WHERE host_id = ?", (new_status, host_id))
        return {"event_id": event_id, "redacted_patterns": found_secrets}, triggered

    def _stall_streak(
        self, host_id: str, harness: str, agent: str, kind: str, message: str,
        metadata_json: str, event_id: int, now: float,
    ) -> int:
        """Count consecutive matching failures, or tool calls explicitly marked as stalled."""
        if kind == "tool_call":
            if json.loads(metadata_json).get("progress") is not False:
                return 0
        elif kind not in {"error", "tool_error", "loop_signal", "retry"}:
            return 0
        recent = self.db.query_all(
            """SELECT event_type, message, json_type(metadata_json, '$.progress') AS progress_type FROM events
               WHERE host_id = ? AND harness = ? AND agent_name = ? AND created_at >= ? AND id <= ?
                 AND json_extract(metadata_json, '$.task_id') IS json_extract(?, '$.task_id')
               ORDER BY id DESC LIMIT ?""",
            (host_id, harness, agent, now - self.loop_window_sec, event_id, metadata_json, self.loop_repeat_threshold),
        )
        count = 0
        for row in recent:
            if (row["event_type"], row["message"]) != (kind, message):
                break
            if kind == "tool_call" and row["progress_type"] != "false":
                break
            count += 1
        return count

    def _recover(self, host_id, measured, reason):
        if not measured:
            return
        with self.db.transaction():
            active = self.db.query_all(
                f"SELECT id,host_id,status,rule_code FROM incident_cases WHERE host_id=? AND {incidents.ACTIVE}", (host_id,))
            for case in active:
                if case["rule_code"] in measured:
                    incidents.resolve(self.db, case, "system", reason, measured[case["rule_code"]])

    def resolve_stale(self, host_id: str) -> None:
        self._recover(host_id, {"STALE_HOST_HEARTBEAT": {"last_heartbeat_at": time.time()}}, "heartbeat_resumed")

    def check_stale_hosts(self) -> None:
        # Polling dashboards must not manufacture additional observations of one missed heartbeat.
        cutoff = time.time() - self.stale_host_sec
        sql = f"""SELECT host_id,hostname,last_seen_at FROM hosts h WHERE last_seen_at<? AND NOT EXISTS
                  (SELECT 1 FROM incident_cases a WHERE a.host_id=h.host_id
                   AND a.rule_code='STALE_HOST_HEARTBEAT' AND ({incidents.ACTIVE} OR a.resolved_at>=h.last_seen_at))"""
        if not self.db.query_one(sql + " LIMIT 1", (cutoff,)):
            return
        # Recheck after acquiring the writer. A heartbeat can arrive in between.
        with self.db.transaction():
            stale = self.db.query_all(sql, (cutoff,))
            for h in stale:
                age_s = int(time.time() - float(h["last_seen_at"]))
                self.db.upsert_open_alert(
                    host_id=h["host_id"], rule_code="STALE_HOST_HEARTBEAT", severity="WARNING",
                    title=f"Host heartbeat stale: {h['hostname']}",
                    summary=f"No telemetry received from {h['hostname']} for {age_s}s.",
                    evidence={"age_seconds": age_s, "last_heartbeat_at": h["last_seen_at"]},
                )
                self.db.execute("UPDATE hosts SET status='DEGRADED' WHERE host_id=?", (h["host_id"],))

    def _compute_host_status(self, host_id: str) -> str:
        open_alerts = self.db.query_all(
            f"SELECT severity FROM incident_cases WHERE host_id = ? AND {incidents.ACTIVE}",
            (host_id,),
        )
        severities = {a["severity"] for a in open_alerts}
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "WARNING" in severities:
            return "WARNING"
        return "HEALTHY"

    def build_executive_digest(self) -> dict[str, Any]:
        """Compress fleet telemetry and open alerts into a concise human-readable briefing."""
        self.check_stale_hosts()
        hosts = self.db.query_all("SELECT * FROM hosts ORDER BY last_seen_at DESC")
        active = self.db.query_all(f"SELECT * FROM incident_cases WHERE {incidents.ACTIVE} ORDER BY updated_at DESC")
        open_alerts = [a for a in active if a["status"] == "OPEN"]

        total_hosts = len(hosts)
        total_agent_procs = 0
        running_harnesses: set[str] = set()
        installed_harnesses: set[str] = set()
        total_agent_rss_mb = 0.0
        max_scan_ms = 0.0

        for h in hosts:
            procs = json.loads(h.get("processes_json") or "[]")
            harnesses = json.loads(h.get("harnesses_json") or "[]")
            total_agent_procs += len(procs)
            total_agent_rss_mb += float(h.get("agent_rss_mb") or 0.0)
            max_scan_ms = max(max_scan_ms, float(h.get("scan_duration_ms") or 0.0))
            for hr in harnesses:
                if hr.get("status") in {"running", "installed"}:
                    installed_harnesses.add(hr.get("name", "unknown"))
                if hr.get("status") == "running":
                    running_harnesses.add(hr.get("name", "unknown"))

        crit_count = sum(1 for a in open_alerts if a["severity"] == "CRITICAL")
        warn_count = sum(1 for a in open_alerts if a["severity"] == "WARNING")
        if any(a["severity"] == "CRITICAL" for a in active):
            fleet_status = "CRITICAL"
        elif any(a["severity"] == "WARNING" for a in active):
            fleet_status = "WARNING"
        elif total_hosts == 0:
            fleet_status = "WAITING"
        else:
            fleet_status = "HEALTHY"

        bullets: list[str] = []
        if total_hosts == 0:
            headline = "No remote hosts enrolled yet. Install the lightweight observer agent to start monitoring."
        else:
            harness_list = ", ".join(sorted(running_harnesses)) if running_harnesses else "none active"
            headline = (
                f"{total_hosts} host(s) reporting · {total_agent_procs} agent process(es) observed · "
                f"Active harnesses: {harness_list} · {len(active)} active incident(s), "
                f"{len(open_alerts)} awaiting acknowledgement."
            )
            bullets.append(
                f"Observer overhead: total monitor RSS {total_agent_rss_mb:.1f} MB, "
                f"max scan time {max_scan_ms:.1f} ms (passive read-only mode)."
            )
            if active:
                for a in active[:4]:
                    bullets.append(f"[{a['severity']} · {a['status']}] {a['title']}: {a['summary']}")
            else:
                bullets.append("No anomalous loops, runaway CPU/RAM, quota bursts, or secret leaks detected.")

        return {
            "generated_at": time.time(),
            "fleet_status": fleet_status,
            "headline": headline,
            "bullets": bullets,
            "metrics": {
                "hosts": total_hosts,
                "active_agent_processes": total_agent_procs,
                "running_harnesses": sorted(running_harnesses),
                "installed_harnesses": sorted(installed_harnesses),
                "open_alerts": len(open_alerts),
                "active_incidents": len(active),
                "critical_alerts": crit_count,
                "warning_alerts": warn_count,
                "observer_max_scan_ms": round(max_scan_ms, 2),
            },
        }
