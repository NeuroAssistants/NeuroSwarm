"""Tenant-local event evidence. Large values are read only after an event is opened."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import zlib

import edit_verification
from validation import MISSION_REPORT_TYPES, public_event_metadata

from activity_inspector import clean_location, clean_url, evidence_text, is_sensitive_path, protected_command

MAX_IMAGE_BYTES = 160 * 1024
WORK_FIELDS = ("session", "parent_session", "workspace", "tool", "action", "basis", "outcome",
               "program", "task_id", "agent", "runtime",
               "evidence_reason", "output_reason", "files_reason", "redaction_reason", "query")
WEB_RESOURCE_STR_LIMITS = {
    "kind": 32,
    "method": 16,
    "url": 512,
    "title": 200,
    "query": 240,
    "status_text": 80,
    "response_excerpt": 2400,
}


def _safe_web_resource(raw):
    """Project an allowlisted, bounded, redacted web/browser resource dict."""
    if not isinstance(raw, dict):
        return None
    out = {}
    for key, limit in WEB_RESOURCE_STR_LIMITS.items():
        val = raw.get(key)
        if not isinstance(val, str) or not val.strip():
            continue
        if key == "url":
            if url := clean_url(val):
                out[key] = url
            continue
        cleaned, _ = evidence_text(val.strip(), limit)
        if not cleaned:
            continue
        out[key] = cleaned
    code = raw.get("status_code")
    if type(code) is int and 100 <= code <= 599:
        out["status_code"] = code
    hops = []
    for hop in raw.get("hops") if isinstance(raw.get("hops"), list) else []:
        if isinstance(hop, dict) and type(hop.get("status_code")) is int and 100 <= hop["status_code"] <= 599:
            clean = {"status_code": hop["status_code"]}
            text, _ = evidence_text(hop.get("status_text"), 80)
            if text and text.strip():
                clean["status_text"] = text.strip()
            if where := clean_location(hop.get("location")):  # masks each secret value, keeps the other parameters
                clean["location"] = where
            hops.append(clean)
    if len(hops) > 1:
        out["hops"] = hops[:10]
    return out or None


SOURCE_POSITION = re.compile(r"[A-Za-z0-9_-]{4,64}:[0-9]{1,12}:[0-9]{1,6}")


def step_reference(host, session, step):
    """Bind a map step to its source position on the same host, in the same session.
    The source timestamp and tool disambiguate reused byte offsets after rotation,
    including when the server corrects clock skew before inserting an event.
    """
    src = step.get("src")
    if not host or not session or not isinstance(src, str) or not SOURCE_POSITION.fullmatch(src):
        return None
    identity = [host, session, src, step.get("time"), step.get("tool")]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode("ascii")).hexdigest()


def link_map_steps(db, organization, snapshot):
    """Attach exact event IDs to lightweight map steps with batched indexed reads.
    Leave the cached source snapshot untouched. Older and as-yet unrecorded steps
    can still open their session, but have no exact journal link.
    """
    pending = {}

    def bind(step, host, session_id):
        ref = step_reference(host, session_id, step)
        if ref is None:
            return step
        copy = dict(step)
        pending.setdefault(ref, []).append(copy)
        return copy

    sessions = []
    for session in snapshot.get("sessions", []):
        host = session.get("host_id") or snapshot.get("host_id")
        session_id = session.get("session_id")
        mapped = dict(session)
        if isinstance(session.get("steps"), list):
            mapped["steps"] = [bind(step, host, session_id) for step in session["steps"]]
        for field in ("latest_action", "latest_work"):
            if isinstance(session.get(field), dict):
                mapped[field] = bind(session[field], host, session_id)
        sessions.append(mapped)
    if not pending:
        return snapshot
    refs = list(pending)
    for start in range(0, len(refs), 400):
        batch = refs[start:start + 400]
        marks = ",".join("?" for _ in batch)
        rows = db.query_all(f"SELECT ref,event_id FROM event_origins WHERE ref IN ({marks})", batch)
        for row in rows:
            for step in pending[row["ref"]]:
                step.update(event_id=row["event_id"], event_org=organization)
    return {**snapshot, "sessions": sessions}


def work_summary(raw, *, include_response=False):
    """Project the public work record. An unrelated large field cannot hide its files."""
    try:
        metadata = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return {}
    if not isinstance(metadata, dict):
        return {}
    work = {key: metadata[key][:256] for key in WORK_FIELDS if isinstance(metadata.get(key), str)}
    files = metadata.get("files")
    if isinstance(files, list):
        work["files"] = []
        for path in files[:12]:
            if not isinstance(path, str) or not path or len(path) > 320:
                continue
            if path.startswith(("/", "\\")) or ":" in path or any(ord(c) < 32 for c in path):
                continue
            path = path.replace("\\", "/")
            if any(not part or part.startswith(".") for part in path.split("/")) or is_sensitive_path(path):
                continue
            work["files"].append(path)
    web_res = _safe_web_resource(metadata.get("web_resource"))
    if web_res:
        if not include_response:
            web_res.pop("response_excerpt", None)
        work["web_resource"] = web_res
    return work


def ensure_tables(conn):
    edit_verification.ensure_tables(conn)
    conn.execute("""CREATE TABLE IF NOT EXISTS event_origins (
        event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE, ref TEXT NOT NULL UNIQUE)""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS delete_event_origin AFTER DELETE ON events BEGIN
        DELETE FROM event_origins WHERE event_id=OLD.id;
        END""")
    conn.execute("""CREATE TABLE IF NOT EXISTS event_execution (
        event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
        command_input TEXT, command_output TEXT, exit_code INTEGER, output_truncated INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS event_images (
        event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        path TEXT NOT NULL, digest TEXT NOT NULL, mime_type TEXT NOT NULL, source TEXT NOT NULL,
        captured_at REAL NOT NULL, content BLOB NOT NULL, PRIMARY KEY (event_id,path))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS event_texts (
        event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        path TEXT NOT NULL, excerpt TEXT NOT NULL, truncated INTEGER NOT NULL, PRIMARY KEY(event_id,path))""")
    # Some older standalone journal connections do not enable SQLite foreign keys.
    conn.execute("""CREATE TRIGGER IF NOT EXISTS delete_event_evidence AFTER DELETE ON events BEGIN
        DELETE FROM event_execution WHERE event_id=OLD.id;
        DELETE FROM event_images WHERE event_id=OLD.id;
        DELETE FROM event_texts WHERE event_id=OLD.id;
        END""")


def _bounded_size(width, height):
    return width > 0 and height > 0 and width * height <= 24_000_000


def image_type(data):
    # Only inert raster formats with plausible dimensions and a complete container.
    if data.startswith(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR") and data.endswith(b"\x00\x00\x00\x00IEND\xaeB`\x82"):
        width, height = int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
        if not _bounded_size(width, height):
            return None
        pos, has_pixels = 8, False
        while pos + 12 <= len(data):
            length = int.from_bytes(data[pos:pos+4], "big")
            end = pos + 8 + length
            if end + 4 > len(data) or zlib.crc32(data[pos+4:end]) != int.from_bytes(data[end:end+4], "big"):
                return None
            chunk = data[pos+4:pos+8]
            if chunk == b"IEND":
                return "image/png" if has_pixels and length == 0 and end+4 == len(data) else None
            has_pixels |= chunk == b"IDAT"
            pos = end + 4
    if len(data) >= 14 and data.startswith((b"GIF87a", b"GIF89a")) and data.endswith(b";"):
        if _bounded_size(int.from_bytes(data[6:8], "little"), int.from_bytes(data[8:10], "little")):
            return "image/gif"
    if len(data) >= 26 and data[:4] == b"RIFF" and data[8:12] == b"WEBP" and int.from_bytes(data[4:8], "little")+8 == len(data):
        kind = data[12:16]
        if kind == b"VP8X" and len(data) >= 30:
            width = 1 + int.from_bytes(data[24:27], "little")
            height = 1 + int.from_bytes(data[27:30], "little")
        elif kind == b"VP8L" and data[20] == 0x2f:
            bits = int.from_bytes(data[21:25], "little")
            width, height = 1+(bits & 0x3fff), 1+((bits >> 14) & 0x3fff)
        elif kind == b"VP8 " and len(data) >= 30 and data[23:26] == b"\x9d\x01\x2a":
            width, height = int.from_bytes(data[26:28], "little") & 0x3fff, int.from_bytes(data[28:30], "little") & 0x3fff
        else:
            return None
        if _bounded_size(width, height):
            return "image/webp"
    if data.startswith(b"\xff\xd8\xff") and data.endswith(b"\xff\xd9"):
        pos = 2
        while pos + 9 < len(data) and data[pos] == 255:
            marker = data[pos + 1]
            if marker == 255:
                pos += 1
                continue
            length = int.from_bytes(data[pos+2:pos+4], "big")
            if length < 2 or pos + 2 + length > len(data) or marker == 0xda:
                break
            if marker in (0xc0, 0xc1, 0xc2) and length >= 8:
                height, width = int.from_bytes(data[pos+5:pos+7], "big"), int.from_bytes(data[pos+7:pos+9], "big")
                return "image/jpeg" if _bounded_size(width, height) else None
            pos += 2 + length
    return None


def complete_recorded_result(conn, step, shared_paths, stamp, ref):
    """A collector can see a call and its tool result on different scans.
    Fill only missing values on that exact recorded step. Never attach results
    to a legacy time match or serve a path absent from the original event.
    """
    results = [item for item in shared_paths if item[1].get("source") == "tool_result"]
    if not ref or (not results and step.get("command_output") is None and type(step.get("exit_code")) is not int):
        return
    row = conn.execute("""SELECT o.event_id,e.metadata_json,x.command_output IS NULL,x.exit_code IS NULL,x.command_input
                          FROM event_origins o JOIN events e ON e.id=o.event_id
                          LEFT JOIN event_execution x ON x.event_id=o.event_id WHERE o.ref=?""", (ref,)).fetchone()
    if row is None:
        return
    if protected_command(row[4]):
        step = {**step, "command_output": None}
    missing_output = row[2] and isinstance(step.get("command_output"), str)
    missing_exit = row[3] and type(step.get("exit_code")) is int
    if not (results or missing_output or missing_exit):
        return
    original = work_summary(row[1])
    if original.get("program") != step.get("program"):
        return
    if results:
        existing = conn.execute("""SELECT 'image_previews',path FROM event_images WHERE event_id=?
                                   UNION ALL SELECT 'text_previews',path FROM event_texts WHERE event_id=?""",
                                (row[0], row[0]))
        recorded = {(field, path) for field, path in existing}
        results = [item for item in results if item[2] in original.get("files", []) and (item[0], item[2]) not in recorded]
    if results or missing_output or missing_exit:
        store(conn, row[0], step, results, stamp)


def store(conn, event_id, step, shared_paths, stamp, ref=None):
    if ref:
        conn.execute("INSERT INTO event_origins(event_id,ref) VALUES(?,?)", (event_id, ref))
    native = step.get("native_call_ref")
    if isinstance(native, str) and edit_verification.DIGEST.fullmatch(native):
        src = step.get("src")
        stream, byte_pos, ordinal = None, None, None
        if isinstance(src, str) and SOURCE_POSITION.fullmatch(src):
            stream, offset, index = src.split(":")
            byte_pos, ordinal = int(offset), int(index)
        conn.execute("""INSERT OR IGNORE INTO verification_calls(event_id,host,session,ref,stream,byte_pos,ordinal)
                        SELECT id,host_id,json_extract(metadata_json,'$.session'),?,?,?,? FROM events WHERE id=?""",
                     (native, stream, byte_pos, ordinal, event_id))
    if step.get("category") in ("shell", "file_read"):
        inp, _ = evidence_text(step.get("command_input"), 1024)
        raw_output = None if protected_command(step.get("command_input")) else step.get("command_output")
        out, cut = evidence_text(raw_output, 4096)
        code = step.get("exit_code")
        if type(code) is not int or not -(2**31) <= code < 2**31:
            code = None
        if inp is not None or out is not None or code is not None:
            conn.execute("""INSERT INTO event_execution VALUES(?,?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET
                command_input=coalesce(command_input,excluded.command_input),
                command_output=coalesce(command_output,excluded.command_output),
                exit_code=coalesce(exit_code,excluded.exit_code),
                output_truncated=CASE WHEN command_output IS NULL THEN excluded.output_truncated ELSE output_truncated END
                WHERE (command_input IS NULL AND excluded.command_input IS NOT NULL)
                   OR (command_output IS NULL AND excluded.command_output IS NOT NULL)
                   OR (exit_code IS NULL AND excluded.exit_code IS NOT NULL)""",
                         (event_id, inp, out, code, cut or step.get("output_truncated") is True))
    for field, preview, display in shared_paths:
        if field == "text_previews":
            if preview.get("source") == "tool_result":
                excerpt, clipped = evidence_text(preview.get("text"), 4096)
                if excerpt is not None:
                    conn.execute("INSERT OR IGNORE INTO event_texts VALUES(?,?,?,?)",
                                 (event_id, display, excerpt, clipped or preview.get("truncated") is True))
            continue
        encoded = preview.get("data_base64")
        if not isinstance(encoded, str) or not 0 < len(encoded) <= 4 * ((MAX_IMAGE_BYTES+2)//3):
            continue
        if preview.get("source") not in ("tool_result", "workspace_snapshot"):
            continue
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            continue
        mime = image_type(data)
        if len(data) > MAX_IMAGE_BYTES or not mime or mime != preview.get("mime_type"):
            continue
        captured = preview.get("captured_at", stamp)
        if type(captured) not in (float, int) or not 0 <= captured <= 253402300799:
            continue
        conn.execute("INSERT OR IGNORE INTO event_images VALUES(?,?,?,?,?,?,?)",
                     (event_id, display, hashlib.sha256(data).hexdigest(), mime, preview["source"], captured, data))


def detail(db, org, event_id):
    event = db.query_one("SELECT id,host_id,harness AS runtime,agent_name AS agent,event_type AS source,"
                         "severity,message,created_at AS ts,metadata_json FROM events WHERE id=?", (event_id,))
    if event is None:
        return None
    metadata = event.pop("metadata_json")
    work = work_summary(metadata, include_response=True) if event["source"] == "observed_step" else {}
    execution = db.query_one("SELECT command_input,command_output,exit_code,output_truncated "
                             "FROM event_execution WHERE event_id=?", (event_id,)) or {}
    images = db.query_all("SELECT path,digest AS sha256,mime_type,source,captured_at,length(content) AS size_bytes "
                          "FROM event_images WHERE event_id=? ORDER BY path", (event_id,))
    texts = db.query_all("SELECT path,excerpt AS text,truncated,'tool_result' AS source FROM event_texts "
                         "WHERE event_id=? ORDER BY path", (event_id,))
    for snippet in texts:
        snippet["truncated"] = bool(snippet["truncated"])
    for image in images:
        image["url"] = f"/api/v1/events/{event_id}/images/{image['sha256']}?organization_id={org}"
    verification = {"verification": edit_verification.for_edit(db, event_id, work)} if work.get("action") == "file_edit" else {}
    extra = {}
    for key in ("evidence_reason", "output_reason", "files_reason", "redaction_reason", "web_resource"):
        if key in work:
            extra[key] = work[key]
    record = {**event, "kind": "Event", "work": work} if work else None
    if event["source"] in MISSION_REPORT_TYPES:
        record = {**event, "kind": "Event", "details": public_event_metadata(event["source"], json.loads(metadata))}
    return {"organization": org, "event_id": event_id, "files": work.get("files", []), **verification, **extra,
            "record": record,
            "workspace": work.get("workspace"), "session": work.get("session"), "program": work.get("program"),
            "command_input": execution.get("command_input"), "command_output": execution.get("command_output"),
            "exit_code": execution.get("exit_code"), "output_truncated": bool(execution.get("output_truncated")),
            "images": images, "text_previews": texts}


def image(db, event_id, digest):
    return db.query_one("SELECT mime_type,content FROM event_images WHERE event_id=? AND digest=? LIMIT 1",
                        (event_id, digest))
