"""Passive, non-intrusive cross-platform auto-detector for AI agent harnesses.

Supports:
- Linux & WSL (`/proc/meminfo`, `ps`, `systemctl`, `/proc/<pid>/cwd`)
- macOS (`sysctl hw.memsize`, `vm_stat`, `ps`, `launchctl`, `lsof -a -p <pid> -d cwd`)
- Windows (`ctypes.windll.kernel32.GlobalMemoryStatusEx`, `tasklist /FO CSV /NH`)

Security & zero-interference guarantees:
- Read-only inspection only; never kills, signals, or modifies agent processes.
- Never reads command-line flags, environment variables, .env files, or secret vaults.
- Uses process basenames, verified executables, and configurable workspace labels (no hardcoded team names).
"""

from __future__ import annotations

import csv
import ctypes
import io
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any


HARNESS_SPECS = [
    {
        "id": "openbot",
        "name": "OpenBot",
        "bins": ["openbot"],
        "proc_names": ["openbot", "openbot.exe", "cua-driver", "cua-driver.exe"],
        "dirs": ["/opt/OpenBot", "~/.config/OpenBot", "~/OpenBot"],
        "runtime_keys": [],
        "systemd_prefixes": ["openbot.service"],
        "launchd_labels": ["ai.openbot", "com.openbot"],
    },
    {
        "id": "codex",
        "name": "Codex CLI",
        "bins": ["codex"],
        "proc_names": ["codex", "codex.exe", "codex-code-mode"],
        "dirs": ["~/.codex"],
        "runtime_keys": ["codex"],
        "systemd_prefixes": [],
        "launchd_labels": [],
    },
    {
        "id": "claude-code",
        "name": "Claude Code CLI",
        "bins": ["claude"],
        "proc_names": ["claude", "claude.exe"],
        "dirs": ["~/.claude"],
        "runtime_keys": ["claude", "claude-code"],
        "systemd_prefixes": [],
        "launchd_labels": [],
    },
    {
        "id": "opencode",
        "name": "OpenCode",
        "bins": ["opencode"],
        "proc_names": ["opencode", "opencode.exe"],
        "dirs": ["~/.opencode", "~/.local/share/opencode"],
        "runtime_keys": ["opencode"],
        "systemd_prefixes": ["openbot-opencode"],
        "launchd_labels": [],
    },
    {
        "id": "antigravity-gemini",
        "name": "Gemini / Antigravity",
        "bins": ["gemini", "agy"],
        "proc_names": ["gemini", "gemini.exe", "antigravity", "antigravity.exe"],
        "dirs": ["~/.gemini"],
        "runtime_keys": ["antigravity", "gemini"],
        "systemd_prefixes": [],
        "launchd_labels": [],
    },
    {
        "id": "openclaw",
        "name": "OpenClaw",
        "bins": ["openclaw"],
        "proc_names": ["openclaw", "openclaw.exe"],
        "dirs": ["~/.openclaw"],
        "runtime_keys": ["openclaw"],
        "systemd_prefixes": ["openclaw"],
        "launchd_labels": [],
    },
    {
        "id": "paperclip",
        "name": "Paperclip",
        "bins": ["paperclip"],
        "proc_names": ["paperclip", "paperclip.exe"],
        "dirs": ["~/.paperclip"],
        "runtime_keys": ["paperclip"],
        "systemd_prefixes": ["paperclip"],
        "launchd_labels": [],
    },
    {
        "id": "pi",
        "name": "Pi Coding Agent",
        "bins": [],
        "proc_names": [],
        "dirs": [],
        "runtime_keys": [],
        "systemd_prefixes": [],
        "profile": ("PI_CODING_AGENT_DIR", "~/.pi/agent", "sessions", "directory", "pi"),
    },
    {
        "id": "hermes",
        "name": "Hermes Agent",
        "bins": [],
        "proc_names": [],
        "dirs": [],
        "runtime_keys": [],
        "systemd_prefixes": [],
        "profile": ("HERMES_HOME", "~/.hermes", "state.db", "file", "hermes"),
        "systemd_unit": "hermes-gateway.service",
    },
    {
        "id": "cursor",
        "name": "Cursor Agent",
        "bins": ["cursor", "cursor-agent"],
        "proc_names": ["cursor", "cursor.exe", "cursor-agent", "cursor-agent.exe"],
        "dirs": ["~/.cursor"],
        "runtime_keys": ["cursor"],
        "systemd_prefixes": [],
        "launchd_labels": [],
    },
    {
        "id": "ollama",
        "name": "Ollama Local LLM",
        "bins": ["ollama"],
        "proc_names": ["ollama", "ollama.exe"],
        "dirs": ["~/.ollama"],
        "runtime_keys": [],
        "systemd_prefixes": ["ollama.service"],
        "launchd_labels": ["com.ollama.ollama"],
    },
]


def _safe_expand(path_str: str) -> Path:
    return Path(os.path.expanduser(path_str))


def detect_os_platform() -> str:
    """Return normalized OS label: 'linux', 'wsl', 'darwin', or 'windows'."""
    sys_name = platform.system().lower()
    if sys_name == "linux":
        try:
            rel = platform.release().lower()
            if "microsoft" in rel or "wsl" in rel or Path("/proc/sys/fs/binfmt_misc/WSLInterop").exists():
                return "wsl"
        except Exception:
            pass
        return "linux"
    if sys_name == "darwin":
        return "darwin"
    if sys_name.startswith("win"):
        return "windows"
    return sys_name or "unknown"


def _read_linux_mem_mb() -> tuple[float, float]:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return 0.0, 0.0
    vals: dict[str, int] = {}
    for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(":"):
            try:
                vals[parts[0][:-1]] = int(parts[1])
            except ValueError:
                pass
    total_kb = vals.get("MemTotal", 0)
    avail_kb = vals.get("MemAvailable", vals.get("MemFree", 0))
    total_mb = total_kb / 1024.0
    used_mb = max(0.0, (total_kb - avail_kb) / 1024.0)
    return round(total_mb, 1), round(used_mb, 1)


def _read_macos_mem_mb() -> tuple[float, float]:
    total_mb = 0.0
    used_mb = 0.0
    try:
        out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, timeout=2, stderr=subprocess.DEVNULL)
        total_mb = int(out.strip()) / (1024.0 * 1024.0)
    except Exception:
        return 0.0, 0.0
    try:
        vm = subprocess.check_output(["vm_stat"], text=True, timeout=2, stderr=subprocess.DEVNULL)
        page_size = 4096
        m_ps = re.search(r"page size of (\d+) bytes", vm)
        if m_ps:
            page_size = int(m_ps.group(1))
        pages: dict[str, int] = {}
        for line in vm.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                num_str = v.strip().rstrip(".")
                if num_str.isdigit():
                    pages[k.strip().lower()] = int(num_str)
        active = (
            pages.get("pages active", 0)
            + pages.get("pages wired down", 0)
            + pages.get("pages occupied by compressor", 0)
        )
        used_mb = min(total_mb, (active * page_size) / (1024.0 * 1024.0))
    except Exception:
        pass
    return round(total_mb, 1), round(used_mb, 1)


def _read_windows_mem_mb() -> tuple[float, float]:
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    try:
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):  # type: ignore[attr-defined]
            total_mb = stat.ullTotalPhys / (1024.0 * 1024.0)
            avail_mb = stat.ullAvailPhys / (1024.0 * 1024.0)
            return round(total_mb, 1), round(max(0.0, total_mb - avail_mb), 1)
    except Exception:
        pass
    return 0.0, 0.0


def _read_host_mem_mb() -> tuple[float, float]:
    sys_name = platform.system().lower()
    if sys_name == "linux":
        return _read_linux_mem_mb()
    if sys_name == "darwin":
        return _read_macos_mem_mb()
    if sys_name.startswith("win"):
        return _read_windows_mem_mb()
    return 0.0, 0.0


def _read_self_rss_mb() -> float:
    status_file = Path("/proc/self/status")
    if status_file.exists():
        for line in status_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("VmRSS:"):
                parts = line.split()
                if len(parts) >= 2:
                    return round(int(parts[1]) / 1024.0, 2)
    try:
        import resource

        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if platform.system().lower() == "darwin":
            return round(rss / (1024.0 * 1024.0), 2)
        return round(rss / 1024.0, 2)
    except Exception:
        return 0.0


def _parse_etime(etime_str: str) -> int:
    """Parse POSIX ps etime ([dd-]hh:mm:ss or mm:ss) into seconds."""
    s = etime_str.strip()
    if s.isdigit():
        return int(s)
    days = 0
    if "-" in s:
        d_part, s = s.split("-", 1)
        days = int(d_part) if d_part.isdigit() else 0
    parts = [int(p) for p in s.split(":") if p.isdigit()]
    if len(parts) == 3:
        return days * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]
    if len(parts) == 2:
        return days * 86400 + parts[0] * 60 + parts[1]
    return 0


def _list_windows_processes() -> list[dict[str, Any]]:
    try:
        out = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"],
            text=True,
            timeout=4,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return []
    procs: list[dict[str, Any]] = []
    reader = csv.reader(io.StringIO(out))
    for row in reader:
        if len(row) < 5:
            continue
        try:
            comm = Path(row[0].strip()).name
            pid = int(row[1].strip())
            mem_digits = re.sub(r"[^0-9]", "", row[4])
            rss_mb = round(int(mem_digits) / 1024.0, 1) if mem_digits else 0.0
            procs.append(
                {
                    "pid": pid,
                    "user": os.environ.get("USERNAME", "windows"),
                    "comm": comm,
                    "cpu_pct": 0.0,
                    "rss_mb": rss_mb,
                    "uptime_sec": 0,
                }
            )
        except ValueError:
            continue
    return procs


def _list_safe_processes() -> list[dict[str, Any]]:
    """Read process basenames and resource metrics across Linux, macOS, and Windows."""
    if platform.system().lower().startswith("win"):
        return _list_windows_processes()

    # Try Linux `etimes=` first, fallback to POSIX/macOS `etime=`
    out = ""
    for fmt in ("pid=,user=,comm=,pcpu=,rss=,etimes=", "pid=,user=,comm=,pcpu=,rss=,etime="):
        try:
            out = subprocess.check_output(
                ["ps", "-eo", fmt],
                text=True,
                timeout=3,
                stderr=subprocess.DEVNULL,
            )
            if out:
                break
        except Exception:
            continue
    if not out:
        return []

    procs: list[dict[str, Any]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            pid = int(parts[0])
            user = parts[1]
            # On macOS `comm` can be a full path `/usr/local/bin/codex`; take basename only
            comm = Path(parts[2]).name
            cpu_pct = float(parts[3])
            rss_mb = round(int(parts[4]) / 1024.0, 1)
            uptime_sec = _parse_etime(parts[5])
        except ValueError:
            continue
        procs.append(
            {
                "pid": pid,
                "user": user,
                "comm": comm,
                "cpu_pct": cpu_pct,
                "rss_mb": rss_mb,
                "uptime_sec": uptime_sec,
            }
        )
    return procs


def _list_running_systemd_units() -> list[str]:
    if shutil.which("systemctl"):
        try:
            out = subprocess.check_output(
                ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"],
                text=True,
                timeout=3,
                stderr=subprocess.DEVNULL,
            )
            return [line.split()[0] for line in out.splitlines() if line.split()]
        except Exception:
            return []
    return []


def _list_running_launchd_labels() -> list[str]:
    if platform.system().lower() == "darwin" and shutil.which("launchctl"):
        try:
            out = subprocess.check_output(
                ["launchctl", "list"],
                text=True,
                timeout=3,
                stderr=subprocess.DEVNULL,
            )
            labels = []
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[0].isdigit():
                    labels.append(parts[2])
            return labels
        except Exception:
            return []
    return []


def _managed_installations(root: Path) -> dict[str, list[str]]:
    """Record executable versions, never inferring installation from an empty provider folder."""
    found: dict[str, list[str]] = {}
    if not root.is_dir():
        return found
    for spec in HARNESS_SPECS:
        for provider in spec["runtime_keys"]:
            for binary_name in dict.fromkeys([provider, *spec["bins"]]):
                pattern = f"{provider}/*/*/bin/{binary_name}"
                for exe in root.glob(pattern):
                    version = exe.parents[1].name
                    arch = exe.parents[2].name
                    if (
                        re.fullmatch(r"[0-9][A-Za-z0-9.+_-]{0,39}", version)
                        and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", arch)
                        and exe.is_file()
                        and os.access(exe, os.X_OK)
                    ):
                        found.setdefault(spec["id"], []).append(f"managed:{exe.relative_to(root)}")
    return found


def _configured_workspace_roots() -> tuple[Path, ...]:
    """Return configured activity/workspace roots plus optional OpenBot roots if present."""
    roots: list[Path] = []
    env_roots = os.environ.get("SWARMCONTROL_ACTIVITY_ROOTS", "").strip()
    if env_roots:
        sep = os.pathsep
        for item in env_roots.split(sep):
            for sub in item.split(","):
                s = sub.strip()
                if s:
                    roots.append(_safe_expand(s))

    unique: list[Path] = []
    seen: set[str] = set()
    for r in roots:
        key = str(r)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return tuple(unique)


def _workspace_label(cwd: Path, root: Path) -> str | None:
    """Emit a portable workspace label, supporting both OpenBot and generic project folders."""
    try:
        parts = cwd.relative_to(root).parts
    except ValueError:
        return None
    if ".." in parts:
        return None
    if len(parts) >= 2 and parts[0] == "Agents" and re.fullmatch(
        r"agent-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", parts[1]
    ):
        return "/".join(parts[:2])
    if len(parts) >= 2 and parts[0] == "Shared":
        return "/".join(parts[:2])
    # Generic customer project root configured via SWARMCONTROL_ACTIVITY_ROOTS
    if root.name not in {"OpenBot", "/"} and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", root.name):
        if len(parts) >= 1 and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", parts[0]):
            return f"{root.name}/{parts[0]}"
        return root.name
    return None


def _process_workspace(pid: int, roots: tuple[Path, ...]) -> str | None:
    cwd: Path | None = None
    try:
        if Path("/proc").is_dir():
            cwd = Path(os.readlink(f"/proc/{pid}/cwd"))
        elif platform.system().lower() == "darwin" and shutil.which("lsof"):
            out = subprocess.check_output(
                ["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
                text=True,
                timeout=1.5,
                stderr=subprocess.DEVNULL,
            )
            for ln in out.splitlines():
                if ln.startswith("n/"):
                    cwd = Path(ln[1:])
                    break
    except (OSError, subprocess.SubprocessError):
        cwd = None
    if cwd is None:
        return None
    for root in roots:
        label = _workspace_label(cwd, root)
        if label:
            return label
    return None


def _count_openbot_workspaces() -> int:
    for base in [Path(os.environ.get("SWARMCONTROL_OPENBOT_ROOT") or Path.home() / "OpenBot") / "Agents"]:
        if base.is_dir():
            try:
                return sum(1 for e in base.iterdir() if e.is_dir() and e.name.startswith("agent-"))
            except PermissionError:
                pass
    return 0


def collect_host_snapshot(agent_version: str = "0.3.0", host_id: str | None = None) -> dict[str, Any]:
    """Collect a low-overhead, read-only cross-platform host and harness telemetry snapshot."""
    t0 = time.perf_counter()
    hostname = socket.gethostname()
    resolved_host_id = host_id or hostname
    all_procs = _list_safe_processes()
    running_units = _list_running_systemd_units()
    launchd_labels = _list_running_launchd_labels()
    config = Path(os.environ.get("SWARMCONTROL_OPENBOT_CONFIG") or Path.home() / ".config/OpenBot")
    managed = _managed_installations(config / "provider-runtimes")
    workspace_roots = _configured_workspace_roots()
    openbot_agents_count = _count_openbot_workspaces()

    detected_harnesses: list[dict[str, Any]] = []
    matched_procs: list[dict[str, Any]] = []
    seen_pids: set[int] = set()

    for spec in HARNESS_SPECS:
        evidence: list[str] = sorted(set(managed.get(spec["id"], ())), reverse=True)[:4]
        if "profile" in spec:
            env_name, default_root, marker, kind, command = spec["profile"]
            root = _safe_expand(os.environ.get(env_name) or default_root)
            path = root / marker
            present = path.is_dir() if kind == "directory" else path.is_file()
            if present:
                evidence.append(f"profile:{marker}")
                if shutil.which(command):
                    evidence.append(f"bin:{command}")
        if spec.get("systemd_unit") in running_units:
            evidence.append(f"service:{spec['systemd_unit']}")
        for b in spec["bins"]:
            found = shutil.which(b)
            if found:
                evidence.append(f"bin:{found}")
        for d in spec["dirs"]:
            p = _safe_expand(d)
            if p.exists():
                evidence.append(f"dir:{p}")
        for pref in spec["systemd_prefixes"]:
            for u in running_units:
                if u.startswith(pref):
                    evidence.append(f"service:{u}")
        for lbl in spec.get("launchd_labels", []):
            for active_lbl in launchd_labels:
                if active_lbl.startswith(lbl):
                    evidence.append(f"service:{active_lbl}")

        spec_proc_names = {n.lower() for n in spec["proc_names"]}
        h_procs = [p for p in all_procs if p["comm"].lower() in spec_proc_names]
        for p in h_procs:
            if p["pid"] not in seen_pids:
                seen_pids.add(p["pid"])
                match = {**p, "harness": spec["id"]}
                workspace = _process_workspace(p["pid"], workspace_roots)
                if workspace:
                    match["workspace"] = workspace
                matched_procs.append(match)

        if evidence or h_procs:
            total_cpu = round(sum(p["cpu_pct"] for p in h_procs), 2)
            total_rss = round(sum(p["rss_mb"] for p in h_procs), 1)
            status = "configured"
            if any(e.startswith(("bin:", "managed:")) for e in evidence):
                status = "installed"
            if h_procs or any(e.startswith("service:") for e in evidence):
                status = "running"
            entry: dict[str, Any] = {
                "id": spec["id"],
                "name": spec["name"],
                "status": status,
                "process_count": len(h_procs),
                "cpu_pct": total_cpu,
                "rss_mb": total_rss,
                "evidence": list(dict.fromkeys(evidence))[:8],
            }
            if spec["id"] == "openbot" and openbot_agents_count > 0:
                entry["workspace_agents"] = openbot_agents_count
            detected_harnesses.append(entry)

    try:
        load_1m = round(os.getloadavg()[0], 2)
    except (AttributeError, OSError):
        load_1m = 0.0

    mem_total_mb, mem_used_mb = _read_host_mem_mb()
    scan_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    return {
        "host_id": resolved_host_id,
        "hostname": hostname,
        "os_name": detect_os_platform(),
        "arch": platform.machine() or "unknown",
        "agent_version": agent_version,
        "cpu_count": os.cpu_count() or 1,
        "load_1m": load_1m,
        "mem_total_mb": mem_total_mb,
        "mem_used_mb": mem_used_mb,
        "agent_rss_mb": _read_self_rss_mb(),
        "scan_duration_ms": scan_ms,
        "harnesses": detected_harnesses,
        "processes": sorted(matched_procs, key=lambda x: (-x["cpu_pct"], -x["rss_mb"]))[:50],
        "collected_at": time.time(),
    }


if __name__ == "__main__":
    import json

    print(json.dumps(collect_host_snapshot(), indent=2))
