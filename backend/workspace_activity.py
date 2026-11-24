"""Compare local source-file metadata across dashboard reads. Keep a bounded in-memory window."""
from collections import deque
import os
from pathlib import Path
import stat
from threading import Lock
import time

SOURCE_TYPES = {
    "agent": {".py"}, "backend": {".py"}, "deploy": {".md", ".py", ".service"},
    "frontend": {".js", ".css", ".html"}, "integrations": {".md", ".py"},
    "integrations/tests": {".py"}, "tests": {".py"},
}


class WorkspaceActivity:
    def __init__(self, root: Path):
        self.root = root
        self.previous = None
        self.history = deque(maxlen=24)
        self.lock = Lock()
        self.started = None

    def sample(self):
        with self.lock:
            previous = self.previous or {}
            current = {}
            unavailable = []
            for folder, suffixes in SOURCE_TYPES.items():
                prefix = folder + "/"
                path = self.root / folder
                try:
                    # A symlinked source directory must not extend the observation root.
                    if path.resolve() != path or not stat.S_ISDIR(path.stat().st_mode):
                        raise OSError("Source directory unavailable")
                    with os.scandir(path) as items:
                        for item in items:
                            if item.name.startswith(".") or Path(item.name).suffix not in suffixes:
                                continue
                            name = prefix + item.name
                            try:
                                info = item.stat(follow_symlinks=False)
                            except FileNotFoundError:
                                continue
                            if stat.S_ISREG(info.st_mode):
                                current[name] = (info.st_mtime_ns, info.st_size)
                except FileNotFoundError:
                    continue
                except OSError:
                    unavailable.append(folder)
                    current.update((name, sig) for name, sig in previous.items()
                                   if name.rpartition("/")[0] == folder)
            now = time.time()
            if self.previous is None:
                self.started = now
            else:
                for name in sorted(current.keys() | previous.keys()):
                    if previous.get(name) == current.get(name):
                        continue
                    change = "appeared" if name not in previous else "missing" if name not in current else "updated"
                    self.history.appendleft({"path": name, "change": change, "observed": now})
            self.previous = current
            files = sorted(({"path": name, "modified": sig[0] / 1e9} for name, sig in current.items()),
                           key=lambda f: (-f["modified"], f["path"]))
            folders = []
            for folder in SOURCE_TYPES:
                children = [f for f in files if f["path"].rpartition("/")[0] == folder]
                if children:
                    folders.append({"path": folder, "total": len(children), "recent": children[:5]})
            return {"files": files[:10], "folders": folders, "changes": list(self.history),
                    "since": self.started, "sampled": now, "unavailable": unavailable}
