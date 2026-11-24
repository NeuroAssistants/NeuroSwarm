"""Resource databases. Only the directory selects organization IDs; host IDs never select a database."""

from __future__ import annotations

import tempfile
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path

from auth import AuthManager
from db import Database
from guardrails import GuardrailEngine
from remote_activity import ensure_remote_activity_table


class TenantResources:
    def __init__(self, db: Database, org_id: int):
        self.org_id = org_id
        self.db = db
        self.auth = AuthManager(db, org_id)
        self.guardrails = GuardrailEngine(db)
        self.last_prune = 0.0
        ensure_remote_activity_table(db)

    def maybe_prune(self, retention: float, interval: float) -> None:
        now = time.time()
        if now - self.last_prune >= interval:
            self.db.prune_events(now - retention)
            self.last_prune = now


class ResourceStores:
    """Keep one shared connection per active tenant and a bounded set of idle connections."""

    def __init__(self, primary: Database):
        self.primary = TenantResources(primary, 1)
        self.temp = tempfile.TemporaryDirectory() if str(primary.db_path) == ":memory:" else None
        self.base = Path(self.temp.name) if self.temp else Path(str(primary.db_path) + ".tenants")
        self.lock = threading.Lock()
        self.active: dict[int, tuple[TenantResources, int]] = {}
        self.idle: OrderedDict[int, TenantResources] = OrderedDict()

    @contextmanager
    def open(self, org_id: int, existing_only: bool = False):
        if org_id == 1:
            yield self.primary
            return
        path = self.base / f"{org_id}.sqlite3"
        with self.lock:
            resources, count = self.active.get(org_id, (None, 0))
            if resources is None:
                resources = self.idle.pop(org_id, None)
            if resources is None and (not existing_only or path.is_file()):
                self.base.mkdir(mode=0o700, parents=True, exist_ok=True)
                resources = TenantResources(Database(path), org_id)
            if resources is not None:
                self.active[org_id] = resources, count + 1
        try:
            yield resources
        finally:
            if resources is not None:
                with self.lock:
                    _, count = self.active[org_id]
                    if count > 1:
                        self.active[org_id] = resources, count - 1
                    else:
                        del self.active[org_id]
                        self.idle[org_id] = resources
                        if len(self.idle) > 16:
                            self.idle.popitem(last=False)[1].db.close()

    def close(self):
        with self.lock:
            for resources in self.idle.values():
                resources.db.close()
            self.idle.clear()
            self.primary.db.close()
            if self.temp:
                self.temp.cleanup()
