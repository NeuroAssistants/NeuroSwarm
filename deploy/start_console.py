"""Start a self-hosted instance with stable private bootstrap credentials."""
import os
import secrets
import sys
from pathlib import Path


def main():
    os.umask(0o077)
    root = Path(os.environ.get("SWARMCONTROL_STATE_DIR", "/data"))
    root.mkdir(parents=True, exist_ok=True)
    for filename, env in (("session.key", "SWARMCONTROL_SESSION_SECRET"),
                          ("initial-password", "SWARMCONTROL_ADMIN_PASS")):
        if env in os.environ:
            continue
        path = root / filename
        if not path.exists():
            with path.open("x") as out:
                out.write(secrets.token_urlsafe(32) + "\n")
        os.environ[env] = path.read_text().strip()
        if not os.environ[env]:
            raise SystemExit(f"Empty credential file: {path}")
    os.environ.setdefault("SWARMCONTROL_DB", str(root / "swarmcontrol.db"))
    server = Path(__file__).resolve().parents[1] / "backend/server.py"
    os.execv(sys.executable, [sys.executable, str(server)])


if __name__ == "__main__":
    main()
