"""A fresh source checkout must keep locally generated private state out of Git."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("git"), "Git is required to test checkout exclusions")
class DistributionStateTests(unittest.TestCase):
    def test_source_files_remain_visible_and_local_state_is_private(self):
        private = {
            "data/application-cache", "data/swarmcontrol.db-wal",
            "custom/db/swarmcontrol-initial-password-example", "custom/initial-password",
            "custom/session.key", "custom/app.env", "custom/.env.local",
            "observer/capture_offsets.json", "observer/.capture_offsets.json.123.tmp",
            "observer/pending_activity_queue.json", "observer/.pending_activity_queue.json.123.tmp",
        }
        public = {"README.md", "deploy/start_console.py", "docs/example.json", ".env.example"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
            # Ensure this check is independent of the caller's checkout.
            for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
                env.pop(name, None)
            subprocess.run(["git", "init", "-q"], cwd=root, env=env, check=True)
            shutil.copyfile(ROOT / ".gitignore", root / ".gitignore")
            for name in private | public:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            result = subprocess.check_output(
                ["git", "-c", "core.excludesFile=" + os.devnull, "ls-files",
                 "--others", "--exclude-standard", "-z"], cwd=root, env=env,
            )
            visible = {os.fsdecode(path) for path in result.split(b"\0") if path}
            self.assertEqual(visible, public | {".gitignore"})
