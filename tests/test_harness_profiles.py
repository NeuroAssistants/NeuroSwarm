import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent import detector
from backend.validation import sanitize_heartbeat


class HarnessProfileTests(unittest.TestCase):
    def test_inventory_from_profile_through_heartbeat(self):
        with tempfile.TemporaryDirectory() as folder:
            pi = Path(folder) / "pi-private"
            hermes = Path(folder) / "hermes-private"
            specs = [s for s in detector.HARNESS_SPECS if "profile" in s]
            with (patch.dict(os.environ, {"PI_CODING_AGENT_DIR": str(pi), "HERMES_HOME": str(hermes)}),
                  patch.object(detector, "HARNESS_SPECS", specs),
                  patch.object(detector, "_list_safe_processes", return_value=[{"comm": "pi"}, {"comm": "python"}]),
                  patch.object(detector, "_list_running_systemd_units", return_value=[]) as units,
                  patch.object(detector, "_list_running_launchd_labels", return_value=[]),
                  patch.object(detector.shutil, "which", return_value="/bin/mock") as binary):
                def rows():
                    heartbeat = sanitize_heartbeat(detector.collect_host_snapshot())
                    return {h["id"]: h for h in heartbeat["harnesses"]}

                self.assertEqual(rows(), {})
                (pi / "sessions").mkdir(parents=True)
                hermes.mkdir()
                (hermes / "state.db").touch()
                binary.return_value = None
                self.assertEqual({r["status"] for r in rows().values()}, {"configured"})
                binary.return_value = "/bin/mock"
                self.assertEqual(rows()["pi"]["status"], "installed")
                units.return_value = ["hermes-gateway.service-extra"]
                self.assertEqual(rows()["hermes"]["status"], "installed")
                units.return_value = ["hermes-gateway.service"]
                self.assertEqual(rows()["hermes"]["status"], "running")
                self.assertNotIn(folder, str(rows()))
