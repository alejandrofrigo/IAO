import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import iao_five_motor_supervisor as supervisor


class FiveMotorDiscoveryAdapterTests(unittest.TestCase):
    def test_missing_node_network_adapter_is_migrated_to_public_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "adapters.json"
            config.write_text(json.dumps({
                "motors": {
                    "PADGE": {"command": [], "enabled": False}
                }
            }), encoding="utf-8")
            with patch.object(supervisor, "CONFIG", config):
                motors = supervisor.adapters()
            self.assertTrue(motors["NODE_NETWORK"]["enabled"])
            self.assertEqual(
                motors["NODE_NETWORK"]["command"],
                [
                    supervisor.sys.executable,
                    "-m",
                    "omega.federation_discovery",
                    "--run",
                ],
            )
            self.assertIn("SIN CONFIANZA", motors["NODE_NETWORK"]["group"])

    def test_explicitly_disabled_node_network_adapter_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "adapters.json"
            disabled = {"command": [], "enabled": False, "group": "operator-disabled"}
            config.write_text(json.dumps({"motors": {"NODE_NETWORK": disabled}}), encoding="utf-8")
            with patch.object(supervisor, "CONFIG", config):
                motors = supervisor.adapters()
            self.assertEqual(motors["NODE_NETWORK"], disabled)

    def test_python_module_adapter_validation_resolves_discovery_module(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec("omega.federation_discovery"))


if __name__ == "__main__":
    unittest.main()
