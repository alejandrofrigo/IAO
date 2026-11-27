import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import iao_five_motor_supervisor as supervisor


class FiveMotorP2PIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / "adapters.json"
        self.patch = patch.object(supervisor, "CONFIG", self.config)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_new_supervisor_config_enables_only_quarantined_p2p_discovery(self):
        motors = supervisor.adapters()
        node = motors["NODE_NETWORK"]
        self.assertTrue(node["enabled"])
        self.assertEqual(
            node["command"][-2:],
            ["tools/iao_libp2p_discovery.py", "--run"],
        )
        self.assertIn("PADGE", motors)
        self.assertFalse(motors["GUARDIAN"]["enabled"])
        self.assertFalse(motors["DISTRIBUTED_INTELLIGENCE"]["enabled"])

    def test_existing_operator_node_network_setting_is_preserved(self):
        self.config.write_text(json.dumps({
            "motors": {
                "NODE_NETWORK": {
                    "command": ["custom", "operator-command"],
                    "enabled": False,
                    "group": "operator-defined",
                },
                "PADGE": {"command": [], "enabled": False},
            }
        }))
        motors = supervisor.adapters()
        self.assertFalse(motors["NODE_NETWORK"]["enabled"])
        self.assertEqual(
            motors["NODE_NETWORK"]["command"],
            ["custom", "operator-command"],
        )


if __name__ == "__main__":
    unittest.main()
