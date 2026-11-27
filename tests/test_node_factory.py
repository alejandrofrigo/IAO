import json
import os
import tempfile
import unittest
from pathlib import Path

from omega.node_factory import (
    NodeFactoryError,
    create_nodes,
    inspect_nodes,
)


class NodeFactoryTests(unittest.TestCase):
    def test_creates_independent_unenrolled_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            nodes = create_nodes(3, output_dir=Path(tmp) / "nodes")
            self.assertEqual(len(nodes), 3)
            self.assertEqual(len({n["node_id"] for n in nodes}), 3)
            self.assertEqual({n["status"] for n in nodes}, {"CREATED_UNENROLLED"})
            self.assertEqual(len(inspect_nodes(Path(tmp) / "nodes")), 3)
            for node in nodes:
                root = Path(node["directory"])
                manifest = json.loads((root / "manifest.json").read_text())
                identity = json.loads((root / "identity/public.json").read_text())
                self.assertEqual(manifest["authority"], "NONE")
                self.assertEqual(manifest["capabilities"], [])
                self.assertIsNone(manifest["endpoint"])
                self.assertEqual(identity["node_id"], node["node_id"])
                self.assertTrue((root / "identity/private.key").is_file())
                self.assertNotIn("private", json.dumps(manifest).lower())
                if os.name == "posix":
                    self.assertEqual(
                        (root / "identity/private.key").stat().st_mode & 0o777,
                        0o600,
                    )

    def test_refuses_invalid_batch_sizes_and_roles(self):
        with tempfile.TemporaryDirectory() as tmp:
            for count in (0, 11, True):
                with self.subTest(count=count):
                    with self.assertRaises(NodeFactoryError):
                        create_nodes(count, output_dir=tmp)
            with self.assertRaises(NodeFactoryError):
                create_nodes(1, output_dir=tmp, role="administrator")

    def test_refuses_symlink_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / "target"
            target.mkdir()
            link = base / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaises(NodeFactoryError):
                create_nodes(1, output_dir=link)

    def test_status_ignores_modified_or_incomplete_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = create_nodes(1, output_dir=tmp)[0]
            manifest_path = Path(node["directory"]) / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["authority"] = "ADMIN"
            manifest_path.write_text(json.dumps(manifest))
            self.assertEqual(inspect_nodes(tmp), [])


if __name__ == "__main__":
    unittest.main()
