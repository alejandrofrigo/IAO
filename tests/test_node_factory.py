import json
import os
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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

    def test_status_rejects_symlinked_identity_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = create_nodes(1, output_dir=Path(tmp) / "nodes")[0]
            root = Path(node["directory"])
            identity_dir = root / "identity"
            external_identity = Path(tmp) / "external-identity"
            identity_dir.rename(external_identity)
            try:
                identity_dir.symlink_to(external_identity, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            self.assertEqual(inspect_nodes(Path(tmp) / "nodes"), [])

    def test_batch_rolls_back_if_a_later_node_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "nodes"
            generated_key = Ed25519PrivateKey.generate()
            with patch(
                "omega.node_factory.load_or_create_key",
                side_effect=[
                    generated_key,
                    OSError("simulated key storage failure"),
                ],
            ):
                with self.assertRaisesRegex(OSError, "simulated key storage failure"):
                    create_nodes(2, output_dir=output)

            self.assertEqual(inspect_nodes(output), [])
            self.assertEqual(list(output.glob("node-*")), [])
            self.assertEqual(list(output.glob(".staging-*")), [])

    def test_status_ignores_manifest_with_unhashable_role(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = create_nodes(1, output_dir=tmp)[0]
            manifest_path = Path(node["directory"]) / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["role"] = []
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(inspect_nodes(tmp), [])

    def test_status_ignores_valid_json_that_is_not_an_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            nodes = create_nodes(2, output_dir=tmp)
            first_manifest = Path(nodes[0]["directory"]) / "manifest.json"
            second_identity = Path(nodes[1]["directory"]) / "identity/public.json"
            first_manifest.write_text("[]", encoding="utf-8")
            second_identity.write_text("null", encoding="utf-8")
            self.assertEqual(inspect_nodes(tmp), [])

    def test_status_rejects_public_key_fingerprint_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = create_nodes(1, output_dir=tmp)[0]
            identity_path = Path(node["directory"]) / "identity/public.json"
            identity = json.loads(identity_path.read_text())
            identity["public_key"] = "00" * 32
            identity_path.write_text(json.dumps(identity))
            self.assertEqual(inspect_nodes(tmp), [])

    def test_status_ignores_modified_or_incomplete_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = create_nodes(1, output_dir=tmp)[0]
            manifest_path = Path(node["directory"]) / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["authority"] = "ADMIN"
            manifest_path.write_text(json.dumps(manifest))
            self.assertEqual(inspect_nodes(tmp), [])


    def test_create_rejects_non_string_role_without_type_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            for role in ([], {}, None, 1):
                with self.subTest(role=role):
                    with self.assertRaises(NodeFactoryError):
                        create_nodes(1, output_dir=tmp, role=role)

    def test_status_rejects_boolean_schema_and_identity_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            nodes = create_nodes(2, output_dir=tmp)
            first_manifest = Path(nodes[0]["directory"]) / "manifest.json"
            manifest = json.loads(first_manifest.read_text(encoding="utf-8"))
            manifest["schema"] = True
            first_manifest.write_text(json.dumps(manifest), encoding="utf-8")

            second_identity = Path(nodes[1]["directory"]) / "identity/public.json"
            identity = json.loads(second_identity.read_text(encoding="utf-8"))
            identity["version"] = True
            second_identity.write_text(json.dumps(identity), encoding="utf-8")

            self.assertEqual(inspect_nodes(tmp), [])


if __name__ == "__main__":
    unittest.main()
