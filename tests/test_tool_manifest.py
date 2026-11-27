import unittest

from omega.tools.registry import ToolRegistry, ToolSpec


def make_spec(**overrides):
    values = {
        "name": "knowledge.search",
        "version": "1.0.0",
        "scope": "knowledge.read",
        "effect_class": "READ_ONLY",
        "timeout_seconds": 5,
        "validate_input": lambda value: value,
        "run": lambda value: value,
        "verify": lambda value: "PASS",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
        "provenance": "built-in:knowledge",
    }
    values.update(overrides)
    return ToolSpec(**values)


class ToolManifestTests(unittest.TestCase):
    def test_manifest_is_stable_and_never_exposes_executable_callables(self):
        registry = ToolRegistry()
        registry.register(make_spec())
        manifest = registry.manifest()
        self.assertEqual(manifest[0]["capability"], "knowledge.search")
        self.assertEqual(manifest[0]["effect_class"], "READ_ONLY")
        self.assertEqual(manifest[0]["input_schema"]["required"], ["query"])
        self.assertFalse(manifest[0]["executable"])
        self.assertNotIn("run", manifest[0])
        self.assertEqual(manifest, registry.manifest())

    def test_registration_rejects_invalid_limits_and_schemas(self):
        for patch in (
            {"timeout_seconds": float("inf")},
            {"effect_class": "UNRESTRICTED"},
            {"name": "Invalid Capability"},
            {"input_schema": {"bad": object()}},
            {"input_schema": {"type": "object", "required": ["missing"], "properties": {}}},
            {"input_schema": {"type": "string", "properties": {}}},
            {"input_schema": {"type": "object", "properties": {"query": {"type": "string", "minLength": 9, "maxLength": 2}}}},
            {"input_schema": {"type": "object", "properties": {"nested": {"type": "object", "unknownKeyword": True}}}},
        ):
            with self.subTest(patch=patch):
                registry = ToolRegistry()
                with self.assertRaises(ValueError):
                    registry.register(make_spec(**patch))


if __name__ == "__main__":
    unittest.main()



def test_schema_validator_rejects_unsupported_and_unbounded_array_shapes():
    for schema in (
        {"type": "array"},
        {"type": "array", "items": {"type": "integer", "minimum": float("inf")}},
        {"type": "object", "additionalProperties": "arbitrary"},
    ):
        with unittest.TestCase().assertRaises(ValueError):
            registry = ToolRegistry()
            registry.register(make_spec(input_schema=schema))
