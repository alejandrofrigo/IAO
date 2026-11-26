import unittest

try:
    from pydantic import ValidationError

    from omega.contracts import IntentContract, ToolContract
    HAVE = True
except ImportError:
    HAVE = False


@unittest.skipUnless(HAVE, "pydantic not installed (offline sandbox)")
class ContractTests(unittest.TestCase):
    def test_rejects_bad_risk_class(self) -> None:
        with self.assertRaises(ValidationError):
            IntentContract(intent_id="i", goal="g", allowed_capabilities=[], risk_class="R9",  # type: ignore[arg-type]
                           budget_seconds=10, termination_condition="t")

    def test_tool_name_pattern(self) -> None:
        with self.assertRaises(ValidationError):
            ToolContract(name="Bad Name", version="1", side_effects="none",
                         required_capabilities=[], timeout_seconds=5)
