from __future__ import annotations

import unittest

from omega.task_contract import (
    CONTRACT_VERSION,
    TaskContractError,
    validate_task_intent_v1,
)


def valid_intent() -> dict:
    return {
        "contract_version": CONTRACT_VERSION,
        "goal": "Read public knowledge",
        "allowed_capabilities": ["knowledge.search"],
        "authorized_scopes": ["knowledge.search"],
        "input": {"query": "IAO architecture"},
        "request_digest": "sha256:" + "a" * 64,
        "operator_session_digest": None,
        "operator_device_id": None,
        "risk_class": "R0",
        "budget": {"max_model_calls": 0, "timeout_seconds": 20},
        "termination_condition": "result or terminal error",
        "policy_version": "policy-v1:test",
        "expires_at": "2026-11-27T21:00:00+00:00",
    }


class TaskIntentContractTests(unittest.TestCase):
    def test_accepts_and_detaches_valid_v1_intent(self) -> None:
        source = valid_intent()
        result = validate_task_intent_v1(source)
        result["input"]["query"] = "mutated"
        self.assertEqual(source["input"]["query"], "IAO architecture")

    def test_rejects_unknown_or_missing_fields(self) -> None:
        for mutate in (
            lambda item: item.pop("policy_version"),
            lambda item: item.update({"admin": True}),
        ):
            candidate = valid_intent()
            mutate(candidate)
            with self.subTest(candidate=candidate):
                with self.assertRaises(TaskContractError):
                    validate_task_intent_v1(candidate)

    def test_rejects_unsupported_version_and_risk_class(self) -> None:
        for key, value in (("contract_version", "2.0"), ("risk_class", "R9")):
            candidate = valid_intent()
            candidate[key] = value
            with self.subTest(key=key):
                with self.assertRaises(TaskContractError):
                    validate_task_intent_v1(candidate)

    def test_rejects_oversized_or_non_json_input(self) -> None:
        candidate = valid_intent()
        candidate["input"] = {"blob": "x" * (49 * 1024)}
        with self.assertRaisesRegex(TaskContractError, "TASK_INPUT_TOO_LARGE"):
            validate_task_intent_v1(candidate)
        candidate = valid_intent()
        candidate["input"] = {"nan": float("nan")}
        with self.assertRaises(TaskContractError):
            validate_task_intent_v1(candidate)

    def test_rejects_deep_input_and_unbounded_budget(self) -> None:
        candidate = valid_intent()
        nested = {}
        cursor = nested
        for _ in range(14):
            cursor["x"] = {}
            cursor = cursor["x"]
        candidate["input"] = nested
        with self.assertRaises(TaskContractError):
            validate_task_intent_v1(candidate)
        candidate = valid_intent()
        candidate["budget"]["timeout_seconds"] = 301
        with self.assertRaisesRegex(TaskContractError, "TASK_BUDGET_INVALID"):
            validate_task_intent_v1(candidate)

    def test_rejects_naive_expiry_and_malformed_digest(self) -> None:
        candidate = valid_intent()
        candidate["expires_at"] = "2026-11-27T21:00:00"
        with self.assertRaisesRegex(TaskContractError, "TASK_EXPIRY_INVALID"):
            validate_task_intent_v1(candidate)
        candidate = valid_intent()
        candidate["request_digest"] = "not-a-digest"
        with self.assertRaisesRegex(TaskContractError, "TASK_REQUEST_DIGEST_INVALID"):
            validate_task_intent_v1(candidate)


if __name__ == "__main__":
    unittest.main()
