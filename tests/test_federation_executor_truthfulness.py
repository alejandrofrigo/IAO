import importlib.util
from pathlib import Path
import unittest

MODULE_PATH = Path("tools/iao_federation_external_executor.py")
SPEC = importlib.util.spec_from_file_location(
    "iao_federation_external_executor_test", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

summarize = MODULE.summarize_exchange_results


def verified_item(peer_id):
    return {
        "peer_id": peer_id,
        "status": "RESPONSE_VERIFIED",
        "response_ok": True,
        "response_digest": "a" * 64,
    }


class ExecutorTruthfulnessTests(unittest.TestCase):
    def test_empty_results_never_claim_completion(self):
        result = summarize([])
        self.assertEqual(result["status"], "NO_VERIFIED_EXCHANGES")
        self.assertEqual(result["verified_exchanges"], 0)

    def test_failed_attempts_never_count_as_verified(self):
        result = summarize([
            {"status": "CONNECTION_OR_TASK_FAILED"},
            {"status": "REMOTE_OR_VERIFICATION_FAILURE"},
        ])
        self.assertEqual(result["status"], "NO_VERIFIED_EXCHANGES")
        self.assertEqual(result["attempted_exchanges"], 2)
        self.assertEqual(result["failed_exchanges"], 2)

    def test_partial_success_is_reported_as_partial(self):
        result = summarize([
            verified_item("peer-a"),
            {"status": "CONNECTION_OR_TASK_FAILED"},
        ])
        self.assertEqual(result["status"], "PARTIAL_VERIFIED_EXCHANGES")
        self.assertEqual(result["verified_exchanges"], 1)
        self.assertEqual(result["failed_exchanges"], 1)

    def test_all_attempted_exchanges_verified(self):
        result = summarize([
            verified_item("peer-a"),
            {"status": "LEASE_EXPIRED"},
        ])
        self.assertEqual(result["status"], "VERIFIED_EXCHANGES_COMPLETED")
        self.assertEqual(result["verified_exchanges"], 1)
        self.assertEqual(result["skipped_peer_records"], 1)

    def test_invalid_digest_does_not_count_as_evidence(self):
        item = verified_item("peer-a")
        item["response_digest"] = "not-a-sha256"
        result = summarize([item])
        self.assertEqual(result["status"], "NO_VERIFIED_EXCHANGES")
        self.assertEqual(result["verified_exchanges"], 0)

    def test_response_ok_must_be_true(self):
        item = verified_item("peer-a")
        item["response_ok"] = False
        result = summarize([item])
        self.assertEqual(result["status"], "NO_VERIFIED_EXCHANGES")


if __name__ == "__main__":
    unittest.main()
