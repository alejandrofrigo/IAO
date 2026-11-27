import unittest

from omega.model_comparison import ModelComparisonError, compare_model_candidates


class ModelComparisonTests(unittest.TestCase):
    def test_comparison_is_deterministic_and_preserves_disagreement(self):
        candidates = [
            {"provider_id": "zeta", "model_id": "m2", "response": "alpha beta"},
            {"provider_id": "alpha", "model_id": "m1", "response": "alpha"},
        ]
        result = compare_model_candidates(candidates, required_claims=["alpha", "beta"])
        self.assertEqual([x["provider_id"] for x in result["ranking"]], ["zeta", "alpha"])
        self.assertIn("RESPONSES_DIFFER", result["disagreements"])
        self.assertIsNone(result["selection"])
        self.assertFalse(result["authority_granted"])

    def test_comparison_rejects_duplicate_provider_and_bad_candidate(self):
        candidate = {"provider_id": "same", "model_id": "m", "response": "x"}
        with self.assertRaises(ModelComparisonError):
            compare_model_candidates([candidate, candidate])
        with self.assertRaises(ModelComparisonError):
            compare_model_candidates([{"provider_id": "p"}])


if __name__ == "__main__":
    unittest.main()
