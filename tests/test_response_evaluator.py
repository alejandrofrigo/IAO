import unittest

from omega.response_evaluator import ResponseEvaluationError, evaluate_response


class ResponseEvaluationTests(unittest.TestCase):
    def test_structural_completeness_and_matched_citation(self):
        result = evaluate_response(
            "Alpha result [source-1]",
            required_claims=["Alpha result"],
            evidence_refs=["source-1"],
            require_citations=True,
        )
        self.assertEqual(result["status"], "STRUCTURALLY_COMPLETE")
        self.assertFalse(result["truth_verified"])
        self.assertFalse(result["authoritative"])

    def test_missing_claim_and_unmatched_citation_are_not_accepted(self):
        result = evaluate_response(
            "Other statement [unknown]",
            required_claims=["required claim"],
            evidence_refs=["known"],
            require_citations=True,
        )
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["missing_claims"], ["required claim"])
        self.assertEqual(result["unmatched_citations"], ["unknown"])

    def test_empty_oversized_and_invalid_requirements_fail_closed(self):
        for value in ("", "   ", "x" * 100):
            with self.subTest(value_length=len(value)):
                with self.assertRaises(ResponseEvaluationError):
                    evaluate_response(value, max_bytes=10)
        with self.assertRaises(ResponseEvaluationError):
            evaluate_response("ok", required_claims=["x"] * 65)


if __name__ == "__main__":
    unittest.main()
