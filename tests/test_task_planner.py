from __future__ import annotations

import unittest

from omega.task_planner import PLAN_VERSION, TaskPlanError, compile_task_plan


def proposal() -> dict:
    return {
        "steps": [
            {
                "step_id": "summarize",
                "capability": "knowledge.summarize",
                "input": {"source": "step:fetch"},
                "depends_on": ["fetch"],
            },
            {
                "step_id": "fetch",
                "capability": "knowledge.search",
                "input": {"query": "public docs"},
                "depends_on": [],
            },
            {
                "step_id": "classify",
                "capability": "knowledge.classify",
                "input": {"text": "step:summarize"},
                "depends_on": ["summarize"],
            },
        ]
    }


class DeterministicTaskPlannerTests(unittest.TestCase):
    def test_compiles_stable_topological_order(self) -> None:
        result = compile_task_plan(proposal())
        self.assertEqual(result["plan_version"], PLAN_VERSION)
        self.assertEqual(result["execution_order"], ["fetch", "summarize", "classify"])
        self.assertFalse(result["execution_performed"])
        self.assertTrue(result["authorization_required"])

    def test_output_is_independent_of_input_order(self) -> None:
        first = compile_task_plan(proposal())
        reversed_proposal = {"steps": list(reversed(proposal()["steps"]))}
        self.assertEqual(first, compile_task_plan(reversed_proposal))

    def test_rejects_duplicate_missing_and_cyclic_dependencies(self) -> None:
        candidate = proposal()
        candidate["steps"].append(dict(candidate["steps"][0]))
        with self.assertRaisesRegex(TaskPlanError, "PLAN_STEP_ID_DUPLICATE"):
            compile_task_plan(candidate)
        candidate = proposal()
        candidate["steps"][1]["depends_on"] = ["missing"]
        with self.assertRaisesRegex(TaskPlanError, "PLAN_DEPENDENCY_NOT_FOUND"):
            compile_task_plan(candidate)
        candidate = proposal()
        candidate["steps"][1]["depends_on"] = ["classify"]
        with self.assertRaisesRegex(TaskPlanError, "PLAN_CYCLE_DETECTED"):
            compile_task_plan(candidate)

    def test_rejects_unknown_fields_and_invalid_capabilities(self) -> None:
        candidate = proposal()
        candidate["steps"][0]["execute_shell"] = "true"
        with self.assertRaisesRegex(TaskPlanError, "PLAN_STEP_SCHEMA_INVALID"):
            compile_task_plan(candidate)
        candidate = proposal()
        candidate["steps"][0]["capability"] = "../../arbitrary"
        with self.assertRaisesRegex(TaskPlanError, "PLAN_CAPABILITY_INVALID"):
            compile_task_plan(candidate)

    def test_rejects_non_json_inputs_and_excessive_plan_size(self) -> None:
        candidate = proposal()
        candidate["steps"][0]["input"] = {"bad": float("nan")}
        with self.assertRaisesRegex(TaskPlanError, "PLAN_STEP_INPUT_INVALID"):
            compile_task_plan(candidate)
        candidate = {"steps": [
            {"step_id": "step-" + str(i), "capability": "knowledge.search",
             "input": {}, "depends_on": []}
            for i in range(65)
        ]}
        with self.assertRaisesRegex(TaskPlanError, "PLAN_STEP_COUNT_INVALID"):
            compile_task_plan(candidate)


if __name__ == "__main__":
    unittest.main()
