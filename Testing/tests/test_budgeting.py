import unittest

from Testing.harness.budgeting import evaluate_budget_status, evaluate_projected_experiment_budget


class BudgetingBehaviorTests(unittest.TestCase):
    def test_run_estimated_cost_threshold_is_advisory_by_default(self) -> None:
        status = evaluate_budget_status(
            {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "relative_cost_index": 0.0,
                "estimated_cost_usd": 2.0,
            },
            {"max_run_estimated_cost_usd": 1.5},
            scope="run",
        )

        self.assertTrue(status["ok"])
        self.assertFalse(status["warnings_ok"])
        self.assertEqual(status["hard_exceeded"], [])
        self.assertEqual(len(status["warnings"]), 1)
        self.assertIn("max_run_estimated_cost_usd", status["warnings"][0])

    def test_run_estimated_cost_hard_limit_can_fail(self) -> None:
        status = evaluate_budget_status(
            {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "relative_cost_index": 0.0,
                "estimated_cost_usd": 2.0,
            },
            {"hard_max_run_estimated_cost_usd": 1.5},
            scope="run",
        )

        self.assertFalse(status["ok"])
        self.assertEqual(status["warnings"], [])
        self.assertEqual(len(status["hard_exceeded"]), 1)
        self.assertIn("hard_max_run_estimated_cost_usd", status["hard_exceeded"][0])

    def test_projected_estimated_cost_threshold_is_advisory_by_default(self) -> None:
        status = evaluate_projected_experiment_budget(
            {
                "projected_relative_cost_index": 0.0,
                "projected_estimated_cost_usd": 10.0,
            },
            {"max_experiment_estimated_cost_usd": 6.0},
        )

        self.assertTrue(status["ok"])
        self.assertEqual(status["hard_exceeded"], [])
        self.assertEqual(len(status["warnings"]), 1)
        self.assertIn("projected_estimated_cost_usd", status["warnings"][0])

    def test_projected_hard_estimated_cost_limit_can_fail(self) -> None:
        status = evaluate_projected_experiment_budget(
            {
                "projected_relative_cost_index": 0.0,
                "projected_estimated_cost_usd": 10.0,
            },
            {"hard_max_experiment_estimated_cost_usd": 6.0},
        )

        self.assertFalse(status["ok"])
        self.assertEqual(status["warnings"], [])
        self.assertEqual(len(status["hard_exceeded"]), 1)
        self.assertIn("hard_projected_estimated_cost_usd", status["hard_exceeded"][0])


if __name__ == "__main__":
    unittest.main()
