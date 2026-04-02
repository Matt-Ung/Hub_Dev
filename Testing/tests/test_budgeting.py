import unittest

from Testing.harness.budgeting import resolve_budget_config


class BudgetingTests(unittest.TestCase):
    def test_budget_guardrails_disabled_by_default(self) -> None:
        config = resolve_budget_config()

        self.assertFalse(config["budget_guardrails_enabled"])
        self.assertFalse(config["abort_on_run_budget_exceeded"])
        self.assertFalse(config["abort_experiment_on_budget_exceeded"])
        self.assertIsNone(config["max_run_total_tokens"])
        self.assertIsNone(config["max_run_relative_cost_index"])
        self.assertIsNone(config["max_experiment_estimated_cost_usd"])

    def test_budget_guardrails_can_be_enabled_explicitly(self) -> None:
        config = resolve_budget_config(enable_budget_guardrails=True)

        self.assertTrue(config["budget_guardrails_enabled"])
        self.assertTrue(config["abort_on_run_budget_exceeded"])
        self.assertTrue(config["abort_experiment_on_budget_exceeded"])
        self.assertEqual(config["max_run_total_tokens"], 550000)
        self.assertEqual(config["max_run_relative_cost_index"], 3500.0)
        self.assertEqual(config["max_experiment_estimated_cost_usd"], 75.0)


if __name__ == "__main__":
    unittest.main()
