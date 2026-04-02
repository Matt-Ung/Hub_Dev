import unittest

from Testing.harness.experiment_sweep import _annotate_variant_coverage, _run_entry_has_full_task_coverage


class ExperimentCoverageTests(unittest.TestCase):
    def test_run_entry_full_task_coverage_requires_expected_tasks(self) -> None:
        self.assertTrue(
            _run_entry_has_full_task_coverage(
                {"aggregate": {"sample_count": 4, "expected_task_count": 4, "task_completion_rate": 1.0}}
            )
        )
        self.assertFalse(
            _run_entry_has_full_task_coverage(
                {"aggregate": {"sample_count": 3, "expected_task_count": 4, "task_completion_rate": 0.75}}
            )
        )

    def test_incomplete_variant_is_excluded_from_complete_comparisons(self) -> None:
        variant_rows = [
            {
                "variant_id": "baseline",
                "is_baseline": True,
                "is_family_baseline": False,
                "comparison_baseline_id": "",
                "planned_repetitions": 1,
            },
            {
                "variant_id": "architecture__minimal",
                "is_baseline": False,
                "is_family_baseline": False,
                "comparison_baseline_id": "baseline",
                "planned_repetitions": 1,
            },
        ]

        ready_ids = _annotate_variant_coverage(
            variant_rows,
            attempted_counts={"baseline": 1, "architecture__minimal": 1},
            successful_counts={"baseline": 1, "architecture__minimal": 1},
            complete_counts={"baseline": 1, "architecture__minimal": 0},
        )

        self.assertEqual(ready_ids, {"baseline"})
        baseline_row = variant_rows[0]
        variant_row = variant_rows[1]
        self.assertTrue(baseline_row["included_in_complete_aggregate"])
        self.assertFalse(variant_row["included_in_complete_aggregate"])
        self.assertEqual(variant_row["coverage_status"], "partial")
        self.assertIn("did not finish", variant_row["comparison_ready_reason"])


if __name__ == "__main__":
    unittest.main()
