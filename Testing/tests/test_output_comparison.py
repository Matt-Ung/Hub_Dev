import unittest

from Testing.harness.output_comparison import _representative_row


class OutputComparisonTests(unittest.TestCase):
    def test_representative_row_prefers_median_score_not_best_score(self) -> None:
        rows = [
            {
                "run_id": "run-low",
                "replicate_index": 1,
                "overall_score_0_to_100": 10.0,
                "final_report": "report",
                "produced_result": True,
            },
            {
                "run_id": "run-mid",
                "replicate_index": 2,
                "overall_score_0_to_100": 50.0,
                "final_report": "report",
                "produced_result": True,
            },
            {
                "run_id": "run-high",
                "replicate_index": 3,
                "overall_score_0_to_100": 90.0,
                "final_report": "report",
                "produced_result": True,
            },
        ]

        representative = _representative_row(rows)
        self.assertEqual(representative["run_id"], "run-mid")


if __name__ == "__main__":
    unittest.main()
