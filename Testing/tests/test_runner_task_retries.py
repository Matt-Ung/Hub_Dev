import unittest

from Testing.harness.runner import _annotate_task_retry_result, _should_retry_task_failure


class RunnerTaskRetryTests(unittest.TestCase):
    def test_should_retry_only_retryable_nonterminal_failures(self) -> None:
        self.assertTrue(
            _should_retry_task_failure(
                {"status": "analysis_error", "failure_retryable": True},
                attempt_index=1,
                max_attempts=3,
            )
        )
        self.assertFalse(
            _should_retry_task_failure(
                {"status": "completed", "failure_retryable": True},
                attempt_index=1,
                max_attempts=3,
            )
        )
        self.assertFalse(
            _should_retry_task_failure(
                {"status": "validator_blocked", "failure_retryable": True},
                attempt_index=1,
                max_attempts=3,
            )
        )
        self.assertFalse(
            _should_retry_task_failure(
                {"status": "worker_assignment_failed", "failure_retryable": False},
                attempt_index=1,
                max_attempts=3,
            )
        )
        self.assertFalse(
            _should_retry_task_failure(
                {"status": "analysis_error", "failure_retryable": True},
                attempt_index=3,
                max_attempts=3,
            )
        )

    def test_annotate_task_retry_result_records_attempt_metadata(self) -> None:
        payload = _annotate_task_retry_result(
            {"status": "analysis_error", "failure_retryable": True},
            attempt_index=3,
            max_attempts=3,
            attempt_history=[
                {"attempt_index": 1, "status": "worker_assignment_failed"},
                {"attempt_index": 2, "status": "analysis_error"},
                {"attempt_index": 3, "status": "analysis_error"},
            ],
        )

        self.assertEqual(payload["task_attempt_count"], 3)
        self.assertEqual(payload["task_retry_count"], 2)
        self.assertTrue(payload["task_retried"])
        self.assertTrue(payload["task_retry_exhausted"])
        self.assertEqual(len(payload["task_retry"]["attempts"]), 3)


if __name__ == "__main__":
    unittest.main()
