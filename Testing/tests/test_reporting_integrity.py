import unittest

from Testing.harness.judge import _build_non_result_judge_result
from Testing.harness.reporting import aggregate_records, build_sample_record


def _base_inputs():
    sample_meta = {
        "difficulty": "hard",
        "primary_techniques": ["cfg_reconstruction"],
        "expected_evidence": [],
        "acceptance_targets": [],
    }
    task_meta = {
        "task_id": "default_analysis",
        "task_name": "Default Analysis",
        "query": "Analyze the executable.",
        "target_tools": ["ghidra"],
        "expected_evidence": [],
        "acceptance_targets": [],
        "tags": ["analysis"],
    }
    bundle_manifest = {"bundle_id": "bundle-001"}
    return sample_meta, task_meta, bundle_manifest


class ReportingIntegrityTests(unittest.TestCase):
    def test_synthetic_non_result_judge_payload_does_not_claim_high_confidence(self) -> None:
        result = _build_non_result_judge_result(
            status="analysis_error",
            model_id="openai:test",
            rubric_version="rubric-v1",
            failure_reason="runtime crash",
            agent_result={"status": "analysis_error", "validator_summary": {}, "validation": {}},
            rubric={
                "normalization": {"raw_total_max": 30},
                "dimensions": [{"name": "evidence_grounding", "max_score": 5}],
            },
        )

        self.assertEqual(result["evaluation_mode"], "synthetic_non_result")
        self.assertEqual(result["confidence_0_to_1"], 0.0)

    def test_synthetic_non_result_is_not_counted_as_scored_result(self) -> None:
        sample_meta, task_meta, bundle_manifest = _base_inputs()
        record = build_sample_record(
            "config_decoder_test.exe",
            sample_meta,
            task_meta,
            bundle_manifest,
            {
                "ok": False,
                "status": "validator_blocked",
                "produced_result": False,
                "accepted_final_output": False,
                "failure_reason": "validator rejected output",
            },
            {
                "ok": True,
                "status": "validator_blocked",
                "evaluation_mode": "synthetic_non_result",
                "pass": False,
                "overall_score_0_to_100": 0.0,
                "technical_summary": "blocked",
                "writing_summary": "no accepted result",
                "usage": {},
                "cost_estimate": {},
            },
        )

        metrics = record["metrics"]
        self.assertFalse(metrics["scored_result"])
        self.assertTrue(metrics["synthetic_judge_result"])
        self.assertEqual(metrics["overall_score_0_to_100"], 0.0)

        aggregate = aggregate_records({"run_id": "run-1", "expected_task_count": 1}, [record])
        self.assertEqual(aggregate["judged_count"], 0)
        self.assertEqual(aggregate["scored_result_rate"], 0.0)
        self.assertEqual(aggregate["synthetic_judge_rate"], 1.0)
        self.assertEqual(aggregate["overall_score_mean"], 0.0)

    def test_aggregate_separates_real_scores_from_synthetic_failures(self) -> None:
        sample_meta, task_meta, bundle_manifest = _base_inputs()
        synthetic_record = build_sample_record(
            "config_decoder_test.exe",
            sample_meta,
            task_meta,
            bundle_manifest,
            {
                "ok": False,
                "status": "analysis_error",
                "produced_result": False,
                "accepted_final_output": False,
                "failure_reason": "runtime crash",
            },
            {
                "ok": True,
                "status": "analysis_error",
                "evaluation_mode": "synthetic_non_result",
                "pass": False,
                "overall_score_0_to_100": 0.0,
                "technical_summary": "crash",
                "writing_summary": "no accepted result",
                "usage": {},
                "cost_estimate": {},
            },
        )
        completed_record = build_sample_record(
            "config_decoder_test.exe",
            sample_meta,
            task_meta,
            bundle_manifest,
            {
                "ok": True,
                "status": "completed",
                "produced_result": True,
                "accepted_final_output": True,
                "final_report": "Recovered config logic.",
            },
            {
                "ok": True,
                "status": "completed",
                "evaluation_mode": "agent_judge",
                "pass": True,
                "overall_score_0_to_100": 80.0,
                "technical_summary": "good",
                "writing_summary": "good",
                "usage": {},
                "cost_estimate": {},
            },
        )

        aggregate = aggregate_records(
            {"run_id": "run-2", "expected_task_count": 2},
            [synthetic_record, completed_record],
        )

        self.assertEqual(aggregate["judged_count"], 1)
        self.assertEqual(aggregate["scored_result_rate"], 0.5)
        self.assertEqual(aggregate["synthetic_judge_rate"], 0.5)
        self.assertEqual(aggregate["produced_result_rate"], 0.5)
        self.assertEqual(aggregate["task_success_rate"], 0.5)
        self.assertEqual(aggregate["overall_score_mean"], 40.0)


if __name__ == "__main__":
    unittest.main()
