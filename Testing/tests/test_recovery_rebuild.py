import json
import tempfile
import unittest
from pathlib import Path

from Testing.harness.recovery_rebuild import plan_rebuilt_experiment, rebuild_experiment_from_recovery
from Testing.harness.reporting import aggregate_records


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _record(
    *,
    sample: str,
    task_id: str,
    analysis_status: str,
    judge_status: str,
    score: float | None,
    task_success: bool,
) -> dict:
    return {
        "sample": sample,
        "task_id": task_id,
        "task_name": "Default Analysis",
        "sample_task_id": f"{Path(sample).stem}::{task_id}",
        "task_query": "Analyze the executable.",
        "difficulty": "medium",
        "primary_techniques": ["cfg_reconstruction"],
        "expected_evidence": [],
        "acceptance_targets": [],
        "task_tags": ["analysis"],
        "target_tools": ["ghidra"],
        "bundle_manifest": {},
        "agent_result": {
            "status": analysis_status,
            "final_report": "Recovered output" if task_success else "",
            "produced_result": bool(task_success),
        },
        "judge_result": {
            "status": judge_status,
            "pass": bool(task_success),
            "overall_score_0_to_100": score,
            "technical_summary": "technical summary",
            "writing_summary": "writing summary",
        },
        "metrics": {
            "analysis_status": analysis_status,
            "judge_status": judge_status,
            "produced_result": bool(task_success),
            "task_success": bool(task_success),
            "judge_pass": bool(task_success),
            "scored_result": score is not None,
            "overall_score_0_to_100": score,
            "tool_calls_total": 1,
            "target_tool_hit_rate": 1.0,
            "total_tokens": 10,
            "total_relative_cost_index": 1.25,
            "analysis_duration_sec": 1.0,
            "judge_duration_sec": 1.0,
            "total_duration_sec": 2.0,
            "task_wall_clock_duration_sec": 2.0,
        },
    }


class RecoveryRebuildTests(unittest.TestCase):
    def test_rebuild_experiment_overlays_recovery_records_and_regenerates_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            experiment_root = root / "experiments" / "exp-001"
            original_run_dir = root / "runs" / "baseline-r1"
            recovery_run_dir = root / "runs" / "baseline-r1-recovery"
            output_root = root / "rebuilt"
            sample = "config_decoder_test.exe"
            task_id = "default_analysis"

            run_manifest = {
                "run_id": "baseline-r1",
                "experiment_id": "exp-001",
                "corpus": "experimental",
                "pipeline": "auto_triage",
                "architecture": "balanced",
                "query_variant": "default",
                "subagent_profile": "default",
                "worker_persona_profile": "default",
                "worker_role_prompt_mode": "default",
                "validator_review_level": "default",
                "tool_profile": "full",
                "model_profile": "repo_default",
                "force_model": "",
                "judge_mode": "agent",
                "judge_model": "",
                "variant_name": "baseline",
                "changed_variable": "baseline",
                "comparison_baseline_id": "baseline",
                "comparison_baseline_label": "baseline",
                "config_lineage_id": "cfg-experimental-test",
                "selected_samples": [sample],
                "selected_tasks": [task_id],
                "selected_difficulties": ["medium"],
                "expected_task_count": 1,
                "replicate_index": 1,
                "replicate_count": 1,
                "metadata": {"experiment_variant_id": "baseline"},
            }
            failed_record = _record(
                sample=sample,
                task_id=task_id,
                analysis_status="analysis_error",
                judge_status="not_run",
                score=None,
                task_success=False,
            )
            recovered_record = _record(
                sample=sample,
                task_id=task_id,
                analysis_status="completed",
                judge_status="completed",
                score=82.0,
                task_success=True,
            )

            failed_aggregate = aggregate_records(run_manifest, [failed_record])
            failed_aggregate["terminal_status"] = "completed"
            recovered_aggregate = aggregate_records(run_manifest, [recovered_record])
            recovered_aggregate["terminal_status"] = "completed"

            _write_json(original_run_dir / "run_manifest.json", run_manifest)
            _write_json(original_run_dir / "aggregate.json", failed_aggregate)
            _write_json(
                original_run_dir / "live_status.json",
                {
                    "status": "completed",
                    "tasks": [
                        {
                            "sample": sample,
                            "task_id": task_id,
                            "task_name": "Default Analysis",
                            "sample_task_id": f"{Path(sample).stem}::{task_id}",
                            "status": "analysis_error",
                            "judge_status": "not_run",
                        }
                    ],
                },
            )
            sample_dir = original_run_dir / "samples" / f"{Path(sample).stem}__{task_id}"
            _write_json(sample_dir / "record.json", failed_record)
            _write_json(sample_dir / "agent_result.json", failed_record["agent_result"])
            _write_json(sample_dir / "judge_result.json", failed_record["judge_result"])

            _write_json(recovery_run_dir / "run_manifest.json", run_manifest)
            _write_json(recovery_run_dir / "aggregate.json", recovered_aggregate)
            _write_json(recovery_run_dir / "live_status.json", {"status": "completed", "tasks": []})
            recovery_sample_dir = recovery_run_dir / "samples" / f"{Path(sample).stem}__{task_id}"
            _write_json(recovery_sample_dir / "record.json", recovered_record)
            _write_json(recovery_sample_dir / "agent_result.json", recovered_record["agent_result"])
            _write_json(recovery_sample_dir / "judge_result.json", recovered_record["judge_result"])

            _write_json(
                experiment_root / "experiment_manifest.json",
                {
                    "experiment_id": "exp-001",
                    "config_path": "/tmp/config.json",
                    "corpus": "experimental",
                    "selected_samples": [sample],
                    "selected_tasks": [task_id],
                    "selected_difficulties": ["medium"],
                    "selected_task_keys": [f"{sample}::{task_id}"],
                    "repetitions": 1,
                    "baseline_variant_id": "baseline",
                    "planned_runs": [
                        {
                            "variant_id": "baseline",
                            "variant_name": "baseline",
                            "changed_variable": "baseline",
                            "is_baseline": True,
                            "is_family_baseline": False,
                            "comparison_baseline_id": "baseline",
                            "comparison_baseline_label": "baseline",
                            "pipeline": "auto_triage",
                            "architecture": "balanced",
                            "query_variant": "default",
                            "subagent_profile": "default",
                            "worker_persona_profile": "default",
                            "worker_role_prompt_mode": "default",
                            "validator_review_level": "default",
                            "tool_profile": "full",
                            "model_profile": "repo_default",
                            "force_model": "",
                        }
                    ],
                },
            )
            _write_json(
                experiment_root / "run_catalog.json",
                {
                    "runs": [
                        {
                            "variant_id": "baseline",
                            "variant_name": "baseline",
                            "changed_variable": "baseline",
                            "display_label": "baseline",
                            "comparison_baseline_id": "baseline",
                            "comparison_baseline_label": "baseline",
                            "replicate_index": 1,
                            "planned_repetitions": 1,
                            "run_id": "baseline-r1",
                            "run_dir": str(original_run_dir),
                            "status": "completed",
                            "ok": True,
                            "run_manifest": run_manifest,
                            "aggregate": failed_aggregate,
                        }
                    ]
                },
            )
            _write_json(
                experiment_root / "recovery_attempts" / "recovery-001" / "recovery_session.json",
                {
                    "session_id": "recovery-001",
                    "started_at": "2026-04-04T10:00:00",
                    "summary": {
                        "completed_recovery_runs": 1,
                    },
                    "inspections": [
                        {
                            "run_id": "baseline-r1",
                            "display_label": "baseline",
                            "retryable_tasks": [
                                {
                                    "sample_task_id": f"{Path(sample).stem}::{task_id}",
                                }
                            ],
                            "recovery_result": {
                                "ok": True,
                                "recovery_run_dir": str(recovery_run_dir),
                            },
                        }
                    ],
                },
            )

            result = rebuild_experiment_from_recovery(
                experiment_root,
                output_root=output_root,
                output_experiment_id="exp-001-repaired",
                skip_visuals=True,
            )

            repaired_root = output_root / "exp-001-repaired"
            self.assertEqual(result["repaired_experiment_id"], "exp-001-repaired")
            self.assertTrue((repaired_root / "variant_summary.csv").exists())
            self.assertTrue((repaired_root / "outputs" / "task_output_comparisons" / "index.html").exists())
            self.assertTrue((repaired_root / "by_executable" / "index.json").exists())
            self.assertTrue((repaired_root / "by_executable" / sample).is_dir())

            repaired_catalog = json.loads((repaired_root / "run_catalog.json").read_text())
            repaired_entry = repaired_catalog["runs"][0]
            repaired_record = repaired_entry["aggregate"]["records"][0]
            self.assertEqual(repaired_record["metrics"]["analysis_status"], "completed")
            self.assertEqual(repaired_record["metrics"]["overall_score_0_to_100"], 82.0)

            variant_summary = (repaired_root / "variant_summary.csv").read_text(encoding="utf-8")
            self.assertIn("82.0", variant_summary)

            rebuilt_record_path = repaired_root / "rebuilt_runs" / "baseline-r1" / "samples" / f"{Path(sample).stem}__{task_id}" / "record.json"
            rebuilt_record = json.loads(rebuilt_record_path.read_text())
            self.assertEqual(rebuilt_record["metrics"]["analysis_status"], "completed")

    def test_plan_rebuilt_experiment_ignores_plan_only_recovery_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            experiment_root = root / "experiment"
            _write_json(
                experiment_root / "experiment_manifest.json",
                {
                    "experiment_id": "exp-002",
                    "planned_runs": [],
                    "repetitions": 1,
                },
            )
            _write_json(experiment_root / "run_catalog.json", {"runs": []})
            _write_json(
                experiment_root / "recovery_attempts" / "recovery-plan" / "recovery_session.json",
                {
                    "session_id": "recovery-plan",
                    "started_at": "2026-04-04T08:00:00",
                    "summary": {"completed_recovery_runs": 0},
                    "inspections": [],
                },
            )
            _write_json(
                experiment_root / "recovery_attempts" / "recovery-done" / "recovery_session.json",
                {
                    "session_id": "recovery-done",
                    "started_at": "2026-04-04T09:00:00",
                    "summary": {"completed_recovery_runs": 1},
                    "inspections": [],
                },
            )

            plan = plan_rebuilt_experiment(experiment_root, output_root=root / "out")

            self.assertEqual(plan["session_count"], 1)
            self.assertEqual(plan["recovery_session_ids"], ["recovery-done"])


if __name__ == "__main__":
    unittest.main()
