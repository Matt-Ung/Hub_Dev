import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from Testing.harness.recovery import (
    build_recovery_command,
    execute_recovery_plan,
    inspect_run_recovery,
    plan_recovery,
)
from Testing.harness.samples import build_evaluation_tasks, load_sample_manifest, sample_task_key


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class RecoveryTests(unittest.TestCase):
    def test_build_evaluation_tasks_accepts_exact_task_keys_with_exe_suffix(self) -> None:
        manifest = load_sample_manifest("experimental")
        tasks = build_evaluation_tasks(
            "experimental",
            [Path("/tmp/config_decoder_test.exe")],
            manifest=manifest,
            selected_task_keys=["config_decoder_test.exe::config_value_recovery"],
        )

        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].task_id, "config_value_recovery")
        self.assertEqual(sample_task_key(tasks[0].sample_name, tasks[0].task_id), "config_decoder_test::config_value_recovery")

    def test_inspect_run_recovery_classifies_failed_and_incomplete_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir) / "run-001"
            failed_sample_dir = run_dir / "samples" / "hash_dispatch_test__default_analysis"
            judge_failed_sample_dir = run_dir / "samples" / "config_decoder_test__config_value_recovery"
            run_dir.mkdir(parents=True)
            failed_sample_dir.mkdir(parents=True)
            judge_failed_sample_dir.mkdir(parents=True)

            _write_json(
                run_dir / "run_manifest.json",
                {
                    "run_id": "run-001",
                    "corpus": "experimental",
                    "judge_mode": "agent",
                    "pipeline": "auto_triage",
                    "selected_samples": ["hash_dispatch_test.exe", "config_decoder_test.exe", "basic_loops_test.exe", "maintenance_orchestrator_test.exe"],
                },
            )
            _write_json(
                run_dir / "live_status.json",
                {
                    "status": "failed",
                    "tasks": [
                        {
                            "sample": "hash_dispatch_test.exe",
                            "task_id": "default_analysis",
                            "sample_task_id": "hash_dispatch_test.exe::default_analysis",
                            "status": "analysis_error",
                            "judge_status": "",
                        },
                        {
                            "sample": "config_decoder_test.exe",
                            "task_id": "config_value_recovery",
                            "sample_task_id": "config_decoder_test.exe::config_value_recovery",
                            "status": "completed",
                            "judge_status": "judge_error",
                        },
                        {
                            "sample": "basic_loops_test.exe",
                            "task_id": "default_analysis",
                            "sample_task_id": "basic_loops_test.exe::default_analysis",
                            "status": "not_run_budget_exceeded",
                            "judge_status": "",
                        },
                        {
                            "sample": "maintenance_orchestrator_test.exe",
                            "task_id": "default_analysis",
                            "sample_task_id": "maintenance_orchestrator_test.exe::default_analysis",
                            "status": "pending",
                            "judge_status": "",
                        },
                    ],
                },
            )
            _write_json(
                failed_sample_dir / "record.json",
                {
                    "sample": "hash_dispatch_test.exe",
                    "task_id": "default_analysis",
                    "metrics": {
                        "analysis_status": "analysis_error",
                        "judge_status": "not_run",
                        "failure_reason": "agent crashed",
                    },
                },
            )
            _write_json(
                failed_sample_dir / "agent_result.json",
                {
                    "status": "analysis_error",
                    "failure_reason": "agent crashed",
                },
            )
            _write_json(
                judge_failed_sample_dir / "record.json",
                {
                    "sample": "config_decoder_test.exe",
                    "task_id": "config_value_recovery",
                    "metrics": {
                        "analysis_status": "completed",
                        "judge_status": "judge_error",
                    },
                },
            )
            _write_json(
                judge_failed_sample_dir / "agent_result.json",
                {
                    "status": "completed",
                    "final_report": "agent output",
                },
            )
            _write_json(
                judge_failed_sample_dir / "judge_result.json",
                {
                    "status": "judge_error",
                    "error": "judge timeout",
                },
            )

            inspection = inspect_run_recovery(run_dir, retry_policy="failed_only")

        by_task = {task["sample_task_id"]: task for task in inspection["tasks"]}
        self.assertEqual(by_task["hash_dispatch_test::default_analysis"]["classification"], "failed_analysis")
        self.assertEqual(by_task["config_decoder_test::config_value_recovery"]["classification"], "failed_judge")
        self.assertEqual(by_task["basic_loops_test::default_analysis"]["classification"], "skipped_budget")
        self.assertEqual(by_task["maintenance_orchestrator_test::default_analysis"]["classification"], "incomplete")
        retryable_ids = {task["sample_task_id"] for task in inspection["retryable_tasks"]}
        self.assertEqual(retryable_ids, {"hash_dispatch_test::default_analysis", "config_decoder_test::config_value_recovery"})

    def test_inspect_run_recovery_treats_validator_blocked_as_separate_and_not_retryable_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir) / "run-001"
            sample_dir = run_dir / "samples" / "config_decoder_test__default_analysis"
            run_dir.mkdir(parents=True)
            sample_dir.mkdir(parents=True)

            _write_json(
                run_dir / "run_manifest.json",
                {
                    "run_id": "run-001",
                    "corpus": "experimental",
                    "judge_mode": "agent",
                    "pipeline": "auto_triage",
                    "selected_samples": ["config_decoder_test.exe"],
                    "selected_task_keys": ["config_decoder_test.exe::default_analysis"],
                },
            )
            _write_json(
                run_dir / "live_status.json",
                {
                    "status": "completed",
                    "tasks": [
                        {
                            "sample": "config_decoder_test.exe",
                            "task_id": "default_analysis",
                            "sample_task_id": "config_decoder_test.exe::default_analysis",
                            "status": "validator_blocked",
                            "judge_status": "validator_blocked",
                        }
                    ],
                },
            )
            _write_json(
                sample_dir / "record.json",
                {
                    "sample": "config_decoder_test.exe",
                    "task_id": "default_analysis",
                    "metrics": {
                        "analysis_status": "validator_blocked",
                        "judge_status": "validator_blocked",
                        "failure_reason": "validator rejected the report",
                    },
                },
            )
            _write_json(
                sample_dir / "agent_result.json",
                {
                    "status": "validator_blocked",
                    "failure_reason": "validator rejected the report",
                },
            )
            _write_json(
                sample_dir / "judge_result.json",
                {
                    "status": "validator_blocked",
                },
            )

            inspection_default = inspect_run_recovery(run_dir, retry_policy="non_completed")
            inspection_including = inspect_run_recovery(run_dir, retry_policy="non_completed_including_validator_blocked")

        task_default = inspection_default["tasks"][0]
        task_including = inspection_including["tasks"][0]
        self.assertEqual(task_default["classification"], "validator_blocked")
        self.assertFalse(task_default["retryable"])
        self.assertEqual(inspection_default["retryable_task_count"], 0)
        self.assertEqual(task_including["classification"], "validator_blocked")
        self.assertTrue(task_including["retryable"])
        self.assertEqual(inspection_including["retryable_task_count"], 1)

    def test_plan_recovery_scopes_experiment_to_only_runs_with_retryable_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            experiment_root = Path(temp_dir) / "experiment"
            failed_run_dir = Path(temp_dir) / "runs" / "run-failed"
            completed_run_dir = Path(temp_dir) / "runs" / "run-completed"
            failed_run_dir.mkdir(parents=True)
            completed_run_dir.mkdir(parents=True)

            _write_json(experiment_root / "experiment_manifest.json", {"corpus": "experimental"})
            _write_json(
                experiment_root / "run_catalog.json",
                {
                    "runs": [
                        {
                            "run_id": "run-failed",
                            "run_dir": str(failed_run_dir),
                            "display_label": "worker_prompt_shape:artifact_focused",
                            "status": "failed",
                        },
                        {
                            "run_id": "run-completed",
                            "run_dir": str(completed_run_dir),
                            "display_label": "baseline",
                            "status": "completed",
                        },
                    ]
                },
            )
            _write_json(
                failed_run_dir / "run_manifest.json",
                {
                    "run_id": "run-failed",
                    "corpus": "experimental",
                    "judge_mode": "agent",
                    "pipeline": "auto_triage",
                    "selected_samples": ["hash_dispatch_test.exe"],
                    "selected_task_keys": ["hash_dispatch_test.exe::default_analysis"],
                },
            )
            _write_json(
                failed_run_dir / "live_status.json",
                {
                    "status": "failed",
                    "tasks": [
                        {
                            "sample": "hash_dispatch_test.exe",
                            "task_id": "default_analysis",
                            "sample_task_id": "hash_dispatch_test.exe::default_analysis",
                            "status": "analysis_error",
                            "judge_status": "",
                        }
                    ],
                },
            )
            _write_json(
                completed_run_dir / "run_manifest.json",
                {
                    "run_id": "run-completed",
                    "corpus": "experimental",
                    "judge_mode": "agent",
                    "pipeline": "auto_triage",
                    "selected_samples": ["config_decoder_test.exe"],
                    "selected_task_keys": ["config_decoder_test.exe::config_value_recovery"],
                },
            )
            _write_json(
                completed_run_dir / "live_status.json",
                {
                    "status": "completed",
                    "tasks": [
                        {
                            "sample": "config_decoder_test.exe",
                            "task_id": "config_value_recovery",
                            "sample_task_id": "config_decoder_test.exe::config_value_recovery",
                            "status": "completed",
                            "judge_status": "pass",
                        }
                    ],
                },
            )
            sample_dir = completed_run_dir / "samples" / "config_decoder_test__config_value_recovery"
            sample_dir.mkdir(parents=True)
            _write_json(
                sample_dir / "record.json",
                {
                    "sample": "config_decoder_test.exe",
                    "task_id": "config_value_recovery",
                    "metrics": {
                        "analysis_status": "completed",
                        "judge_status": "pass",
                    },
                },
            )
            _write_json(sample_dir / "agent_result.json", {"status": "completed"})
            _write_json(sample_dir / "judge_result.json", {"status": "pass"})

            plan = plan_recovery(experiment_root)

            self.assertEqual(plan["runs_examined"], 2)
            self.assertEqual(plan["runs_with_retryable_tasks"], 1)
            self.assertEqual(plan["retryable_task_count"], 1)
            self.assertEqual(plan["inspections"][0]["run_id"], "run-failed")

    def test_execute_recovery_plan_writes_session_and_records_recovery_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir) / "run-001"
            run_dir.mkdir(parents=True)
            _write_json(
                run_dir / "run_manifest.json",
                {
                    "run_id": "run-001",
                    "corpus": "experimental",
                    "pipeline": "auto_triage",
                    "architecture": "balanced",
                    "query_variant": "brief",
                    "subagent_profile": "default",
                    "worker_persona_profile": "artifact_focused",
                    "worker_role_prompt_mode": "default",
                    "validator_review_level": "default",
                    "tool_profile": "full",
                    "model_profile": "repo_default",
                    "judge_mode": "agent",
                    "metadata": {"experiment_variant_id": "worker_prompt_shape__artifact_focused"},
                    "selected_samples": ["hash_dispatch_test.exe"],
                    "selected_task_keys": ["hash_dispatch_test.exe::default_analysis"],
                },
            )
            _write_json(
                run_dir / "live_status.json",
                {
                    "status": "failed",
                    "tasks": [
                        {
                            "sample": "hash_dispatch_test.exe",
                            "task_id": "default_analysis",
                            "sample_task_id": "hash_dispatch_test.exe::default_analysis",
                            "status": "analysis_error",
                            "judge_status": "",
                        }
                    ],
                },
            )

            recovery_run_dir = Path(temp_dir) / "results" / "runs" / "recovered-run"
            recovery_run_dir.mkdir(parents=True)
            with patch("Testing.harness.recovery.run_command") as run_command_mock:
                run_command_mock.return_value = {
                    "ok": True,
                    "returncode": 0,
                    "stdout": "EVAL_RUN_RESULT_JSON::{\"run_id\":\"recovered-run\",\"run_dir\":\"%s\",\"status\":\"completed\",\"sample_count\":1}\n"
                    % str(recovery_run_dir),
                    "stderr": "",
                }

                result = execute_recovery_plan(run_dir, quiet_child_output=True)

            self.assertEqual(result["summary"]["launched_recovery_runs"], 1)
            self.assertEqual(result["summary"]["completed_recovery_runs"], 1)
            self.assertEqual(result["summary"]["failed_recovery_runs"], 0)
            session_path = Path(result["session_dir"]) / "recovery_session.json"
            self.assertTrue(session_path.exists())
            recorded = json.loads(session_path.read_text(encoding="utf-8"))
            inspection = recorded["inspections"][0]
            command = inspection["recovery_command"]["command"]
            self.assertIn("--sample-task-key", command)
            task_key_index = command.index("--sample-task-key")
            self.assertEqual(command[task_key_index + 1], "hash_dispatch_test::default_analysis")
            self.assertIn("--skip-build", command)
            self.assertIn("--skip-prepare", command)
            self.assertIn("--meta", command)
            self.assertEqual(inspection["recovery_result"]["recovery_run_dir"], str(recovery_run_dir.resolve()))
            build_payload = build_recovery_command(
                recorded["inspections"][0],
                session_id=recorded["session_id"],
                session_dir=Path(recorded["session_dir"]),
            )
            self.assertEqual(build_payload["retry_exact_keys"], ["hash_dispatch_test::default_analysis"])

    def test_execute_recovery_plan_can_launch_recovery_runs_concurrently(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            experiment_root = root / "experiment"
            runs_root = root / "runs"
            recovery_results_root = root / "results" / "runs"
            experiment_root.mkdir(parents=True)
            runs_root.mkdir(parents=True)
            recovery_results_root.mkdir(parents=True)

            run_entries = []
            for index, sample_name in enumerate(["hash_dispatch_test.exe", "config_decoder_test.exe"], start=1):
                run_id = f"run-{index}"
                run_dir = runs_root / run_id
                run_dir.mkdir(parents=True)
                _write_json(
                    run_dir / "run_manifest.json",
                    {
                        "run_id": run_id,
                        "corpus": "experimental",
                        "pipeline": "auto_triage",
                        "judge_mode": "agent",
                        "selected_samples": [sample_name],
                        "selected_task_keys": [f"{sample_name}::default_analysis"],
                    },
                )
                _write_json(
                    run_dir / "live_status.json",
                    {
                        "status": "failed",
                        "tasks": [
                            {
                                "sample": sample_name,
                                "task_id": "default_analysis",
                                "sample_task_id": f"{sample_name}::default_analysis",
                                "status": "analysis_error",
                                "judge_status": "",
                            }
                        ],
                    },
                )
                run_entries.append(
                    {
                        "run_id": run_id,
                        "run_dir": str(run_dir),
                        "display_label": run_id,
                        "status": "failed",
                    }
                )

            _write_json(experiment_root / "experiment_manifest.json", {"corpus": "experimental"})
            _write_json(experiment_root / "run_catalog.json", {"runs": run_entries})

            active = 0
            peak = 0
            call_index = 0
            lock = threading.Lock()

            def _fake_run_command(*args, **kwargs):
                nonlocal active, peak, call_index
                with lock:
                    call_index += 1
                    local_index = call_index
                    active += 1
                    peak = max(peak, active)
                time.sleep(0.12)
                with lock:
                    active -= 1
                recovery_run_dir = recovery_results_root / f"recovered-run-{local_index}"
                recovery_run_dir.mkdir(parents=True, exist_ok=True)
                return {
                    "ok": True,
                    "returncode": 0,
                    "stdout": (
                        "EVAL_RUN_RESULT_JSON::{\"run_id\":\"recovered-run-%d\",\"run_dir\":\"%s\",\"status\":\"completed\",\"sample_count\":1}\n"
                        % (local_index, str(recovery_run_dir))
                    ),
                    "stderr": "",
                }

            with patch("Testing.harness.recovery.run_command", side_effect=_fake_run_command):
                result = execute_recovery_plan(
                    experiment_root,
                    quiet_child_output=True,
                    max_concurrent_recovery_runs=2,
                )

            self.assertEqual(result["summary"]["launched_recovery_runs"], 2)
            self.assertEqual(result["summary"]["completed_recovery_runs"], 2)
            self.assertEqual(result["summary"]["failed_recovery_runs"], 0)
            self.assertGreaterEqual(peak, 2)
            self.assertEqual(result["max_concurrent_recovery_runs"], 2)


if __name__ == "__main__":
    unittest.main()
