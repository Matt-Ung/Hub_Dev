import json
import tempfile
import unittest
from pathlib import Path

from Testing.harness import live_progress
from Testing.harness.experiment_sweep import _planned_run_instance
from Testing.harness.launch_presets import build_launch_preset_command
from Testing.harness.live_progress import load_live_view_detail, load_live_view_state


class LiveProgressTests(unittest.TestCase):
    def test_planned_run_instance_uses_deterministic_run_id_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            logs_dir = Path(temp_dir) / "logs"
            entry = _planned_run_instance(
                experiment_id="sweep-experimental-20260401_120000",
                corpus_name="experimental",
                run_cfg={
                    "variant_id": "query_verbosity__brief",
                    "variant_name": "brief",
                    "changed_variable": "query_verbosity",
                    "comparison_baseline_id": "baseline",
                    "comparison_baseline_label": "baseline",
                },
                repetition_index=1,
                planned_repetitions=1,
                live_logs_dir=logs_dir,
            )

        self.assertEqual(
            entry["run_id"],
            "eval-experimental-sweep-experimental-20260401_120000-query_verbosity__brief-r1",
        )
        self.assertTrue(str(entry["live_status_path"]).endswith("/live_status.json"))
        self.assertTrue(str(entry["log_path"]).endswith(".log"))
        self.assertEqual(entry["status"], "pending")

    def test_live_view_state_reads_live_status_stage_updates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            experiment_root = Path(temp_dir) / "experiment"
            run_dir = experiment_root / "runs" / "run-001"
            run_dir.mkdir(parents=True)
            (experiment_root / "experiment_manifest.json").write_text(
                json.dumps({"corpus": "experimental"}),
                encoding="utf-8",
            )
            (experiment_root / "run_catalog.json").write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "run_id": "run-001",
                                "run_dir": str(run_dir),
                                "status": "running",
                                "display_label": "baseline",
                                "ok": None,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "live_status.json").write_text(
                json.dumps(
                    {
                        "stage": "judge",
                        "current_phase": "judge",
                        "tasks": [],
                    }
                ),
                encoding="utf-8",
            )

            state = load_live_view_state(experiment_root)

        self.assertEqual(state["summary"]["total_runs"], 1)
        self.assertEqual(state["summary"]["running"], 1)
        self.assertEqual(state["runs"][0]["stage"], "judge")
        self.assertEqual(state["runs"][0]["current_phase"], "judge")

    def test_launch_preset_can_forward_live_view_flag(self) -> None:
        command = build_launch_preset_command(
            "paid_narrow_pilot",
            explicit_judge_model="openai:gpt-4o-mini",
            live_view=True,
        )

        self.assertIn("Testing/run_experiment_sweep.py", command)
        self.assertIn("--live-view", command)

    def test_live_view_detail_surfaces_run_output_and_pipeline_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            experiment_root = Path(temp_dir) / "experiment"
            run_dir = experiment_root / "runs" / "run-001"
            sample_dir = run_dir / "samples" / "sample-a"
            run_dir.mkdir(parents=True)
            sample_dir.mkdir(parents=True)
            log_path = experiment_root / "live_view" / "logs" / "run-001.log"
            log_path.parent.mkdir(parents=True)

            (experiment_root / "experiment_manifest.json").write_text(
                json.dumps({"corpus": "experimental"}),
                encoding="utf-8",
            )
            (experiment_root / "run_catalog.json").write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "run_id": "run-001",
                                "run_dir": str(run_dir),
                                "log_path": str(log_path),
                                "status": "running",
                                "display_label": "baseline",
                                "pipeline": "auto_triage",
                                "is_baseline": True,
                                "ok": None,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "run_manifest.json").write_text(
                json.dumps({"pipeline": "auto_triage", "judge_mode": "agent"}),
                encoding="utf-8",
            )
            (run_dir / "live_status.json").write_text(
                json.dumps(
                    {
                        "status": "running",
                        "stage": "analysis",
                        "current_phase": "analysis",
                        "current_sample": "config_decoder_test.exe",
                        "current_task_id": "config_value_recovery",
                        "last_message": "Starting analysis.",
                        "tasks": [],
                    }
                ),
                encoding="utf-8",
            )
            (sample_dir / "agent_result.json").write_text(
                json.dumps(
                    {
                        "status": "completed",
                        "final_report": "Recovered config strings and parsing flow.",
                        "accepted_final_output": True,
                    }
                ),
                encoding="utf-8",
            )
            log_path.write_text(
                "\n".join(
                    [
                        "[16:08:54] Stage started: preflight (kind=preflight, subagents=preflight_analyst)",
                        "[16:12:38] Stage finished: preflight in 224.1s",
                        "[16:12:57] Stage started: planner (kind=planner, subagents=none)",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            detail = load_live_view_detail(experiment_root, "run-001")

        self.assertIn("Recovered config strings", detail["run_output"]["text"])
        self.assertEqual(detail["pipeline_progress"]["current_key"], "agent:planner")
        self.assertEqual(detail["pipeline_progress"]["stages"][0]["status"], "completed")
        self.assertIn("Stage started: planner", detail["server_status"]["text"])

    def test_live_view_template_uses_equal_output_panel_grid(self) -> None:
        self.assertIn(
            "grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));",
            live_progress._INDEX_HTML,
        )
        self.assertEqual(live_progress._INDEX_HTML.count('class="surface output-panel"'), 3)


if __name__ == "__main__":
    unittest.main()
