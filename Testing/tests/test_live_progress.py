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
                        "current_sample": "config_decoder_test.exe",
                        "current_task_id": "config_value_recovery",
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
        self.assertEqual(state["runs"][0]["current_sample"], "config_decoder_test.exe")
        self.assertEqual(state["runs"][0]["current_task_id"], "config_value_recovery")
        self.assertEqual(state["executables"][0]["sample"], "config_decoder_test.exe")
        self.assertEqual(state["executables"][0]["status"], "running")

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
            sample_dir = run_dir / "samples" / "config_decoder_test__config_value_recovery"
            run_dir.mkdir(parents=True)
            sample_dir.mkdir(parents=True)
            log_path = experiment_root / "live_view" / "logs" / "run-001.log"
            log_path.parent.mkdir(parents=True)

            (experiment_root / "experiment_manifest.json").write_text(
                json.dumps(
                    {
                        "corpus": "experimental",
                        "selected_samples": ["config_decoder_test.exe"],
                        "selected_task_keys": ["config_decoder_test.exe::config_value_recovery"],
                    }
                ),
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
                        "tasks": [
                            {
                                "sample": "config_decoder_test.exe",
                                "task_id": "config_value_recovery",
                                "task_name": "Config Value Recovery",
                                "sample_task_id": "config_decoder_test.exe::config_value_recovery",
                                "status": "running",
                                "judge_status": "",
                                "score": None,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (sample_dir / "record.json").write_text(
                json.dumps(
                    {
                        "sample": "config_decoder_test.exe",
                        "task_id": "config_value_recovery",
                        "task_name": "Config Value Recovery",
                        "sample_task_id": "config_decoder_test.exe::config_value_recovery",
                        "task_query": "Recover the config strings and explain the parsing flow.",
                        "agent_result": {
                            "status": "completed",
                            "query": "Recover the config strings and explain the parsing flow.",
                            "final_report": "Recovered config strings and parsing flow.",
                            "accepted_final_output": True,
                        },
                        "judge_result": {
                            "status": "pass",
                            "score": 0.92,
                            "technical_summary": "Good coverage of parsing flow.",
                        },
                        "metrics": {
                            "analysis_status": "completed",
                            "judge_status": "pass",
                            "overall_score": 0.92,
                        },
                    }
                ),
                encoding="utf-8",
            )
            (sample_dir / "agent_result.json").write_text(
                json.dumps(
                    {
                        "status": "completed",
                        "query": "Recover the config strings and explain the parsing flow.",
                        "final_report": "Recovered config strings and parsing flow.",
                        "accepted_final_output": True,
                    }
                ),
                encoding="utf-8",
            )
            (sample_dir / "judge_result.json").write_text(
                json.dumps(
                    {
                        "status": "pass",
                        "score": 0.92,
                        "technical_summary": "Good coverage of parsing flow.",
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

        self.assertIn("query:", detail["run_output"]["text"])
        self.assertIn("Recovered config strings", detail["run_output"]["text"])
        self.assertEqual(detail["selected_task"]["sample_task_id"], "config_decoder_test.exe::config_value_recovery")
        self.assertEqual(detail["focused_sample"], "config_decoder_test.exe")
        self.assertEqual(detail["task_view"]["sample"], "config_decoder_test.exe")
        self.assertEqual(detail["pipeline_progress"]["current_key"], "agent:planner")
        self.assertEqual(detail["pipeline_progress"]["stages"][0]["status"], "completed")
        self.assertIn("Stage started: planner", detail["server_status"]["text"])

    def test_live_view_detail_prefers_matching_family_baseline_for_selected_variant(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            experiment_root = Path(temp_dir) / "experiment"
            global_baseline_dir = experiment_root / "runs" / "run-global-baseline-r2"
            family_baseline_r1_dir = experiment_root / "runs" / "run-family-baseline-r1"
            family_baseline_r2_dir = experiment_root / "runs" / "run-family-baseline-r2"
            selected_run_dir = experiment_root / "runs" / "run-brief-r2"
            for path in [global_baseline_dir, family_baseline_r1_dir, family_baseline_r2_dir, selected_run_dir]:
                path.mkdir(parents=True)
            selected_sample_dir = selected_run_dir / "samples" / "config_decoder_test__config_value_recovery"
            global_baseline_sample_dir = global_baseline_dir / "samples" / "config_decoder_test__config_value_recovery"
            family_baseline_r1_sample_dir = family_baseline_r1_dir / "samples" / "config_decoder_test__config_value_recovery"
            family_baseline_r2_sample_dir = family_baseline_r2_dir / "samples" / "config_decoder_test__config_value_recovery"
            for path in [
                selected_sample_dir,
                global_baseline_sample_dir,
                family_baseline_r1_sample_dir,
                family_baseline_r2_sample_dir,
            ]:
                path.mkdir(parents=True)

            (experiment_root / "experiment_manifest.json").write_text(
                json.dumps(
                    {
                        "corpus": "experimental",
                        "selected_samples": ["config_decoder_test.exe"],
                        "selected_task_keys": ["config_decoder_test.exe::config_value_recovery"],
                    }
                ),
                encoding="utf-8",
            )
            (experiment_root / "run_catalog.json").write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "run_id": "run-global-baseline-r2",
                                "run_dir": str(global_baseline_dir),
                                "variant_id": "baseline",
                                "replicate_index": 2,
                                "display_label": "baseline",
                                "is_baseline": True,
                                "status": "completed",
                                "ok": True,
                            },
                            {
                                "run_id": "run-family-baseline-r1",
                                "run_dir": str(family_baseline_r1_dir),
                                "variant_id": "query_verbosity__baseline",
                                "replicate_index": 1,
                                "display_label": "query_verbosity:baseline",
                                "is_baseline": False,
                                "is_family_baseline": True,
                                "status": "completed",
                                "ok": True,
                            },
                            {
                                "run_id": "run-family-baseline-r2",
                                "run_dir": str(family_baseline_r2_dir),
                                "variant_id": "query_verbosity__baseline",
                                "replicate_index": 2,
                                "display_label": "query_verbosity:baseline",
                                "is_baseline": False,
                                "is_family_baseline": True,
                                "status": "completed",
                                "ok": True,
                            },
                            {
                                "run_id": "run-brief-r2",
                                "run_dir": str(selected_run_dir),
                                "variant_id": "query_verbosity__brief",
                                "replicate_index": 2,
                                "display_label": "query_verbosity:brief",
                                "comparison_baseline_id": "query_verbosity__baseline",
                                "comparison_baseline_label": "query_verbosity:baseline",
                                "pipeline": "auto_triage",
                                "status": "running",
                                "ok": None,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (selected_run_dir / "run_manifest.json").write_text(
                json.dumps({"pipeline": "auto_triage", "judge_mode": "agent"}),
                encoding="utf-8",
            )
            (selected_run_dir / "live_status.json").write_text(
                json.dumps(
                    {
                        "status": "running",
                        "stage": "analysis",
                        "current_phase": "analysis",
                        "current_sample": "config_decoder_test.exe",
                        "current_task_id": "config_value_recovery",
                        "tasks": [
                            {
                                "sample": "config_decoder_test.exe",
                                "task_id": "config_value_recovery",
                                "task_name": "Config Value Recovery",
                                "sample_task_id": "config_decoder_test.exe::config_value_recovery",
                                "status": "running",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (selected_sample_dir / "record.json").write_text(
                json.dumps(
                    {
                        "sample": "config_decoder_test.exe",
                        "task_id": "config_value_recovery",
                        "task_name": "Config Value Recovery",
                        "sample_task_id": "config_decoder_test.exe::config_value_recovery",
                        "task_query": "Recover the config strings.",
                        "metrics": {"analysis_status": "running"},
                    }
                ),
                encoding="utf-8",
            )
            (global_baseline_sample_dir / "record.json").write_text(
                json.dumps(
                    {
                        "sample": "config_decoder_test.exe",
                        "task_id": "config_value_recovery",
                        "task_name": "Config Value Recovery",
                        "sample_task_id": "config_decoder_test.exe::config_value_recovery",
                        "task_query": "Recover the config strings.",
                        "metrics": {"analysis_status": "completed"},
                    }
                ),
                encoding="utf-8",
            )
            (global_baseline_sample_dir / "agent_result.json").write_text(
                json.dumps(
                    {
                        "status": "completed",
                        "final_report": "Global baseline report.",
                    }
                ),
                encoding="utf-8",
            )
            (family_baseline_r1_sample_dir / "record.json").write_text(
                json.dumps(
                    {
                        "sample": "config_decoder_test.exe",
                        "task_id": "config_value_recovery",
                        "task_name": "Config Value Recovery",
                        "sample_task_id": "config_decoder_test.exe::config_value_recovery",
                        "task_query": "Recover the config strings.",
                        "metrics": {"analysis_status": "completed"},
                    }
                ),
                encoding="utf-8",
            )
            (family_baseline_r1_sample_dir / "agent_result.json").write_text(
                json.dumps(
                    {
                        "status": "completed",
                        "final_report": "Family baseline replicate 1.",
                    }
                ),
                encoding="utf-8",
            )
            (family_baseline_r2_sample_dir / "record.json").write_text(
                json.dumps(
                    {
                        "sample": "config_decoder_test.exe",
                        "task_id": "config_value_recovery",
                        "task_name": "Config Value Recovery",
                        "sample_task_id": "config_decoder_test.exe::config_value_recovery",
                        "task_query": "Recover the config strings.",
                        "metrics": {"analysis_status": "completed"},
                    }
                ),
                encoding="utf-8",
            )
            (family_baseline_r2_sample_dir / "agent_result.json").write_text(
                json.dumps(
                    {
                        "status": "completed",
                        "final_report": "Family baseline replicate 2.",
                    }
                ),
                encoding="utf-8",
            )

            detail = load_live_view_detail(experiment_root, "run-brief-r2")

        self.assertEqual(detail["comparison_baseline"]["display_label"], "query_verbosity:baseline")
        self.assertEqual(detail["comparison_baseline"]["run_id"], "run-family-baseline-r2")
        self.assertIn("Family baseline replicate 2.", detail["baseline_output"]["text"])

    def test_live_view_detail_treats_budget_exceeded_terminal_state_as_non_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            experiment_root = Path(temp_dir) / "experiment"
            run_dir = experiment_root / "runs" / "run-001"
            run_dir.mkdir(parents=True)

            (experiment_root / "experiment_manifest.json").write_text(
                json.dumps(
                    {
                        "corpus": "experimental",
                        "selected_samples": ["config_decoder_test.exe"],
                        "selected_task_keys": ["config_decoder_test.exe::config_value_recovery"],
                    }
                ),
                encoding="utf-8",
            )
            (experiment_root / "run_catalog.json").write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "run_id": "run-001",
                                "run_dir": str(run_dir),
                                "variant_id": "baseline",
                                "display_label": "baseline",
                                "pipeline": "auto_triage",
                                "is_baseline": True,
                                "status": "completed",
                                "ok": True,
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
                        "status": "budget_exceeded",
                        "stage": "budget_exceeded",
                        "current_phase": "budget_exceeded",
                        "tasks": [],
                    }
                ),
                encoding="utf-8",
            )

            detail = load_live_view_detail(experiment_root, "run-001")

        self.assertEqual(detail["pipeline_progress"]["current_label"], "Budget exceeded")
        self.assertEqual(detail["pipeline_progress"]["stages"][-1]["status"], "completed")
        self.assertEqual(detail["pipeline_progress"]["stages"][-1]["state_text"], "Budget exceeded")

    def test_live_view_state_groups_runs_by_executable_using_executable_scoped_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            experiment_root = Path(temp_dir) / "experiment"
            run_dir = experiment_root / "runs" / "run-001"
            run_dir.mkdir(parents=True)

            (experiment_root / "experiment_manifest.json").write_text(
                json.dumps(
                    {
                        "corpus": "experimental",
                        "selected_samples": [
                            "basic_loops_test.exe",
                            "maintenance_orchestrator_test.exe",
                        ],
                        "selected_task_keys": [
                            "basic_loops_test.exe::default_analysis",
                            "maintenance_orchestrator_test.exe::default_analysis",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (experiment_root / "run_catalog.json").write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "run_id": "run-001",
                                "run_dir": str(run_dir),
                                "variant_id": "baseline",
                                "display_label": "baseline",
                                "pipeline": "auto_triage",
                                "is_baseline": True,
                                "status": "running",
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
                        "current_sample": "basic_loops_test.exe",
                        "current_task_id": "default_analysis",
                        "tasks": [
                            {
                                "sample": "basic_loops_test.exe",
                                "task_id": "default_analysis",
                                "sample_task_id": "basic_loops_test.exe::default_analysis",
                                "status": "running",
                            },
                            {
                                "sample": "maintenance_orchestrator_test.exe",
                                "task_id": "default_analysis",
                                "sample_task_id": "maintenance_orchestrator_test.exe::default_analysis",
                                "status": "pending",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            state = load_live_view_state(experiment_root)

        cards_by_sample = {card["sample"]: card for card in state["executables"]}
        active_card = cards_by_sample["basic_loops_test.exe"]
        inactive_card = cards_by_sample["maintenance_orchestrator_test.exe"]

        self.assertEqual(active_card["status"], "running")
        self.assertEqual(active_card["runs"][0]["status"], "running")
        self.assertIn("task=default_analysis", active_card["runs"][0]["meta"])
        self.assertEqual(inactive_card["status"], "pending")
        self.assertEqual(inactive_card["runs"][0]["status"], "pending")
        self.assertIn("active on basic_loops_test.exe", inactive_card["runs"][0]["meta"])

    def test_live_view_detail_can_focus_on_selected_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            experiment_root = Path(temp_dir) / "experiment"
            run_dir = experiment_root / "runs" / "run-001"
            run_dir.mkdir(parents=True)
            sample_a_dir = run_dir / "samples" / "basic_loops_test__default_analysis"
            sample_b_dir = run_dir / "samples" / "maintenance_orchestrator_test__default_analysis"
            sample_a_dir.mkdir(parents=True)
            sample_b_dir.mkdir(parents=True)

            (experiment_root / "experiment_manifest.json").write_text(
                json.dumps(
                    {
                        "corpus": "experimental",
                        "selected_samples": [
                            "basic_loops_test.exe",
                            "maintenance_orchestrator_test.exe",
                        ],
                        "selected_task_keys": [
                            "basic_loops_test.exe::default_analysis",
                            "maintenance_orchestrator_test.exe::default_analysis",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (experiment_root / "run_catalog.json").write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "run_id": "run-001",
                                "run_dir": str(run_dir),
                                "variant_id": "baseline",
                                "display_label": "baseline",
                                "pipeline": "auto_triage",
                                "is_baseline": True,
                                "status": "running",
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
                        "current_sample": "basic_loops_test.exe",
                        "current_task_id": "default_analysis",
                        "tasks": [
                            {
                                "sample": "basic_loops_test.exe",
                                "task_id": "default_analysis",
                                "task_name": "Default Analysis",
                                "sample_task_id": "basic_loops_test.exe::default_analysis",
                                "status": "running",
                            },
                            {
                                "sample": "maintenance_orchestrator_test.exe",
                                "task_id": "default_analysis",
                                "task_name": "Default Analysis",
                                "sample_task_id": "maintenance_orchestrator_test.exe::default_analysis",
                                "status": "pending",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (sample_b_dir / "record.json").write_text(
                json.dumps(
                    {
                        "sample": "maintenance_orchestrator_test.exe",
                        "task_id": "default_analysis",
                        "task_name": "Default Analysis",
                        "sample_task_id": "maintenance_orchestrator_test.exe::default_analysis",
                        "task_query": "Inspect orchestration flow.",
                        "metrics": {"analysis_status": "pending"},
                    }
                ),
                encoding="utf-8",
            )

            detail = load_live_view_detail(
                experiment_root,
                "run-001",
                sample_name="maintenance_orchestrator_test.exe",
            )

        self.assertEqual(detail["focused_sample"], "maintenance_orchestrator_test.exe")
        self.assertEqual(detail["selected_task"]["sample_task_id"], "maintenance_orchestrator_test.exe::default_analysis")
        self.assertEqual(detail["task_view"]["sample"], "maintenance_orchestrator_test.exe")
        self.assertEqual(len(detail["task_view"]["tasks"]), 1)

    def test_live_view_template_uses_three_column_hierarchy(self) -> None:
        self.assertIn(
            "grid-template-columns: minmax(260px, 1fr) minmax(260px, 1fr) minmax(540px, 2fr);",
            live_progress._INDEX_HTML,
        )
        self.assertEqual(live_progress._INDEX_HTML.count('class="surface output-panel"'), 3)
        self.assertIn("Executable Queue", live_progress._INDEX_HTML)
        self.assertIn("Runs For Executable", live_progress._INDEX_HTML)


if __name__ == "__main__":
    unittest.main()
