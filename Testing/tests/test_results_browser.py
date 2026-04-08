import json
import os
import tempfile
import unittest
from pathlib import Path

from Testing.harness.results_browser import (
    load_results_browser_catalog,
    load_results_browser_detail,
    load_results_browser_state,
)


class ResultsBrowserTests(unittest.TestCase):
    def test_results_browser_catalog_lists_newest_experiment_first(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            results_root = Path(temp_dir) / "results"
            experiments_root = results_root / "experiments"
            older = experiments_root / "sweep-experimental-20260401_000000-a"
            newer = experiments_root / "sweep-experimental-20260402_000000-b"
            older.mkdir(parents=True)
            newer.mkdir(parents=True)
            for experiment_root, corpus in [(older, "experimental"), (newer, "prototype")]:
                (experiment_root / "experiment_manifest.json").write_text(
                    json.dumps({"corpus": corpus}),
                    encoding="utf-8",
                )
                (experiment_root / "run_catalog.json").write_text(
                    json.dumps({"runs": []}),
                    encoding="utf-8",
                )
            os.utime(older, (1_700_000_000, 1_700_000_000))
            os.utime(newer, (1_800_000_000, 1_800_000_000))

            catalog = load_results_browser_catalog(results_root)

        self.assertEqual(catalog["experiments"][0]["experiment_id"], "sweep-experimental-20260402_000000-b")
        self.assertEqual(catalog["experiments"][0]["corpus"], "prototype")
        self.assertEqual(catalog["experiments"][1]["experiment_id"], "sweep-experimental-20260401_000000-a")

    def test_results_browser_detail_includes_visual_gallery_and_task_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            results_root = Path(temp_dir) / "results"
            experiment_root = results_root / "experiments" / "sweep-experimental-20260402_000000-browser"
            run_dir = results_root / "runs" / "run-001"
            sample_dir = run_dir / "samples" / "config_decoder_test__config_value_recovery"
            outputs_root = experiment_root / "outputs"
            chart_path = outputs_root / "task_score_heatmap.png"
            task_pages_root = outputs_root / "task_output_comparisons" / "tasks"
            run_dir.mkdir(parents=True)
            sample_dir.mkdir(parents=True)
            task_pages_root.mkdir(parents=True)
            chart_path.parent.mkdir(parents=True, exist_ok=True)
            chart_path.write_bytes(b"\x89PNG\r\n\x1a\n")
            (task_pages_root / "config_decoder_test.exe-config_value_recovery.html").write_text(
                "<html><body>task page</body></html>",
                encoding="utf-8",
            )

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
                        "status": "completed",
                        "stage": "completed",
                        "current_phase": "completed",
                        "tasks": [
                            {
                                "sample": "config_decoder_test.exe",
                                "task_id": "config_value_recovery",
                                "task_name": "Config Value Recovery",
                                "sample_task_id": "config_decoder_test.exe::config_value_recovery",
                                "status": "completed",
                                "judge_status": "pass",
                                "score": 92.0,
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
                        "task_query": "Recover the config strings.",
                        "agent_result": {
                            "status": "completed",
                            "final_report": "Recovered config strings.",
                        },
                        "metrics": {
                            "analysis_status": "completed",
                            "judge_status": "pass",
                            "overall_score": 92.0,
                        },
                    }
                ),
                encoding="utf-8",
            )
            (sample_dir / "agent_result.json").write_text(
                json.dumps({"status": "completed", "final_report": "Recovered config strings."}),
                encoding="utf-8",
            )
            (outputs_root / "chart_manifest.json").write_text(
                json.dumps(
                    {
                        "ok": True,
                        "created_files": [
                            {
                                "path": str(chart_path),
                                "title": "Task Score Heatmap",
                                "description": "Heatmap for task-level score shifts.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (outputs_root / "task_output_comparisons" / "comparison_manifest.json").write_text(
                json.dumps(
                    {
                        "tasks": {
                            "config_decoder_test.exe::config_value_recovery": {
                                "sample": "config_decoder_test.exe",
                                "task_id": "config_value_recovery",
                                "task_name": "Config Value Recovery",
                                "page": "tasks/config_decoder_test.exe-config_value_recovery.html",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            detail = load_results_browser_detail(
                results_root,
                "sweep-experimental-20260402_000000-browser",
                "run-001",
                sample_name="config_decoder_test.exe",
            )

        gallery = detail["visual_gallery"]
        self.assertEqual(detail["focused_sample"], "config_decoder_test.exe")
        self.assertEqual(gallery["images"][0]["title"], "Task Score Heatmap")
        self.assertIn("/artifact?", gallery["images"][0]["url"])
        self.assertEqual(gallery["task_pages"][0]["sample_task_id"], "config_decoder_test.exe::config_value_recovery")
        self.assertIn("/artifact?", gallery["task_pages"][0]["url"])

    def test_results_browser_state_includes_experiment_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            results_root = Path(temp_dir) / "results"
            experiment_root = results_root / "experiments" / "sweep-experimental-20260402_000000-analysis"
            run_dir = results_root / "runs" / "run-001"
            outputs_root = experiment_root / "outputs"
            experiment_root.mkdir(parents=True)
            run_dir.mkdir(parents=True)
            (outputs_root / "task_output_comparisons").mkdir(parents=True)
            chart_path = outputs_root / "baseline_vs_variant_scores.png"
            chart_path.write_bytes(b"\x89PNG\r\n\x1a\n")
            (experiment_root / "experiment_manifest.json").write_text(
                json.dumps(
                    {
                        "corpus": "experimental",
                        "selected_samples": ["config_decoder_test.exe"],
                        "selected_task_keys": [
                            "config_decoder_test.exe::default_analysis",
                            "config_decoder_test.exe::config_value_recovery",
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
                                "architecture": "balanced",
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
                json.dumps({"status": "completed", "stage": "completed", "current_phase": "completed", "tasks": []}),
                encoding="utf-8",
            )
            (experiment_root / "variant_summary.csv").write_text(
                "\n".join(
                    [
                        "variant_id,display_label,changed_variable,is_baseline,overall_score_mean,overall_score_stddev,score_delta,task_success_rate,task_success_delta,analysis_failure_rate,completed_repetitions,planned_repetitions,included_in_complete_aggregate",
                        "baseline,baseline,baseline,True,70.0,1.5,,0.80,,0.00,3,3,True",
                        "worker_subagents__single_generalist,worker_subagents:single_generalist,worker_subagents,False,76.0,2.1,6.0,0.84,0.04,0.00,3,3,True",
                        "worker_prompt_shape__empty,worker_prompt_shape:empty,worker_prompt_shape,False,81.0,4.2,11.0,0.90,0.10,0.05,3,3,True",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (experiment_root / "task_comparison.csv").write_text(
                "\n".join(
                    [
                        "variant_id,display_label,changed_variable,sample,task_id,task_name,sample_task_id,score,baseline_score,score_delta,task_success_rate",
                        "worker_subagents__single_generalist,worker_subagents:single_generalist,worker_subagents,config_decoder_test.exe,config_value_recovery,Config Value Recovery,config_decoder_test.exe::config_value_recovery,84.0,75.0,9.0,1.0",
                        "worker_prompt_shape__empty,worker_prompt_shape:empty,worker_prompt_shape,config_decoder_test.exe,config_value_recovery,Config Value Recovery,config_decoder_test.exe::config_value_recovery,92.0,75.0,17.0,1.0",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (outputs_root / "chart_manifest.json").write_text(
                json.dumps(
                    {
                        "ok": True,
                        "created_files": [
                            {
                                "path": str(chart_path),
                                "title": "Baseline vs Variant Mean Score",
                                "description": "Overview chart with error bars.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (outputs_root / "task_output_comparisons" / "comparison_manifest.json").write_text(
                json.dumps(
                    {
                        "tasks": {
                            "config_decoder_test.exe::config_value_recovery": {
                                "sample": "config_decoder_test.exe",
                                "task_id": "config_value_recovery",
                                "task_name": "Config Value Recovery",
                                "page": "tasks/config_decoder_test.exe-config_value_recovery.html",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            state = load_results_browser_state(results_root, "sweep-experimental-20260402_000000-analysis")

        analysis = state["experiment_analysis"]
        self.assertEqual(analysis["configuration_count"], 3)
        self.assertEqual(analysis["best_variant"]["display_label"], "worker_prompt_shape:empty")
        self.assertEqual(analysis["widest_task_shift"]["sample_task_id"], "config_decoder_test.exe::config_value_recovery")
        self.assertEqual(analysis["chart_sections"][0]["key"], "overview")
        self.assertEqual(analysis["chart_sections"][0]["images"][0]["title"], "Baseline vs Variant Mean Score")
        self.assertEqual(len(analysis["task_matrix_columns"]), 2)
        self.assertEqual(analysis["task_matrix_rows"][0]["sample_task_id"], "config_decoder_test.exe::config_value_recovery")
        self.assertIn("worker_subagents__single_generalist", analysis["task_matrix_rows"][0]["configs"])
        self.assertIn("worker_prompt_shape__empty", analysis["task_matrix_rows"][0]["configs"])

    def test_results_browser_reports_visualization_error_when_static_charts_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            results_root = Path(temp_dir) / "results"
            experiment_root = results_root / "experiments" / "sweep-experimental-20260402_000000-nocharts"
            run_dir = results_root / "runs" / "run-001"
            outputs_root = experiment_root / "outputs"
            experiment_root.mkdir(parents=True)
            run_dir.mkdir(parents=True)
            outputs_root.mkdir(parents=True)

            (experiment_root / "experiment_manifest.json").write_text(
                json.dumps(
                    {
                        "corpus": "experimental",
                        "selected_samples": ["config_decoder_test.exe"],
                        "selected_task_keys": ["config_decoder_test.exe::default_analysis"],
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
                json.dumps({"status": "completed", "stage": "completed", "current_phase": "completed", "tasks": []}),
                encoding="utf-8",
            )
            (experiment_root / "variant_summary.csv").write_text(
                "\n".join(
                    [
                        "variant_id,display_label,changed_variable,is_baseline,overall_score_mean,overall_score_stddev,score_delta,task_success_rate,task_success_delta,analysis_failure_rate,completed_repetitions,planned_repetitions,included_in_complete_aggregate",
                        "baseline,baseline,baseline,True,70.0,1.5,,0.80,,0.00,3,3,True",
                        "worker_prompt_shape__empty,worker_prompt_shape:empty,worker_prompt_shape,False,81.0,4.2,11.0,0.90,0.10,0.05,3,3,True",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (experiment_root / "task_comparison.csv").write_text(
                "\n".join(
                    [
                        "variant_id,display_label,changed_variable,sample,task_id,task_name,sample_task_id,score,baseline_score,score_delta,task_success_rate",
                        "worker_prompt_shape__empty,worker_prompt_shape:empty,worker_prompt_shape,config_decoder_test.exe,default_analysis,Default Analysis,config_decoder_test.exe::default_analysis,92.0,75.0,17.0,1.0",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (outputs_root / "visualization_error.json").write_text(
                json.dumps({"ok": False, "error": "ModuleNotFoundError: No module named 'matplotlib'"}),
                encoding="utf-8",
            )

            catalog = load_results_browser_catalog(results_root)
            state = load_results_browser_state(results_root, "sweep-experimental-20260402_000000-nocharts")
            detail = load_results_browser_detail(results_root, "sweep-experimental-20260402_000000-nocharts", "run-001")

        self.assertEqual(catalog["experiments"][0]["visualization_error"], "ModuleNotFoundError: No module named 'matplotlib'")
        self.assertEqual(state["experiment_analysis"]["visualization_error"], "ModuleNotFoundError: No module named 'matplotlib'")
        self.assertEqual(state["experiment_analysis"]["chart_count"], 0)
        self.assertTrue(state["experiment_analysis"]["variant_rows"])
        self.assertEqual(detail["visual_gallery"]["visualization_error"], "ModuleNotFoundError: No module named 'matplotlib'")


if __name__ == "__main__":
    unittest.main()
