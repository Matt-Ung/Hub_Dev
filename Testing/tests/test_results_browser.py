import json
import os
import tempfile
import unittest
from pathlib import Path

from Testing.harness.results_browser import (
    load_results_browser_catalog,
    load_results_browser_detail,
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


if __name__ == "__main__":
    unittest.main()
