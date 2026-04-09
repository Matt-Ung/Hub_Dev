import json
import tempfile
import unittest
from pathlib import Path

from Testing.harness.archive_results_browser import (
    load_archive_results_browser_catalog,
    load_archive_results_browser_detail,
    load_archive_results_browser_state,
)


class ArchiveResultsBrowserTests(unittest.TestCase):
    def test_archive_browser_reads_legacy_experiment_and_run_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_root = Path(temp_dir) / "archive" / "results_legacy"
            experiment_root = archive_root / "experiments" / "sweep-experimental-20260402_000000-legacy"
            run_root = archive_root / "runs" / "run-001"
            sample_dir = run_root / "samples" / "config_decoder_test__config_value_recovery"
            log_path = experiment_root / "live_view" / "logs" / "run-001.log"

            sample_dir.mkdir(parents=True, exist_ok=True)
            log_path.parent.mkdir(parents=True, exist_ok=True)

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
                                "run_dir": "/old/location/Testing/results/runs/run-001",
                                "log_path": "/old/location/Testing/results/experiments/sweep-experimental-20260402_000000-legacy/live_view/logs/run-001.log",
                                "display_label": "baseline",
                                "status": "completed",
                                "changed_variable": "baseline",
                                "pipeline": "auto_triage",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (run_root / "run_manifest.json").write_text(
                json.dumps({"pipeline": "auto_triage", "architecture": "balanced"}),
                encoding="utf-8",
            )
            (sample_dir / "record.json").write_text(
                json.dumps(
                    {
                        "sample": "config_decoder_test.exe",
                        "task_id": "config_value_recovery",
                        "task_name": "Config Value Recovery",
                        "sample_task_id": "config_decoder_test.exe::config_value_recovery",
                    }
                ),
                encoding="utf-8",
            )
            (sample_dir / "agent_result.json").write_text(
                json.dumps({"final_report": "Recovered config strings."}),
                encoding="utf-8",
            )
            (sample_dir / "judge_result.json").write_text(
                json.dumps({"technical_summary": "Strong config recovery evidence."}),
                encoding="utf-8",
            )
            log_path.write_text("legacy log line\n", encoding="utf-8")

            catalog = load_archive_results_browser_catalog(archive_root)
            state = load_archive_results_browser_state(archive_root, "sweep-experimental-20260402_000000-legacy")
            detail = load_archive_results_browser_detail(archive_root, "sweep-experimental-20260402_000000-legacy", "run-001")

        self.assertEqual(catalog["experiments"][0]["experiment_id"], "sweep-experimental-20260402_000000-legacy")
        self.assertEqual(state["summary"]["total_runs"], 1)
        self.assertEqual(state["runs"][0]["run_dir"], str(run_root.resolve()))
        self.assertIn("config_value_recovery", detail["selected_task_text"])
        self.assertIn("Recovered config strings.", detail["agent_output"])
        self.assertIn("Strong config recovery evidence.", detail["judge_output"])
        self.assertIn("legacy log line", detail["server_log"])


if __name__ == "__main__":
    unittest.main()
