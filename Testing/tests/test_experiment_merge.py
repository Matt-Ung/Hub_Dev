import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Testing.harness.experiment_merge import merge_experiments, plan_merged_experiment


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class ExperimentMergeTests(unittest.TestCase):
    def _make_experiment(
        self,
        root: Path,
        name: str,
        *,
        planned_runs: list[dict],
        run_entries: list[dict],
        selected_samples: list[str] | None = None,
        selected_task_keys: list[str] | None = None,
        repetitions: int = 3,
    ) -> Path:
        experiment_root = root / name
        experiment_root.mkdir(parents=True, exist_ok=True)
        _write_json(
            experiment_root / "experiment_manifest.json",
            {
                "experiment_id": name,
                "corpus": "experimental",
                "selected_samples": selected_samples or ["config_decoder_test_stripped.exe", "config_decoder_test_upx_stripped.exe"],
                "selected_task_keys": selected_task_keys
                or [
                    "config_decoder_test_stripped.exe::default_analysis",
                    "config_decoder_test_upx_stripped.exe::default_analysis",
                ],
                "repetitions": repetitions,
                "planned_runs": planned_runs,
            },
        )
        _write_json(experiment_root / "run_catalog.json", {"runs": run_entries})
        return experiment_root

    def _make_run(self, root: Path, run_id: str, *, variant_id: str, display_label: str, replicate_index: int) -> dict:
        run_dir = root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        _write_json(
            run_dir / "run_manifest.json",
            {
                "run_id": run_id,
                "config_lineage_id": f"{variant_id}-{replicate_index}",
                "pipeline": "auto_triage",
                "architecture": "balanced",
            },
        )
        _write_json(
            run_dir / "aggregate.json",
            {
                "records": [{"sample_task_id": "config_decoder_test_stripped::default_analysis"}],
                "expected_task_count": 1,
                "task_completion_rate": 1.0,
                "overall_score_mean": 75.0,
                "task_success_rate": 1.0,
            },
        )
        return {
            "run_id": run_id,
            "run_dir": str(run_dir),
            "variant_id": variant_id,
            "display_label": display_label,
            "replicate_index": replicate_index,
            "ok": True,
            "status": "completed",
        }

    def test_plan_merged_experiment_uses_primary_baseline_and_secondary_variants(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            runs_root = root / "runs"
            primary_runs = [
                self._make_run(runs_root, "primary-baseline-r1", variant_id="baseline", display_label="baseline", replicate_index=1),
                self._make_run(
                    runs_root,
                    "primary-worker-r1",
                    variant_id="worker_subagents__single_generalist",
                    display_label="worker_subagents:single_generalist",
                    replicate_index=1,
                ),
            ]
            secondary_runs = [
                self._make_run(runs_root, "secondary-baseline-r1", variant_id="baseline", display_label="baseline", replicate_index=1),
                self._make_run(
                    runs_root,
                    "secondary-empty-r1",
                    variant_id="worker_prompt_shape__empty",
                    display_label="worker_prompt_shape:empty",
                    replicate_index=1,
                ),
            ]
            primary = self._make_experiment(
                root,
                "primary-exp",
                planned_runs=[
                    {"variant_id": "baseline", "display_label": "baseline", "pipeline": "auto_triage", "architecture": "balanced"},
                    {"variant_id": "worker_subagents__single_generalist", "display_label": "worker_subagents:single_generalist"},
                ],
                run_entries=primary_runs,
            )
            secondary = self._make_experiment(
                root,
                "secondary-exp",
                planned_runs=[
                    {"variant_id": "baseline", "display_label": "baseline", "pipeline": "auto_triage", "architecture": "balanced"},
                    {"variant_id": "worker_prompt_shape__empty", "display_label": "worker_prompt_shape:empty"},
                ],
                run_entries=secondary_runs,
            )

            plan = plan_merged_experiment(primary, additional_experiments=[secondary], output_experiment_id="merged-exp")

        self.assertEqual(plan["variant_count"], 3)
        self.assertEqual(
            [row["variant_id"] for row in plan["run_plans"]],
            ["baseline", "worker_subagents__single_generalist", "worker_prompt_shape__empty"],
        )

    def test_merge_experiments_materializes_combined_run_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            runs_root = root / "runs"
            primary = self._make_experiment(
                root,
                "primary-exp",
                planned_runs=[
                    {"variant_id": "baseline", "display_label": "baseline", "pipeline": "auto_triage", "architecture": "balanced"},
                    {"variant_id": "worker_subagents__single_generalist", "display_label": "worker_subagents:single_generalist"},
                ],
                run_entries=[
                    self._make_run(runs_root, "primary-baseline-r1", variant_id="baseline", display_label="baseline", replicate_index=1),
                    self._make_run(
                        runs_root,
                        "primary-worker-r1",
                        variant_id="worker_subagents__single_generalist",
                        display_label="worker_subagents:single_generalist",
                        replicate_index=1,
                    ),
                ],
            )
            secondary = self._make_experiment(
                root,
                "secondary-exp",
                planned_runs=[
                    {"variant_id": "baseline", "display_label": "baseline", "pipeline": "auto_triage", "architecture": "balanced"},
                    {"variant_id": "worker_prompt_shape__empty", "display_label": "worker_prompt_shape:empty"},
                ],
                run_entries=[
                    self._make_run(runs_root, "secondary-baseline-r1", variant_id="baseline", display_label="baseline", replicate_index=1),
                    self._make_run(
                        runs_root,
                        "secondary-empty-r1",
                        variant_id="worker_prompt_shape__empty",
                        display_label="worker_prompt_shape:empty",
                        replicate_index=1,
                    ),
                ],
            )

            with patch("Testing.harness.experiment_merge.materialize_experiment_outputs") as materialize_mock:
                materialize_mock.return_value = {"complete_variant_ids": ["baseline", "worker_subagents__single_generalist", "worker_prompt_shape__empty"]}
                result = merge_experiments(primary, additional_experiments=[secondary], output_root=root / "merged")

            args = materialize_mock.call_args.kwargs
            merged_entries = args["run_entries"]
            merged_manifest = args["experiment_manifest"]

        self.assertEqual(len(merged_entries), 3)
        self.assertEqual(
            sorted(entry["variant_id"] for entry in merged_entries),
            ["baseline", "worker_prompt_shape__empty", "worker_subagents__single_generalist"],
        )
        self.assertEqual(
            [item["variant_id"] for item in merged_manifest["planned_runs"]],
            ["baseline", "worker_subagents__single_generalist", "worker_prompt_shape__empty"],
        )
        self.assertEqual(result["merged_run_count"], 3)


if __name__ == "__main__":
    unittest.main()
