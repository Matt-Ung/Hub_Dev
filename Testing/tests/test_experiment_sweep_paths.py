import tempfile
import unittest
from pathlib import Path
import shutil

from Testing.harness.experiment_sweep import _resolve_sweep_root
from Testing.harness.paths import PREFLIGHT_ROOT, RESULTS_ROOT


class ExperimentSweepPathTests(unittest.TestCase):
    def test_preflight_only_uses_dedicated_preflight_root(self) -> None:
        root = _resolve_sweep_root(
            corpus_name="final_round",
            label="unit-test",
            preflight_only=True,
        )

        try:
            self.assertTrue(str(root).startswith(str(PREFLIGHT_ROOT)))
            self.assertEqual(root.parent, PREFLIGHT_ROOT)
            self.assertIn("preflight-final_round-", root.name)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_preflight_only_rejects_resume(self) -> None:
        with self.assertRaises(SystemExit):
            _resolve_sweep_root(
                corpus_name="experimental",
                resume_path="some-existing-experiment",
                preflight_only=True,
            )

    def test_resume_reuses_existing_experiment_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            experiment_root = Path(temp_dir) / "sweep-experimental-20260408_000000-test"
            experiment_root.mkdir(parents=True)

            resolved = _resolve_sweep_root(
                corpus_name="experimental",
                resume_path=str(experiment_root),
                preflight_only=False,
            )

            self.assertEqual(resolved, experiment_root)

    def test_real_runs_still_use_experiments_root(self) -> None:
        root = _resolve_sweep_root(
            corpus_name="experimental",
            label="unit-test",
            preflight_only=False,
        )

        try:
            self.assertTrue(str(root).startswith(str(RESULTS_ROOT / "experiments")))
            self.assertEqual(root.parent, RESULTS_ROOT / "experiments")
            self.assertIn("sweep-experimental-", root.name)
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
