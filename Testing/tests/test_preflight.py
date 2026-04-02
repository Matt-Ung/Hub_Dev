import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from Testing.harness.preflight import _module_available_in_python, validate_run_configuration


class PreflightModuleProbeTests(unittest.TestCase):
    def test_module_probe_uses_subprocess_for_symlinked_venv_python(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            link_path = Path(tmpdir) / "venv-python"
            os.symlink(sys.executable, link_path)

            with patch("Testing.harness.preflight.subprocess.run") as run_mock:
                run_mock.return_value = Mock(returncode=0)
                ok = _module_available_in_python(str(link_path), "json")

        self.assertTrue(ok)
        run_mock.assert_called_once()

    def test_validate_run_configuration_rejects_unknown_worker_role_prompt_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_path = Path(tmpdir) / "sample.exe"
            sample_path.write_bytes(b"MZ")
            manifest = {
                "samples": {
                    "sample.exe": {
                        "sample": "sample.exe",
                        "difficulty": "easy",
                        "default_query": "Analyze this binary.",
                        "tasks": [
                            {
                                "task_id": "default_analysis",
                                "name": "Default Analysis",
                                "query": "Analyze this binary.",
                                "expected_evidence": ["entrypoint"],
                                "acceptance_targets": ["purpose"],
                            }
                        ],
                    }
                },
                "sample_order": ["sample.exe"],
            }

            with patch("Testing.harness.preflight._module_available_in_python", return_value=True):
                result = validate_run_configuration(
                    corpus_name="experimental",
                    sample_paths=[sample_path],
                    manifest=manifest,
                    selected_samples=[],
                    selected_task_ids=[],
                    selected_difficulties=[],
                    pipeline="auto_triage",
                    architecture="balanced",
                    query_variant="default",
                    worker_persona_profile="default",
                    worker_role_prompt_mode="surprise",
                    validator_review_level="default",
                    tool_profile="full",
                    judge_mode="agent",
                    explicit_judge_model="openai:gpt-4o-mini",
                    forced_model="",
                    python_executable=sys.executable,
                    bundle_root=None,
                    require_ready_bundles=False,
                )

        self.assertFalse(result["ok"])
        self.assertTrue(
            any("worker_role_prompt_mode" in str(item) for item in (result.get("errors") or []))
        )


if __name__ == "__main__":
    unittest.main()
