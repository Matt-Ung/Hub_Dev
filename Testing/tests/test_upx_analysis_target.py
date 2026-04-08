import tempfile
import unittest
from pathlib import Path
import sys
import types
from unittest.mock import patch

from Testing.harness.artifacts import build_artifact_servers_manifest, resolve_analysis_bundle
from Testing.harness.launch_presets import build_launch_preset_command
from Testing.harness.paths import DEFAULT_SERVERS_MANIFEST, read_json, write_json

if "pydantic_ai" not in sys.modules:
    pydantic_ai_stub = types.ModuleType("pydantic_ai")
    pydantic_ai_stub.ModelMessage = object
    sys.modules["pydantic_ai"] = pydantic_ai_stub
if "pydantic_ai.messages" not in sys.modules:
    messages_stub = types.ModuleType("pydantic_ai.messages")
    for name in (
        "FunctionToolCallEvent",
        "FunctionToolResultEvent",
        "ModelRequest",
        "ModelResponse",
        "RetryPromptPart",
        "ToolCallPart",
        "ToolReturnPart",
        "UserPromptPart",
    ):
        setattr(messages_stub, name, type(name, (), {}))
    sys.modules["pydantic_ai.messages"] = messages_stub

from multi_agent_wf.shared_state import _new_shared_state, apply_automation_payload_to_state


class UpxAnalysisTargetTests(unittest.TestCase):
    def _write_bundle(self, bundle_dir: Path, sample_path: Path, *, corpus: str = "experimental") -> None:
        bundle_dir.mkdir(parents=True, exist_ok=True)
        write_json(
            bundle_dir / "bundle_manifest.json",
            {
                "corpus": corpus,
                "identity": {
                    "path": str(sample_path.resolve()),
                    "name": sample_path.name,
                    "md5": "a" * 32,
                    "sha256": "b" * 64,
                },
                "manifest": {"sample": "sample.exe"},
            },
        )
        write_json(
            bundle_dir / "automation_payload.json",
            {
                "source": "headless_batch",
                "corpus": corpus,
                "program_name": sample_path.name,
                "executable_path": str(sample_path.resolve()),
                "executable_md5": "a" * 32,
                "executable_sha256": "b" * 64,
            },
        )
        write_json(bundle_dir / "ghidra_analysis.json", {"program": {"name": sample_path.name}})

    def test_resolve_analysis_bundle_prefers_existing_upx_derived_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            original_sample = root / "packed.exe"
            original_sample.write_bytes(b"MZpacked")
            bundle_dir = root / "bundle"
            self._write_bundle(bundle_dir, original_sample)

            derived_output = root / "bundle" / "derived" / "upx_unpacked_binary" / "packed_upx_unpacked.exe"
            derived_output.parent.mkdir(parents=True, exist_ok=True)
            derived_output.write_bytes(b"MZunpacked")
            derived_bundle_dir = root / "bundle" / "derived" / "upx_unpacked" / "packed_upx_unpacked"
            self._write_bundle(derived_bundle_dir, derived_output)

            def _inspect(bundle_path: Path, **_: object) -> dict:
                if Path(bundle_path).resolve() == derived_bundle_dir.resolve():
                    return {"ready_for_analysis": True, "fresh_for_analysis": True}
                return {"ready_for_analysis": True, "fresh_for_analysis": False}

            with patch("Testing.harness.artifacts._run_upx_test", return_value={"available": True, "ok": True, "recognized": True}), patch(
                "Testing.harness.artifacts.resolve_analyze_headless", return_value=Path("/fake/analyzeHeadless")
            ), patch("Testing.harness.artifacts.inspect_bundle_dir", side_effect=_inspect):
                resolved = resolve_analysis_bundle(bundle_dir, prefer_upx_unpacked=True)

        self.assertEqual(Path(resolved["bundle_dir"]).resolve(), derived_bundle_dir.resolve())
        self.assertEqual(resolved["analysis_target"]["kind"], "upx_unpacked")
        self.assertTrue(resolved["analysis_target"]["packed_detected"])
        self.assertEqual(resolved["automation_payload"]["analysis_target"]["kind"], "upx_unpacked")

    def test_resolve_analysis_bundle_falls_back_when_unpack_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            original_sample = root / "packed.exe"
            original_sample.write_bytes(b"MZpacked")
            bundle_dir = root / "bundle"
            self._write_bundle(bundle_dir, original_sample)

            with patch("Testing.harness.artifacts._run_upx_test", return_value={"available": True, "ok": True, "recognized": True}), patch(
                "Testing.harness.artifacts.resolve_analyze_headless", return_value=Path("/fake/analyzeHeadless")
            ), patch(
                "Testing.harness.artifacts._run_upx_unpack",
                return_value={"available": True, "ok": False, "output_exists": False, "error": "test failure"},
            ):
                resolved = resolve_analysis_bundle(bundle_dir, prefer_upx_unpacked=True)

        self.assertEqual(Path(resolved["bundle_dir"]).resolve(), bundle_dir.resolve())
        self.assertEqual(resolved["analysis_target"]["kind"], "original")
        self.assertTrue(resolved["analysis_target"]["packed_detected"])
        self.assertIn("unpacking failed", resolved["analysis_target"]["selection_reason"].lower())

    def test_resolve_analysis_bundle_falls_back_when_shared_derived_lock_times_out(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            original_sample = root / "packed.exe"
            original_sample.write_bytes(b"MZpacked")
            bundle_dir = root / "bundle"
            self._write_bundle(bundle_dir, original_sample)

            with patch("Testing.harness.artifacts._run_upx_test", return_value={"available": True, "ok": True, "recognized": True}), patch(
                "Testing.harness.artifacts.resolve_analyze_headless", return_value=Path("/fake/analyzeHeadless")
            ), patch(
                "Testing.harness.artifacts._bundle_materialization_lock",
                side_effect=TimeoutError("Timed out waiting for the shared UPX-derived bundle lock"),
            ):
                resolved = resolve_analysis_bundle(bundle_dir, prefer_upx_unpacked=True)

        self.assertEqual(Path(resolved["bundle_dir"]).resolve(), bundle_dir.resolve())
        self.assertEqual(resolved["analysis_target"]["kind"], "original")
        self.assertIn("timed out waiting", resolved["analysis_target"]["selection_reason"].lower())

    def test_apply_automation_payload_tracks_unpacked_target_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            unpacked = root / "unpacked.exe"
            original = root / "packed.exe"
            unpacked.write_bytes(b"MZunpacked")
            original.write_bytes(b"MZpacked")
            state = {"shared_state": _new_shared_state()}
            payload = {
                "source": "headless_batch",
                "executable_path": str(unpacked.resolve()),
                "executable_md5": "1" * 32,
                "executable_sha256": "2" * 64,
                "analysis_target": {
                    "kind": "upx_unpacked",
                    "selection_reason": "UPX detected; using unpacked target.",
                    "effective_executable_path": str(unpacked.resolve()),
                    "packed_detected": True,
                    "packer": "upx",
                },
                "original_sample": {
                    "path": str(original.resolve()),
                    "md5": "3" * 32,
                    "sha256": "4" * 64,
                },
                "upx_detection": {"recognized": True},
                "upx_unpack": {"ok": True, "output_path": str(unpacked.resolve())},
            }

            apply_automation_payload_to_state(state, payload)

        shared = state["shared_state"]
        self.assertEqual(shared["validated_sample_path"], str(unpacked.resolve()))
        self.assertEqual(shared["analysis_target_kind"], "upx_unpacked")
        self.assertEqual(shared["analysis_target_original_path"], str(original.resolve()))
        self.assertTrue(shared["analysis_target_packed_detected"])
        self.assertEqual(shared["analysis_target_packer"], "upx")
        self.assertTrue(shared["upx_unpack"]["ok"])

    def test_launch_preset_builder_forwards_prefer_unpacked_upx_flag(self) -> None:
        command = build_launch_preset_command(
            "sanity_core_slice_r1",
            explicit_judge_model="openai:gpt-4o-mini",
            prefer_upx_unpacked=True,
        )

        self.assertIn("--prefer-unpacked-upx", command)

    def test_artifact_manifest_omits_upx_server_for_unpacked_analysis_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            bundle_dir = root / "bundle"
            bundle_dir.mkdir(parents=True, exist_ok=True)
            output_path = root / "servers.json"

            build_artifact_servers_manifest(
                bundle_dir,
                output_path,
                tool_profile="full",
                analysis_target_kind="upx_unpacked",
            )
            manifest = read_json(output_path)
            raw_manifest = read_json(DEFAULT_SERVERS_MANIFEST)

        self.assertNotIn("upxmcp", manifest)
        self.assertIn("upxmcp", raw_manifest)
        self.assertIn("ghidramcp", manifest)

    def test_artifact_manifest_keeps_upx_server_for_original_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            bundle_dir = root / "bundle"
            bundle_dir.mkdir(parents=True, exist_ok=True)
            output_path = root / "servers.json"

            build_artifact_servers_manifest(
                bundle_dir,
                output_path,
                tool_profile="full",
                analysis_target_kind="original",
            )
            manifest = read_json(output_path)

        self.assertIn("upxmcp", manifest)


if __name__ == "__main__":
    unittest.main()
