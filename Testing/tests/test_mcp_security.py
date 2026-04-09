import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import artifact_paths

try:
    from MCPServers import bridge_mcp_ghidra
except ModuleNotFoundError:
    bridge_mcp_ghidra = None


class ArtifactPathSecurityTests(unittest.TestCase):
    def test_per_type_override_must_stay_under_agent_artifact_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "agent_artifacts"
            outside = Path(temp_dir) / "outside_reports"
            env = {
                "AGENT_ARTIFACT_DIR": str(root),
                "AGENT_REPORT_ARTIFACT_DIR": str(outside),
            }
            with mock.patch.dict(os.environ, env, clear=False):
                with self.assertRaisesRegex(ValueError, "must stay under the configured root"):
                    artifact_paths.get_agent_artifact_dir("reports")

    def test_relative_override_cannot_escape_agent_artifact_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "agent_artifacts"
            env = {
                "AGENT_ARTIFACT_DIR": str(root),
                "AGENT_PYTHON_ARTIFACT_DIR": "../desktop_escape",
            }
            with mock.patch.dict(os.environ, env, clear=False):
                with self.assertRaisesRegex(ValueError, "must stay under the configured root"):
                    artifact_paths.get_agent_artifact_dir("python")

    def test_tool_output_path_must_stay_under_scoped_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "agent_artifacts"
            outside = Path(temp_dir) / "Desktop" / "patched.exe"
            env = {
                "AGENT_ARTIFACT_DIR": str(root),
            }
            with mock.patch.dict(os.environ, env, clear=False):
                with self.assertRaisesRegex(ValueError, "must stay under the configured root"):
                    artifact_paths.resolve_tool_output_path("binary_patch", str(outside))

    def test_tool_output_path_accepts_relative_path_under_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "agent_artifacts"
            env = {
                "AGENT_ARTIFACT_DIR": str(root),
            }
            with mock.patch.dict(os.environ, env, clear=False):
                resolved = artifact_paths.resolve_tool_output_path("upx", "session_01/unpacked.exe")
                self.assertTrue(str(resolved).startswith(str(root.resolve())))
                self.assertEqual(resolved.name, "unpacked.exe")


@unittest.skipIf(bridge_mcp_ghidra is None, "bridge_mcp_ghidra dependencies are unavailable in this test environment")
class GhidraMcpSecurityTests(unittest.TestCase):
    def test_mutating_calls_are_disabled_by_default(self) -> None:
        original = bridge_mcp_ghidra.ghidra_allow_mutations
        bridge_mcp_ghidra.ghidra_allow_mutations = False
        try:
            called = {"value": False}

            def live_callable() -> str:
                called["value"] = True
                return "ok"

            result = bridge_mcp_ghidra._call_mutating_with_fallback("rename_function", live_callable)
            self.assertIn("disabled by default", result)
            self.assertFalse(called["value"])
        finally:
            bridge_mcp_ghidra.ghidra_allow_mutations = original

    def test_remote_ghidra_server_url_rejected_by_default(self) -> None:
        original = bridge_mcp_ghidra.ghidra_allow_remote_server
        bridge_mcp_ghidra.ghidra_allow_remote_server = False
        try:
            with self.assertRaisesRegex(ValueError, "remote Ghidra server URLs are disabled by default"):
                bridge_mcp_ghidra._validated_ghidra_server_url("http://10.10.10.10:8080/")
        finally:
            bridge_mcp_ghidra.ghidra_allow_remote_server = original


if __name__ == "__main__":
    unittest.main()
