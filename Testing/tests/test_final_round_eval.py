import json
import unittest
from pathlib import Path

from Testing.harness.judge import _build_judge_payload
from Testing.harness.samples import load_sample_manifest, model_visible_sample_metadata, resolve_sample_tasks


class FinalRoundManifestTests(unittest.TestCase):
    def test_final_round_manifest_uses_opaque_runtime_names(self) -> None:
        manifest = load_sample_manifest("final_round")
        sample_meta = manifest["samples"]["sample1.exe"]
        visible = model_visible_sample_metadata(sample_meta)

        self.assertEqual(sample_meta["original_source_name"], "Emotet")
        self.assertEqual(
            sample_meta["reference_json_path"],
            "Testing/sources/final_round/reference/sample1.json",
        )
        self.assertEqual(visible["sample"], "sample1.exe")
        self.assertNotIn("original_source_name", visible)
        self.assertNotIn("reference_json_path", visible)

    def test_final_round_reference_file_exists(self) -> None:
        manifest = load_sample_manifest("final_round")
        sample_meta = manifest["samples"]["sample1.exe"]
        reference_path = Path(sample_meta["reference_json_path"])

        self.assertTrue(reference_path.exists())

    def test_final_round_manifest_exposes_only_default_analysis_task(self) -> None:
        tasks = resolve_sample_tasks("final_round", "sample1.exe")
        task_ids = [task["task_id"] for task in tasks]

        self.assertEqual(task_ids, ["default_analysis"])

    def test_final_round_judge_payload_includes_evaluator_reference_only(self) -> None:
        manifest = load_sample_manifest("final_round")
        sample_meta = manifest["samples"]["sample1.exe"]
        task_meta = resolve_sample_tasks("final_round", "sample1.exe")[0]

        payload_text = _build_judge_payload(
            "sample1.exe",
            sample_meta,
            task_meta,
            bundle_manifest={},
            agent_result={"ok": True, "final_report": "test"},
            rubric={"dimensions": []},
        )
        payload_json = payload_text.split("```json\n", 1)[1].rsplit("\n```", 1)[0]
        payload = json.loads(payload_json)

        self.assertNotIn("reference_json_path", payload["sample_metadata"])
        self.assertIn("evaluator_reference", payload)
        self.assertIn("must_hit_anchors", payload["evaluator_reference"])
        self.assertIn("SystemService", "\n".join(payload["evaluator_reference"]["must_hit_anchors"]))


if __name__ == "__main__":
    unittest.main()
