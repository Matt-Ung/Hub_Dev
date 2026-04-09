import unittest

from Testing.harness.tool_redundancy import normalize_tool_call_entries, summarize_tool_call_redundancy


class ToolRedundancyTests(unittest.TestCase):
    def test_semantic_redundancy_detects_near_equivalent_calls(self) -> None:
        entries = [
            {
                "stage": "workers",
                "kind": "tool_call",
                "tool_name": "callStrings",
                "args": {"file_path": "/tmp/sample.exe", "min_len": 4},
                "source": "worker.alpha",
            },
            {
                "stage": "workers",
                "kind": "tool_call",
                "tool_name": "list_strings",
                "args": {"file_path": "/tmp/sample.exe", "min_length": 6},
                "source": "worker.beta",
            },
            {
                "stage": "workers",
                "kind": "tool_call",
                "tool_name": "decompile_function_by_address",
                "args": {"address": "140001400"},
                "source": "worker.alpha",
            },
            {
                "stage": "workers",
                "kind": "tool_call",
                "tool_name": "decompile_function_by_address",
                "args": {"address": "0x140001400"},
                "source": "worker.beta",
            },
            {
                "stage": "workers",
                "kind": "tool_cache_hit",
                "tool_name": "decompile_function_by_address",
                "server_id": "ghidramcp",
                "args": {"address": "0x140001400"},
            },
        ]

        normalized = normalize_tool_call_entries(entries)
        summary = summarize_tool_call_redundancy(entries, normalized_calls=normalized)

        self.assertEqual(len(normalized), 4)
        self.assertFalse(normalized[0]["is_semantic_repeat"])
        self.assertTrue(normalized[1]["is_semantic_repeat"])
        self.assertTrue(normalized[3]["is_exact_repeat"])
        self.assertEqual(summary["total_tool_calls"], 4)
        self.assertEqual(summary["exact_duplicate_calls"], 1)
        self.assertEqual(summary["semantic_duplicate_calls"], 2)
        self.assertEqual(summary["cache_event_counts"]["tool_cache_hit"], 1)
        self.assertEqual(summary["top_duplicate_targets"][0]["semantic_target_kind"], "function")
        self.assertEqual(summary["top_duplicate_targets"][0]["semantic_target_label"], "0x140001400")

        strings_target = next(
            item
            for item in summary["top_duplicate_targets"]
            if item["tool_family"] == "strings_scan"
        )
        self.assertEqual(strings_target["duplicate_calls"], 1)
        self.assertEqual(strings_target["semantic_target_label"], "/tmp/sample.exe")


if __name__ == "__main__":
    unittest.main()
