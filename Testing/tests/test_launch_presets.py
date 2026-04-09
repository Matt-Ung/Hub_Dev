import unittest

from Testing.harness.launch_checks import build_launch_preset_projection_report
from Testing.harness.launch_presets import (
    available_launch_presets,
    build_launch_preset_command,
    resolve_launch_preset,
)
from Testing.harness.paths import repo_python_executable


class LaunchPresetTests(unittest.TestCase):
    def test_available_launch_presets_matches_curated_folder_set(self) -> None:
        self.assertEqual(
            available_launch_presets(),
            [
                "budget_best_value_r1",
                "budget_best_value_r2",
                "coverage_broad_r1_60usd",
                "sanity_core_slice_r1",
                "smoke_default_quick",
                "sweep_decoder_depth_followups_r3",
                "sweep_decoder_depth_r3",
                "thesis_final_eval_r3_100usd",
            ],
        )

    def test_smoke_preset_is_single_run_entrypoint(self) -> None:
        command = build_launch_preset_command(
            "smoke_default_quick",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertEqual(command[0], repo_python_executable())
        self.assertIn("Testing/scripts/run_evaluation.py", command)
        self.assertIn("--sample", command)
        self.assertIn("basic_loops_test.exe", command)
        self.assertIn("--task", command)
        self.assertIn("default_analysis", command)
        self.assertNotIn("--config", command)

    def test_budget_best_value_preset_skips_budget_flags_by_default(self) -> None:
        command = build_launch_preset_command(
            "budget_best_value_r2",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertIn("--label", command)
        label_index = command.index("--label")
        self.assertEqual(command[label_index + 1], "budget-best-value")
        self.assertNotIn("--enable-budget-guardrails", command)
        self.assertNotIn("--max-experiment-estimated-cost-usd", command)

    def test_budget_best_value_preset_can_opt_into_budget_flags(self) -> None:
        command = build_launch_preset_command(
            "budget_best_value_r2",
            explicit_judge_model="openai:gpt-4o-mini",
            enable_budget_guardrails=True,
        )

        self.assertIn("--enable-budget-guardrails", command)
        self.assertIn("--max-experiment-estimated-cost-usd", command)
        budget_index = command.index("--max-experiment-estimated-cost-usd")
        self.assertEqual(command[budget_index + 1], "20.0")

    def test_budget_best_value_r1_sets_single_repetition(self) -> None:
        command = build_launch_preset_command(
            "budget_best_value_r1",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertIn("--repetitions", command)
        repetition_index = command.index("--repetitions")
        self.assertEqual(command[repetition_index + 1], "1")
        self.assertIn("--config", command)
        config_index = command.index("--config")
        self.assertEqual(command[config_index + 1], "Testing/config/presets/budget_best_value_r1.json")

    def test_coverage_broad_preset_uses_self_contained_preset_config(self) -> None:
        command = build_launch_preset_command(
            "coverage_broad_r1_60usd",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertIn("--config", command)
        config_index = command.index("--config")
        self.assertEqual(command[config_index + 1], "Testing/config/presets/coverage_broad_r1_60usd.json")
        difficulties = [
            command[index + 1]
            for index, token in enumerate(command)
            if token == "--difficulty-filter" and index + 1 < len(command)
        ]
        self.assertEqual(difficulties, ["medium", "hard"])
        self.assertNotIn("--variable", command)

    def test_coverage_broad_projection_stays_under_sixty_usd(self) -> None:
        report = build_launch_preset_projection_report("coverage_broad_r1_60usd")

        self.assertEqual(report["child_runs"], 5)
        self.assertEqual(report["tasks_per_child_run"], 23)
        self.assertLess(float(report["projection"]["projected_estimated_cost_usd"]), 60.0)

    def test_decoder_depth_r3_combines_both_decoder_variants(self) -> None:
        command = build_launch_preset_command(
            "sweep_decoder_depth_r3",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        samples = [
            command[index + 1]
            for index, token in enumerate(command)
            if token == "--sample" and index + 1 < len(command)
        ]
        tasks = [
            command[index + 1]
            for index, token in enumerate(command)
            if token == "--task" and index + 1 < len(command)
        ]
        self.assertEqual(
            samples,
            [
                "config_decoder_test_stripped.exe",
                "config_decoder_test_upx_stripped.exe",
            ],
        )
        self.assertEqual(
            tasks,
            [
                "default_analysis",
                "config_value_recovery",
                "decode_parser_flow_recovery",
                "parser_validation_audit",
                "packing_decoder_triage",
            ],
        )
        self.assertIn("--config", command)
        config_index = command.index("--config")
        self.assertEqual(command[config_index + 1], "Testing/config/presets/sweep_decoder_depth_r3.json")
        self.assertIn("--prefer-unpacked-upx", command)
        self.assertIn("--repetitions", command)
        repetition_index = command.index("--repetitions")
        self.assertEqual(command[repetition_index + 1], "3")

    def test_decoder_depth_followups_r3_uses_self_contained_preset_config(self) -> None:
        command = build_launch_preset_command(
            "sweep_decoder_depth_followups_r3",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertIn("--config", command)
        config_index = command.index("--config")
        self.assertEqual(
            command[config_index + 1],
            "Testing/config/presets/sweep_decoder_depth_followups_r3.json",
        )
        tasks = [
            command[index + 1]
            for index, token in enumerate(command)
            if token == "--task" and index + 1 < len(command)
        ]
        self.assertEqual(
            tasks,
            [
                "default_analysis",
                "config_value_recovery",
                "decode_parser_flow_recovery",
                "parser_validation_audit",
                "packing_decoder_triage",
            ],
        )

    def test_thesis_final_eval_preset_uses_final_round_corpus_and_self_config(self) -> None:
        command = build_launch_preset_command(
            "thesis_final_eval_r3_100usd",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertIn("Testing/scripts/run_experiment_sweep.py", command)
        self.assertIn("--corpus", command)
        corpus_index = command.index("--corpus")
        self.assertEqual(command[corpus_index + 1], "final_round")
        self.assertIn("--config", command)
        config_index = command.index("--config")
        self.assertEqual(command[config_index + 1], "Testing/config/presets/thesis_final_eval_r3_100usd.json")
        self.assertIn("--prefer-unpacked-upx", command)
        self.assertIn("--task-failure-retries", command)
        retries_index = command.index("--task-failure-retries")
        self.assertEqual(command[retries_index + 1], "1")
        tasks = [
            command[index + 1]
            for index, token in enumerate(command)
            if token == "--task" and index + 1 < len(command)
        ]
        self.assertEqual(tasks, ["default_analysis"])

        report = build_launch_preset_projection_report("thesis_final_eval_r3_100usd")
        self.assertEqual(report["child_runs"], 24)
        self.assertEqual(report["tasks_per_child_run"], 5)
        self.assertAlmostEqual(float(report["projection"]["projected_estimated_cost_usd"]), 60.0)
        self.assertNotIn("--variable", command)
        self.assertIn("--repetitions", command)
        repetition_index = command.index("--repetitions")
        self.assertEqual(command[repetition_index + 1], "3")

    def test_sweep_launch_preset_can_forward_concurrent_repetition_override(self) -> None:
        command = build_launch_preset_command(
            "sweep_decoder_depth_r3",
            explicit_judge_model="openai:gpt-4o-mini",
            max_concurrent_repetitions=3,
        )

        self.assertIn("--max-concurrent-repetitions", command)
        concurrency_index = command.index("--max-concurrent-repetitions")
        self.assertEqual(command[concurrency_index + 1], "3")

    def test_preset_file_name_matches_declared_name(self) -> None:
        preset = resolve_launch_preset("thesis_final_eval_r3_100usd")

        self.assertEqual(preset.get("name"), "thesis_final_eval_r3_100usd")
        self.assertEqual(
            preset.get("_preset_rel_path"),
            "Testing/config/presets/thesis_final_eval_r3_100usd.json",
        )


if __name__ == "__main__":
    unittest.main()
