import unittest

from Testing.harness.launch_presets import build_launch_preset_command, resolve_launch_preset


class LaunchPresetTests(unittest.TestCase):
    def test_single_run_preset_includes_run_level_overrides(self) -> None:
        command = build_launch_preset_command(
            "compare_minimal_architecture_decoder",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertIn("Testing/run_evaluation.py", command)
        self.assertIn("--sample", command)
        self.assertIn("config_decoder_test.exe", command)
        self.assertIn("--task", command)
        self.assertIn("config_value_recovery", command)
        self.assertIn("--architecture", command)
        self.assertIn("minimal", command)
        self.assertNotIn("--timeout-sec", command)

    def test_full_suite_r1_preset_sets_single_repetition(self) -> None:
        command = build_launch_preset_command(
            "full_suite_default_r1",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertIn("Testing/run_experiment_sweep.py", command)
        self.assertIn("--repetitions", command)
        repetition_index = command.index("--repetitions")
        self.assertEqual(command[repetition_index + 1], "1")

    def test_quiet_alias_marks_wrapper_level_quiet_output(self) -> None:
        preset = resolve_launch_preset("paid_narrow_pilot_quiet")

        self.assertTrue(bool(preset.get("quiet_child_output")))

    def test_budget_best_value_preset_carries_label_and_budget_ceiling(self) -> None:
        command = build_launch_preset_command(
            "budget_best_value_r2",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertIn("--label", command)
        label_index = command.index("--label")
        self.assertEqual(command[label_index + 1], "budget-best-value")
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

    def test_broad_coverage_preset_includes_custom_config(self) -> None:
        command = build_launch_preset_command(
            "coverage_broad_r1_60usd",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertIn("--config", command)
        config_index = command.index("--config")
        self.assertEqual(command[config_index + 1], "Testing/config/experiment_sweeps_broad_coverage_r1.json")


if __name__ == "__main__":
    unittest.main()
