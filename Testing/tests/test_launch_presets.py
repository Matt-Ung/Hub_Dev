import unittest

from Testing.harness.launch_checks import build_launch_preset_projection_report
from Testing.harness.launch_presets import build_launch_preset_command, resolve_launch_preset
from Testing.harness.paths import repo_python_executable


class LaunchPresetTests(unittest.TestCase):
    def test_single_run_preset_includes_run_level_overrides(self) -> None:
        command = build_launch_preset_command(
            "compare_minimal_architecture_decoder",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertEqual(command[0], repo_python_executable())
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

    def test_broad_coverage_preset_includes_custom_config(self) -> None:
        command = build_launch_preset_command(
            "coverage_broad_r1_60usd",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        self.assertIn("--config", command)
        config_index = command.index("--config")
        self.assertEqual(command[config_index + 1], "Testing/config/experiment_sweeps_broad_coverage_r1.json")
        variables = [
            command[index + 1]
            for index, token in enumerate(command)
            if token == "--variable" and index + 1 < len(command)
        ]
        self.assertEqual(variables, ["query_verbosity", "worker_subagents", "worker_prompt_shape"])
        difficulties = [
            command[index + 1]
            for index, token in enumerate(command)
            if token == "--difficulty-filter" and index + 1 < len(command)
        ]
        self.assertEqual(difficulties, ["medium", "hard"])

    def test_broad_coverage_preset_projects_below_sixty_usd(self) -> None:
        report = build_launch_preset_projection_report("coverage_broad_r1_60usd")

        self.assertEqual(report["child_runs"], 5)
        self.assertEqual(report["tasks_per_child_run"], 23)
        self.assertLess(float(report["projection"]["projected_estimated_cost_usd"]), 60.0)

    def test_sweep_architecture_focus_uses_worker_prompt_shape_family(self) -> None:
        command = build_launch_preset_command(
            "sweep_architecture_focus_r1",
            explicit_judge_model="openai:gpt-4o-mini",
        )

        variables = [
            command[index + 1]
            for index, token in enumerate(command)
            if token == "--variable" and index + 1 < len(command)
        ]
        self.assertIn("worker_prompt_shape", variables)
        self.assertNotIn("worker_persona_prompt", variables)


if __name__ == "__main__":
    unittest.main()
