from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any, Dict, List


def generate_experiment_visuals(
    output_dir: Path,
    *,
    variant_rows: List[Dict[str, Any]],
    dimension_rows: List[Dict[str, Any]],
    task_rows: List[Dict[str, Any]],
    difficulty_rows: List[Dict[str, Any]],
    technique_rows: List[Dict[str, Any]],
    significance_overall_rows: List[Dict[str, Any]] | None = None,
    significance_difficulty_rows: List[Dict[str, Any]] | None = None,
    significance_task_rows: List[Dict[str, Any]] | None = None,
    paired_task_overall_rows: List[Dict[str, Any]] | None = None,
    paired_task_difficulty_rows: List[Dict[str, Any]] | None = None,
    timing_variant_rows: List[Dict[str, Any]] | None = None,
    timing_task_rows: List[Dict[str, Any]] | None = None,
    timing_task_tag_rows: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import pandas as pd
    except Exception as exc:  # pragma: no cover - optional dependency at runtime
        error_payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "created_files": []}
        (output_dir / "visualization_error.json").write_text(json.dumps(error_payload, indent=2) + "\n", encoding="utf-8")
        return error_payload

    created_files: List[Dict[str, str]] = []

    plt.style.use("seaborn-v0_8-whitegrid")

    def _wrap_label(value: Any, width: int = 18) -> str:
        text = str(value or "")
        return "\n".join(textwrap.wrap(text, width=width)) or text

    def _annotate_bars(ax, values: List[float], *, fmt: str = "{:.2f}") -> None:
        for patch, value in zip(ax.patches, values):
            if value is None:
                continue
            x = patch.get_x() + patch.get_width() / 2
            y = patch.get_height()
            va = "bottom" if float(value) >= 0 else "top"
            offset = 0.5 if float(value) >= 0 else -0.5
            ax.text(x, y + offset, fmt.format(float(value)), ha="center", va=va, fontsize=8)

    def _annotate_heatmap(ax, data_frame, *, fmt: str = "{:.2f}") -> None:
        if data_frame.shape[0] > 14 or data_frame.shape[1] > 10:
            return
        for y_index, row_name in enumerate(data_frame.index):
            for x_index, column_name in enumerate(data_frame.columns):
                value = data_frame.loc[row_name, column_name]
                ax.text(x_index, y_index, fmt.format(float(value)), ha="center", va="center", fontsize=7, color="#111111")

    def _significance_marker(row: Dict[str, Any]) -> str:
        basis = str(row.get("significance_basis") or "")
        if bool(row.get("statistically_significant_95pct")):
            return "R*" if basis == "replicate" else "T*"
        status = str(row.get("status") or "")
        if status == "insufficient_repetitions":
            return "?"
        if status == "insufficient_pairs":
            return "?"
        p_value = row.get("p_value")
        try:
            return f"p={float(p_value):.3f}" if p_value is not None else ""
        except Exception:
            return ""

    overall_sig_df = pd.DataFrame(significance_overall_rows or [])
    task_sig_df = pd.DataFrame(significance_task_rows or [])
    difficulty_sig_df = pd.DataFrame(significance_difficulty_rows or [])
    paired_overall_sig_df = pd.DataFrame(paired_task_overall_rows or [])
    paired_difficulty_sig_df = pd.DataFrame(paired_task_difficulty_rows or [])
    timing_variant_df = pd.DataFrame(timing_variant_rows or [])
    timing_task_df = pd.DataFrame(timing_task_rows or [])
    timing_task_tag_df = pd.DataFrame(timing_task_tag_rows or [])

    overall_sig_map: Dict[str, Dict[str, Any]] = {}
    if not overall_sig_df.empty:
        for _, row in overall_sig_df.iterrows():
            overall_sig_map[str(row.get("variant_id") or "")] = {**row.to_dict(), "significance_basis": "replicate"}
    if not paired_overall_sig_df.empty:
        for _, row in paired_overall_sig_df.iterrows():
            variant_id = str(row.get("variant_id") or "")
            if variant_id in overall_sig_map and overall_sig_map[variant_id].get("p_value") is not None:
                continue
            overall_sig_map[variant_id] = {**row.to_dict(), "significance_basis": "paired_task"}

    def _row_label(row: Dict[str, Any]) -> str:
        sample_task_id = str(row.get("sample_task_id") or "").strip()
        if sample_task_id:
            return sample_task_id
        sample = str(row.get("sample") or "").strip()
        task_name = str(row.get("task_name") or row.get("task_id") or "").strip()
        return f"{sample}::{task_name}" if task_name else sample

    def _save_current_figure(filename: str, title: str, description: str) -> None:
        path = output_dir / filename
        plt.tight_layout()
        plt.savefig(path, dpi=180, bbox_inches="tight")
        plt.close()
        created_files.append({"path": str(path), "title": title, "description": description})

    variant_df = pd.DataFrame(variant_rows or [])
    if not variant_df.empty:
        ordered = variant_df.copy()
        ordered["display_label"] = ordered["display_label"].fillna(ordered["variant_id"])
        ordered["display_label_wrapped"] = ordered["display_label"].map(lambda value: _wrap_label(value, width=16))

        plt.figure(figsize=(max(10, len(ordered) * 1.15), 5.5))
        ax = plt.gca()
        ax.bar(
            ordered["display_label_wrapped"],
            ordered["overall_score_mean"],
            color="#4c78a8",
            yerr=ordered["overall_score_stddev"] if "overall_score_stddev" in ordered.columns else None,
            capsize=4,
        )
        plt.axhline(float(ordered.loc[ordered["is_baseline"] == True, "overall_score_mean"].iloc[0]), color="#f58518", linestyle="--", linewidth=1.5)  # noqa: E712
        plt.ylabel("Mean score (0-100)")
        plt.xlabel("Configuration")
        plt.xticks(rotation=20, ha="right")
        plt.title("Baseline vs Variant Mean Score")
        _annotate_bars(ax, [float(value) for value in ordered["overall_score_mean"].fillna(0.0)], fmt="{:.1f}")
        _save_current_figure(
            "baseline_vs_variant_scores.png",
            "Baseline vs Variant Mean Score",
            "Bar chart comparing aggregate mean score for the baseline and each one-variable-at-a-time variant, with replicate variance shown as error bars when available.",
        )

        delta_df = ordered.dropna(subset=["score_delta"]).copy()
        if not delta_df.empty:
            if overall_sig_map:
                delta_df = delta_df.merge(
                    pd.DataFrame(
                        [
                            {
                                "variant_id": variant_id,
                                "statistically_significant_95pct": row.get("statistically_significant_95pct"),
                                "p_value": row.get("p_value"),
                                "status": row.get("status"),
                                "significance_basis": row.get("significance_basis"),
                            }
                            for variant_id, row in overall_sig_map.items()
                        ]
                    ),
                    on="variant_id",
                    how="left",
                )
            plt.figure(figsize=(max(10, len(delta_df) * 1.15), 5.5))
            ax = plt.gca()
            colors = ["#54a24b" if float(value) >= 0.0 else "#e45756" for value in delta_df["score_delta"]]
            ax.bar(delta_df["display_label_wrapped"], delta_df["score_delta"], color=colors)
            plt.axhline(0.0, color="#444444", linestyle="--", linewidth=1.2)
            plt.ylabel("Score delta")
            plt.xlabel("Configuration")
            plt.xticks(rotation=20, ha="right")
            plt.title("Variant Score Delta vs Comparison Baseline")
            _annotate_bars(ax, [float(value) for value in delta_df["score_delta"].fillna(0.0)], fmt="{:+.1f}")
            for idx, (_, sig_row) in enumerate(delta_df.iterrows()):
                marker = _significance_marker(sig_row.to_dict())
                if not marker:
                    continue
                y_val = float(sig_row["score_delta"] or 0.0)
                y_pos = y_val + (3.0 if y_val >= 0.0 else -3.0)
                va = "bottom" if y_val >= 0.0 else "top"
                ax.text(idx, y_pos, marker, ha="center", va=va, fontsize=12, color="#111111")
            _save_current_figure(
                "variant_score_deltas.png",
                "Variant Score Delta vs Comparison Baseline",
                "Bar chart showing mean score delta for each configuration relative to its configured comparison baseline. `R*` marks replicate-level significance, `T*` marks paired-task significance, and `?` indicates insufficient data for the available test.",
            )

        plt.figure(figsize=(max(10, len(ordered) * 1.15), 5.5))
        ax = plt.gca()
        ax.bar(
            ordered["display_label_wrapped"],
            ordered["task_success_rate"],
            color="#54a24b",
            yerr=ordered["task_success_rate_stddev"] if "task_success_rate_stddev" in ordered.columns else None,
            capsize=4,
        )
        plt.ylabel("Task success rate")
        plt.xlabel("Configuration")
        plt.xticks(rotation=20, ha="right")
        plt.ylim(0, 1.05)
        plt.title("Task Success Rate by Configuration")
        _annotate_bars(ax, [float(value) for value in ordered["task_success_rate"].fillna(0.0)], fmt="{:.2f}")
        _save_current_figure(
            "task_success_rates.png",
            "Task Success Rate by Configuration",
            "Bar chart showing task-level success rate for the baseline and each variant, with replicate variance shown as error bars when available.",
        )

        success_delta_df = ordered.dropna(subset=["task_success_delta"]).copy()
        if not success_delta_df.empty:
            plt.figure(figsize=(max(10, len(success_delta_df) * 1.15), 5.5))
            ax = plt.gca()
            colors = ["#54a24b" if float(value) >= 0.0 else "#e45756" for value in success_delta_df["task_success_delta"]]
            ax.bar(success_delta_df["display_label_wrapped"], success_delta_df["task_success_delta"], color=colors)
            plt.axhline(0.0, color="#444444", linestyle="--", linewidth=1.2)
            plt.ylabel("Task success delta")
            plt.xlabel("Configuration")
            plt.xticks(rotation=20, ha="right")
            plt.title("Variant Task Success Delta vs Comparison Baseline")
            _annotate_bars(ax, [float(value) for value in success_delta_df["task_success_delta"].fillna(0.0)], fmt="{:+.2f}")
            _save_current_figure(
                "variant_task_success_deltas.png",
                "Variant Task Success Delta vs Comparison Baseline",
                "Bar chart showing task-success-rate delta for each configuration relative to its configured comparison baseline.",
            )

        outcome_df = ordered.copy()
        if {"produced_result_rate", "validator_blocked_rate", "analysis_failure_rate"}.issubset(outcome_df.columns):
            completed = outcome_df["produced_result_rate"].fillna(0.0)
            validator_blocked = outcome_df["validator_blocked_rate"].fillna(0.0)
            analysis_failed = outcome_df["analysis_failure_rate"].fillna(0.0)
            other = (1.0 - completed - validator_blocked - analysis_failed).clip(lower=0.0)

            plt.figure(figsize=(max(10, len(outcome_df) * 1.15), 5.8))
            x_labels = list(outcome_df["display_label_wrapped"])
            plt.bar(x_labels, completed, label="produced_result", color="#54a24b")
            plt.bar(x_labels, validator_blocked, bottom=completed, label="validator_blocked", color="#f2cf5b")
            plt.bar(
                x_labels,
                analysis_failed,
                bottom=completed + validator_blocked,
                label="analysis_error",
                color="#e45756",
            )
            plt.bar(
                x_labels,
                other,
                bottom=completed + validator_blocked + analysis_failed,
                label="other",
                color="#bab0ac",
            )
            plt.ylabel("Outcome rate")
            plt.xlabel("Configuration")
            plt.xticks(rotation=20, ha="right")
            plt.ylim(0, 1.05)
            plt.legend()
            plt.title("Run Outcome Rates by Configuration")
            _save_current_figure(
                "run_outcome_rates.png",
                "Run Outcome Rates by Configuration",
                "Stacked bar chart showing produced-result, validator-blocked, and analysis-error rates for each configuration.",
            )

        scatter_df = ordered.dropna(subset=["mean_relative_cost_index", "overall_score_mean"]).copy()
        if not scatter_df.empty:
            plt.figure(figsize=(7.5, 5.5))
            plt.scatter(scatter_df["mean_relative_cost_index"], scatter_df["overall_score_mean"], color="#e45756")
            for _, row in scatter_df.iterrows():
                plt.annotate(str(row["display_label"]), (row["mean_relative_cost_index"], row["overall_score_mean"]), fontsize=8)
            plt.xlabel("Mean relative cost index")
            plt.ylabel("Mean score (0-100)")
            plt.title("Cost vs Performance")
            _save_current_figure(
                "cost_vs_performance.png",
                "Cost vs Performance",
                "Scatter plot comparing relative cost index against mean score for each configuration.",
            )

        impact_df = ordered[~ordered["is_baseline"].fillna(False)].copy()
        impact_df = impact_df[~impact_df["is_family_baseline"].fillna(False)]
        impact_df = impact_df.dropna(subset=["score_delta"])
        if not impact_df.empty:
            variable_summary = (
                impact_df
                .groupby("changed_variable", dropna=False)["score_delta"]
                .agg(lambda values: float(sum(abs(float(v)) for v in values) / max(len(values), 1)))
                .reset_index(name="mean_abs_score_delta")
                .sort_values("mean_abs_score_delta", ascending=False)
            )
            plt.figure(figsize=(max(8, len(variable_summary) * 1.2), 5.2))
            plt.bar(variable_summary["changed_variable"], variable_summary["mean_abs_score_delta"], color="#4c78a8")
            plt.ylabel("Mean absolute score delta")
            plt.xlabel("Changed variable")
            plt.xticks(rotation=25, ha="right")
            plt.title("Aggregate Variable Impact")
            _save_current_figure(
                "variable_impact_summary.png",
                "Aggregate Variable Impact",
                "Bar chart showing mean absolute score delta by changed-variable family across all non-baseline variants.",
            )

            family_rows = []
            for variable_name, family_df in impact_df.groupby("changed_variable"):
                family_sorted = family_df.sort_values("score_delta", ascending=False)
                for _, family_row in family_sorted.iterrows():
                    family_rows.append((str(variable_name), str(family_row["display_label"]), float(family_row["score_delta"])))
            if family_rows:
                family_df = pd.DataFrame(family_rows, columns=["changed_variable", "display_label", "score_delta"])
                if overall_sig_map:
                    family_df = family_df.merge(
                        pd.DataFrame(
                            [
                                {
                                    "display_label": row.get("display_label"),
                                    "statistically_significant_95pct": row.get("statistically_significant_95pct"),
                                    "p_value": row.get("p_value"),
                                    "status": row.get("status"),
                                    "significance_basis": row.get("significance_basis"),
                                }
                                for row in overall_sig_map.values()
                            ]
                        ),
                        on="display_label",
                        how="left",
                    )
                grouped = family_df.groupby("changed_variable")
                family_names = list(grouped.groups.keys())
                max_variants = max(len(group) for _, group in grouped)
                plt.figure(figsize=(max(10, len(family_names) * 1.4), 5.8))
                ax = plt.gca()
                total_width = 0.8
                bar_width = total_width / max(max_variants, 1)
                x_positions = list(range(len(family_names)))
                legend_labels = set()
                for idx, family_name in enumerate(family_names):
                    group = grouped.get_group(family_name).reset_index(drop=True)
                    for variant_idx, (_, group_row) in enumerate(group.iterrows()):
                        offset = -total_width / 2 + (variant_idx + 0.5) * bar_width
                        xpos = x_positions[idx] + offset
                        color = "#54a24b" if float(group_row["score_delta"]) >= 0.0 else "#e45756"
                        label = str(group_row["display_label"])
                        ax.bar(xpos, float(group_row["score_delta"]), width=bar_width * 0.95, color=color, label=label if label not in legend_labels else None)
                        marker = _significance_marker(group_row.to_dict())
                        if marker:
                            y_val = float(group_row["score_delta"])
                            y_pos = y_val + (3.0 if y_val >= 0.0 else -3.0)
                            va = "bottom" if y_val >= 0.0 else "top"
                            ax.text(xpos, y_pos, marker, ha="center", va=va, fontsize=10, color="#111111")
                        legend_labels.add(label)
                ax.axhline(0.0, color="#444444", linestyle="--", linewidth=1.2)
                ax.set_xticks(x_positions)
                ax.set_xticklabels([_wrap_label(name, 14) for name in family_names])
                ax.set_ylabel("Score delta")
                ax.set_xlabel("Changed variable")
                ax.set_title("Variant Score Delta by Variable Family")
                ax.legend(fontsize=8, ncol=2)
                _save_current_figure(
                    "family_score_deltas.png",
                    "Variant Score Delta by Variable Family",
                    "Grouped bar chart comparing score deltas for variants within each changed-variable family. `R*` marks replicate-level significance, `T*` marks paired-task significance, and `?` indicates insufficient data for the available test.",
                )

    dimension_df = pd.DataFrame(dimension_rows or [])
    if not dimension_df.empty:
        pivot = (
            dimension_df
            .pivot(index="display_label", columns="dimension", values="delta_from_baseline")
            .fillna(0.0)
        )
        plt.figure(figsize=(max(9, pivot.shape[1] * 1.2), max(5.5, pivot.shape[0] * 0.5)))
        ax = plt.gca()
        plt.imshow(pivot.values, cmap="coolwarm", aspect="auto")
        plt.colorbar(label="Delta from baseline")
        plt.xticks(range(len(pivot.columns)), list(pivot.columns), rotation=35, ha="right")
        plt.yticks(range(len(pivot.index)), list(pivot.index))
        plt.title("Rubric Dimension Delta Heatmap")
        _annotate_heatmap(ax, pivot)
        _save_current_figure(
            "rubric_dimension_deltas.png",
            "Rubric Dimension Delta Heatmap",
            "Heatmap of rubric-dimension deltas from the configured comparison baseline across variants.",
        )

    task_df = pd.DataFrame(task_rows or [])
    if not task_df.empty:
        task_df = task_df.copy()
        task_df["task_label"] = task_df.apply(lambda row: _row_label(row.to_dict()), axis=1)
        score_pivot = (
            task_df
            .pivot(index="task_label", columns="display_label", values="score_delta")
            .fillna(0.0)
        )
        plt.figure(figsize=(max(9, score_pivot.shape[1] * 1.2), max(5.5, score_pivot.shape[0] * 0.55)))
        ax = plt.gca()
        plt.imshow(score_pivot.values, cmap="coolwarm", aspect="auto")
        plt.colorbar(label="Score delta")
        plt.xticks(range(len(score_pivot.columns)), list(score_pivot.columns), rotation=35, ha="right")
        plt.yticks(range(len(score_pivot.index)), list(score_pivot.index))
        plt.title("Per-Task Score Delta Heatmap")
        _annotate_heatmap(ax, score_pivot)
        _save_current_figure(
            "task_score_heatmap.png",
            "Per-Task Score Delta Heatmap",
            "Heatmap showing how each sample-task score changed relative to its configured comparison baseline under each variant.",
        )

        success_pivot = (
            task_df
            .pivot(index="task_label", columns="display_label", values="task_success_numeric")
            .fillna(0.0)
        )
        plt.figure(figsize=(max(9, success_pivot.shape[1] * 1.2), max(5.5, success_pivot.shape[0] * 0.55)))
        ax = plt.gca()
        plt.imshow(success_pivot.values, cmap="YlGn", aspect="auto", vmin=0.0, vmax=1.0)
        plt.colorbar(label="Task success rate")
        plt.xticks(range(len(success_pivot.columns)), list(success_pivot.columns), rotation=35, ha="right")
        plt.yticks(range(len(success_pivot.index)), list(success_pivot.index))
        plt.title("Per-Task Success Rate Heatmap")
        _annotate_heatmap(ax, success_pivot)
        _save_current_figure(
            "task_success_heatmap.png",
            "Per-Task Success Rate Heatmap",
            "Heatmap showing task success rate for each sample-task under each variant after replicate aggregation.",
        )

    if not task_sig_df.empty:
        task_sig_df = task_sig_df.copy()
        task_sig_df["task_label"] = task_sig_df["sample_task_id"].fillna("")
        task_sig_df["significance_code"] = task_sig_df.apply(
            lambda row: 2.0 if bool(row.get("statistically_significant_95pct")) and str(row.get("direction") or "") == "improved"
            else -2.0 if bool(row.get("statistically_significant_95pct")) and str(row.get("direction") or "") == "degraded"
            else 1.0 if str(row.get("status") or "") == "ok" and str(row.get("direction") or "") == "improved"
            else -1.0 if str(row.get("status") or "") == "ok" and str(row.get("direction") or "") == "degraded"
            else 0.0,
            axis=1,
        )
        sig_pivot = (
            task_sig_df
            .pivot(index="task_label", columns="display_label", values="significance_code")
            .fillna(0.0)
        )
        plt.figure(figsize=(max(9, sig_pivot.shape[1] * 1.2), max(5.5, sig_pivot.shape[0] * 0.55)))
        ax = plt.gca()
        plt.imshow(sig_pivot.values, cmap="RdYlGn", aspect="auto", vmin=-2.0, vmax=2.0)
        cbar = plt.colorbar(label="Significance status")
        cbar.set_ticks([-2, -1, 0, 1, 2])
        cbar.set_ticklabels(["sig degrade", "degrade", "inconclusive", "improve", "sig improve"])
        plt.xticks(range(len(sig_pivot.columns)), list(sig_pivot.columns), rotation=35, ha="right")
        plt.yticks(range(len(sig_pivot.index)), list(sig_pivot.index))
        plt.title("Per-Task Significance Status Heatmap")
        if sig_pivot.shape[0] <= 14 and sig_pivot.shape[1] <= 10:
            label_map = {-2.0: "*-", -1.0: "-", 0.0: "?", 1.0: "+", 2.0: "*+"}
            for y_index, row_name in enumerate(sig_pivot.index):
                for x_index, column_name in enumerate(sig_pivot.columns):
                    value = float(sig_pivot.loc[row_name, column_name])
                    ax.text(x_index, y_index, label_map.get(value, ""), ha="center", va="center", fontsize=8, color="#111111")
        _save_current_figure(
            "task_significance_heatmap.png",
            "Per-Task Significance Status Heatmap",
            "Heatmap showing whether each task improved, degraded, or changed significantly versus its comparison baseline. Stars indicate statistically significant 95% changes; question marks indicate inconclusive or insufficient-repeat comparisons.",
        )

    if not difficulty_sig_df.empty:
        difficulty_sig_df = difficulty_sig_df.copy()
        difficulty_sig_df["significance_code"] = difficulty_sig_df.apply(
            lambda row: 2.0 if bool(row.get("statistically_significant_95pct")) and str(row.get("direction") or "") == "improved"
            else -2.0 if bool(row.get("statistically_significant_95pct")) and str(row.get("direction") or "") == "degraded"
            else 1.0 if str(row.get("status") or "") == "ok" and str(row.get("direction") or "") == "improved"
            else -1.0 if str(row.get("status") or "") == "ok" and str(row.get("direction") or "") == "degraded"
            else 0.0,
            axis=1,
        )
        difficulty_pivot_sig = (
            difficulty_sig_df
            .pivot(index="difficulty", columns="display_label", values="significance_code")
            .fillna(0.0)
        )
        plt.figure(figsize=(max(9, difficulty_pivot_sig.shape[1] * 1.2), max(4.5, difficulty_pivot_sig.shape[0] * 0.9)))
        ax = plt.gca()
        plt.imshow(difficulty_pivot_sig.values, cmap="RdYlGn", aspect="auto", vmin=-2.0, vmax=2.0)
        cbar = plt.colorbar(label="Significance status")
        cbar.set_ticks([-2, -1, 0, 1, 2])
        cbar.set_ticklabels(["sig degrade", "degrade", "inconclusive", "improve", "sig improve"])
        plt.xticks(range(len(difficulty_pivot_sig.columns)), list(difficulty_pivot_sig.columns), rotation=35, ha="right")
        plt.yticks(range(len(difficulty_pivot_sig.index)), list(difficulty_pivot_sig.index))
        plt.title("Difficulty-Band Significance Status Heatmap")
        if difficulty_pivot_sig.shape[0] <= 10 and difficulty_pivot_sig.shape[1] <= 10:
            label_map = {-2.0: "*-", -1.0: "-", 0.0: "?", 1.0: "+", 2.0: "*+"}
            for y_index, row_name in enumerate(difficulty_pivot_sig.index):
                for x_index, column_name in enumerate(difficulty_pivot_sig.columns):
                    value = float(difficulty_pivot_sig.loc[row_name, column_name])
                    ax.text(x_index, y_index, label_map.get(value, ""), ha="center", va="center", fontsize=8, color="#111111")
        _save_current_figure(
            "difficulty_significance_heatmap.png",
            "Difficulty-Band Significance Status Heatmap",
            "Heatmap showing whether each difficulty band improved, degraded, or changed significantly versus its comparison baseline. Stars indicate statistically significant 95% changes; question marks indicate inconclusive or insufficient-repeat comparisons.",
        )

    if not paired_difficulty_sig_df.empty:
        paired_difficulty_sig_df = paired_difficulty_sig_df.copy()
        paired_difficulty_sig_df["significance_code"] = paired_difficulty_sig_df.apply(
            lambda row: 2.0 if bool(row.get("statistically_significant_95pct")) and str(row.get("direction") or "") == "improved"
            else -2.0 if bool(row.get("statistically_significant_95pct")) and str(row.get("direction") or "") == "degraded"
            else 1.0 if str(row.get("status") or "") == "ok" and str(row.get("direction") or "") == "improved"
            else -1.0 if str(row.get("status") or "") == "ok" and str(row.get("direction") or "") == "degraded"
            else 0.0,
            axis=1,
        )
        paired_difficulty_pivot = (
            paired_difficulty_sig_df
            .pivot(index="difficulty", columns="display_label", values="significance_code")
            .fillna(0.0)
        )
        plt.figure(figsize=(max(9, paired_difficulty_pivot.shape[1] * 1.2), max(4.5, paired_difficulty_pivot.shape[0] * 0.9)))
        ax = plt.gca()
        plt.imshow(paired_difficulty_pivot.values, cmap="RdYlGn", aspect="auto", vmin=-2.0, vmax=2.0)
        cbar = plt.colorbar(label="Paired-task significance status")
        cbar.set_ticks([-2, -1, 0, 1, 2])
        cbar.set_ticklabels(["sig degrade", "degrade", "inconclusive", "improve", "sig improve"])
        plt.xticks(range(len(paired_difficulty_pivot.columns)), list(paired_difficulty_pivot.columns), rotation=35, ha="right")
        plt.yticks(range(len(paired_difficulty_pivot.index)), list(paired_difficulty_pivot.index))
        plt.title("Paired-Task Difficulty Significance Heatmap")
        if paired_difficulty_pivot.shape[0] <= 10 and paired_difficulty_pivot.shape[1] <= 10:
            label_map = {-2.0: "*-", -1.0: "-", 0.0: "?", 1.0: "+", 2.0: "*+"}
            for y_index, row_name in enumerate(paired_difficulty_pivot.index):
                for x_index, column_name in enumerate(paired_difficulty_pivot.columns):
                    value = float(paired_difficulty_pivot.loc[row_name, column_name])
                    ax.text(x_index, y_index, label_map.get(value, ""), ha="center", va="center", fontsize=8, color="#111111")
        _save_current_figure(
            "paired_task_difficulty_significance_heatmap.png",
            "Paired-Task Difficulty Significance Heatmap",
            "Heatmap showing whether each difficulty band improved or degraded under the paired across-task significance test. This chart is useful when whole-run replicate counts are low.",
        )

    difficulty_df = pd.DataFrame(difficulty_rows or [])
    if not difficulty_df.empty:
        difficulty_pivot = (
            difficulty_df
            .pivot(index="difficulty", columns="display_label", values="score_delta")
            .fillna(0.0)
        )
        plt.figure(figsize=(max(9, difficulty_pivot.shape[1] * 1.2), max(4.5, difficulty_pivot.shape[0] * 0.8)))
        ax = plt.gca()
        plt.imshow(difficulty_pivot.values, cmap="coolwarm", aspect="auto")
        plt.colorbar(label="Score delta")
        plt.xticks(range(len(difficulty_pivot.columns)), list(difficulty_pivot.columns), rotation=35, ha="right")
        plt.yticks(range(len(difficulty_pivot.index)), list(difficulty_pivot.index))
        plt.title("Difficulty-Band Score Delta Heatmap")
        _annotate_heatmap(ax, difficulty_pivot)
        _save_current_figure(
            "difficulty_score_deltas.png",
            "Difficulty-Band Score Delta Heatmap",
            "Heatmap showing score deltas by difficulty band for each configuration relative to its configured comparison baseline.",
        )

    technique_df = pd.DataFrame(technique_rows or [])
    if not technique_df.empty:
        technique_pivot = (
            technique_df
            .pivot(index="technique", columns="display_label", values="score_delta")
            .fillna(0.0)
        )
        plt.figure(figsize=(max(9, technique_pivot.shape[1] * 1.2), max(5.5, technique_pivot.shape[0] * 0.55)))
        ax = plt.gca()
        plt.imshow(technique_pivot.values, cmap="coolwarm", aspect="auto")
        plt.colorbar(label="Score delta")
        plt.xticks(range(len(technique_pivot.columns)), list(technique_pivot.columns), rotation=35, ha="right")
        plt.yticks(range(len(technique_pivot.index)), list(technique_pivot.index))
        plt.title("Technique Score Delta Heatmap")
        _annotate_heatmap(ax, technique_pivot)
        _save_current_figure(
            "technique_score_deltas.png",
            "Technique Score Delta Heatmap",
            "Heatmap showing score deltas by primary technique bucket for each configuration relative to its configured comparison baseline.",
        )

    if not timing_variant_df.empty:
        timing_variant_df = timing_variant_df.copy()
        timing_variant_df["mean_task_wall_clock_duration_sec"] = pd.to_numeric(
            timing_variant_df["mean_task_wall_clock_duration_sec"], errors="coerce"
        )
        if "wall_clock_duration_stddev" in timing_variant_df.columns:
            timing_variant_df["wall_clock_duration_stddev"] = pd.to_numeric(
                timing_variant_df["wall_clock_duration_stddev"], errors="coerce"
            )
        timing_variant_df = timing_variant_df.dropna(subset=["mean_task_wall_clock_duration_sec"]).copy()
        if not timing_variant_df.empty:
            timing_variant_df["display_label_wrapped"] = timing_variant_df["display_label"].map(lambda value: _wrap_label(value, width=16))
            plt.figure(figsize=(max(10, len(timing_variant_df) * 1.15), 5.5))
            ax = plt.gca()
            ax.bar(
                timing_variant_df["display_label_wrapped"],
                timing_variant_df["mean_task_wall_clock_duration_sec"],
                color="#72b7b2",
                yerr=timing_variant_df["wall_clock_duration_stddev"] if "wall_clock_duration_stddev" in timing_variant_df.columns else None,
                capsize=4,
            )
            plt.ylabel("Mean wall-clock task duration (s)")
            plt.xlabel("Configuration")
            plt.xticks(rotation=20, ha="right")
            plt.title("Mean Completion Time by Configuration")
            _annotate_bars(ax, [float(value) for value in timing_variant_df["mean_task_wall_clock_duration_sec"].fillna(0.0)], fmt="{:.1f}")
            _save_current_figure(
                "variant_completion_time.png",
                "Mean Completion Time by Configuration",
                "Bar chart showing the mean wall-clock completion time per sample-task for each configuration, aggregated across all captured replicates.",
            )

    if not timing_task_df.empty:
        timing_task_df = timing_task_df.copy()
        timing_task_df["mean_task_wall_clock_duration_sec"] = pd.to_numeric(
            timing_task_df["mean_task_wall_clock_duration_sec"], errors="coerce"
        )
        timing_task_df = timing_task_df.dropna(subset=["mean_task_wall_clock_duration_sec"]).copy()
        timing_task_df["task_label"] = timing_task_df.apply(lambda row: _row_label(row.to_dict()), axis=1)
        duration_pivot = (
            timing_task_df
            .pivot(index="task_label", columns="display_label", values="mean_task_wall_clock_duration_sec")
            .fillna(0.0)
        )
        plt.figure(figsize=(max(9, duration_pivot.shape[1] * 1.2), max(5.5, duration_pivot.shape[0] * 0.55)))
        ax = plt.gca()
        plt.imshow(duration_pivot.values, cmap="YlOrBr", aspect="auto")
        plt.colorbar(label="Mean wall-clock task duration (s)")
        plt.xticks(range(len(duration_pivot.columns)), list(duration_pivot.columns), rotation=35, ha="right")
        plt.yticks(range(len(duration_pivot.index)), list(duration_pivot.index))
        plt.title("Per-Task Completion Time Heatmap")
        _annotate_heatmap(ax, duration_pivot)
        _save_current_figure(
            "task_completion_time_heatmap.png",
            "Per-Task Completion Time Heatmap",
            "Heatmap showing mean wall-clock completion time for each sample-task under each configuration, aggregated across replicate runs when present.",
        )

    if not timing_task_tag_df.empty:
        timing_task_tag_df = timing_task_tag_df.copy()
        timing_task_tag_df["mean_task_wall_clock_duration_sec"] = pd.to_numeric(
            timing_task_tag_df["mean_task_wall_clock_duration_sec"], errors="coerce"
        )
        timing_task_tag_df = timing_task_tag_df.dropna(subset=["mean_task_wall_clock_duration_sec"]).copy()
        tag_pivot = (
            timing_task_tag_df
            .pivot(index="task_tag", columns="display_label", values="mean_task_wall_clock_duration_sec")
            .fillna(0.0)
        )
        plt.figure(figsize=(max(9, tag_pivot.shape[1] * 1.2), max(4.5, tag_pivot.shape[0] * 0.8)))
        ax = plt.gca()
        plt.imshow(tag_pivot.values, cmap="YlGnBu", aspect="auto")
        plt.colorbar(label="Mean wall-clock task duration (s)")
        plt.xticks(range(len(tag_pivot.columns)), list(tag_pivot.columns), rotation=35, ha="right")
        plt.yticks(range(len(tag_pivot.index)), list(tag_pivot.index))
        plt.title("Task-Category Completion Time Heatmap")
        _annotate_heatmap(ax, tag_pivot)
        _save_current_figure(
            "task_category_completion_time_heatmap.png",
            "Task-Category Completion Time Heatmap",
            "Heatmap showing mean wall-clock completion time by task tag/category for each configuration, aggregated across replicate runs when present.",
        )

    error_path = output_dir / "visualization_error.json"
    if error_path.exists():
        try:
            error_path.unlink()
        except Exception:
            pass
    manifest = {"ok": True, "created_files": created_files}
    (output_dir / "chart_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
