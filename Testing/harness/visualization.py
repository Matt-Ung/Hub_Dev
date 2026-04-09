"""
File: visualization.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Generate the maintained chart suite for experiment reports and the results
  browser.

Summary:
  This module turns experiment summaries into presentation-ready PNG charts
  with a consistent accessible style. It is the plotting layer behind the
  experiment refresh path and browser chart cards.
"""

from __future__ import annotations

import json
import math
import textwrap
from pathlib import Path
from typing import Any, Dict, Iterable, List


SERIES_COLORS = [
    "#0072B2",
    "#009E73",
    "#E69F00",
    "#CC79A7",
    "#D55E00",
    "#56B4E9",
    "#4C6A92",
    "#6F7D3C",
]
MARKER_SEQUENCE = ["o", "s", "^", "P", "X", "v", "<", ">"]
BASELINE_COLOR = "#1F3A5F"
REFERENCE_COLOR = "#94a3b8"
POSITIVE_COLOR = "#009E73"
NEGATIVE_COLOR = "#D55E00"
NEUTRAL_COLOR = "#4C6A92"
FAILURE_COLORS = {
    "completed_judged": "#7BC8A4",
    "validator_blocked": "#E9C46A",
    "judge_error": "#B38BD4",
    "analysis_error": "#E76F51",
    "worker_assignment_failed": "#C44536",
    "missing_coverage": "#CBD5E1",
}

DIRECT_LABEL_ALIASES = {
    "baseline": "Baseline",
    "worker_subagents:single_generalist": "Single generalist",
    "worker_prompt_shape:artifact_focused": "Evidence-focused",
    "worker_prompt_shape:empty": "No role prompt",
    "response_scope:brief": "Brief response scope",
    "pipeline_preset:validators_reporter": "Validators + reporter",
    "architecture_preset:ghidra_focused": "Ghidra-focused",
}
FAMILY_LABEL_ALIASES = {
    "worker_subagents": "Workers",
    "worker_prompt_shape": "Prompt",
    "pipeline_preset": "Pipeline",
    "architecture_preset": "Architecture",
    "response_scope": "Response scope",
    "tool_availability": "Tools",
    "validator_review_level": "Validator review",
    "validator_topology": "Validator topology",
    "model_profile": "Model",
}
VALUE_LABEL_ALIASES = {
    "single_generalist": "Single generalist",
    "artifact_focused": "Evidence-focused",
    "empty": "No role prompt",
    "brief": "Brief",
    "validators_reporter": "Validators + reporter",
    "ghidra_focused": "Ghidra-focused",
    "minimal": "Minimal",
    "model_augmented": "Model-augmented",
}


def _safe_float(value: Any) -> float | None:
    try:
        text = str(value).strip()
        if not text:
            return None
        return float(text)
    except Exception:
        return None


def _humanize_token(value: Any) -> str:
    text = str(value or "").strip().replace("__", " ").replace("_", " ")
    text = " ".join(part for part in text.split() if part)
    if not text:
        return ""
    return text.title()


def _short_config_label(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text in DIRECT_LABEL_ALIASES:
        return DIRECT_LABEL_ALIASES[text]
    if ":" in text:
        family, raw_value = text.split(":", 1)
        family_label = FAMILY_LABEL_ALIASES.get(family, _humanize_token(family))
        value_label = VALUE_LABEL_ALIASES.get(raw_value, _humanize_token(raw_value))
        if value_label.lower().startswith(family_label.lower()):
            return value_label
        return f"{family_label}: {value_label}"
    return VALUE_LABEL_ALIASES.get(text, _humanize_token(text))


def _short_category_label(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.replace("UPX", "UPX")
    return _humanize_token(text)


def _wrap_label(value: Any, width: int = 18) -> str:
    text = str(value or "")
    return "\n".join(textwrap.wrap(text, width=width)) or text


def _configure_matplotlib(plt) -> None:
    plt.style.use("seaborn-v0_8-whitegrid")
    plt.rcParams.update(
        {
            "figure.facecolor": "white",
            "savefig.facecolor": "white",
            "axes.facecolor": "white",
            "axes.edgecolor": "#cbd5e1",
            "axes.labelcolor": "#1f2937",
            "axes.titleweight": "semibold",
            "axes.titlesize": 14,
            "axes.labelsize": 11.5,
            "axes.titlepad": 10,
            "axes.axisbelow": True,
            "xtick.color": "#334155",
            "ytick.color": "#334155",
            "xtick.labelsize": 10.5,
            "ytick.labelsize": 10.5,
            "grid.color": "#e5e7eb",
            "grid.linewidth": 0.8,
            "legend.frameon": False,
            "legend.fontsize": 9.5,
            "legend.title_fontsize": 10,
            "font.family": "DejaVu Sans",
        }
    )


def _style_axes(ax, *, grid_axis: str = "x") -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#cbd5e1")
    ax.spines["bottom"].set_color("#cbd5e1")
    ax.grid(axis=grid_axis, color="#e5e7eb", linewidth=0.8)
    ax.tick_params(axis="both", length=0, pad=6)
    if grid_axis != "both":
        ax.grid(axis="y" if grid_axis == "x" else "x", visible=False)


def _save_figure(
    fig,
    output_dir: Path,
    created_files: List[Dict[str, str]],
    filename: str,
    title: str,
    description: str,
    *,
    tight_rect: tuple[float, float, float, float] | None = None,
) -> None:
    path = output_dir / filename
    if tight_rect is not None:
        fig.tight_layout(pad=1.6, rect=tight_rect)
    else:
        fig.tight_layout(pad=1.6)
    fig.savefig(path, dpi=200, bbox_inches="tight")
    fig.clf()
    created_files.append({"path": str(path), "title": title, "description": description})


def _coerce_numeric_frame(df, columns: Iterable[str]):
    for column in columns:
        if column in df.columns:
            df[column] = df[column].apply(_safe_float)
    return df


def _title(prefix: str, value: str) -> str:
    prefix = str(prefix or "").strip()
    return f"{prefix} {value}".strip() if prefix else value


def _build_color_map(variant_df) -> Dict[str, str]:
    color_map: Dict[str, str] = {"baseline": BASELINE_COLOR}
    non_baseline_ids = [
        str(variant_id)
        for variant_id in list(variant_df["variant_id"])
        if str(variant_id) and str(variant_id) != "baseline"
    ]
    for index, variant_id in enumerate(non_baseline_ids):
        color_map[variant_id] = SERIES_COLORS[index % len(SERIES_COLORS)]
    return color_map


def _build_marker_map(variant_df) -> Dict[str, str]:
    marker_map: Dict[str, str] = {"baseline": "D"}
    non_baseline_ids = [
        str(variant_id)
        for variant_id in list(variant_df["variant_id"])
        if str(variant_id) and str(variant_id) != "baseline"
    ]
    for index, variant_id in enumerate(non_baseline_ids):
        marker_map[variant_id] = MARKER_SEQUENCE[index % len(MARKER_SEQUENCE)]
    return marker_map


def _format_number_tick(value: Any, _position: Any = None) -> str:
    numeric = _safe_float(value)
    if numeric is None or not math.isfinite(numeric):
        return ""
    if abs(numeric) >= 1000:
        return f"{numeric:,.0f}"
    if float(numeric).is_integer():
        return f"{numeric:.0f}"
    return f"{numeric:.1f}"


def _format_percent_tick(value: Any, _position: Any = None) -> str:
    numeric = _safe_float(value)
    if numeric is None or not math.isfinite(numeric):
        return ""
    return f"{numeric * 100:.0f}%"


def _apply_axis_formatter(ax, *, axis: str = "x", kind: str = "number") -> None:
    from matplotlib.ticker import FuncFormatter

    formatter = FuncFormatter(_format_percent_tick if kind == "percent" else _format_number_tick)
    target = ax.xaxis if axis == "x" else ax.yaxis
    target.set_major_formatter(formatter)


def _build_variant_legend_handles(variant_df, color_map: Dict[str, str], marker_map: Dict[str, str]) -> List[Any]:
    from matplotlib.lines import Line2D

    handles: List[Any] = []
    for _, row in variant_df.iterrows():
        variant_id = str(row["variant_id"])
        handles.append(
            Line2D(
                [0],
                [0],
                marker=marker_map.get(variant_id, "o"),
                color="none",
                markerfacecolor=color_map.get(variant_id, NEUTRAL_COLOR),
                markeredgecolor="#111827" if variant_id == "baseline" else "white",
                markeredgewidth=1.0,
                markersize=9 if variant_id == "baseline" else 8,
                label=str(row["short_label"]),
            )
        )
    return handles


def _write_label_legend(output_dir: Path, variant_df) -> None:
    payload = {
        "config_labels": [
            {
                "variant_id": str(row["variant_id"]),
                "display_label": str(row["display_label"]),
                "short_label": str(row["short_label"]),
            }
            for _, row in variant_df.iterrows()
        ]
    }
    (output_dir / "config_label_legend.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_figure_guide(output_dir: Path, created_files: List[Dict[str, str]]) -> None:
    lines = [
        "# Figure Guide",
        "",
        "This directory contains the thesis-oriented experiment figures generated from aggregate sweep outputs.",
        "",
    ]
    for index, entry in enumerate(created_files, start=1):
        lines.append(f"{index}. `{Path(str(entry.get('path') or '')).name}`")
        lines.append(f"   - {entry.get('title', '')}")
        lines.append(f"   - {entry.get('description', '')}")
        lines.append("")
    (output_dir / "figure_guide.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _plot_overall_performance_ranking(
    plt,
    output_dir: Path,
    created_files: List[Dict[str, str]],
    variant_df,
    color_map: Dict[str, str],
    *,
    title_prefix: str,
) -> None:
    ranking_df = variant_df.sort_values(["overall_score_mean", "task_success_rate"], ascending=[False, False]).reset_index(drop=True)
    fig, ax = plt.subplots(figsize=(11.5, max(4.8, 0.72 * len(ranking_df) + 1.8)))
    y_positions = list(range(len(ranking_df)))
    colors = [color_map.get(str(row["variant_id"]), NEUTRAL_COLOR) for _, row in ranking_df.iterrows()]
    values = [float(row["overall_score_mean"] or 0.0) for _, row in ranking_df.iterrows()]
    errors = [float(row["overall_score_stddev"] or 0.0) if row["overall_score_stddev"] is not None else 0.0 for _, row in ranking_df.iterrows()]
    ax.barh(y_positions, values, color=colors, xerr=errors, ecolor="#475569", capsize=4, height=0.62)
    ax.set_yticks(y_positions)
    ax.set_yticklabels([_wrap_label(label, width=18) for label in list(ranking_df["short_label"])])
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Mean overall score (0-100)")
    ax.set_title(_title(title_prefix, "Overall Performance Ranking"))
    _style_axes(ax, grid_axis="x")
    _apply_axis_formatter(ax, axis="x", kind="number")
    for y_pos, (_, row) in zip(y_positions, ranking_df.iterrows()):
        mean_score = float(row["overall_score_mean"] or 0.0)
        delta = _safe_float(row.get("score_delta"))
        delta_text = "baseline" if str(row["variant_id"]) == "baseline" or delta is None else f"Δ {delta:+.1f}"
        ax.text(
            min(mean_score + 1.2, 98.5),
            y_pos,
            f"{mean_score:.1f} · {delta_text}",
            va="center",
            ha="left",
            fontsize=9,
            color="#1f2937",
        )
    _save_figure(
        fig,
        output_dir,
        created_files,
        "01_overall_performance_ranking.png",
        "Overall Performance Ranking",
        "Ranked horizontal bar chart showing mean score by configuration with replicate variance and concise delta annotations for quick baseline-versus-variant comparison.",
    )


def _pareto_frontier(points: List[tuple[float, float]]) -> List[int]:
    frontier: List[int] = []
    for index, (x_value, y_value) in enumerate(points):
        dominated = False
        for other_index, (other_x, other_y) in enumerate(points):
            if other_index == index:
                continue
            if other_x <= x_value and other_y >= y_value and (other_x < x_value or other_y > y_value):
                dominated = True
                break
        if not dominated:
            frontier.append(index)
    return frontier


def _plot_tradeoff_views(
    plt,
    output_dir: Path,
    created_files: List[Dict[str, str]],
    variant_df,
    color_map: Dict[str, str],
    *,
    title_prefix: str,
) -> None:
    tradeoff_df = variant_df.dropna(subset=["overall_score_mean"]).copy()
    if tradeoff_df.empty:
        return
    marker_map = _build_marker_map(tradeoff_df)
    legend_handles = _build_variant_legend_handles(tradeoff_df, color_map, marker_map)
    fig, axes = plt.subplots(1, 2, figsize=(15.8, 6.6))
    panels = [
        ("mean_task_wall_clock_duration_sec", "Mean wall-clock duration per task (s)", "Runtime vs Performance"),
        ("mean_relative_cost_index", "Mean relative cost index", "Cost vs Performance"),
    ]
    for axis, (x_col, x_label, subtitle) in zip(axes, panels):
        panel_df = tradeoff_df.dropna(subset=[x_col]).copy()
        if panel_df.empty:
            axis.axis("off")
            continue
        points = [(float(row[x_col]), float(row["overall_score_mean"])) for _, row in panel_df.iterrows()]
        frontier_indices = set(_pareto_frontier(points))
        min_x = min(point[0] for point in points)
        max_x = max(point[0] for point in points)
        min_y = min(point[1] for point in points)
        max_y = max(point[1] for point in points)
        for idx, (_, row) in enumerate(panel_df.iterrows()):
            variant_id = str(row["variant_id"])
            x_value = float(row[x_col])
            y_value = float(row["overall_score_mean"])
            is_baseline = variant_id == "baseline"
            marker = marker_map.get(variant_id, "o")
            size = 170 if is_baseline else 115
            axis.scatter(
                [x_value],
                [y_value],
                s=size,
                color=color_map.get(variant_id, NEUTRAL_COLOR),
                edgecolor="#111827" if is_baseline else "white",
                linewidth=1.3,
                marker=marker,
                zorder=3,
            )
            if idx in frontier_indices:
                axis.scatter(
                    [x_value],
                    [y_value],
                    s=size + 55,
                    marker=marker,
                    facecolors="none",
                    edgecolors="#111827",
                    linewidth=1.6,
                    zorder=4,
                )
        axis.set_xlabel(x_label)
        axis.set_ylabel("Mean score (0-100)")
        axis.set_title(subtitle, fontsize=13)
        _style_axes(axis, grid_axis="both")
        _apply_axis_formatter(axis, axis="x", kind="number")
        _apply_axis_formatter(axis, axis="y", kind="number")
        axis.set_ylim(max(0.0, min_y - 4.0), min(100.0, max_y + 5.0))
        x_padding = max((max_x - min_x) * 0.10, max_x * 0.03 if max_x else 1.0)
        axis.set_xlim(max(0.0, min_x - x_padding), max_x + x_padding)
    fig.suptitle(_title(title_prefix, "Score, Runtime, and Cost Tradeoffs"), y=0.98, fontsize=16, fontweight="semibold")
    fig.text(
        0.5,
        0.92,
        "Labels move to a shared legend to avoid overlap. Baseline uses a diamond marker; outlined markers are Pareto-efficient.",
        ha="center",
        va="center",
        fontsize=9.5,
        color="#475569",
    )
    fig.legend(
        handles=legend_handles,
        loc="upper center",
        bbox_to_anchor=(0.5, 0.88),
        ncol=min(3, max(1, len(legend_handles))),
        columnspacing=1.6,
        handletextpad=0.6,
    )
    _save_figure(
        fig,
        output_dir,
        created_files,
        "02_tradeoff_frontiers.png",
        "Score, Runtime, and Cost Tradeoffs",
        "Two-panel tradeoff view showing which configurations sit on or near the runtime-performance and cost-performance frontiers. Direct point labels are replaced by a shared legend so dense clusters remain readable.",
        tight_rect=(0.02, 0.02, 0.98, 0.82),
    )


def _plot_reliability_and_coverage(
    plt,
    output_dir: Path,
    created_files: List[Dict[str, str]],
    variant_df,
    color_map: Dict[str, str],
    *,
    title_prefix: str,
) -> None:
    reliability_df = variant_df.copy()
    reliability_df["worker_assignment_failed_rate"] = reliability_df["worker_assignment_failed_rate"].fillna(0.0) if "worker_assignment_failed_rate" in reliability_df.columns else 0.0
    reliability_df["analysis_failure_rate"] = reliability_df["analysis_failure_rate"].fillna(0.0)
    reliability_df["pure_analysis_error_rate"] = (
        reliability_df["analysis_failure_rate"] - reliability_df["worker_assignment_failed_rate"]
    ).clip(lower=0.0)
    reliability_df["validator_blocked_rate"] = reliability_df["validator_blocked_rate"].fillna(0.0)
    reliability_df["judge_error_rate"] = reliability_df["judge_error_rate"].fillna(0.0)
    reliability_df["completion_rate"] = reliability_df["completion_rate"].fillna(0.0)
    reliability_df["missing_coverage_rate"] = (1.0 - reliability_df["completion_rate"]).clip(lower=0.0)
    reliability_df["completed_judged_rate"] = (
        1.0
        - reliability_df["missing_coverage_rate"]
        - reliability_df["validator_blocked_rate"]
        - reliability_df["judge_error_rate"]
        - reliability_df["pure_analysis_error_rate"]
        - reliability_df["worker_assignment_failed_rate"]
    ).clip(lower=0.0)
    reliability_df = reliability_df.sort_values(["overall_score_mean", "task_success_rate"], ascending=[False, False]).reset_index(drop=True)

    fig, axes = plt.subplots(1, 2, figsize=(15.8, max(5.6, 0.72 * len(reliability_df) + 1.9)))
    left, right = axes
    y_positions = list(range(len(reliability_df)))
    left.set_yticks(y_positions)
    left.set_yticklabels([_wrap_label(label, width=18) for label in list(reliability_df["short_label"])])
    left.invert_yaxis()
    cumulative = [0.0] * len(reliability_df)
    segments = [
        ("completed_judged_rate", "Completed / judged", FAILURE_COLORS["completed_judged"]),
        ("validator_blocked_rate", "Validator blocked", FAILURE_COLORS["validator_blocked"]),
        ("judge_error_rate", "Judge error", FAILURE_COLORS["judge_error"]),
        ("pure_analysis_error_rate", "Analysis-stage failure", FAILURE_COLORS["analysis_error"]),
        ("worker_assignment_failed_rate", "Worker/transport failure", FAILURE_COLORS["worker_assignment_failed"]),
        ("missing_coverage_rate", "Missing coverage", FAILURE_COLORS["missing_coverage"]),
    ]
    for field, label, color in segments:
        values = [float(row[field] or 0.0) for _, row in reliability_df.iterrows()]
        left.barh(y_positions, values, left=cumulative, color=color, label=label, height=0.66)
        cumulative = [base + value for base, value in zip(cumulative, values)]
    left.set_xlim(0, 1.0)
    left.set_xlabel("Rate")
    left.set_title("Outcome breakdown", fontsize=13)
    _style_axes(left, grid_axis="x")
    _apply_axis_formatter(left, axis="x", kind="percent")

    right.set_yticks(y_positions)
    right.set_yticklabels([])
    right.invert_yaxis()
    right.scatter(reliability_df["completion_rate"], y_positions, s=95, color="#2563eb", label="Repetition coverage", zorder=3)
    right.scatter(reliability_df["task_success_rate"], y_positions, s=95, color="#1f8a5b", marker="s", label="Task success", zorder=3)
    for y_pos, (_, row) in zip(y_positions, reliability_df.iterrows()):
        completed_reps = int(row.get("completed_repetitions") or 0)
        planned_reps = int(row.get("planned_repetitions") or 0)
        if completed_reps >= planned_reps and planned_reps > 0:
            continue
        right.text(
            min(max(float(row["completion_rate"] or 0.0), float(row["task_success_rate"] or 0.0)) + 0.03, 0.97),
            y_pos,
            f"{completed_reps}/{planned_reps} reps",
            va="center",
            ha="left",
            fontsize=8.5,
            color="#1f2937",
        )
    right.set_xlim(0, 1.0)
    right.set_xlabel("Rate")
    right.set_title("Coverage vs quality", fontsize=13)
    _style_axes(right, grid_axis="x")
    _apply_axis_formatter(right, axis="x", kind="percent")

    left_handles, left_labels = left.get_legend_handles_labels()
    right_handles, right_labels = right.get_legend_handles_labels()
    fig.suptitle(_title(title_prefix, "Reliability and Coverage"), y=0.98, fontsize=16, fontweight="semibold")
    fig.legend(
        left_handles + right_handles,
        left_labels + right_labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 0.90),
        ncol=4,
        columnspacing=1.4,
        handletextpad=0.6,
    )
    _save_figure(
        fig,
        output_dir,
        created_files,
        "03_reliability_and_coverage.png",
        "Reliability and Coverage",
        "Two-panel view separating completed results from validator blocks, judge errors, analysis failures, worker/transport failures, and missing coverage, alongside repetition coverage versus task-success rates.",
        tight_rect=(0.02, 0.02, 0.98, 0.84),
    )


def _plot_task_category_score_deltas(
    plt,
    output_dir: Path,
    created_files: List[Dict[str, str]],
    technique_df,
    color_map: Dict[str, str],
    *,
    title_prefix: str,
) -> None:
    import pandas as pd

    plot_df = technique_df[technique_df["variant_id"] != "baseline"].dropna(subset=["score_delta"]).copy()
    if plot_df.empty:
        return
    plot_df["short_label"] = plot_df["display_label"].map(_short_config_label)
    plot_df["technique_label"] = plot_df["technique"].map(_short_category_label)
    ordering = (
        plot_df.groupby("technique_label")["score_delta"]
        .agg(lambda values: max(abs(float(value or 0.0)) for value in values))
        .sort_values(ascending=False)
    )
    selected_categories = list(ordering.index[:8])
    plot_df = plot_df[plot_df["technique_label"].isin(selected_categories)].copy()
    plot_df["technique_label"] = pd.Categorical(plot_df["technique_label"], categories=selected_categories, ordered=True)
    plot_df = plot_df.sort_values(["technique_label", "short_label"])

    variant_ids = [variant_id for variant_id in plot_df["variant_id"].drop_duplicates() if str(variant_id)]
    marker_map = _build_marker_map(plot_df[["variant_id"]].drop_duplicates().assign(display_label=lambda frame: frame["variant_id"], short_label=lambda frame: frame["variant_id"]))
    fig, ax = plt.subplots(figsize=(12.8, max(5.0, len(selected_categories) * 0.70 + 2.2)))
    base_positions = list(range(len(selected_categories)))
    total_span = 0.58
    if len(variant_ids) <= 1:
        offsets = {variant_ids[0]: 0.0} if variant_ids else {}
    else:
        offsets = {
            variant_id: -total_span / 2 + (index * (total_span / (len(variant_ids) - 1)))
            for index, variant_id in enumerate(variant_ids)
        }
    for variant_index, variant_id in enumerate(variant_ids):
        variant_slice = plot_df[plot_df["variant_id"] == variant_id].set_index("technique_label")
        values = [float(variant_slice.loc[label, "score_delta"]) if label in variant_slice.index else 0.0 for label in selected_categories]
        positions = [base_pos + offsets.get(variant_id, 0.0) for base_pos in base_positions]
        ax.hlines(
            positions,
            [0.0] * len(values),
            values,
            color=color_map.get(str(variant_id), NEUTRAL_COLOR),
            linewidth=1.2,
            alpha=0.26,
            zorder=2,
        )
        ax.scatter(
            values,
            positions,
            s=78,
            color=color_map.get(str(variant_id), NEUTRAL_COLOR),
            marker=marker_map.get(str(variant_id), MARKER_SEQUENCE[variant_index % len(MARKER_SEQUENCE)]),
            edgecolor="white",
            linewidth=0.8,
            label=_short_config_label(variant_slice["display_label"].iloc[0]) if not variant_slice.empty else _short_config_label(variant_id),
            zorder=3,
        )
    ax.axvline(0.0, color="#475569", linewidth=1.2, linestyle="--")
    ax.set_yticks(base_positions)
    ax.set_yticklabels([_wrap_label(label, width=18) for label in selected_categories])
    ax.set_xlabel("Score delta vs baseline")
    ax.set_title(_title(title_prefix, "Score Delta by Task Category"))
    _style_axes(ax, grid_axis="x")
    _apply_axis_formatter(ax, axis="x", kind="number")
    all_values = [float(value or 0.0) for value in plot_df["score_delta"].tolist()]
    max_abs = max((abs(value) for value in all_values), default=1.0)
    padding = max(3.0, max_abs * 0.10)
    ax.set_xlim(-(max_abs + padding), max_abs + padding)
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.10),
        ncol=min(3, max(1, len(variant_ids))),
        columnspacing=1.6,
        handletextpad=0.6,
    )
    ax.invert_yaxis()
    _save_figure(
        fig,
        output_dir,
        created_files,
        "04_task_category_score_deltas.png",
        "Score Delta by Task Category",
        "Comparative dot plot showing which configurations help or hurt specific technique/task categories relative to baseline without the clutter of overlapping filled bars.",
    )


def _plot_task_category_runtime(
    plt,
    output_dir: Path,
    created_files: List[Dict[str, str]],
    timing_task_tag_df,
    color_map: Dict[str, str],
    *,
    title_prefix: str,
) -> None:
    import pandas as pd

    plot_df = timing_task_tag_df.dropna(subset=["mean_task_wall_clock_duration_sec"]).copy()
    if plot_df.empty:
        return
    plot_df["short_label"] = plot_df["display_label"].map(_short_config_label)
    plot_df["task_tag_label"] = plot_df["task_tag"].map(_short_category_label)
    baseline_df = plot_df[plot_df["variant_id"] == "baseline"].copy()
    if baseline_df.empty:
        return
    ordering = baseline_df.sort_values("mean_task_wall_clock_duration_sec", ascending=False)["task_tag_label"].tolist()
    ordering = ordering[:8]
    plot_df = plot_df[plot_df["task_tag_label"].isin(ordering)].copy()
    baseline_df = baseline_df[baseline_df["task_tag_label"].isin(ordering)].copy()
    plot_df["task_tag_label"] = pd.Categorical(plot_df["task_tag_label"], categories=list(reversed(ordering)), ordered=True)
    baseline_df["task_tag_label"] = pd.Categorical(baseline_df["task_tag_label"], categories=list(reversed(ordering)), ordered=True)

    fig, axes = plt.subplots(1, 2, figsize=(15.8, max(5.2, len(ordering) * 0.58 + 2.3)))
    left, right = axes

    baseline_df = baseline_df.sort_values("task_tag_label")
    left.barh(
        list(range(len(baseline_df))),
        list(baseline_df["mean_task_wall_clock_duration_sec"]),
        color=BASELINE_COLOR,
        height=0.62,
    )
    left.set_yticks(list(range(len(baseline_df))))
    left.set_yticklabels([_wrap_label(label, width=18) for label in list(baseline_df["task_tag_label"])])
    left.set_xlabel("Mean wall-clock duration (s)")
    left.set_title("Baseline bottlenecks", fontsize=13)
    _style_axes(left, grid_axis="x")
    _apply_axis_formatter(left, axis="x", kind="number")

    delta_df = plot_df[plot_df["variant_id"] != "baseline"].dropna(subset=["task_wall_clock_delta_sec"]).copy()
    if delta_df.empty:
        right.axis("off")
    else:
        variant_ids = [variant_id for variant_id in delta_df["variant_id"].drop_duplicates() if str(variant_id)]
        marker_map = _build_marker_map(delta_df[["variant_id"]].drop_duplicates().assign(display_label=lambda frame: frame["variant_id"], short_label=lambda frame: frame["variant_id"]))
        y_positions = {label: index for index, label in enumerate(list(reversed(ordering)))}
        for variant_index, variant_id in enumerate(variant_ids):
            variant_slice = delta_df[delta_df["variant_id"] == variant_id]
            xs = [float(value or 0.0) for value in variant_slice["task_wall_clock_delta_sec"]]
            ys = [y_positions[str(label)] for label in variant_slice["task_tag_label"]]
            right.scatter(
                xs,
                ys,
                s=72,
                color=color_map.get(str(variant_id), NEUTRAL_COLOR),
                marker=marker_map.get(str(variant_id), MARKER_SEQUENCE[variant_index % len(MARKER_SEQUENCE)]),
                edgecolor="white",
                linewidth=0.8,
                label=_short_config_label(variant_slice["display_label"].iloc[0]),
            )
        right.axvline(0.0, color="#475569", linewidth=1.2, linestyle="--")
        right.set_yticks(list(range(len(ordering))))
        right.set_yticklabels([_wrap_label(label, width=18) for label in list(reversed(ordering))])
        right.set_xlabel("Runtime delta vs baseline (s)")
        right.set_title("Variant runtime shift", fontsize=13)
        _style_axes(right, grid_axis="x")
        _apply_axis_formatter(right, axis="x", kind="number")
        right.legend(
            loc="upper center",
            bbox_to_anchor=(0.5, -0.10),
            ncol=min(3, max(1, len(variant_ids))),
            columnspacing=1.6,
            handletextpad=0.6,
        )

    fig.suptitle(_title(title_prefix, "Runtime by Task Category"), y=0.98, fontsize=16, fontweight="semibold")
    _save_figure(
        fig,
        output_dir,
        created_files,
        "05_task_category_runtime.png",
        "Runtime by Task Category",
        "Two-panel runtime view showing baseline task-category bottlenecks and the runtime delta introduced by each configuration relative to baseline.",
        tight_rect=(0.02, 0.04, 0.98, 0.92),
    )


def _plot_task_score_distribution(
    plt,
    output_dir: Path,
    created_files: List[Dict[str, str]],
    task_df,
    color_map: Dict[str, str],
    variant_order: List[str],
    *,
    title_prefix: str,
) -> None:
    distribution_df = task_df.dropna(subset=["score"]).copy()
    if distribution_df.empty:
        return
    grouped = []
    labels = []
    colors = []
    for variant_id in variant_order:
        values = [
            float(value)
            for value in distribution_df.loc[distribution_df["variant_id"] == variant_id, "score"].tolist()
            if value is not None
        ]
        if not values:
            continue
        grouped.append(values)
        label_row = distribution_df.loc[distribution_df["variant_id"] == variant_id, "display_label"]
        label = _short_config_label(label_row.iloc[0] if not label_row.empty else variant_id)
        labels.append(_wrap_label(label, width=18))
        colors.append(color_map.get(str(variant_id), NEUTRAL_COLOR))
    if not grouped:
        return
    fig, ax = plt.subplots(figsize=(11.5, max(4.8, len(grouped) * 0.78 + 1.8)))
    boxplot = ax.boxplot(grouped, vert=False, patch_artist=True, labels=labels, widths=0.6, medianprops={"color": "#111827", "linewidth": 1.8})
    for patch, color in zip(boxplot["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.72)
        patch.set_edgecolor("#1f2937")
    for position, values, color in zip(range(1, len(grouped) + 1), grouped, colors):
        offsets = [position + ((index - (len(values) - 1) / 2) * 0.04) for index in range(len(values))]
        ax.scatter(values, offsets, s=20, color=color, edgecolor="white", linewidth=0.4, alpha=0.45, zorder=3)
    ax.set_xlim(0, 100)
    ax.set_xlabel("Per-task aggregate score")
    ax.set_title(_title(title_prefix, "Per-Task Score Distribution"))
    _style_axes(ax, grid_axis="x")
    _apply_axis_formatter(ax, axis="x", kind="number")
    _save_figure(
        fig,
        output_dir,
        created_files,
        "06_task_score_distribution.png",
        "Per-Task Score Distribution",
        "Horizontal box-and-dot plot showing how widely each configuration's task-level scores vary across the experiment scope, which is more informative than a dense per-task heatmap for consistency analysis.",
    )


def _plot_effect_size_summary(
    plt,
    output_dir: Path,
    created_files: List[Dict[str, str]],
    significance_overall_rows: List[Dict[str, Any]],
    color_map: Dict[str, str],
    *,
    title_prefix: str,
) -> None:
    if not significance_overall_rows:
        return
    import pandas as pd

    sig_df = pd.DataFrame(significance_overall_rows or [])
    if sig_df.empty:
        return
    sig_df = _coerce_numeric_frame(sig_df, ["effect_size_hedges_g", "mean_diff", "p_value", "variant_n", "baseline_n"])
    sig_df = sig_df.dropna(subset=["effect_size_hedges_g", "mean_diff"]).copy()
    if sig_df.empty:
        return
    sig_df["short_label"] = sig_df["display_label"].map(_short_config_label)
    sig_df = sig_df.sort_values("effect_size_hedges_g", ascending=True).reset_index(drop=True)

    fig, ax = plt.subplots(figsize=(11.5, max(4.8, 0.82 * len(sig_df) + 1.8)))
    y_positions = list(range(len(sig_df)))
    ax.axvline(0.0, color="#475569", linestyle="--", linewidth=1.2)
    for threshold in (-0.8, -0.5, -0.2, 0.2, 0.5, 0.8):
        ax.axvline(threshold, color="#e5e7eb", linestyle=":", linewidth=0.9, zorder=0)
    for y_pos, (_, row) in zip(y_positions, sig_df.iterrows()):
        variant_id = str(row["variant_id"])
        effect_size = float(row["effect_size_hedges_g"])
        mean_diff = float(row["mean_diff"])
        is_significant = str(row.get("statistically_significant_95pct") or "").lower() in {"1", "true", "yes"}
        ax.hlines(y_pos, 0.0, effect_size, color=color_map.get(variant_id, NEUTRAL_COLOR), linewidth=2.4)
        ax.scatter(
            [effect_size],
            [y_pos],
            s=110,
            color=color_map.get(variant_id, NEUTRAL_COLOR),
            edgecolor="#111827" if is_significant else "white",
            linewidth=1.4,
            zorder=3,
        )
        ax.text(
            effect_size + (0.05 if effect_size >= 0.0 else -0.05),
            y_pos,
            f"Δ {mean_diff:+.1f}",
            va="center",
            ha="left" if effect_size >= 0.0 else "right",
            fontsize=8.8,
            color="#1f2937",
        )
    ax.set_yticks(y_positions)
    ax.set_yticklabels([_wrap_label(label, width=18) for label in list(sig_df["short_label"])])
    ax.set_xlabel("Hedges' g effect size")
    ax.set_title(_title(title_prefix, "Effect Size Summary"))
    _style_axes(ax, grid_axis="x")
    _apply_axis_formatter(ax, axis="x", kind="number")
    _save_figure(
        fig,
        output_dir,
        created_files,
        "07_effect_size_summary.png",
        "Effect Size Summary",
        "Effect-size-first summary of replicate-level significance tests. Text density is reduced so the chart foregrounds practical magnitude; outlined markers indicate nominal 95% significance.",
    )


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
    title_prefix: str = "",
) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import pandas as pd
    except Exception as exc:  # pragma: no cover - optional dependency at runtime
        for stale_name in ("chart_manifest.json", "figure_guide.md"):
            stale_path = output_dir / stale_name
            if stale_path.exists():
                try:
                    stale_path.unlink()
                except Exception:
                    pass
        error_payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "created_files": []}
        (output_dir / "visualization_error.json").write_text(json.dumps(error_payload, indent=2) + "\n", encoding="utf-8")
        return error_payload

    _configure_matplotlib(plt)
    created_files: List[Dict[str, str]] = []
    warnings: List[Dict[str, str]] = []

    variant_df = pd.DataFrame(variant_rows or [])
    task_df = pd.DataFrame(task_rows or [])
    technique_df = pd.DataFrame(technique_rows or [])
    timing_tag_df = pd.DataFrame(timing_task_tag_rows or [])

    if not variant_df.empty:
        variant_df = variant_df.copy()
        variant_df["display_label"] = variant_df["display_label"].fillna(variant_df["variant_id"])
        variant_df["short_label"] = variant_df["display_label"].map(_short_config_label)
        variant_df = _coerce_numeric_frame(
            variant_df,
            [
                "overall_score_mean",
                "overall_score_stddev",
                "task_success_rate",
                "task_success_rate_stddev",
                "score_delta",
                "task_success_delta",
                "completion_rate",
                "validator_blocked_rate",
                "worker_assignment_failed_rate",
                "analysis_failure_rate",
                "judge_error_rate",
                "mean_relative_cost_index",
                "mean_task_wall_clock_duration_sec",
                "completed_repetitions",
                "planned_repetitions",
            ],
        )
        variant_df["completion_rate"] = variant_df["completion_rate"].fillna(
            variant_df.apply(
                lambda row: (
                    float(row["completed_repetitions"] or 0.0) / float(row["planned_repetitions"] or 0.0)
                    if row.get("planned_repetitions")
                    else 0.0
                ),
                axis=1,
            )
        )
        variant_df["worker_assignment_failed_rate"] = variant_df["worker_assignment_failed_rate"].fillna(0.0) if "worker_assignment_failed_rate" in variant_df.columns else 0.0
        variant_df["is_baseline"] = variant_df["is_baseline"].astype(str).str.lower().isin({"1", "true", "yes"})
        variant_df = variant_df.sort_values(
            ["is_baseline", "overall_score_mean", "task_success_rate"],
            ascending=[False, False, False],
        ).reset_index(drop=True)
        _write_label_legend(output_dir, variant_df)

    if not task_df.empty:
        task_df = task_df.copy()
        task_df["display_label"] = task_df["display_label"].fillna(task_df["variant_id"])
        task_df = _coerce_numeric_frame(task_df, ["score", "baseline_score", "score_delta", "task_success_rate"])

    if not technique_df.empty:
        technique_df = technique_df.copy()
        technique_df["display_label"] = technique_df["display_label"].fillna(technique_df["variant_id"])
        technique_df = _coerce_numeric_frame(technique_df, ["score_delta", "mean_score", "baseline_mean_score"])

    if not timing_tag_df.empty:
        timing_tag_df = timing_tag_df.copy()
        timing_tag_df["display_label"] = timing_tag_df["display_label"].fillna(timing_tag_df["variant_id"])
        timing_tag_df = _coerce_numeric_frame(
            timing_tag_df,
            ["mean_task_wall_clock_duration_sec", "task_wall_clock_delta_sec"],
        )

    color_map = _build_color_map(variant_df) if not variant_df.empty else {"baseline": BASELINE_COLOR}
    variant_order = list(variant_df["variant_id"]) if not variant_df.empty else []

    plot_jobs = [
        ("overall ranking", lambda: _plot_overall_performance_ranking(plt, output_dir, created_files, variant_df, color_map, title_prefix=title_prefix)),
        ("tradeoff view", lambda: _plot_tradeoff_views(plt, output_dir, created_files, variant_df, color_map, title_prefix=title_prefix)),
        ("reliability and coverage", lambda: _plot_reliability_and_coverage(plt, output_dir, created_files, variant_df, color_map, title_prefix=title_prefix)),
        ("task category score deltas", lambda: _plot_task_category_score_deltas(plt, output_dir, created_files, technique_df, color_map, title_prefix=title_prefix)),
        ("task category runtime", lambda: _plot_task_category_runtime(plt, output_dir, created_files, timing_tag_df, color_map, title_prefix=title_prefix)),
        ("task score distribution", lambda: _plot_task_score_distribution(plt, output_dir, created_files, task_df, color_map, variant_order, title_prefix=title_prefix)),
        ("effect size summary", lambda: _plot_effect_size_summary(plt, output_dir, created_files, list(significance_overall_rows or []), color_map, title_prefix=title_prefix)),
    ]

    for label, plot_job in plot_jobs:
        try:
            if variant_df.empty and label in {"overall ranking", "tradeoff view", "reliability and coverage"}:
                continue
            plot_job()
        except Exception as exc:  # pragma: no cover - defensive plotting isolation
            plt.close("all")
            warnings.append({"plot": label, "error": f"{type(exc).__name__}: {exc}"})

    if warnings:
        (output_dir / "visualization_warnings.json").write_text(json.dumps({"ok": False, "warnings": warnings}, indent=2) + "\n", encoding="utf-8")
    else:
        warning_path = output_dir / "visualization_warnings.json"
        if warning_path.exists():
            try:
                warning_path.unlink()
            except Exception:
                pass

    if created_files:
        error_path = output_dir / "visualization_error.json"
        if error_path.exists():
            try:
                error_path.unlink()
            except Exception:
                pass
        _write_figure_guide(output_dir, created_files)
        manifest = {
            "ok": not warnings,
            "created_files": created_files,
            "warnings": warnings,
            "label_legend_path": str(output_dir / "config_label_legend.json"),
            "figure_guide_path": str(output_dir / "figure_guide.md"),
        }
        (output_dir / "chart_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return manifest

    error_payload = {
        "ok": False,
        "error": warnings[0]["error"] if warnings else "No figures were generated",
        "warnings": warnings,
        "created_files": [],
    }
    manifest_path = output_dir / "chart_manifest.json"
    if manifest_path.exists():
        try:
            manifest_path.unlink()
        except Exception:
            pass
    (output_dir / "visualization_error.json").write_text(json.dumps(error_payload, indent=2) + "\n", encoding="utf-8")
    return error_payload
