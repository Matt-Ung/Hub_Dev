"""
File: significance.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Compute exploratory statistical comparisons over experiment results.

Summary:
  This module runs the maintained permutation and sign-flip tests used by the
  experiment report stack. It writes structured significance tables while
  keeping the results clearly exploratory rather than confirmatory.
"""

from __future__ import annotations

import csv
import itertools
import math
import random
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List, Tuple

from .paths import ensure_dir, write_json


DEFAULT_CONFIDENCE_LEVEL = 0.95
DEFAULT_ALPHA = 0.05
MAX_EXACT_PERMUTATIONS = 200_000
MONTE_CARLO_SAMPLES = 50_000


def _write_rows_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    ensure_dir(path.parent)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: List[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _safe_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except Exception:
        return None


def _record_score(record: Dict[str, Any]) -> float | None:
    metrics = record.get("metrics") or {}
    value = _safe_float(metrics.get("overall_score_0_to_100"))
    if value is not None:
        return value
    if str(metrics.get("judge_status") or "") == "judge_error":
        return 0.0
    return None


def _mean(values: Iterable[float]) -> float | None:
    cleaned = [float(value) for value in values]
    return round(mean(cleaned), 6) if cleaned else None


def _variance(values: List[float], sample_mean: float | None = None) -> float | None:
    if len(values) < 2:
        return None
    mu = sample_mean if sample_mean is not None else float(mean(values))
    return sum((float(value) - mu) ** 2 for value in values) / (len(values) - 1)


def _hedges_g(a: List[float], b: List[float]) -> float | None:
    if len(a) < 2 or len(b) < 2:
        return None
    mean_a = float(mean(a))
    mean_b = float(mean(b))
    var_a = _variance(a, mean_a)
    var_b = _variance(b, mean_b)
    if var_a is None or var_b is None:
        return None
    pooled_num = (len(a) - 1) * var_a + (len(b) - 1) * var_b
    pooled_den = len(a) + len(b) - 2
    if pooled_den <= 0:
        return None
    pooled_std = math.sqrt(max(pooled_num / pooled_den, 0.0))
    if pooled_std == 0.0:
        return None
    cohen_d = (mean_a - mean_b) / pooled_std
    correction = 1.0 - (3.0 / (4.0 * (len(a) + len(b)) - 9.0)) if (len(a) + len(b)) > 2 else 1.0
    return round(cohen_d * correction, 6)


def _effect_label(effect_size: float | None) -> str:
    if effect_size is None:
        return "n/a"
    magnitude = abs(effect_size)
    if magnitude < 0.2:
        return "negligible"
    if magnitude < 0.5:
        return "small"
    if magnitude < 0.8:
        return "medium"
    return "large"


def _permutation_p_value(a: List[float], b: List[float]) -> Tuple[float | None, str, int]:
    if len(a) < 2 or len(b) < 2:
        return None, "insufficient_repetitions", 0

    observed = abs(float(mean(a)) - float(mean(b)))
    pooled = list(a) + list(b)
    n_a = len(a)
    total_permutations = math.comb(len(pooled), n_a)

    if total_permutations <= MAX_EXACT_PERMUTATIONS:
        indices = range(len(pooled))
        extreme = 0
        for combo in itertools.combinations(indices, n_a):
            combo_set = set(combo)
            group_a = [pooled[idx] for idx in combo_set]
            group_b = [pooled[idx] for idx in indices if idx not in combo_set]
            diff = abs(float(mean(group_a)) - float(mean(group_b)))
            if diff >= observed - 1e-12:
                extreme += 1
        return round(extreme / total_permutations, 6), "exact_permutation", total_permutations

    rng = random.Random(1337)
    extreme = 0
    trials = MONTE_CARLO_SAMPLES
    for _ in range(trials):
        shuffled = list(pooled)
        rng.shuffle(shuffled)
        group_a = shuffled[:n_a]
        group_b = shuffled[n_a:]
        diff = abs(float(mean(group_a)) - float(mean(group_b)))
        if diff >= observed - 1e-12:
            extreme += 1
    return round(extreme / trials, 6), "monte_carlo_permutation", trials


def _comparison_row(
    *,
    scope: str,
    changed_variable: str,
    variant_id: str,
    display_label: str,
    comparison_baseline_id: str,
    comparison_baseline_label: str,
    metric_name: str,
    variant_values: List[float],
    baseline_values: List[float],
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    extra = dict(extra or {})
    variant_mean = _mean(variant_values)
    baseline_mean = _mean(baseline_values)
    mean_diff = (
        round(float(variant_mean) - float(baseline_mean), 6)
        if variant_mean is not None and baseline_mean is not None
        else None
    )
    p_value, method, iteration_count = _permutation_p_value(variant_values, baseline_values)
    effect_size = _hedges_g(variant_values, baseline_values)
    statistically_significant = bool(p_value is not None and p_value <= DEFAULT_ALPHA)
    direction = "no_change"
    if mean_diff is not None:
        if mean_diff > 0:
            direction = "improved"
        elif mean_diff < 0:
            direction = "degraded"
    status = "ok" if p_value is not None else "insufficient_repetitions"
    row = {
        "scope": scope,
        "metric": metric_name,
        "changed_variable": changed_variable,
        "variant_id": variant_id,
        "display_label": display_label,
        "comparison_baseline_id": comparison_baseline_id,
        "comparison_baseline_label": comparison_baseline_label,
        "variant_n": len(variant_values),
        "baseline_n": len(baseline_values),
        "variant_mean": variant_mean,
        "baseline_mean": baseline_mean,
        "mean_diff": mean_diff,
        "effect_size_hedges_g": effect_size,
        "effect_size_label": _effect_label(effect_size),
        "p_value": p_value,
        "confidence_equivalent": round(1.0 - float(p_value), 6) if p_value is not None else None,
        "confidence_level_target": DEFAULT_CONFIDENCE_LEVEL,
        "alpha_threshold": DEFAULT_ALPHA,
        "statistically_significant_95pct": statistically_significant,
        "direction": direction,
        "test_method": method,
        "test_iteration_count": iteration_count,
        "status": status,
    }
    row.update(extra)
    return row


def _overall_series(successful_entries: List[Dict[str, Any]]) -> Dict[str, List[float]]:
    by_variant: Dict[str, List[float]] = defaultdict(list)
    for entry in successful_entries:
        aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
        score = _safe_float(aggregate.get("overall_score_mean"))
        if score is None:
            continue
        by_variant[str(entry.get("variant_id") or "")].append(score)
    return dict(by_variant)


def _difficulty_series(successful_entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[float]]]:
    by_variant: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    for entry in successful_entries:
        aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
        by_difficulty = aggregate.get("by_difficulty") if isinstance(aggregate.get("by_difficulty"), dict) else {}
        for difficulty, bucket in by_difficulty.items():
            score = _safe_float((bucket or {}).get("mean_score"))
            if score is not None:
                by_variant[str(entry.get("variant_id") or "")][str(difficulty)].append(score)
    return {variant: dict(groups) for variant, groups in by_variant.items()}


def _task_series(successful_entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[float]]]:
    by_variant: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    for entry in successful_entries:
        aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
        for record in aggregate.get("records") or []:
            if not isinstance(record, dict):
                continue
            score = _record_score(record)
            if score is None:
                continue
            sample_task_id = str(record.get("sample_task_id") or "").strip()
            if sample_task_id:
                by_variant[str(entry.get("variant_id") or "")][sample_task_id].append(score)
    return {variant: dict(groups) for variant, groups in by_variant.items()}


def _task_difficulty_map(successful_entries: List[Dict[str, Any]]) -> Dict[str, str]:
    difficulty_map: Dict[str, str] = {}
    for entry in successful_entries:
        aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
        for record in aggregate.get("records") or []:
            if not isinstance(record, dict):
                continue
            sample_task_id = str(record.get("sample_task_id") or "").strip()
            difficulty = str(record.get("difficulty") or "unknown").strip() or "unknown"
            if sample_task_id and sample_task_id not in difficulty_map:
                difficulty_map[sample_task_id] = difficulty
    return difficulty_map


def _paired_sign_flip_p_value(differences: List[float]) -> Tuple[float | None, str, int]:
    cleaned = [float(value) for value in differences if abs(float(value)) > 1e-12]
    if len(cleaned) < 2:
        return None, "insufficient_pairs", 0
    magnitudes = [abs(value) for value in cleaned]
    observed = abs(sum(cleaned))
    total_assignments = 2 ** len(magnitudes)
    if total_assignments <= MAX_EXACT_PERMUTATIONS:
        extreme = 0
        for sign_bits in itertools.product((-1.0, 1.0), repeat=len(magnitudes)):
            statistic = abs(sum(sign * mag for sign, mag in zip(sign_bits, magnitudes)))
            if statistic >= observed - 1e-12:
                extreme += 1
        return round(extreme / total_assignments, 6), "exact_sign_flip", total_assignments

    rng = random.Random(1337)
    extreme = 0
    for _ in range(MONTE_CARLO_SAMPLES):
        statistic = abs(sum((1.0 if rng.random() >= 0.5 else -1.0) * mag for mag in magnitudes))
        if statistic >= observed - 1e-12:
            extreme += 1
    return round(extreme / MONTE_CARLO_SAMPLES, 6), "monte_carlo_sign_flip", MONTE_CARLO_SAMPLES


def _paired_task_row(
    *,
    changed_variable: str,
    variant_id: str,
    display_label: str,
    comparison_baseline_id: str,
    comparison_baseline_label: str,
    variant_task_scores: Dict[str, float],
    baseline_task_scores: Dict[str, float],
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    extra = dict(extra or {})
    shared_task_ids = sorted(set(variant_task_scores.keys()) & set(baseline_task_scores.keys()))
    diffs = [float(variant_task_scores[task_id]) - float(baseline_task_scores[task_id]) for task_id in shared_task_ids]
    p_value, method, iteration_count = _paired_sign_flip_p_value(diffs)
    mean_diff = _mean(diffs)
    statistically_significant = bool(p_value is not None and p_value <= DEFAULT_ALPHA)
    direction = "no_change"
    if mean_diff is not None:
        if mean_diff > 0:
            direction = "improved"
        elif mean_diff < 0:
            direction = "degraded"
    row = {
        "inference_basis": "paired_task",
        "changed_variable": changed_variable,
        "variant_id": variant_id,
        "display_label": display_label,
        "comparison_baseline_id": comparison_baseline_id,
        "comparison_baseline_label": comparison_baseline_label,
        "matched_task_count": len(shared_task_ids),
        "mean_task_delta": mean_diff,
        "p_value": p_value,
        "confidence_equivalent": round(1.0 - float(p_value), 6) if p_value is not None else None,
        "confidence_level_target": DEFAULT_CONFIDENCE_LEVEL,
        "alpha_threshold": DEFAULT_ALPHA,
        "statistically_significant_95pct": statistically_significant,
        "direction": direction,
        "test_method": method,
        "test_iteration_count": iteration_count,
        "status": "ok" if p_value is not None else "insufficient_pairs",
    }
    row.update(extra)
    return row


def build_significance_outputs(
    output_dir: Path,
    *,
    successful_entries: List[Dict[str, Any]],
    variant_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    output_dir = ensure_dir(output_dir)
    overall_by_variant = _overall_series(successful_entries)
    difficulty_by_variant = _difficulty_series(successful_entries)
    task_by_variant = _task_series(successful_entries)
    task_difficulty = _task_difficulty_map(successful_entries)

    overall_rows: List[Dict[str, Any]] = []
    difficulty_rows: List[Dict[str, Any]] = []
    task_rows: List[Dict[str, Any]] = []
    paired_task_overall_rows: List[Dict[str, Any]] = []
    paired_task_difficulty_rows: List[Dict[str, Any]] = []

    comparison_targets = [
        row for row in variant_rows
        if not bool(row.get("is_baseline")) and not bool(row.get("is_family_baseline"))
    ]

    for row in comparison_targets:
        variant_id = str(row.get("variant_id") or "")
        baseline_id = str(row.get("comparison_baseline_id") or "baseline")
        variant_values = list(overall_by_variant.get(variant_id) or [])
        baseline_values = list(overall_by_variant.get(baseline_id) or [])
        overall_rows.append(
            _comparison_row(
                scope="overall",
                changed_variable=str(row.get("changed_variable") or ""),
                variant_id=variant_id,
                display_label=str(row.get("display_label") or ""),
                comparison_baseline_id=baseline_id,
                comparison_baseline_label=str(row.get("comparison_baseline_label") or "baseline"),
                metric_name="overall_score_mean",
                variant_values=variant_values,
                baseline_values=baseline_values,
            )
        )

        all_difficulties = sorted(set((difficulty_by_variant.get(variant_id) or {}).keys()) | set((difficulty_by_variant.get(baseline_id) or {}).keys()))
        for difficulty in all_difficulties:
            difficulty_rows.append(
                _comparison_row(
                    scope="difficulty",
                    changed_variable=str(row.get("changed_variable") or ""),
                    variant_id=variant_id,
                    display_label=str(row.get("display_label") or ""),
                    comparison_baseline_id=baseline_id,
                    comparison_baseline_label=str(row.get("comparison_baseline_label") or "baseline"),
                    metric_name="difficulty_mean_score",
                    variant_values=list((difficulty_by_variant.get(variant_id) or {}).get(difficulty) or []),
                    baseline_values=list((difficulty_by_variant.get(baseline_id) or {}).get(difficulty) or []),
                    extra={"difficulty": difficulty},
                )
            )

        all_tasks = sorted(set((task_by_variant.get(variant_id) or {}).keys()) | set((task_by_variant.get(baseline_id) or {}).keys()))
        for sample_task_id in all_tasks:
            task_rows.append(
                _comparison_row(
                    scope="task",
                    changed_variable=str(row.get("changed_variable") or ""),
                    variant_id=variant_id,
                    display_label=str(row.get("display_label") or ""),
                    comparison_baseline_id=baseline_id,
                    comparison_baseline_label=str(row.get("comparison_baseline_label") or "baseline"),
                    metric_name="task_score",
                    variant_values=list((task_by_variant.get(variant_id) or {}).get(sample_task_id) or []),
                    baseline_values=list((task_by_variant.get(baseline_id) or {}).get(sample_task_id) or []),
                    extra={"sample_task_id": sample_task_id},
                )
            )

        variant_task_means = {
            task_id: float(_mean(values) or 0.0)
            for task_id, values in (task_by_variant.get(variant_id) or {}).items()
            if _mean(values) is not None
        }
        baseline_task_means = {
            task_id: float(_mean(values) or 0.0)
            for task_id, values in (task_by_variant.get(baseline_id) or {}).items()
            if _mean(values) is not None
        }
        paired_task_overall_rows.append(
            _paired_task_row(
                changed_variable=str(row.get("changed_variable") or ""),
                variant_id=variant_id,
                display_label=str(row.get("display_label") or ""),
                comparison_baseline_id=baseline_id,
                comparison_baseline_label=str(row.get("comparison_baseline_label") or "baseline"),
                variant_task_scores=variant_task_means,
                baseline_task_scores=baseline_task_means,
                extra={"scope": "overall"},
            )
        )

        difficulty_names = sorted({task_difficulty.get(task_id, "unknown") for task_id in set(variant_task_means.keys()) | set(baseline_task_means.keys())})
        for difficulty in difficulty_names:
            variant_subset = {task_id: score for task_id, score in variant_task_means.items() if task_difficulty.get(task_id, "unknown") == difficulty}
            baseline_subset = {task_id: score for task_id, score in baseline_task_means.items() if task_difficulty.get(task_id, "unknown") == difficulty}
            paired_task_difficulty_rows.append(
                _paired_task_row(
                    changed_variable=str(row.get("changed_variable") or ""),
                    variant_id=variant_id,
                    display_label=str(row.get("display_label") or ""),
                    comparison_baseline_id=baseline_id,
                    comparison_baseline_label=str(row.get("comparison_baseline_label") or "baseline"),
                    variant_task_scores=variant_subset,
                    baseline_task_scores=baseline_subset,
                    extra={"scope": "difficulty", "difficulty": difficulty},
                )
            )

    variable_summary_rows: List[Dict[str, Any]] = []
    grouped_overall: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    grouped_task: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    grouped_difficulty: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in overall_rows:
        grouped_overall[str(row.get("changed_variable") or "")].append(row)
    for row in task_rows:
        grouped_task[str(row.get("changed_variable") or "")].append(row)
    for row in difficulty_rows:
        grouped_difficulty[str(row.get("changed_variable") or "")].append(row)

    all_variables = sorted(set(grouped_overall.keys()) | set(grouped_task.keys()) | set(grouped_difficulty.keys()))
    for variable in all_variables:
        overall_group = grouped_overall.get(variable) or []
        task_group = grouped_task.get(variable) or []
        difficulty_group = grouped_difficulty.get(variable) or []
        significant_improvements = [
            row for row in task_group
            if row.get("statistically_significant_95pct") and str(row.get("direction") or "") == "improved"
        ]
        significant_degradations = [
            row for row in task_group
            if row.get("statistically_significant_95pct") and str(row.get("direction") or "") == "degraded"
        ]
        usable_rows = [row for row in overall_group if row.get("p_value") is not None]
        variable_summary_rows.append(
            {
                "changed_variable": variable,
                "overall_variant_count": len(overall_group),
                "overall_significant_count": sum(1 for row in overall_group if row.get("statistically_significant_95pct")),
                "paired_task_overall_significant_count": sum(
                    1 for row in paired_task_overall_rows
                    if str(row.get("changed_variable") or "") == variable and row.get("statistically_significant_95pct")
                ),
                "task_rows": len(task_group),
                "task_significant_improvements": len(significant_improvements),
                "task_significant_degradations": len(significant_degradations),
                "difficulty_rows": len(difficulty_group),
                "minimum_overall_p_value": min((row.get("p_value") for row in usable_rows), default=None),
                "minimum_paired_task_p_value": min(
                    (
                        row.get("p_value")
                        for row in paired_task_overall_rows
                        if str(row.get("changed_variable") or "") == variable and row.get("p_value") is not None
                    ),
                    default=None,
                ),
                "maximum_abs_overall_mean_diff": (
                    max((abs(float(row.get("mean_diff") or 0.0)) for row in overall_group), default=0.0)
                    if overall_group else None
                ),
            }
        )

    report_lines: List[str] = []
    report_lines.append("# Statistical Significance Summary")
    report_lines.append("")
    report_lines.append("- Scoring significance is evaluated against the relevant comparison baseline using a two-sided permutation test on replicate-level scores.")
    report_lines.append("- Score-based significance includes zero-score non-results when a configuration failed to produce an accepted output, so interpret it as combined performance-plus-reliability rather than answer quality alone.")
    report_lines.append("- Confidence target: `0.95`")
    report_lines.append("- Alpha threshold: `0.05`")
    report_lines.append("- `statistically_significant_95pct=true` means the observed score shift achieved `p <= 0.05`.")
    report_lines.append("- No multiple-comparison correction is applied. Task-level and difficulty-level significance rows are exploratory and should not be read as confirmatory evidence.")
    report_lines.append("- When repetitions are too small, rows are marked `insufficient_repetitions` instead of forcing a misleading significance claim.")
    report_lines.append("")
    report_lines.append("## Overall")
    report_lines.append("")
    report_lines.append("| Variant | Variable | Baseline | Variant Mean | Baseline Mean | Mean Diff | p-value | Significant (95%) | Effect | Status |")
    report_lines.append("|---|---|---|---:|---:|---:|---:|---|---|---|")
    for row in overall_rows:
        report_lines.append(
            "| {display_label} | {changed_variable} | {comparison_baseline_label} | {variant_mean} | {baseline_mean} | {mean_diff} | {p_value} | {statistically_significant_95pct} | {effect_size_label} | {status} |".format(**row)
        )
    report_lines.append("")
    report_lines.append("## Paired Across-Task")
    report_lines.append("")
    report_lines.append("- This test does not require repeated whole-run replicates. It compares each variant to its baseline over matched sample-task score deltas within the same sweep.")
    report_lines.append("- Treat it as an exploratory within-sweep stability signal when repetitions are scarce, not as a substitute for independent replicate-level inference.")
    report_lines.append("")
    report_lines.append("| Variant | Variable | Baseline | Matched Tasks | Mean Task Delta | p-value | Significant (95%) | Status |")
    report_lines.append("|---|---|---|---:|---:|---:|---|---|")
    for row in paired_task_overall_rows:
        report_lines.append(
            "| {display_label} | {changed_variable} | {comparison_baseline_label} | {matched_task_count} | {mean_task_delta} | {p_value} | {statistically_significant_95pct} | {status} |".format(**row)
        )
    report_lines.append("")
    report_lines.append("See `significance_by_difficulty.csv`, `significance_by_task.csv`, `paired_task_significance_overall.csv`, and `paired_task_significance_by_difficulty.csv` for the narrower breakdowns.")
    report_lines.append("")

    payload = {
        "confidence_level_target": DEFAULT_CONFIDENCE_LEVEL,
        "alpha_threshold": DEFAULT_ALPHA,
        "test_name": "two_sided_permutation_test_on_replicate_level_scores",
        "multiple_comparison_correction": "none",
        "overall": overall_rows,
        "by_difficulty": difficulty_rows,
        "by_task": task_rows,
        "paired_task_overall": paired_task_overall_rows,
        "paired_task_by_difficulty": paired_task_difficulty_rows,
        "by_variable": variable_summary_rows,
    }
    write_json(output_dir / "significance.json", payload)
    _write_rows_csv(output_dir / "significance_overall.csv", overall_rows)
    _write_rows_csv(output_dir / "significance_by_difficulty.csv", difficulty_rows)
    _write_rows_csv(output_dir / "significance_by_task.csv", task_rows)
    _write_rows_csv(output_dir / "paired_task_significance_overall.csv", paired_task_overall_rows)
    _write_rows_csv(output_dir / "paired_task_significance_by_difficulty.csv", paired_task_difficulty_rows)
    _write_rows_csv(output_dir / "variable_significance_summary.csv", variable_summary_rows)
    (output_dir / "significance_report.md").write_text("\n".join(report_lines).rstrip() + "\n", encoding="utf-8")

    return {
        "ok": True,
        "output_dir": str(output_dir),
        "overall_rows_count": len(overall_rows),
        "difficulty_rows_count": len(difficulty_rows),
        "task_rows_count": len(task_rows),
        "paired_task_overall_rows_count": len(paired_task_overall_rows),
        "paired_task_difficulty_rows_count": len(paired_task_difficulty_rows),
        "variable_rows_count": len(variable_summary_rows),
        "payload": payload,
    }
