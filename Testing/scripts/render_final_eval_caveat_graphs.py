#!/usr/bin/env python3
"""
File: render_final_eval_caveat_graphs.py
Author: Matt-Ung
Last Updated: 2026-04-09
Purpose:
  Render thesis-facing caveat graphs for the completed final held-out
  evaluation experiment.

Summary:
  This script reads one finished `sweep-final_round-*` experiment and produces
  compact figures plus machine-readable summaries that highlight where the
  final run failed by executable and why those failures occurred. It is meant
  to support thesis discussion of the final-run caveats, especially the
  context-bloat failure mode that did not dominate the earlier experimental
  benchmark.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS_ROOT = REPO_ROOT / "Testing" / "results" / "experiments"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "Thesis_Agentic_RE" / "Pictures" / "experiment_results"

OUTCOME_ORDER = (
    "completed",
    "worker_assignment_failed",
    "analysis_error",
    "judge_error",
    "validator_blocked",
    "no_result",
    "unknown",
)
OUTCOME_COLORS = {
    "completed": "#75c6a1",
    "worker_assignment_failed": "#d66a5f",
    "analysis_error": "#e0b75c",
    "judge_error": "#b56576",
    "validator_blocked": "#7286b7",
    "no_result": "#aab2bd",
    "unknown": "#8d99ae",
}

FAILURE_CAUSE_ORDER = (
    "context_length_exceeded",
    "invalid_request_payload",
    "usage_limit_exceeded",
    "tool_retry_exhausted",
    "other",
)
FAILURE_CAUSE_COLORS = {
    "context_length_exceeded": "#d66a5f",
    "invalid_request_payload": "#e0b75c",
    "usage_limit_exceeded": "#6d597a",
    "tool_retry_exhausted": "#4f772d",
    "other": "#8d99ae",
}


def _sample_sort_key(sample_name: str) -> Tuple[int, str]:
    stem = Path(sample_name).stem
    digits = "".join(ch for ch in stem if ch.isdigit())
    if digits:
        return (int(digits), stem)
    return (10**9, stem)


def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _classify_assignment_error(text: str) -> str:
    lowered = str(text or "").lower()
    if "context_length_exceeded" in lowered or "input tokens exceed the configured limit" in lowered:
        return "context_length_exceeded"
    if "could not parse the json body" in lowered:
        return "invalid_request_payload"
    if "request_limit of 50" in lowered or "usagelimitexceeded" in lowered:
        return "usage_limit_exceeded"
    if "exceeded max retries count" in lowered:
        return "tool_retry_exhausted"
    return "other"


"""
Function: _resolve_experiment_dir
Inputs:
  - explicit_path: optional CLI-supplied experiment directory.
Description:
  Resolve the experiment directory that should be analyzed. If the caller does
  not pass one explicitly, the newest `sweep-final_round-*` experiment under
  the maintained experiment root is selected.
Outputs:
  Returns the resolved experiment directory path.
Side Effects:
  Reads the experiment root directory listing.
"""
def _resolve_experiment_dir(explicit_path: str) -> Path:
    if str(explicit_path or "").strip():
        path = Path(explicit_path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Experiment directory not found: {path}")
        return path

    candidates = sorted(
        EXPERIMENTS_ROOT.glob("sweep-final_round-*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise FileNotFoundError("No sweep-final_round-* experiment directories were found.")
    return candidates[0].resolve()


"""
Function: _collect_task_outcomes
Inputs:
  - experiment_dir: completed experiment directory.
Description:
  Read the final task-level `agent_result.json` files and aggregate their final
  analysis outcomes by executable.
Outputs:
  Returns one summary row per executable plus overall task totals.
Side Effects:
  Reads final task result JSON files from disk.
"""
def _collect_task_outcomes(experiment_dir: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    per_sample: Dict[str, Counter[str]] = defaultdict(Counter)
    total_tasks = 0
    for path in experiment_dir.glob("runs/*/r*/cases/*/*/agent_result.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        sample = path.parts[-3]
        status = str(data.get("status") or "unknown").strip() or "unknown"
        per_sample[sample][status] += 1
        total_tasks += 1

    rows: List[Dict[str, Any]] = []
    for sample in sorted(per_sample.keys(), key=_sample_sort_key):
        counter = per_sample[sample]
        total = sum(counter.values())
        completed = int(counter.get("completed", 0))
        rows.append(
            {
                "sample": sample,
                "total_tasks": total,
                "completed": completed,
                "completed_rate": round(completed / total, 6) if total else None,
                **{status: int(counter.get(status, 0)) for status in OUTCOME_ORDER if counter.get(status, 0)},
            }
        )

    summary = {
        "total_tasks": total_tasks,
        "worker_assignment_failed_tasks": sum(row.get("worker_assignment_failed", 0) for row in rows),
        "analysis_error_tasks": sum(row.get("analysis_error", 0) for row in rows),
    }
    return rows, summary


"""
Function: _collect_assignment_failures
Inputs:
  - experiment_dir: completed experiment directory.
Description:
  Read every attempt-level task artifact, extract failed host-worker assignment
  details, and classify the underlying root cause for each failed assignment.
Outputs:
  Returns one summary row per executable plus aggregate root-cause totals.
Side Effects:
  Reads attempt-level task result JSON files from disk.
"""
def _collect_assignment_failures(experiment_dir: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    per_sample: Dict[str, Counter[str]] = defaultdict(Counter)
    total_failures = 0
    for path in experiment_dir.glob("runs/*/r*/cases/*/*/attempts/attempt_*/agent_result.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        sample = path.parts[-5]
        summary = data.get("worker_assignment_summary") or {}
        failed_items = summary.get("failed_items") or []
        for item in failed_items:
            cause = _classify_assignment_error(str((item or {}).get("error") or ""))
            per_sample[sample][cause] += 1
            total_failures += 1

    rows: List[Dict[str, Any]] = []
    overall = Counter[str]()
    for sample in sorted(per_sample.keys(), key=_sample_sort_key):
        counter = per_sample[sample]
        overall.update(counter)
        total = sum(counter.values())
        rows.append(
            {
                "sample": sample,
                "failed_assignments": total,
                "context_length_share": round(counter.get("context_length_exceeded", 0) / total, 6) if total else None,
                **{cause: int(counter.get(cause, 0)) for cause in FAILURE_CAUSE_ORDER if counter.get(cause, 0)},
            }
        )

    summary = {
        "failed_assignments": total_failures,
        **{cause: int(overall.get(cause, 0)) for cause in FAILURE_CAUSE_ORDER},
    }
    return rows, summary


def _plot_stacked_bars(
    rows: List[Dict[str, Any]],
    *,
    category_order: Iterable[str],
    category_colors: Dict[str, str],
    total_key: str,
    title: str,
    ylabel: str,
    annotation_builder: Any,
    output_path: Path,
) -> None:
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "matplotlib is required to render the final-evaluation caveat graphs. "
            "Install it in the Python environment used to run this script."
        ) from exc

    samples = [str(row["sample"]) for row in rows]
    labels = [Path(sample).stem for sample in samples]
    x_positions = list(range(len(samples)))
    bottoms = [0] * len(samples)

    fig, ax = plt.subplots(figsize=(10.5, 5.6))
    used_categories = [name for name in category_order if any(int(row.get(name, 0) or 0) for row in rows)]
    for name in used_categories:
        values = [int(row.get(name, 0) or 0) for row in rows]
        ax.bar(
            x_positions,
            values,
            bottom=bottoms,
            label=name.replace("_", " "),
            color=category_colors.get(name, "#999999"),
            edgecolor="white",
            linewidth=0.8,
        )
        bottoms = [bottom + value for bottom, value in zip(bottoms, values)]

    ax.set_xticks(x_positions, labels)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(axis="y", linestyle=":", alpha=0.25)
    ax.legend(frameon=False, ncols=3, fontsize=9, loc="upper center", bbox_to_anchor=(0.5, 1.18))

    y_max = max(bottoms) if bottoms else 0
    ax.set_ylim(0, y_max + max(1.0, 0.08 * max(y_max, 1)))
    for index, row in enumerate(rows):
        total = int(row.get(total_key, 0) or 0)
        annotation = str(annotation_builder(row)).strip()
        if annotation:
            ax.text(index, total + max(0.2, 0.01 * max(y_max, 1)), annotation, ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=200, bbox_inches="tight")
    plt.close(fig)


"""
Function: main
Inputs:
  - None directly. Command-line flags choose the experiment directory, output
    directory, and filename prefix for the rendered caveat artifacts.
Description:
  Analyze one final held-out evaluation experiment, summarize task outcomes and
  worker-failure causes by executable, and render thesis-facing caveat graphs
  plus machine-readable summary files.
Outputs:
  Returns nothing. Prints a JSON summary describing the rendered artifact set.
Side Effects:
  Reads experiment result artifacts, writes CSV/JSON summaries, and writes PNG
  figures under the requested output directory.
"""
def main() -> None:
    parser = argparse.ArgumentParser(description="Render final-evaluation caveat graphs for the thesis.")
    parser.add_argument(
        "--experiment",
        default="",
        help="Path to the finished experiment directory. Defaults to the newest sweep-final_round-* experiment.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory where the PNG/CSV/JSON outputs should be written.",
    )
    parser.add_argument(
        "--prefix",
        default="final_eval_caveat",
        help="Filename prefix for the generated outputs.",
    )
    args = parser.parse_args()

    experiment_dir = _resolve_experiment_dir(args.experiment)
    output_dir = Path(args.output_dir).expanduser().resolve()
    prefix = str(args.prefix or "final_eval_caveat").strip() or "final_eval_caveat"
    output_dir.mkdir(parents=True, exist_ok=True)

    task_rows, task_summary = _collect_task_outcomes(experiment_dir)
    failure_rows, failure_summary = _collect_assignment_failures(experiment_dir)

    outcome_png = output_dir / f"{prefix}_outcome_by_executable.png"
    failure_png = output_dir / f"{prefix}_worker_failure_causes_by_executable.png"
    task_csv = output_dir / f"{prefix}_outcome_by_executable.csv"
    failure_csv = output_dir / f"{prefix}_worker_failure_causes_by_executable.csv"
    summary_json = output_dir / f"{prefix}_summary.json"

    _plot_stacked_bars(
        task_rows,
        category_order=OUTCOME_ORDER,
        category_colors=OUTCOME_COLORS,
        total_key="total_tasks",
        title="Final held-out evaluation: task outcomes by executable",
        ylabel="Task outcomes across 7 variants x 3 repetitions",
        annotation_builder=lambda row: f"{int(row.get('completed', 0))}/{int(row.get('total_tasks', 0))} completed",
        output_path=outcome_png,
    )
    _plot_stacked_bars(
        failure_rows,
        category_order=FAILURE_CAUSE_ORDER,
        category_colors=FAILURE_CAUSE_COLORS,
        total_key="failed_assignments",
        title="Final held-out evaluation: failed worker assignments by executable",
        ylabel="Underlying host-worker assignment failures",
        annotation_builder=lambda row: (
            f"{int(round(float(row.get('context_length_share', 0.0) or 0.0) * 100))}% context"
            if int(row.get('failed_assignments', 0) or 0)
            else ""
        ),
        output_path=failure_png,
    )

    _write_csv(task_csv, task_rows)
    _write_csv(failure_csv, failure_rows)

    summary_payload = {
        "experiment_dir": str(experiment_dir),
        "output_dir": str(output_dir),
        "generated_files": {
            "task_outcome_png": str(outcome_png),
            "worker_failure_png": str(failure_png),
            "task_outcome_csv": str(task_csv),
            "worker_failure_csv": str(failure_csv),
        },
        "task_outcomes": task_summary,
        "assignment_failures": failure_summary,
    }
    summary_json.write_text(json.dumps(summary_payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary_payload, indent=2))


if __name__ == "__main__":
    main()
