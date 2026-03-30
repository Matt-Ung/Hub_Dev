#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List

from harness.paths import CONFIG_ROOT, RESULTS_ROOT, ensure_dir, read_json, write_json
from harness.query_variants import apply_query_variant, load_query_variants
from harness.samples import get_corpus_config, load_sample_manifest, resolve_sample_metadata, resolve_sample_tasks, sample_task_key


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


def _shorten(text: str, limit: int = 140) -> str:
    clean = " ".join(str(text or "").split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 1].rstrip() + "…"


def _fmt_list(items: Iterable[str]) -> str:
    values = [str(item).strip() for item in items if str(item).strip()]
    return ", ".join(values)


def _build_catalog(corpus_name: str) -> Dict[str, Any]:
    corpus = get_corpus_config(corpus_name)
    manifest = load_sample_manifest(corpus_name)
    query_variants = load_query_variants()
    sweep_config = read_json(CONFIG_ROOT / "experiment_sweeps.json")
    sample_rows: List[Dict[str, Any]] = []
    task_rows: List[Dict[str, Any]] = []
    dimension_rows: List[Dict[str, Any]] = []
    query_variant_rows: List[Dict[str, Any]] = []
    matrix_rows: List[Dict[str, Any]] = []
    difficulty_counts: Counter[str] = Counter()
    tag_counts: Counter[str] = Counter()

    sweep_variables = [str((entry or {}).get("variable") or "").strip() for entry in (sweep_config.get("sweeps") or []) if str((entry or {}).get("variable") or "").strip()]

    for variant_name in sorted(query_variants.keys()):
        variant = query_variants.get(variant_name) or {}
        query_variant_rows.append(
            {
                "query_variant": variant_name,
                "description": str(variant.get("description") or "").strip(),
                "prefix": str(variant.get("prefix") or "").strip(),
                "suffix": str(variant.get("suffix") or "").strip(),
            }
        )

    for sample_name in manifest.get("sample_order") or []:
        sample_meta = resolve_sample_metadata(corpus_name, sample_name, manifest=manifest)
        difficulty = str(sample_meta.get("difficulty") or "unknown").strip() or "unknown"
        tasks = resolve_sample_tasks(corpus_name, sample_name, manifest=manifest)
        difficulty_counts[difficulty] += 1
        sample_rows.append(
            {
                "sample": sample_name,
                "difficulty": difficulty,
                "task_count": len(tasks),
                "primary_techniques": _fmt_list(sample_meta.get("primary_techniques") or []),
                "default_query": str(sample_meta.get("default_query") or "").strip(),
            }
        )
        for task in tasks:
            task_id = str(task.get("task_id") or "").strip()
            task_name = str(task.get("name") or task_id).strip() or task_id
            base_query = str(task.get("query") or "").strip()
            sample_task_id = sample_task_key(sample_name, task_id)
            prompts = {
                variant_name: apply_query_variant(base_query, sample_meta, variant_name)
                for variant_name in sorted(query_variants.keys())
            }
            tags = [str(item).strip() for item in (task.get("tags") or []) if str(item).strip()]
            for tag in tags:
                tag_counts[tag] += 1
            task_row = {
                "sample": sample_name,
                "difficulty": difficulty,
                "task_id": task_id,
                "task_name": task_name,
                "sample_task_id": sample_task_id,
                "tags": _fmt_list(tags),
                "target_tools": _fmt_list(task.get("target_tools") or []),
                "expected_evidence": _fmt_list(task.get("expected_evidence") or []),
                "acceptance_targets": _fmt_list(task.get("acceptance_targets") or []),
                "base_query": base_query,
            }
            for variant_name, prompt in prompts.items():
                task_row[f"prompt_{variant_name}"] = prompt
            task_rows.append(task_row)

            matrix_row: Dict[str, Any] = {
                "sample_task_id": sample_task_id,
                "sample": sample_name,
                "difficulty": difficulty,
                "task_name": task_name,
                "tags": _fmt_list(tags),
            }
            for sweep in sweep_config.get("sweeps") or []:
                if not isinstance(sweep, dict):
                    continue
                variable = str(sweep.get("variable") or "").strip()
                variants = [
                    str((variant or {}).get("name") or "").strip()
                    for variant in (sweep.get("variants") or [])
                    if str((variant or {}).get("name") or "").strip()
                ]
                matrix_row[variable] = "baseline + " + ", ".join(variants) if variants else "baseline only"
            matrix_rows.append(matrix_row)

    baseline = dict(sweep_config.get("baseline") or {})
    for sweep in sweep_config.get("sweeps") or []:
        if not isinstance(sweep, dict):
            continue
        variable = str(sweep.get("variable") or "").strip()
        variants = []
        overridden_fields: List[str] = []
        for variant in sweep.get("variants") or []:
            if not isinstance(variant, dict):
                continue
            name = str(variant.get("name") or "").strip()
            overrides = dict(variant.get("overrides") or {})
            if name:
                variants.append(name)
            for field_name in overrides.keys():
                field_text = str(field_name).strip()
                if field_text and field_text not in overridden_fields:
                    overridden_fields.append(field_text)
        family_baseline = dict(sweep.get("baseline_overrides") or {})
        dimension_rows.append(
            {
                "variable": variable,
                "description": str(sweep.get("description") or "").strip(),
                "baseline_value": json.dumps({k: baseline.get(k) for k in sorted(set(overridden_fields) | set(family_baseline.keys()))}, ensure_ascii=False),
                "family_baseline_overrides": json.dumps(family_baseline, ensure_ascii=False) if family_baseline else "",
                "variants": ", ".join(variants),
                "overridden_fields": ", ".join(overridden_fields),
            }
        )

    summary = {
        "corpus": corpus_name,
        "source_root": str(corpus.source_root),
        "build_root": str(corpus.build_root),
        "sample_count": len(sample_rows),
        "task_count": len(task_rows),
        "difficulty_counts": dict(sorted(difficulty_counts.items())),
        "query_variants": sorted(query_variants.keys()),
        "sweep_variable_count": len(sweep_variables),
        "sweep_variables": sweep_variables,
        "top_tags": dict(tag_counts.most_common()),
    }
    return {
        "summary": summary,
        "baseline": baseline,
        "samples": sample_rows,
        "tasks": task_rows,
        "query_variants": query_variant_rows,
        "dimensions": dimension_rows,
        "task_dimension_matrix": matrix_rows,
    }


def _render_markdown(catalog: Dict[str, Any]) -> str:
    summary = catalog["summary"]
    baseline = catalog["baseline"]
    lines: List[str] = []
    lines.append("# Test Catalog")
    lines.append("")
    lines.append(f"- Corpus: `{summary['corpus']}`")
    lines.append(f"- Samples: `{summary['sample_count']}`")
    lines.append(f"- Tasks: `{summary['task_count']}`")
    lines.append(f"- Query variants: `{', '.join(summary['query_variants'])}`")
    lines.append(f"- Sweep variables: `{', '.join(summary['sweep_variables'])}`")
    lines.append("")
    lines.append("## Baseline Configuration")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    for key in sorted(baseline.keys()):
        lines.append(f"| {key} | `{baseline[key]}` |")
    lines.append("")
    lines.append("## Difficulty Summary")
    lines.append("")
    for difficulty, count in summary["difficulty_counts"].items():
        lines.append(f"- `{difficulty}`: `{count}` sample(s)")
    lines.append("")
    lines.append("## Samples")
    lines.append("")
    lines.append("| Sample | Difficulty | Tasks | Techniques |")
    lines.append("|---|---|---:|---|")
    for row in catalog["samples"]:
        lines.append(
            f"| {row['sample']} | {row['difficulty']} | {row['task_count']} | {row['primary_techniques']} |"
        )
    lines.append("")
    lines.append("## Query Variants")
    lines.append("")
    lines.append("| Variant | Description |")
    lines.append("|---|---|")
    for row in catalog["query_variants"]:
        lines.append(f"| {row['query_variant']} | {row['description']} |")
    lines.append("")
    lines.append("## Tasks")
    lines.append("")
    for row in catalog["tasks"]:
        lines.append(f"### `{row['sample_task_id']}`")
        lines.append("")
        lines.append(f"- Sample: `{row['sample']}`")
        lines.append(f"- Difficulty: `{row['difficulty']}`")
        lines.append(f"- Tags: `{row['tags']}`")
        lines.append(f"- Target tools: `{row['target_tools']}`")
        lines.append(f"- Base query: `{row['base_query']}`")
        lines.append(f"- Prompt `default`: `{row.get('prompt_default', row['base_query'])}`")
        lines.append(f"- Prompt `brief`: `{row.get('prompt_brief', '')}`")
        lines.append(f"- Prompt `detailed`: `{row.get('prompt_detailed', '')}`")
        lines.append(f"- Acceptance targets: `{row['acceptance_targets']}`")
        lines.append("")
    lines.append("## Sweep Dimensions")
    lines.append("")
    lines.append("| Variable | Variants | Overrides | Description |")
    lines.append("|---|---|---|---|")
    for row in catalog["dimensions"]:
        lines.append(
            f"| {row['variable']} | {row['variants']} | {row['overridden_fields']} | {row['description']} |"
        )
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- Task queries shown here are the evaluation-task prompts before stage-manager and role prompts are layered on top by the runtime.")
    lines.append("- Unless you restrict `--sample`, `--task`, or `--difficulty-filter`, every manifest-defined task is eligible for every sweep family.")
    return "\n".join(lines).rstrip() + "\n"


def _render_html(catalog: Dict[str, Any]) -> str:
    summary = catalog["summary"]
    baseline = catalog["baseline"]

    def esc(value: Any) -> str:
        return html.escape(str(value or ""))

    sample_rows = "\n".join(
        "<tr>"
        f"<td>{esc(row['sample'])}</td>"
        f"<td><span class='badge diff-{esc(row['difficulty'])}'>{esc(row['difficulty'])}</span></td>"
        f"<td>{esc(row['task_count'])}</td>"
        f"<td>{esc(row['primary_techniques'])}</td>"
        "</tr>"
        for row in catalog["samples"]
    )

    task_rows = []
    for row in catalog["tasks"]:
        prompt_variants = []
        for key in sorted(k for k in row.keys() if k.startswith("prompt_")):
            variant_name = key.replace("prompt_", "", 1)
            prompt_variants.append(
                f"<h5>{esc(variant_name)}</h5><pre>{esc(row[key])}</pre>"
            )
        task_rows.append(
            "<tr>"
            f"<td>{esc(row['sample_task_id'])}</td>"
            f"<td><span class='badge diff-{esc(row['difficulty'])}'>{esc(row['difficulty'])}</span></td>"
            f"<td>{esc(row['tags'])}</td>"
            f"<td>{esc(row['target_tools'])}</td>"
            f"<td><details><summary>{esc(_shorten(row['base_query'], 100))}</summary><pre>{esc(row['base_query'])}</pre></details></td>"
            f"<td><details><summary>View prompt variants</summary>{''.join(prompt_variants)}</details></td>"
            f"<td><details><summary>{esc(_shorten(row['acceptance_targets'], 90))}</summary><div>{esc(row['acceptance_targets'])}</div></details></td>"
            "</tr>"
        )
    task_table = "\n".join(task_rows)

    dimension_rows = "\n".join(
        "<tr>"
        f"<td>{esc(row['variable'])}</td>"
        f"<td>{esc(row['variants'])}</td>"
        f"<td>{esc(row['overridden_fields'])}</td>"
        f"<td>{esc(row['description'])}</td>"
        "</tr>"
        for row in catalog["dimensions"]
    )

    query_variant_rows = "\n".join(
        "<tr>"
        f"<td>{esc(row['query_variant'])}</td>"
        f"<td>{esc(row['description'])}</td>"
        f"<td><details><summary>View wrapper</summary><pre>{esc(row['prefix'])}</pre><pre>{esc(row['suffix'])}</pre></details></td>"
        "</tr>"
        for row in catalog["query_variants"]
    )

    baseline_rows = "\n".join(
        "<tr>"
        f"<td>{esc(key)}</td>"
        f"<td>{esc(value)}</td>"
        "</tr>"
        for key, value in sorted(baseline.items())
    )

    matrix_headers = "".join(f"<th>{esc(row['variable'])}</th>" for row in catalog["dimensions"])
    matrix_rows = []
    for row in catalog["task_dimension_matrix"]:
        cells = "".join(
            f"<td>{esc(row.get(dim['variable'], ''))}</td>"
            for dim in catalog["dimensions"]
        )
        matrix_rows.append(
            "<tr>"
            f"<td>{esc(row['sample_task_id'])}</td>"
            f"<td>{esc(row['difficulty'])}</td>"
            f"<td>{esc(row['tags'])}</td>"
            f"{cells}"
            "</tr>"
        )
    matrix_body = "\n".join(matrix_rows)

    summary_cards = []
    for label, value in [
        ("Samples", summary["sample_count"]),
        ("Tasks", summary["task_count"]),
        ("Query variants", ", ".join(summary["query_variants"])),
        ("Sweep variables", summary["sweep_variable_count"]),
    ]:
        summary_cards.append(f"<div class='card'><div class='label'>{esc(label)}</div><div class='value'>{esc(value)}</div></div>")

    difficulty_list = "".join(f"<li><strong>{esc(k)}</strong>: {esc(v)}</li>" for k, v in summary["difficulty_counts"].items())

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Test Catalog - {esc(summary['corpus'])}</title>
  <style>
    :root {{
      --bg: #f4f1e8;
      --panel: #fffaf0;
      --ink: #1f1c18;
      --muted: #6a635b;
      --line: #d7cdbd;
      --accent: #8a5a2b;
      --easy: #2a7f62;
      --medium: #b97400;
      --hard: #9f2f2f;
    }}
    body {{ margin: 0; font-family: Georgia, serif; background: var(--bg); color: var(--ink); }}
    .wrap {{ max-width: 1400px; margin: 0 auto; padding: 28px; }}
    h1, h2 {{ margin: 0 0 12px; }}
    p, li {{ line-height: 1.45; }}
    .cards {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 18px 0 24px; }}
    .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px; }}
    .card .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }}
    .card .value {{ font-size: 22px; margin-top: 6px; }}
    .section {{ margin-top: 28px; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); }}
    th, td {{ text-align: left; vertical-align: top; padding: 10px; border-bottom: 1px solid var(--line); }}
    th {{ background: #efe7d8; position: sticky; top: 0; z-index: 1; }}
    .scroll {{ overflow: auto; border: 1px solid var(--line); border-radius: 10px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; color: white; font-size: 12px; font-weight: 700; }}
    .diff-easy {{ background: var(--easy); }}
    .diff-medium {{ background: var(--medium); }}
    .diff-hard {{ background: var(--hard); }}
    pre {{ white-space: pre-wrap; background: #fbf7ef; border: 1px solid var(--line); padding: 10px; border-radius: 8px; }}
    details > summary {{ cursor: pointer; color: var(--accent); }}
    .note {{ background: #f9f2df; border-left: 4px solid var(--accent); padding: 12px 14px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Test Catalog</h1>
    <p>Generated from the manifest, query-variant config, and sweep definition for the <strong>{esc(summary['corpus'])}</strong> corpus.</p>
    <div class="cards">{''.join(summary_cards)}</div>

    <div class="section">
      <h2>Baseline Configuration</h2>
      <div class="scroll">
        <table>
          <thead><tr><th>Field</th><th>Value</th></tr></thead>
          <tbody>{baseline_rows}</tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <h2>Difficulty Summary</h2>
      <ul>{difficulty_list}</ul>
    </div>

    <div class="section">
      <h2>Samples</h2>
      <div class="scroll">
        <table>
          <thead><tr><th>Sample</th><th>Difficulty</th><th>Tasks</th><th>Primary Techniques</th></tr></thead>
          <tbody>{sample_rows}</tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <h2>Query Variants</h2>
      <div class="scroll">
        <table>
          <thead><tr><th>Variant</th><th>Description</th><th>Wrapper</th></tr></thead>
          <tbody>{query_variant_rows}</tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <h2>Tasks and Prompted Work</h2>
      <div class="scroll">
        <table>
          <thead><tr><th>Sample Task</th><th>Difficulty</th><th>Tags</th><th>Target Tools</th><th>Base Query</th><th>Prompt Variants</th><th>Acceptance Targets</th></tr></thead>
          <tbody>{task_table}</tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <h2>Sweep Dimensions</h2>
      <div class="scroll">
        <table>
          <thead><tr><th>Variable</th><th>Variants</th><th>Overrides</th><th>Description</th></tr></thead>
          <tbody>{dimension_rows}</tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <h2>Task × Dimension Matrix</h2>
      <div class="scroll">
        <table>
          <thead><tr><th>Sample Task</th><th>Difficulty</th><th>Tags</th>{matrix_headers}</tr></thead>
          <tbody>{matrix_body}</tbody>
        </table>
      </div>
    </div>

    <div class="section note">
      Task queries shown here are the evaluation-task prompts before stage-manager and role prompts are layered on top by the runtime. Unless you restrict <code>--sample</code>, <code>--task</code>, or <code>--difficulty-filter</code>, every manifest-defined task is eligible for every sweep family.
    </div>
  </div>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Render an easy-to-read catalog of test samples, tasks, and sweep dimensions.")
    parser.add_argument("--corpus", choices=["prototype", "experimental"], default="experimental")
    parser.add_argument("--output-dir", default="", help="Optional output directory override")
    args = parser.parse_args()

    catalog = _build_catalog(args.corpus)
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else (RESULTS_ROOT / "catalog" / args.corpus)
    output_dir = ensure_dir(output_dir)

    write_json(output_dir / "catalog.json", catalog)
    _write_rows_csv(output_dir / "samples.csv", catalog["samples"])
    _write_rows_csv(output_dir / "tasks.csv", catalog["tasks"])
    _write_rows_csv(output_dir / "query_variants.csv", catalog["query_variants"])
    _write_rows_csv(output_dir / "sweep_dimensions.csv", catalog["dimensions"])
    _write_rows_csv(output_dir / "task_dimension_matrix.csv", catalog["task_dimension_matrix"])
    (output_dir / "benchmark_catalog.md").write_text(_render_markdown(catalog), encoding="utf-8")
    (output_dir / "benchmark_catalog.html").write_text(_render_html(catalog), encoding="utf-8")

    print(
        json.dumps(
            {
                "corpus": args.corpus,
                "output_dir": str(output_dir),
                "sample_count": catalog["summary"]["sample_count"],
                "task_count": catalog["summary"]["task_count"],
                "sweep_variables": catalog["summary"]["sweep_variables"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
