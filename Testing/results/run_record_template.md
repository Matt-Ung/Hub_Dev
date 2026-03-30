# Per-Sample-Task Review Worksheet

This worksheet is optional and is intended for manual spot-checking of a sample-task record inside a structured run produced by `Testing/run_evaluation.py`.

---

```
Run ID:         eval-<corpus>-<timestamp>-<label>
Date:           YYYY-MM-DD
Corpus:
Architecture:
Pipeline:
Sample:
Task ID:
Task name:
Judge model:
Record path:    Testing/results/runs/<run_id>/samples/<sample_task_slug>/record.json
Alt path:       Testing/results/runs/<run_id>/by_executable/<exe>/<config_lineage_id>/tasks/<task_id>/runs/run_###/record.json

Scores:
  Evidence grounding:        /5
  Specificity:               /5
  Technique coverage:        /5
  False claim control:       /5
  Task alignment:            /5
  Report conciseness:        /3
  Overall (0-100):           /100

Efficiency:
  tool_calls_total:
  unique_tools_used:
  tools_used:

Unsupported claims:
Missed expected points:
Strongest points:
Judge summary:
Judge reasoning: see judge_reasoning.md in the by_executable run slot
```

---

The authoritative rubric lives in `Testing/config/binary_judge_rubric.json`.
