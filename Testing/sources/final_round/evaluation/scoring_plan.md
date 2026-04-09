# Final Round Scoring Plan

This final-round corpus is scored primarily on evidence-grounded recovery, not
family naming.

## Intended Weighting

- evidence recovery:
  - `0.35`
- capability inference:
  - `0.25`
- reasoning quality and task alignment:
  - `0.20`
- false-positive / unsupported-claim control:
  - `0.15`
- optional family attribution:
  - `0.05`

## Interpretation

The evaluation should emphasize:

- whether the system found concrete artifacts
- whether behavior claims were supported by those artifacts
- whether the report stayed aligned with the requested task
- whether unsupported claims were avoided

Family attribution remains low weight because the runtime sees opaque filenames
only (`sample1.exe` through `sample5.exe`), and useful reverse-engineering
output does not require correct family naming.

## Active Grounding Material

The strongest source-grounded evaluator references are already checked in:

- `Testing/sources/final_round/reference/sample1.json`
- `Testing/sources/final_round/reference/sample2.json`
- `Testing/sources/final_round/reference/sample3.json`
- `Testing/sources/final_round/reference/sample4.json`
- `Testing/sources/final_round/reference/sample5.json`

The maintained judge now consumes those JSON references directly as
evaluator-only grounding during final-round scoring. The paired Markdown files
remain synchronized reviewer-facing summaries rather than the machine-read
source of truth.

If analyst review notes are added later, treat them as overlays on those
reference files, not as replacements for the checked-in source-grounded facts.
