# Final Round Evaluation Assets

This directory contains evaluator-side material for the active final-round
corpus.

Use:

- [sample_manifest.json](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/final_round/sample_manifest.json)
  as the harness-facing corpus manifest
- [reference/](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/final_round/reference)
  as the source-grounded per-sample reference bundle
- [scoring_plan.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/final_round/evaluation/scoring_plan.md)
  as the evaluator scoring guidance
- [review_schema.json](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/final_round/evaluation/review_schema.json)
  if you want analyst review records layered on top of the checked-in references

This directory is evaluator-only. The runtime consumes the parent corpus
manifest and the built opaque executables during analysis. The maintained judge
now also consumes the parent corpus `reference/*.json` files as evaluator-only
grounding, but it does not read the review notes or schema files in this
`evaluation/` directory during runtime.
