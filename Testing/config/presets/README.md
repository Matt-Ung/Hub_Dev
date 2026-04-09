# Launch Presets

Each JSON file in this folder is one predefined launch preset.

Rules:

- one file = one preset
- the filename should match the preset name
- sweep presets should be self-contained and include their own:
  - `baseline`
  - `repetitions`
  - `sweeps`
- single-run presets should contain only the run fields they actually need

The loader discovers presets by scanning `Testing/config/presets/*.json`.

For sweep presets, the preset file itself is also used as the `--config`
payload for `run_experiment_sweep.py`, so there is no second sweep-definition
file to keep in sync.

Current maintained presets:

- `smoke_default_quick`
- `sanity_core_slice_r1`
- `budget_best_value_r1`
- `budget_best_value_r2`
- `coverage_broad_r1_60usd`
- `sweep_decoder_depth_r3`
- `sweep_decoder_depth_followups_r3`
- `thesis_final_eval_r3_100usd`
