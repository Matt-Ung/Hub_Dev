# Experimental Test Source

This is the maintained benchmark corpus for the binary-analysis harness.

Compiled outputs are written to:

```text
Testing/build/experimental/
```

The benchmark definition is split across:

- the C source files in this directory
- [sample_manifest.json](sample_manifest.json)

See [SAMPLE_INDEX.md](SAMPLE_INDEX.md) for the current sample matrix and coverage notes.

One maintained sample now explicitly targets deceptive analysis surfaces:
threatening names, strings, and dormant handlers are allowed, but the real
runtime behavior must remain benign and tightly scoped. When editing or adding
similar samples, keep the decoy cues inert and make the true behavior
recoverable from executed code flow.

When adding harder discrimination cases, prefer explicit variant additions over
global build-rule changes:

- add stripped hard variants for symbol-light evaluation
- vary leakage profiles across samples instead of making every sample equally opaque
- keep at least some medium samples analyzable without turning the tier into a second hard bucket

## Build

```bash
make -C Testing/Experimental_Test_Source all-with-gcc
make -C Testing/Experimental_Test_Source upx
```

## Add A New Sample

1. Add the new `.c` file here.
2. Update the Makefile so the executable is built into `Testing/build/experimental/`.
3. Add a manifest entry in [sample_manifest.json](sample_manifest.json).
4. Rebuild:

```bash
make -C Testing/Experimental_Test_Source all-with-gcc
```

5. Refresh the test catalog if you want an immediate visual sanity check:

```bash
python Testing/render_test_catalog.py --corpus experimental
```

## Add A New Task To An Existing Sample

Add another entry under that sample's `tasks[]`.

Each task should define:

- `task_id`
- `name`
- `query`
- `target_tools`
- `expected_evidence`
- `acceptance_targets`
- `tags`

Guidelines:

- Keep `task_id` stable once used in results or sweeps.
- Use focused tasks for discriminative comparisons and broad `default_analysis` tasks for general program understanding.
- Make `expected_evidence` concrete enough for judging, but not so brittle that wording changes fail good outputs.
- Keep `acceptance_targets` tied to observable facts, not vague expectations.

## Manifest Expectations

The harness treats the manifest as the source of truth for:

- difficulty labels
- task definitions
- task tags/categories
- target tools
- expected evidence / acceptance targets

If a sample has no `tasks[]`, the harness synthesizes a single `default_analysis` task from `default_query`. For the maintained experimental corpus, prefer explicit `tasks[]` entries.

## When To Regenerate Bundles

Bundles must be regenerated when:

- the built executable changes
- the Ghidra export script changes
- the bundle preparer version changes

They do **not** need regeneration when only prompting, worker persona overlays, or worker role prompt mode changes.
