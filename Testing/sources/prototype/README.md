# Prototype Source Corpus

This is the maintained smoke and regression corpus for the binary-analysis
harness.

## Contract

The prototype corpus is defined by:

- the C source files in this directory
- [sample_manifest.json](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/prototype/sample_manifest.json)
- compiled outputs under `Testing/build/prototype/`

The manifest is the source of truth for:

- sample metadata
- difficulty labels
- task definitions
- `expected_evidence`
- `acceptance_targets`

There are no separate per-sample judge-reference files for this corpus.

## Build

```bash
make -C Testing/sources/prototype all
make -C Testing/sources/prototype all-gcc
make -C Testing/sources/prototype all-with-gcc
make -C Testing/sources/prototype upx
```

`all-with-gcc` is the normal full build. `upx` adds the maintained packed
variants.

## Coverage Shape

This corpus stays intentionally small and broad. It is for:

- quick harness sanity checks
- regression testing after workflow changes
- stripped and packed path smoke coverage

See [SAMPLE_INDEX.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/prototype/SAMPLE_INDEX.md)
for the current executable matrix.

## Add Or Update A Sample

1. Add or edit the relevant `.c` file here.
2. Update the Makefile so it builds into `Testing/build/prototype/`.
3. Update [sample_manifest.json](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/prototype/sample_manifest.json).
4. Rebuild:

```bash
make -C Testing/sources/prototype all-with-gcc
```

5. Refresh the catalog if you want a quick manifest sanity check:

```bash
python Testing/scripts/render_test_catalog.py --corpus prototype
```

## Manifest Expectations

- every executable variant should have an explicit `default_analysis` task
- every task should carry `expected_evidence`
- every task should carry `acceptance_targets`
- task IDs should remain stable once they appear in results
