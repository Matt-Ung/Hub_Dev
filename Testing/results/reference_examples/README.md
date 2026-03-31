# Versioned Result Examples

Use this directory only for intentionally curated, reproducible result artifacts
that are meant to stay in git.

Examples of appropriate contents:

- a small canonical sweep output used in docs
- a hand-selected run record used as a schema example
- a fixed benchmark snapshot referenced by a writeup

Do not place routine generated output here. Normal run artifacts belong under the
generated `Testing/results/` subtrees created by the harness and are gitignored by
default.
