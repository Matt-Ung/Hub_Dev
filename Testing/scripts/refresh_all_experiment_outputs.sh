#!/usr/bin/env bash
# File: refresh_all_experiment_outputs.sh
# Author: Matt-Ung
# Last Updated: 2026-04-11
# Purpose:
#   Refresh experiment-level outputs for every maintained and/or archived
#   experiment directory currently present in the repo.
#
# Summary:
#   This helper discovers experiment directories by their
#   `experiment_manifest.json`, reruns the canonical output-materialization
#   path for each one, and prints a summary of successes and failures. It is
#   intended for thesis-era chart/report maintenance when visualization logic
#   changes and all experiments need to be regenerated reproducibly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTING_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TESTING_ROOT/.." && pwd)"

DEFAULT_PARENT_VENV_PYTHON="$REPO_ROOT/../.venv/bin/python"
DEFAULT_REPO_VENV_PYTHON="$REPO_ROOT/.venv/bin/python"
if [[ -x "$DEFAULT_PARENT_VENV_PYTHON" ]]; then
  PYTHON_BIN="$DEFAULT_PARENT_VENV_PYTHON"
elif [[ -x "$DEFAULT_REPO_VENV_PYTHON" ]]; then
  PYTHON_BIN="$DEFAULT_REPO_VENV_PYTHON"
else
  PYTHON_BIN="${PYTHON:-python3}"
fi

INCLUDE_MAINTAINED=1
INCLUDE_ARCHIVE=1
SKIP_VISUALS=0
FAIL_FAST=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage:
  bash Testing/scripts/refresh_all_experiment_outputs.sh [options]

Options:
  --maintained-only   Refresh only Testing/results/experiments/*
  --archive-only      Refresh only Testing/archive/results_legacy/experiments/*
  --skip-visuals      Rebuild CSV/JSON/Markdown/browser outputs without PNG charts
  --fail-fast         Stop on the first failed experiment refresh
  --dry-run           Print the experiment list without refreshing
  --help              Show this help text

Notes:
  - The script discovers experiments by locating experiment_manifest.json files.
  - If a repo-adjacent virtualenv exists at ../.venv/bin/python, it is used.
  - Otherwise the script falls back to $PYTHON or python3.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --maintained-only)
      INCLUDE_MAINTAINED=1
      INCLUDE_ARCHIVE=0
      shift
      ;;
    --archive-only)
      INCLUDE_MAINTAINED=0
      INCLUDE_ARCHIVE=1
      shift
      ;;
    --skip-visuals)
      SKIP_VISUALS=1
      shift
      ;;
    --fail-fast)
      FAIL_FAST=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

collect_experiments() {
  local root="$1"
  if [[ ! -d "$root" ]]; then
    return 0
  fi
  find "$root" -mindepth 1 -maxdepth 2 -type f -name 'experiment_manifest.json' -print \
    | sort \
    | while IFS= read -r manifest_path; do
        dirname "$manifest_path"
      done
}

declare -a EXPERIMENTS=()
if [[ "$INCLUDE_MAINTAINED" -eq 1 ]]; then
  while IFS= read -r experiment_dir; do
    [[ -n "$experiment_dir" ]] && EXPERIMENTS+=("$experiment_dir")
  done < <(collect_experiments "$TESTING_ROOT/results/experiments")
fi
if [[ "$INCLUDE_ARCHIVE" -eq 1 ]]; then
  while IFS= read -r experiment_dir; do
    [[ -n "$experiment_dir" ]] && EXPERIMENTS+=("$experiment_dir")
  done < <(collect_experiments "$TESTING_ROOT/archive/results_legacy/experiments")
fi

if [[ "${#EXPERIMENTS[@]}" -eq 0 ]]; then
  echo "No experiment directories were discovered." >&2
  exit 1
fi

echo "Python: $PYTHON_BIN"
echo "Experiments discovered: ${#EXPERIMENTS[@]}"
for experiment_dir in "${EXPERIMENTS[@]}"; do
  echo "  - ${experiment_dir#$REPO_ROOT/}"
done

if [[ "$DRY_RUN" -eq 1 ]]; then
  exit 0
fi

declare -a SUCCEEDED=()
declare -a FAILED=()

for experiment_dir in "${EXPERIMENTS[@]}"; do
  echo
  echo "==> Refreshing ${experiment_dir#$REPO_ROOT/}"
  refresh_args=("$PYTHON_BIN" "Testing/scripts/run_refresh_experiment_outputs.py" "$experiment_dir")
  if [[ "$SKIP_VISUALS" -eq 1 ]]; then
    refresh_args+=("--skip-visuals")
  fi

  if (
    cd "$REPO_ROOT"
    "${refresh_args[@]}"
  ); then
    SUCCEEDED+=("$experiment_dir")
  else
    FAILED+=("$experiment_dir")
    if [[ "$FAIL_FAST" -eq 1 ]]; then
      echo
      echo "Stopping on first failure because --fail-fast was set." >&2
      break
    fi
  fi
done

echo
echo "Refresh summary"
echo "  Succeeded: ${#SUCCEEDED[@]}"
echo "  Failed: ${#FAILED[@]}"

if [[ "${#FAILED[@]}" -gt 0 ]]; then
  echo
  echo "Failed experiments:"
  for experiment_dir in "${FAILED[@]}"; do
    echo "  - ${experiment_dir#$REPO_ROOT/}"
  done
  exit 1
fi

