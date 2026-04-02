#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: Testing/clean_results.sh [--dry-run] [--include-catalog] [--include-logs]

Reset generated testing state while preserving tracked documentation and
reference examples.

Default cleanup scope:
  - Testing/results/doctor
  - Testing/results/experiments
  - Testing/results/lineages
  - Testing/results/runs

Optional flags:
  --dry-run          Print what would be removed without deleting anything.
  --include-catalog  Also reset Testing/results/catalog.
  --include-logs     Also remove generated agent logs under logs/agentToolBench_*.
  --help             Show this help text.
EOF
}

DRY_RUN=0
INCLUDE_CATALOG=0
INCLUDE_LOGS=0

while (($#)); do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      ;;
    --include-catalog)
      INCLUDE_CATALOG=1
      ;;
    --include-logs)
      INCLUDE_LOGS=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULTS_ROOT="${REPO_ROOT}/Testing/results"
LOGS_ROOT="${REPO_ROOT}/logs"

TARGETS=(
  "${RESULTS_ROOT}/doctor"
  "${RESULTS_ROOT}/experiments"
  "${RESULTS_ROOT}/lineages"
  "${RESULTS_ROOT}/runs"
)

if [[ "${INCLUDE_CATALOG}" -eq 1 ]]; then
  TARGETS+=("${RESULTS_ROOT}/catalog")
fi

echo "Repo root: ${REPO_ROOT}"
echo "Cleaning generated testing state:"
for target in "${TARGETS[@]}"; do
  echo "  - ${target}"
done
if [[ "${INCLUDE_LOGS}" -eq 1 ]]; then
  echo "  - ${LOGS_ROOT}/agentToolBench_*"
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "Dry run only. No files were removed."
  exit 0
fi

reset_dir() {
  local dir="$1"
  rm -rf -- "${dir}"
  mkdir -p -- "${dir}"
}

for target in "${TARGETS[@]}"; do
  reset_dir "${target}"
done

if [[ "${INCLUDE_LOGS}" -eq 1 && -d "${LOGS_ROOT}" ]]; then
  find "${LOGS_ROOT}" -maxdepth 1 -type d -name 'agentToolBench_*' -exec rm -rf {} +
fi

echo "Done."
echo "Preserved tracked files under ${RESULTS_ROOT}, including README.md, run_record_template.md, and reference_examples/."
