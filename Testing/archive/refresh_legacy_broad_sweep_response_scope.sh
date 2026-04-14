#!/usr/bin/env bash
# File: refresh_legacy_broad_sweep_response_scope.sh
# Author: Matt-Ung
# Last Updated: 2026-04-08
# Purpose:
#   Copy the archived repaired broad sweep, rename the old query-verbosity
#   family metadata to response-scope metadata, and regenerate experiment
#   outputs and graphs in the archive.
#
# Summary:
#   This helper exists for thesis-era historical maintenance only. It creates
#   a new archived experiment from the repaired broad sweep, rewrites the
#   experiment metadata from `query_verbosity` / `query_variant` to
#   `response_scope` / `response_scope_variant`, points the copied catalog at
#   the copied `rebuilt_runs/` tree, and reruns the maintained experiment
#   output refresh path so charts and reports reflect the newer naming.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTING_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TESTING_ROOT/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"

DEFAULT_SOURCE="$SCRIPT_DIR/results_legacy/experiments/sweep-experimental-20260402_084227-coverage-broad-r1-60usd-repaired-v1"
DEFAULT_DEST="$SCRIPT_DIR/results_legacy/experiments/sweep-experimental-20260402_084227-coverage-broad-r1-60usd-repaired-v1-response-scope"

SOURCE_EXPERIMENT="$DEFAULT_SOURCE"
DEST_EXPERIMENT="$DEFAULT_DEST"
OVERWRITE=0
SKIP_VISUALS=0

usage() {
  cat <<'EOF'
Usage:
  bash Testing/archive/refresh_legacy_broad_sweep_response_scope.sh [options]

Options:
  --source PATH       Override the archived repaired broad-sweep source.
  --dest PATH         Override the destination archived experiment path.
  --overwrite         Remove the destination first if it already exists.
  --skip-visuals      Rebuild CSV/JSON/Markdown outputs without PNG charts.
  --help              Show this help text.

Default source:
  Testing/archive/results_legacy/experiments/sweep-experimental-20260402_084227-coverage-broad-r1-60usd-repaired-v1

Default destination:
  Testing/archive/results_legacy/experiments/sweep-experimental-20260402_084227-coverage-broad-r1-60usd-repaired-v1-response-scope
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      SOURCE_EXPERIMENT="${2:-}"
      shift 2
      ;;
    --dest)
      DEST_EXPERIMENT="${2:-}"
      shift 2
      ;;
    --overwrite)
      OVERWRITE=1
      shift
      ;;
    --skip-visuals)
      SKIP_VISUALS=1
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

SOURCE_EXPERIMENT="$(cd "$(dirname "$SOURCE_EXPERIMENT")" && pwd)/$(basename "$SOURCE_EXPERIMENT")"
DEST_EXPERIMENT="$(cd "$(dirname "$DEST_EXPERIMENT")" && pwd)/$(basename "$DEST_EXPERIMENT")"

if [[ ! -d "$SOURCE_EXPERIMENT" ]]; then
  echo "Source experiment does not exist: $SOURCE_EXPERIMENT" >&2
  exit 1
fi

if [[ -e "$DEST_EXPERIMENT" ]]; then
  if [[ "$OVERWRITE" -eq 1 ]]; then
    rm -rf "$DEST_EXPERIMENT"
  else
    echo "Destination already exists: $DEST_EXPERIMENT" >&2
    echo "Rerun with --overwrite or choose a different --dest path." >&2
    exit 1
  fi
fi

mkdir -p "$(dirname "$DEST_EXPERIMENT")"
cp -R "$SOURCE_EXPERIMENT" "$DEST_EXPERIMENT"

"$PYTHON_BIN" - "$DEST_EXPERIMENT" <<'PY'
import json
import sys
from pathlib import Path

experiment_root = Path(sys.argv[1]).expanduser().resolve()


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, payload):
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def rewrite_fields(obj: dict) -> None:
    if not isinstance(obj, dict):
        return
    if "query_variant" in obj:
        obj["response_scope_variant"] = obj.pop("query_variant")
    obj.setdefault("analysis_hint_variant", "default")

    if str(obj.get("changed_variable") or "") == "query_verbosity":
        obj["changed_variable"] = "response_scope"
    if str(obj.get("variant_id") or "") == "query_verbosity__brief":
        obj["variant_id"] = "response_scope__brief"
    if str(obj.get("comparison_baseline_id") or "") == "query_verbosity__baseline":
        obj["comparison_baseline_id"] = "response_scope__baseline"
    if str(obj.get("comparison_baseline_label") or "") == "query_verbosity:baseline":
        obj["comparison_baseline_label"] = "response_scope:baseline"
    if str(obj.get("display_label") or "") == "query_verbosity:brief":
        obj["display_label"] = "response_scope:brief"
    if str(obj.get("display_label") or "") == "query_verbosity:baseline":
        obj["display_label"] = "response_scope:baseline"

    description = str(obj.get("variant_description") or "")
    if description:
        description = description.replace(
            "task prompt/query detail level with a shorter-than-default query variant",
            "requested response scope with a shorter-than-default response-scope variant",
        )
        description = description.replace(
            "task prompt/query detail level",
            "requested response scope",
        )
        description = description.replace("query variant", "response-scope variant")
        obj["variant_description"] = description


manifest_path = experiment_root / "experiment_manifest.json"
manifest = load_json(manifest_path)
config_path = str(manifest.get("config_path") or "")
if config_path.endswith("experiment_sweeps_broad_coverage_r1.json"):
    manifest["config_path"] = str((Path("Testing/config/presets/coverage_broad_r1_60usd.json")).as_posix())
for planned in manifest.get("planned_runs") or []:
    rewrite_fields(planned)
dump_json(manifest_path, manifest)

catalog_path = experiment_root / "run_catalog.json"
catalog = load_json(catalog_path)
for entry in catalog.get("runs") or []:
    if not isinstance(entry, dict):
        continue
    rewrite_fields(entry)
    run_id = str(entry.get("run_id") or "").strip()
    if run_id:
        entry["run_dir"] = str((experiment_root / "rebuilt_runs" / run_id).resolve())
dump_json(catalog_path, catalog)

for run_manifest_path in sorted((experiment_root / "rebuilt_runs").glob("*/run_manifest.json")):
    run_manifest = load_json(run_manifest_path)
    rewrite_fields(run_manifest)
    dump_json(run_manifest_path, run_manifest)
PY

REFRESH_ARGS=("$PYTHON_BIN" "Testing/scripts/run_refresh_experiment_outputs.py" "$DEST_EXPERIMENT")
if [[ "$SKIP_VISUALS" -eq 1 ]]; then
  REFRESH_ARGS+=("--skip-visuals")
fi

(
  cd "$REPO_ROOT"
  "${REFRESH_ARGS[@]}"
)

echo
echo "Refreshed archive experiment:"
echo "  $DEST_EXPERIMENT"
echo
echo "Outputs:"
echo "  $DEST_EXPERIMENT/outputs"
