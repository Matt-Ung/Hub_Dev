import getpass
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .workflow_config_loader import load_workflow_config

PACKAGE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_ROOT.parent
WORKFLOW_CONFIG_DIR = PACKAGE_ROOT / "workflow_config"

PLANNER_WORK_ITEMS_START = "WORK_ITEMS_JSON_START"
PLANNER_WORK_ITEMS_END = "WORK_ITEMS_JSON_END"
VALIDATION_DECISION_START = "VALIDATION_GATE_JSON_START"
VALIDATION_DECISION_END = "VALIDATION_GATE_JSON_END"
GHIDRA_CHANGE_PROPOSALS_START = "GHIDRA_CHANGE_PROPOSALS_JSON_START"
GHIDRA_CHANGE_PROPOSALS_END = "GHIDRA_CHANGE_PROPOSALS_JSON_END"
YARA_RULE_PROPOSALS_START = "YARA_RULE_PROPOSALS_JSON_START"
YARA_RULE_PROPOSALS_END = "YARA_RULE_PROPOSALS_JSON_END"

VALIDATOR_REVIEW_LEVEL_CHOICES = [
    ("easy (Business Manager)", "easy"),
    ("default (CS Background)", "default"),
    ("intermediate (CS Professor)", "intermediate"),
    ("strict (Seasoned Professional Malware Analyst)", "strict"),
]
VALIDATOR_REVIEW_LEVEL_LABELS = {
    value: label for label, value in VALIDATOR_REVIEW_LEVEL_CHOICES
}
WORKER_ROLE_PROMPT_MODE_CHOICES = [
    ("default (Use worker archetype role prompt)", "default"),
    ("blank (Suppress worker archetype role prompt)", "blank"),
]
WORKER_ROLE_PROMPT_MODE_LABELS = {
    value: label for label, value in WORKER_ROLE_PROMPT_MODE_CHOICES
}
SHELL_EXECUTION_MODE_CHOICES = [
    ("None", "none"),
    ("Yes, with permission from user", "ask"),
    ("Yes FULL ACCESS (Use at Risk)", "full"),
]
SHELL_EXECUTION_MODE_LABELS = {value: label for label, value in SHELL_EXECUTION_MODE_CHOICES}
PATH_HANDOFF_LINE_PREFIX = "Validated sample path:"
SAMPLE_PATH_SUFFIXES = ("exe", "dll", "sys", "scr", "ocx", "cpl", "bin", "elf", "so", "dylib")
SAMPLE_PATH_WINDOWS_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])([A-Za-z]:[\\/][^\r\n\"'<>|?*]+?\.(?:"
    + "|".join(SAMPLE_PATH_SUFFIXES)
    + r"))"
)
SAMPLE_PATH_POSIX_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])((?:/|\./|\.\./)[^\r\n\"']+?\.(?:"
    + "|".join(SAMPLE_PATH_SUFFIXES)
    + r"))"
)
SAMPLE_PATH_QUOTED_RE = re.compile(
    r"(?i)[\"']((?:[A-Za-z]:[\\/]|/|\./|\.\./)[^\"'\r\n]+?\.(?:"
    + "|".join(SAMPLE_PATH_SUFFIXES)
    + r"))[\"']"
)
GHIDRA_EXECUTABLE_PATH_RE = re.compile(r"(?im)^Executable Path:\s*(.+?)\s*$")
GHIDRA_EXECUTABLE_MD5_RE = re.compile(r"(?im)^Executable MD5:\s*([0-9a-fA-F]{32})\s*$")
GHIDRA_EXECUTABLE_SHA256_RE = re.compile(r"(?im)^Executable SHA256:\s*([0-9a-fA-F]{64})\s*$")
GHIDRA_IMAGE_BASE_RE = re.compile(r"(?im)^Image Base:\s*(.+?)\s*$")

_CONFIG_BOOTSTRAPPED = False
_STAGE_KIND_METADATA_KEYS = (
    "tool_free",
    "supports_parallel_assignments",
    "finalizes_report",
    "parses_planner_work_items",
    "runs_validation_gate",
)


def _env_flag_from(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _parse_path_list(raw: str) -> List[str]:
    if not raw.strip():
        return []
    sep = os.pathsep if os.pathsep in raw else ","
    return [p.strip() for p in raw.split(sep) if p.strip()]


def _parse_optional_positive_int(raw: Any, default: int | None = None) -> int | None:
    if raw is None:
        return default
    text = str(raw).strip()
    if not text:
        return default
    value = int(text)
    return value if value > 0 else None


def _parse_lower_marker_list(raw: str) -> Tuple[str, ...]:
    return tuple(marker.strip().lower() for marker in str(raw or "").split(",") if marker.strip())


def _resolve_repo_relative_path(raw_path: str) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path.resolve()


def _normalize_validator_review_level(value: Any) -> str:
    if isinstance(value, bool):
        return "strict" if value else "default"
    normalized = str(value or "").strip().lower()
    if normalized in {"easy", "default", "intermediate", "strict"}:
        return normalized
    if normalized in {"business", "business manager", "manager", "simple", "easy review"}:
        return "easy"
    if normalized in {"balanced", "normal", "cs", "cs background"}:
        return "default"
    if normalized in {"professor", "cs professor", "medium", "moderate"}:
        return "intermediate"
    return "default"


def _normalize_shell_execution_mode(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"none", "ask", "full"}:
        return normalized
    if normalized in {"off", "disabled", "disable", "no", "false"}:
        return "none"
    if normalized in {"prompt", "approval", "approve", "with permission", "permission", "yes with permission"}:
        return "ask"
    if normalized in {"on", "enabled", "enable", "yes", "full access", "unsafe", "use at risk"}:
        return "full"
    return "none"


def _normalize_worker_role_prompt_mode(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"default", "blank"}:
        return normalized
    if normalized in {"empty", "none", "off", "disabled", "disable", "no_role", "no_role_prompt", "bare"}:
        return "blank"
    return "default"


def resolve_pipeline_definition(
    pipeline_template: List[Dict[str, Any]],
    worker_architecture: List[Tuple[str, int]],
) -> List[Dict[str, Any]]:
    # Tutorial 1.2 in extension_tutorial.md: `use_worker_architecture` is
    # resolved here so a pipeline stage can inherit the selected architecture
    # preset instead of hardcoding its own slot list.
    resolved: List[Dict[str, Any]] = []
    for raw_stage in pipeline_template:
        stage = dict(raw_stage)
        if stage.get("use_worker_architecture"):
            stage["architecture"] = list(worker_architecture)
        else:
            stage["architecture"] = list(stage.get("architecture") or [])
        resolved.append(stage)
    return resolved


def _pipeline_log_slots_from_presets(
    pipeline_presets: Mapping[str, List[Dict[str, Any]]],
) -> List[Tuple[str, str]]:
    # Tutorial 1.5 in extension_tutorial.md: stage log accordions are derived
    # from pipeline presets, so valid new stage names appear in the dashboard
    # automatically without extra UI registration.
    ordered: List[Tuple[str, str]] = []
    seen: set[Tuple[str, str]] = set()
    for pipeline in pipeline_presets.values():
        for stage in pipeline:
            slot = (str(stage["name"]), str(stage["stage_kind"]))
            if slot in seen:
                continue
            seen.add(slot)
            ordered.append(slot)
    return ordered


def _load_dotenv_if_present(dotenv_path: Optional[str] = None) -> Optional[Path]:
    raw_path = (dotenv_path or os.environ.get("DOTENV_PATH") or "").strip()
    candidates: List[Path] = []
    if raw_path:
        explicit_path = Path(raw_path).expanduser()
        candidates.append(explicit_path)
        if not explicit_path.is_absolute():
            candidates.append(_resolve_repo_relative_path(raw_path))
    candidates.append(Path.cwd() / ".env")
    candidates.append(REPO_ROOT / ".env")

    seen: set[str] = set()
    resolved_path: Optional[Path] = None
    for candidate in candidates:
        try:
            current = candidate.resolve()
        except Exception:
            continue
        key = str(current)
        if key in seen:
            continue
        seen.add(key)
        if current.exists() and current.is_file():
            resolved_path = current
            break

    if resolved_path is None:
        return None

    try:
        from dotenv import load_dotenv

        load_dotenv(dotenv_path=resolved_path, override=False)
        print(f"[env] loaded {resolved_path}")
        return resolved_path
    except Exception:
        pass

    try:
        for raw_line in resolved_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key or key in os.environ:
                continue
            if len(value) >= 2 and ((value[0] == value[-1] == "'") or (value[0] == value[-1] == '"')):
                value = value[1:-1]
            os.environ[key] = value
        print(f"[env] loaded {resolved_path} (fallback parser)")
    except Exception as e:
        print(f"[env] warning: failed to parse {resolved_path}: {e}")
    return resolved_path


def _build_launch_kwargs(env: Mapping[str, str], extra_launch_kwargs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    launch_kwargs: Dict[str, Any] = dict(extra_launch_kwargs or {})
    server_name = str(env.get("GRADIO_SERVER_NAME") or "").strip()
    server_port = str(env.get("GRADIO_SERVER_PORT") or "").strip()
    if server_name and "server_name" not in launch_kwargs:
        launch_kwargs["server_name"] = server_name
    if server_port and "server_port" not in launch_kwargs:
        try:
            launch_kwargs["server_port"] = int(server_port)
        except ValueError:
            pass
    if "share" not in launch_kwargs and "GRADIO_SHARE" in env:
        launch_kwargs["share"] = _env_flag_from(env, "GRADIO_SHARE", False)
    if "inbrowser" not in launch_kwargs and "GRADIO_INBROWSER" in env:
        launch_kwargs["inbrowser"] = _env_flag_from(env, "GRADIO_INBROWSER", False)
    return launch_kwargs


def _sanitize_gradio_env(env: Dict[str, str]) -> None:
    for key in ("GRADIO_SERVER_NAME", "GRADIO_SERVER_PORT"):
        if key in env and not str(env.get(key) or "").strip():
            env.pop(key, None)


def _load_workflow_config_with_placeholders() -> Dict[str, Any]:
    return load_workflow_config(
        WORKFLOW_CONFIG_DIR,
        placeholders={
            "PLANNER_WORK_ITEMS_START": PLANNER_WORK_ITEMS_START,
            "PLANNER_WORK_ITEMS_END": PLANNER_WORK_ITEMS_END,
            "VALIDATION_DECISION_START": VALIDATION_DECISION_START,
            "VALIDATION_DECISION_END": VALIDATION_DECISION_END,
            "GHIDRA_CHANGE_PROPOSALS_START": GHIDRA_CHANGE_PROPOSALS_START,
            "GHIDRA_CHANGE_PROPOSALS_END": GHIDRA_CHANGE_PROPOSALS_END,
            "YARA_RULE_PROPOSALS_START": YARA_RULE_PROPOSALS_START,
            "YARA_RULE_PROPOSALS_END": YARA_RULE_PROPOSALS_END,
        },
    )


def get_stage_kind_metadata(stage_kind: str) -> Dict[str, bool]:
    normalized_kind = str(stage_kind or "").strip()
    metadata = globals().get("STAGE_KIND_METADATA", {})
    entry = metadata.get(normalized_kind)
    if not isinstance(entry, dict):
        raise RuntimeError(f"Unknown stage kind metadata for {normalized_kind!r}")
    return {
        key: bool(entry.get(key, False))
        for key in _STAGE_KIND_METADATA_KEYS
    }


def stage_kind_flag(stage_kind: str, flag: str) -> bool:
    if flag not in _STAGE_KIND_METADATA_KEYS:
        raise RuntimeError(f"Unknown stage kind metadata flag: {flag!r}")
    return bool(get_stage_kind_metadata(stage_kind).get(flag))


def _build_runtime_settings(
    env: Mapping[str, str],
    *,
    workflow_config: Optional[Dict[str, Any]] = None,
    loaded_dotenv: Optional[Path] = None,
    extra_launch_kwargs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    # Tutorial 4.1 in extension_tutorial.md: add env-backed workflow knobs and
    # their normalized defaults here before wiring them into frontend/runtime.
    current_workflow_config = workflow_config or _load_workflow_config_with_placeholders()
    architecture_presets = current_workflow_config["architecture_presets"]
    architecture_preset_descriptions = current_workflow_config["architecture_preset_descriptions"]
    stage_kind_metadata = current_workflow_config["stage_kind_metadata"]
    pipeline_presets = current_workflow_config["pipeline_presets"]
    pipeline_preset_descriptions = current_workflow_config["pipeline_preset_descriptions"]

    raw_architecture_name = (env.get("DEEP_AGENT_ARCHITECTURE_NAME") or "aws_collaboration").strip()
    if raw_architecture_name.lower() in {"auto", "dynamic"}:
        architecture_name = "dynamic"
        architecture_fallback_name = "aws_collaboration"
    else:
        architecture_name = raw_architecture_name
        architecture_fallback_name = architecture_name
    if architecture_fallback_name not in architecture_presets:
        raise RuntimeError(
            f"Unknown DEEP_AGENT_ARCHITECTURE_NAME={architecture_name!r}. "
            f"Available presets: {', '.join(sorted(architecture_presets))}"
        )

    raw_pipeline_name = (env.get("DEEP_AGENT_PIPELINE_NAME") or "preflight_planner_workers_validators_reporter").strip()
    auto_select_pipeline = raw_pipeline_name.lower() in {"auto", "dynamic"}
    if auto_select_pipeline:
        auto_select_pipeline = True
        pipeline_name = "preflight_planner_workers_validators_reporter"
    else:
        pipeline_name = raw_pipeline_name
    if pipeline_name not in pipeline_presets:
        raise RuntimeError(
            f"Unknown DEEP_AGENT_PIPELINE_NAME={pipeline_name!r}. "
            f"Available presets: {', '.join(sorted(pipeline_presets))}"
        )

    architecture = list(architecture_presets[architecture_fallback_name])
    pipeline = resolve_pipeline_definition(pipeline_presets[pipeline_name], architecture)

    return {
        "DOTENV_PATH": str(loaded_dotenv) if loaded_dotenv else "",
        "OPENAI_MODEL_ID": env.get("OPENAI_MODEL_ID", "openai:gpt-5-mini"),
        "DEEP_FORCE_MODEL_ID": str(env.get("DEEP_FORCE_MODEL_ID", "")).strip(),
        "MAX_ROLE_HISTORY_MESSAGES": int(env.get("MAX_ROLE_HISTORY_MESSAGES", "16")),
        "MAX_TASK_OUTPUTS": int(env.get("MAX_TASK_OUTPUTS", "32")),
        "MAX_TOOL_LOG_CHARS": int(env.get("MAX_TOOL_LOG_CHARS", "120000")),
        "MAX_TOOL_RESULT_CACHE_ENTRIES": int(env.get("MAX_TOOL_RESULT_CACHE_ENTRIES", "64")),
        "MAX_VALIDATION_REPLAN_RETRIES": int(env.get("MAX_VALIDATION_REPLAN_RETRIES", "2")),
        "MAX_PARALLEL_WORKERS": max(1, int(env.get("MAX_PARALLEL_WORKERS", "2"))),
        "TOOL_RESULT_CACHE_SERVER_MARKERS": _parse_lower_marker_list(
            env.get(
                "TOOL_RESULT_CACHE_SERVER_MARKERS",
                "ghidra,capa,floss,string,hashdb,binwalk,yara,gitleaks,searchsploit,trivy",
            )
        ),
        "SERIAL_MCP_SERVER_MARKERS": _parse_lower_marker_list(
            env.get("SERIAL_MCP_SERVER_MARKERS", "ghidra")
        ),
        "SERIAL_HOST_WORKER_ARCHETYPES": _parse_lower_marker_list(
            env.get("SERIAL_HOST_WORKER_ARCHETYPES", "ghidra_analyst")
        ),
        "DEEP_ENABLE_MEMORY": _env_flag_from(env, "DEEP_ENABLE_MEMORY", True),
        "DEEP_MEMORY_DIR": env.get("DEEP_MEMORY_DIR", ".deep/memory"),
        "DEEP_PERSIST_BACKEND": _env_flag_from(env, "DEEP_PERSIST_BACKEND", True),
        "AUTO_TRIAGE_INCLUDE_PRESWEEP_STRING_PREVIEWS": _env_flag_from(
            env,
            "AUTO_TRIAGE_INCLUDE_PRESWEEP_STRING_PREVIEWS",
            True,
        ),
        "DEEP_BACKEND_ROOT": env.get("DEEP_BACKEND_ROOT", "./.deep_backend"),
        "DEEP_ENABLE_SKILLS": _env_flag_from(env, "DEEP_ENABLE_SKILLS", True),
        "DEEP_INCLUDE_BUNDLED_SKILLS": _env_flag_from(env, "DEEP_INCLUDE_BUNDLED_SKILLS", True),
        "DEEP_SKILL_DIRS": _parse_path_list(str(env.get("DEEP_SKILL_DIRS", ""))),
        "HOST_PARALLEL_WORKER_EXECUTION": _env_flag_from(env, "HOST_PARALLEL_WORKER_EXECUTION", True),
        "DEEP_CONTEXT_MAX_TOKENS": int(env.get("DEEP_CONTEXT_MAX_TOKENS", "18000")),
        "DEEP_AGENT_REQUEST_LIMIT": _parse_optional_positive_int(env.get("DEEP_AGENT_REQUEST_LIMIT"), 50),
        "MAX_STATUS_LOG_LINES": int(env.get("MAX_STATUS_LOG_LINES", "400")),
        "STATUS_LOG_STDOUT": _env_flag_from(env, "STATUS_LOG_STDOUT", True),
        "DEEP_AGENT_RETRIES": int(env.get("DEEP_AGENT_RETRIES", "4")),
        "DEEP_WORKER_SUBAGENT_PROFILE": str(env.get("DEEP_WORKER_SUBAGENT_PROFILE", "default")).strip().lower() or "default",
        "DEEP_WORKER_PERSONA_PROFILE": str(env.get("DEEP_WORKER_PERSONA_PROFILE", "default")).strip().lower() or "default",
        "DEEP_WORKER_ROLE_PROMPT_MODE": _normalize_worker_role_prompt_mode(
            env.get("DEEP_WORKER_ROLE_PROMPT_MODE", "default")
        ),
        "DEEP_AGENT_AUTO_SELECT_PIPELINE": auto_select_pipeline,
        "DEEP_AGENT_PIPELINE_ROUTER_MODEL": env.get("DEEP_AGENT_PIPELINE_ROUTER_MODEL", "openai:gpt-4o-mini"),
        "DEFAULT_ALLOW_PARENT_INPUT": _env_flag_from(env, "DEFAULT_ALLOW_PARENT_INPUT", False),
        "DEFAULT_VALIDATOR_REVIEW_LEVEL": _normalize_validator_review_level(
            env.get("DEFAULT_VALIDATOR_REVIEW_LEVEL", "default")
        ),
        "DEFAULT_SHELL_EXECUTION_MODE": _normalize_shell_execution_mode(
            env.get("DEFAULT_SHELL_EXECUTION_MODE", "none")
        ),
        "AUTOMATION_TRIGGER_ENABLED": _env_flag_from(env, "AUTOMATION_TRIGGER_ENABLED", False),
        "AUTOMATION_TRIGGER_HOST": (env.get("AUTOMATION_TRIGGER_HOST") or "127.0.0.1").strip() or "127.0.0.1",
        "AUTOMATION_TRIGGER_PORT": int(env.get("AUTOMATION_TRIGGER_PORT", "7861")),
        "AUTOMATION_TRIGGER_PATH": (
            (env.get("AUTOMATION_TRIGGER_PATH") or "/automation/ghidra-load").strip() or "/automation/ghidra-load"
        ),
        "AUTOMATION_TRIGGER_HEALTH_PATH": (
            (env.get("AUTOMATION_TRIGGER_HEALTH_PATH") or "/automation/health").strip() or "/automation/health"
        ),
        "MCP_SERVER_MANIFEST_PATH": str(
            _resolve_repo_relative_path(env.get("MCP_SERVER_MANIFEST_PATH", "MCPServers/servers.json"))
        ),
        "AUTOMATION_DEFAULT_PROMPT_TEMPLATE": env.get(
            "AUTOMATION_DEFAULT_PROMPT_TEMPLATE",
            (
                "A binary has just finished auto-analysis in Ghidra.\n"
                "Use the currently opened sample and produce an initial technical triage focused on program purpose, "
                "key control-flow pivots, concrete capabilities, relevant strings/configuration, obfuscation or "
                "anti-analysis indicators, and the highest-value next pivots.\n"
                "Program name: {program_name}\n"
                "Executable path: {executable_path}\n"
                "Executable SHA256: {executable_sha256}\n"
                "Executable MD5: {executable_md5}\n"
                "Ghidra project path: {ghidra_project_path}\n"
                "{path_handoff_line}"
            ),
        ),
        "WORKFLOW_CONFIG": current_workflow_config,
        "STAGE_KIND_METADATA": stage_kind_metadata,
        "AGENT_ARCHETYPE_PROMPTS": current_workflow_config["agent_archetype_prompts"],
        "WORKER_PERSONA_PROFILES": current_workflow_config["worker_persona_profiles"],
        "PIPELINE_STAGE_MANAGER_PROMPTS": current_workflow_config["stage_manager_prompts"],
        "DEEP_AGENT_ARCHITECTURE_PRESETS": architecture_presets,
        "DEEP_AGENT_ARCHITECTURE_DESCRIPTIONS": architecture_preset_descriptions,
        "DEEP_AGENT_PIPELINE_PRESETS": pipeline_presets,
        "DEEP_AGENT_PIPELINE_DESCRIPTIONS": pipeline_preset_descriptions,
        "AGENT_ARCHETYPE_SPECS": current_workflow_config["agent_archetype_specs"],
        "PIPELINE_STAGE_OUTPUT_CONTRACTS": current_workflow_config["stage_output_contracts"],
        "DEEP_AGENT_ARCHITECTURE_NAME": architecture_name,
        "DEEP_AGENT_ARCHITECTURE_FALLBACK_NAME": architecture_fallback_name,
        "DEEP_AGENT_ARCHITECTURE": architecture,
        "DEEP_AGENT_PIPELINE_NAME": pipeline_name,
        "DEEP_AGENT_PIPELINE": pipeline,
        "PIPELINE_LOG_SLOTS": _pipeline_log_slots_from_presets(pipeline_presets),
        "launch_kwargs": _build_launch_kwargs(env, extra_launch_kwargs),
    }


def apply_runtime_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    global _CONFIG_BOOTSTRAPPED
    for key, value in settings.items():
        globals()[key] = value
    _CONFIG_BOOTSTRAPPED = True
    return {
        "dotenv_path": settings.get("DOTENV_PATH", ""),
        "launch_kwargs": dict(settings.get("launch_kwargs") or {}),
        "runtime_settings": {k: v for k, v in settings.items() if k != "launch_kwargs"},
    }


def bootstrap_from_env(
    *,
    prompt_for_api_key: bool = True,
    dotenv_path: Optional[str] = None,
    extra_launch_kwargs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    loaded_dotenv = _load_dotenv_if_present(dotenv_path)
    _sanitize_gradio_env(os.environ)
    if prompt_for_api_key and not os.environ.get("OPENAI_API_KEY"):
        os.environ["OPENAI_API_KEY"] = getpass.getpass("Enter your OpenAI API Key: ")
    settings = _build_runtime_settings(
        os.environ,
        loaded_dotenv=loaded_dotenv,
        extra_launch_kwargs=extra_launch_kwargs,
    )
    return apply_runtime_settings(settings)


_DEFAULT_APP_SETTINGS = apply_runtime_settings(_build_runtime_settings({}, extra_launch_kwargs={}))
