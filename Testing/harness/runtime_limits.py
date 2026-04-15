"""
File: runtime_limits.py
Author: Matt-Ung
Last Updated: 2026-04-09
Purpose:
  Resolve request-limit defaults and overrides for testing-harness runs.

Summary:
  This module centralizes how the maintained testing harness chooses the deep
  agent request cap for evaluation runs. It keeps the runner, sweep launcher,
  and recovery flow aligned so they all record and reuse the same effective
  limit.
"""

from __future__ import annotations

import os
from typing import Any, Mapping

from multi_agent_wf.runtime_defaults import DEFAULT_DEEP_AGENT_REQUEST_LIMIT

DEFAULT_TESTING_DEEP_AGENT_REQUEST_LIMIT = DEFAULT_DEEP_AGENT_REQUEST_LIMIT


def parse_optional_request_limit(value: Any) -> int | None:
    """
    Function: parse_optional_request_limit
    Inputs:
      - value: raw candidate request-limit value from CLI args, manifests, or
        environment variables.
    Description:
      Normalize a request-limit setting into either a positive integer or
      `None` when the limit should be treated as disabled.
    Outputs:
      Returns a positive integer request limit or `None`.
    Side Effects:
      None.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    normalized = int(text)
    return normalized if normalized > 0 else None


def resolve_testing_deep_agent_request_limit(
    explicit_value: Any = None,
    *,
    env: Mapping[str, str] | None = None,
    default: int = DEFAULT_TESTING_DEEP_AGENT_REQUEST_LIMIT,
) -> int | None:
    """
    Function: resolve_testing_deep_agent_request_limit
    Inputs:
      - explicit_value: optional CLI or manifest override for the request cap.
      - env: optional environment mapping. Defaults to `os.environ`.
      - default: fallback limit used by maintained evaluation runs when no
        explicit testing or runtime override is present.
    Description:
      Resolve the effective deep-agent request limit for testing-harness runs.
      Explicit CLI values win first, then testing-specific env overrides, then
      the general runtime env, and finally the maintained evaluation default.
    Outputs:
      Returns a positive integer request limit, or `None` when the caller
      explicitly disabled it with a zero-or-negative value.
    Side Effects:
      None.
    """
    environment = env or os.environ
    if explicit_value is not None:
        return parse_optional_request_limit(explicit_value)
    for key in ("TESTING_DEEP_AGENT_REQUEST_LIMIT", "DEEP_AGENT_REQUEST_LIMIT"):
        if key in environment and str(environment.get(key) or "").strip():
            return parse_optional_request_limit(environment.get(key))
    return parse_optional_request_limit(default)


def request_limit_env_value(limit: int | None) -> str:
    """
    Function: request_limit_env_value
    Inputs:
      - limit: normalized request-limit value.
    Description:
      Convert a normalized limit into the string form written into env vars so
      child processes and runtime reloads can distinguish an explicit disabled
      cap (`0`) from an unset variable.
    Outputs:
      Returns a string environment value.
    Side Effects:
      None.
    """
    return str(int(limit)) if limit is not None else "0"
