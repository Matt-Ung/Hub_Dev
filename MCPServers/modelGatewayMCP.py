#!/usr/bin/env python3
"""
FastMCP server for alternate model backends such as Hugging Face-hosted models
or OpenAI-compatible self-hosted / GPU-hosted inference endpoints.
"""

from __future__ import annotations

import argparse
import logging
from typing import Any, Dict, List

from fastmcp import FastMCP

from modelGatewayProviders import (
    GenerationRequest,
    generate_with_backend,
    normalize_provider_name,
    parse_jsonish_object,
    list_provider_summaries,
)

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "model_gateway_mcp",
    instructions=(
        "MCP server for alternate model backends. Use it to call Hugging Face-hosted, "
        "self-hosted, or OpenAI-compatible inference endpoints as advisory secondary models."
    ),
)


def _make_request(
    *,
    prompt: str,
    system_prompt: str,
    provider: str,
    model: str,
    endpoint_url: str,
    auth_env_var: str,
    temperature: float,
    max_tokens: int,
    top_p: float,
    timeout_sec: int,
) -> GenerationRequest:
    return GenerationRequest(
        prompt=str(prompt or ""),
        system_prompt=str(system_prompt or ""),
        provider=normalize_provider_name(provider),
        model=str(model or ""),
        endpoint_url=str(endpoint_url or ""),
        auth_env_var=str(auth_env_var or ""),
        temperature=float(temperature),
        max_tokens=int(max_tokens),
        top_p=float(top_p),
        timeout_sec=int(timeout_sec),
    )


@mcp.tool()
def listAltModelBackends() -> Dict[str, Any]:
    """List supported alternate-model providers and environment variables."""
    return list_provider_summaries()


@mcp.tool()
def generateWithAltModel(
    prompt: str,
    system_prompt: str = "",
    provider: str = "",
    model: str = "",
    endpoint_url: str = "",
    auth_env_var: str = "",
    temperature: float = 0.2,
    max_tokens: int = 768,
    top_p: float = 1.0,
    timeout_sec: int = 90,
) -> Dict[str, Any]:
    """
    Generate text with an alternate backend.
    """
    try:
        request = _make_request(
            prompt=prompt,
            system_prompt=system_prompt,
            provider=provider,
            model=model,
            endpoint_url=endpoint_url,
            auth_env_var=auth_env_var,
            temperature=temperature,
            max_tokens=max_tokens,
            top_p=top_p,
            timeout_sec=timeout_sec,
        )
        return generate_with_backend(request)
    except Exception as exc:
        logger.exception("generateWithAltModel failed")
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
def classifyWithAltModel(
    text: str,
    labels: List[str],
    task_instruction: str = "",
    provider: str = "",
    model: str = "",
    endpoint_url: str = "",
    auth_env_var: str = "",
    temperature: float = 0.0,
    max_tokens: int = 192,
    top_p: float = 1.0,
    timeout_sec: int = 60,
) -> Dict[str, Any]:
    """
    Ask the alternate model to classify text into one of a fixed set of labels.
    """
    allowed = [str(label).strip() for label in list(labels or []) if str(label).strip()]
    if not allowed:
        return {"ok": False, "error": "labels must contain at least one non-empty label"}

    instruction = str(task_instruction or "Choose the single best label for the content.").strip()
    system_prompt = (
        "You are a careful classifier. Return JSON only with keys "
        "`label`, `confidence`, and `rationale`. Do not add markdown fences."
    )
    prompt = (
        f"Task: {instruction}\n"
        f"Allowed labels: {', '.join(allowed)}\n\n"
        "Return JSON exactly like:\n"
        '{"label": "<one allowed label>", "confidence": 0.0, "rationale": "<short explanation>"}\n\n'
        f"Content:\n{text}"
    )
    response = generateWithAltModel(
        prompt=prompt,
        system_prompt=system_prompt,
        provider=provider,
        model=model,
        endpoint_url=endpoint_url,
        auth_env_var=auth_env_var,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        timeout_sec=timeout_sec,
    )
    if not response.get("ok"):
        return response
    try:
        parsed = parse_jsonish_object(str(response.get("text") or ""))
    except Exception as exc:
        return {
            "ok": False,
            "error": f"unable to parse classification JSON: {exc}",
            "raw_text": response.get("text", ""),
            "provider": response.get("provider", ""),
            "model": response.get("model", ""),
        }

    raw_label = str(parsed.get("label") or "").strip()
    match = next((label for label in allowed if label.lower() == raw_label.lower()), "")
    if not match:
        return {
            "ok": False,
            "error": f"classifier returned unsupported label: {raw_label!r}",
            "allowed_labels": allowed,
            "raw_text": response.get("text", ""),
            "provider": response.get("provider", ""),
            "model": response.get("model", ""),
        }

    try:
        confidence = float(parsed.get("confidence", 0.0))
    except Exception:
        confidence = 0.0

    return {
        "ok": True,
        "provider": response.get("provider", ""),
        "model": response.get("model", ""),
        "endpoint_url": response.get("endpoint_url", ""),
        "label": match,
        "confidence": confidence,
        "rationale": str(parsed.get("rationale") or "").strip(),
        "raw_text": response.get("text", ""),
    }


@mcp.tool()
def compareModelOutputs(
    prompt: str,
    candidate_a: str,
    candidate_b: str,
    criteria: str = "",
    provider: str = "",
    model: str = "",
    endpoint_url: str = "",
    auth_env_var: str = "",
    temperature: float = 0.0,
    max_tokens: int = 320,
    top_p: float = 1.0,
    timeout_sec: int = 90,
) -> Dict[str, Any]:
    """
    Use the alternate backend as a judge between two candidate outputs.
    """
    judge_criteria = str(criteria or "Prefer the more accurate, evidence-grounded, and technically useful answer.").strip()
    system_prompt = (
        "You are an impartial evaluator. Return JSON only with keys "
        "`preferred`, `rationale`, and `confidence`. "
        "`preferred` must be one of: A, B, tie."
    )
    judge_prompt = (
        f"Original task:\n{prompt}\n\n"
        f"Criteria:\n{judge_criteria}\n\n"
        f"Candidate A:\n{candidate_a}\n\n"
        f"Candidate B:\n{candidate_b}\n\n"
        "Return JSON exactly like:\n"
        '{"preferred": "A", "confidence": 0.0, "rationale": "<short explanation>"}'
    )
    response = generateWithAltModel(
        prompt=judge_prompt,
        system_prompt=system_prompt,
        provider=provider,
        model=model,
        endpoint_url=endpoint_url,
        auth_env_var=auth_env_var,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        timeout_sec=timeout_sec,
    )
    if not response.get("ok"):
        return response
    try:
        parsed = parse_jsonish_object(str(response.get("text") or ""))
    except Exception as exc:
        return {
            "ok": False,
            "error": f"unable to parse comparison JSON: {exc}",
            "raw_text": response.get("text", ""),
            "provider": response.get("provider", ""),
            "model": response.get("model", ""),
        }
    preferred = str(parsed.get("preferred") or "").strip().lower()
    if preferred not in {"a", "b", "tie"}:
        return {
            "ok": False,
            "error": f"comparison returned unsupported preferred value: {preferred!r}",
            "raw_text": response.get("text", ""),
            "provider": response.get("provider", ""),
            "model": response.get("model", ""),
        }
    try:
        confidence = float(parsed.get("confidence", 0.0))
    except Exception:
        confidence = 0.0
    return {
        "ok": True,
        "provider": response.get("provider", ""),
        "model": response.get("model", ""),
        "endpoint_url": response.get("endpoint_url", ""),
        "preferred": preferred,
        "confidence": confidence,
        "rationale": str(parsed.get("rationale") or "").strip(),
        "raw_text": response.get("text", ""),
    }


@mcp.tool()
def recoverDecompilationWithAltModel(
    decompiled_code: str,
    surrounding_context: str = "",
    task_focus: str = "Recover better names, type hints, and clearer source-like logic without inventing unsupported behavior.",
    provider: str = "",
    model: str = "",
    endpoint_url: str = "",
    auth_env_var: str = "",
    temperature: float = 0.1,
    max_tokens: int = 700,
    top_p: float = 1.0,
    timeout_sec: int = 120,
) -> Dict[str, Any]:
    """
    Specialized helper for decompiler cleanup inspired by neural decompilation papers.
    """
    system_prompt = (
        "You are assisting reverse engineering from deterministic decompiler output. "
        "Return JSON only with keys `refined_pseudocode`, `type_hints`, "
        "`naming_suggestions`, and `confidence_notes`. "
        "Do not claim behavior that is not supported by the snippet."
    )
    prompt = (
        f"Goal: {task_focus}\n\n"
        "If you infer better names or types, present them as suggestions rather than facts.\n\n"
        "Surrounding context:\n"
        f"{surrounding_context or '(none)'}\n\n"
        "Decompiler output:\n"
        f"{decompiled_code}\n\n"
        "Return JSON exactly like:\n"
        '{'
        '"refined_pseudocode": "<cleaned source-like text>", '
        '"type_hints": ["<hint 1>"], '
        '"naming_suggestions": ["<suggestion 1>"], '
        '"confidence_notes": "<limits and caveats>"'
        '}'
    )
    response = generateWithAltModel(
        prompt=prompt,
        system_prompt=system_prompt,
        provider=provider,
        model=model,
        endpoint_url=endpoint_url,
        auth_env_var=auth_env_var,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        timeout_sec=timeout_sec,
    )
    if not response.get("ok"):
        return response
    try:
        parsed = parse_jsonish_object(str(response.get("text") or ""))
    except Exception as exc:
        return {
            "ok": False,
            "error": f"unable to parse decompilation-recovery JSON: {exc}",
            "raw_text": response.get("text", ""),
            "provider": response.get("provider", ""),
            "model": response.get("model", ""),
        }
    return {
        "ok": True,
        "provider": response.get("provider", ""),
        "model": response.get("model", ""),
        "endpoint_url": response.get("endpoint_url", ""),
        "refined_pseudocode": str(parsed.get("refined_pseudocode") or "").strip(),
        "type_hints": list(parsed.get("type_hints") or []),
        "naming_suggestions": list(parsed.get("naming_suggestions") or []),
        "confidence_notes": str(parsed.get("confidence_notes") or "").strip(),
        "raw_text": response.get("text", ""),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for alternate model backends")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8095)
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="sse", host=args.mcp_host, port=args.mcp_port)


if __name__ == "__main__":
    main()
