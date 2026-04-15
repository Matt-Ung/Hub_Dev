#!/usr/bin/env python3
"""
Provider abstraction for alternate-model inference backends used by modelGatewayMCP.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List

import requests


class InferenceBackendError(RuntimeError):
    pass


_HTTP_RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
_HTTP_RETRY_BACKOFF_SECONDS = (1.0, 3.0, 6.0)


def _env_text(name: str) -> str:
    return str(os.environ.get(name) or "").strip()


def _coerce_float(value: Any, default: float) -> float:
    try:
        if value is None or value == "":
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def _coerce_int(value: Any, default: int) -> int:
    try:
        if value is None or value == "":
            return int(default)
        return int(value)
    except Exception:
        return int(default)


def _auth_token_from_env(explicit_env_var: str, *fallback_env_vars: str) -> str:
    candidate_vars: List[str] = []
    if explicit_env_var:
        candidate_vars.append(explicit_env_var)
    candidate_vars.extend(fallback_env_vars)
    for env_var in candidate_vars:
        token = _env_text(env_var)
        if token:
            return token
    return ""


def _redact_endpoint(endpoint_url: str) -> str:
    return str(endpoint_url or "").strip()


def _strip_fence(text: str) -> str:
    value = str(text or "").strip()
    if value.startswith("```"):
        value = re.sub(r"^```(?:json)?\s*", "", value, flags=re.IGNORECASE)
        value = re.sub(r"\s*```$", "", value)
    return value.strip()


def parse_jsonish_object(text: str) -> Dict[str, Any]:
    value = _strip_fence(text)
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    start = value.find("{")
    end = value.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            parsed = json.loads(value[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    raise InferenceBackendError("model output did not contain a parseable JSON object")


def _retry_backoff_sec(attempt_index: int) -> float:
    if attempt_index < len(_HTTP_RETRY_BACKOFF_SECONDS):
        return float(_HTTP_RETRY_BACKOFF_SECONDS[attempt_index])
    last = float(_HTTP_RETRY_BACKOFF_SECONDS[-1])
    growth = 2 ** max(0, attempt_index - len(_HTTP_RETRY_BACKOFF_SECONDS) + 1)
    return float(min(10.0, last * growth))


def _should_retry_response(response: requests.Response) -> bool:
    return int(getattr(response, "status_code", 0) or 0) in _HTTP_RETRY_STATUS_CODES


def _post_json_with_retry(
    url: str,
    *,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    timeout_sec: int,
    max_attempts: int = 4,
) -> requests.Response:
    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=max(1, int(timeout_sec)),
            )
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_error = exc
            if attempt >= max_attempts:
                raise InferenceBackendError(
                    f"request failed after {attempt} attempt(s): {type(exc).__name__}: {exc}"
                ) from exc
            time.sleep(_retry_backoff_sec(attempt - 1))
            continue

        if response.ok or not _should_retry_response(response) or attempt >= max_attempts:
            return response

        time.sleep(_retry_backoff_sec(attempt - 1))

    if last_error is not None:
        raise InferenceBackendError(
            f"request failed after {max_attempts} attempt(s): {type(last_error).__name__}: {last_error}"
        ) from last_error
    raise InferenceBackendError("request failed without a response")


@dataclass
class GenerationRequest:
    prompt: str
    system_prompt: str = ""
    provider: str = ""
    model: str = ""
    endpoint_url: str = ""
    auth_env_var: str = ""
    temperature: float = 0.2
    max_tokens: int = 768
    top_p: float = 1.0
    timeout_sec: int = 90


class InferenceBackend:
    provider_id: str = ""
    description: str = ""
    env_hints: List[str] = []

    def resolve(self, request: GenerationRequest) -> GenerationRequest:
        raise NotImplementedError

    def generate(self, request: GenerationRequest) -> Dict[str, Any]:
        raise NotImplementedError


class OpenAICompatibleBackend(InferenceBackend):
    provider_id = "openai_compatible"
    description = (
        "OpenAI-compatible chat completions API. Use for vLLM, llama.cpp servers, "
        "Runpod OpenAI-compatible deployments, or similar hosted inference endpoints."
    )
    env_hints = [
        "ALT_MODEL_DEFAULT_PROVIDER",
        "ALT_MODEL_DEFAULT_MODEL",
        "ALT_MODEL_DEFAULT_ENDPOINT",
        "OPENAI_COMPAT_MODEL_ID",
        "OPENAI_COMPAT_BASE_URL",
        "OPENAI_COMPAT_API_KEY",
    ]

    def resolve(self, request: GenerationRequest) -> GenerationRequest:
        model = str(request.model or _env_text("OPENAI_COMPAT_MODEL_ID") or _env_text("ALT_MODEL_DEFAULT_MODEL")).strip()
        endpoint = str(request.endpoint_url or _env_text("OPENAI_COMPAT_BASE_URL") or _env_text("ALT_MODEL_DEFAULT_ENDPOINT")).strip()
        if not model:
            raise InferenceBackendError("openai_compatible provider requires a model name")
        if not endpoint:
            raise InferenceBackendError("openai_compatible provider requires an endpoint URL")
        token = _auth_token_from_env(request.auth_env_var, "OPENAI_COMPAT_API_KEY", "ALT_MODEL_AUTH_TOKEN")
        endpoint = endpoint.rstrip("/")
        if endpoint.endswith("/chat/completions"):
            chat_url = endpoint
        elif endpoint.endswith("/v1"):
            chat_url = endpoint + "/chat/completions"
        else:
            chat_url = endpoint + "/v1/chat/completions"
        return GenerationRequest(
            prompt=request.prompt,
            system_prompt=request.system_prompt,
            provider=self.provider_id,
            model=model,
            endpoint_url=chat_url,
            auth_env_var=token,
            temperature=_coerce_float(request.temperature, _coerce_float(_env_text("ALT_MODEL_DEFAULT_TEMPERATURE"), 0.2)),
            max_tokens=_coerce_int(request.max_tokens, _coerce_int(_env_text("ALT_MODEL_DEFAULT_MAX_TOKENS"), 768)),
            top_p=_coerce_float(request.top_p, _coerce_float(_env_text("ALT_MODEL_DEFAULT_TOP_P"), 1.0)),
            timeout_sec=_coerce_int(request.timeout_sec, _coerce_int(_env_text("ALT_MODEL_DEFAULT_TIMEOUT_SEC"), 90)),
        )

    def generate(self, request: GenerationRequest) -> Dict[str, Any]:
        resolved = self.resolve(request)
        headers = {"Content-Type": "application/json"}
        if resolved.auth_env_var:
            headers["Authorization"] = "Bearer " + resolved.auth_env_var
        payload = {
            "model": resolved.model,
            "messages": [],
            "temperature": resolved.temperature,
            "max_tokens": resolved.max_tokens,
            "top_p": resolved.top_p,
        }
        if resolved.system_prompt:
            payload["messages"].append({"role": "system", "content": resolved.system_prompt})
        payload["messages"].append({"role": "user", "content": resolved.prompt})
        response = _post_json_with_retry(
            resolved.endpoint_url,
            headers=headers,
            payload=payload,
            timeout_sec=resolved.timeout_sec,
        )
        if not response.ok:
            raise InferenceBackendError(f"{response.status_code}: {response.text[:1000]}")
        data = response.json()
        choices = data.get("choices") if isinstance(data, dict) else None
        if not isinstance(choices, list) or not choices:
            raise InferenceBackendError("openai-compatible endpoint returned no choices")
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        text = ""
        if isinstance(message, dict):
            text = str(message.get("content") or "")
        if not text:
            text = str(choices[0].get("text") or "")
        return {
            "ok": True,
            "provider": self.provider_id,
            "model": resolved.model,
            "endpoint_url": _redact_endpoint(resolved.endpoint_url),
            "text": text.strip(),
            "finish_reason": str(choices[0].get("finish_reason") or ""),
            "usage": data.get("usage") if isinstance(data.get("usage"), dict) else {},
            "raw_response": data,
        }


class HuggingFaceInferenceBackend(InferenceBackend):
    provider_id = "huggingface_inference"
    description = (
        "Hugging Face hosted Inference API or a Hugging Face-style text-generation endpoint. "
        "Best for direct Hugging Face-hosted open-weight model calls."
    )
    env_hints = [
        "ALT_MODEL_DEFAULT_PROVIDER",
        "ALT_MODEL_DEFAULT_MODEL",
        "ALT_MODEL_DEFAULT_ENDPOINT",
        "HF_MODEL_ID",
        "HF_INFERENCE_ENDPOINT",
        "HF_INFERENCE_API_TOKEN",
    ]

    def resolve(self, request: GenerationRequest) -> GenerationRequest:
        model = str(request.model or _env_text("HF_MODEL_ID") or _env_text("ALT_MODEL_DEFAULT_MODEL")).strip()
        endpoint = str(request.endpoint_url or _env_text("HF_INFERENCE_ENDPOINT") or _env_text("ALT_MODEL_DEFAULT_ENDPOINT")).strip()
        if not endpoint:
            if not model:
                raise InferenceBackendError("huggingface_inference provider requires a model or endpoint URL")
            endpoint = "https://api-inference.huggingface.co/models/" + model
        token = _auth_token_from_env(request.auth_env_var, "HF_INFERENCE_API_TOKEN", "ALT_MODEL_AUTH_TOKEN")
        return GenerationRequest(
            prompt=request.prompt,
            system_prompt=request.system_prompt,
            provider=self.provider_id,
            model=model,
            endpoint_url=endpoint,
            auth_env_var=token,
            temperature=_coerce_float(request.temperature, _coerce_float(_env_text("ALT_MODEL_DEFAULT_TEMPERATURE"), 0.2)),
            max_tokens=_coerce_int(request.max_tokens, _coerce_int(_env_text("ALT_MODEL_DEFAULT_MAX_TOKENS"), 768)),
            top_p=_coerce_float(request.top_p, _coerce_float(_env_text("ALT_MODEL_DEFAULT_TOP_P"), 1.0)),
            timeout_sec=_coerce_int(request.timeout_sec, _coerce_int(_env_text("ALT_MODEL_DEFAULT_TIMEOUT_SEC"), 90)),
        )

    def generate(self, request: GenerationRequest) -> Dict[str, Any]:
        resolved = self.resolve(request)
        headers = {"Content-Type": "application/json"}
        if resolved.auth_env_var:
            headers["Authorization"] = "Bearer " + resolved.auth_env_var
        inputs = resolved.prompt if not resolved.system_prompt else "[SYSTEM]\n%s\n\n[USER]\n%s" % (
            resolved.system_prompt,
            resolved.prompt,
        )
        payload = {
            "inputs": inputs,
            "parameters": {
                "max_new_tokens": resolved.max_tokens,
                "temperature": resolved.temperature,
                "top_p": resolved.top_p,
                "return_full_text": False,
            },
            "options": {
                "wait_for_model": True,
                "use_cache": False,
            },
        }
        response = _post_json_with_retry(
            resolved.endpoint_url,
            headers=headers,
            payload=payload,
            timeout_sec=resolved.timeout_sec,
        )
        if not response.ok:
            raise InferenceBackendError(f"{response.status_code}: {response.text[:1000]}")
        data = response.json()
        text = ""
        finish_reason = ""
        if isinstance(data, list) and data:
            first = data[0]
            if isinstance(first, dict):
                text = str(first.get("generated_text") or first.get("summary_text") or "")
                finish_reason = str(first.get("finish_reason") or "")
        elif isinstance(data, dict):
            if data.get("error"):
                raise InferenceBackendError(str(data.get("error")))
            text = str(data.get("generated_text") or data.get("summary_text") or "")
            finish_reason = str(data.get("finish_reason") or "")
        if not text:
            text = json.dumps(data, ensure_ascii=False)
        return {
            "ok": True,
            "provider": self.provider_id,
            "model": resolved.model,
            "endpoint_url": _redact_endpoint(resolved.endpoint_url),
            "text": text.strip(),
            "finish_reason": finish_reason,
            "usage": {},
            "raw_response": data,
        }


_PROVIDERS: Dict[str, InferenceBackend] = {
    "openai_compatible": OpenAICompatibleBackend(),
    "huggingface_inference": HuggingFaceInferenceBackend(),
}

_PROVIDER_ALIASES = {
    "openai": "openai_compatible",
    "openai_compatible": "openai_compatible",
    "openai-compatible": "openai_compatible",
    "vllm": "openai_compatible",
    "runpod": "openai_compatible",
    "runpod_openai": "openai_compatible",
    "llamacpp": "openai_compatible",
    "llama.cpp": "openai_compatible",
    "huggingface": "huggingface_inference",
    "hf": "huggingface_inference",
    "hf_inference": "huggingface_inference",
    "huggingface_inference": "huggingface_inference",
}


def normalize_provider_name(raw: str) -> str:
    value = str(raw or _env_text("ALT_MODEL_DEFAULT_PROVIDER") or "openai_compatible").strip().lower()
    return _PROVIDER_ALIASES.get(value, value)


def get_backend(provider_name: str) -> InferenceBackend:
    normalized = normalize_provider_name(provider_name)
    backend = _PROVIDERS.get(normalized)
    if backend is None:
        raise InferenceBackendError(
            "Unknown alternate-model provider %r. Supported providers: %s"
            % (provider_name, ", ".join(sorted(_PROVIDERS)))
        )
    return backend


def list_provider_summaries() -> Dict[str, Any]:
    default_provider = normalize_provider_name(_env_text("ALT_MODEL_DEFAULT_PROVIDER") or "openai_compatible")
    return {
        "default_provider": default_provider,
        "providers": {
            name: {
                "description": backend.description,
                "env_hints": list(backend.env_hints),
            }
            for name, backend in sorted(_PROVIDERS.items())
        },
    }


def generate_with_backend(request: GenerationRequest) -> Dict[str, Any]:
    backend = get_backend(request.provider)
    return backend.generate(request)
