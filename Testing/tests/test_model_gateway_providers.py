import importlib
import sys
import types
import unittest
from unittest.mock import Mock, patch


def _import_model_gateway_providers_with_stubbed_requests():
    requests_mod = types.ModuleType("requests")
    requests_mod.Timeout = type("Timeout", (Exception,), {})
    requests_mod.ConnectionError = type("ConnectionError", (Exception,), {})
    requests_mod.Response = type("Response", (), {})
    requests_mod.post = lambda *args, **kwargs: None
    sys.modules["requests"] = requests_mod
    sys.modules.pop("MCPServers.modelGatewayProviders", None)
    return importlib.import_module("MCPServers.modelGatewayProviders")


class ModelGatewayProviderRetryTests(unittest.TestCase):
    def test_openai_compatible_backend_retries_rate_limit_then_succeeds(self) -> None:
        providers_mod = _import_model_gateway_providers_with_stubbed_requests()
        backend = providers_mod.OpenAICompatibleBackend()

        rate_limited = Mock()
        rate_limited.ok = False
        rate_limited.status_code = 429
        rate_limited.text = "Too Many Requests"

        success = Mock()
        success.ok = True
        success.status_code = 200
        success.json.return_value = {
            "choices": [
                {
                    "message": {"content": "ok"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }

        request = providers_mod.GenerationRequest(
            prompt="hello",
            provider="openai_compatible",
            model="test-model",
            endpoint_url="https://example.invalid/v1/chat/completions",
            timeout_sec=5,
        )

        with patch.object(providers_mod.requests, "post", side_effect=[rate_limited, success]) as fake_post, patch.object(
            providers_mod.time, "sleep"
        ) as fake_sleep:
            result = backend.generate(request)

        self.assertEqual(result["text"], "ok")
        self.assertEqual(fake_post.call_count, 2)
        fake_sleep.assert_called_once_with(1.0)

    def test_openai_compatible_backend_retries_connection_error_then_raises(self) -> None:
        providers_mod = _import_model_gateway_providers_with_stubbed_requests()
        backend = providers_mod.OpenAICompatibleBackend()
        request = providers_mod.GenerationRequest(
            prompt="hello",
            provider="openai_compatible",
            model="test-model",
            endpoint_url="https://example.invalid/v1/chat/completions",
            timeout_sec=5,
        )

        with patch.object(
            providers_mod.requests,
            "post",
            side_effect=providers_mod.requests.ConnectionError("socket closed"),
        ) as fake_post, patch.object(providers_mod.time, "sleep") as fake_sleep:
            with self.assertRaises(providers_mod.InferenceBackendError):
                backend.generate(request)

        self.assertEqual(fake_post.call_count, 4)
        self.assertEqual(fake_sleep.call_count, 3)


if __name__ == "__main__":
    unittest.main()
