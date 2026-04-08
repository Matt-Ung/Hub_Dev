import asyncio
import importlib
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from Testing.harness.analyze import _derive_result_status


def _install_runtime_dependency_stubs() -> None:
    pydantic_ai = types.ModuleType("pydantic_ai")
    pydantic_ai.Agent = type("Agent", (), {})
    pydantic_ai.ModelMessage = type("ModelMessage", (), {})

    pydantic_ai_mcp = types.ModuleType("pydantic_ai.mcp")

    class MCPServerStdio:
        def __init__(self, command, *, args=None, env=None, cwd=None, tool_prefix=None, log_level=None, log_handler=None, timeout=None, read_timeout=None, process_tool_call=None, allow_sampling=None, sampling_model=None, max_retries=None, elicitation_callback=None, cache_tools=None, cache_resources=None, id=None, client_info=None):
            self.command = command
            self.args = list(args or [])
            self.env = env
            self.cwd = cwd
            self.tool_prefix = tool_prefix
            self.log_level = log_level
            self.log_handler = log_handler
            self.timeout = timeout
            self.read_timeout = read_timeout
            self.process_tool_call = process_tool_call
            self.allow_sampling = allow_sampling
            self.sampling_model = sampling_model
            self.max_retries = max_retries
            self.elicitation_callback = elicitation_callback
            self.cache_tools = cache_tools
            self.cache_resources = cache_resources
            self.id = id
            self.client_info = client_info
            self._running = False
            self.enter_count = 0
            self.exit_count = 0

        def is_running(self):
            return self._running

        async def __aenter__(self):
            self.enter_count += 1
            self._running = True
            return self

        async def __aexit__(self, *args):
            self.exit_count += 1
            self._running = False
            return None

    pydantic_ai_mcp.MCPServerStdio = MCPServerStdio

    pydantic_ai_messages = types.ModuleType("pydantic_ai.messages")
    for name in (
        "FunctionToolCallEvent",
        "FunctionToolResultEvent",
        "ModelRequest",
        "ModelResponse",
        "RetryPromptPart",
        "ToolCallPart",
        "ToolReturnPart",
        "UserPromptPart",
    ):
        setattr(pydantic_ai_messages, name, type(name, (), {}))

    pydantic_deep = types.ModuleType("pydantic_deep")
    pydantic_deep.__file__ = __file__
    pydantic_deep.create_deep_agent = lambda **kwargs: {"agent_kwargs": kwargs}
    pydantic_deep.create_default_deps = lambda backend=None: {"backend": backend}
    pydantic_deep.create_sliding_window_processor = lambda **kwargs: {"processor": kwargs}

    sys.modules["pydantic_ai"] = pydantic_ai
    sys.modules["pydantic_ai.mcp"] = pydantic_ai_mcp
    sys.modules["pydantic_ai.messages"] = pydantic_ai_messages
    sys.modules["pydantic_deep"] = pydantic_deep


def _import_runtime_with_stubs():
    _install_runtime_dependency_stubs()
    sys.modules.pop("multi_agent_wf.shared_state", None)
    sys.modules.pop("multi_agent_wf.runtime", None)
    return importlib.import_module("multi_agent_wf.runtime")


def _import_pipeline_with_stubs():
    _install_runtime_dependency_stubs()
    sys.modules.pop("multi_agent_wf.shared_state", None)
    sys.modules.pop("multi_agent_wf.runtime", None)
    sys.modules.pop("multi_agent_wf.pipeline", None)
    return importlib.import_module("multi_agent_wf.pipeline")


class HostParallelWorkerRegressionTests(unittest.TestCase):
    def test_worker_assignment_failure_marks_transient_errors_retryable(self) -> None:
        status = _derive_result_status(
            {
                "planned_work_item_status": {
                    "1": {
                        "status": "blocked",
                        "slot_name": "ghidra_analyst",
                        "error": "ReadError:",
                    }
                }
            },
            "",
        )

        self.assertEqual(status["status"], "worker_assignment_failed")
        self.assertTrue(bool(status.get("failure_retryable")))
        self.assertEqual(status.get("failure_category"), "transient_transport")
        self.assertEqual(status.get("failure_stage"), "workers")

    def test_stage_agent_retries_once_after_async_task_tool_misuse(self) -> None:
        pipeline_mod = _import_pipeline_with_stubs()

        call_log = []

        class FakeResult:
            output = "recovered"

            def all_messages(self):
                return []

        class FakeStageAgent:
            def run_sync(self, prompt, *, message_history=None, deps=None):
                call_log.append(
                    {
                        "prompt": str(prompt),
                        "message_history": message_history,
                        "deps": deps,
                    }
                )
                if len(call_log) == 1:
                    raise RuntimeError("UnexpectedModelBehavior: Tool 'wait_tasks' exceeded max retries count of 1")
                return FakeResult()

        stage = types.SimpleNamespace(
            name="preflight",
            agent=FakeStageAgent(),
            deps=types.SimpleNamespace(),
        )
        old_history = ["prior-message"]
        state = {}

        result = pipeline_mod._run_stage_agent_sync_with_guardrails(
            stage=stage,
            stage_prompt="Preflight prompt",
            old_history=old_history,
            state=state,
        )

        self.assertEqual(result.output, "recovered")
        self.assertEqual(len(call_log), 2)
        self.assertEqual(call_log[0]["message_history"], old_history)
        self.assertIsNone(call_log[1]["message_history"])
        self.assertIn("Async task-management tools", call_log[1]["prompt"])
        self.assertIn("Stage retry triggered", state.get("status_log", ""))

    def test_stage_agent_retries_transient_rate_limit_failure(self) -> None:
        pipeline_mod = _import_pipeline_with_stubs()

        call_count = 0
        sleep_calls = []

        class FakeResult:
            output = "recovered"

            def all_messages(self):
                return []

        class FakeStageAgent:
            def run_sync(self, prompt, *, message_history=None, deps=None):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise RuntimeError("ModelHTTPError: status_code: 429, model_name: gpt-5-mini, body: {'type': 'rate_limit_error'}")
                return FakeResult()

        stage = types.SimpleNamespace(
            name="planner",
            agent=FakeStageAgent(),
            deps=types.SimpleNamespace(),
        )
        state = {}

        with patch.object(pipeline_mod.time, "sleep", side_effect=lambda seconds: sleep_calls.append(seconds)):
            result = pipeline_mod._run_stage_agent_sync_with_guardrails(
                stage=stage,
                stage_prompt="Planner prompt",
                old_history=["prior-message"],
                state=state,
            )

        self.assertEqual(result.output, "recovered")
        self.assertEqual(call_count, 2)
        self.assertEqual(sleep_calls, [1.0])
        self.assertIn("Stage transient failure: planner attempt 1/3", state.get("status_log", ""))

    def test_stage_agent_does_not_retry_deterministic_invalid_request(self) -> None:
        pipeline_mod = _import_pipeline_with_stubs()

        call_count = 0
        sleep_calls = []

        class FakeStageAgent:
            def run_sync(self, prompt, *, message_history=None, deps=None):
                nonlocal call_count
                call_count += 1
                raise RuntimeError(
                    "ModelHTTPError: status_code: 400, model_name: gpt-5-mini, body: "
                    "{'message': \"We could not parse the JSON body of your request.\", 'type': 'invalid_request_error'}"
                )

        stage = types.SimpleNamespace(
            name="planner",
            agent=FakeStageAgent(),
            deps=types.SimpleNamespace(),
        )
        state = {}

        with patch.object(pipeline_mod.time, "sleep", side_effect=lambda seconds: sleep_calls.append(seconds)):
            with self.assertRaises(RuntimeError):
                pipeline_mod._run_stage_agent_sync_with_guardrails(
                    stage=stage,
                    stage_prompt="Planner prompt",
                    old_history=["prior-message"],
                    state=state,
                )

        self.assertEqual(call_count, 1)
        self.assertEqual(sleep_calls, [])

    def test_result_status_is_demoted_when_worker_assignment_fails(self) -> None:
        shared = {
            "validation_history": [],
            "validation_retry_count": 0,
            "validation_max_retries": 2,
            "validation_last_decision": "",
            "validation_replan_feedback": "",
            "planned_work_item_status": {
                "1": {
                    "status": "completed",
                    "slot_name": "ghidra_analyst",
                    "error": "",
                },
                "2": {
                    "status": "blocked",
                    "slot_name": "control_flow_analyst",
                    "error": "RuntimeError: Attempted to exit cancel scope in a different task than it was entered in",
                    "duration_sec": 131.2,
                },
            },
        }

        status = _derive_result_status(shared, "provisional final report")

        self.assertEqual(status["status"], "worker_assignment_failed")
        self.assertFalse(status["produced_result"])
        self.assertFalse(status["accepted_final_output"])
        self.assertIn("control_flow_analyst", status["failure_reason"])
        self.assertEqual(status["worker_assignment_summary"]["failed_assignments"], 1)

    def test_result_status_captures_failure_category_and_stage_for_analysis_error(self) -> None:
        shared = {
            "validation_history": [],
            "validation_retry_count": 0,
            "validation_max_retries": 2,
            "validation_last_decision": "",
            "validation_replan_feedback": "",
            "planned_work_item_status": {},
            "last_pipeline_error": {
                "stage_name": "planner",
                "stage_kind": "planner",
                "error_text": "ModelHTTPError: status_code: 429, model_name: gpt-5-mini",
                "category": "rate_limit",
                "retryable": True,
            },
        }

        status = _derive_result_status(shared, "", error="ModelHTTPError: status_code: 429, model_name: gpt-5-mini")

        self.assertEqual(status["status"], "analysis_error")
        self.assertEqual(status["failure_category"], "rate_limit")
        self.assertEqual(status["failure_stage"], "planner")
        self.assertTrue(status["failure_retryable"])

    def test_host_worker_executor_uses_isolated_backend_and_disables_context_manager(self) -> None:
        runtime_mod = _import_runtime_with_stubs()

        runtime_mod.AGENT_ARCHETYPE_SPECS["test_worker"] = {
            "tool_domain": "none",
            "model": "openai:gpt-5-mini",
        }
        runtime_mod.AGENT_ARCHETYPE_PROMPTS["test_worker"] = "Test worker instructions"

        created_agents = []

        def fake_create_deep_agent(**kwargs):
            created_agents.append(kwargs)
            return {"agent": "fake"}

        def fake_create_default_deps(backend=None):
            return {"backend": backend}

        class FakeBackend:
            def __init__(self, root_dir):
                self.root_dir = Path(root_dir)

        fake_runtime = types.SimpleNamespace(
            static_tools=[],
            dynamic_tools=[],
            skill_directories=[],
            deep_backend=types.SimpleNamespace(root_dir=Path("/tmp/shared-deep-backend")),
        )

        with patch.object(runtime_mod, "create_deep_agent", side_effect=fake_create_deep_agent), patch.object(
            runtime_mod,
            "create_default_deps",
            side_effect=fake_create_default_deps,
        ), patch.object(runtime_mod, "_ControlledLocalBackend", FakeBackend), patch.object(
            runtime_mod,
            "_toolsets_for_domain",
            return_value=[],
        ):
            _, deps, _, meta = runtime_mod.build_host_worker_assignment_executor(
                fake_runtime,
                stage_name="workers",
                slot_name="control_flow_analyst",
                archetype_name="test_worker",
                work_item_id="4",
                stage_model="openai:gpt-5-mini",
            )

        self.assertTrue(meta["isolated_backend"])
        self.assertIn("host_parallel_workers/workers/control_flow_analyst/4", meta["backend_root"])
        self.assertIsNot(deps["backend"], fake_runtime.deep_backend)
        self.assertFalse(created_agents[0]["context_manager"])
        self.assertTrue(str(meta["memory_dir"]).endswith("workers/control_flow_analyst/4"))

    def test_blank_worker_role_prompt_mode_omits_archetype_prompt_for_host_workers(self) -> None:
        runtime_mod = _import_runtime_with_stubs()
        runtime_mod.DEEP_WORKER_ROLE_PROMPT_MODE = "blank"

        runtime_mod.AGENT_ARCHETYPE_SPECS["test_worker"] = {
            "tool_domain": "none",
            "model": "openai:gpt-5-mini",
        }
        runtime_mod.AGENT_ARCHETYPE_PROMPTS["test_worker"] = "Test worker instructions"

        created_agents = []

        def fake_create_deep_agent(**kwargs):
            created_agents.append(kwargs)
            return {"agent": "fake"}

        def fake_create_default_deps(backend=None):
            return {"backend": backend}

        class FakeBackend:
            def __init__(self, root_dir):
                self.root_dir = Path(root_dir)

        fake_runtime = types.SimpleNamespace(
            static_tools=[],
            dynamic_tools=[],
            skill_directories=[],
            deep_backend=types.SimpleNamespace(root_dir=Path("/tmp/shared-deep-backend")),
        )

        with patch.object(runtime_mod, "create_deep_agent", side_effect=fake_create_deep_agent), patch.object(
            runtime_mod,
            "create_default_deps",
            side_effect=fake_create_default_deps,
        ), patch.object(
            runtime_mod,
            "_ControlledLocalBackend",
            FakeBackend,
        ), patch.object(
            runtime_mod,
            "_toolsets_for_domain",
            return_value=[],
        ):
            runtime_mod.build_host_worker_assignment_executor(
                fake_runtime,
                stage_name="workers",
                slot_name="control_flow_analyst",
                archetype_name="test_worker",
                work_item_id="7",
                stage_model="openai:gpt-5-mini",
            )

        instructions = str(created_agents[0]["instructions"] or "")
        self.assertNotIn("Test worker instructions", instructions)
        self.assertIn("Execution note:", instructions)

    def test_loop_local_worker_runtime_clones_mcp_toolsets(self) -> None:
        runtime_mod = _import_runtime_with_stubs()

        tool_a = runtime_mod.MCPServerStdio("python", args=["a.py"], id="ghidramcp")
        tool_b = runtime_mod.MCPServerStdio("python", args=["b.py"], id="stringmcp")
        base_runtime = runtime_mod.MultiAgentRuntime(
            pipeline_name="auto_triage",
            worker_architecture_name="balanced",
            worker_architecture=[("ghidra_analyst", 1)],
            pipeline_definition=[],
            stages=[],
            static_tool_ids=["ghidramcp", "stringmcp"],
            dynamic_tool_ids=[],
            sandbox_tool_ids=[],
            static_tools=[tool_a, tool_b],
            dynamic_tools=[],
            skill_directories=[],
            deep_backend=None,
        )

        loop_local_runtime = runtime_mod.build_loop_local_host_worker_runtime(base_runtime)

        self.assertIsNot(loop_local_runtime, base_runtime)
        self.assertEqual([tool.id for tool in loop_local_runtime.static_tools], ["ghidramcp", "stringmcp"])
        self.assertIsNot(loop_local_runtime.static_tools[0], tool_a)
        self.assertIsNot(loop_local_runtime.static_tools[1], tool_b)
        self.assertEqual(loop_local_runtime.static_tools[0].args, ["a.py"])
        self.assertEqual(loop_local_runtime.static_tools[1].args, ["b.py"])

    def test_enter_mcp_toolsets_async_preopens_and_close_releases_servers(self) -> None:
        runtime_mod = _import_runtime_with_stubs()

        tool_a = runtime_mod.MCPServerStdio("python", args=["a.py"], id="ghidramcp")
        tool_b = runtime_mod.MCPServerStdio("python", args=["b.py"], id="stringmcp")

        entered_ids = asyncio.run(runtime_mod._enter_mcp_toolsets_async([tool_a, tool_b], []))
        self.assertEqual(entered_ids, ["ghidramcp", "stringmcp"])
        self.assertTrue(tool_a.is_running())
        self.assertTrue(tool_b.is_running())
        self.assertEqual(tool_a.enter_count, 1)
        self.assertEqual(tool_b.enter_count, 1)

        asyncio.run(runtime_mod._close_mcp_toolsets_async([tool_a, tool_b], []))
        self.assertFalse(tool_a.is_running())
        self.assertFalse(tool_b.is_running())
        self.assertEqual(tool_a.exit_count, 1)
        self.assertEqual(tool_b.exit_count, 1)
        self.assertFalse(getattr(tool_a, "_runtime_helper_preentered", False))
        self.assertFalse(getattr(tool_b, "_runtime_helper_preentered", False))

    def test_shutdown_runtime_sync_skips_untracked_running_servers(self) -> None:
        runtime_mod = _import_runtime_with_stubs()

        class FailOnExitServer(runtime_mod.MCPServerStdio):
            async def __aexit__(self, *args):
                self.exit_count += 1
                raise AssertionError("shutdown should not close untracked server sessions")

        tool = FailOnExitServer("python", args=["a.py"], id="ghidramcp")
        tool._running = True
        runtime_mod._RUNTIME_SHARED_ASSETS = runtime_mod.RuntimeSharedAssets(
            manifest_path="servers.json",
            toolsets=[tool],
            static_tools=[tool],
            dynamic_tools=[],
            skill_directories=[],
            deep_backend=None,
        )

        with patch("builtins.print") as fake_print:
            runtime_mod.shutdown_runtime_sync()

        self.assertEqual(tool.exit_count, 0)
        self.assertIsNone(runtime_mod._RUNTIME_SHARED_ASSETS)
        fake_print.assert_not_called()

    def test_close_mcp_toolsets_async_suppresses_cancelled_error_from_server_exit(self) -> None:
        runtime_mod = _import_runtime_with_stubs()

        class CancelOnExitServer(runtime_mod.MCPServerStdio):
            async def __aexit__(self, *args):
                self.exit_count += 1
                raise asyncio.CancelledError("cancel scope teardown conflict")

        tool = CancelOnExitServer("python", args=["a.py"], id="ghidramcp")
        tool._running = True

        async def close_and_continue() -> int:
            await runtime_mod._close_mcp_toolsets_async([tool], [])
            await asyncio.sleep(0)
            task = asyncio.current_task()
            return task.cancelling() if task is not None else 0

        with patch("builtins.print") as fake_print:
            remaining_cancellations = asyncio.run(close_and_continue())

        self.assertEqual(tool.exit_count, 1)
        self.assertEqual(remaining_cancellations, 0)
        fake_print.assert_not_called()

    def test_serial_host_worker_archetypes_gate_only_matching_roles(self) -> None:
        pipeline_mod = _import_pipeline_with_stubs()

        assignments = [
            {
                "index": 1,
                "slot_name": "ghidra_analyst",
                "archetype_name": "ghidra_analyst",
                "work_item": {"id": "1"},
            },
            {
                "index": 2,
                "slot_name": "ghidra_analyst",
                "archetype_name": "ghidra_analyst",
                "work_item": {"id": "2"},
            },
            {
                "index": 3,
                "slot_name": "control_flow_analyst",
                "archetype_name": "control_flow_analyst",
                "work_item": {"id": "3"},
            },
        ]
        active_counts = {}
        max_active_counts = {}
        start_order = []

        async def assignment_runner(assignment):
            archetype = assignment["archetype_name"]
            work_item_id = str((assignment.get("work_item") or {}).get("id") or assignment["index"])
            active_counts[archetype] = active_counts.get(archetype, 0) + 1
            max_active_counts[archetype] = max(max_active_counts.get(archetype, 0), active_counts[archetype])
            start_order.append((work_item_id, archetype))
            await asyncio.sleep(0.01 if archetype == "ghidra_analyst" else 0.001)
            active_counts[archetype] -= 1
            return {
                "index": int(assignment["index"]),
                "work_item_id": work_item_id,
                "slot_name": str(assignment["slot_name"]),
                "archetype_name": archetype,
                "status": "ok",
            }

        results = asyncio.run(
            pipeline_mod._run_host_parallel_assignments_async(
                assignments,
                concurrency_limit=2,
                assignment_runner=assignment_runner,
                serial_archetypes=("ghidra_analyst",),
            )
        )

        self.assertEqual(sorted(results), [1, 2, 3])
        self.assertEqual(max_active_counts.get("ghidra_analyst"), 1)
        self.assertEqual(max_active_counts.get("control_flow_analyst"), 1)
        self.assertLess(start_order.index(("3", "control_flow_analyst")), start_order.index(("2", "ghidra_analyst")))

    def test_host_worker_assignment_does_not_reuse_message_history(self) -> None:
        pipeline_mod = _import_pipeline_with_stubs()

        run_calls = []

        class FakeResult:
            output = "worker ok"

            def all_messages(self):
                return ["new-history"]

            @property
            def usage(self):
                return None

        class FakeAgent:
            async def run(self, prompt, *, message_history=None, deps=None):
                run_calls.append(message_history)
                return FakeResult()

        def fake_build_executor(*args, **kwargs):
            return FakeAgent(), types.SimpleNamespace(), "openai:gpt-5-mini", {}

        async def fake_sleep(_seconds: float) -> None:
            return None

        assignment = {
            "index": 1,
            "slot_name": "ghidra_analyst",
            "archetype_name": "ghidra_analyst",
            "work_item": {"id": "1", "objective": "Inspect config decode path", "evidence_targets": []},
        }
        state = {"shared_state": {}, "allow_parent_input": False}

        with patch.object(pipeline_mod, "build_host_worker_assignment_executor", side_effect=fake_build_executor), patch.object(
            pipeline_mod,
            "_build_host_worker_prompt",
            return_value="worker prompt",
        ), patch.object(
            pipeline_mod,
            "get_role_history",
            side_effect=AssertionError("host worker assignments should not read prior message history"),
        ), patch.object(
            pipeline_mod.asyncio,
            "sleep",
            side_effect=fake_sleep,
        ):
            result = asyncio.run(
                pipeline_mod._run_host_worker_assignment(
                    runtime=object(),
                    stage_name="workers",
                    stage_kind="workers",
                    state=state,
                    user_text="Analyze sample",
                    prior_stage_outputs={},
                    assignment=assignment,
                    stage_model="openai:gpt-5-mini",
                )
            )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(run_calls, [None])

    def test_host_worker_assignment_retries_transient_failures(self) -> None:
        pipeline_mod = _import_pipeline_with_stubs()

        build_count = 0
        sleep_calls = []

        class FakeResult:
            output = "worker ok"

            def all_messages(self):
                return []

            @property
            def usage(self):
                return None

        class FakeAgent:
            def __init__(self, fail: bool):
                self.fail = fail

            async def run(self, prompt, *, message_history=None, deps=None):
                if self.fail:
                    raise RuntimeError(
                        "RemoteProtocolError: peer closed connection without sending complete message body "
                        "(incomplete chunked read)"
                    )
                return FakeResult()

        def fake_build_executor(*args, **kwargs):
            nonlocal build_count
            build_count += 1
            return FakeAgent(fail=build_count == 1), types.SimpleNamespace(), "openai:gpt-5-mini", {}

        async def fake_sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        assignment = {
            "index": 1,
            "slot_name": "ghidra_analyst",
            "archetype_name": "ghidra_analyst",
            "work_item": {"id": "1", "objective": "Inspect config decode path", "evidence_targets": []},
        }
        state = {"shared_state": {}, "allow_parent_input": False}

        with patch.object(pipeline_mod, "build_host_worker_assignment_executor", side_effect=fake_build_executor), patch.object(
            pipeline_mod,
            "_build_host_worker_prompt",
            return_value="worker prompt",
        ), patch.object(
            pipeline_mod.asyncio,
            "sleep",
            side_effect=fake_sleep,
        ):
            result = asyncio.run(
                pipeline_mod._run_host_worker_assignment(
                    runtime=object(),
                    stage_name="workers",
                    stage_kind="workers",
                    state=state,
                    user_text="Analyze sample",
                    prior_stage_outputs={},
                    assignment=assignment,
                    stage_model="openai:gpt-5-mini",
                )
            )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(build_count, 2)
        self.assertEqual(sleep_calls, [1.0])

    def test_host_worker_assignment_does_not_retry_deterministic_invalid_request(self) -> None:
        pipeline_mod = _import_pipeline_with_stubs()

        build_count = 0
        sleep_calls = []

        class FakeAgent:
            async def run(self, prompt, *, message_history=None, deps=None):
                raise RuntimeError(
                    "ModelHTTPError: status_code: 400, model_name: gpt-5-mini, body: "
                    "{'message': \"We could not parse the JSON body of your request.\", "
                    "'type': 'invalid_request_error'}"
                )

        def fake_build_executor(*args, **kwargs):
            nonlocal build_count
            build_count += 1
            return FakeAgent(), types.SimpleNamespace(), "openai:gpt-5-mini", {}

        async def fake_sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        assignment = {
            "index": 1,
            "slot_name": "ghidra_analyst",
            "archetype_name": "ghidra_analyst",
            "work_item": {"id": "1", "objective": "Inspect config decode path", "evidence_targets": []},
        }
        state = {"shared_state": {}, "allow_parent_input": False}

        with patch.object(pipeline_mod, "build_host_worker_assignment_executor", side_effect=fake_build_executor), patch.object(
            pipeline_mod,
            "_build_host_worker_prompt",
            return_value="worker prompt",
        ), patch.object(
            pipeline_mod.asyncio,
            "sleep",
            side_effect=fake_sleep,
        ):
            result = asyncio.run(
                pipeline_mod._run_host_worker_assignment(
                    runtime=object(),
                    stage_name="workers",
                    stage_kind="workers",
                    state=state,
                    user_text="Analyze sample",
                    prior_stage_outputs={},
                    assignment=assignment,
                    stage_model="openai:gpt-5-mini",
                )
            )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(build_count, 1)
        self.assertEqual(sleep_calls, [])

    def test_worker_stage_retries_only_failed_transient_assignments(self) -> None:
        pipeline_mod = _import_pipeline_with_stubs()

        assignments = [
            {
                "index": 1,
                "slot_name": "ghidra_analyst",
                "archetype_name": "ghidra_analyst",
                "work_item": {"id": "1"},
            },
            {
                "index": 2,
                "slot_name": "control_flow_analyst",
                "archetype_name": "control_flow_analyst",
                "work_item": {"id": "2"},
            },
        ]
        call_batches = []

        async def fake_enter(*_args, **_kwargs):
            return ["ghidramcp"]

        async def fake_close(*_args, **_kwargs):
            return None

        async def fake_run_host_parallel_assignments_async(batch, **_kwargs):
            indices = [int(item["index"]) for item in batch]
            call_batches.append(indices)
            if len(call_batches) == 1:
                return {
                    1: {
                        "index": 1,
                        "work_item_id": "1",
                        "slot_name": "ghidra_analyst",
                        "archetype_name": "ghidra_analyst",
                        "model": "openai:gpt-5-mini",
                        "role_key": "worker-1",
                        "history": [],
                        "output_text": "",
                        "usage": {},
                        "duration_sec": 1.0,
                        "model_duration_sec": 1.0,
                        "status": "failed",
                        "error": "ReadError:",
                        "retryable": True,
                        "error_category": "transient_transport",
                    },
                    2: {
                        "index": 2,
                        "work_item_id": "2",
                        "slot_name": "control_flow_analyst",
                        "archetype_name": "control_flow_analyst",
                        "model": "openai:gpt-5-mini",
                        "role_key": "worker-2",
                        "history": [],
                        "output_text": "ok",
                        "usage": {},
                        "duration_sec": 1.0,
                        "model_duration_sec": 1.0,
                        "status": "ok",
                    },
                }
            return {
                1: {
                    "index": 1,
                    "work_item_id": "1",
                    "slot_name": "ghidra_analyst",
                    "archetype_name": "ghidra_analyst",
                    "model": "openai:gpt-5-mini",
                    "role_key": "worker-1",
                    "history": [],
                    "output_text": "recovered",
                    "usage": {},
                    "duration_sec": 1.0,
                    "model_duration_sec": 1.0,
                    "status": "ok",
                }
            }

        runtime = types.SimpleNamespace(static_tools=[], dynamic_tools=[])
        stage = types.SimpleNamespace(
            name="workers",
            stage_kind="workers",
            architecture=[("ghidra_analyst", 1), ("control_flow_analyst", 1)],
            subagent_names=["ghidra_analyst", "control_flow_analyst"],
            model="openai:gpt-5-mini",
        )
        state = {"shared_state": {"planned_work_items": [{"id": "1"}, {"id": "2"}]}, "allow_parent_input": False}

        with patch.object(pipeline_mod, "_plan_host_worker_assignments", return_value=assignments), patch.object(
            pipeline_mod,
            "build_loop_local_host_worker_runtime",
            return_value=runtime,
        ), patch.object(
            pipeline_mod,
            "_enter_mcp_toolsets_async",
            side_effect=fake_enter,
        ), patch.object(
            pipeline_mod,
            "_close_mcp_toolsets_async",
            side_effect=fake_close,
        ), patch.object(
            pipeline_mod,
            "_run_host_parallel_assignments_async",
            side_effect=fake_run_host_parallel_assignments_async,
        ), patch.object(
            pipeline_mod,
            "_record_model_usage",
            return_value=None,
        ), patch.object(
            pipeline_mod,
            "append_tool_log_delta",
            return_value=None,
        ), patch.object(
            pipeline_mod,
            "update_validated_sample_path_from_messages",
            return_value=None,
        ), patch.object(
            pipeline_mod,
            "update_validated_sample_path",
            return_value=None,
        ):
            output = pipeline_mod._run_host_parallel_worker_stage(
                runtime=runtime,
                stage=stage,
                user_text="Analyze sample",
                prior_stage_outputs={},
                state=state,
            )

        self.assertEqual(call_batches, [[1, 2], [1]])
        self.assertIn("completed_assignments: 2", output)
        summary = state["shared_state"]["host_worker_assignment_summary"]
        self.assertEqual(summary["failed_assignments"], 0)
        self.assertEqual(summary["stage_retry_rounds_used"], 1)
        self.assertEqual(summary["stage_retry_recovered_assignments"], 1)

    def test_worker_stage_contains_all_failed_assignments_without_raising(self) -> None:
        pipeline_mod = _import_pipeline_with_stubs()

        assignments = [
            {
                "index": 1,
                "slot_name": "ghidra_analyst",
                "archetype_name": "ghidra_analyst",
                "work_item": {"id": "1"},
            },
            {
                "index": 2,
                "slot_name": "control_flow_analyst",
                "archetype_name": "control_flow_analyst",
                "work_item": {"id": "2"},
            },
        ]

        async def fake_enter(*_args, **_kwargs):
            return []

        async def fake_close(*_args, **_kwargs):
            return None

        async def fake_run_host_parallel_assignments_async(batch, **_kwargs):
            return {
                int(item["index"]): {
                    "index": int(item["index"]),
                    "work_item_id": str((item.get("work_item") or {}).get("id") or item["index"]),
                    "slot_name": str(item["slot_name"]),
                    "archetype_name": str(item["archetype_name"]),
                    "model": "openai:gpt-5-mini",
                    "role_key": f"worker-{item['index']}",
                    "history": [],
                    "output_text": "",
                    "usage": {},
                    "duration_sec": 1.0,
                    "model_duration_sec": 1.0,
                    "status": "failed",
                    "error": "ModelHTTPError: status_code: 400 invalid_request_error",
                    "retryable": False,
                    "error_category": "invalid_request",
                }
                for item in batch
            }

        runtime = types.SimpleNamespace(static_tools=[], dynamic_tools=[])
        stage = types.SimpleNamespace(
            name="workers",
            stage_kind="workers",
            architecture=[("ghidra_analyst", 1), ("control_flow_analyst", 1)],
            subagent_names=["ghidra_analyst", "control_flow_analyst"],
            model="openai:gpt-5-mini",
        )
        state = {"shared_state": {"planned_work_items": [{"id": "1"}, {"id": "2"}]}, "allow_parent_input": False}

        with patch.object(pipeline_mod, "_plan_host_worker_assignments", return_value=assignments), patch.object(
            pipeline_mod,
            "build_loop_local_host_worker_runtime",
            return_value=runtime,
        ), patch.object(
            pipeline_mod,
            "_enter_mcp_toolsets_async",
            side_effect=fake_enter,
        ), patch.object(
            pipeline_mod,
            "_close_mcp_toolsets_async",
            side_effect=fake_close,
        ), patch.object(
            pipeline_mod,
            "_run_host_parallel_assignments_async",
            side_effect=fake_run_host_parallel_assignments_async,
        ), patch.object(
            pipeline_mod,
            "_record_model_usage",
            return_value=None,
        ), patch.object(
            pipeline_mod,
            "append_tool_log_delta",
            return_value=None,
        ), patch.object(
            pipeline_mod,
            "update_validated_sample_path_from_messages",
            return_value=None,
        ), patch.object(
            pipeline_mod,
            "update_validated_sample_path",
            return_value=None,
        ):
            output = pipeline_mod._run_host_parallel_worker_stage(
                runtime=runtime,
                stage=stage,
                user_text="Analyze sample",
                prior_stage_outputs={},
                state=state,
            )

        self.assertIn("failed_assignments: 2", output)
        summary = state["shared_state"]["host_worker_assignment_summary"]
        self.assertTrue(summary["all_assignments_failed"])
        self.assertEqual(summary["failed_assignments"], 2)


if __name__ == "__main__":
    unittest.main()
