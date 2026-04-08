import threading
import time
import unittest

from Testing.harness.experiment_sweep import _execute_child_run_specs


class ExperimentSweepConcurrencyTests(unittest.TestCase):
    def test_child_specs_can_overlap_when_concurrency_is_enabled(self) -> None:
        active = 0
        max_active = 0
        completed: list[str] = []
        lock = threading.Lock()

        def fake_runner(argv, **kwargs):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return {"ok": True, "returncode": 0, "stdout": "", "stderr": ""}

        specs = [
            {"cmd": ["run", "r1"], "stream_output": False, "stream_prefix": "", "stream_heartbeat_sec": 30},
            {"cmd": ["run", "r2"], "stream_output": False, "stream_prefix": "", "stream_heartbeat_sec": 30},
            {"cmd": ["run", "r3"], "stream_output": False, "stream_prefix": "", "stream_heartbeat_sec": 30},
        ]

        _execute_child_run_specs(
            specs,
            max_concurrent=3,
            runner=fake_runner,
            on_complete=lambda spec, completed_result: completed.append(spec["cmd"][1]) or True,
        )

        self.assertGreaterEqual(max_active, 2)
        self.assertCountEqual(completed, ["r1", "r2", "r3"])

    def test_stops_launching_new_specs_after_completion_requests_stop(self) -> None:
        launched: list[str] = []
        completed: list[str] = []

        def fake_runner(argv, **kwargs):
            label = str(argv[1])
            if label == "stop":
                time.sleep(0.02)
            else:
                time.sleep(0.08)
            return {"ok": True, "returncode": 0, "stdout": "", "stderr": ""}

        specs = [
            {"cmd": ["run", "keep"], "stream_output": False, "stream_prefix": "", "stream_heartbeat_sec": 30},
            {"cmd": ["run", "stop"], "stream_output": False, "stream_prefix": "", "stream_heartbeat_sec": 30},
            {"cmd": ["run", "late"], "stream_output": False, "stream_prefix": "", "stream_heartbeat_sec": 30},
        ]

        def on_launch(spec):
            launched.append(spec["cmd"][1])

        def on_complete(spec, completed_result):
            completed.append(spec["cmd"][1])
            return spec["cmd"][1] != "stop"

        _execute_child_run_specs(
            specs,
            max_concurrent=2,
            runner=fake_runner,
            on_launch=on_launch,
            on_complete=on_complete,
        )

        self.assertEqual(launched, ["keep", "stop"])
        self.assertIn("stop", completed)
        self.assertIn("keep", completed)
        self.assertNotIn("late", completed)


if __name__ == "__main__":
    unittest.main()
