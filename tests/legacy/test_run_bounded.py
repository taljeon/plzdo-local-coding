import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from run_bounded import run, verification_command


class BoundedRunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def execute(self, code, timeout=3):
        return run([sys.executable, "-c", code], self.root,
                   self.root / "evidence", timeout)

    def test_exact_output_and_defensive_event_parsing(self):
        stdout = (b'not json\n[1]\n{"type":"item.completed",'
                  b'"item":{"type":"agent_message"}}\n'
                  b'{"type":"turn.completed","usage":{"input_tokens":7}}\n\xff')
        result = self.execute(
            f"import os; os.write(1, {stdout!r}); os.write(2, b'warning\\n')")
        self.assertEqual(result["return_code"], 0)
        self.assertFalse(result["timed_out"])
        self.assertEqual((self.root / "evidence/events.jsonl").read_bytes(), stdout)
        self.assertEqual((self.root / "evidence/stderr.log").read_bytes(), b"warning\n")
        self.assertEqual(result["reported_usage"], {"input_tokens": 7})
        self.assertEqual(result["first_model_event"]["item_type"], "agent_message")
        self.assertEqual(result["malformed_json_lines"], 2)
        self.assertEqual(json.loads((self.root / "evidence/summary.json").read_text()), result)

    def test_pipe_capture_is_byte_preserving_and_child_has_only_pipes(self):
        code = ("import os,stat; "
                "assert stat.S_ISFIFO(os.fstat(1).st_mode); "
                "assert stat.S_ISFIFO(os.fstat(2).st_mode); "
                "os.write(1, b'\\x00\\xff' + b'a' * 200000); "
                "os.write(2, b'\\xfe' + b'b' * 200000)")
        result = run([sys.executable, '-c', code], self.root, self.root / 'pipes', 3,
                     pipe_output=True)
        self.assertEqual(result['return_code'], 0)
        self.assertEqual(result['output_capture'], 'host-pipes')
        self.assertEqual((self.root / 'pipes/events.jsonl').read_bytes(), b'\x00\xff' + b'a' * 200000)
        self.assertEqual((self.root / 'pipes/stderr.log').read_bytes(), b'\xfe' + b'b' * 200000)

    def test_pipe_capture_still_enforces_deadline_and_keeps_partial_output(self):
        code = "import os,time; os.write(1,b'before timeout\\n'); time.sleep(5)"
        result = run([sys.executable, '-c', code], self.root, self.root / 'pipes', 0.15,
                     pipe_output=True)
        self.assertEqual(result['return_code'], 124)
        self.assertTrue(result['timed_out'])
        self.assertLess(result['duration_seconds'], 1)
        self.assertEqual((self.root / 'pipes/events.jsonl').read_bytes(), b'before timeout\n')

    def test_pipe_capture_preserves_event_observation(self):
        event = {'type': 'item.completed', 'item': {'type': 'agent_message'}}
        code = 'print(' + repr(json.dumps(event)) + ')'
        result = run([sys.executable, '-c', code], self.root, self.root / 'pipes', 3,
                     pipe_output=True)
        self.assertEqual(result['return_code'], 0)
        self.assertIsNotNone(result['first_model_event_observed_seconds'])
        self.assertEqual(result['first_model_event']['item_type'], 'agent_message')

    def test_failed_exit_propagates_through_owned_library_driver(self):
        engine = Path(__file__).resolve().parents[2] / "local_coding/_engine"
        driver = (
            'import json,sys;sys.path.insert(0,sys.argv[1]);from run_bounded import run;'
            'result=run([sys.executable,"-I","-S","-B","-c","raise SystemExit(7)"],'
            'sys.argv[2],sys.argv[3],3);print(json.dumps(result));raise SystemExit(result["return_code"])')
        result = subprocess.run([
            sys.executable, '-I', '-S', '-B', '-c', driver, str(engine),
            str(self.root), str(self.root / "evidence")
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(json.loads(result.stdout)["child_exit_code"], 7)

    def test_timeout_kills_child_after_parent_exits(self):
        marker = self.root / "survived"
        child = ("import signal,time,pathlib; signal.signal(signal.SIGTERM, signal.SIG_IGN);"
                 f"time.sleep(1.2); pathlib.Path({str(marker)!r}).write_text('alive')")
        parent = f"import subprocess,sys; subprocess.Popen([sys.executable,'-c',{child!r}])"
        result = self.execute(parent, timeout=0.25)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["return_code"], 124)
        self.assertEqual(result["child_exit_code"], 0)
        self.assertLess(result["duration_seconds"], 1.2)
        time.sleep(1.3)
        self.assertFalse(marker.exists())

    def test_evidence_collision_rejected_without_launch(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "events.jsonl").write_bytes(b"keep me")
        with self.assertRaises(FileExistsError):
            self.execute("raise SystemExit(0)")
        self.assertEqual((evidence / "events.jsonl").read_bytes(), b"keep me")

    def test_nonfinite_deadline_is_rejected(self):
        for timeout in (float("nan"), float("inf"), 0, -1):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.execute("raise SystemExit(0)", timeout)
        self.assertFalse((self.root / "evidence").exists())

    def test_environment_override_and_stdin_eof(self):
        code = "import os,sys,json; print(json.dumps([os.environ['BOUNDED_TEST'],sys.stdin.read()]))"
        result = run([sys.executable, "-c", code], self.root, self.root / "evidence", 3,
                     env_override={"BOUNDED_TEST": "child-only"})
        output = (self.root / "evidence/events.jsonl").read_text()
        self.assertEqual(json.loads(output), ["child-only", ""])
        self.assertEqual(result["return_code"], 0)
        self.assertEqual(result["environment_override_names"], ["BOUNDED_TEST"])

    def test_event_timing_separates_thread_and_model_output(self):
        code = ("import time; print('{\"type\":\"thread.started\"}',flush=True); time.sleep(.12); "
                "print('{\"type\":\"item.started\",\"item\":{\"type\":\"command_execution\"}}',flush=True); "
                "time.sleep(.12); print('{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\"}}')")
        result = self.execute(code)
        self.assertGreater(result["first_agent_or_tool_event_observed_seconds"],
                           result["first_stdout_observed_seconds"] + .06)
        self.assertGreater(result["first_model_event_observed_seconds"],
                           result["first_agent_or_tool_event_observed_seconds"] + .06)
        stamps = [json.loads(line) for line in
                  (self.root / "evidence/event-timestamps.jsonl").read_text().splitlines()]
        self.assertEqual(len(stamps), 3)
        self.assertEqual(sum(item["byte_length"] for item in stamps),
                         (self.root / "evidence/events.jsonl").stat().st_size)

    def test_home_override_is_rejected_before_writes(self):
        for key in ("HOME", "home", "CODEX_HOME"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                run([sys.executable, "-c", "pass"], self.root,
                    self.root / "evidence", 3, env_override={key: str(self.root)})
        self.assertFalse((self.root / "evidence").exists())

    def test_verification_failure_limit_stops_delayed_child(self):
        marker = self.root / "survived-check-failures"
        child = ("import signal,time,pathlib; signal.signal(signal.SIGTERM, signal.SIG_IGN);"
                 f"time.sleep(1.2); pathlib.Path({str(marker)!r}).write_text('alive')")
        events = [
            {"type": "item.completed", "item": {"id": str(index),
             "type": "command_execution", "exit_code": 1, "command": command}}
            for index, command in enumerate(("rg pytest .", "python3 -m pytest -q", "git diff --check"))
        ]
        code = (f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}]);"
                f"print({''.join(json.dumps(event) + chr(10) for event in events)!r},end='',flush=True);"
                "time.sleep(3)")
        result = run([sys.executable, "-c", code], self.root, self.root / "evidence", 3,
                     max_failed_verifications=2)
        self.assertEqual(result["return_code"], 125)
        self.assertEqual(result["stop_reason"], "verification-failure-limit")
        self.assertEqual(result["failed_verifications"], 2)
        self.assertFalse(result["timed_out"])
        time.sleep(1.3)
        self.assertFalse(marker.exists())

    def test_verification_command_identification(self):
        for command in ("pytest -q", "python3 -m pytest tests/test.py",
                        "/bin/zsh -lc 'cd /tmp && python3 -m pytest -q'", "git diff --check"):
            with self.subTest(command=command):
                self.assertTrue(verification_command(command))
        for command in ("rg pytest .", "rg 'git diff --check' .", "git diff --stat", "echo pytest"):
            with self.subTest(command=command):
                self.assertFalse(verification_command(command))


if __name__ == "__main__":
    unittest.main()
