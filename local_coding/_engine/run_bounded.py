#!/usr/bin/env python3
"""Run one argv with a deadline and byte-preserving, non-overwriting evidence."""

if __name__ == '__main__':
    raise SystemExit('INTERNAL_HELPER_REQUIRES_KERNEL')

from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import shlex
import signal
import selectors
import subprocess
import time


def group_exists(pid):
    """Keep tracking present or unproven groups; only ESRCH proves absence."""
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Darwin can return EPERM while the last member exits. Keep the
        # existing bounded reap/observation loop active; this is not absence.
        return True


def terminate_group(process, grace=0.3):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        process.poll()
        if not group_exists(process.pid):
            break
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        except PermissionError:
            # Darwin may transiently deny signaling an exiting group. This is
            # not absence; bounded reap/group observation below decides cleanup.
            pass
        if sig == signal.SIGTERM:
            end = time.monotonic() + grace
            while time.monotonic() < end:
                process.poll()  # Reap the parent, but keep tracking its group.
                if not group_exists(process.pid):
                    break
                time.sleep(0.02)
    reap_deadline = time.monotonic() + 5
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        return False
    while group_exists(process.pid):
        remaining = reap_deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.02, remaining))
    return True


def process_cleanup_receipt(process):
    """Observe only the process group this runner created, never a child-tree claim."""
    receipt = {'schema': 'plzdo.engine-cleanup.v1', 'completed': False, 'passed': False,
               'owned': process is not None, 'started': process is not None,
               'scope': 'initial-posix-process-group',
               'detached_descendants_verified': False}
    if process is None:
        # Popen did not return a created process; a failed spawn is not ownership.
        receipt.update(completed=True, passed=True, process_reaped=None, group_absent=None)
        return receipt
    receipt['pid'] = process.pid
    try:
        reaped = process.poll() is not None
        absent = not group_exists(process.pid)
        receipt.update(process_reaped=reaped, group_absent=absent,
                       completed=reaped and absent, passed=reaped and absent)
    except (OSError, ValueError) as exc:
        receipt['error_type'] = type(exc).__name__
    return receipt


def inspect_events(path):
    first_model_event, usage, malformed = None, None, 0
    with path.open("rb") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                malformed += 1
                continue
            if not isinstance(event, dict):
                continue
            item = event.get("item")
            item_type = item.get("type") if isinstance(item, dict) else None
            event_type = event.get("type")
            if first_model_event is None and (
                item_type == "agent_message"
                or event_type in ("response.created", "response.output_text.delta")
            ):
                first_model_event = {"type": event_type, "item_type": item_type}
            if isinstance(event.get("usage"), dict):
                usage = event["usage"]
    return first_model_event, usage, malformed


def verification_command(command, depth=0):
    """Recognize direct pytest/git checks, not searches that mention their names."""
    if not isinstance(command, str) or depth > 3:
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        segments, current = [], []
        for token in lexer:
            if token and all(char in ";&|" for char in token):
                segments.append(current)
                current = []
            else:
                current.append(token)
        segments.append(current)
    except ValueError:
        return False
    for args in segments:
        while args and "=" in args[0] and not args[0].startswith("/"):
            args = args[1:]
        if not args:
            continue
        executable = Path(args[0]).name
        if executable in ("sh", "bash", "zsh") and len(args) > 2 and args[1] in ("-c", "-lc", "-ic"):
            if verification_command(args[2], depth + 1):
                return True
        if executable == "pytest" or (
            executable.startswith("python") and any(
                args[index:index + 2] == ["-m", "pytest"] for index in range(1, len(args))
            )
        ) or (executable == "git" and args[1:2] == ["diff"] and "--check" in args[2:]):
            return True
    return False


class EventObserver:
    """Timestamp completed lines when polled, without changing the raw stream."""

    def __init__(self, reader, sidecar):
        self.reader, self.sidecar = reader, sidecar
        self.pending, self.offset = b"", 0
        self.first_model, self.first_agent_or_tool = None, None
        self.failed_verifications = 0
        self.completed_verification_ids = set()

    def poll(self, elapsed, final=False):
        self.pending += self.reader.read()
        lines = self.pending.split(b"\n")
        self.pending = lines.pop()
        records = [(line, len(line) + 1) for line in lines]
        if final and self.pending:
            records.append((self.pending, len(self.pending)))
            self.pending = b""
        for line, length in records:
            try:
                event = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                event = None
            item = event.get("item") if isinstance(event, dict) else None
            item_type = item.get("type") if isinstance(item, dict) else None
            event_type = event.get("type") if isinstance(event, dict) else None
            if (event_type == "item.completed" and item_type == "command_execution"
                    and type(item.get("exit_code")) is int and item["exit_code"] != 0
                    and verification_command(item.get("command"))):
                item_id = item.get("id")
                if not isinstance(item_id, str) or item_id not in self.completed_verification_ids:
                    self.failed_verifications += 1
                    if isinstance(item_id, str):
                        self.completed_verification_ids.add(item_id)
            model = item_type == "agent_message" or event_type in (
                "response.created", "response.output_text.delta")
            tool = item_type in ("command_execution", "mcp_tool_call", "web_search", "file_change")
            if model and self.first_model is None:
                self.first_model = elapsed
            if (model or tool) and self.first_agent_or_tool is None:
                self.first_agent_or_tool = elapsed
            self.sidecar.write(json.dumps({
                "byte_offset": self.offset, "byte_length": length,
                "observed_seconds": elapsed, "type": event_type, "item_type": item_type,
            }) + "\n")
            self.offset += length
        self.sidecar.flush()


def run(argv, cwd, evidence_dir, timeout_seconds, env_override=None,
        max_failed_verifications=None, env_allowlist=None, pipe_output=False,
        stop_check=None):
    if not argv or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("argv and a positive timeout are required")
    if max_failed_verifications is not None and (
        type(max_failed_verifications) is not int or max_failed_verifications < 1
    ):
        raise ValueError("max_failed_verifications must be a positive integer")
    cwd = Path(cwd).resolve(strict=True)
    if not cwd.is_dir():
        raise ValueError("cwd must be a directory")
    overrides = dict(env_override or {})
    if {"HOME", "home", "CODEX_HOME"}.intersection(overrides):
        raise ValueError("HOME and CODEX_HOME overrides are not allowed")
    if any(not isinstance(key, str) or not isinstance(value, str)
           or "=" in key or "\0" in key or "\0" in value
           for key, value in overrides.items()):
        raise ValueError("environment overrides must be valid string pairs")
    if type(pipe_output) is not bool:
        raise ValueError("pipe_output must be boolean")
    if stop_check is not None and not callable(stop_check):
        raise ValueError("stop_check must be a trusted callable")
    child_env = (os.environ.copy() if env_allowlist is None else
                 {key: value for key, value in os.environ.items() if key in env_allowlist})
    child_env.update(overrides)
    evidence = Path(evidence_dir)
    evidence.mkdir(parents=True, exist_ok=False)
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    timed_out, first_output, error, process = False, None, None, None
    stop_reason = "process-exited"
    supervisor_stop = False
    stdout_path = evidence / "events.jsonl"
    with (stdout_path.open("xb") as out, (evidence / "stderr.log").open("xb") as err,
          stdout_path.open("rb") as reader,
          (evidence / "event-timestamps.jsonl").open("x", encoding="utf-8") as timestamps):
        observer = EventObserver(reader, timestamps)
        pipes = selectors.DefaultSelector()

        def drain_pipes():
            # A bounded nonblocking drain prevents output floods from starving
            # the process deadline. Only this host writes the evidence files.
            budget = 4 * 1024 * 1024
            while budget > 0:
                ready = pipes.select(timeout=0)
                if not ready:
                    break
                for key, _ in ready:
                    try:
                        chunk = os.read(key.fd, min(65536, budget))
                    except BlockingIOError:
                        continue
                    if chunk:
                        key.data.write(chunk)
                        budget -= len(chunk)
                    else:
                        pipes.unregister(key.fileobj)
                        key.fileobj.close()
                    if budget <= 0:
                        break
            out.flush()
            err.flush()

        try:
            process = subprocess.Popen(argv, cwd=cwd,
                                       stdout=subprocess.PIPE if pipe_output else out,
                                       stderr=subprocess.PIPE if pipe_output else err,
                                       stdin=subprocess.DEVNULL, env=child_env,
                                       shell=False, start_new_session=True)
            if pipe_output:
                for stream, target in ((process.stdout, out), (process.stderr, err)):
                    os.set_blocking(stream.fileno(), False)
                    pipes.register(stream, selectors.EVENT_READ, target)
            while True:
                elapsed = time.monotonic() - started
                drain_pipes()
                observer.poll(elapsed)
                if first_output is None and stdout_path.stat().st_size:
                    first_output = elapsed
                if (max_failed_verifications is not None
                        and observer.failed_verifications >= max_failed_verifications):
                    stop_reason = "verification-failure-limit"
                    terminate_group(process)
                    break
                exited = process.poll() is not None
                if exited and not group_exists(process.pid):
                    break
                if stop_check is not None:
                    try:
                        requested_stop = stop_check()
                        if requested_stop is not None and (
                            not isinstance(requested_stop, str) or not requested_stop
                            or len(requested_stop) > 100
                            or not all(c.isascii() and (c.isalnum() or c in "-_") for c in requested_stop)
                        ):
                            requested_stop = "supervision-error"
                    except Exception:
                        requested_stop = "supervision-error"
                    if requested_stop:
                        supervisor_stop = True
                        stop_reason = requested_stop
                        terminate_group(process)
                        break
                if elapsed >= timeout_seconds:
                    timed_out = True
                    stop_reason = "timeout"
                    terminate_group(process)
                    break
                time.sleep(min(0.02, timeout_seconds - elapsed))
        except OSError as exc:
            error = str(exc)
            stop_reason = "execution-error"
            if process is not None:
                terminate_group(process)
        except BaseException:
            if process is not None:
                terminate_group(process)
            raise
        finally:
            drain_pipes()
            for key in list(pipes.get_map().values()):
                pipes.unregister(key.fileobj)
                key.fileobj.close()
            pipes.close()
        observer.poll(time.monotonic() - started, final=True)
    duration = time.monotonic() - started
    model_event, usage, malformed = inspect_events(stdout_path)
    child_exit = process.returncode if process is not None else None
    return_code = (126 if supervisor_stop else
                   125 if stop_reason == "verification-failure-limit" else
                   (124 if timed_out else (127 if error else child_exit)))
    if return_code is not None and return_code < 0:
        return_code = 128 - return_code
    cleanup = process_cleanup_receipt(process)
    if cleanup['passed'] is not True and return_code in (None, 0):
        return_code = 126
    summary = {
        "argv": argv, "cwd": str(cwd), "started_at": started_at,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration, "timeout_seconds": timeout_seconds,
        "timed_out": timed_out, "child_exit_code": child_exit,
        "return_code": return_code, "error": error,
        "stop_reason": stop_reason, "max_failed_verifications": max_failed_verifications,
        "supervision_enabled": stop_check is not None, "supervisor_stop": supervisor_stop,
        "failed_verifications": observer.failed_verifications,
        "first_stdout_observed_seconds": first_output,
        "first_model_event_observed_seconds": observer.first_model,
        "first_agent_or_tool_event_observed_seconds": observer.first_agent_or_tool,
        "first_model_event": model_event, "reported_usage": usage,
        "environment_override_names": sorted(overrides), "stdin": "DEVNULL",
        "output_capture": "host-pipes" if pipe_output else "direct-files",
        "cleanup": cleanup,
        "malformed_json_lines": malformed,
        "metric_limitations": [
            "First stdout is observed by 20ms polling; it is not model TTFT.",
            "Event timestamps record completed-line observation, including child buffering; not TTFT.",
            "Event identity and usage are untrusted child reports, not verified metrics.",
            "Deadline covers the initial POSIX process group, not descendants that detach.",
            "Failure limit uses reported completed pytest/git-diff checks; hidden/internal retries are not observable.",
            "Timeout cleanup may extend elapsed time by the termination grace period.",
        ],
    }
    with (evidence / "summary.json").open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return summary

