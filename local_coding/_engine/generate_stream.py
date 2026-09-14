"""One profile-bound local Ollama streaming request, with bounded durable evidence.

Only a complete, normally stopped JSON object becomes response.json. Wire data
and terminal failure metadata remain separate. This process never retries.
"""
from __future__ import annotations

if __name__ == '__main__':
    raise SystemExit('INTERNAL_HELPER_REQUIRES_KERNEL')

import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request

from generate_edits import NoRedirect, response_metrics
from json_codec import strict_json
from generation_profile import detect_repetition, profile_sha256, resolve_profile

ENDPOINT = 'http://127.0.0.1:11434/api/chat'
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_PROFILE_BYTES = 65536
WIRE_LIMIT = 64 * 1024 * 1024
RESPONSE_LIMIT = 2 * 1024 * 1024
FRAME_LIMIT = 1024 * 1024
REPETITION_INTERVAL = 4096
METRIC_FIELDS = ('prompt_eval_count', 'prompt_eval_cached_count', 'eval_count', 'prompt_eval_duration',
                 'total_duration', 'load_duration', 'eval_duration')


class StreamFailure(RuntimeError):
    """Only a bounded symbolic code is exposed, never provider/body text."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code
        self.status_write_failed: bool = False
        self.evidence_close_failed: bool = False


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True,
                      allow_nan=False).encode('utf-8')


def _require(condition, code):
    if not condition:
        raise StreamFailure(code)


def _publish_exclusive(source, destination):
    """Publish a fully written marker atomically, without a hardlink or overwrite.

    Same Darwin RENAME_EXCL primitive as the frozen sequential comparison.
    A missing marker before this rename is expected; partial JSON is never public.
    """
    _require(sys.platform == 'darwin', 'ATOMIC_PUBLISH_UNSUPPORTED')
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renamex_np
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(os.fsencode(source), os.fsencode(destination), 0x4) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def validate_request(request, profile):
    _require(isinstance(request, dict), 'INVALID_REQUEST')
    _require('tools' not in request, 'TOOL_REQUEST')
    _require(not any(key in request for key in ('remote_host', 'remote_model')), 'REMOTE_REQUEST')
    expected = {key: profile[key] for key in
                ('model', 'options', 'stream', 'think', 'truncate', 'shift', 'keep_alive')}
    _require(set(request) == set(expected) | {'messages', 'format'}, 'REQUEST_PROFILE_MISMATCH')
    for key, value in expected.items():
        _require(_json_bytes(request[key]) == _json_bytes(value), 'REQUEST_PROFILE_MISMATCH')
    _require(isinstance(request['format'], dict), 'INVALID_FORMAT')
    messages = request['messages']
    _require(isinstance(messages, list) and 1 <= len(messages) <= 128, 'INVALID_MESSAGES')
    for message in messages:
        _require(isinstance(message, dict) and set(message) == {'role', 'content'}, 'INVALID_MESSAGES')
        _require(message['role'] in {'system', 'user', 'assistant'}
                 and isinstance(message['content'], str) and '\0' not in message['content'], 'INVALID_MESSAGES')
    _require(len(_json_bytes(request)) <= MAX_REQUEST_BYTES, 'REQUEST_LIMIT')
    return request


class Evidence:
    def __init__(self, response_path, started, *, thinking=False):
        self.response_path = Path(response_path)
        directory = self.response_path.parent
        _require(directory.is_dir() and directory.resolve() == directory, 'INVALID_EVIDENCE_DIRECTORY')
        self.wire_path = directory / 'wire.jsonl'
        self.status_path = directory / 'stream-status.json'
        self.progress_path = directory / 'progress.json'
        outputs = [self.response_path, self.wire_path, self.status_path, self.progress_path]
        _require(len(set(outputs)) == 4, 'OUTPUT_COLLISION')
        _require(not any(path.exists() or path.is_symlink() for path in outputs), 'OUTPUT_EXISTS')
        self.wire = self.wire_path.open('xb')
        self.wire_bytes = 0
        self.wire_limit = WIRE_LIMIT
        self.frames = 0
        self.content_bytes = 0
        self.content_chars = 0
        self.first_content = None
        self.last_content = None
        self.thinking = thinking
        self.first_activity = self.last_activity = None
        self.thinking_bytes = self.thinking_chars = 0
        self.thinking_tail = ''
        self.last_observed = started
        self.started = started
        self.last_progress_write = started
        self.progress_interval = 1
        self.progress_writes = 0
        self.profile = None
        self.profile_hash = None
        self.request_hash = None
        self.request_profile_match = False
        self.progress_identity = self.progress_raw = None
        try:
            self.write_progress(started)
        except BaseException:
            self.wire.close()
            raise

    def progress(self):
        result = {'first_content_monotonic': self.first_content,
                  'last_content_monotonic': self.last_content, 'content_chars': self.content_chars}
        if self.thinking:
            result.update(first_activity_monotonic=self.first_activity,
                          last_activity_monotonic=self.last_activity,
                          thinking_chars=self.thinking_chars, thinking_bytes=self.thinking_bytes,
                          content_bytes=self.content_bytes)
        return result

    def _remember_progress(self, raw):
        info = self.progress_path.lstat()
        self.progress_identity = (info.st_dev, info.st_ino)
        self.progress_raw = raw
        self.progress_writes += 1

    def append_wire(self, raw):
        remaining = self.wire_limit - self.wire_bytes
        kept = raw[:remaining]
        self.wire.write(kept)
        self.wire.flush()
        self.wire_bytes += len(kept)
        _require(len(raw) <= remaining, 'WIRE_LIMIT')

    def update_content(self, content, now):
        self.update_activity('', content, now)

    def update_activity(self, thinking, content, now):
        if not thinking and not content:
            return
        _require(self.thinking or not thinking, 'UNEXPECTED_THINKING')
        first_activity = self.thinking and self.first_activity is None
        if self.thinking:
            if first_activity:
                self.first_activity = now
            self.last_activity = now
            self.thinking_chars += len(thinking)
            self.thinking_bytes += len(thinking.encode('utf-8'))
        first_content = bool(content) and self.first_content is None
        if first_content:
            self.first_content = now
        if content:
            self.last_content = now
        self.content_chars += len(content)
        self.content_bytes += len(content.encode('utf-8'))
        # The first content marker must be visible immediately. Otherwise a
        # fast first token followed by a stall still looks like 600s prefill to
        # the supervisor. Only subsequent content updates are throttled.
        if not first_activity and not first_content and now - self.last_progress_write < self.progress_interval:
            return
        self.write_progress(now)

    def _verify_progress(self):
        descriptor = os.open(self.progress_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as current:
            info = os.fstat(current.fileno())
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                     and (info.st_dev, info.st_ino) == self.progress_identity
                     and current.read(4097) == self.progress_raw, 'PROGRESS_CHANGED')

    def write_progress(self, now):
        if self.progress_identity is not None:
            self._verify_progress()
        raw = _json_bytes(self.progress())
        descriptor, name = tempfile.mkstemp(prefix='.progress-', suffix='.tmp', dir=self.progress_path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            if self.progress_identity is None:
                _publish_exclusive(temporary, self.progress_path)
            else:
                self._verify_progress()
                os.replace(temporary, self.progress_path)
            self._remember_progress(raw)
            self.last_progress_write = now
        finally:
            if temporary.exists():
                temporary.unlink()

    def status(self, status, code, now):
        profile = self.profile or {}
        result = {'status': status, 'error_code': code,
                'profile_id': profile.get('id'), 'profile_sha256': self.profile_hash,
                'expected_model_digest': profile.get('model_digest'),
                'request_sha256': self.request_hash, 'request_profile_match': self.request_profile_match,
                'profile_validated': self.profile is not None,
                'wire_bytes': self.wire_bytes, 'frames': self.frames,
                'content_bytes': self.content_bytes, **self.progress(),
                'first_content_seconds': None if self.first_content is None else self.first_content - self.started,
                'duration_seconds': max(0, now - self.started), 'progress_writes': self.progress_writes,
                'retry_performed': False}
        if self.thinking:
            result['first_activity_seconds'] = (None if self.first_activity is None else
                                                self.first_activity - self.started)
        return result

    def finish(self, status, code, now):
        with self.status_path.open('xb') as output:
            output.write(_json_bytes(self.status(status, code, now)) + b'\n')

    def close(self):
        self.wire.close()


def _validate_frame(frame, model, *, thinking=False):
    _require(isinstance(frame, dict), 'INVALID_FRAME')
    _require('error' not in frame, 'SERVER_ERROR')
    actual_model = frame.get('model')
    matches = (isinstance(actual_model, str) and actual_model.isascii() and actual_model.lower() == model.lower()
               if thinking else actual_model == model)
    _require(matches, 'MODEL_MISMATCH')
    _require(frame.get('remote_host') in (None, '') and frame.get('remote_model') in (None, ''), 'REMOTE_RESPONSE')
    _require(not frame.get('tool_calls'), 'TOOL_RESPONSE')
    _require(type(frame.get('done')) is bool, 'INVALID_FRAME')
    message = frame.get('message')
    _require(isinstance(message, dict), 'INVALID_MESSAGE')
    _require(not message.get('tool_calls'), 'TOOL_RESPONSE')
    _require('tool_calls' not in message or isinstance(message['tool_calls'], list), 'INVALID_MESSAGE')
    _require('tool_calls' not in frame or isinstance(frame['tool_calls'], list), 'INVALID_FRAME')
    _require(set(message) <= {'role', 'content', 'thinking', 'tool_calls'}
             and message.get('role') == 'assistant'
             and isinstance(message.get('content', '' if thinking else None), str), 'INVALID_MESSAGE')
    if thinking:
        _require(isinstance(message.get('thinking', ''), str), 'INVALID_MESSAGE')
    else:
        _require(message.get('thinking') in (None, ''), 'UNEXPECTED_THINKING')
    if frame['done']:
        _require(frame.get('done_reason') == 'stop', 'STOP_REASON')
    else:
        _require(frame.get('done_reason') in (None, ''), 'INVALID_FRAME')
    return message.get('content', '')


def _check_activity(evidence, now, profile):
    try:
        valid = type(now) in (int, float) and math.isfinite(now) and now >= evidence.last_observed
    except OverflowError:
        valid = False
    _require(valid, 'CLOCK_INVALID')
    evidence.last_observed = now
    _require(now - evidence.started < profile['generation_deadline'], 'GENERATION_DEADLINE')
    first = evidence.first_activity is None
    elapsed = now - (evidence.started if first else evidence.last_activity)
    timeout = profile['first_content_timeout'] if first else profile['content_idle_timeout']
    _require(elapsed < timeout, 'FIRST_ACTIVITY_STALL' if first else 'ACTIVITY_STALL')


def consume_frames(lines, profile, evidence, *, clock=time.monotonic, repetition_fn=detect_repetition):
    """Pure iterable seam around bounded evidence; no network or model calls."""
    chunks, last_check, final = [], 0, None
    thinking_checked = 0
    thinking_enabled = profile['think'] is True
    for raw in lines:
        _require(isinstance(raw, bytes), 'INVALID_WIRE')
        evidence.append_wire(raw)
        _require(len(raw) <= profile['frame_limit'], 'FRAME_LIMIT')
        now = clock()
        if thinking_enabled:
            _check_activity(evidence, now, profile)
        else:
            _require(now - evidence.started <= profile['generation_deadline'], 'GENERATION_DEADLINE')
        if not raw.strip():
            continue
        _require(final is None, 'AFTER_DONE')
        try:
            text = raw.decode('utf-8', errors='strict')
        except UnicodeDecodeError as exc:
            raise StreamFailure('INVALID_UTF8') from exc
        try:
            frame = strict_json(text)
        except (ValueError, TypeError) as exc:
            raise StreamFailure('INVALID_FRAME_JSON') from exc
        content = _validate_frame(frame, profile['model'], thinking=thinking_enabled)
        evidence.frames += 1
        thinking = frame['message'].get('thinking', '') if thinking_enabled else ''
        try:
            if thinking_enabled:
                _require(evidence.thinking_bytes + len(thinking.encode('utf-8')) <= profile['thinking_limit'],
                         'THINKING_LIMIT')
                _require(evidence.content_bytes + len(content.encode('utf-8')) <= profile['response_limit'],
                         'RESPONSE_LIMIT')
                evidence.update_activity(thinking, content, now)
            else:
                evidence.update_content(content, now)
        except UnicodeError as exc:
            raise StreamFailure('INVALID_CONTENT_UNICODE') from exc
        _require(evidence.content_bytes <= profile['response_limit'], 'RESPONSE_LIMIT')
        # Thinking retains only the same bounded repetition tail used by v3.
        # Visit each exact 4096-character boundary even across uneven frames.
        offset = 0
        while offset < len(thinking):
            size = min(len(thinking) - offset, REPETITION_INTERVAL - thinking_checked % REPETITION_INTERVAL)
            evidence.thinking_tail = (evidence.thinking_tail + thinking[offset:offset + size])[
                -profile['repetition_max_unit'] * profile['repetition_cycles']:]
            thinking_checked += size
            offset += size
            if thinking_checked % REPETITION_INTERVAL == 0 and repetition_fn(evidence.thinking_tail, profile):
                raise StreamFailure('REPETITION_DETECTED')
        chunks.append(content)
        if evidence.content_chars - last_check >= REPETITION_INTERVAL:
            observed = ''.join(chunks)
            while evidence.content_chars - last_check >= REPETITION_INTERVAL:
                last_check += REPETITION_INTERVAL
                if repetition_fn(observed[:last_check], profile):
                    raise StreamFailure('REPETITION_DETECTED')
        if frame['done']:
            final = frame
    _require(final is not None, 'MISSING_DONE')
    content = ''.join(chunks)
    try:
        payload = strict_json(content)
    except (ValueError, TypeError) as exc:
        raise StreamFailure('INVALID_CONTENT_JSON') from exc
    _require(isinstance(payload, dict), 'INVALID_CONTENT_OBJECT')
    merged = {**final, 'message': {'role': 'assistant', 'content': content}}
    if thinking_enabled:
        merged = {key: final[key] for key in ('model', 'done', 'done_reason')}
        merged.update({key: final[key] for key in METRIC_FIELDS
                       if type(final.get(key)) is int and 0 <= final[key] <= 2 ** 63 - 1})
        merged['message'] = {'role': 'assistant', 'content': content}
    try:
        merged_bytes = _json_bytes(merged)
    except UnicodeError as exc:
        raise StreamFailure('INVALID_CONTENT_UNICODE') from exc
    _require(len(merged_bytes) <= profile['response_limit'], 'RESPONSE_LIMIT')
    return merged, merged_bytes


def _http_lines(response, frame_limit):
    while True:
        raw = response.readline(frame_limit + 1)
        if not raw:
            return
        yield raw


def _metrics(merged, merged_bytes, evidence, profile):
    safe = {'model': profile['model'], 'done_reason': 'stop'}
    for key in METRIC_FIELDS:
        value = merged.get(key)
        safe[key] = value if type(value) is int and 0 <= value <= 2 ** 63 - 1 else None
    result = response_metrics(safe, len(merged_bytes))
    first = None if evidence.first_content is None else evidence.first_content - evidence.started
    result.update({'ttft_seconds': first, 'first_content_seconds': first,
                   'ttft_measurement': 'streaming-first-nonempty-content-observed',
                   'generation_profile_id': profile['id'], 'generation_profile_sha256': evidence.profile_hash,
                   'streaming': True, 'request_profile_match': True, 'wire_bytes': evidence.wire_bytes,
                   'stream_frames': evidence.frames})
    if evidence.thinking:
        result.update(first_activity_seconds=None if evidence.first_activity is None else
                      evidence.first_activity - evidence.started,
                      thinking_chars=evidence.thinking_chars, thinking_bytes=evidence.thinking_bytes,
                      activity_timeout_semantics=profile['activity_timeout_semantics'])
    return result


def _record_failure(evidence, failure, clock):
    """Preserve the primary error when immutable terminal evidence cannot be written."""
    if not failure.status_write_failed:
        try:
            evidence.finish('failed', failure.code, clock())
        except Exception:
            # A collision is not permission to replace an existing record. The
            # parent receives this marker through its bounded stdout pipe.
            failure.status_write_failed = True
    return failure


def run_generation(profile, request, response_path, *, opener=None, clock=time.monotonic,
                   repetition_fn=detect_repetition):
    """Run one validated request, or raise a symbolic failure after terminal evidence."""
    normalized, profile_error = None, None
    try:
        normalized = resolve_profile(profile)
    except (ValueError, TypeError, KeyError) as exc:
        profile_error = exc
    evidence = Evidence(Path(response_path), clock(), thinking=normalized is not None and normalized['think'] is True)
    failure = None
    try:
        if profile_error is not None:
            raise StreamFailure('INVALID_PROFILE') from profile_error
        expected_hash = profile_sha256(normalized)
        evidence.profile, evidence.profile_hash = normalized, expected_hash
        evidence.wire_limit = normalized['wire_limit']
        evidence.progress_interval = normalized['progress_interval']
        validate_request(request, normalized)
        evidence.request_profile_match = True
        request_bytes = _json_bytes(request)
        evidence.request_hash = hashlib.sha256(request_bytes).hexdigest()
        if opener is None:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        http_request = urllib.request.Request(ENDPOINT, data=request_bytes,
                                              headers={'Content-Type': 'application/json'})
        with opener.open(http_request, timeout=normalized['first_content_timeout']) as response:
            merged, merged_bytes = consume_frames(_http_lines(response, normalized['frame_limit']), normalized,
                                                   evidence, clock=clock, repetition_fn=repetition_fn)
        with evidence.response_path.open('xb') as output:
            output.write(merged_bytes)
        metrics = _metrics(merged, merged_bytes, evidence, normalized)
        try:
            evidence.finish('complete', None, clock())
        except Exception as exc:
            failure = StreamFailure('STREAM_IO_OR_CONTRACT_ERROR')
            failure.status_write_failed = True
            raise failure from exc
        return metrics
    except StreamFailure as exc:
        failure = _record_failure(evidence, exc, clock)
        raise
    except (TimeoutError, socket.timeout) as exc:
        failure = _record_failure(evidence, StreamFailure('HTTP_TIMEOUT'), clock)
        raise failure from exc
    except urllib.error.URLError as exc:
        code = 'HTTP_TIMEOUT' if isinstance(exc.reason, (TimeoutError, socket.timeout)) else 'HTTP_ERROR'
        failure = _record_failure(evidence, StreamFailure(code), clock)
        raise failure from exc
    except KeyboardInterrupt as exc:
        failure = _record_failure(evidence, StreamFailure('INTERRUPTED'), clock)
        raise failure from exc
    except Exception as exc:
        failure = _record_failure(evidence, StreamFailure('STREAM_IO_OR_CONTRACT_ERROR'), clock)
        raise failure from exc
    finally:
        try:
            evidence.close()
        except Exception as exc:
            if failure is None:
                failure = StreamFailure('STREAM_IO_OR_CONTRACT_ERROR')
                failure.evidence_close_failed = True
                # Terminal status may already be complete; never overwrite it.
                # The parent's owned stdout receipt makes this a hard failure.
                raise failure from exc
            failure.evidence_close_failed = True


def _read_json(path, limit):
    _require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit, 'INPUT_FILE_LIMIT')
    with path.open('rb') as source:
        raw = source.read(limit + 1)
    _require(len(raw) <= limit, 'INPUT_FILE_LIMIT')
    try:
        return strict_json(raw.decode('utf-8', errors='strict'))
    except UnicodeError as exc:
        raise StreamFailure('INVALID_INPUT_UTF8') from exc
    except ValueError as exc:
        raise StreamFailure('INVALID_INPUT_JSON') from exc


def _worker_main(argv=None):
    """Internal fixed worker entry; direct script execution is unsupported."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('request', type=Path)
    parser.add_argument('response', type=Path)
    args = parser.parse_args(argv)
    try:
        profile = _read_json(args.profile, MAX_PROFILE_BYTES)
        request = _read_json(args.request, MAX_REQUEST_BYTES)
        metrics = run_generation(profile, request, args.response.absolute())
    except StreamFailure as exc:
        receipt = {'status': 'failed', 'error_code': exc.code}
        if exc.status_write_failed:
            receipt['status_write_failed'] = True
        if exc.evidence_close_failed:
            receipt['evidence_close_failed'] = True
        print(json.dumps(receipt), flush=True)
        return 1
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({'status': 'failed', 'error_code': 'PREFLIGHT_IO_ERROR'}), flush=True)
        return 1
    print(json.dumps(metrics, allow_nan=False), flush=True)
    return 0

