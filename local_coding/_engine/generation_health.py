"""Native VM summaries and bounded generation supervision, without a memory cap.

Admission checks current system health, not the unmeasured model's future peak.
Compression alone never stops generation. No private process data is collected.
V1 requires physical free pages; V2 uses free plus file-backed pages as estimated
reclaimable headroom, never as guaranteed immediately available RAM or model fit.
"""
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from collections import deque
from decimal import Decimal

from json_codec import strict_json
from generation_profile import profile_sha256, resolve_profile

MAX_TRACE_RECORDS = 2048
MAX_TRACE_BYTES = 2 * 1024 * 1024
PROGRESS_READ_ATTEMPTS = 3
_HUI_PROGRESS_FIELDS = {'first_content_monotonic', 'last_content_monotonic', 'content_chars',
                        'first_activity_monotonic', 'last_activity_monotonic',
                        'thinking_chars', 'thinking_bytes', 'content_bytes'}
_FIELDS = ('pressure', 'free_bytes', 'file_backed_bytes', 'compressed_physical_bytes',
           'compressed_logical_bytes', 'swap_used_bytes', 'swap_out_bytes', 'page_out_bytes')
_OPTIONAL_FIELDS = ('page_size', 'free_pages', 'file_backed_pages', 'compressed_physical_pages',
                    'compressed_logical_pages', 'swap_out_pages', 'page_out_pages')


class TelemetryError(ValueError):
    """Native telemetry is absent, malformed or cannot be trusted as numeric data."""


class CriticalPressureObserved(TelemetryError):
    """A valid critical pressure reading requires no other telemetry to stop."""
    def __init__(self):
        self.partial = {'pressure': 4}
        super().__init__('Native critical memory pressure observed')


class HealthAdmissionError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class _ReplacedProgress(ValueError):
    """An opened, now-unlinked marker has a distinct safe replacement to reread."""


def _finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def _validated_sample(raw):
    if type(raw) is not dict or any(key not in raw for key in _FIELDS):
        if type(raw) is dict and type(raw.get('pressure')) is int and raw['pressure'] == 4:
            raise CriticalPressureObserved()
        raise TelemetryError('Required memory telemetry fields are missing')
    result = {}
    for key in _FIELDS + _OPTIONAL_FIELDS:
        if key in raw:
            if type(raw[key]) is not int or raw[key] < 0:
                if type(raw.get('pressure')) is int and raw['pressure'] == 4:
                    raise CriticalPressureObserved()
                raise TelemetryError('Memory telemetry fields must be nonnegative integers')
            result[key] = raw[key]
    if result['pressure'] not in (1, 2, 4):
        raise TelemetryError('Unknown native memory pressure level')
    return result


def parse_system_telemetry(pressure_text, swap_text, vm_text):
    """Parse only public aggregate fields from macOS sysctl and vm_stat."""
    if any(type(text) is not str or len(text) > 65536 for text in (pressure_text, swap_text, vm_text)):
        raise TelemetryError('Invalid native memory telemetry text')
    try:
        pressure = int(pressure_text.strip())
        page_match = re.search(r'page size of (\d+) bytes', vm_text)
        if page_match is None:
            raise TelemetryError('VM page size is unavailable')
        page_size = int(page_match.group(1))
        if page_size <= 0 or page_size > 1024 * 1024:
            raise TelemetryError('VM page size is invalid')
        result = {'pressure': pressure, 'page_size': page_size}
        labels = {
            'free': 'Pages free', 'file_backed': 'File-backed pages',
            'compressed_physical': 'Pages occupied by compressor',
            'compressed_logical': 'Pages stored in compressor',
            'swap_out': 'Swapouts', 'page_out': 'Pageouts',
        }
        for field, label in labels.items():
            match = re.search(r'^' + re.escape(label) + r':\s*(\d+)\.?\s*$', vm_text, re.MULTILINE)
            if match is None:
                raise TelemetryError('Required VM counter is unavailable: ' + label)
            pages = int(match.group(1))
            result[field + '_pages'] = pages
            result[field + '_bytes'] = pages * page_size
        used = re.search(r'\bused\s*=\s*(\d+(?:\.\d+)?)\s*([KMGT]?)(?:i?B)?\b', swap_text)
        if used is None:
            raise TelemetryError('Swap usage is unavailable')
        result['swap_used_bytes'] = int(Decimal(used.group(1)) * (1024 ** ('KMGT'.find(used.group(2)) + 1)
                                                        if used.group(2) else 1))
        return _validated_sample(result)
    except (ValueError, ArithmeticError) as exc:
        if isinstance(exc, TelemetryError):
            raise
        raise TelemetryError('Malformed native memory telemetry') from exc


def sample_system():
    """Read three fixed native aggregate commands, each with a two-second bound."""
    outputs = []
    commands = [
        ['/usr/sbin/sysctl', '-n', 'kern.memorystatus_vm_pressure_level'],
        ['/usr/sbin/sysctl', '-n', 'vm.swapusage'],
        ['/usr/bin/vm_stat'],
    ]
    try:
        for index, command in enumerate(commands):
            completed = subprocess.run(command, capture_output=True, text=True, check=True, timeout=2,
                                       env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
            outputs.append(completed.stdout)
            if index == 0:
                try:
                    pressure = int(completed.stdout.strip())
                except ValueError as exc:
                    raise TelemetryError('Native pressure telemetry is malformed') from exc
                if pressure not in (1, 2, 4):
                    raise TelemetryError('Unknown native memory pressure level')
                if pressure == 4:
                    raise CriticalPressureObserved()
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise TelemetryError('Native memory telemetry unavailable') from exc
    return parse_system_telemetry(*outputs)


class GenerationHealth:
    def __init__(self, profile, progress_path, trace_path, sampler=None, clock=time.monotonic):
        self.profile = resolve_profile(profile)
        self.progress_path = Path(progress_path).absolute()
        self.trace_path = Path(trace_path).absolute()
        for path in (self.progress_path, self.trace_path):
            if path.resolve() != path or not path.parent.is_dir():
                raise ValueError('Generation telemetry paths must be canonical with existing parents')
        if self.progress_path == self.trace_path:
            raise ValueError('Progress and trace paths must differ')
        self.sampler, self.clock = sampler or sample_system, clock
        self._trace_fd = None
        self._trace_records, self._trace_bytes, self._trace_truncated = 0, 0, False
        self._started, self._last_sample_at = None, None
        self._baseline, self._last_sample = None, None
        self._failures, self._sample_count = 0, 0
        self._warning_since, self._warning_base = None, None
        self._growth_streak, self._max_swap_growth = 0, 0
        self._first_content, self._last_content, self._content_chars = None, None, 0
        self._first_activity = self._last_activity = None
        self._thinking_chars = self._thinking_bytes = self._content_bytes = 0
        self._progress_seen = False
        self._progress_stale_reads = self._progress_reopens = 0
        self._progress_read_error = None
        self._admitted, self._stop_reason, self._closed = False, None, False
        self._latest_sample_complete = False
        self._sample_ordinal = 0
        self._warning_history = (deque(maxlen=self.profile['burst_window'] // self.profile['memory_sample_interval'] + 1)
                                 if self.profile.get('burst_guard_mode') == 'consecutive-or-rolling-net' else None)
        self._burst_detail = None
        self._deterioration_trigger = None

    def _now(self):
        value = self.clock()
        if not _finite(value):
            raise ValueError('Generation monitor clock must be finite monotonic seconds')
        return value

    def _write_trace(self, event, now, **fields):
        row = {'event': event, 'monotonic_seconds': now, **fields}
        encoded = (json.dumps(row, allow_nan=False, separators=(',', ':')) + '\n').encode()
        if self._trace_records >= MAX_TRACE_RECORDS or self._trace_bytes + len(encoded) > MAX_TRACE_BYTES:
            self._trace_truncated = True
            return
        view = memoryview(encoded)
        while view:
            count = os.write(self._trace_fd, view)
            if count <= 0:
                raise OSError('Generation trace write failed')
            view = view[count:]
        self._trace_records += 1
        self._trace_bytes += len(encoded)

    def _stop(self, reason, now):
        if self._stop_reason is None:
            self._stop_reason = reason
            try:
                self._write_trace('stop', now, reason=reason, content_chars=self._content_chars)
            except OSError:
                pass
        return self._stop_reason

    def preflight(self):
        if self._admitted or self._trace_fd is not None or self._closed:
            raise ValueError('Generation preflight is single-use')
        now = self._now()
        try:
            self._trace_fd = os.open(self.trace_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                sample = _validated_sample(self.sampler())
            except CriticalPressureObserved as exc:
                self._last_sample = dict(exc.partial)
                self._write_trace('preflight-rejected', now, reason='memory-pressure-critical',
                                  telemetry=self._last_sample, telemetry_complete=False)
                raise HealthAdmissionError('memory-pressure-critical') from exc
            except Exception:
                self._write_trace('preflight-rejected', now, reason='memory-telemetry-unavailable', telemetry=None)
                raise HealthAdmissionError('memory-telemetry-unavailable')
            now = self._now()
            self._baseline, self._last_sample = sample, sample
            self._latest_sample_complete = True
            self._sample_count = 1
            estimated_headroom = self.profile.get('headroom_measurement') == 'free-plus-file-backed-estimate'
            headroom = sample['free_bytes'] + (sample['file_backed_bytes'] if estimated_headroom else 0)
            floor_reason = 'memory-preflight-headroom-floor' if estimated_headroom else 'memory-preflight-free-floor'
            reason = ('memory-pressure-critical' if sample['pressure'] == 4 else
                      'memory-preflight-not-normal' if sample['pressure'] != 1 else
                      floor_reason if headroom < self.profile['free_floor'] else None)
            metadata = {'passed': reason is None, 'telemetry': dict(sample),
                        'profile_sha256': profile_sha256(self.profile),
                        'health_floor_bytes': self.profile['free_floor'],
                        'target_peak_memory_prevalidated': False,
                        'controlled_first_load_calibration_required': True}
            if estimated_headroom:
                metadata.update(headroom_measurement='free-plus-file-backed-estimate',
                                estimated_headroom_bytes=headroom,
                                headroom_is_immediately_available_ram=False,
                                headroom_is_model_fit_guarantee=False,
                                headroom_limitations=['File-backed pages are potentially reclaimable; their sum with free pages is not guaranteed immediately available RAM or proof of model fit.'])
            self._write_trace('preflight', now, **metadata)
            if reason:
                raise HealthAdmissionError(reason)
            self._started = self._last_sample_at = now
            self._admitted = True
            return metadata
        except BaseException as exc:
            if isinstance(exc, HealthAdmissionError):
                self._stop_reason = exc.reason
            self.close()
            raise

    def _check_progress_descriptor(self, descriptor):
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink not in (0, 1) or info.st_size > 4096:
            raise ValueError('Unsafe generation progress marker')
        if info.st_nlink == 0:
            replacement = self.progress_path.lstat()
            if (not stat.S_ISREG(replacement.st_mode) or replacement.st_nlink != 1
                    or replacement.st_size > 4096
                    or (replacement.st_dev, replacement.st_ino) == (info.st_dev, info.st_ino)):
                raise ValueError('Unsafe generation progress replacement')
            raise _ReplacedProgress('Progress replaced after open')

    def _read_progress_once(self):
        try:
            descriptor = os.open(self.progress_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if self._progress_seen:
                raise ValueError('Generation progress disappeared')
            return
        with os.fdopen(descriptor, 'rb') as progress:
            self._check_progress_descriptor(progress.fileno())
            raw = progress.read(4097)
            self._check_progress_descriptor(progress.fileno())
        if len(raw) > 4096:
            raise ValueError('Generation progress exceeds limit')
        return raw

    def _read_progress(self):
        for attempt in range(1, PROGRESS_READ_ATTEMPTS + 1):
            try:
                raw = self._read_progress_once()
                break
            except _ReplacedProgress:
                self._progress_stale_reads += 1
                if attempt == PROGRESS_READ_ATTEMPTS:
                    self._progress_read_error = 'atomic-replacement-contention'
                    raise
                self._progress_reopens += 1
        if raw is None:
            return
        data = strict_json(raw)
        if type(data) is not dict:
            raise ValueError('Invalid generation progress marker')
        first, last, count = (data.get('first_content_monotonic'), data.get('last_content_monotonic'), data.get('content_chars'))
        if type(count) is not int or not 0 <= count <= self.profile['response_limit']:
            raise ValueError('Invalid generation content counter')
        now = self._now()
        if count == 0:
            if first is not None or last is not None or self._content_chars:
                raise ValueError('Invalid zero-content progress marker')
        else:
            if not all(_finite(value) for value in (first, last)):
                raise ValueError('Invalid generation content timestamps')
            if not self._started <= first <= last <= now:
                raise ValueError('Generation progress timestamps are outside this run')
            if self._first_content is not None and (first != self._first_content or count < self._content_chars
                    or last < self._last_content or (count == self._content_chars and last != self._last_content)):
                raise ValueError('Generation content progress cannot regress or fake activity')
        if self.profile.get('activity_timeout_semantics') == 'thinking-or-content':
            self._validate_activity_progress(data, first, last, count, now)
        self._first_content, self._last_content, self._content_chars = first, last, count
        self._progress_seen = True

    def _validate_activity_progress(self, data, content_first, content_last, content_chars, now):
        if set(data) != _HUI_PROGRESS_FIELDS:
            raise ValueError('Invalid thinking progress schema')
        thinking_chars, thinking_bytes, content_bytes = (data[key] for key in
                                                       ('thinking_chars', 'thinking_bytes', 'content_bytes'))
        for count, size, limit, old_count, old_size in (
            (thinking_chars, thinking_bytes, self.profile['thinking_limit'], self._thinking_chars, self._thinking_bytes),
            (content_chars, content_bytes, self.profile['response_limit'], self._content_chars, self._content_bytes),
        ):
            if (type(count) is not int or type(size) is not int or not 0 <= count <= size <= limit
                    or size > 4 * count or count < old_count or size < old_size
                    or not count - old_count <= size - old_size <= 4 * (count - old_count)):
                raise ValueError('Invalid thinking/content progress counter')
        first, last = data['first_activity_monotonic'], data['last_activity_monotonic']
        total = thinking_chars + content_chars
        if total == 0:
            if first is not None or last is not None:
                raise ValueError('Empty progress cannot claim activity')
        elif not (_finite(first) and _finite(last) and self._started <= first <= last <= now):
            raise ValueError('Invalid activity timestamps')
        if content_chars and not first <= content_first <= content_last <= last:
            raise ValueError('Content timestamps are outside activity')
        if thinking_chars == 0 and (first != content_first or last != content_last):
            raise ValueError('Content-only activity timestamps must match content')
        if self._first_activity is not None:
            if first != self._first_activity or last is None or last < self._last_activity:
                raise ValueError('Activity cannot regress')
            if total == self._thinking_chars + self._content_chars and last != self._last_activity:
                raise ValueError('Unchanged thinking/content cannot fake activity')
            if self._content_chars == 0 and content_chars and content_first < self._last_activity:
                raise ValueError('New content precedes previous activity')
            if content_chars > self._content_chars and (content_last < self._last_activity
                    or (thinking_chars == self._thinking_chars and last != content_last)):
                raise ValueError('New content activity is inconsistent')
        self._first_activity, self._last_activity = first, last
        self._thinking_chars, self._thinking_bytes, self._content_bytes = thinking_chars, thinking_bytes, content_bytes

    def _activity_fields(self):
        return {'first_activity_monotonic': self._first_activity, 'last_activity_monotonic': self._last_activity,
                'thinking_chars': self._thinking_chars, 'thinking_bytes': self._thinking_bytes,
                'content_bytes': self._content_bytes}

    def _measure_burst_window(self, now):
        """Compare retained valid WARNING observations, never invented gap values."""
        if self._warning_history is None:
            return {}
        cutoff = now - self.profile['burst_window']
        while self._warning_history and self._warning_history[0]['at'] < cutoff:
            self._warning_history.popleft()
        rows = list(self._warning_history)
        used = max(0, rows[-1]['used'] - rows[0]['used']) if len(rows) > 1 else 0
        swapped = max(0, rows[-1]['out'] - rows[0]['out']) if len(rows) > 1 else 0
        # Both endpoints must still be in the window. A gap in sampler ordinals
        # means missing telemetry, not an observed growing transition.
        transitions = sum(after['ordinal'] == before['ordinal'] + 1
                          and (after['used'] > before['used'] or after['out'] > before['out'])
                          for before, after in zip(rows, rows[1:]))
        self._burst_detail = {'window_seconds': self.profile['burst_window'],
                              'valid_warning_observations': len(rows), 'growing_transitions': transitions,
                              'net_swap_used_bytes': used, 'net_swap_out_bytes': swapped,
                              'net_growth_bytes': max(used, swapped),
                              'window_span_seconds': rows[-1]['at'] - rows[0]['at'] if len(rows) > 1 else 0}
        return {'burst_guard': dict(self._burst_detail)}

    def _sample_health(self, now):
        self._sample_ordinal += 1
        try:
            sample = _validated_sample(self.sampler())
        except CriticalPressureObserved as exc:
            now = self._now()
            self._last_sample_at = now
            self._last_sample, self._latest_sample_complete = dict(exc.partial), False
            self._write_trace('sample-critical', now, telemetry=self._last_sample, telemetry_complete=False,
                              **self._measure_burst_window(now))
            return 'memory-pressure-critical'
        except Exception:
            now = self._now()
            self._last_sample_at = now
            self._latest_sample_complete = False
            self._failures += 1
            # A missing sample is not evidence that warning pressure recovered.
            # Keep the epoch/baseline, but require a fresh consecutive growth
            # streak before acting on later valid warning samples.
            self._growth_streak = 0
            self._write_trace('sample-unavailable', now, consecutive_failures=self._failures, telemetry=None,
                              **self._measure_burst_window(now))
            return 'memory-telemetry-lost' if self._failures >= self.profile['telemetry_failures'] else None
        now = self._now()
        self._last_sample_at = now
        self._failures = 0
        self._sample_count += 1
        previous = self._last_sample
        self._last_sample = sample
        self._latest_sample_complete = True
        if sample['pressure'] == 2:
            if self._warning_since is None:
                self._warning_since, self._warning_base = now, previous
            growing = sample['swap_used_bytes'] > previous['swap_used_bytes'] or sample['swap_out_bytes'] > previous['swap_out_bytes']
            self._growth_streak = self._growth_streak + 1 if growing else 0
            growth = max(0, sample['swap_used_bytes'] - self._warning_base['swap_used_bytes'],
                         sample['swap_out_bytes'] - self._warning_base['swap_out_bytes'])
            self._max_swap_growth = max(self._max_swap_growth, growth)
            deteriorating = (now - self._warning_since >= self.profile['warning_window']
                             and growth >= self.profile['sustained_swap_growth']
                             and self._growth_streak >= self.profile['successive_growth_samples'])
            if self._warning_history is not None:
                self._warning_history.append({'at': now, 'ordinal': self._sample_ordinal,
                                              'used': sample['swap_used_bytes'], 'out': sample['swap_out_bytes']})
                self._measure_burst_window(now)
                burst = (now - self._warning_since >= self.profile['warning_window']
                         and self._burst_detail['net_growth_bytes'] >= self.profile['sustained_swap_growth']
                         and self._burst_detail['growing_transitions'] >= self.profile['burst_min_growth_observations'])
                self._deterioration_trigger = 'consecutive-growth' if deteriorating else 'rolling-net-growth' if burst else None
                deteriorating = deteriorating or burst
        elif sample['pressure'] == 1:
            self._warning_since = self._warning_base = None
            self._growth_streak, deteriorating = 0, False
            if self._warning_history is not None:
                self._warning_history.clear()
                self._deterioration_trigger = None
        else:
            deteriorating = False
        self._write_trace('sample', now, telemetry=sample, content_chars=self._content_chars,
                          first_content_monotonic=self._first_content, last_content_monotonic=self._last_content,
                          warning_since=self._warning_since, successive_growth_samples=self._growth_streak,
                          **(self._activity_fields() if self.profile['think'] else {}),
                          **self._measure_burst_window(now))
        if sample['pressure'] == 4:
            return 'memory-pressure-critical'
        return 'memory-pressure-deterioration' if deteriorating else None

    def __call__(self):
        if self._stop_reason is not None:
            return self._stop_reason
        if not self._admitted or self._closed:
            raise ValueError('Generation monitor requires an active successful preflight')
        now = self._now()
        if now - self._started >= self.profile['generation_deadline']:
            return self._stop('generation-deadline', now)
        if now - self._last_sample_at >= self.profile['memory_sample_interval']:
            try:
                reason = self._sample_health(now)
            except OSError:
                reason = 'memory-trace-unavailable'
            if reason:
                return self._stop(reason, self._now())
        # Read after potentially slow native sampling so freshly resumed output
        # cannot be mistaken for idle output using a pre-sample marker.
        try:
            self._read_progress()
        except (OSError, ValueError, TypeError, RecursionError):
            return self._stop('generation-progress-invalid', self._now())
        now = self._now()
        if now - self._started >= self.profile['generation_deadline']:
            return self._stop('generation-deadline', now)
        if self.profile.get('activity_timeout_semantics') == 'thinking-or-content':
            if self._first_activity is None:
                if now - self._started >= self.profile['first_content_timeout']:
                    return self._stop('generation-prefill-stall', now)
            elif now - self._last_activity >= self.profile['content_idle_timeout']:
                return self._stop('generation-activity-stall', now)
        elif self._first_content is None:
            if now - self._started >= self.profile['first_content_timeout']:
                return self._stop('generation-prefill-stall', now)
        elif now - self._last_content >= self.profile['content_idle_timeout']:
            return self._stop('generation-content-stall', now)
        return None

    def summary(self):
        result = {'profile_sha256': profile_sha256(self.profile), 'admitted': self._admitted,
                'stop_reason': self._stop_reason, 'started_monotonic': self._started,
                'successful_samples': self._sample_count, 'consecutive_telemetry_failures': self._failures,
                'baseline': dict(self._baseline) if self._baseline is not None else None,
                'latest_sample': dict(self._last_sample) if self._last_sample is not None else None,
                'latest_sample_complete': self._latest_sample_complete,
                'first_content_monotonic': self._first_content, 'last_content_monotonic': self._last_content,
                'content_chars': self._content_chars, 'max_warning_swap_growth_bytes': self._max_swap_growth,
                'trace_records': self._trace_records, 'trace_bytes': self._trace_bytes,
                'trace_truncated': self._trace_truncated, 'target_peak_memory_prevalidated': False}
        if self._warning_history is not None:
            result.update(burst_guard=dict(self._burst_detail) if self._burst_detail is not None else None,
                          warning_history_limit=self._warning_history.maxlen,
                          deterioration_trigger=self._deterioration_trigger)
        if self.profile['think']:
            result.update(**self._activity_fields(), activity_timeout_semantics=self.profile['activity_timeout_semantics'],
                          progress_stale_reads=self._progress_stale_reads, progress_reopens=self._progress_reopens,
                          progress_read_error=self._progress_read_error)
        return result

    def close(self):
        if self._trace_fd is not None:
            os.close(self._trace_fd)
            self._trace_fd = None
        self._closed = True
