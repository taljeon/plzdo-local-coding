"""One native Google Antigravity review dispatch through shared supervision."""
from __future__ import annotations

import math
import os
from pathlib import Path
import stat
import tempfile
import uuid

from local_coding.api import canonical_bytes, strict_json, require_cleanup, run_bounded

from . import agy_context, transports
from .transports import ProviderError


AGY_VERSION = '1.2.2'
AGY_BINARY_SHA256 = 'cabadc15a61944372bede1fdff186701c17467dd9d718e97dc79283055d3c101'
AGY_MODELS = ('gemini-3.8-flash-high', 'gemini-3.8-flash-medium')
PROMPT_POLICY = 'plzdo.agy-review-prompt.v1'
_USAGE_KEYS = {'input_tokens', 'output_tokens', 'thinking_tokens', 'cache_read_tokens', 'total_tokens'}


def validate_model(model):
    if model not in AGY_MODELS:
        raise ProviderError('agyModel must be an explicitly resolved supported Gemini 3.8 slug')


def verified_runtime(pin):
    if pin.get('sha256') != AGY_BINARY_SHA256:
        raise ProviderError('AGY requires the source-pinned official 1.2.2 native binary')
    return transports.verified_binary(pin['path'], pin['sha256'])


def build_provider_prompt(prompt):
    """Source-owned suffix; approved Work bytes and engine identity bind it."""
    if not isinstance(prompt, str):
        raise ProviderError('AGY Work prompt must be text')
    return (prompt + '\n\nRequired JSON Schema for the response text:\n'
            + canonical_bytes(transports.REVIEW_SCHEMA).decode('utf-8')
            + '\nReturn only one JSON object matching this schema, with all four keys: '
              'verdict, summary, issues, plan. Use empty arrays when appropriate. '
              'Use the normal text response channel. Do not use Markdown fences or surrounding prose. '
              'Do not invoke any tools, shell, browsing, file access, or subagents. '
              'Do not call finish, FINISH, StructuredOutput, or any other tool to format the answer.')


def build_command(executable, provider_prompt, model, timeout):
    validate_model(model)
    # No resume/default-project context, alternate account, permission bypass,
    # extra workspace, agent override, native schema/finish tool, or retry setting.
    # 1.2.2 warns that --mode plan is ineffective with disabled slash expansion.
    return [executable, '--disable-slash-commands', '--sandbox',
            '--new-project', '--output-format', 'stream-json', '--model', model,
            '--print-timeout', str(max(1, int(timeout * 1000) - 1000)) + 'ms',
            '--log-file', os.devnull, '-p', provider_prompt]


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _usage(value):
    if (not isinstance(value, dict) or set(value) - _USAGE_KEYS
            or any(type(item) is not int or item < 0 for item in value.values())):
        raise ProviderError('Malformed AGY usage observation')


def _conversation(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError) as exc:
        raise ProviderError('Malformed AGY conversation identity') from exc
    return value


def parse_stream(text, *, cwd, model, complete=True):
    """Validate documented NDJSON; partial mode also stops observed bad steps."""
    lines = text.splitlines()
    if not complete and text and not text.endswith('\n'):
        lines = lines[:-1]
    conversation, initialized, terminal = None, False, None
    steps, fragments, tools = {}, [], []
    for line in lines:
        if not line.strip():
            raise ProviderError('Blank AGY stream event')
        event = strict_json(line)
        if not isinstance(event, dict) or terminal is not None:
            raise ProviderError('Malformed or trailing AGY stream event')
        kind = event.get('event')
        if kind == 'init':
            if initialized or set(event) != {'event', 'conversation_id', 'init'}:
                raise ProviderError('Duplicate or malformed AGY init')
            conversation = _conversation(event['conversation_id'])
            value = event['init']
            required = {'cwd', 'tools', 'permission_mode', 'model'}
            if (not isinstance(value, dict) or set(value) != required
                    or value['cwd'] != str(cwd) or value['model'] != model
                    or value['permission_mode'] != 'request-review'
                    or not isinstance(value['tools'], list)
                    or any(not isinstance(name, str) or not name or len(name) > 160 for name in value['tools'])
                    or len(value['tools']) > 256 or len(set(value['tools'])) != len(value['tools'])):
                raise ProviderError('AGY init differs from admitted plain-text model, workspace, or permissions')
            # Registration is observable metadata, never an assertion that tools
            # are disabled. Every invocation is rejected below.
            tools, initialized = value['tools'], True
        elif kind == 'step_update':
            if not initialized or set(event) != {'event', 'step_update'}:
                raise ProviderError('AGY step precedes initialization or has unexpected fields')
            step = event['step_update']
            required = {'conversation_id', 'step_index', 'state', 'step_type'}
            allowed = required | {'text_delta', 'duration_seconds', 'usage'}
            if (not isinstance(step, dict) or not required <= set(step) or set(step) - allowed
                    or step['conversation_id'] != conversation
                    or type(step['step_index']) is not int or step['step_index'] < 0
                    or step['state'] not in {'ACTIVE', 'DONE'}
                    or step['step_type'] not in {'user_input', 'agent_response', 'checkpoint'}):
                raise ProviderError('AGY tool, subagent, failed, or malformed step is not permitted')
            index = step['step_index']
            old = steps.get(index)
            if (steps and index < max(steps)) or (old is not None and (
                    old['type'] != step['step_type'] or old['state'] == 'DONE')):
                raise ProviderError('AGY step order or terminal state changed')
            if 'duration_seconds' in step and not _number(step['duration_seconds']):
                raise ProviderError('Malformed AGY step duration')
            if 'usage' in step:
                _usage(step['usage'])
            if 'text_delta' in step:
                if not isinstance(step['text_delta'], str) or step['step_type'] != 'agent_response':
                    raise ProviderError('Unexpected AGY text outside an agent response')
                fragments.append(step['text_delta'])
            steps[index] = {'type': step['step_type'], 'state': step['state']}
        elif kind == 'result':
            if not initialized or set(event) != {'event', 'result'}:
                raise ProviderError('AGY terminal result precedes initialization or is malformed')
            value = event['result']
            required = {'conversation_id', 'status', 'response', 'duration_seconds', 'num_turns', 'usage'}
            if (not isinstance(value, dict) or set(value) != required
                    or value['conversation_id'] != conversation or value['status'] != 'SUCCESS'
                    or type(value['num_turns']) is not int or value['num_turns'] != 1
                    or not _number(value['duration_seconds'])
                    or not isinstance(value['response'], str)):
                raise ProviderError('AGY result is unsuccessful or differs from the admitted one-shot review')
            _usage(value['usage'])
            output = transports.validate_review(strict_json(value['response']))
            if canonical_bytes(strict_json(''.join(fragments))) != canonical_bytes(output):
                raise ProviderError('AGY review JSON differs from captured response text')
            if (any(step['state'] != 'DONE' for step in steps.values())
                    or sum(step['type'] == 'user_input' for step in steps.values()) != 1
                    or not any(step['type'] == 'agent_response' for step in steps.values())):
                raise ProviderError('AGY result lacks exactly one completed input and response')
            terminal = {'review': output, 'conversation_id': conversation, 'observed_model': model,
                        'registered_tools': tools, 'usage': value['usage'],
                        'duration_seconds': value['duration_seconds']}
        else:
            raise ProviderError('Unknown AGY stream event')
    if complete and (not initialized or terminal is None):
        raise ProviderError('AGY stream lacks one successful terminal result')
    return terminal


def reject_diagnostics(text):
    import re
    if re.search(r'(?i)\b(?:error|warn(?:ing)?|failed|denied|denial|forbidden|unauthorized|'
                 r'permission|approval|retry(?:ing)?|not allowed|not permitted)\b', text):
        raise ProviderError('AGY reported an error, permission notice, or retry diagnostic')


def _complete_event_lines(path):
    # A pipe read may end inside a UTF-8 character. Decode only complete NDJSON
    # lines while running; the final bounded read must decode the entire stream.
    if path.resolve(strict=True) != path:
        raise ProviderError('Unsafe AGY event capture')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ProviderError('Unsafe AGY event capture')
        chunks, size = [], 0
        while chunk := os.read(fd, min(65536, transports.MAX_RESULT_BYTES + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            if size > transports.MAX_RESULT_BYTES:
                raise ProviderError('AGY event capture exceeded its bound')
        raw = b''.join(chunks)
        return raw[:raw.rfind(b'\n') + 1].decode('utf-8', 'strict')
    finally:
        os.close(fd)


def review(work, pin, model, global_rules_sha256, trace, *, deadline):
    transports.require_active_session()
    transports.remaining_seconds(deadline)
    validate_model(model)
    prompt = strict_json(work.prompt_bytes)
    bundle_hash = transports.validate_bundle(prompt)
    if work.operation != 'review' or work.schema_bytes != canonical_bytes(transports.REVIEW_SCHEMA):
        raise ProviderError('AGY supports only the fixed advisory review schema')
    provider_prompt = build_provider_prompt(prompt)
    provider_prompt_hash = transports.validate_bundle(provider_prompt)
    before = agy_context.snapshot(global_rules_sha256)
    identity = verified_runtime(pin)
    evidence = transports._open_evidence(work, trace)
    trace.update(provider='agy', requested_model=model, input_sha256=bundle_hash,
                 work_prompt_sha256=transports.sha256(work.prompt_bytes),
                 provider_prompt_sha256=provider_prompt_hash,
                 provider_prompt_bytes=len(provider_prompt.encode('utf-8')), provider_prompt_policy=PROMPT_POLICY,
                 requested_schema_sha256=transports.sha256(work.schema_bytes),
                 response_validation='host-json-review-schema', native_schema_enforcement=False,
                 authority='advisory', source_of_truth=False, ambient_context=before,
                 context_matches_after=False, workspace_unchanged=False,
                 adapter_dispatches=0, adapter_retries=0, native_api_retries='pinned-binary-default-uncontrolled',
                 native_account_storage='provider-default', tools_disabled=False, native_auto_update=False)
    transports._save_json(evidence / 'ambient-context-before.json', before)
    transports._save_json(evidence / 'provider-input.json', {key: trace[key] for key in (
        'input_sha256', 'work_prompt_sha256', 'provider_prompt_sha256', 'provider_prompt_bytes',
        'provider_prompt_policy', 'requested_schema_sha256', 'response_validation', 'native_schema_enforcement')})
    # Fixed OS temp parent avoids attaching a repository or caller-provided cwd.
    with tempfile.TemporaryDirectory(prefix='plzdo-private-agy-', dir=Path('/tmp').resolve()) as directory:
        temporary = Path(directory).resolve()
        workspace, scratch = temporary / 'workspace', temporary / 'tmp'
        workspace.mkdir(mode=0o500)
        scratch.mkdir(mode=0o700)
        workspace_before = agy_context.workspace_snapshot(workspace)
        process_root = evidence / 'process'
        failure = []

        def stop_check():
            try:
                for name in ('events.jsonl', 'stderr.log'):
                    path = process_root / name
                    if path.exists() and path.stat().st_size > transports.MAX_RESULT_BYTES:
                        return 'agy-output-limit'
                if (process_root / 'events.jsonl').exists():
                    parse_stream(_complete_event_lines(process_root / 'events.jsonl'),
                                 cwd=workspace, model=model, complete=False)
                if (process_root / 'stderr.log').exists():
                    reject_diagnostics(transports._bounded_read(process_root / 'stderr.log'))
            except (ValueError, OSError, RuntimeError) as exc:
                failure[:] = [type(exc).__name__ + ': ' + str(exc)[:300]]
                return 'agy-observed-boundary-failure'
            return None

        if agy_context.snapshot(global_rules_sha256) != before or verified_runtime(pin) != identity:
            raise ProviderError('AGY ambient context or executable changed before dispatch')
        timeout = min(transports.remaining_seconds(deadline), 180)
        argv = build_command(identity['path'], provider_prompt, model, timeout)
        trace['cleanup'] = {'schema': 'plzdo.engine-cleanup.v1', 'completed': False,
                            'passed': False, 'owned': True, 'started': True}
        trace['adapter_dispatches'] = 1
        origin_keys = {name for name in os.environ if name.startswith('META_HARNESS_')
                       or name in {'CI', 'LOCAL_CODING_UNATTENDED'}}
        result = run_bounded(argv, workspace, process_root, timeout, pipe_output=True,
            env_allowlist=frozenset({'HOME'} | origin_keys),
            env_override={'PATH': os.defpath, 'TMPDIR': str(scratch), 'LANG': 'C',
                          'LC_ALL': 'C', 'TERM': 'dumb', 'NO_COLOR': '1',
                          'AGY_CLI_DISABLE_AUTO_UPDATE': 'true'}, stop_check=stop_check)
        trace['cleanup'] = result.get('cleanup') if isinstance(result.get('cleanup'), dict) else {}
        trace['process'] = {key: result.get(key) for key in (
            'return_code', 'child_exit_code', 'timed_out', 'error', 'duration_seconds', 'supervisor_stop')}
        trace['boundary_failure'] = failure
        require_cleanup(trace['cleanup'])
        transports._save_json(evidence / 'owned-cleanup.json', trace['cleanup'])
        after = agy_context.snapshot(global_rules_sha256)
        transports._save_json(evidence / 'ambient-context-after.json', after)
        trace['context_matches_after'] = after == before
        trace['workspace_unchanged'] = agy_context.workspace_snapshot(workspace) == workspace_before
        if not trace['context_matches_after'] or not trace['workspace_unchanged'] or verified_runtime(pin) != identity:
            raise ProviderError('AGY ambient context, executable, or owned workspace changed')
        if (failure or result.get('return_code') != 0 or result.get('child_exit_code') != 0
                or result.get('timed_out') is not False or result.get('error') is not None):
            raise ProviderError('AGY dispatch did not complete within the approved boundary')
        reject_diagnostics(transports._bounded_read(process_root / 'stderr.log'))
        parsed = parse_stream(transports._bounded_read(process_root / 'events.jsonl'),
                              cwd=workspace, model=model)
    transports.remaining_seconds(deadline)
    trace.update({key: value for key, value in parsed.items() if key != 'review'})
    trace.update(executable=identity, native_version=AGY_VERSION,
                 execution_workspace='owned-empty-workspace-with-admitted-global-context')
    transports._save_json(evidence / 'review.json', parsed['review'])
    return parsed['review']
