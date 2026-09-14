"""Pinned Ollama transport with owned cleanup; public isolation is unsupported.

The fixed personal transport is reusable only through trusted private composition.
It makes no process-isolation claim and exposes no selectable endpoint or callback.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

from json_codec import canonical_bytes, strict_json
from provider_common import ContractError, ProviderError, require, validate_bundle
from engine_types import (EngineIdentity, Work, WorkResult, EngineFailure, CLEANUP_SCHEMA,
                          no_start_cleanup, require_cleanup, RETRYABLE_ENGINE_CODES)
from run_bounded import run
from local_model import local_status, MODEL, MANIFEST, DIGEST
from host_paths import (SOURCE_DIRECTORY, ollama_models_root,
                        ensure_state_root, validate_model_slot_path)

HUIHUI_MANIFEST = ollama_models_root() / 'manifests/registry.ollama.ai/huihui_ai/Qwen3.8-abliterated/27b-q6_K_L'
RETRYABLE_GENERATION_CODES = RETRYABLE_ENGINE_CODES

class LocalGenerationError(ProviderError):
    def __init__(self, code, message, *, hard_stop=False, status_write_failed=False,
                 evidence_close_failed=False):
        super().__init__(message)
        self.generation_error_code = code
        self.generation_hard_stop = hard_stop
        self.status_write_failed = status_write_failed
        self.evidence_close_failed = evidence_close_failed

def sha(data):
    return hashlib.sha256(data).hexdigest()

def save(path, value):
    with Path(path).open('x', encoding='utf-8') as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.write('\n')

@contextmanager
def local_model_slot(timeout=180, *, path=None):
    """Serialize CLI local runs through generation AND unload, without a daemon."""
    if path is None:
        from composition import current_state_root
        directory = current_state_root()
        ensure_state_root(directory)
        workflows = directory / 'runs'
        workflows.mkdir(parents=True, exist_ok=True)
        require(workflows.resolve() == workflows, 'Unsafe local model lock directory')
        target = workflows / '.local-model.lock'
    else:
        target = validate_model_slot_path(path)
    parent_fd = os.open(target.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        for component in target.parent.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child
        parent_info = os.fstat(parent_fd)
        if path is not None:
            require(parent_info.st_uid == os.getuid() and not parent_info.st_mode & 0o022,
                    'Unsafe shared local model lock directory ownership')
        descriptor = os.open(target.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        lock_info = os.fstat(descriptor)
        require(stat.S_ISREG(lock_info.st_mode) and lock_info.st_nlink == 1
                and lock_info.st_uid == os.getuid() and not lock_info.st_mode & 0o022,
                'Unsafe local model lock file')
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < deadline, 'Local model slot timeout; another workflow is still active')
                time.sleep(0.05)
        def verify_held_slot():
            current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
            current_parent = target.parent.stat()
            held = os.fstat(descriptor)
            require((lock_info.st_dev, lock_info.st_ino) == (current.st_dev, current.st_ino)
                    == (held.st_dev, held.st_ino) and held.st_nlink == 1
                    and held.st_uid == os.getuid() and not held.st_mode & 0o022
                    and (current_parent.st_dev, current_parent.st_ino) == (parent_info.st_dev, parent_info.st_ino)
                    and target.resolve() == target,
                    'Local model lock identity changed during execution')
        verify_held_slot()
        yield verify_held_slot
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)

def _generation_failure_object(path):
    """Read a small owned failure receipt without following special files."""
    try:
        path = Path(path).absolute()
        if path.resolve() != path:
            raise ValueError('Noncanonical failure evidence')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096:
                raise ValueError('Invalid failure evidence file')
            raw = source.read(4097)
        if len(raw) > 4096:
            raise ValueError('Failure evidence exceeds bound')
        if not raw.strip():
            return None
        value = strict_json(raw)
        if not isinstance(value, dict):
            raise ValueError('Failure evidence must be an object')
        return value
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError):
        raise LocalGenerationError('GENERATION_DIAGNOSTIC_INVALID',
            'Official generation failure evidence is invalid', hard_stop=True) from None


def _profile_stream_failure(evidence):
    # The pipe is written by the owned child, not by model frame content. Prefer
    # it over a collided status path so the original symbolic error survives.
    receipt = _generation_failure_object(evidence / 'process/events.jsonl')
    status_write_failed = evidence_close_failed = False
    if receipt is not None:
        if (set(receipt) - {'status', 'error_code', 'status_write_failed', 'evidence_close_failed'}
                or receipt.get('status') != 'failed'
                or any(type(receipt.get(key, False)) is not bool
                       for key in ('status_write_failed', 'evidence_close_failed'))):
            raise LocalGenerationError('GENERATION_DIAGNOSTIC_INVALID',
                'Official child failure receipt is invalid', hard_stop=True)
        code = receipt.get('error_code')
        status_write_failed = receipt.get('status_write_failed', False)
        evidence_close_failed = receipt.get('evidence_close_failed', False)
    else:
        status = _generation_failure_object(evidence / 'stream-status.json')
        if not status or status.get('status') != 'failed':
            raise LocalGenerationError('GENERATION_DIAGNOSTIC_INVALID',
                'Official generation has no valid terminal failure evidence', hard_stop=True)
        code = status.get('error_code')
    if not isinstance(code, str) or not re.fullmatch('[A-Z_]{1,80}', code):
        raise LocalGenerationError('GENERATION_DIAGNOSTIC_INVALID',
            'Official generation failure code is invalid', hard_stop=True)
    hard_stop = code not in RETRYABLE_GENERATION_CODES or status_write_failed or evidence_close_failed or code in {
        'REQUEST_PROFILE_MISMATCH', 'INVALID_PROFILE', 'MODEL_MISMATCH',
        'REMOTE_RESPONSE', 'REMOTE_REQUEST', 'TOOL_RESPONSE', 'TOOL_REQUEST',
        'GENERATION_DEADLINE', 'OUTPUT_EXISTS', 'OUTPUT_COLLISION',
        'INVALID_EVIDENCE_DIRECTORY', 'PROGRESS_CHANGED', 'PREFLIGHT_IO_ERROR',
        'FIRST_ACTIVITY_STALL', 'ACTIVITY_STALL', 'CLOCK_INVALID', 'TOKEN_USAGE_INVALID',
    }
    message = 'Official streaming generation failed: ' + code
    if status_write_failed:
        message += '; terminal status could not be recorded'
    if evidence_close_failed:
        message += '; wire evidence could not be closed'
    return LocalGenerationError(code, message, hard_stop=hard_stop,
                                status_write_failed=status_write_failed,
                                evidence_close_failed=evidence_close_failed)


def _local_identity(profile=None):
    """Explicit new profiles select Hui; absent/old profiles keep their identity."""
    from generation_profile import HUIHUI_PROFILE_ID, HUIHUI_MODEL, HUIHUI_DIGEST
    if profile is not None and profile['id'] == HUIHUI_PROFILE_ID:
        require(profile['model'] == HUIHUI_MODEL and profile['model_digest'] == HUIHUI_DIGEST,
                'Hui profile model identity mismatch')
        return HUIHUI_MODEL, HUIHUI_DIGEST, HUIHUI_MANIFEST
    require(profile is None or (profile['model'] == MODEL and profile['model_digest'] == DIGEST),
            'Profile model identity mismatch')
    return MODEL, DIGEST, MANIFEST


def _model_name_matches(value, model):
    from generation_profile import HUIHUI_MODEL
    if model == HUIHUI_MODEL:
        return type(value) is str and value.isascii() and value.lower() == model.lower()
    return value == model


def _loaded_model_matches(row, model, digest):
    return (isinstance(row, dict) and _model_name_matches(row.get('name'), model)
            and row.get('digest') == digest
            and not row.get('remote_host') and not row.get('remote_model')
            and ('model' not in row or _model_name_matches(row['model'], model)))


def _verify_local_manifest(manifest, expected_digest, *, hui=False):
    try:
        if hui and (manifest.resolve(strict=True) != manifest or manifest.is_symlink()):
            raise LocalGenerationError('MODEL_MANIFEST_UNSAFE', 'Local model manifest path is unsafe', hard_stop=True)
        require(sha(manifest.read_bytes()) == expected_digest, 'Model identity mismatch')
    except FileNotFoundError as exc:
        raise LocalGenerationError('MODEL_NOT_INSTALLED',
            'Pinned local model is not installed; create a new explicitly approved Hui profile packet. No automatic download or provider switch.',
            hard_stop=True) from exc


def unload_profile(profile, *, owned):
    """Only stop a matching model after this CLI segment started local inference."""
    from generation_profile import resolve_profile
    profile = resolve_profile(profile)
    model, digest, _ = _local_identity(profile)
    before = local_status('ps')
    models = before.get('models')
    require(isinstance(models, list), 'Invalid loaded model identity response')
    if not models:
        return {'model': model, 'model_digest': digest, 'owned_generation_started': owned,
                'unload_sent': False, 'before': before, 'after': before}
    require(owned, 'Unowned loaded model remains; do not evict another session')
    require(len(models) == 1 and _loaded_model_matches(models[0], model, digest)
            and models[0].get('context_length') == profile['options']['num_ctx'],
            'Foreign loaded model identity; do not evict another session')
    import urllib.request
    from generate_edits import NoRedirect
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request('http://127.0.0.1:11434/api/generate',
        data=json.dumps({'model': model, 'keep_alive': 0, 'stream': False}).encode(),
        headers={'Content-Type': 'application/json'})
    with opener.open(request, timeout=30) as response:
        raw = response.read(65537)
    require(len(raw) <= 65536, 'Unloading response exceeds limit')
    result = strict_json(raw)
    require(isinstance(result, dict) and result.get('done') is True
            and result.get('done_reason') == 'unload' and _model_name_matches(result.get('model'), model)
            and not result.get('remote_host') and not result.get('remote_model') and not result.get('error'),
            'Model unload failed')
    after = local_status('ps')
    require(after.get('models') == [], 'Unexpected loaded model remains')
    return {'model': model, 'model_digest': digest, 'owned_generation_started': True,
            'unload_sent': True, 'before': before, 'after': after, 'unload': result}


def _generation_command(script, *arguments):
    require(script in {'generate_stream.py', 'generate_edits.py'}, 'Unknown generation helper')
    bootstrap = (
        'import runpy,sys\n'
        'from pathlib import Path\n'
        'root=Path(sys.argv.pop(1)); target=Path(sys.argv.pop(1))\n'
        'if (root.resolve(strict=True)!=root or target.parent!=root '
        'or target.name not in {"generate_stream.py","generate_edits.py"} '
        'or target.resolve(strict=True)!=target):\n'
        '    raise SystemExit("INTERNAL_HELPER_REQUIRES_KERNEL")\n'
        'arguments=sys.argv[1:]\n'
        'sys.argv=[str(target),*arguments]\n'
        'sys.path[:]=[str(root)]+[value for value in sys.path if value!=str(root)]\n'
        'worker=runpy.run_path(str(target),run_name="_plzdo_owned_generation")\n'
        'raise SystemExit(worker["_worker_main"](arguments) or 0)\n')
    return [sys.executable, '-I', '-S', '-B', '-c', bootstrap, str(SOURCE_DIRECTORY),
            str(SOURCE_DIRECTORY / script), *(str(value) for value in arguments)]


def _remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise LocalGenerationError('GENERATION_DEADLINE',
                                   'Effective generation invocation deadline elapsed', hard_stop=True)
    return value


def local_edits(prompt, schema, evidence, timeout, *, generation_profile=None,
                _on_launch=None, _allow_loaded=None):
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 7200,
            'Invalid effective generation timeout')
    deadline = time.monotonic() + timeout
    def status(endpoint):
        return local_status(endpoint, timeout_seconds=min(10, _remaining(deadline)))
    profile = None
    system = 'Author code edits as JSON only. You have no tools.'
    evidence = Path(evidence)
    evidence.mkdir(parents=True, exist_ok=False)
    if generation_profile is not None:
        from generation_profile import resolve_profile, input_budget, profile_sha256
        try:
            profile = resolve_profile(generation_profile)
        except ValueError as exc:
            raise LocalGenerationError('PROFILE_BINDING_INVALID', 'Official profile binding failed', hard_stop=True) from exc
        try:
            budget = input_budget(prompt, system, profile)
        except ValueError as exc:
            raise LocalGenerationError('INPUT_BUDGET_EXCEEDED', 'Official profile input budget exceeded', hard_stop=True) from exc
        save(evidence / 'profile.json', profile)
        save(evidence / 'input-budget.json', budget)
    model, model_digest, manifest = _local_identity(profile)
    from generation_profile import HUIHUI_PROFILE_ID
    hui = profile is not None and profile['id'] == HUIHUI_PROFILE_ID
    _verify_local_manifest(manifest, model_digest, hui=hui)
    require(status('version')['version'] == '0.33.3', 'Ollama version drift')
    tags = status('tags').get('models')
    require(isinstance(tags, list), 'Invalid installed model identity response')
    if not any(_loaded_model_matches(m, model, model_digest) for m in tags):
        raise LocalGenerationError('MODEL_NOT_INSTALLED', 'Pinned local model identity is not installed', hard_stop=True)
    loaded_before = status('ps').get('models')
    require(isinstance(loaded_before, list), 'Missing loaded-model baseline evidence')
    require(len(loaded_before) <= 1 and all(_loaded_model_matches(m, model, model_digest)
            for m in loaded_before), 'Loaded model identity/concurrency mismatch')
    if hui and loaded_before and not (_allow_loaded is not None and _allow_loaded()):
        raise LocalGenerationError('MODEL_ALREADY_LOADED',
            'Hui model was already loaded before this owned generation; leave the other session untouched', hard_stop=True)
    context = profile['options']['num_ctx'] if profile else 65536
    if profile:
        require(not loaded_before or loaded_before[0].get('context_length') == context,
                'Loaded model identity/context conflicts with new profile; require an unloaded baseline')
    request = {'model': model, 'stream': False, 'think': False, 'truncate': False,
        'shift': False, 'keep_alive': '5m', 'format': schema,
        'options': {'num_ctx': 65536, 'num_predict': 4096, 'temperature': 0, 'seed': 42},
        'messages': [{'role': 'system', 'content': system},
                     {'role': 'user', 'content': prompt}]}
    if profile:
        request.update({key: profile[key] for key in ('stream', 'think', 'truncate', 'shift', 'keep_alive')})
        request['options'] = dict(profile['options'])
    save(evidence / 'request.json', request)
    if profile:
        from generation_health import GenerationHealth
        supervisor = GenerationHealth(profile, evidence / 'progress.json', evidence / 'memory.jsonl')
        try:
            try:
                supervisor.preflight()
            except (ValueError, OSError, RuntimeError) as exc:
                raise LocalGenerationError('MEMORY_ADMISSION_FAILED', 'Official profile memory/telemetry admission failed', hard_stop=True) from exc
            effective_timeout = min(_remaining(deadline), profile['generation_deadline'] + profile['supervisor_grace'])
            if _on_launch is not None:
                _on_launch()
            summary = run(_generation_command('generate_stream.py', '--profile', evidence / 'profile.json',
                evidence / 'request.json', evidence / 'response.json'), SOURCE_DIRECTORY, evidence / 'process',
                effective_timeout, stop_check=supervisor,
                env_allowlist=('LANG', 'LC_ALL'), env_override={'PATH': os.defpath}, pipe_output=True)
        finally:
            if hui:
                health_error = None
                try:
                    supervisor.close()
                except Exception as exc:
                    health_error = type(exc).__name__
                try:
                    health = supervisor.summary()
                    if health_error:
                        health['close_error_type'] = health_error
                    save(evidence / 'health-summary.json', health)
                except Exception as exc:
                    health_error = health_error or type(exc).__name__
                if health_error:
                    raise LocalGenerationError('HEALTH_EVIDENCE_FAILED',
                        'Hui supervision evidence could not be closed or saved: ' + health_error,
                        hard_stop=True)
            else:
                save(evidence / 'health-summary.json', supervisor.summary())
                supervisor.close()
        reason = summary.get('stop_reason', '')
        if summary.get('supervisor_stop') or summary.get('timed_out'):
            code = ('MEMORY_PRESSURE' if reason.startswith('memory-pressure') else
                    'TELEMETRY_UNAVAILABLE' if reason.startswith('memory-telemetry') else
                    'GENERATION_DEADLINE' if reason in ('generation-deadline', 'timeout') else
                    'GENERATION_STALL' if reason in ('generation-prefill-stall', 'generation-content-stall', 'generation-activity-stall') else
                    'GENERATION_SUPERVISION_ERROR')
            raise LocalGenerationError(code, 'Official generation stopped: ' + reason,
                hard_stop=hui or code != 'GENERATION_STALL')
    else:
        summary = run(_generation_command('generate_edits.py', evidence / 'request.json',
            evidence / 'response.json'), SOURCE_DIRECTORY, evidence / 'process', _remaining(deadline),
            env_allowlist=('LANG', 'LC_ALL'), env_override={'PATH': os.defpath}, pipe_output=True)
    try:
        require_cleanup(summary.get('cleanup'))
    except EngineFailure as exc:
        raise LocalGenerationError('LOCAL_PROCESS_CLEANUP_UNPROVEN',
            'Owned generation process cleanup lacks explicit evidence', hard_stop=True) from exc
    _verify_local_manifest(manifest, model_digest, hui=hui)
    if profile and summary['return_code'] != 0:
        # A failed write may leave partial response bytes. Do not parse those
        # before recovering the authoritative child failure code.
        raise _profile_stream_failure(evidence)
    response_path = evidence / 'response.json'
    response = strict_json(response_path.read_bytes()) if response_path.exists() else None
    if response:
        require(_model_name_matches(response.get('model'), model) and not response.get('remote_model')
                and not response.get('remote_host'), 'Model identity mismatch in response')
        require(not response.get('message', {}).get('tool_calls'), 'Forbidden model tool response')
    if summary['return_code'] != 0 or response is None:
        if profile:
            raise _profile_stream_failure(evidence)
        raise ProviderError('local-generation-failed-or-timed-out')
    if profile:
        prompt_tokens, output_tokens = response.get('prompt_eval_count'), response.get('eval_count')
        if (type(prompt_tokens) is not int or type(output_tokens) is not int
                or prompt_tokens < 0 or not 0 <= output_tokens <= profile['options']['num_predict']):
            raise LocalGenerationError('TOKEN_USAGE_INVALID', 'Official generation token evidence is missing or invalid', hard_stop=True)
        if prompt_tokens + profile['template_reserve'] + profile['options']['num_predict'] > context:
            raise LocalGenerationError('INPUT_BUDGET_EXCEEDED', 'Reported prompt exceeds reserved context budget', hard_stop=True)
    loaded = status('ps').get('models')
    require(isinstance(loaded, list), 'Missing loaded-model completion evidence')
    require(len(loaded) == 1 and _loaded_model_matches(loaded[0], model, model_digest)
            and loaded[0].get('context_length') == context, 'Loaded model identity/context/concurrency mismatch')
    identity = {'model': model, 'digest': model_digest,
        'response_sha256': sha((evidence / 'response.json').read_bytes()),
        'loaded': loaded, 'duration_seconds': summary['duration_seconds']}
    if profile:
        identity.update(generation_profile=profile['id'], profile_sha256=profile_sha256(profile),
                        actual_options=request['options'], memory_health=str(evidence / 'health-summary.json'),
                        provider_reported_prompt_tokens=prompt_tokens, provider_reported_output_tokens=output_tokens,
                        reported_token_budget_checked=True)
    save(evidence / 'identity.json', identity)
    return strict_json(response['message']['content'])

def implementation_sha256():
    """Exact reusable source identity; never reads a model or contacts its server."""
    names = ('ollama_engine.py', 'engine_types.py', 'provider_common.py', 'json_codec.py',
             'local_model.py', 'generate_edits.py', 'generate_stream.py',
             'generation_profile.py', 'generation_health.py', 'run_bounded.py')
    rows = []
    for name in names:
        path = SOURCE_DIRECTORY / name
        require(path.resolve() == path and path.is_file() and not path.is_symlink(),
                'Ollama implementation source identity is unsafe')
        rows.append({'name': name, 'sha256': sha(path.read_bytes())})
    return sha(canonical_bytes(rows))


class OllamaEngine:
    """Fixed public engine. No caller flag can weaken the isolation requirement."""
    def identity(self):
        return EngineIdentity('ollama', ('generate',), implementation_sha256())

    def execute(self, work):
        # This must precede profile, manifest, status, endpoint, and process access.
        raise EngineFailure('ISOLATION_PROFILE_UNSUPPORTED',
            'A verified owned-Ollama server egress isolation profile is unavailable',
            evidence={'isolation_verified': False, 'transport_started': False},
            cleanup=no_start_cleanup())


def execute_owned_ollama(work, identity):
    """Fixed personal-local transport for trusted private composition only.

    It neither starts nor reconfigures a daemon. The existing loopback server and
    system memory are trusted personal resources, not a verified isolation realm.
    All started generation is unloaded while the same model lock remains held.
    """
    from workflow_core import _read_check_evidence as _read_owned_evidence
    from generation_profile import HUIHUI_PROFILE_ID, resolve_profile
    if not isinstance(work, Work) or not isinstance(identity, EngineIdentity):
        raise TypeError('Immutable Work and EngineIdentity required')
    require(work.operation == 'generate' and work.operation in identity.roles,
            'Ollama transport operation identity mismatch')
    profile = resolve_profile(strict_json(work.profile_bytes))
    require(profile['id'] == HUIHUI_PROFILE_ID, 'Explicit pinned Hui profile required')
    evidence = work.evidence_dir
    require(evidence.resolve() == evidence and not evidence.exists() and not evidence.is_symlink(),
            'Ollama evidence destination must be new and canonical')
    prompt, schema = strict_json(work.prompt_bytes), strict_json(work.schema_bytes)
    validate_bundle(prompt)
    ownership = {'started': False}
    receipt = no_start_cleanup()
    metadata = {'trust': 'personal-local', 'isolation_verified': False,
                'reservation_id': work.reservation_id,
                'endpoint': 'http://127.0.0.1:11434', 'generation_profile': profile['id']}
    payload, error = None, None

    def started():
        verify_slot()
        ownership['started'] = True

    deadline = min(work.deadline_monotonic,
                   time.monotonic() + profile['generation_deadline'] + profile['supervisor_grace'])
    if deadline <= time.monotonic():
        raise EngineFailure('GENERATION_DEADLINE', 'Work deadline elapsed before owned generation',
                            evidence=metadata, cleanup=receipt)
    with local_model_slot(_remaining(deadline)) as verify_slot:
        try:
            payload = local_edits(prompt, schema, evidence, _remaining(deadline),
                                  generation_profile=profile, _on_launch=started)
        except BaseException as exc:
            error = exc
        finally:
            if ownership['started']:
                receipt = {'schema': CLEANUP_SCHEMA, 'completed': False, 'passed': False,
                           'owned': True, 'started': True, 'model': profile['model']}
                process_closed = model_closed = False
                try:
                    process_summary = strict_json(_read_owned_evidence(evidence / 'process', 'summary.json', 256 * 1024))
                    require(isinstance(process_summary, dict), 'Invalid owned generation process summary')
                    receipt['process_cleanup'] = process_summary.get('cleanup')
                    require_cleanup(receipt['process_cleanup'])
                    process_closed = True
                except BaseException as exc:
                    receipt['process_evidence_error_type'] = type(exc).__name__
                try:
                    verify_slot()
                    receipt.update(unload_profile(profile, owned=True))
                    from generation_health import sample_system
                    receipt['health_after_cleanup'] = sample_system()
                    require(receipt['health_after_cleanup']['pressure'] != 4,
                            'Critical pressure after local model cleanup')
                    verify_slot()
                    model_closed = True
                except BaseException as exc:
                    receipt['error_type'] = type(exc).__name__
                receipt.update(completed=process_closed and model_closed, passed=process_closed and model_closed)
            if evidence.is_dir() and evidence.resolve() == evidence:
                try:
                    save(evidence / 'owned-cleanup.json', receipt)
                except BaseException as exc:
                    receipt.update(passed=False, evidence_error_type=type(exc).__name__)
            elif ownership['started']:
                receipt.update(passed=False, completed=False, evidence_error_type='EvidenceDirectoryMissing')
        require_cleanup(receipt)
        verify_slot()
    if error is not None:
        if isinstance(error, LocalGenerationError):
            code = error.generation_error_code
            metadata.update(status_write_failed=error.status_write_failed,
                            evidence_close_failed=error.evidence_close_failed)
            raise EngineFailure(code, str(error)[:2000], evidence=metadata, cleanup=receipt,
                retryable=code in RETRYABLE_ENGINE_CODES and not error.generation_hard_stop) from error
        raise EngineFailure('OLLAMA_EXECUTION_FAILED', type(error).__name__ + ': ' + str(error)[:600],
                            evidence=metadata, cleanup=receipt) from error
    return WorkResult(canonical_bytes(payload), identity, metadata, receipt)
