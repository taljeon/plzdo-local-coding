"""Fixed private engines. Work carries bytes, never ledger or target authority."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re

from local_coding.api import (EngineIdentity, Work, WorkResult, EngineFailure,
    canonical_bytes, strict_json, require_cleanup, no_start_cleanup,
    run_bounded, execute_owned_ollama, ollama_implementation_sha256)

from . import transports, agy_context, agy_transport


ROLES = {'ollama': ('generate',), 'codex-openai': ('design-review', 'generate'),
         'claude': ('review',), 'grok-cli': ('review',), 'agy': ('review',)}
SOURCE_FILES = ('__init__.py', '__main__.py', 'engines.py', 'transports.py', 'grok_admission.py',
                'orchestration.py', 'private_hn_backend.py', 'cli.py', 'agy_context.py', 'agy_transport.py')
LAUNCHER_FILES = ('plzdo-private', 'plzdo_private_entry.py')
AGY_RULES_UNSET = object()


def _launcher_directory():
    parent = Path(__file__).absolute().parent.parent
    candidates = [parent / 'bin']
    if (parent.name == 'site-packages' and re.fullmatch(r'python(?:3(?:\.\d+)?)?', parent.parent.name)
            and parent.parent.parent.name in {'lib', 'lib64'}):
        candidates.append(parent.parent.parent.parent / 'bin')
    found = [path for path in candidates if all((path / name).is_file() for name in LAUNCHER_FILES)]
    if len(found) != 1 or found[0].resolve(strict=True) != found[0]:
        raise ValueError('Exactly one fixed private launcher directory is required')
    return found[0]


def source_sha256():
    rows = {}
    root = Path(__file__).absolute().parent
    for name in SOURCE_FILES:
        path = root / name
        if path.resolve(strict=True) != path or not path.is_file():
            raise ValueError('Unsafe private implementation source')
        rows[name] = hashlib.sha256(transports._bounded_read(path, trusted_source=True).encode('utf-8')).hexdigest()
    launchers = _launcher_directory()
    for name in LAUNCHER_FILES:
        rows['launcher/' + name] = hashlib.sha256(
            transports._bounded_read(launchers / name, limit=1024 * 1024, trusted_source=True).encode('utf-8')).hexdigest()
    # Bind the reused process supervisor rather than privately copying it.
    path = Path(run_bounded.__code__.co_filename).absolute()
    rows['public-run-bounded'] = hashlib.sha256(transports._bounded_read(path, trusted_source=True).encode('utf-8')).hexdigest()
    return hashlib.sha256(canonical_bytes(rows)).hexdigest()


def _pin(pin):
    if (not isinstance(pin, dict) or set(pin) != {'path', 'sha256'}
            or not isinstance(pin['path'], str) or not Path(pin['path']).is_absolute()
            or re.fullmatch(r'[a-f0-9]{64}', pin.get('sha256', '')) is None):
        raise ValueError('A closed provider binary path and SHA-256 pin are required')
    return canonical_bytes(pin)


@dataclass(frozen=True)
class ExternalEngine:
    """Source-owned external roles, selected only by the fixed composition."""
    engine_id: str
    pin_bytes: bytes
    model: str | None = None
    global_rules_sha256: str | None = None

    def __post_init__(self):
        if self.engine_id not in {'codex-openai', 'claude', 'grok-cli', 'agy'}:
            raise ValueError('Unknown private external engine')
        if type(self.pin_bytes) is not bytes or _pin(strict_json(self.pin_bytes)) != self.pin_bytes:
            raise ValueError('Provider pin must be canonical immutable bytes')
        if self.engine_id == 'codex-openai':
            if self.model is not None and (not isinstance(self.model, str)
                    or re.fullmatch(r'[A-Za-z0-9._:-]{1,100}', self.model) is None
                    or any(part in self.model.lower() for part in ('ollama', 'qwen', 'llama'))):
                raise ValueError('Invalid explicit cloud Codex model')
        elif self.engine_id == 'agy':
            agy_transport.validate_model(self.model)
            agy_context.validate_rules_pin(self.global_rules_sha256)
            if strict_json(self.pin_bytes)['sha256'] != agy_transport.AGY_BINARY_SHA256:
                raise ValueError('AGY requires the source-pinned official 1.2.2 native binary')
        elif self.model is not None:
            raise ValueError('This engine does not accept a model override')
        if self.engine_id != 'agy' and self.global_rules_sha256 is not None:
            raise ValueError('Only AGY accepts its explicit global-rules pin')

    def identity(self):
        pin = strict_json(self.pin_bytes)
        if self.engine_id in {'codex-openai', 'claude'}:
            transports._check_endpoint_overrides('codex' if self.engine_id == 'codex-openai' else 'claude')
        elif self.engine_id == 'grok-cli' and any(os.environ.get(name) for name in ('GROK_BASE_URL', 'GROK_API_BASE', 'XAI_BASE_URL')):
            raise ValueError('Grok endpoint override present')
        if self.engine_id == 'agy':
            context = agy_context.snapshot(self.global_rules_sha256)
            agy_transport.verified_runtime(pin)
        else:
            transports.verified_binary(pin['path'], pin['sha256'], _claude_package=self.engine_id == 'claude')
        closure = {'privateSource': source_sha256(), 'engineId': self.engine_id,
                   'roles': list(ROLES[self.engine_id]), 'runtime': pin,
                   'model': self.model if self.engine_id in {'codex-openai', 'agy'} else
                            'opus' if self.engine_id == 'claude' else 'operator-configured'}
        if self.engine_id == 'agy':
            closure.update(nativeVersion=agy_transport.AGY_VERSION,
                           globalRulesSha256=self.global_rules_sha256,
                           ambientContextSha256=context['snapshotSha256'])
        return EngineIdentity(self.engine_id, ROLES[self.engine_id],
                              hashlib.sha256(canonical_bytes(closure)).hexdigest())

    def execute(self, work):
        trace = {'cleanup': no_start_cleanup(), 'provider': self.engine_id,
                 'source_of_truth': False, 'apply_status': 'not_applied'}
        try:
            if not isinstance(work, Work) or work.operation not in ROLES[self.engine_id]:
                raise ValueError('Engine operation is not permitted')
            deadline = work.deadline_monotonic
            transports.remaining_seconds(deadline)
            if self.engine_id == 'grok-cli':
                from .grok_admission import GROK_SCHEMA
                if strict_json(work.schema_bytes) != GROK_SCHEMA:
                    raise ValueError('Grok requires the fixed advisory review schema')
            identity = self.identity()
            transports.remaining_seconds(deadline)
            pin = strict_json(self.pin_bytes)
            if self.engine_id == 'codex-openai':
                value = transports.codex(work, pin, self.model, trace, deadline=deadline)
            elif self.engine_id == 'claude':
                value = transports.claude(work, pin, trace, deadline=deadline)
            elif self.engine_id == 'agy':
                value = agy_transport.review(work, pin, self.model, self.global_rules_sha256,
                                             trace, deadline=deadline)
            else:
                value = transports.grok(work, pin, trace, deadline=deadline)
            require_cleanup(trace['cleanup'])
            if self.identity() != identity:
                raise ValueError('Private engine implementation changed during execution')
            result = WorkResult(canonical_bytes(value), identity,
                {key: value for key, value in trace.items() if key != 'cleanup'}, trace['cleanup'])
            transports.remaining_seconds(deadline)
            return result
        except BaseException as exc:
            if isinstance(exc, EngineFailure):
                raise EngineFailure(exc.code, str(exc).removeprefix(exc.code + ': ')[:1800],
                    evidence={**{key: value for key, value in trace.items() if key != 'cleanup'},
                              'failure_evidence': exc.evidence},
                    cleanup=exc.cleanup, retryable=exc.retryable) from exc
            raise EngineFailure('EXTERNAL_ENGINE_FAILED',
                type(exc).__name__ + ': ' + str(exc)[:1800],
                evidence={key: value for key, value in trace.items() if key != 'cleanup'},
                cleanup=trace.get('cleanup', {}), retryable=False) from exc


@dataclass(frozen=True)
class PersonalOllamaEngine:
    def identity(self):
        closure = {'privateSource': source_sha256(),
                   'publicOllamaSource': ollama_implementation_sha256(),
                   'trust': 'personal-local', 'isolation_verified': False}
        return EngineIdentity('ollama', ROLES['ollama'],
                              hashlib.sha256(canonical_bytes(closure)).hexdigest())

    def execute(self, work):
        return execute_owned_ollama(work, self.identity())


def fixed_engines(provider_pins, *, codex_model=None, agy_model=None, agy_global_rules_sha256=AGY_RULES_UNSET):
    if not isinstance(provider_pins, dict) or set(provider_pins) - {'codex-openai', 'claude', 'grok-cli', 'agy'}:
        raise ValueError('Only fixed private provider binary pins are accepted')
    if 'agy' in provider_pins:
        if agy_model is None or agy_global_rules_sha256 is AGY_RULES_UNSET:
            raise ValueError('AGY requires explicit agyModel and agyGlobalRulesSha256 configuration')
    elif agy_model is not None or agy_global_rules_sha256 is not AGY_RULES_UNSET:
        raise ValueError('AGY configuration requires its pinned engine')
    engines = {'ollama': PersonalOllamaEngine()}
    for name in sorted(provider_pins):
        engines[name] = ExternalEngine(name, _pin(provider_pins[name]),
            codex_model if name == 'codex-openai' else agy_model if name == 'agy' else None,
            agy_global_rules_sha256 if name == 'agy' else None)
    if codex_model is not None and 'codex-openai' not in engines:
        raise ValueError('A Codex model requires its pinned engine')
    return engines
