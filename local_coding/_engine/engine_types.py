"""Immutable, data-only composition boundary; no path grants or plugin loading."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import math
from pathlib import Path
import re
import time
from types import MappingProxyType
from typing import Protocol

from json_codec import canonical_bytes, strict_json

MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_BYTES = 256 * 1024
CLEANUP_SCHEMA = 'plzdo.engine-cleanup.v1'
RETRYABLE_ENGINE_CODES = frozenset({'INVALID_CONTENT_JSON', 'INVALID_CONTENT_OBJECT',
                                   'INVALID_CONTENT_UNICODE'})


def _identifier(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}', value) is not None


def thaw(value):
    if isinstance(value, Mapping):
        return {key: thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [thaw(child) for child in value]
    return value


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(child) for child in value)
    return value


def frozen_mapping(value):
    if not isinstance(value, Mapping):
        raise ValueError('Engine evidence must be a JSON object')
    encoded = canonical_bytes(thaw(value))
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise ValueError('Engine evidence exceeds the byte limit')
    return _freeze(strict_json(encoded))


@dataclass(frozen=True)
class EngineIdentity:
    engine_id: str
    roles: tuple[str, ...]
    implementation_sha256: str

    def __post_init__(self):
        if (not _identifier(self.engine_id) or type(self.roles) is not tuple
                or not self.roles or len(self.roles) > 8
                or not all(_identifier(role) for role in self.roles)
                or len(set(self.roles)) != len(self.roles)
                or type(self.implementation_sha256) is not str
                or re.fullmatch(r'[a-f0-9]{64}', self.implementation_sha256) is None):
            raise ValueError('Invalid immutable engine identity')


@dataclass(frozen=True)
class Work:
    operation: str
    prompt_bytes: bytes
    schema_bytes: bytes
    profile_bytes: bytes
    timeout_seconds: int
    evidence_dir: Path
    reservation_id: str
    deadline_monotonic: float = field(init=False)

    def __post_init__(self):
        created = time.monotonic()
        if type(created) not in (int, float) or not math.isfinite(created):
            raise ValueError('Invalid monotonic work clock')
        if not _identifier(self.operation) or not _identifier(self.reservation_id):
            raise ValueError('Invalid work operation/reservation identity')
        for field, maximum in (('prompt_bytes', 96000), ('schema_bytes', 128 * 1024),
                               ('profile_bytes', 64 * 1024)):
            raw = getattr(self, field)
            if type(raw) is not bytes or not 0 < len(raw) <= maximum:
                raise ValueError('Work contains missing or oversized ' + field)
            value = strict_json(raw)
            if canonical_bytes(value) != raw:
                raise ValueError('Work bytes must be canonical JSON: ' + field)
        if type(strict_json(self.prompt_bytes)) is not str:
            raise ValueError('Work prompt must encode one JSON string')
        if not isinstance(strict_json(self.schema_bytes), dict) or not isinstance(strict_json(self.profile_bytes), dict):
            raise ValueError('Work schema/profile must encode JSON objects')
        if type(self.timeout_seconds) is not int or not 10 <= self.timeout_seconds <= 7200:
            raise ValueError('Invalid work timeout')
        deadline = float(created + self.timeout_seconds)
        if not math.isfinite(deadline):
            raise ValueError('Invalid monotonic work deadline')
        object.__setattr__(self, 'deadline_monotonic', deadline)
        if not isinstance(self.evidence_dir, Path) or not self.evidence_dir.is_absolute():
            raise ValueError('Work evidence destination must be absolute')


@dataclass(frozen=True)
class WorkResult:
    payload_bytes: bytes
    identity: EngineIdentity
    evidence: Mapping
    cleanup: Mapping

    def __post_init__(self):
        if type(self.payload_bytes) is not bytes or not 0 < len(self.payload_bytes) <= MAX_PAYLOAD_BYTES:
            raise ValueError('Invalid engine payload bytes')
        if not isinstance(self.identity, EngineIdentity):
            raise ValueError('Engine result lacks immutable identity')
        object.__setattr__(self, 'evidence', frozen_mapping(self.evidence))
        object.__setattr__(self, 'cleanup', frozen_mapping(self.cleanup))


class EngineFailure(RuntimeError):
    """Typed failure. Retry requires explicit closed cleanup and an approved slot."""
    def __init__(self, code, message, *, evidence, cleanup, retryable=False):
        if type(code) is not str or re.fullmatch(r'[A-Z][A-Z0-9_]{0,119}', code) is None:
            raise ValueError('Invalid engine failure code')
        if type(message) is not str or not 0 < len(message) <= 2000 or type(retryable) is not bool:
            raise ValueError('Invalid engine failure details')
        super().__init__(code + ': ' + message)
        self.code, self.retryable = code, retryable
        self.evidence, self.cleanup = frozen_mapping(evidence), frozen_mapping(cleanup)


class Engine(Protocol):
    def identity(self) -> EngineIdentity: ...
    def execute(self, work: Work) -> WorkResult: ...


def require_cleanup(receipt):
    required = {'schema', 'completed', 'passed', 'owned', 'started'}
    if (not isinstance(receipt, Mapping) or not required <= receipt.keys()
            or receipt['schema'] != CLEANUP_SCHEMA
            or any(type(receipt[key]) is not bool for key in ('completed', 'passed', 'owned', 'started'))
            or receipt['completed'] is not True or receipt['passed'] is not True
            or (receipt['started'] and not receipt['owned'])):
        raise EngineFailure('ENGINE_CLEANUP_FAILED', 'Owned cleanup has not completed with explicit evidence',
                            evidence={}, cleanup=receipt if isinstance(receipt, Mapping) else {})
    return receipt


def no_start_cleanup():
    return {'schema': CLEANUP_SCHEMA, 'completed': True, 'passed': True,
            'owned': False, 'started': False}
