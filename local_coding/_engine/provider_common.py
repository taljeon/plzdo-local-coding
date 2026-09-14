"""Bounded input validation; this module contains no provider transport."""
import hashlib
import os
import re

MAX_BUNDLE_BYTES = 96000
MAX_RESULT_BYTES = 2 * 1024 * 1024


class ContractError(ValueError):
    """The packet or owned candidate is outside the implemented capability."""


def require(condition, message):
    if not condition:
        raise ContractError(message)


class ProviderError(RuntimeError):
    """A transport or its structured evidence could not be accepted."""


def validate_bundle(bundle):
    if not isinstance(bundle, str) or not bundle.strip() or '\0' in bundle:
        raise ProviderError('Bundle must be nonempty text without NUL bytes')
    if len(bundle.encode('utf-8')) > MAX_BUNDLE_BYTES:
        raise ProviderError('Bundle exceeds the scoped 96000-byte limit')
    patterns = (
        r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        r'\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{25,}|xox[baprs]-[A-Za-z0-9-]{15,})',
        r'(?i)\bauthorization\s*:\s*bearer\s+\S+',
        r'(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*[\'"][^\'"\n]{8,}[\'"]',
    )
    if any(re.search(pattern, bundle) for pattern in patterns):
        raise ProviderError('Bundle contains credential-like material; prepare a smaller safe bundle')
    return hashlib.sha256(bundle.encode('utf-8')).hexdigest()


def require_active_session():
    denied = ('META_HARNESS_AGENT_CONTEXT', 'META_HARNESS_SCHEDULED_AUTOMATION',
              'META_HARNESS_HEARTBEAT_LANE', 'CI')
    if any(os.environ.get(key, '').strip().lower() not in {'', '0', 'false', 'no'}
           for key in denied):
        raise ProviderError('Interactive browser work requires an active user session')
