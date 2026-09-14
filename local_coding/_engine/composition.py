"""Two source-owned compositions; never deserialize a Policy from task input.

This is trusted in-process reuse, not a sandbox against hostile Python callers.
One process has one fixed state/policy/engine composition, as the prior CLI did.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Mapping

from state_io import canonical_bytes, require

_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ROLES = frozenset({"generate", "review", "design-review"})


@dataclass(frozen=True)
class Policy:
    namespace: str = "plzdo.local"
    engine_roles: Mapping[str, tuple[str, ...]] = field(default_factory=lambda: {"ollama": ("generate",)})
    generation_order: tuple[str, ...] = ("ollama",)
    generation_limits: Mapping[str, int] = field(default_factory=lambda: {"ollama": 2})
    high_risk_engines: tuple[str, ...] = ()
    admission_engines: tuple[str, ...] = ()
    source_files: tuple[Path, ...] = ()

    def __post_init__(self):
        require(self.namespace in {"plzdo.local", "plzdo.overlay"}, "Unsupported composition namespace")
        roles = {key: tuple(value) for key, value in self.engine_roles.items()}
        require(bool(roles) and len(roles) <= 5, "Invalid fixed engine registry size")
        for identifier, values in roles.items():
            require(isinstance(identifier, str) and _ID.fullmatch(identifier), "Invalid fixed engine identifier")
            require(bool(values) and len(set(values)) == len(values) and set(values) <= _ROLES,
                    "Invalid fixed engine roles")
        limits = dict(self.generation_limits)
        require(set(limits) <= set(roles), "Generation limit outside registry")
        require(all(type(value) is int and 1 <= value <= 2 for value in limits.values()),
                "Invalid fixed generation limit")
        order, high, admission = map(tuple, (self.generation_order, self.high_risk_engines, self.admission_engines))
        require(len(set(order)) == len(order) and set(order) == set(limits), "Generation order/limit mismatch")
        require(all("generate" in roles[key] for key in order), "Non-generator in generation order")
        require(len(set(high)) == len(high) and set(high) <= set(order), "Invalid high-risk route")
        require(len(set(admission)) == len(admission) and set(admission) <= set(roles)
                and all("review" in roles[key] for key in admission), "Invalid admission engines")
        sources = tuple(Path(path).absolute() for path in self.source_files)
        require(len(sources) <= 128 and len(set(sources)) == len(sources), "Invalid composition source closure")
        if self.namespace == "plzdo.local":
            require(roles == {"ollama": ("generate",)} and order == ("ollama",)
                    and limits == {"ollama": 2} and not high and not admission and not sources,
                    "Public composition cannot be expanded")
        else:
            require(bool(sources), "Private composition needs its source identity")
        object.__setattr__(self, "engine_roles", MappingProxyType(roles))
        object.__setattr__(self, "generation_limits", MappingProxyType(limits))
        object.__setattr__(self, "generation_order", order)
        object.__setattr__(self, "high_risk_engines", high)
        object.__setattr__(self, "admission_engines", admission)
        object.__setattr__(self, "source_files", sources)

    def schema_version(self, kind):
        require(kind in {"exact", "scope", "parent-exact", "parent-scope"}, "Unsupported authority kind")
        return self.namespace + "." + kind + ".v2"

    def operations(self, engine_ids):
        selected = set(engine_ids)
        require(selected <= set(self.engine_roles), "Engine outside fixed composition")
        return [{"engineId": identifier, "role": role}
                for identifier in sorted(selected) for role in sorted(self.engine_roles[identifier])]

    def generation_plan(self, packet, engine_ids):
        if packet.get("kind") == "compute-analysis":
            return []
        selected = set(engine_ids)
        require(selected <= set(self.engine_roles), "Engine outside fixed composition")
        risk = packet.get("risk", "normal")
        require(risk in {"normal", "high"}, "Invalid task risk")
        order = self.high_risk_engines if risk == "high" else self.generation_order
        generators = [identifier for identifier in order if identifier in selected]
        if risk == "high" and any("generate" in self.engine_roles[item] for item in selected):
            require(bool(generators), "HIGH_RISK_LOCAL_UNSUPPORTED")
        plan = []
        for identifier in generators:
            count = self.generation_limits[identifier]
            if identifier == "ollama":
                requested = packet.get("local_attempts", 2)
                require(type(requested) is int and 1 <= requested <= 2, "Invalid local attempt count")
                count = min(requested, count)
            for _ in range(count):
                plan.append({"engineId": identifier, "role": "generate", "ordinal": len(plan) + 1})
        require(len(plan) <= 3, "Generation plan exceeds bounded composition")
        return plan


PUBLIC_POLICY = Policy()
_context = None


def configure(policy, engines, state_root):
    global _context
    require(isinstance(policy, Policy), "Source-owned Policy required")
    root = Path(state_root).absolute()
    require(root == root.resolve(strict=False) and root != Path("/"), "Invalid state root")
    values = dict(engines)
    require(set(values) == set(policy.engine_roles), "Fixed engine registry mismatch")
    candidate = (policy, MappingProxyType(values), root)
    if _context is not None:
        require(_context[0] == policy and _context[2] == root
                and all(_context[1][key] is values[key] for key in values),
                "COMPOSITION_CHANGED_USE_A_NEW_PROCESS")
        return
    # Never change the operator's global settings. This is this CLI process's
    # explicit state argument, fixed before legacy flat helpers are imported.
    os.environ["LOCAL_CODING_STATE_ROOT"] = str(root)
    _context = candidate
    current_engine_pins(tuple(values))


def current_policy():
    return _context[0] if _context is not None else PUBLIC_POLICY


def current_state_root():
    require(_context is not None, "Runtime composition is not configured")
    return _context[2]


def engine(identifier, role):
    require(_context is not None and identifier in _context[1], "Engine not in fixed registry")
    require(role in current_policy().engine_roles[identifier], "Operation outside fixed engine roles")
    current_engine_pins((identifier,))
    return _context[1][identifier]


def current_engine_pins(engine_ids):
    require(_context is not None, "Runtime composition is not configured")
    selected = tuple(engine_ids)
    require(len(set(selected)) == len(selected) and set(selected) <= set(_context[1]), "Invalid selected engines")
    result = {}
    for identifier in sorted(selected):
        observed = _context[1][identifier].identity()
        require(observed.engine_id == identifier
                and tuple(observed.roles) == current_policy().engine_roles[identifier]
                and isinstance(observed.implementation_sha256, str)
                and _SHA.fullmatch(observed.implementation_sha256), "Engine identity mismatch")
        result[identifier] = {"implementationSha256": observed.implementation_sha256,
                              "roles": list(observed.roles)}
    return result


def _source_hash(path):
    require(path.suffix in {".py", ".json", ".toml"} and path.resolve(strict=True) == path,
            "Unsafe composition source")
    require(not any(part.lower() in {".ssh", ".aws", ".codex", ".claude", ".grok", ".env"}
                    for part in path.parts), "Sensitive composition source")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022
                and before.st_size <= 1024 * 1024, "Unsafe composition source identity")
        data = source.read(1024 * 1024 + 1)
        after, current = os.fstat(source.fileno()), path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(len(data) == before.st_size and identity(before) == identity(after) == identity(current),
                "Composition source changed")
    return hashlib.sha256(data).hexdigest()


def policy_data():
    policy = current_policy()
    return {"namespace": policy.namespace, "engineRoles": {k: list(v) for k, v in policy.engine_roles.items()},
            "generationOrder": list(policy.generation_order), "generationLimits": dict(policy.generation_limits),
            "highRiskEngines": list(policy.high_risk_engines), "admissionEngines": list(policy.admission_engines),
            "compositionSourceSha256": [_source_hash(path) for path in policy.source_files],
            "enginePins": current_engine_pins(tuple(policy.engine_roles)), "crashRefund": False,
            "implicitLegacyBudgetImport": False}
