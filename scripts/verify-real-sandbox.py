"""Opt-in local proof using synthetic data and exact installed Python file reads.

No model/provider is called. The normal frozen checker still runs inside the
existing Codex offline sandbox; no unsandboxed retry or broad directory grant.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
ENGINE = PROJECT / 'local_coding/_engine'
sys.path.insert(0, str(ENGINE))


def main():
    # The existing sandbox deliberately denies global temp trees. Exercise the
    # real supported workspace/state boundary without removing those denies.
    evidence_root = PROJECT / 'evidence'
    evidence_root.mkdir(exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='real-sandbox-', dir=evidence_root)).resolve()
    state = root / 'state'
    state.mkdir(mode=0o700)
    os.environ['LOCAL_CODING_STATE_ROOT'] = str(state)
    os.environ.pop('LOCAL_CODING_RUNTIME_POLICY', None)
    os.environ.pop('LOCAL_CODING_RUNTIME_POLICY_SHA256', None)
    import workflow_validation as checks
    import host_paths
    candidate = root / 'candidate'
    candidate.mkdir(mode=0o700)
    (candidate / 'answer.py').write_text('def answer():\n    return 42\n')
    (candidate / 'answer.json').write_text('{"answer": 42}\n')
    (candidate / 'notes.md').write_text('Synthetic offline checker proof.\n')
    packs = [
        {'type': 'python-syntax', 'paths': ['answer.py']},
        {'type': 'json-schema', 'path': 'answer.json',
         'schema': {'type': 'object', 'additionalProperties': False,
                    'required': ['answer'], 'properties': {'answer': {'const': 42}}}},
        {'type': 'text', 'path': 'notes.md', 'required': ['Synthetic'], 'forbidden': ['FAILED']},
    ]
    for pack in packs:
        assert checks._run_builtin(pack, candidate)['passed']
    # Trace only already-imported public interpreter/dependency files. Never
    # walk user homes, account state, browser profiles, or arbitrary packages.
    prefix = Path(sys.prefix).resolve()
    base = Path(sys.base_prefix).resolve()
    files = {Path(sys.executable).resolve(), base / 'Python', prefix / 'pyvenv.cfg'}
    for module in list(sys.modules.values()):
        for attribute in ('__file__', '__cached__'):
            raw = getattr(module, attribute, None)
            if raw:
                p = Path(raw).resolve()
                if (p.is_relative_to(prefix) or p.is_relative_to(base)) and p.is_file() and not Path(raw).is_symlink():
                    files.add(p)
    for p in (base / 'lib').glob('*.dylib'):
        if p.is_file() and not p.is_symlink():
            files.add(p)
    # JSON Schema's public packaged schema resources are data, not user config.
    import jsonschema_specifications
    resources = Path(jsonschema_specifications.__file__).resolve().parent / 'schemas'
    for p in resources.rglob('*'):
        if p.is_file() and not p.is_symlink():
            files.add(p)
    # In the deliberately created private complete prefix, every dependency
    # is reviewed test-runtime material. Declare the whole exact file closure
    # so the controller can freeze it under its already read-only stage.
    if prefix.name == 'python-prefix' and prefix.parent.name.startswith('plzdo-runtime-checks.'):
        for p in prefix.rglob('*'):
            if p.is_file() and not p.is_symlink():
                files.add(p)
    binary = Path(sys.executable).resolve()
    reads = []
    for p in sorted(files):
        if not p.is_file() or p == binary:
            continue
        data = p.read_bytes()
        reads.append({'path': str(p), 'sha256': hashlib.sha256(data).hexdigest()})
    policy = {'schema': 'local-coding-runtime.v1',
              'executables': [{'command': 'python3', 'path': str(binary),
                               'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}],
              'read_files': reads}
    policy_path = root / 'python-runtime-policy.json'
    policy_path.write_text(json.dumps(policy, sort_keys=True))
    policy_path.chmod(0o600)
    os.environ['LOCAL_CODING_RUNTIME_POLICY'] = str(policy_path)
    os.environ['LOCAL_CODING_RUNTIME_POLICY_SHA256'] = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    host_paths.runtime_policy()
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in candidate.iterdir()}
    packet = {'allowed_paths': list(before), 'checks': [], 'validation_packs': packs,
              'timeout_seconds': 120}
    result = checks.run_artifact_checks(packet, candidate, root / 'verification')
    unchanged = before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in candidate.iterdir()}
    report = {'synthetic_data': True, 'model_calls': 0, 'provider_calls': 0,
              'root': str(root), 'read_file_count': len(reads), 'original_candidate_unchanged': unchanged,
              'sandbox_bypassed': False, 'result': result, 'passed': result['passed'] and unchanged}
    (root / 'report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
