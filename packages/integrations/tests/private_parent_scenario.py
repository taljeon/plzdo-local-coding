"""Real private CLI -> shared Kernel -> read-only PlzDo verifier on owned fixtures."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

BASE = Path(__file__).resolve().parents[1]
RUNTIME = BASE.parents[1]
CORE = RUNTIME.parent / 'plzdo'
DEPENDENCIES = Path(sys.argv[1])
sys.path[:0] = [str(CORE), str(DEPENDENCIES)]
from plzdo_local_code_adapter import codec

spec = importlib.util.spec_from_file_location('_private_parent_fixture', CORE / 'tests/adapter/fixtures.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
ENTRY = """
from pathlib import Path
import sys
base, dependencies = Path(sys.argv[1]), Path(sys.argv[2])
runtime = base.parents[1]
sys.path[:0] = [str(base), str(runtime), str(runtime.parent/'plzdo'), str(dependencies)]
from plzdo_private_overlay.cli import main
raise SystemExit(main(sys.argv[3:]))
"""


def cli(config, *arguments, ok=True):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(('LOCAL_CODING_', 'PLZDO_'))}
    interpreter = config.parent / 'fixture-python'
    result = subprocess.run([str(interpreter), '-s', '-B', '-c', ENTRY, str(BASE), str(DEPENDENCIES),
                             '--config', str(config), *arguments],
                            capture_output=True, text=True, env=environment, timeout=30)
    assert result.stderr == '', result.stderr
    value = json.loads(result.stdout)
    assert (result.returncode == 0) is ok, value
    assert value['schemaVersion'] == 'plzdo.private-result.v1'
    return value['result'] if ok else value


def setup(root):
    root.mkdir(mode=0o700)
    envelope, _ = fixtures.fixture(root, CORE)
    binary = root / 'synthetic-codex'
    binary.write_bytes(b'fixture; never execute a provider\n')
    binary.chmod(0o700)
    config = root / 'private.json'
    fixtures.write_json(config, {'schemaVersion': 'plzdo.private-config.v1',
        'stateRoot': str(root / 'runtime-state'), 'providerPins': {'codex-openai': {
            'path': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}}})
    descriptor_sha = codec.digest(envelope['request']['verifier'])
    result = cli(config, 'trust-verifier', '--verifier', str(root / 'pins/verifier.json'),
                 '--descriptor-sha256', descriptor_sha, '--confirm', 'TRUST PARENT VERIFIER ' + descriptor_sha)
    assert result['execution_authorized'] is False and result['parent_approved'] is False
    return config, envelope['request']['expiresAt']


def arguments(root, expiry):
    return ('--parent-reference', str(root / 'pins/parent-reference.json'),
            '--verifier', str(root / 'pins/verifier.json'), '--expires-at', expiry,
            '--max-live-calls', '2', '--allow-engine', 'ollama', '--allow-engine', 'codex-openai')


TEMPLATE = {'kind': 'artifact-create', 'id': 'template-text', 'objective': 'Create fixture text',
            'allowed_paths': ['result.txt'], 'generation_profile': 'huihui-qwen38-q6kl-v1',
            'task_category': 'product-development', 'local_attempts': 1,
            'validation_packs': [{'type': 'text', 'path': 'result.txt', 'required': ['fixture']}]}
SCOPE = {'schemaVersion': 'plzdo.task-scope.v2',
         'templates': {'text': {'packet': TEMPLATE, 'basePolicy': {'mode': 'exact'}}}}

with tempfile.TemporaryDirectory(prefix='plzdo-private-parent-') as temporary:
    outer = Path(temporary).resolve()
    root = outer / 'exact'
    config, expiry = setup(root)
    fixtures.write_json(root / 'packet.json', TEMPLATE)
    prepared = cli(config, 'parent-prepare', '--packet', str(root / 'packet.json'),
                   *arguments(root, expiry))
    request = prepared['request']
    assert prepared['execution_authorized'] is False and prepared['provider_calls'] == 0
    assert prepared['marker'] == codec.MARKER_PREFIX + request['requestSha256']
    assert request['execution']['allowedEngines'] == ['codex-openai', 'ollama']
    assert request['packet']['authorityId'] == request['id']
    assert not (root / 'runtime-state/contracts').exists()
    cli(config, 'parent-adopt', '--id', request['id'], '--request-sha256', request['requestSha256'], ok=False)
    fixtures.save_formalization(request, fixtures.formalization(request))
    adopted = cli(config, 'parent-adopt', '--id', request['id'], '--request-sha256', request['requestSha256'])
    assert adopted['document']['schemaVersion'] == 'plzdo.overlay.parent-exact.v2'
    assert adopted['atomic_lease'] is False
    ledger_path = root / 'runtime-state/ledgers' / (request['id'] + '.json')
    original = ledger_path.read_bytes()
    cli(config, 'parent-adopt', '--id', request['id'], '--request-sha256', request['requestSha256'])
    assert ledger_path.read_bytes() == original
    fixtures.save_formalization(request, fixtures.formalization(request, status='draft'))
    cli(config, 'parent-adopt', '--id', request['id'], '--request-sha256', request['requestSha256'], ok=False)
    assert ledger_path.read_bytes() == original

    root = outer / 'scoped'
    config, expiry = setup(root)
    fixtures.write_json(root / 'scope.json', SCOPE)
    prepared = cli(config, 'parent-prepare-scope', '--scope', str(root / 'scope.json'),
        *arguments(root, expiry), '--max-total-runs', '1', '--max-children', '1')
    request = prepared['request']
    assert prepared['marker'] == codec.SCOPE_MARKER_PREFIX + request['requestSha256']
    fixtures.write_json(root / 'child.json', {**TEMPLATE, 'id': 'child-one'})
    cli(config, 'scope-admit', '--id', request['id'], '--template', 'text',
        '--packet', str(root / 'child.json'), ok=False)
    fixtures.save_formalization(request, fixtures.formalization(request))
    adopted = cli(config, 'parent-adopt', '--id', request['id'], '--request-sha256', request['requestSha256'])
    assert adopted['document']['schemaVersion'] == 'plzdo.overlay.parent-scope.v2'
    admitted = cli(config, 'scope-admit', '--id', request['id'], '--template', 'text', '--packet', str(root / 'child.json'))
    assert admitted['new_operator_approval'] is False
    assert admitted['child']['packet']['authorityId'] == request['id']
    assert admitted['child']['binding']['allowedEngines'] == ['codex-openai', 'ollama']
    fixtures.write_json(root / 'child.json', {**TEMPLATE, 'id': 'child-two'})
    cli(config, 'scope-admit', '--id', request['id'], '--template', 'text',
        '--packet', str(root / 'child.json'), ok=False)
    status = cli(config, 'status', '--id', request['id'])
    assert status['ledger']['records'] == []
    assert len(list((root / 'runtime-state/ledgers').glob('*.json'))) == 1

    standalone = cli(config, 'scope-draft', '--id', 'standalone-scope', '--scope', str(root / 'scope.json'),
        '--expires-at', expiry, '--max-live-calls', '2', '--allow-engine', 'ollama',
        '--allow-engine', 'codex-openai', '--max-total-runs', '1', '--max-children', '1')
    assert standalone['document']['schemaVersion'] == 'plzdo.overlay.scope.v2'
    assert standalone['document']['execution']['taskScope']['templates']['text']['packet']['authorityId'] == 'standalone-scope'
    approved = cli(config, 'scope-approve', '--id', 'standalone-scope',
        '--payload-sha256', standalone['approval_payload_sha256'], '--confirm', standalone['required_confirmation'])
    assert approved['status'] == 'approved'
    fixtures.write_json(root / 'child.json', {**TEMPLATE, 'id': 'local-child', 'authorityId': 'wrong-root'})
    cli(config, 'scope-admit', '--id', 'standalone-scope', '--template', 'text',
        '--packet', str(root / 'child.json'), ok=False)
    fixtures.write_json(root / 'child.json', {**TEMPLATE, 'id': 'local-child'})
    child = cli(config, 'scope-admit', '--id', 'standalone-scope', '--template', 'text', '--packet', str(root / 'child.json'))
    assert child['child']['packet']['authorityId'] == 'standalone-scope'
    assert cli(config, 'status', '--id', 'standalone-scope')['ledger']['records'] == []
    print(json.dumps({'private_exact_parent': 'passed', 'private_scoped_parent': 'passed',
                      'private_standalone_scope': 'passed', 'adoption_replay': 'preserved',
                      'unapproved_or_revoked_parent': 'refused', 'wrong_root_or_extra_child': 'refused',
                      'provider_calls': 0, 'core_verifier': 'real-read-only-process'}))
