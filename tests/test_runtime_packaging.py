"""Static package selection and isolated synthetic-prefix launches, without builds."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

import pytest

import host_paths

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / 'bin' / 'plzdo_runtime_entry.py'
LAUNCHER = ROOT / 'bin' / 'plzdo-local-code'


def prefix_fixture(root, name='prefix'):
    prefix = root / name
    binary = prefix / 'bin'
    binary.mkdir(parents=True)
    for path in (ENTRY, LAUNCHER):
        shutil.copy2(path, binary / path.name)
    (binary / 'python3').symlink_to(sys.executable)
    for name in ('local_coding', 'plzdo_local', 'plzdo_local_code_adapter'):
        folder = prefix / name
        folder.mkdir()
        (folder / '__init__.py').write_text('__version__ = "0.3.0"\n')
    (prefix / 'local_coding' / 'cli.py').write_text(
        'import sys,json,plzdo_local,plzdo_local_code_adapter\n'
        'def main(argv):\n'
        '    print(json.dumps({"isolated":sys.flags.isolated,"no_site":sys.flags.no_site,'
        '"no_bytecode":sys.dont_write_bytecode,"argv":argv,"sys_path":sys.path,'
        '"core_files":[plzdo_local.__file__,plzdo_local_code_adapter.__file__]}))\n'
        '    return 0\n')
    return prefix


def source_fixture(root):
    runtime = prefix_fixture(root, 'plzdo-local-coding')
    (runtime / 'pyproject.toml').write_text('[project]\nname="plzdo-local-runtime"\n')
    core = root / 'plzdo'
    core.mkdir()
    for name in ('plzdo_local', 'plzdo_local_code_adapter'):
        (runtime / name).rename(core / name)
    return runtime, core


def test_metadata_selects_exact_public_runtime_and_companion():
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    assert project['project']['name'] == 'plzdo-local-runtime'
    assert project['project']['version'] == '0.3.0'
    assert project['project']['requires-python'] == '>=3.11'
    assert project['project']['dependencies'] == ['plzdo==0.3.0', 'jsonschema==4.25.1']
    assert 'scripts' not in project['project']
    packaged = project['tool']['setuptools']
    assert packaged['packages'] == ['local_coding'] and packaged['include-package-data'] is False
    assert packaged['script-files'] == ['bin/plzdo-local-code', 'bin/plzdo_runtime_entry.py']
    selected = packaged['package-data']['local_coding']
    assert len(selected) == len(set(selected))
    assert not any('*' in path for path in selected)
    assert {'_engine/' + name for name in host_paths.PERMISSION_SOURCE_FILES} <= set(selected)
    assert not any(fragment in path for path in selected for fragment in (
        'workflow_providers', 'grok_admission', 'grok_review_only', 'automation', 'pilot', 'structured_complete'))


def test_fixed_prefix_launcher_ignores_python_startup_and_ambient_paths(tmp_path):
    prefix = prefix_fixture(tmp_path)
    attacker = tmp_path / 'ambient'
    attacker.mkdir()
    marker = tmp_path / 'unexpected-startup'
    injected = 'from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n'
    (attacker / 'sitecustomize.py').write_text(injected)
    (prefix / 'sitecustomize.py').write_text(injected)
    (prefix / 'malicious.pth').write_text('import pathlib; pathlib.Path(' + repr(str(marker)) + ').touch()\n')
    env = {**os.environ, 'PYTHONPATH': str(attacker), 'PYTHONSTARTUP': str(attacker / 'sitecustomize.py'),
           'PYTHONHOME': str(attacker), 'PATH': str(attacker)}
    child = subprocess.run([str(prefix / 'bin' / 'plzdo-local-code'), '--version'],
                           env=env, capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    receipt = json.loads(child.stdout)
    assert receipt['isolated'] == 1 and receipt['no_site'] == 1 and receipt['no_bytecode'] is True
    assert str(prefix) not in receipt['sys_path'] and str(attacker) not in receipt['sys_path']
    assert not marker.exists()


def test_launcher_rejects_ambiguous_and_symlinked_package_roots(tmp_path):
    prefix = prefix_fixture(tmp_path)
    second = prefix / 'lib' / ('python' + '.'.join(map(str, sys.version_info[:2]))) / 'site-packages' / 'local_coding'
    second.mkdir(parents=True)
    (second / '__init__.py').write_text('__version__="0.3.0"\n')
    command = [str(prefix / 'bin' / 'plzdo-local-code'), '--version']
    child = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert child.returncode != 0 and 'EXACTLY_ONE_FIXED_PACKAGE_REQUIRED' in child.stderr
    shutil.rmtree(second)
    original = prefix / 'plzdo_local'
    moved = tmp_path / 'foreign-core'
    original.rename(moved)
    original.symlink_to(moved, target_is_directory=True)
    child = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert child.returncode != 0 and 'PACKAGE_PREFIX_IDENTITY_INVALID' in child.stderr


def test_source_launcher_uses_only_exact_sibling_core(tmp_path):
    runtime, core = source_fixture(tmp_path)
    for name in ('plzdo_local', 'plzdo_local_code_adapter'):
        shutil.copytree(core / name, runtime / name)
    env = {**os.environ, 'PLZDO_RUNTIME_CORE_ROOT': str(runtime), 'PYTHONPATH': str(runtime)}
    child = subprocess.run([str(runtime / 'bin' / 'plzdo-local-code'), '--version'],
                           env=env, capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    receipt = json.loads(child.stdout)
    assert all(Path(path).parent.parent == core for path in receipt['core_files'])
    assert str(core) not in receipt['sys_path']


@pytest.mark.parametrize('kind,error', [
    ('missing', 'EXACTLY_ONE_FIXED_PACKAGE_REQUIRED'),
    ('core-symlink', 'PACKAGE_PREFIX_IDENTITY_INVALID'),
    ('package-symlink', 'PACKAGE_PREFIX_IDENTITY_INVALID'),
    ('init-symlink', 'PACKAGE_PREFIX_IDENTITY_INVALID'),
    ('metadata-symlink', 'SOURCE_LAYOUT_IDENTITY_INVALID'),
    ('metadata-directory', 'SOURCE_LAYOUT_IDENTITY_INVALID'),
])
def test_source_launcher_rejects_invalid_layout_without_prefix_fallback(tmp_path, kind, error):
    runtime, core = source_fixture(tmp_path)
    marker = tmp_path / 'unexpected-core-import'
    for name in ('plzdo_local', 'plzdo_local_code_adapter'):
        package = runtime / name
        package.mkdir()
        (package / '__init__.py').write_text(
            'from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n__version__="0.3.0"\n')
    if kind == 'missing':
        core.rename(tmp_path / 'other-core')
    elif kind == 'metadata-directory':
        (runtime / 'pyproject.toml').unlink()
        (runtime / 'pyproject.toml').mkdir()
    else:
        source = {'core-symlink': core, 'package-symlink': core / 'plzdo_local',
                  'init-symlink': core / 'plzdo_local' / '__init__.py',
                  'metadata-symlink': runtime / 'pyproject.toml'}[kind]
        target = tmp_path / 'foreign'
        source.rename(target)
        source.symlink_to(target, target_is_directory=target.is_dir())
    env = {**os.environ, 'PYTHONPATH': str(runtime), 'PLZDO_RUNTIME_CORE_ROOT': str(runtime)}
    child = subprocess.run([str(runtime / 'bin' / 'plzdo-local-code'), '--version'],
                           env=env, capture_output=True, text=True, timeout=10)
    assert child.returncode != 0 and error in child.stderr
    assert not marker.exists()


def test_same_named_installed_prefix_keeps_own_core_without_source_marker(tmp_path):
    prefix = prefix_fixture(tmp_path, 'plzdo-local-coding')
    sibling = tmp_path / 'plzdo'
    sibling.mkdir()
    for name in ('plzdo_local', 'plzdo_local_code_adapter'):
        shutil.copytree(prefix / name, sibling / name)
    child = subprocess.run([str(prefix / 'bin' / 'plzdo-local-code'), '--version'],
                           capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    assert all(Path(path).parent.parent == prefix for path in json.loads(child.stdout)['core_files'])


@pytest.mark.parametrize('kind', ['other-root', 'missing-core', 'core-symlink', 'package-symlink', 'init-symlink'])
def test_development_harness_rejects_invalid_core_before_state_or_pytest(tmp_path, kind):
    runtime, core = source_fixture(tmp_path)
    scripts = runtime / 'scripts'
    scripts.mkdir()
    shutil.copy2(ROOT / 'scripts' / 'harness-env.sh', scripts / 'harness-env.sh')
    env = {**os.environ, 'PLZDO_RUNTIME_PROJECT_ROOT': str(runtime), 'PLZDO_RUNTIME_CORE_ROOT': str(core)}
    if kind == 'other-root':
        env['PLZDO_RUNTIME_CORE_ROOT'] = str(runtime)
    elif kind == 'missing-core':
        core.rename(tmp_path / 'other-core')
    else:
        source = {'core-symlink': core, 'package-symlink': core / 'plzdo_local',
                  'init-symlink': core / 'plzdo_local' / '__init__.py'}[kind]
        target = tmp_path / 'foreign'
        source.rename(target)
        source.symlink_to(target, target_is_directory=target.is_dir())
    marker = tmp_path / 'unexpected-scratch'
    commands = tmp_path / 'commands'
    commands.mkdir()
    (commands / 'mktemp').write_text('#!/bin/sh\n/usr/bin/touch "$SCRATCH_MARKER"\nexit 1\n')
    (commands / 'mktemp').chmod(0o700)
    env.update(PATH=str(commands) + ':/usr/bin:/bin', SCRATCH_MARKER=str(marker))
    child = subprocess.run(['/bin/sh', '-eu', str(scripts / 'harness-env.sh')],
                           env=env, capture_output=True, text=True, timeout=10)
    assert child.returncode != 0 and 'Runtime checks require' in child.stderr
    assert not marker.exists()


def test_source_version_uses_isolated_launcher_without_optional_dependencies():
    child = subprocess.run([str(LAUNCHER), '--version'], capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    assert '0.3.0' in child.stdout


def test_direct_unisolated_entry_refuses(tmp_path):
    child = subprocess.run([sys.executable, '-B', str(ENTRY), '--version'],
                           capture_output=True, text=True, timeout=10)
    assert child.returncode != 0
    assert 'isolated Python' in child.stderr


def test_policy_binds_package_schema_and_launcher_bytes(tmp_path, monkeypatch):
    engine = tmp_path / 'local_coding' / '_engine'
    engine.mkdir(parents=True)
    for name in host_paths.PERMISSION_SOURCE_FILES:
        path = engine / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# bounded synthetic engine source\n')
    for name in host_paths.PACKAGE_POLICY_SOURCE_FILES:
        path = engine.parent / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{}\n' if path.suffix == '.json' else '# bounded synthetic package source\n')
    binary = tmp_path / 'bin'
    binary.mkdir()
    for name in host_paths.LAUNCHER_SOURCE_FILES:
        (binary / name).write_text('# bounded synthetic launcher\n')
    monkeypatch.setattr(host_paths, 'SOURCE_DIRECTORY', engine)
    before = host_paths.permission_policy_fingerprint()
    (binary / 'plzdo_runtime_entry.py').write_text('# changed launcher\n')
    changed = host_paths.permission_policy_fingerprint()
    assert before != changed
    (engine.parent / 'api.py').write_text('# changed composition API\n')
    assert changed != host_paths.permission_policy_fingerprint()
    (engine.parent / 'schemas' / 'authority-common.schema.json').unlink()
    with pytest.raises(FileNotFoundError):
        host_paths.permission_policy_fingerprint()


def test_ollama_identity_cannot_capture_a_state_root_before_composition(tmp_path):
    engine = ROOT / 'local_coding' / '_engine'
    root = tmp_path / 'later-state'
    code = ('import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
            'import ollama_engine;engine=ollama_engine.OllamaEngine();engine.identity();'
            'assert "workflow_core" not in sys.modules;'
            'import composition;composition.configure(composition.PUBLIC_POLICY,{"ollama":engine},Path(sys.argv[2]));'
            'import workflow_core;assert workflow_core.DIRECTORY==Path(sys.argv[2]);'
            'assert not Path(sys.argv[2]).exists()')
    child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code, str(engine), str(root)],
                           capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr


def test_source_doctor_is_dependency_free_and_cannot_probe_live_model(tmp_path):
    state = tmp_path / 'untouched'
    child = subprocess.run([str(LAUNCHER), '--state-root', str(state), 'doctor'],
                           capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    output = json.loads(child.stdout)
    assert output['result']['provider_calls'] == 0
    assert output['result']['live_inference_supported'] is False
    assert not state.exists()


def test_retired_modules_and_aliases_are_absent_from_public_package():
    forbidden = ('automation.py', 'automation_entry.py', '_engine/workflow_providers.py',
                 '_engine/grok_admission.py', '_engine/grok_review_only.py', '_engine/admit_grok.py',
                 '_engine/automation_authority.py', '_engine/pilot.py', '_engine/policy.py',
                 '_engine/structured_complete.py', '_engine/check_candidate.py', '_engine/validated_edits.py')
    assert all(not (ROOT / 'local_coding' / name).exists() for name in forbidden)
    assert not hasattr(host_paths, 'contract_backend') and not hasattr(host_paths, 'legacy_hn_root')
