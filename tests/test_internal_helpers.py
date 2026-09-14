"""Direct helper denial and fixed owned-worker startup; no models or listeners."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

import ollama_engine
from provider_common import ContractError

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / 'local_coding' / '_engine'
HELPERS = ('generate_edits.py', 'generate_stream.py', 'run_bounded.py', 'workflow_preview.py')


def helper_arguments(name, root):
    # Invalid generation input prevents a real model request even if a future
    # regression accidentally reinstates the obsolete parser/main path.
    request = root / 'request.json'
    request.write_text('{"model":"invalid-fixture","stream":false}\n')
    if name == 'generate_edits.py':
        return [str(request), str(root / 'response.json')]
    if name == 'generate_stream.py':
        return ['--profile', str(root / 'missing-profile.json'), str(request), str(root / 'response.json')]
    if name == 'run_bounded.py':
        marker = root / 'unexpected-child'
        return ['--cwd', str(root), '--evidence-dir', str(root / 'process'), '--timeout-seconds', '1', '--',
                sys.executable, '-I', '-S', '-B', '-c',
                'from pathlib import Path;Path(' + repr(str(marker)) + ').write_text("unexpected")']
    candidate = root / 'candidate'
    candidate.mkdir()
    (candidate / 'index.html').write_text('<!doctype html><title>Fixture</title>\n')
    return ['--candidate', str(candidate), '--allowed-path', 'index.html',
            '--evidence-dir', str(root / 'preview'), '--packet-sha256', 'a' * 64, '--ttl-seconds', '1']


def snapshot(root):
    return {str(path.relative_to(root)): path.read_bytes() if path.is_file() else None
            for path in root.rglob('*')}


@pytest.mark.parametrize('name', HELPERS)
@pytest.mark.parametrize('mode', ('script', 'module'))
def test_direct_main_refuses_before_arguments_or_side_effects(tmp_path, name, mode):
    arguments = helper_arguments(name, tmp_path)
    before = snapshot(tmp_path)
    if mode == 'script':
        command = [sys.executable, '-I', '-S', '-B', str(ENGINE / name), *arguments]
    else:
        driver = ('import runpy,sys;sys.path.insert(0,sys.argv.pop(1));'
                  'name=sys.argv.pop(1);runpy.run_module(name,run_name="__main__")')
        command = [sys.executable, '-I', '-S', '-B', '-c', driver, str(ROOT),
                   'local_coding._engine.' + name.removesuffix('.py'), *arguments]
    child = subprocess.run(command, capture_output=True, text=True, timeout=5,
                           env={**os.environ, 'LOCAL_CODING_STATE_ROOT': str(tmp_path / 'unused-state')})
    assert child.returncode != 0
    assert child.stdout == ''
    assert child.stderr.strip() == 'INTERNAL_HELPER_REQUIRES_KERNEL'
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize('name', HELPERS)
def test_direct_help_is_not_an_internal_unlock(name):
    child = subprocess.run([sys.executable, '-I', '-S', '-B', str(ENGINE / name), '--help'],
                           capture_output=True, text=True, timeout=5)
    assert child.returncode != 0 and child.stdout == ''
    assert child.stderr.strip() == 'INTERNAL_HELPER_REQUIRES_KERNEL'


@pytest.mark.parametrize('name', ('generate_edits.py', 'generate_stream.py'))
def test_owned_generation_entry_can_run_actual_help_without_io(tmp_path, name):
    child = subprocess.run(ollama_engine._generation_command(name, '--help'), cwd=tmp_path,
                           capture_output=True, text=True, timeout=5)
    assert child.returncode == 0, child.stderr
    assert 'request' in child.stdout and 'response' in child.stdout
    if name == 'generate_stream.py':
        assert '--profile' in child.stdout
    assert list(tmp_path.iterdir()) == []


def test_owned_generation_entry_has_a_fixed_script_allowlist():
    for name in ('run_bounded.py', 'workflow_preview.py', '../generate_stream.py'):
        with pytest.raises(ContractError, match='Unknown generation helper'):
            ollama_engine._generation_command(name, '--help')
