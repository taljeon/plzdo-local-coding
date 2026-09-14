from pathlib import Path
import subprocess
import sys

import jsonschema


def test_private_parent_and_scope_cli_with_real_read_only_core_verifier():
    scenario = Path(__file__).with_name('private_parent_scenario.py')
    dependency_parent = Path(jsonschema.__file__).resolve().parent.parent
    result = subprocess.run([sys.executable, '-s', '-B', str(scenario), str(dependency_parent)],
                            capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"provider_calls": 0' in result.stdout
