from pathlib import Path
import subprocess
import sys

import jsonschema


def test_private_composition_consumes_real_kernel_and_shared_pipeline():
    scenario = Path(__file__).with_name('kernel_consumer_scenario.py')
    dependencies = Path(jsonschema.__file__).resolve().parent.parent
    result = subprocess.run([sys.executable, '-s', '-B', str(scenario), str(dependencies)],
                            capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"provider_calls": 0' in result.stdout


def test_agy_review_reuses_real_private_approval_and_nonrefundable_ledger():
    scenario = Path(__file__).with_name('agy_kernel_scenario.py')
    dependencies = Path(jsonschema.__file__).resolve().parent.parent
    result = subprocess.run([sys.executable, '-s', '-B', str(scenario), str(dependencies)],
                            capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"failed_send_consumed": true' in result.stdout
    assert '"provider_calls": 0' in result.stdout
