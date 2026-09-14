"""Fixed flat-helper origins, including cached and transitive import paths."""
from pathlib import Path
import subprocess
import sys

import pytest

RUNTIME = Path(__file__).resolve().parents[1]
SCRIPT = r'''
import sys,types
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_coding._bootstrap import ENGINE_ROOT,engine_module
scenario=sys.argv[2]
if scenario=='transitive':
    foreign=types.ModuleType('json_codec');foreign.__file__='/synthetic/foreign/json_codec.py'
    sys.modules['json_codec']=foreign
    try:engine_module('engine_types')
    except RuntimeError as error:assert str(error)=='RUNTIME_MODULE_COLLISION'
    else:raise AssertionError('Foreign transitive helper was accepted')
    assert 'engine_types' not in sys.modules
else:
    original=engine_module('engine_types')
    sys.path.insert(0,'/synthetic/caller')
    assert engine_module('engine_types') is original
    assert sys.path[0]==str(ENGINE_ROOT)
print('verified',scenario)
'''


@pytest.mark.parametrize('scenario', ['transitive', 'cached'])
def test_fixed_helper_boundary(scenario):
    result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', SCRIPT, str(RUNTIME), scenario],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
