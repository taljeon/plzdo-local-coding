#!/bin/sh
set -eu
PLZDO_RUNTIME_PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
export PLZDO_RUNTIME_PROJECT_ROOT
. "$PLZDO_RUNTIME_PROJECT_ROOT/scripts/harness-env.sh"
PLZDO_RUNTIME_PYTHON=${PLZDO_RUNTIME_PYTHON:-python3}
"$PLZDO_RUNTIME_PYTHON" -B -c '
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Runtime checks require Python 3.11+")
import pytest
print("Python:", sys.version.split()[0], sys.executable)
print("pytest:", pytest.__version__, pytest.__file__)
'
printf 'Core source: %s\n' "$PLZDO_RUNTIME_CORE_ROOT"
printf 'Test state: %s\n' "$LOCAL_CODING_STATE_ROOT"
"$PLZDO_RUNTIME_PYTHON" -B -m pytest -p no:cacheprovider "$PLZDO_RUNTIME_PROJECT_ROOT/tests" -q --tb=short
