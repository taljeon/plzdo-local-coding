#!/bin/sh
# Development test environment only. Runtime startup never runs this script.
PLZDO_RUNTIME_EXPECTED_CORE_ROOT="$(dirname -- "$PLZDO_RUNTIME_PROJECT_ROOT")/plzdo"
if [ "${PLZDO_RUNTIME_CORE_ROOT:-$PLZDO_RUNTIME_EXPECTED_CORE_ROOT}" != "$PLZDO_RUNTIME_EXPECTED_CORE_ROOT" ]; then
    printf '%s\n' 'Runtime checks require the exact sibling plzdo source root.' >&2
    exit 1
fi
PLZDO_RUNTIME_CORE_ROOT=$PLZDO_RUNTIME_EXPECTED_CORE_ROOT
if [ ! -d "$PLZDO_RUNTIME_CORE_ROOT" ] || [ -L "$PLZDO_RUNTIME_CORE_ROOT" ] ||
   [ "$(CDPATH= cd -- "$PLZDO_RUNTIME_CORE_ROOT" && pwd -P)" != "$PLZDO_RUNTIME_CORE_ROOT" ]; then
    printf '%s\n' 'Runtime checks require a canonical, non-symlink sibling plzdo directory.' >&2
    exit 1
fi
for PLZDO_RUNTIME_CORE_PACKAGE in plzdo_local plzdo_local_code_adapter; do
    PLZDO_RUNTIME_CORE_PACKAGE_PATH="$PLZDO_RUNTIME_CORE_ROOT/$PLZDO_RUNTIME_CORE_PACKAGE"
    if [ ! -d "$PLZDO_RUNTIME_CORE_PACKAGE_PATH" ] || [ -L "$PLZDO_RUNTIME_CORE_PACKAGE_PATH" ] ||
       [ ! -f "$PLZDO_RUNTIME_CORE_PACKAGE_PATH/__init__.py" ] ||
       [ -L "$PLZDO_RUNTIME_CORE_PACKAGE_PATH/__init__.py" ]; then
        printf '%s\n' 'Runtime checks require both regular core source packages.' >&2
        exit 1
    fi
done
export PLZDO_RUNTIME_CORE_ROOT
PLZDO_RUNTIME_CHECK_TMP=$(mktemp -d /private/tmp/plzdo-runtime-checks.XXXXXX) || exit 1
mkdir -m 700 "$PLZDO_RUNTIME_CHECK_TMP/state" || exit 1
export LOCAL_CODING_STATE_ROOT="$PLZDO_RUNTIME_CHECK_TMP/state"
export PYTHONDONTWRITEBYTECODE=1
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export PYTHONPATH="$PLZDO_RUNTIME_PROJECT_ROOT/local_coding/_engine:$PLZDO_RUNTIME_PROJECT_ROOT:$PLZDO_RUNTIME_CORE_ROOT"
unset PYTEST_ADDOPTS LOCAL_CODING_RUNTIME_POLICY LOCAL_CODING_RUNTIME_POLICY_SHA256
unset LOCAL_CODING_CONTRACT_BACKEND LOCAL_CODING_LEGACY_HN_ROOT
# Preserve owned scratch for diagnosis; no caller-provided directory is removed.
