#!/bin/sh
set -eu
PLZDO_RUNTIME_PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
exec sh "$PLZDO_RUNTIME_PROJECT_ROOT/scripts/verify-harness.sh"
