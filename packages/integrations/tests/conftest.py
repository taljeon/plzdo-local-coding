"""Integration tests use the real runtime checkout and sibling core checkout."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(RUNTIME))
sys.path.insert(0, str(RUNTIME.parent / 'plzdo'))
