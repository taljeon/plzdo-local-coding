"""Select the exact source engine for maintained v2 and inherited unit tests."""
from pathlib import Path
import sys

ENGINE = Path(__file__).resolve().parents[1] / 'local_coding' / '_engine'
sys.path.insert(0, str(ENGINE))
