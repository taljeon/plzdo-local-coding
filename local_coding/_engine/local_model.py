"""Small local gateway helpers; historical identity is not a new default."""
import os
import math
from pathlib import Path

from json_codec import strict_json

MODEL = 'qwen3-coder:30b-a3b-q4_K_M'
DIGEST = '06c1097efce0431c2045fe7b2e5108366e43bee1b4603a7aded8f21689e90bca'
MANIFEST = (Path(os.environ.get('LOCAL_CODING_OLLAMA_MODELS', str(Path.home() / '.ollama/models')))
            / 'manifests/registry.ollama.ai/library/qwen3-coder/30b-a3b-q4_K_M')


def local_status(endpoint, *, timeout_seconds=10):
    if endpoint not in {'version', 'tags', 'ps'}:
        raise ValueError('Unsupported local status endpoint')
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 10):
        raise ValueError('Invalid bounded local status timeout')
    import urllib.request
    from generate_edits import NoRedirect
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open('http://127.0.0.1:11434/api/' + endpoint, timeout=timeout_seconds) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('Local status response exceeds the byte limit')
    result = strict_json(raw)
    if not isinstance(result, dict):
        raise ValueError('Local status response must be an object')
    return result
