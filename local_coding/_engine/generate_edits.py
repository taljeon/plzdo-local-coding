"""One local-only structured generation request; no tool execution."""
if __name__ == '__main__':
    raise SystemExit('INTERNAL_HELPER_REQUIRES_KERNEL')

import argparse
import json
from pathlib import Path
import urllib.request

from json_codec import strict_json, unique_object

MODEL = 'qwen3-coder:30b-a3b-q4_K_M'
MAX_BYTES = 2 * 1024 * 1024

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def response_metrics(data, response_bytes):
    cached_count = data.get('prompt_eval_cached_count')
    prompt_duration = data.get('prompt_eval_duration')
    return {
        'model': data.get('model'), 'done_reason': data.get('done_reason'),
        'prompt_eval_count': data.get('prompt_eval_count'),
        'prompt_eval_cached_count': cached_count if type(cached_count) is int and cached_count >= 0 else None,
        'eval_count': data.get('eval_count'),
        'prompt_eval_duration_ns': prompt_duration if type(prompt_duration) is int and prompt_duration >= 0 else None,
        'total_duration_ns': data.get('total_duration'),
        'load_duration_ns': data.get('load_duration'),
        'eval_duration_ns': data.get('eval_duration'),
        'response_bytes': response_bytes,
        'ttft_seconds': None,
    }

def _worker_main(argv=None):
    """Internal fixed worker entry; direct script execution is unsupported."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('request', type=Path)
    parser.add_argument('response', type=Path)
    args = parser.parse_args(argv)
    request_bytes = args.request.read_bytes()
    request = strict_json(request_bytes)
    if request.get('model') != MODEL or request.get('tools') or request.get('stream') is not False:
        raise SystemExit('Invalid local generation contract')
    if args.response.exists():
        raise SystemExit('Response evidence already exists')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request('http://127.0.0.1:11434/api/chat', data=request_bytes,
                                 headers={'Content-Type': 'application/json'})
    with opener.open(req, timeout=160) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise SystemExit('Response exceeds the byte limit')
    with args.response.open('xb') as output:
        output.write(raw)
    data = strict_json(raw)
    if data.get('model') != MODEL or data.get('done') is not True or data.get('done_reason') != 'stop':
        raise SystemExit('Incomplete or wrong-model response')
    if data.get('remote_host') or data.get('remote_model') or data.get('message', {}).get('tool_calls'):
        raise SystemExit('Unexpected remote/tool response')
    payload = strict_json(data['message']['content'])
    if not isinstance(payload, dict):
        raise SystemExit('Expected one complete JSON edit object')
    print(json.dumps(response_metrics(data, len(raw))), flush=True)
