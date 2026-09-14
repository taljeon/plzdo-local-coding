"""Read-only, prompt-free metrics export for bounded workflow evidence."""
import csv
import json
from pathlib import Path
import re

from json_codec import strict_json
from engine_types import EngineFailure, require_cleanup

FIELDS = ('run','task_id','kind','state','provider','attempt','fault_injection','passed',
          'first_attempt_passed','provider_transitions','model','model_digest',
          'prompt_tokens','cached_prompt_tokens','output_tokens','generation_seconds',
          'verification_seconds','attempt_seconds','run_seconds','error_code','ttft_seconds','cleanup_passed')

def _read(path):
    path=Path(path)
    if not path.exists(): return {}
    if path.is_symlink() or not path.is_file() or path.stat().st_size>4*1024*1024:
        raise ValueError('Unsafe or oversized metrics evidence')
    value=strict_json(path.read_bytes())
    if not isinstance(value,dict): raise ValueError('Metrics evidence must be an object')
    return value

def _number(value, integer=False):
    if type(value) not in ((int,) if integer else (int,float)) or value<0: return None
    if value!=value or value==float('inf'): return None
    return value

def _cleanup_passed(receipt):
    if not isinstance(receipt,dict) or type(receipt.get('passed')) is not bool:
        return None
    try:
        require_cleanup(receipt)
    except (EngineFailure, ValueError, TypeError):
        return False if receipt['passed'] is False or receipt.get('completed') is False else None
    return True

def collect_run(run_dir):
    root=Path(run_dir).resolve(strict=True)
    packet,result=_read(root/'packet.json'),_read(root/'result.json')
    cleanup=result.get('cleanup') or _read(root/'cleanup.json')
    if not result: raise ValueError('Missing terminal workflow result')
    attempts=result.get('attempts',[])
    if not isinstance(attempts,list) or any(not isinstance(item,dict)
            or item.get('passed') is not None and type(item['passed']) is not bool for item in attempts):
        raise ValueError('Invalid attempt outcomes in metrics evidence')
    first=(attempts[0]['passed'] if attempts and attempts[0].get('passed') is not None
           and not result.get('fault_injection') else None)
    rows=[]
    for attempt in attempts or [{}]:
        provider=attempt.get('provider')
        if provider is not None and (type(provider) is not str
                or re.fullmatch(r'[a-z][a-z0-9-]{0,79}',provider) is None):
            raise ValueError('Unknown implementation provider in metrics evidence')
        if provider and (type(attempt.get('number')) is not int or not 1<=attempt['number']<=3):
            raise ValueError('Invalid bounded attempt identity in metrics evidence')
        stage=root/(str(provider)+'-'+str(attempt.get('number',1))) if provider else root
        info=_read(stage/'provider/provider.json')
        identity=_read(stage/'provider/identity.json')
        process=_read(stage/'provider/process/summary.json')
        local=provider in ('ollama','local')
        response=_read(stage/'provider/response.json') if local else {}
        usage=process.get('reported_usage') or {}
        checks=attempt.get('checks',{}).get('checks',[])
        durations=[_number(c.get('duration_seconds')) for c in checks]
        verified=sum(durations) if durations and all(v is not None for v in durations) else None
        rows.append(dict(zip(FIELDS,[root.name,packet.get('id'),packet.get('kind','repo-edit'),result.get('state'),
          provider,attempt.get('number'),bool(result.get('fault_injection')),attempt.get('passed'),first,
          result.get('provider_transitions'),identity.get('model') or info.get('model'),identity.get('digest'),
          _number(response.get('prompt_eval_count') if local else usage.get('input_tokens'),True),
          _number(response.get('prompt_eval_cached_count') if local else usage.get('cached_input_tokens'),True),
          _number(response.get('eval_count') if local else usage.get('output_tokens'),True),
          _number(process.get('duration_seconds')),verified,_number(attempt.get('duration_seconds')),
          _number(result.get('duration_seconds')),attempt.get('error_code'),None,
          _cleanup_passed(attempt.get('cleanup') if isinstance(attempt.get('cleanup'),dict) else cleanup)])))
    return rows

def export_runs(run_dirs,output_dir):
    rows=[row for root in run_dirs for row in collect_run(root)]
    output=Path(output_dir)
    output.mkdir(parents=True,exist_ok=False)
    with (output/'metrics.json').open('x',encoding='utf-8') as out:
        json.dump({'rows':rows,'limitations':['Usage is provider-reported, not independently measured.',
            'Fault-injected runs are excluded from first-attempt quality statistics.',
            'Nonstreaming TTFT and missing metrics remain unknown.',
            'run_seconds sums active pipeline segments; managed-browser observation and user waiting are excluded, so this is not full end-to-end wall time.',
            'No prompts, source code, raw diagnostics or environment values are exported.']},out,ensure_ascii=False,indent=2)
        out.write('\n')
    with (output/'metrics.csv').open('x',encoding='utf-8',newline='') as out:
        writer=csv.DictWriter(out,fieldnames=FIELDS);writer.writeheader()
        for row in rows:
            # A user-supplied run path must not create a spreadsheet formula.
            writer.writerow({k:("'"+v if isinstance(v,str) and v.startswith(('=','+','-','@')) else v) for k,v in row.items()})
    return {'rows':len(rows),'json':str(output/'metrics.json'),'csv':str(output/'metrics.csv')}
