"""Byte-bound managed-browser handoff; observations never come from Qwen.

The active Codex coordinator observes UI through the approved browser tool.
This is not a native browser attestation or an OS-wide browser network sandbox.
"""
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket

from json_codec import strict_json
from workflow_core import ContractError, snapshot, _read_check_evidence
from workflow_artifacts import inspect_artifact_scope
from provider_common import require_active_session
from engine_types import require_cleanup

def require(value, message):
    if not value: raise ContractError(message)

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()

def read(path):
    path=Path(path)
    require(path.resolve()==path and path.is_file() and not path.is_symlink()
            and path.stat().st_nlink==1 and path.stat().st_size<=2*1024*1024,'Unsafe browser evidence path')
    value=strict_json(path.read_bytes())
    require(isinstance(value,dict),'Browser evidence must be an object')
    return value

def _pending_attempt(root, result):
    attempts = result.get('attempts')
    require(isinstance(attempts,list) and bool(attempts), 'Pending browser attempt is missing')
    last = attempts[-1]
    require(isinstance(last,dict) and isinstance(last.get('operation'),dict), 'Invalid pending attempt operation')
    operation = last['operation']
    require(set(operation)=={'engineId','role','ordinal'} and operation['role']=='generate'
            and isinstance(operation['engineId'],str) and re.fullmatch(r'[a-z][a-z0-9-]{0,79}',operation['engineId'])
            and type(operation['ordinal']) is int and operation['ordinal']==len(attempts),
            'Invalid pending attempt identity')
    stage=root/(operation['engineId']+'-'+str(operation['ordinal']))
    require(last.get('candidate')==str(stage/'candidate') and result.get('candidate')==last['candidate']
            and result.get('pending_patch')==str(stage/'actual.patch'), 'Pending browser stage scope mismatch')
    raw=_read_check_evidence(stage,'attempt.json',2*1024*1024)
    original=strict_json(raw)
    require(isinstance(original,dict) and digest(original)==digest(last) and original.get('passed') is None
            and original.get('status')=='awaiting_browser_validation', 'Pending attempt receipt changed')
    return stage,original,hashlib.sha256(raw).hexdigest()

def pending_run(run_dir, *, kernel):
    from workflow import validate_task_packet, packet_hash
    workflows = Path(kernel.state_root) / 'runs'
    root=Path(run_dir)
    require(root.is_absolute() and root.resolve(strict=True)==root,
            'Browser run path must be canonical and cannot traverse symlinks')
    require(root.is_relative_to(workflows) and root!=workflows,'Browser run must belong to this workflow')
    packet=validate_task_packet(read(root/'packet.json'))
    result=read(root/'result.json')
    require(packet.get('kind')=='artifact-create' and result.get('state')=='awaiting_browser_validation',
            'Browser run is not awaiting required validation')
    _pending_attempt(root,result)
    candidate=Path(result['candidate'])
    cleanup=result.get('cleanup')
    require_cleanup(cleanup)
    require(snapshot(candidate)==result['pending_snapshot'] and inspect_artifact_scope(packet,candidate)['passed'],
            'Browser candidate scope/identity drift')
    document,_=kernel.approved_contract(packet)
    authorization=document['execution'].get('previewAuthorization',{})
    from contracts import validate_preview_authorization
    try:
        validate_preview_authorization(authorization, packets=[packet])
    except ValueError as exc:
        raise ContractError('Temporary preview is not approved: ' + str(exc)) from exc
    return root,packet,result,candidate,authorization,packet_hash(packet)

def start_preview(run_dir, ttl_seconds=300, *, kernel):
    from workflow_preview import serve_preview
    from contracts import _timestamp
    require_active_session()
    root,packet,result,candidate,authorization,packet_sha=pending_run(run_dir,kernel=kernel)
    require(type(ttl_seconds) is int and 1<=ttl_seconds<=min(300,authorization['maxLifetimeSeconds']), 'Preview lifetime exceeds approval')
    document,_=kernel.approved_contract(packet)
    require(datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds) <= _timestamp(document['expiresAt']),
            'Preview lifetime would exceed contract expiry')
    ledger=root/'preview-starts.jsonl'
    fd=os.open(ledger,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a+',encoding='utf-8') as out:
        fcntl.flock(out,fcntl.LOCK_EX);out.seek(0)
        starts=[strict_json(line) for line in out if line.strip()]
        require(len(starts)<authorization['maxSessionsPerRun'],'Preview session budget exhausted')
        for prior in starts:
            stopped=read(root/'browser-previews'/str(prior['index'])/'stopped.json')
            require(stopped.get('server_closed') is True,'Previous preview is still active or closure unproven')
        index=len(starts)+1
        out.seek(0,2);out.write(json.dumps({'index':index,'packet_sha256':packet_sha,
            'snapshot_sha256':digest(result['pending_snapshot']),'attempt':len(result['attempts']),
            'at':datetime.now(timezone.utc).isoformat()})+'\n');out.flush();os.fsync(out.fileno())
    return serve_preview(candidate,packet['allowed_paths'],root/'browser-previews'/str(index),packet_sha,
                         ttl_seconds,expires_at=document['expiresAt'])

def validate_observations(observation, requests, preview):
    """Check completeness separately from whether actual observed assertions pass."""
    require(observation.get('authority')=='coordinator-observed'
            and observation.get('transport')=='cua-in-app-browser'
            and observation.get('preview_session_id')==preview['session_id']
            and observation.get('packet_sha256')==preview['packet_sha256'], 'Browser observation provenance mismatch')
    require(observation.get('console_scope')=='captured-errors-for-this-created-tab', 'Browser console observation scope required')
    packs=observation.get('packs')
    require(isinstance(packs,list) and len(packs)==len(requests),'Browser observations missing required packs')
    records=[]
    for request,observed in zip(requests,packs):
        pack=request['pack']
        require(observed.get('pack_index')==request['pack_index'],'Browser pack identity mismatch')
        views=observed.get('viewports')
        require(isinstance(views,list) and len(views)==len(pack['widths']),'Browser viewport evidence missing')
        passed=True
        for width,view in zip(pack['widths'],views):
            require(view.get('width')==width and view.get('url')==preview['urls'][pack['path']], 'Observed viewport or URL mismatch')
            layout=view.get('layout',{})
            require(layout.get('observed_width')==width and type(layout.get('body_present')) is bool
                    and type(layout.get('horizontal_overflow')) is bool,'Actual browser layout measurement required')
            text=view.get('expected_text')
            require(isinstance(text,list) and len(text)==len(pack['expected_text']), 'Missing visible text observations')
            for wanted,item in zip(pack['expected_text'],text):
                require(item.get('text')==wanted and type(item.get('visible')) is bool,'Invalid visible text evidence')
                passed=passed and item['visible']
            clicks=view.get('clicks')
            require(isinstance(clicks,list) and len(clicks)==len(pack['clicks']),'Missing click observations')
            for wanted,item in zip(pack['clicks'],clicks):
                require(item.get('selector')==wanted['selector'] and item.get('expect_text')==wanted['expect_text']
                        and type(item.get('before_visible')) is bool and type(item.get('after_visible')) is bool,'Invalid click evidence')
                passed=passed and item['before_visible'] is False and item['after_visible'] is True
            errors=view.get('console_errors')
            require(isinstance(errors,list) and all(isinstance(v,str) for v in errors),'Missing console observations')
            screenshot=view.get('screenshot',{})
            header=screenshot.get('header_bytes',[])
            valid_header=isinstance(header,list) and len(header)==8 and all(type(v) is int and 0<=v<=255 for v in header)
            valid_image=valid_header and (screenshot.get('mime_type')=='image/png' and header==[137,80,78,71,13,10,26,10]
                         or screenshot.get('mime_type')=='image/jpeg' and len(header)==8 and header[:3]==[255,216,255])
            require(screenshot.get('source')=='cua-tool-output' and valid_image
                    and type(screenshot.get('byte_length')) is int and 24<=screenshot['byte_length']<=16*1024*1024
                    and isinstance(screenshot.get('captured_at'),str),'Missing actual tool screenshot observation')
            captured=datetime.fromisoformat(screenshot['captured_at'].replace('Z','+00:00'))
            require(captured.tzinfo is not None and captured>=datetime.fromisoformat(preview['started_at']), 'Screenshot observation time invalid')
            require(type(view.get('visual_review_passed')) is bool,'Coordinator visual inspection required')
            passed=passed and layout['body_present'] and not layout['horizontal_overflow'] and not errors and view['visual_review_passed']
        records.append({'kind':'html-browser','driver':'managed','authority':'coordinator-observed',
            'executed':True,'passed':passed,'return_code':None,'verification_status':'pass' if passed else 'fail',
            'pack_index':request['pack_index'],
            'report':observed,'duration_seconds':None,
            'limitations':['Screenshots are native CUA tool outputs, not invented local PNG paths.',
                'CSP/frozen preview assets are enforced by the preview; this is not OS-wide browser network isolation.',
                'UI evidence is observed by the active coordinator, not a signed native attestation.']})
    return records

def finish_browser(run_dir, observation_path, *, kernel):
    from workflow import save,store_result
    require_active_session()
    root,packet,result,candidate,authorization,packet_sha=pending_run(run_dir,kernel=kernel)
    stage,original,original_sha=_pending_attempt(root,result)
    observation_path=Path(observation_path).resolve(strict=True)
    require(observation_path.is_relative_to(root),'Observation must be task-owned evidence')
    require(not any(observation_path.is_relative_to(Path(attempt['candidate'])) for attempt in result['attempts']),
            'Browser observations must not originate from model-produced candidate files')
    observation=read(observation_path)
    index=observation.get('preview_index')
    require(type(index) is int and 1<=index<=authorization['maxSessionsPerRun'],'Invalid preview index')
    starts=[strict_json(line) for line in (root/'preview-starts.jsonl').read_text().splitlines()]
    require(starts and starts[-1]['index']==index and starts[-1]['snapshot_sha256']==digest(result['pending_snapshot']),
            'Browser observation is not for latest frozen candidate')
    folder=root/'browser-previews'/str(index)
    preview,stopped=read(folder/'preview.json'),read(folder/'stopped.json')
    require(preview.get('packet_sha256')==packet_sha and preview.get('host')=='127.0.0.1'
            and type(preview.get('port')) is int and 1<=preview['port']<=65535,'Preview source mismatch')
    expected={path:{'sha256':hashlib.sha256((candidate/path).read_bytes()).hexdigest(),
                    'bytes':(candidate/path).stat().st_size} for path in packet['allowed_paths']}
    require(preview['files']==expected and stopped.get('session_id')==preview['session_id']
            and stopped.get('pid')==preview['pid'] and stopped.get('server_closed') is True,
            'Preview bytes/closure mismatch')
    with socket.socket() as probe:
        probe.settimeout(1)
        code=probe.connect_ex(('127.0.0.1',preview['port']))
    require(code==errno.ECONNREFUSED,'Preview closure needs actual connection refusal, not timeout/permission denial')
    def aware_time(value):
        require(isinstance(value,str),'Browser lifecycle timestamp must be aware ISO')
        try:
            parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
            require(parsed.tzinfo is not None and parsed.utcoffset() is not None,
                    'Browser lifecycle timestamp must be aware ISO')
            return parsed.astimezone(timezone.utc)
        except (ValueError,TypeError,OverflowError) as exc:
            raise ContractError('Invalid browser lifecycle timestamp') from exc

    ttl=preview.get('ttl_seconds')
    require(type(ttl) is int and 1<=ttl<=min(300,authorization['maxLifetimeSeconds']),'Invalid preview lifetime')
    started_at=aware_time(preview.get('started_at'))
    stopped_at=aware_time(stopped.get('stopped_at'))
    require(stopped_at>=started_at,'Preview stopped before it started')
    try:
        records=validate_observations(observation,result['pending_browser'],preview)
    except (ValueError,TypeError,OverflowError) as exc:
        raise ContractError('Invalid browser observation') from exc
    for pack in observation['packs']:
        for view in pack['viewports']:
            captured=aware_time(view['screenshot'].get('captured_at'))
            require(started_at<=captured<=stopped_at
                    and (captured-started_at).total_seconds()<=ttl,
                    'Screenshot observation outside preview lifetime')
    last=result['attempts'][-1]
    earlier=[r for r in last['checks']['checks'] if r.get('status')!='awaiting_browser_validation']
    require(all(r.get('return_code')==0 for r in earlier) and last['checks']['scope']['passed']
            and last['checks'].get('diff_check',{}).get('passed'),'Non-browser gate has not passed')
    closure={'host':'127.0.0.1','port':preview['port'],'errno':code,'connection_refused':True}
    validated={'records':records,'authority':'coordinator-observed','observation_path':str(observation_path)}
    missing=[]
    for name,expected_proof in (('closed-probe.json',closure),('validated-observations.json',validated)):
        path=folder/name
        if path.exists() or path.is_symlink():
            existing=read(path)
            if name=='closed-probe.json':
                require(all(type(existing.get(key)) is type(value) and existing.get(key)==value
                            for key,value in closure.items()),'Existing closure proof binding mismatch')
            else:
                require(digest(existing)==digest(expected_proof),'Existing browser observation proof mismatch')
        else:
            missing.append((path,expected_proof))
    # Check every existing receipt before publishing any missing receipt.
    for path,proof in missing:
        if path.name=='closed-probe.json':
            proof={**proof,'observed_at':datetime.now(timezone.utc).isoformat()}
        save(path,proof)
    passed=all(record['passed'] for record in records)
    last['checks']['checks']=earlier+records
    last['checks']['passed']=passed;last['checks']['pending_browser']=[]
    last['checks']['status']='verified' if passed else 'failed'
    last['passed']=passed;last['status']='verified' if passed else 'retry_required'
    last['browser_evidence']=str(folder/'validated-observations.json')
    result['browser_evidence']=last['browser_evidence']
    if passed:
        result.update(state='candidate_ready',accepted_patch=result['pending_patch'],
                      accepted_snapshot=result['pending_snapshot'])
        result.pop('retry_feedback',None)
    else:
        last['error_code']='BROWSER_CHECK_FAILED'
        result.update(state='retry_required',retry_feedback={'reason':'Required browser assertions failed.',
            'reason_code':'BROWSER_CHECK_FAILED','failed_packs':[r['pack_index'] for r in records if not r['passed']],
            'observed_clicks':[v['clicks'] for p in observation['packs'] for v in p['viewports']],
            'hint':'A click must reveal the initially hidden expected text on its first activation; ensure stylesheet and inline visibility state agree.'})
    last['browser_finalization']={
        'schema':'plzdo.browser-attempt-final.v1',
        'original_receipt':str(stage/'attempt.json'), 'original_receipt_sha256':original_sha,
        'observations':str(folder/'validated-observations.json'),
        'observations_sha256':hashlib.sha256((folder/'validated-observations.json').read_bytes()).hexdigest(),
        'closure':str(folder/'closed-probe.json'),
        'closure_sha256':hashlib.sha256((folder/'closed-probe.json').read_bytes()).hexdigest()}
    final_path=stage/'attempt.browser-final.json'
    if final_path.exists() or final_path.is_symlink():
        require(digest(read(final_path))==digest(last),'Existing final browser attempt receipt mismatch')
    else:
        save(final_path,last)
    require(isinstance(result.get('run_id'),str) and bool(result['run_id']), 'Browser run identity is missing')
    # A pending receipt grants no retry. Bind its immutable terminal successor
    # before publishing either a successful candidate or the next-slot marker.
    kernel.complete_attempt(packet,result['run_id'],original['operation']['ordinal'],final_path)
    for key in ('pending_browser','pending_patch','pending_snapshot'):result.pop(key,None)
    store_result(root,result)
    return {'state':result['state'],'authority':'coordinator-observed','browser_passed':passed,
            'preview_closed':True,'provider_calls_added':0}
