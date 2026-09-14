"""Real authority/ledger and reused pipeline, with source-only offline engines.

Each case is a new process to preserve the production one-composition invariant.
Synthetic checks exercise orchestration; isolated real check execution is covered
by the existing checker suite. No model, provider CLI, or sandbox job is started.
"""
import os
from pathlib import Path
import subprocess
import sys

import pytest

RUNTIME = Path(__file__).resolve().parents[1]
SCRIPT = r'''
import copy,json,sys
from pathlib import Path
from datetime import datetime,timedelta,timezone
root=Path(sys.argv[2]); scenario=sys.argv[3]
shadow=root/'caller-modules';shadow.mkdir()
(shadow/'workflow.py').write_text("raise AssertionError('Caller module was executed')\n")
sys.path.insert(0,str(Path(sys.argv[1])/'local_coding/_engine'))
sys.path.insert(0,str(shadow))
sys.path.insert(0,sys.argv[1])
from local_coding.api import Kernel,EngineIdentity,WorkResult,EngineFailure,canonical_bytes,no_start_cleanup
class Offline:
    sha='a'*64
    calls=0
    works=[]
    def identity(self): return EngineIdentity('ollama',('generate',),self.sha)
    def execute(self,work):
        self.calls+=1
        self.works.append(work)
        if scenario=='expiry':
            import contracts
            contracts._now=lambda: expiry+timedelta(seconds=1)
        if scenario=='cleanup':
            return WorkResult(b'{}',self.identity(),{}, {})
        if scenario=='interrupt':
            raise KeyboardInterrupt()
        if scenario=='returned-identity':
            return WorkResult(b'{}',EngineIdentity('ollama',('generate',),'b'*64),
                              {'synthetic':True},no_start_cleanup())
        if scenario=='terminal-source-unavailable':
            def missing(_): raise ValueError('Synthetic target is now unavailable')
            k.workflow.validate_task_packet=missing
        data=b'{invalid' if scenario=='retry' and self.calls==1 else canonical_bytes({'files':[{'path':'hello.txt','content':'hello\n'}]})
        return WorkResult(data,self.identity(),{'synthetic':True},no_start_cleanup())
e=Offline()
if scenario=='preloaded-collision':
    import types
    wrong=types.ModuleType('workflow');wrong.__file__=str(shadow/'workflow.py')
    sys.modules['workflow']=wrong
    try:Kernel(root/'state',engines={'ollama':e})
    except RuntimeError as error:assert str(error)=='RUNTIME_MODULE_COLLISION'
    else:raise AssertionError('Preloaded foreign helper accepted')
    assert not (root/'state').exists()
    print('verified',scenario);raise SystemExit(0)
k=Kernel(root/'state',engines={'ollama':e})
p={'kind':'artifact-create','id':'task','authorityId':'root','objective':'Create a greeting',
   'allowed_paths':['hello.txt'],'generation_profile':'huihui-qwen38-q6kl-v1',
   'task_category':'product-development','validation_packs':[{'type':'text','path':'hello.txt','required':['hello']}]}
expiry=datetime.now(timezone.utc)+timedelta(hours=1)
p=k.normalize(p)
d=k.draft_contract('root',[p],expires_at=expiry.isoformat(),max_live_integration_calls=2,allowed_engines=['ollama'])
sha=k.payload_sha256(d)
k.approve_contract('root',expected_payload_sha256=sha,confirmation='APPROVE root '+sha)
def checks(*args):
    return {'passed':True,'scope':{'passed':True},'checks':[{'executed':True,'return_code':0,
       'execution_receipt':{'schema':'check-execution-receipt.v1','passed':True}}],
       'diff_check':{'passed':True},'pending_browser':[]}
k.workflow.run_artifact_checks=checks
if scenario=='drift':
    e.sha='b'*64
    try: k.begin_run(p,'drift')
    except ValueError: pass
    else: raise AssertionError('Fresh pin drift accepted')
    assert e.calls==0 and k.status('root')['summary']['runs']==0
elif scenario=='namespace':
    from state_io import StateStore
    with StateStore(k.state_root) as st,st.locked():
        raw=st.read_bytes('ledgers','root.json'); doc=st.read_json('ledgers','root.json')
        doc['schemaVersion']='plzdo.overlay.ledger.v2'
        st.write_json('ledgers','root.json',doc,expected_bytes=raw)
    try:k.status('root')
    except ValueError:pass
    else:raise AssertionError('Cross-namespace ledger accepted')
else:
    result=k.workflow.run_pipeline(p,'fixture',kernel=k)
    value=k.status('root'); records=value['ledger']['records']
    if scenario in ('cleanup','interrupt','returned-identity'):
        assert result['state']=='blocked' and e.calls==1
        assert records[-1]['disposition']=='blocked'
        assert not (Path(result['attempts'][0]['candidate'])/'hello.txt').exists()
        if scenario=='returned-identity':
            assert result['attempts'][0]['error_code']=='ENGINE_IDENTITY_CHANGED'
            assert result['attempts'][0]['cleanup']==no_start_cleanup()
    else:
        assert result['state']=='candidate_ready',result
        assert e.calls==(2 if scenario=='retry' else 1)
        assert value['summary']['engine_calls_consumed']==e.calls
        assert records[-1]['disposition']=='accepted'
        assert all(r['authority_observation'] is None for r in records)
    if scenario=='expiry':
        assert len([r for r in records if r['kind']=='engine-result'])==1
        try:k.begin_run(p,'after-expiry')
        except ValueError:pass
        else:raise AssertionError('Expired authority reused')
    elif scenario in ('success','retry'):
        first=next(r for r in records if r['kind']=='generate')
        first_work=e.works[0]
        try:k._dispatch(p,first['reservation_id'],first_work.prompt_bytes,first_work.schema_bytes,first_work.evidence_dir)
        except ValueError:pass
        else:raise AssertionError('Repeated dispatch accepted')
        assert e.calls==(2 if scenario=='retry' else 1)
        original=value['ledger']['headSha256']
        latest=result['attempts'][-1]
        receipt=Path(latest['candidate']).parent/'attempt.json'
        k.complete_attempt(p,result['run_id'],latest['number'],receipt)
        assert k.status('root')['ledger']['headSha256']==original
        receipt.write_text('{}\n')
        try:k.status('root')
        except ValueError:pass
        else:raise AssertionError('Mutated immutable receipt accepted')
print('verified',scenario)
'''


@pytest.mark.parametrize('scenario', ['success', 'retry', 'cleanup', 'interrupt', 'returned-identity', 'expiry', 'terminal-source-unavailable', 'drift', 'namespace', 'preloaded-collision'])
def test_real_kernel_boundaries(tmp_path, scenario):
    result = subprocess.run([sys.executable, '-B', '-c', SCRIPT, str(RUNTIME), str(tmp_path.resolve()), scenario],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
