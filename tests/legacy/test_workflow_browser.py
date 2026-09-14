import copy
import unittest
from workflow_browser import validate_observations
from workflow_core import ContractError

class ManagedBrowserEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.preview={'session_id':'test-session','packet_sha256':'a'*64,
            'started_at':'2026-09-07T00:00:00+00:00','urls':{'index.html':'http://127.0.0.1:5555/nonce/index.html'}}
        pack={'type':'html-browser','driver':'managed','path':'index.html','widths':[390],
              'expected_text':['Title'],'clicks':[{'selector':'#show','expect_text':'Ready'}]}
        self.requests=[{'pack_index':0,'pack':pack}]
        self.observed={'authority':'coordinator-observed','transport':'cua-in-app-browser',
            'preview_session_id':'test-session','packet_sha256':'a'*64,
            'console_scope':'captured-errors-for-this-created-tab','packs':[{'pack_index':0,'viewports':[{
                'width':390,'url':self.preview['urls']['index.html'],
                'layout':{'observed_width':390,'body_present':True,'horizontal_overflow':False},
                'expected_text':[{'text':'Title','visible':True}],
                'clicks':[{'selector':'#show','expect_text':'Ready','before_visible':False,'after_visible':True}],
                'console_errors':[],'visual_review_passed':True,'screenshot':{
                    'source':'cua-tool-output','mime_type':'image/png','byte_length':100,
                    'header_bytes':[137,80,78,71,13,10,26,10],'captured_at':'2026-09-07T00:00:01Z'}}]}]}
    def test_complete_observation_is_not_native_process_attestation(self):
        records=validate_observations(self.observed,self.requests,self.preview)
        self.assertTrue(records[0]['passed']);self.assertIsNone(records[0]['return_code'])
        self.assertEqual(records[0]['authority'],'coordinator-observed')
    def test_real_noop_failure_is_recorded_not_accepted(self):
        self.observed['packs'][0]['viewports'][0]['clicks'][0]['after_visible']=False
        records=validate_observations(self.observed,self.requests,self.preview)
        self.assertFalse(records[0]['passed'])
    def test_missing_capture_or_wrong_viewport_fails_closed(self):
        for field in ('screenshot','expected_text','clicks','console_errors'):
            value=copy.deepcopy(self.observed);value['packs'][0]['viewports'][0].pop(field)
            with self.assertRaises(ContractError):validate_observations(value,self.requests,self.preview)
        self.observed['packs'][0]['viewports'][0]['layout']['observed_width']=1280
        with self.assertRaises(ContractError):validate_observations(self.observed,self.requests,self.preview)
    def test_wrong_session_hash_or_url_rejected(self):
        for key,value in [('preview_session_id','old-session'),('packet_sha256','b'*64)]:
            changed={**self.observed,key:value}
            with self.assertRaises(ContractError):validate_observations(changed,self.requests,self.preview)
        self.observed['packs'][0]['viewports'][0]['url']='file:///private/source'
        with self.assertRaises(ContractError):validate_observations(self.observed,self.requests,self.preview)

if __name__=='__main__':unittest.main()
