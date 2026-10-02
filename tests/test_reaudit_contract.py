import unittest,json,sys,subprocess,copy,base64,hashlib,datetime
from dsse_envelope_review import audit
from dsse_envelope_review.common import ReviewError,load
import test_review as fixtures
def reject(test,d):
    with test.assertRaises(ReviewError):audit(d)
    p=subprocess.run([sys.executable,'-m','dsse_envelope_review','-'],input=json.dumps(d).encode(),capture_output=True,timeout=10)
    out=json.loads(p.stdout);test.assertEqual(p.returncode,1);test.assertEqual(out['status'],'FAIL');test.assertFalse(out['complete']);test.assertFalse(out.get('verified',False))
class FiniteInputTests(unittest.TestCase):
    def test_exponent_overflow_rejected_api_and_cli(self):
        for raw in (b'{"x":1e999}',b'{"x":[-1e999]}'):
            with self.assertRaises(ReviewError):load(raw)
            p=subprocess.run([sys.executable,'-m','dsse_envelope_review','-'],input=raw,capture_output=True,timeout=10);out=json.loads(p.stdout)
            self.assertEqual(p.returncode,1);self.assertFalse(out['complete']);self.assertEqual(out['status'],'FAIL')
        self.assertEqual(load(b'{"x":1.25}'),{'x':1.25})
    def test_unknown_fields_error_does_not_echo_canary(self):
        canary='SYNTHETIC-PRIVATE-CANARY-cc94e6f3'
        with self.assertRaises(ReviewError) as e:audit({canary:canary})
        self.assertNotIn(canary,str(e.exception))
        p=subprocess.run([sys.executable,'-m','dsse_envelope_review','-'],input=json.dumps({canary:canary}).encode(),capture_output=True,timeout=10)
        self.assertEqual(p.returncode,1);self.assertNotIn(canary,p.stdout.decode()+p.stderr.decode())

class FilePlatformCapabilityTests(unittest.TestCase):
    def test_missing_or_unusable_file_flags_fail_closed(self):
        from unittest import mock
        from dsse_envelope_review.common import read
        from dsse_envelope_review import common
        for flag in ('O_NOFOLLOW','O_NONBLOCK'):
            for value in (None,0,'unusable'):
                with mock.patch.object(common.os,flag,value,create=True):
                    with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')
            with mock.patch.object(common.os,flag,1,create=True):
                delattr(common.os,flag)
                with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')

class IndependentThresholdAndUtf8Tests(unittest.TestCase):
    def test_utf8_byte_length_and_independent_threshold_api_cli(self):
        t=fixtures.DsseTests();t.setUp();second=fixtures.ed25519.Ed25519PrivateKey.generate()
        typ='application/日本語';body=b'Independent evidence bytes'
        # DSSE protocol v1: LEN counts UTF-8 bytes, not Python characters.
        expected_pae=b'DSSEv1 21 application/\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e 26 Independent evidence bytes'
        d={'envelope':{'payloadType':typ,'payload':fixtures.enc(body),'signatures':[{'keyid':'same-untrusted-hint','sig':fixtures.enc(k.sign(expected_pae))} for k in (t.key,second)]},'trusted_keys':[fixtures.pemkey(k) for k in (t.key,second)],'expected_payload_type':typ,'threshold':2}
        self.assertEqual(audit(d)['accepted_key_count'],2)
        p=subprocess.run([sys.executable,'-m','dsse_envelope_review','-'],input=json.dumps(d).encode(),capture_output=True,timeout=10);self.assertEqual(p.returncode,0);self.assertEqual(json.loads(p.stdout)['accepted_key_count'],2)
        bad=copy.deepcopy(d);bad['envelope']['signatures'].pop();reject(self,bad)
        wrong=b'DSSEv1 15 application/\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e 26 Independent evidence bytes'
        bad=copy.deepcopy(d);bad['envelope']['signatures']=[{'sig':fixtures.enc(k.sign(wrong))} for k in (t.key,second)];reject(self,bad)
