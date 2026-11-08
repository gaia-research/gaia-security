"""All credentials below are synthetic values constructed at runtime, never live secrets."""
import hashlib
import json
import unittest
from gaia_security.redaction import contains_raw_secret, fingerprint_secret, redact_structure, redact_text

class TestRedaction(unittest.TestCase):
    def test_fingerprint(self):
        value='synthetic test data'
        self.assertEqual(fingerprint_secret(value),'[REDACTED:sha256='+hashlib.sha256(value.encode()).hexdigest()[:12]+']')
    def test_recognized_credentials(self):
        values=[
            'ghp_'+'a'*36,
            'github_pat_'+'a'*40+'_'+'b'*30,
            'sk-proj-'+'a'*40,
            'sk-ant-api03-'+'b'*40,
            'AIza'+'c'*35,
            'AKIA'+'D'*16,
            'xoxb-'+'1'*12+'-'+'2'*13+'-'+'a'*24,
            'eyJ'+'a'*30+'.'+'b'*30+'.'+'c'*30,
            '-----BEGIN '+'RSA PRIVATE KEY-----\n'+'synthetic-non-key-content\n'+'-----END '+'RSA PRIVATE KEY-----',
        ]
        for raw in values:
            with self.subTest(prefix=raw[:4]):
                result=redact_text('context '+raw+' end')
                self.assertNotIn(raw,result)
                self.assertIn('[REDACTED:sha256=',result)
                self.assertFalse(contains_raw_secret(result))
    def test_long_credentials_not_truncated(self):
        raw='ghp_'+'a'*1000
        result=redact_text(raw)
        self.assertNotIn('a'*10,result)
    def test_dictionary_keys_and_nested_values(self):
        raw='ghp_'+'x'*36
        result=redact_structure({raw:[{'credential':raw}]})
        self.assertNotIn(raw,json.dumps(result))
    def test_control_character_sanitization(self):
        self.assertNotIn(chr(27),redact_text('display'+chr(27)+'[31m'))
    def test_public_text_unchanged(self):
        self.assertEqual(redact_text('ordinary public text'),'ordinary public text')
