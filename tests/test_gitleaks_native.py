"""Optional native profile regressions; dummy credentials exist only in temp files."""
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from gaia_security.registry import find_repo_root

@unittest.skipUnless(shutil.which('gitleaks'),'Native Gitleaks not installed')
class NativeProfileTests(unittest.TestCase):
    def test_all_custom_spellings_are_detected(self):
        expected={'gaia-mcp-bearer-token':0,'gaia-jwt-session-token':0}
        lines=[]
        for kind,suffixes,rule in [('mcp',('token','bearer','key'),'gaia-mcp-bearer-token'),('session',('token','jwt'),'gaia-jwt-session-token')]:
            for left,right,suffix,uppercase in itertools.product(('_','-',''),('_','-',''),suffixes,(False,True)):
                label=left.join(('gaia',kind))+right+suffix
                if uppercase:label=label.upper()
                digest=hashlib.sha256(label.encode()).hexdigest()
                dummy=digest if kind=='mcp' else 'ey'+digest[:20]+'.ey'+digest[20:40]+'.'+digest[40:]
                lines.append(label+' = '+repr(dummy))
                expected[rule]+=1
        with TemporaryDirectory(prefix='gaia-profile-fixture-') as tmp:
            target=Path(tmp)/'input';target.mkdir()
            (target/'synthetic.txt').write_text('\n'.join(lines)+'\n')
            out=Path(tmp)/'report.json'
            result=subprocess.run(['gitleaks','dir',str(target),'--config',str(find_repo_root()/'profiles/gitleaks/gitleaks.toml'),'--report-format','json','--report-path',str(out),'--redact','--no-banner'],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,1)
            records=json.loads(out.read_text())
            for rule,count in expected.items():
                self.assertEqual(sum(r['RuleID']==rule for r in records),count)
