"""Runtime boundary validation without third-party runtime dependencies."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import re


def evidence_digest(evidences):
    records = [e.to_dict() for e in evidences]
    return hashlib.sha256(json.dumps(sorted(records,key=lambda x:json.dumps(x,sort_keys=True)),sort_keys=True,separators=(',',':')).encode()).hexdigest()


def check(value, kind, label):
    if type(value) is not kind:
        raise ValueError('Invalid '+label+' shape')
    return value


def string(obj,key):
    return check(obj[key],str,key)


def validate_native(scanner,data):
    """Reject unknown native envelopes, including valid JSON with missing fields."""
    if scanner in ('gitleaks','dependabot-alerts','codeql-alerts'):
        check(data,list,scanner)
        for item in data:
            check(item,dict,scanner+' record')
            if scanner == 'gitleaks':
                for key in ('RuleID','File','Secret'): string(item,key)
                check(item['StartLine'],int,'StartLine')
                if item['StartLine'] < 1: raise ValueError('Invalid StartLine')
            elif scanner == 'dependabot-alerts':
                if string(item,'state') not in {'open','fixed','dismissed','auto_dismissed'}:
                    raise ValueError('Unknown Dependabot alert state')
                advisory=check(item['security_advisory'],dict,'advisory'); string(advisory,'ghsa_id')
                dep=check(item['dependency'],dict,'dependency');string(dep,'manifest_path')
                package=check(dep['package'],dict,'package');string(package,'name');string(package,'ecosystem')
            else:
                if string(item,'state') not in {'open','fixed','dismissed'}:
                    raise ValueError('Unknown CodeQL alert state')
                rule=check(item['rule'],dict,'rule');string(rule,'id')
                instance=check(item['most_recent_instance'],dict,'instance')
                loc=check(instance['location'],dict,'location');string(loc,'path')
                check(loc['start_line'],int,'start_line')
        return
    check(data,dict,scanner)
    if scanner == 'osv-scanner':
        for result in check(data['results'],list,'results'):
            check(result,dict,'result')
            source=check(result.get('source',result.get('packageSource')),dict,'source');string(source,'path')
            for pkg in check(result['packages'],list,'packages'):
                check(pkg,dict,'package result')
                info=check(pkg['package'],dict,'package');string(info,'name');string(info,'version');string(info,'ecosystem')
                for vuln in check(pkg['vulnerabilities'],list,'vulnerabilities'):
                    check(vuln,dict,'vulnerability');string(vuln,'id')
                    for alias in check(vuln.get('aliases',[]),list,'aliases'):check(alias,str,'alias')
                    check(vuln.get('database_specific',{}),dict,'database_specific')
    elif scanner == 'semgrep-ce':
        for error in check(data['errors'],list,'errors'):check(error,dict,'error')
        for item in check(data['results'],list,'results'):
            check(item,dict,'match');string(item,'check_id');string(item,'path')
            for key in ('start','end'):
                loc=check(item[key],dict,key);check(loc['line'],int,'line')
            check(item['extra'],dict,'extra')
    elif scanner == 'trivy':
        if data.get('SchemaVersion') != 2: raise ValueError('Unsupported Trivy schema')
        string(data,'ArtifactName');string(data,'ArtifactType');check(data['Metadata'],dict,'Metadata')
        # Native empty Trivy scans legitimately omit Results entirely.
        for result in check([] if data.get('Results') is None else data['Results'],list,'Results'):
            check(result,dict,'result');string(result,'Target')
            for item in check([] if result.get('Misconfigurations') is None else result['Misconfigurations'],list,'Misconfigurations'):
                check(item,dict,'misconfiguration');string(item,'ID');string(item,'Severity')
                check(item.get('CauseMetadata',{}),dict,'CauseMetadata')
    else:
        raise ValueError('Unsupported native envelope')


DISPOSITIONS={'action_required','remediated_in_pr','false_positive','accepted_risk','test_fixture_excluded','deferred_steward_wave'}
QUESTIONS=('is_genuine','is_reachable','boundary_crossed','exploitation_plausible')

def validate_disposition(entry):
    """Executable enforcement of dispositions.schema.json's security invariants."""
    check(entry,dict,'disposition')
    allowed={'repository','finding_id','source_commit','expires_at','reviewer','disposition_id','evidence_refs','evidence_sha256','validation'}
    if set(entry) != allowed: raise ValueError('Missing or unknown disposition fields')
    for key in allowed-{'validation','evidence_refs'}:
        if not string(entry,key).strip():raise ValueError('Empty '+key)
    for key in ('source_commit','evidence_sha256'):
        if not re.fullmatch('[0-9a-f]{'+('40' if key=='source_commit' else '64')+'}',entry[key]):raise ValueError('Invalid digest')
    if not re.fullmatch(r'GSEC-[0-9a-f]{12}',entry['finding_id']):raise ValueError('Invalid finding identity')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',entry['repository']):raise ValueError('Invalid repository')
    refs=check(entry['evidence_refs'],list,'evidence_refs')
    if not refs or any(type(ref) is not str or not ref.strip() for ref in refs):raise ValueError('Invalid evidence refs')
    expires=datetime.fromisoformat(entry['expires_at'].replace('Z','+00:00'))
    if expires.tzinfo is None:raise ValueError('Expiry must have timezone')
    v=check(entry['validation'],dict,'validation')
    required=set(QUESTIONS)|{'existing_mitigations','duplicate_of','disposition','validated_priority','confidence','rationale'}
    if not required.issubset(v) or set(v)-required-{'disposition_id'}:raise ValueError('Missing/unknown assessment fields')
    for key in QUESTIONS:check(v[key],bool,key)
    mitigations=check(v['existing_mitigations'],list,'mitigations')
    if any(type(x) is not str for x in mitigations):raise ValueError('Invalid mitigation')
    if v['duplicate_of'] is not None and not re.fullmatch(r'GSEC-[0-9a-f]{12}',str(v['duplicate_of'])):raise ValueError('Invalid duplicate')
    if v['disposition'] not in DISPOSITIONS:raise ValueError('Invalid disposition state')
    if v['validated_priority'] not in {'P0','P1','P2','P3','P4','NONE'}:raise ValueError('Invalid priority')
    if v['confidence'] not in {'high','medium','low'}:raise ValueError('Invalid confidence')
    if not string(v,'rationale').strip():raise ValueError('Missing rationale')
    if v['disposition']=='false_positive' and v['is_genuine']:raise ValueError('Inconsistent false positive')
    if v['disposition']=='action_required' and not v['is_genuine']:raise ValueError('Non-genuine action')
    if v['disposition']=='test_fixture_excluded' and (v['is_reachable'] or v['exploitation_plausible']):raise ValueError('Inconsistent fixture exclusion')
    return expires
