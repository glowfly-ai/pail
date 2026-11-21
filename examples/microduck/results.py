# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Release result classification: missing measurements never become passes."""
import hashlib,json
from pathlib import Path
EXPECTED={'CA-'+str(n).zfill(2) for n in range(1,14)}|{'CA-15','CA-16','CA-17','CA-18','CB-1'}

def classify(raw,returncode,demo_inconclusive=False):
    checks=raw.get('rows',[]);ids=[r.get('id')for r in checks]
    counts={s:sum(r.get('status')==s for r in checks)for s in ['PASS','FAIL','INCONCLUSIVE','SKIP','NOT_RUN']}
    errors=[]
    # --demo-inconclusive runs ONE case with the harness's own tail stalled on purpose: a demonstration of the third word,
    # never a judgement — so the partial case set is expected there, and the result says what it is.
    if len(ids)!=len(set(ids)) or (set(ids)!=EXPECTED and not demo_inconclusive):errors.append('Missing, duplicate or unexpected check ID')
    if sum(counts.values())!=len(checks):errors.append('Unknown check status')
    if raw.get('executed')!=counts['PASS']+counts['FAIL']+counts['INCONCLUSIVE']:errors.append('Raw executed count mismatch')
    if raw.get('failed')!=counts['FAIL'] or raw.get('skipped')!=counts['SKIP']:errors.append('Raw failure/skip count mismatch')
    reviewed=[]
    for r in checks:
        if r.get('status')!='SKIP':continue
        if r['id']=='CA-15' and 'NEEDS_UPSTREAM_BUILTIN_LIST'in r.get('reason',''):continue
        # A SKIP the backend raised itself (Unsupported) and its maintainer accepted with a written reason
        # (`--reviewed-skip CA-ID:REASON`) is a reviewed limitation: it never becomes a PASS, it stops being a BLOCKED.
        if r.get('reviewed_skip') and str(r.get('reason','')).startswith('Unsupported'):
            reviewed.append(str(r['id'])+': '+str(r.get('reason'))+' — reviewed skip, accepted by the backend maintainer: '+str(r['reviewed_skip']));continue
        errors.append('Unreviewed skip: '+str(r.get('id')))
    # A reviewed skip that was declared but never used names a case that did not report Unsupported (a wrong
    # case id, or a case that passed/failed on its own): said in the result, not only in the raw report.
    for cid,info in (raw.get('reviewed_skips') or {}).items():
        if not info.get('used'):reviewed.append(cid+': reviewed skip declared but NOT used — the case did not report Unsupported (check the case id); the declaration changed nothing')
    # INCONCLUSIVE rows: nothing failed, but a check could not be decided from what was observed, twice. Neither a PASS
    # nor a FAIL — a third word, and the reasons go with it.
    inconclusive=[]
    for r in checks:
        if r.get('status')!='INCONCLUSIVE':continue
        why=[c.get('detail') for c in (r.get('observations') or {}).get('checks',[]) if c.get('inconclusive')]
        inconclusive.append(str(r['id'])+': INCONCLUSIVE after '+str(r.get('attempts',1))+' attempt(s) — '+' | '.join(str(w)[:200] for w in why))
    status=('BLOCKED'if errors or counts['NOT_RUN']else'FAIL'if returncode or counts['FAIL']else'INCONCLUSIVE'if counts['INCONCLUSIVE']
            else'PASS_WITH_LIMITATIONS'if counts['SKIP']else'PASS')
    if demo_inconclusive:
        inconclusive.append('DEMO: --demo-inconclusive stalled the harness\'s own gate-log tail on purpose after the first record of the case; '
                            'this run demonstrates the INCONCLUSIVE path and is NOT a judgement of the adapter')
        if status in ('PASS','PASS_WITH_LIMITATIONS'):status='DEMO_INCOMPLETE'   # the stall did not reach a check that needed a later record
    return dict(schema_version=1,profile='microduck-software-preview',status=status,hardware_tested=False,checks=checks,
                counts={k.lower():v for k,v in counts.items()},errors=errors,
                limitations=['Physical hardware validation pending','Isolated dev control transport; not a production security deployment']+(['CA-15: upstream fake does not provide built-in skill inventory']if any(r.get('id')=='CA-15' and r.get('status')=='SKIP' for r in checks)else[])+reviewed+inconclusive)

def gate_refusals(state,names=('services.log','execution.log'),extra_text=''):
    """Gate refusal reasons seen in the rig's service logs during this run, most common first, and a diagnosis when
    clock steps dominate. The scene judge summarises these for a failed scene; a conformance run that fails or blocks
    while the adapter's wall clock was being stepped otherwise shows nothing but red cases.

    `names` are the log files to read, so another product-level check can be classified by the SAME rule under its
    own file names (P023-L2: `test-supersede` blamed its own reconnect for a clock that was being stepped).

    `extra_text` is counted the same way: what the caller's own probe was told. The gate does not report a clock
    refusal to the Issuer, so service logs hold none; in the real failure state of 0.2.4 the probe's result had 89
    ERR_CLOCK_DRIFT and the logs had 0, and the classification over the logs alone said nothing."""
    import collections,re
    counter=collections.Counter()
    for name in names:
        p=Path(state)/name
        if not p.exists():continue
        try:text=p.read_text(errors='replace')
        except OSError:continue
        # the adapter's tracing lines (`reason="ERR_X"`, possibly ANSI-coloured) and JSON gate records (`"reason": "ERR_X"`)
        counter.update(re.findall(r'reason.{0,24}?(ERR_[A-Z_]+)',text))
    if extra_text:counter.update(re.findall(r'reason.{0,24}?(ERR_[A-Z_]+)',extra_text))
    out={'top':dict(counter.most_common(5))}
    drift=counter.get('ERR_CLOCK_DRIFT',0)
    if drift and drift>=max(counter.values())*0.5:
        out['diagnosis']=('CLOCK_PREREQUISITE_FAILED: the gate refused '+str(drift)+' commands with ERR_CLOCK_DRIFT during this run — the adapter saw its '
                          'wall clock being stepped (a VM time-sync agent, two time sources in one VM, or a host clock away from NTP), not a policy '
                          'refusal and not a defect of the adapter under test. No threshold was changed. Fix the time source (see `doctor` clock row and '
                          'the delivery README), then run again with a NEW --state.')
    return out

def tree_manifest(root):
    # Build and runtime compare exactly the same inputs, not two drifting exclusion lists.
    import sys
    from pathlib import Path
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'common'))
    from build_runtime import source_entries, source_digest
    return {'sha256':source_digest(root),'files':source_entries(root)}
