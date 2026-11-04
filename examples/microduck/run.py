#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Optional, isolated Microduck software preview. Use a public source tree."""
import argparse,hashlib,json,os,platform,re,subprocess,sys,time,uuid,tempfile
# Local helper imports must not create __pycache__ in the delivered source tree.
# Enforce this here instead of relying on a developer's Python environment.
sys.dont_write_bytecode=True
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
IMAGE='pail/microduck-preview:local'
def call(args,env=None,log=None,check=True):
    if log:
        with Path(log).open('a') as f:p=subprocess.run(args,env=env,stdout=f,stderr=subprocess.STDOUT)
    else:p=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    if check and p.returncode:
        # P23-L1: say why the stack did not come up on the top line (examples/common/compose_failure.py)
        sys.path.insert(0,str(ROOT/'examples'/'common'))
        from compose_failure import explain,explain_file
        cause=explain_file(log) if log else explain(p.stdout)
        raise RuntimeError('Command failed (%s): %s%s%s'%(p.returncode,' '.join(args),(' — '+cause) if cause else '',(' — see '+str(log))if log else '\n'+p.stdout[-4000:]))
    return p

def atomic_json(path,obj):
    tmp=path.with_name(path.name+'.tmp-'+uuid.uuid4().hex)
    with tmp.open('x') as f:json.dump(obj,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    tmp.chmod(0o644);tmp.replace(path)

sys.path.insert(0, str(HERE.parent / 'common'))
from evaluation_runtime import split_distribution, issuer_image
from run_names import project_name, release_id  # preview.40 review item 01: pail-<kind>-<release>-<run>
ISSUER_REQUIRED = ('Issuer source is not supplied. Use the complete evaluation bundle with '
                   'its images.lock.json and load the pinned Issuer image. See RELEASE.md.')

def require_issuer():
    if split_distribution(ROOT):
        return issuer_image(ROOT)
    if not (ROOT/'cloud/issuer/cmd/pail_services').is_dir():
        raise ValueError(ISSUER_REQUIRED)
    return None

def doctor():
    if not (ROOT/'sdk/proto/pail.proto').is_file():raise ValueError('Use the public source snapshot: sdk/proto/pail.proto is required')
    server=json.loads(call(['docker','version','--format','{{json .Server}}']).stdout)
    if server.get('Os')!='linux':raise ValueError('Linux Docker containers required')
    call(['docker','compose','version'])
    mask=os.umask(0);os.umask(mask)
    out=dict(host=platform.system(),machine=platform.machine(),docker_os=server['Os'],container_arch=server['Arch'],umask=format(mask,'04o'))
    # What the Docker host has, and how busy it is. A fleet's timed scenes fail on a Docker host
    # that is out of memory or crowded (DEMO.md section 8); say so here.
    try:
        cpus,mem,running=call(['docker','info','--format','{{.NCPU}} {{.MemTotal}} {{.ContainersRunning}}']).stdout.split()
        out.update(docker_cpus=int(cpus),docker_memory_mib=int(mem)//1048576,containers_running=int(running))
        if int(running)>=20 or int(mem)//1048576<8192:
            out['note']='busy or small Docker host: timed scenes, fleet scenes especially, may fail here (DEMO.md section 8)'
    except (ValueError,OSError):
        out['docker_info']='unavailable'
    return out

def build(image,log):
    doctor();print('Building public Core, adapter and official fake; first build downloads dependencies.',flush=True)
    from results import tree_manifest
    digest=tree_manifest(ROOT)['sha256']
    sys.path.insert(0,str(HERE.parent/'common'))
    from build_runtime import Builder
    work=Path(tempfile.mkdtemp(prefix='pail-duck-build-'))
    with Path(log).open('a') as f:f.write('BOUNDED_BUILD_EVIDENCE='+str(work)+'\n')
    with Builder(work) as builder:
        return builder.build(ROOT,HERE/'Dockerfile',args=['PAIL_SOURCE_SHA256='+digest,'PAIL_VERSION='+(ROOT/'VERSION').read_text().strip()])

def environment(state,meta):
    # one communication contract (0.2.0-preview.40): a run recorded under the removed `legacy` contract is not revived
    if meta.get('contract')=='legacy':raise ValueError('LEGACY_RUN_UNSUPPORTED: this run was recorded with the removed `legacy` contract; clean it with this release\'s `cleanup --state <dir>` (stopping it with the release that created it also works), then start a new run')
    e=os.environ.copy();e.update(PAIL_DUCK_STATE=str(state),PAIL_DUCK_IMAGE=meta['image']);e.pop('PAIL_CORE_COMM_CONTRACT',None);e['PAIL_DUCK_ISSUER_IMAGE']=meta.get('issuer_image') or require_issuer() or meta['image'];return e

def resolve_issuer_image(reference):
    """`--issuer-image`: the Issuer evaluation image to run beside a tree that has no images.lock.json of its own
    (a working copy). Must exist locally and be the Issuer component; recorded by immutable ID."""
    p=call(['docker','image','inspect',reference,'--format','{{.Id}} {{index .Config.Labels "org.pail.component"}}'],check=False)
    if p.returncode:raise ValueError('ISSUER_IMAGE_MISSING: '+reference+' is not a local image; load the delivered Issuer archive first')
    image_id,component=(p.stdout.split()+[''])[:2]
    if component!='issuer-eval':raise ValueError('ISSUER_IMAGE_WRONG_COMPONENT: '+reference+' is not the Issuer evaluation image (label org.pail.component='+component+')')
    return image_id

def compose(state,meta):
    cmd=['docker','compose','--project-name',meta['project'],'-f',str(HERE/'compose.yaml')]
    if meta['profile']=='conformance':cmd+=['-f',str(HERE/'compose.conformance.yaml')]
    if meta.get('custom_adapter'):cmd+=['-f',str(state/'adapter.compose.json')]
    return cmd

def load(state):
    if state.is_symlink():raise ValueError('State must not be a symlink')
    meta=json.loads((state/'run.json').read_text())
    if meta['state']!=str(state) or not re.fullmatch('pail-duck-[a-f0-9]{12}',meta['project']):raise ValueError('State identity mismatch')
    return meta

def clean_stop(state,meta):call(compose(state,meta)+['down','--remove-orphans'],env=environment(state,meta),log=state/'stop.log')

def run(profile,state,image,skip_build=False,adapter_binary=None,backend='microduck_uds',issuer_image=None,reviewed_skips=(),demo_inconclusive=False):
    # one communication contract (0.2.0-preview.40): no selecting setting; the variable present at all — even empty
    # (0.2.0-preview.41, P40-L2) — refuses with the message of core_operation_wire.py
    if 'PAIL_CORE_COMM_CONTRACT' in os.environ:raise ValueError('CORE_COMM_CONTRACT_SETTING_REMOVED: PAIL_CORE_COMM_CONTRACT has no meaning (there is one communication contract); unset it')
    if state.exists() and (state.is_symlink() or any(state.iterdir())):raise ValueError('Choose a new empty state directory')
    if ROOT == state.resolve() or ROOT in state.resolve().parents:raise ValueError('Keep generated state outside the source tree')
    if ':' in backend and profile!='conformance':raise ValueError('A custom backend applies to the conformance profile only')
    state.mkdir(parents=True,exist_ok=True);state.chmod(0o755)
    for name,mode in [('control',0o700),('evidence',0o755)]:
        (state/name).mkdir();(state/name).chmod(mode)
    meta=dict(run_id=uuid.uuid4().hex,project=project_name('duck',release_id(ROOT)),state=str(state),image=image,profile=profile,status='PREFLIGHT',environment=doctor(),hardware_tested=False,backend=backend)
    peers=['prepare','issuer','agent','fake','adapter','harness']
    if profile=='conformance':peers+=['token-seam','state-seam','observe-issuer','observe-agent','observe-fake','observe']
    if issuer_image:meta['issuer_image']=resolve_issuer_image(issuer_image)
    from results import tree_manifest
    source=tree_manifest(ROOT);atomic_json(state/'source-manifest.json',source);meta['source_manifest_sha256']=source['sha256']
    meta['retained_volumes']=[meta['project']+'_private',meta['project']+'_run']
    meta['started_at_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    atomic_json(state/'run.json',meta);print('STATE='+str(state),flush=True)
    if adapter_binary:
        import shutil
        source=Path(adapter_binary).resolve()
        if not source.is_file():raise ValueError('CUSTOM_ADAPTER_NOT_FOUND: '+str(source)+' is not an existing file')   # a named refusal, not a traceback
        head=source.read_bytes()[:64]
        if head[:4]!=b'\x7fELF' or head[4]!=2 or int.from_bytes(head[18:20],'little')!=183:
            raise ValueError('CUSTOM_ADAPTER_PLATFORM: supply an executable Linux ARM64 ELF binary with the documented Microduck UDS contract')
        target=state/'adapter-under-test';shutil.copyfile(source,target);target.chmod(0o555)
        meta['custom_adapter']={'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'source':str(source),'mounted_roles':['adapter','observe','harness']}
        patch={'services':{role:{'volumes':[str(target)+':/usr/local/bin/pail-duckd:ro']} for role in meta['custom_adapter']['mounted_roles']}}
        atomic_json(state/'adapter.compose.json',patch);atomic_json(state/'run.json',meta)
    cmd=compose(state,meta);env=environment(state,meta);result=dict(status='BLOCKED',hardware_tested=False,checks=[]);exitcode=3
    try:
        if not skip_build:meta['image_id']=build(image,state/'build.log')
        else:meta['image_id']=call(['docker','image','inspect',image,'--format','{{.Id}}']).stdout.strip()
        labels=json.loads(call(['docker','image','inspect',meta['image_id'],'--format','{{json .Config.Labels}}']).stdout) or {}
        if labels.get('org.pail.source-manifest-sha256')!=meta['source_manifest_sha256']:
            from build_runtime import source_mismatch
            raise RuntimeError(source_mismatch(ROOT))
        meta['core_version']=(ROOT/'VERSION').read_text().strip()
        meta['upstream_commit']='942e58e3aa6dbb28e7037203fff11866122c7567'
        meta['api_version']=44
        meta['image']=meta['image_id'];env=environment(state,meta);meta['status']='PREPARED';atomic_json(state/'run.json',meta)
        call(cmd+['run','--rm','prepare'],env=env,log=state/'prepare.log')
        call(cmd+['up','-d','issuer','agent','fake'],env=env,log=state/'startup.log')
        deadline=time.monotonic()+60
        while True:
            p=call(cmd+['exec','-T','fake','python','-c','import os; assert os.path.exists("/run/duck/raw/robotd.sock")'],env=env,check=False)
            if p.returncode==0:break
            if time.monotonic()>deadline:raise RuntimeError('Fake readiness deadline expired')
            time.sleep(.5)
        if profile=='conformance':
            call(cmd+['up','-d','token-seam','state-seam','observe-issuer','observe-agent','observe-fake'],env=env,log=state/'startup.log')
            deadline=time.monotonic()+30
            while True:
                p=call(cmd+['exec','-T','state-seam','python','-c','import os; assert os.path.exists("/run/duck/raw/state-seam.sock") and os.path.exists("/run/duck/seam.ctl") and os.path.exists("/run/duck/raw/observe-robotd.sock")'],env=env,check=False)
                if p.returncode==0:break
                if time.monotonic()>deadline:raise RuntimeError('Fault seam readiness expired')
                time.sleep(.2)
        call(cmd+['up','-d','adapter']+(['observe']if profile=='conformance'else[]),env=env,log=state/'startup.log')
        deadline=time.monotonic()+60
        while True:
            p=call(cmd+['run','--rm','--no-deps','harness','python','/opt/pail/example/support.py','ready'],env=env,check=False)
            if p.returncode==0:break
            if time.monotonic()>deadline:raise RuntimeError('Readiness deadline expired: '+p.stdout[-2000:])
            time.sleep(.5)
        call(cmd+['run','--rm','--no-deps','harness','python','/opt/pail/example/support.py','permissions'],env=env,log=state/'permission.log')
        meta['status']='RUNNING';atomic_json(state/'run.json',meta)
        if profile=='demo':
            p=call(cmd+['run','--rm','--no-deps','harness','python','/opt/pail/example/support.py','demo'],env=env,log=state/'execution.log',check=False)
            result=json.loads((state/'evidence/demo.json').read_text())
            ok=p.returncode==0 and len(result['checks'])==3 and all(x['status']=='PASS' for x in result['checks'])
            result['status']='PASS'if ok else'FAIL';exitcode=0 if ok else 1
        else:
            from control import serve_pending
            args=cmd+['run','--rm','--no-deps','harness','python','/opt/pail/pvs/conformance/run.py','--backend',backend,'--report','/state/evidence/conformance.json']
            if ':' in backend:args+=['--rows-of','microduck_uds']   # a custom transport executes the Microduck column of CA_MAP until it has its own
            for item in reviewed_skips:args+=['--reviewed-skip',item]   # a backend's own Unsupported, accepted with a written reason (results.classify)
            if os.environ.get('PAIL_DUCK_CASES'):args+=['--only',os.environ['PAIL_DUCK_CASES']]
            if demo_inconclusive:
                # the INCONCLUSIVE path on purpose: the harness stalls its own gate-log tail after the first record, so CA-09 comes
                # out INCONCLUSIVE twice (one retry) and the run ends with exit 4 and a DIAGNOSIS line — a demo of the word, not a judgement
                args+=['--observation-fault','tail_stall']
                if not os.environ.get('PAIL_DUCK_CASES'):args+=['--only','CA-09']   # two gate expectations in sequence: the second one meets the stalled tail
            with (state/'execution.log').open('a') as log:
                child=subprocess.Popen(args,env=env,stdout=log,stderr=subprocess.STDOUT)
                deadline=time.monotonic()+600
                try:
                    while child.poll() is None:
                        serve_pending(state,meta,cmd,env,atomic_json)
                        if time.monotonic()>deadline:raise RuntimeError('Conformance deadline expired')
                        time.sleep(.05)
                finally:
                    if child.poll() is None:child.terminate();child.wait(timeout=10)
            from results import classify
            result=classify(json.loads((state/'evidence/conformance.json').read_text()),child.returncode,demo_inconclusive=demo_inconclusive)
            exitcode=0 if result['status'] in ['PASS','PASS_WITH_LIMITATIONS'] else 3 if result['status']=='BLOCKED' else 4 if result['status']=='INCONCLUSIVE' else 1
            meta['reviewed_skips']=list(reviewed_skips)
    except KeyboardInterrupt:result['status']='INTERRUPTED';exitcode=130
    except Exception as e:result['error']=str(e);print(str(e),file=sys.stderr)
    finally:
        call(cmd+['logs','--no-color'],env=env,log=state/'services.log',check=False)
        if (state/'evidence/permissions.json').exists():result['access_contract']=json.loads((state/'evidence/permissions.json').read_text())
        try:clean_stop(state,meta)
        except Exception as e:result['cleanup_error']=str(e);exitcode=3
        meta['ended_at_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
        result['source_manifest_sha256']=meta['source_manifest_sha256'];result['artifact_sha256']=None
        if profile=='conformance':
            # Which gate refusals the rig saw, so a red run during clock steps is named as such instead of blamed on the adapter.
            from results import gate_refusals
            result['gate_refusals']=gate_refusals(state)
        meta['status']=result['status'];atomic_json(state/'run.json',meta);result['run']=meta;atomic_json(state/'result.json',result)
        print('RESULT='+result['status']+' report='+str(state/'result.json'),flush=True)
        if result.get('gate_refusals',{}).get('diagnosis') and result['status'] not in ('PASS','PASS_WITH_LIMITATIONS'):
            print('DIAGNOSIS: '+result['gate_refusals']['diagnosis'],flush=True)
        if result.get('status')=='INCONCLUSIVE':
            print('DIAGNOSIS: INCONCLUSIVE — '+' || '.join(l for l in result.get('limitations',[]) if 'INCONCLUSIVE' in l)
                  +' — the adapter was neither passed nor failed on these cases; run again with a NEW --state on a quiet host',flush=True)
    return exitcode

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('action',choices=['doctor','build','demo','conformance','status','stop']);ap.add_argument('--state',type=Path);ap.add_argument('--image',default=IMAGE);ap.add_argument('--skip-build',action='store_true',help='Reuse verified runtime images');ap.add_argument('--adapter-binary',type=Path)
    ap.add_argument('--build',action='store_true',help='build the Core image from THIS tree (online), even when the tree is a delivered split distribution; the way to run a working copy with your own backend')
    ap.add_argument('--backend',default='microduck_uds',help='conformance backend: microduck_uds (default) or a custom MODULE:CLASS under pvs-public/runner/adapters/ of the built tree')
    ap.add_argument('--issuer-image',help='Issuer evaluation image (ID or tag, loaded locally) to run beside a tree without its own images.lock.json, e.g. a working copy built with --build')
    ap.add_argument('--demo-inconclusive',action='store_true',help='conformance only: run CA-09 with the gate-log tail deliberately stalled so the INCONCLUSIVE result (exit 4, DIAGNOSIS line) can be seen before it is relied on; the result is a demonstration, not a judgement of the adapter')
    ap.add_argument('--reviewed-skip',action='append',default=[],metavar='CA-ID:REASON',help='conformance only: accept one case your backend reports as Unsupported, with the reason recorded; the row stays SKIP and the result becomes PASS_WITH_LIMITATIONS instead of BLOCKED. Repeatable')
    a=ap.parse_args()
    if a.reviewed_skip and a.action!='conformance':ap.error('--reviewed-skip applies to the conformance profile')
    if a.demo_inconclusive and a.action!='conformance':ap.error('--demo-inconclusive applies to the conformance profile')
    for item in a.reviewed_skip:   # refused here, before any stack starts — not by the harness after the rig is up
        if not re.fullmatch(r'CA-\d\d:\S.*',item):ap.error('--reviewed-skip wants CA-NN:REASON with a non-empty reason, got %r'%item)
    if a.build and a.skip_build:ap.error('--build and --skip-build exclude each other')
    if a.action not in ('build','doctor') and not a.issuer_image:require_issuer()
    if a.action=='doctor':print(json.dumps(doctor(),indent=2));return 0
    if a.action=='build':print(build(a.image,HERE/'build.log'));return 0
    if a.state is None:ap.error('--state required')
    if a.action in ('demo','conformance') and split_distribution(ROOT) and a.image==IMAGE and not a.build:
        from evaluation_runtime import runtime_images
        a.image=runtime_images(ROOT)['microduck'];a.skip_build=True
    state=a.state.absolute()
    if a.action in ['demo','conformance']:return run(a.action,state,a.image,a.skip_build,a.adapter_binary,a.backend,a.issuer_image,tuple(a.reviewed_skip),a.demo_inconclusive)
    meta=load(state)
    if a.action=='status':print(json.dumps(meta,indent=2));return 0
    clean_stop(state,meta);return 0
if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,RuntimeError) as e:print('REFUSED: '+str(e),file=sys.stderr);sys.exit(2)
