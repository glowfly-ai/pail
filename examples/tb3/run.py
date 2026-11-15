#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Build and test ONLY this public tree. Generated keys/state stay outside it.
Usage: python3 examples/tb3/run.py [--state /absolute/new/directory] [--skip-build]
No motors, external ports or host DDS. Raw evidence and machine verdicts are retained.
"""
import argparse,hashlib,json,os,re,shutil,subprocess,sys,tempfile,time,traceback,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state');p.add_argument('--skip-build',action='store_true');p.add_argument('--remove-images',action='store_true',help='Remove only image tags built by this run after evidence collection; never remove reused images');a=p.parse_args()
# Fail before creating state or generating keys when prerequisites are missing.
if os.name != 'posix':
 print('Native Windows is not supported by this runner. Use Linux/macOS; WSL2 is not yet validated.',file=sys.stderr);sys.exit(2)
for tool in ('docker','openssl'):
 if not shutil.which(tool):print('Missing prerequisite: '+tool,file=sys.stderr);sys.exit(2)
sys.path.insert(0, str(ROOT / 'examples/common'))
from evaluation_runtime import split_distribution, runtime_images
from run_names import project_name, release_id  # preview.40 review item 01: pail-<kind>-<release>-<run>
locked_images = runtime_images(ROOT) if split_distribution(ROOT) else None
if locked_images:
 a.skip_build = True
 os.environ['PAIL_TB3_CLOUD_IMAGE'] = locked_images['issuer']
 os.environ['PAIL_TB3_GATE_IMAGE'] = locked_images['tb3_gate']
elif not (ROOT/'cloud/issuer/cmd/pail_services').is_dir():
 print('Issuer evaluation image is required. Use the matching evaluation bundle.',file=sys.stderr);sys.exit(2)
for args,hint in [(['docker','compose','version'],'Install the Docker Compose v2 plugin.'),(['docker','info'],'Start Docker Desktop/Engine and check your Docker context and permissions.')]:
 try:
  r=subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True,timeout=20)
 except (OSError,subprocess.TimeoutExpired):print(hint,file=sys.stderr);sys.exit(2)
 if r.returncode:print(hint,file=sys.stderr);sys.exit(2)
state=Path(a.state).resolve() if a.state else Path(tempfile.mkdtemp(prefix='pail-tb3-'))
if state==ROOT or ROOT in state.parents:raise SystemExit('state must be outside the source tree')
if state.exists() and any(state.iterdir()):raise SystemExit('state must be empty; old runs must remain intact')
permission_tool=ROOT/'examples/tb3/permissions.py'
policy=json.loads(subprocess.check_output([sys.executable,'-B',str(permission_tool),'describe'],text=True))
subprocess.run([sys.executable,'-B',str(permission_tool),'init','--state',str(state)],check=True)
e=state/'evidence';cfg=state/'runtime/config'
(e/'permission-policy.json').write_text(json.dumps(policy,indent=2)+'\n')
project=project_name('tb3',release_id(ROOT));env=dict(os.environ,PAIL_TB3_STATE=str(state));ci='pail/tb3-cloud:'+project;gi='pail/tb3-gate:'+project
env['PAIL_TB3_CLOUD_IMAGE']=ci;env['PAIL_TB3_GATE_IMAGE']=gi
compose=['docker','compose','-p',project,'-f',str(ROOT/'examples/tb3/compose.yaml')]
# one communication contract (0.2.0-preview.40): nothing selects it, no cohort override
checks=[];started=False;created_images=[];manifest={}
print('STATE='+str(state),flush=True)
class PrerequisiteFailed(RuntimeError):pass
def cmd(args,name,timeout=1200):
 with (e/(name+'.log')).open('w') as f:
  proc=subprocess.run(args,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
 if proc.returncode:
  if name=='up':
   # P23-L1: a stack that did not come up blocks the test; name the cause on the top line (examples/common/compose_failure.py)
   from compose_failure import explain_file
   raise StackNotUp('STACK_NOT_UP — '+(explain_file(e/'up.log') or 'cause not recognised; see '+str(e/'up.log')))
  error=PrerequisiteFailed if name in ['runtime-ownership','reference-access','permission-service','permission-host'] else RuntimeError
  raise error(name+' rc='+str(proc.returncode)+'; see '+str(e/(name+'.log')))
 return (e/(name+'.log')).read_text()
def verify_journal():
 # blackbox_verify exits 7 while the newest records are not yet under a signed checkpoint. The Issuer covers them once
 # its writes pause for about a second, so wait for that instead of accepting records outside every signature.
 for attempt in range(6):
  try:return cmd(compose+['exec','-T','issuer','blackbox_verify','-check-chain','-dir','/var/log/pail_blackbox','-keyfile','/etc/pail/keys/issuer_ed25519.json'],'journal-verify')
  except RuntimeError:
   if attempt==5 or 'UNATTESTED_TAIL' not in (e/'journal-verify.log').read_text():raise
   time.sleep(1.5)
def check(id,ok,expected,actual):
 checks.append(dict(id=id,passed=bool(ok),expected=expected,actual=actual,t=time.time()));print(('PASS ' if ok else 'FAIL ')+id+' '+str(actual),flush=True)
 (e/'results.json').write_text(json.dumps(checks,indent=2))
 if not ok:raise AssertionError(id)
def wait(fn,label,timeout=50):
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.25)
 raise AssertionError('no observation: '+label)
class ClockPrerequisiteFailed(PrerequisiteFailed):pass
class StackNotUp(PrerequisiteFailed):pass
clock_offsets={}
log_sizes={}
def check_clock(role,wall,mono):
 offset=wall-mono
 if role not in clock_offsets:clock_offsets[role]=offset
 drift=offset-clock_offsets[role]
 if abs(drift)>.25:
  (e/'clock-prerequisite.json').write_text(json.dumps({'passed':False,'role':role,'wall_minus_monotonic_change_seconds':drift,'harness_tolerance_seconds':.25,'security_thresholds_changed':False},indent=2))
  raise ClockPrerequisiteFailed('CLOCK_PREREQUISITE_FAILED: wall/monotonic discontinuity for '+role)
def rows(role,since=0):
 check_clock('runner',time.time(),time.monotonic())
 f=e/'runtime'/(role+'.jsonl')
 try:body=f.read_text()
 except FileNotFoundError:
  if role in log_sizes:raise PrerequisiteFailed('OBSERVATION_UNAVAILABLE: previously observed log disappeared: '+str(f))
  return []
 except OSError as ex:raise PrerequisiteFailed('OBSERVATION_UNAVAILABLE: cannot read '+str(f)+': '+str(ex)) from ex
 if len(body)<log_sizes.get(role,0):raise PrerequisiteFailed('OBSERVATION_UNAVAILABLE: log shrank: '+str(f))
 if body:log_sizes[role]=len(body)
 out=[]
 for l in body.splitlines():
  try:r=json.loads(l)
  except ValueError:continue
  if 'mono' not in r:raise RuntimeError('observer record lacks monotonic timestamp')
  check_clock(role,r['t'],r['mono'])
  if r.get('reason')=='ERR_CLOCK_DRIFT':
   (e/'clock-prerequisite.json').write_text(json.dumps({'passed':False,'role':role,'reason':'ERR_CLOCK_DRIFT','security_thresholds_changed':False}))
   raise ClockPrerequisiteFailed('CLOCK_PREREQUISITE_FAILED: gate reports ERR_CLOCK_DRIFT')
  if r['t']>=since:out.append(r)
 return out
def gate(since,**kw):return [r for r in rows('planner',since) if r['event']=='gate' and all(r.get(k)==v for k,v in kw.items())]
def drives(since):return [r for r in rows('base',since) if r['event']=='drive' and (abs(r['x'])>1e-8 or abs(r['z'])>1e-8)]
def set_input(on,speed=.05):
 f=state/'control/input.next'
 with f.open('w') as stream:
  stream.write(json.dumps(dict(on=on,speed=speed)));stream.flush();os.fsync(stream.fileno())
 f.chmod(0o644);f.replace(state/'control/input.json')
def json_line(s):
 # tb3-probe writes its log on stderr (e.g. "authorization request plan=… operation=…" since the communication-contract
 # operation ids) and cmd() keeps stderr in the same log file; the result is the last JSON object line, as every other
 # probe caller reads it (hardware/console_hw.py, tools/latency/lat_run.py). Parsing the whole capture broke on the
 # first stderr line (preview.39 stage-07 Linux replay: "Extra data: line 1 column 5").
 lines=[l for l in s.splitlines() if l.startswith('{')]
 if not lines:raise ValueError('probe printed no JSON line: '+s.strip()[-300:])
 return json.loads(lines[-1])
def probe(mode='peek',duration=6):
 s=cmd(compose+['exec','-T','issuer','tb3-probe','-mode',mode,'-duration',str(duration)],'probe-'+mode+'-'+str(time.time_ns()),30)
 return json_line(s)
try:
 manifest={str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for f in ROOT.rglob('*') if f.is_file() and '.git' not in f.parts}
 (e/'source_manifest.json').write_text(json.dumps(manifest,indent=2))
 if not a.skip_build:
  print('Building cloud and gate from this tree; first build may take 10–20 minutes.',flush=True)
  cmd(['docker','build','--progress=plain','-t',ci,'-f','docker/Dockerfile.cloud','.'],'build-cloud');created_images.append(ci)
  cmd(['docker','build','--progress=plain','--build-arg','PAIL_BUILD_JOBS=2','-t',gi,'-f','docker/Dockerfile.gate','.'],'build-gate');created_images.append(gi)
 else:
  # Reuse is explicit and requires separately supplied image tags.
  ci=os.environ['PAIL_TB3_CLOUD_IMAGE'];gi=os.environ['PAIL_TB3_GATE_IMAGE'];env['PAIL_TB3_CLOUD_IMAGE']=ci;env['PAIL_TB3_GATE_IMAGE']=gi
 image_info=json.loads(subprocess.check_output(['docker','image','inspect',ci,gi],text=True))
 (e/'images.json').write_text(json.dumps([dict(id=x['Id'],architecture=x['Architecture'],tags=x['RepoTags']) for x in image_info],indent=2))
 for f in ['policy.yaml','sros2_policy.xml','skills.diff_drive_amr.yaml']:shutil.copy2(ROOT/'config'/f,cfg/f)
 pol=(cfg/'policy.yaml').read_text();pol=pol.replace('max_linear_speed_mps: 1.0','max_linear_speed_mps: 0.1').replace('sls.linear_mps: 1.0','sls.linear_mps: 0.1').replace('token_ttl_ms: 3600000','token_ttl_ms: 30000')
 if '\ntoken_schema:' in pol:raise RuntimeError('review existing token schema before overriding')
 (cfg/'policy.yaml').write_text(pol+'\ntoken_schema: 5\n');shutil.copy2(ROOT/'examples/tb3/site_model.yaml',cfg/'site_model.yaml')
 shutil.copy2(ROOT/'scripts/gen_dev_keys.py',state/'runtime/scripts/gen_dev_keys.py');cmd([sys.executable,'-B',str(state/'runtime/scripts/gen_dev_keys.py')],'generate-keys')
 cmd(['docker','run','--rm','-u',str(os.getuid())+':'+str(os.getgid()),'-e','HOME=/tmp','-v',str(ROOT)+':/src:ro','-v',str(state)+':/state','--entrypoint','bash',gi,'-c','source /opt/ros/humble/setup.bash && bash /src/scripts/sros2_provision.sh /state/runtime/config robot-01'],'provision')
 der=subprocess.check_output(['openssl','x509','-in',str(cfg/'grpc_certs/robot-01/client.crt'),'-outform','DER']);fp=hashlib.sha256(der).hexdigest()
 (cfg/'requesters.yaml').write_text('version: 1\nrequesters:\n  - match: {caller: mtls, cert_sha256: "'+fp+'"}\n    kind: agentic_ai\n    id: reference-planner\n    skills: [twist]\n')
 def sign(args,name):return cmd(['docker','run','--rm','-u',str(os.getuid())+':'+str(os.getgid()),'--network','none','-v',str(cfg)+':/config','-v',str(state/'root-keys')+':/root-keys','--entrypoint','pail-keyring-sign',ci]+args,name)
 text=sign(['gen-root','--out','/root-keys/root.json','--key-id','reference-root'],'generate-root');pub=next(l.split('=',1)[1] for l in text.splitlines() if l.startswith('ROOT_PUBKEY_B64='));(cfg/'keys/root_pub.b64').write_text(pub+'\n')
 now=int(time.time());(cfg/'keys/payload.json').write_text(json.dumps(dict(bundle_version=1,issued_at_unix=now,expires_at_unix=now+3600,keys=json.loads((cfg/'keys/keyring.json').read_text())['keys'])))
 sign(['sign','--root','/root-keys/root.json','--payload','/config/keys/payload.json','--out','/config/keys/keyring_bundle.json'],'sign-bundle')
 # Public launch/actor/XML inputs are copied, not bound from the caller's checkout.
 # copyfile + explicit modes deliberately do not inherit restrictive archive/umask modes.
 reference=state/'runtime/reference'
 cmd([sys.executable,'-B',str(permission_tool),'stage','--state',str(state),'--core',str(ROOT)],'reference-files')
 # `stage` prints one JSON line {sha256:{name:digest},mode,source_unchanged} (examples/tb3/permissions.py). Keep the
 # staged digests: the cross-UID read below must observe exactly these bytes for exactly the declared reference set.
 staged=json.loads([line for line in (e/'reference-files.log').read_text().splitlines() if line.startswith('{')][-1])
 reference_hashes=staged['sha256']
 if sorted(reference_hashes)!=sorted(policy['reference_files']):raise RuntimeError('staged reference set differs from the declared policy')
 (e/'reference-files.json').write_text(json.dumps(staged,indent=2)+'\n')
 cmd(['docker','run','--rm','-u','0','--network','none','-v',str(state)+':/state','--entrypoint','python3',gi,'/state/runtime/reference/permissions.py','prepare','--state','/state'],'runtime-ownership')
 cmd(['docker','run','--rm','--network','none','-u','10001:10001','-v',str(reference)+':/reference:ro','--entrypoint','python3',gi,'-c',
      'import os,hashlib,json; from pathlib import Path; names='+json.dumps(policy['reference_files'])+'; print(json.dumps({"uid":os.getuid(),"sha256":{n:hashlib.sha256((Path("/reference")/n).read_bytes()).hexdigest() for n in names}}))'],'reference-access')
 # The log holds stdout and stderr together; a Docker platform warning (bundle run on a foreign
 # architecture) precedes the JSON line. Parse the last JSON object, never the whole log.
 observed=json.loads([line for line in (e/'reference-access.log').read_text().splitlines() if line.startswith('{')][-1])
 if observed['uid']!=10001 or observed['sha256']!=reference_hashes:raise RuntimeError('runtime reference read does not match staged bytes')
 set_input(False)
 mounts=[]
 for name,readonly in [('runtime/config',True),('runtime/reference',True),('control',True),('evidence/runtime',False),('blackbox',False),('keyring-state',False)]:
  mounts+=['-v',str(state/name)+':/state/'+name+(':ro' if readonly else '')]
 cmd(['docker','run','--rm','--network','none','-u','10001:10001',*mounts,'--entrypoint','sh',gi,'-c','umask 077; exec python3 /state/runtime/reference/permissions.py runtime --state /state'],'permission-service')
 cmd([sys.executable,'-B',str(permission_tool),'host','--state',str(state)],'permission-host')
 cmd(compose+['up','-d'],'up');started=True
 cids=subprocess.check_output(compose+['ps','-aq'],env=env,text=True).split()
 runtime=json.loads(subprocess.check_output(['docker','inspect',*cids],text=True));layout=[]
 for container in runtime:
  host=container['HostConfig'];assert not host['Privileged'] and not host.get('Devices') and not host.get('PortBindings') and host['NetworkMode']!='host'
  layout.append(dict(name=container['Name'],image=container['Image'],network=host['NetworkMode'],devices=host.get('Devices'),privileged=host['Privileged']))
 (e/'runtime-layout.json').write_text(json.dumps(layout,indent=2))
 def ready():
  try:return probe()['status']=='NO_TOKEN'
  except RuntimeError:return False
 wait(ready,'issuer readiness')
 for role,enclave in [('planner','oem_planner'),('base','driver'),('safety','safety_adapter'),('evidence','perception')]:
  cmd(compose+['exec','-d','-e','ROS_SECURITY_ENCLAVE_OVERRIDE=/'+enclave,'robot','bash','-c','source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && umask 077 && touch /evidence/runtime/'+role+'-process.log && chmod 0644 /evidence/runtime/'+role+'-process.log && exec python3 -u /reference/mock_io.py --role '+role+' > /evidence/runtime/'+role+'-process.log 2>&1'],'actor-'+role)
 for role in ['planner','base','safety','evidence']:wait(lambda r=role:any(x['event']=='ready' for x in rows(r)),role+' ready')
 end=time.monotonic()+50  # the actors' ready rows can land before the gate entrypoint prints its preflight; re-read the log until S33 is there or 50 s pass
 while True:
  boot=cmd(compose+['logs','robot'],'robot-boot')
  if 'S33 OK' in boot or time.monotonic()>end:break
  time.sleep(.5)
 check('registry_loaded','S33 OK' in boot,'S33 checks registry','S33 OK' in boot)
 start=time.time();set_input(True);wait(lambda:len(gate(start,reason='ERR_NO_TOKEN'))>=10,'no token blocks');time.sleep(2);end=time.time();noauth=len(drives(start));noauth_window=[start,end];set_input(False)
 r=probe('submit');t=r['tokens'][0];check('v5_signed_metadata',r['status']=='ACCEPTED' and t['schema']==5 and t['skill']=='twist','ACCEPTED/schema5/twist',t)
 start=time.time();set_input(True);wait(lambda:gate(start,state='PERMIT',token=t['id']),'matching permit');wait(lambda:len(drives(start))>=5,'same base observer sees output');check('base_forward',True,'nonzero base input',len(drives(start)))
 check('no_authority_blocks',noauth==0,'zero before authorization, live observer afterwards',dict(nonzero=noauth,window=noauth_window))
 last=time.time()
 def completed():
  observed=gate(last,state='BLOCK')
  if not any(x['reason'] in ['ERR_TOKEN_CONSUMED','ERR_NO_TOKEN'] for x in observed):return False
  log=cmd(compose+['logs','--no-color','robot'],'completion-observation')
  marker='step complete: token '+t['id']+' consumed'
  if marker not in log:return False
  (e/'completion-observation.json').write_text(json.dumps({'token_id':t['id'],'marker':marker,'observed':True},indent=2));return True
 wait(completed,'consumption of the issued token after duration')
 time.sleep(1);mark=time.time();time.sleep(2);check('completion_stops',len(drives(mark))==0,'zero nonzero output after matched-token duration consumption',len(drives(mark)));set_input(False)
 r=probe('submit',20);start=time.time();set_input(True);wait(lambda:gate(start,state='PERMIT',token=r['tokens'][0]['id']),'second positive control');wait(lambda:drives(start),'second base output')
 start=time.time();set_input(True,.2);wait(lambda:gate(start,reason='ERR_CONSTRAINT'),'speed limit refusal');time.sleep(1);mark=time.time();time.sleep(2);check('speed_limit',len(drives(mark))==0,'0.2 rejected under 0.1 bound',len(drives(mark)))
 start=time.time();set_input(True,.05);wait(lambda:drives(start),'valid speed restored')
 # Stop only the gate child. The bridge and mock base remain running under launch.
 start=time.time();cmd(compose+['exec','-T','robot','pkill','-KILL','-x','pep_gate_node'],'kill-gate');wait(lambda:any(r['event']=='drive' and r['x']==0 and r['z']==0 for r in rows('base',start)),'bridge explicit zero');time.sleep(1);mark=time.time();time.sleep(2);check('bridge_deadman',not drives(mark),'zero with planner still publishing',dict(nonzero=len(drives(mark)),inputs=sum(x['event']=='input' for x in rows('planner',mark))))
 set_input(False);time.sleep(2)
 out=verify_journal();ck=re.search(r'(\d+) checkpoints',out);check('journal_verifies','OK: chain verified' in out and ck is not None and int(ck[1])>0,'chain + at least one checked signature',out.strip())
except Exception as ex:
 if isinstance(ex,PrerequisiteFailed):(e/'prerequisite-failure.json').write_text(json.dumps({'kind':'clock' if isinstance(ex,ClockPrerequisiteFailed) else 'stack' if isinstance(ex,StackNotUp) else 'permissions','message':str(ex)},indent=2))
 (e/'error.txt').write_text(traceback.format_exc());print('ERROR '+str(ex),flush=True)
finally:
 set_input(False)
 if started:
  for service in ['issuer','robot']:subprocess.run(compose+['logs','--no-color',service],env=env,stdout=(e/(service+'-final.log')).open('w'),stderr=subprocess.STDOUT)
  subprocess.run(compose+['cp','issuer:/var/log/pail_blackbox',str(e/'journal')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  subprocess.run(compose+['down'],env=env,stdout=(e/'cleanup.log').open('w'),stderr=subprocess.STDOUT)
 image_cleanup={'created_tags':created_images,'remove_requested':a.remove_images,'results':[]}
 for tag in created_images:
  if a.remove_images:
   removed=subprocess.run(['docker','image','rm',tag],text=True,capture_output=True)
   image_cleanup['results'].append({'tag':tag,'rc':removed.returncode,'message':(removed.stdout+removed.stderr).strip()})
   print(('IMAGE_REMOVED ' if removed.returncode==0 else 'IMAGE_RETAINED ')+tag,flush=True)
  else:print('IMAGE_RETAINED '+tag+'; optional cleanup: docker image rm '+tag,flush=True)
 if a.skip_build:print('Reused images retained; this run does not own their tags.',flush=True)
 (e/'image-cleanup.json').write_text(json.dumps(image_cleanup,indent=2))
 after={str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for f in ROOT.rglob('*') if f.is_file() and '.git' not in f.parts}
 if after!=manifest:(e/'error.txt').write_text('source tree changed during the run')
 success=len(checks)==8 and all(x['passed'] for x in checks) and not (e/'error.txt').exists()
 (e/'FINAL_RESULT.json').write_text(json.dumps(dict(passed=success,prerequisites_ok=not (e/'prerequisite-failure.json').exists(),checks=checks,scope='development, message-level gate -> bridge -> synthetic base; no hardware',state=str(state),project=project),indent=2))  # project: lets the evaluation cleanup name this run's stopped containers
 # Never hash or copy generated private configuration into the public evidence set.
 # evidence/runtime/raw-archive.lock (0600) and raw-slots/ (0700) are the retention manager's private control files
 # (examples/common/raw_retention.py, owned by the service UID). A native Linux runner cannot read them, they carry no
 # evidence, and rglob would list them on macOS but silently skip the directory on Linux: keep them out of MANIFEST.json.
 retention_private=e/'runtime/raw-slots'
 files={str(f.relative_to(e)):hashlib.sha256(f.read_bytes()).hexdigest() for f in e.rglob('*') if f.is_file() and f.name!='MANIFEST.json' and f.name!='raw-archive.lock' and retention_private not in f.parents};(e/'MANIFEST.json').write_text(json.dumps(files,indent=2))
 # a prerequisite that failed (clock, permissions, stack not up) is BLOCKED, never FAIL: no judgement ran (P23-L1)
 blocked=(e/'prerequisite-failure.json').exists()
 print('RESULT='+('PASS' if success else 'BLOCKED' if blocked else 'FAIL')+' EVIDENCE='+str(e),flush=True)
 raise SystemExit(0 if success else (3 if blocked and json.loads((e/'prerequisite-failure.json').read_text()).get('kind')=='stack' else 2 if blocked else 1))
