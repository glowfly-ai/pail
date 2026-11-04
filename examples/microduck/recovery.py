# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Per-robot intent/execution/health state; healthy transport is not resume consent."""
import copy
import threading
import time
import uuid
from diagnostics import ClockWatch, ProbeError, transport
from fleet import FleetError


class Recovery:
    def __init__(self,fleet,wall=time.time,steady=time.monotonic):
        self.fleet=fleet;self.wall=wall;self.steady=steady
        self.mu=threading.RLock();self.closed=threading.Event();self.thread=None
        self.clock_id='controller-'+uuid.uuid4().hex
        self.clock=ClockWatch(wall=wall,steady=steady)
        self.rows={rid:self.blank() for rid in [r['robot_id'] for r in fleet.config['robots']]}
        self.processes={};self.instances={};self.observer_clocks={};self.pending=set();self.cleaned=set()
        self.reinitializing=set();self.recovering=set();self.last_retry={};self.started=steady();self.policy=fleet.config.get('recovery_policy',{'mode':'operator'})

    @staticmethod
    def blank():
        return {'intent':'NONE','execution':'READY_IDLE','health':'UNKNOWN','paused':False,
                'resume_requirement':'NONE','reason':None,'fault_generation':0,'attempts':0,
                'diagnostic':None,'clock':None,'request_id':None,'plan_id':None,'text':None,
                'retry_eligible':False,'first_failure_ms':None,'last_failure_ms':None,'recovered_at_ms':None,'probe_attempts':0}

    def restore(self,records):
        if not records:return
        if set(records)!=set(self.rows):raise FleetError('RECOVERY_ROBOT_MAP')
        for rid,row in records.items():
            self.rows[rid].update(row)
            # A service resume never replays an aging request from an earlier supervisor.
            self.rows[rid].update(intent='STOP_REQUESTED',execution='READY_IDLE',health='UNKNOWN',paused=False,resume_requirement='NEW_COMMAND_REQUIRED')

    def persist(self):
        if self.closed.is_set() or self.fleet.lifecycle.lock is None:return
        with self.fleet.lifecycle.mu:
            self.fleet.meta['recovery']=copy.deepcopy(self.rows)
            self.fleet.lifecycle.write()

    def snapshot(self,rid):
        with self.mu:
            r=copy.deepcopy(self.rows[rid]);r.pop('text',None)
            r['clock_stable']=self.clock.stable(self.observer_clocks.get(rid)) and self.clock.stable(self.clock_id)
            return r

    def paused(self,rid):
        with self.mu:return self.rows[rid]['paused']

    def request(self,rid,request,stop=False,automatic=False):
        with self.mu:
            r=self.rows[rid]
            r.update(intent='STOP_REQUESTED' if stop else 'CONTINUE_REQUESTED',request_id=request['request_id'],retry_eligible=False)
            if not stop:r['text']=request['text']
            if not automatic:r['attempts']=0
            if stop:r['execution']='PAUSED' if r['paused'] else 'READY_IDLE'
            self.persist()

    def result(self,rid,result,request_id=None):
        with self.mu:
            r=self.rows[rid]
            if request_id is not None and r['request_id']!=request_id:return
            r['retry_eligible']=bool(result.get('accepted') or result.get('execution')=='UNKNOWN')
            if result.get('plan'):r['plan_id']=result['plan']
            if not r['paused']:
                r['execution']='RUNNING' if result.get('accepted') else 'READY_IDLE'
            self.persist()

    def fail(self,rid,reason,diagnostic=None,clock=None):
        with self.mu:
            if self.closed.is_set():return
            r=self.rows[rid];now=int(self.wall()*1000)
            changed=not r['paused'] or (reason=='CLOCK' and r['reason']!='CLOCK') or bool(clock and clock.get('event')=='clock_step') or rid in self.recovering
            if changed:r['fault_generation']+=1
            r.update(paused=True,execution='PAUSED_CLOCK' if reason=='CLOCK' or r['reason']=='CLOCK' else 'PAUSED',
                     resume_requirement='OPERATOR_CONFIRMATION',last_failure_ms=now)
            if r['first_failure_ms'] is None:r['first_failure_ms']=now
            if r['reason']!='CLOCK':r['reason']=reason
            if diagnostic:r['diagnostic']=dict(diagnostic)
            if clock:r['clock']=dict(clock)
            if changed:
                self.pending.add(rid);self.cleaned.discard(rid)
                # Stop local dispatch before any potentially slow cancellation RPC.
                # This file write shares the motion-dispatch lock, not the RPC lock.
                try:
                    self.fleet.stacks[rid].write_control(instruction=True,mode='idle',steps=[],raw={})
                    r['idle_dispatch']='WRITTEN_NOT_PHYSICAL_STOP_PROOF'
                except Exception:r['idle_dispatch']='UNCONFIRMED'
                self.persist()

    def health(self,rid,ok,diagnostic=None,duration=0):
        with self.mu:
            r=self.rows[rid];previous=r['health'];r['probe_attempts']+=1
            r['health']='RESPONDING' if ok else 'UNAVAILABLE'
            if diagnostic:r['diagnostic']=dict(diagnostic,endpoint='agent_to_issuer',duration_ms=round(duration*1000,3),attempt=r['probe_attempts'])
            if ok and previous!='RESPONDING':r['recovered_at_ms']=int(self.wall()*1000)
            if previous!=r['health']:self.persist()
        if not ok:self.fail(rid,'TRANSPORT',diagnostic)

    def observe(self,rid,record):
        if self.closed.is_set() or record.get('replayed'):return
        if record.get('robot_id')!=rid or record.get('run_id')!=self.fleet.run_id:return
        role=record.get('source')
        if role not in ('planner','observer','evidence'):return
        with self.mu:
            instance=record.get('producer_instance_id');key=(rid,role);old=self.instances.get(key)
            self.instances[key]=instance
            if old and instance and old!=instance:self.fail(rid,'RESTART',transport(basis='instance_changed'))
            event=self.clock.observe(role,record)
            if role=='observer' and record.get('clock_id') not in (None,'unavailable'):self.observer_clocks[rid]=record['clock_id']
            if event:
                affected={rid}|{other for other,realm in self.observer_clocks.items() if realm==event['clock_id']}
                for other in affected:self.fail(other,'CLOCK',clock=event)
            row=self.rows[rid]
            if record.get('observation_current') and record.get('plan_matches_current') is not False and not row['paused']:
                if record.get('event')=='plan_done':row['execution']='SETTLING'
                if record.get('event')=='pose' and row['execution']=='SETTLING' and abs(record.get('v',1))<.005 and abs(record.get('w',1))<.01:
                    row['execution']='READY_IDLE';self.persist()
            if record.get('event')=='gate' and record.get('reason')=='ERR_CLOCK_DRIFT':
                self.fail(rid,'CLOCK',clock={'event':'gate_clock_refusal','clock_id':record.get('clock_id'),
                    'producer_instance_id':instance,'detected_at_ms':int(self.wall()*1000),'wall_delta_s':None,
                    'monotonic_delta_s':None,'basis':'gate_reported_ERR_CLOCK_DRIFT','issuer_clock_difference_measured':False})

    def note_instances(self,items,seed=False):
        """Record the managed containers' start times. A start time NEWER than the recorded one is a restart this
        supervisor did not perform (a service restarted behind its back) and latches RESTART. seed=True records the
        start times of a restart the console performed itself (`restart_robot`, the fault buttons) so that the next
        inventory pass has nothing new to report about it. Measured 2026-10-10 (Linux recipient replay, fleet scene R,
        3 of 6): the console restarted the robot and paused it, the operator confirmed, a plan was accepted — and the
        2 s inventory pass THEN saw the containers' new start times, paused the robot again, wrote idle and cancelled
        the just-accepted plan (NORTHBOUND_CANCEL); the move stalled on ERR_NO_TOKEN. An inventory snapshot OLDER
        than a seeded start (taken before that restart) is never a fault either."""
        for item in items:
            with self.mu:
                rid=item['robot_id'];key=(rid,item['role']);old=self.processes.get(key);started=item['started_at']
                if rid in self.reinitializing and item['role']=='adapter':continue
                if old is None or started is None or started>old:self.processes[key]=started
                if seed:continue
                if item['oom_killed']:self.fail(rid,'TRANSPORT',transport(basis='oom_killed'))
                elif not item['running']:self.fail(rid,'RESTART',transport(basis='service_not_running'))
                elif old and started and started>old:self.fail(rid,'RESTART',transport(basis='instance_changed'))

    def observe_controller(self):
        with self.mu:
            event=self.clock.observe('controller',{'t':self.wall(),'mono':self.steady(),'clock_id':self.clock_id,'producer_instance_id':self.clock_id})
            if event:
                for rid in self.rows:self.fail(rid,'CLOCK',clock=event)

    def start(self):
        self.thread=threading.Thread(target=self.loop,daemon=True);self.thread.start()

    def close(self):
        self.closed.set()
        if self.thread and self.thread is not threading.current_thread():self.thread.join(35)
        if self.thread and self.thread.is_alive():raise FleetError('RECOVERY_WORKER_NOT_STOPPED')

    def cleanup(self,rid):
        console=self.fleet.consoles[rid];stack=self.fleet.stacks[rid]
        with console.command_lock:
            stack.write_control(instruction=True,mode='idle',steps=[],raw={},override_linear=None)
            self.fleet.reconcile_plans(robot_id=rid)
        with self.mu:
            self.cleaned.add(rid)
            self.rows[rid]['reconciliation']='CONFIRMED';self.persist()

    def confirm(self,rid,confirmed=False,automatic=False):
        if rid not in self.rows or confirmed is not True:raise FleetError('OPERATOR_CONFIRMATION_REQUIRED')
        with self.mu:
            r=self.rows[rid]
            if not r['paused']:return {'robot_id':rid,'execution':r['execution'],'new_command_required':r['execution']=='READY_IDLE','already_not_paused':True}
            if r['health']!='RESPONDING':raise FleetError('TRANSPORT_NOT_RECOVERED')
            if not self.clock.stable(self.clock_id) or not self.clock.stable(self.observer_clocks.get(rid)):
                raise FleetError('CLOCK_STABILITY_NOT_OBSERVED')
            generation=r['fault_generation'];needs_restart=r['reason']=='CLOCK'
            if rid in self.recovering:raise FleetError('RECOVERY_ALREADY_RUNNING')
            self.recovering.add(rid)
        try:
            self.cleanup(rid)
            if self.closed.is_set():raise FleetError('SERVICE_STOPPING')
            if needs_restart:
                with self.mu:self.reinitializing.add(rid)
                try:
                    self.fleet.reinitialize_clock_component(rid)
                    with self.mu:
                        for item in self.fleet.recovery_inventory():
                            if item['robot_id']==rid and item['role']=='adapter':
                                self.processes[(rid,'adapter')]=item['started_at']
                finally:
                    with self.mu:self.reinitializing.discard(rid)
            with self.mu:
                if self.closed.is_set():raise FleetError('SERVICE_STOPPING')
                if self.rows[rid]['fault_generation']!=generation:raise FleetError('NEW_FAULT_DURING_RECOVERY')
                if self.rows[rid]['health']!='RESPONDING':raise FleetError('TRANSPORT_NOT_RECOVERED')
                if not self.clock.stable(self.clock_id) or not self.clock.stable(self.observer_clocks.get(rid)):
                    raise FleetError('CLOCK_STABILITY_NOT_OBSERVED')
                self.rows[rid].update(paused=False,execution='READY_IDLE',resume_requirement='NEW_COMMAND_REQUIRED',reason=None)
                self.pending.discard(rid);self.persist()
        finally:
            with self.mu:self.recovering.discard(rid)
        return {'robot_id':rid,'execution':'READY_IDLE','new_command_required':True,'component_reinitialized':needs_restart}

    def loop(self):
        try:self.run_loop()
        except Exception:
            # A failed supervisor cannot leave the command path open.
            with self.fleet.admission:self.fleet.accepting=False
            with self.mu:
                for row in self.rows.values():
                    row.update(paused=True,execution='PAUSED',reason='SUPERVISOR_FAILED',resume_requirement='SERVICE_RECOVERY')
            self.closed.set()
            for stack in self.fleet.stacks.values():
                try:stack.write_control(instruction=True,mode='idle',steps=[],raw={})
                except Exception:pass

    def run_loop(self):
        next_probe=0
        while not self.closed.is_set():
            self.observe_controller()
            for rid in list(self.rows):
                if self.closed.is_set():break
                with self.mu:pending=rid in self.pending
                if pending:
                    try:self.cleanup(rid)
                    except Exception:
                        with self.mu:self.rows[rid]['reconciliation']='UNKNOWN';self.persist()
                    finally:
                        with self.mu:self.pending.discard(rid)
            if self.steady()>=next_probe:
                try:self.note_instances(self.fleet.recovery_inventory())
                except Exception:
                    for rid in self.rows:self.fail(rid,'TRANSPORT',transport(basis='inventory_unavailable'))
                for rid,stack in self.fleet.stacks.items():
                    if self.closed.is_set():break
                    started=self.steady()
                    try:
                        status=stack.probe('status',timeout=5)
                        self.health(rid,status.get('issuer')=='OK',duration=self.steady()-started)
                    except ProbeError as exc:self.health(rid,False,exc.diagnostic,self.steady()-started)
                    except Exception:self.health(rid,False,transport(basis='probe_process_failed'),self.steady()-started)
                next_probe=self.steady()+2
            if self.policy['mode']=='software-aging':self.auto_step()
            self.closed.wait(.2)

    def auto_step(self):
        for rid in self.rows:
            with self.mu:
                r=self.rows[rid]
                if (not r['paused'] or r['intent']!='CONTINUE_REQUESTED' or not r.get('text') or not r['retry_eligible']
                        or r['attempts']>=self.policy['max_attempts'] or r['health']!='RESPONDING'
                        or self.steady()-self.last_retry.get(rid,self.started)<self.policy['cooldown_s']):continue
                if not self.clock.stable(self.clock_id) or not self.clock.stable(self.observer_clocks.get(rid)):continue
                r['attempts']+=1;self.last_retry[rid]=self.steady();text=r['text'];intent_id=r['request_id'];self.persist()
            try:
                self.confirm(rid,True,automatic=True)
                if self.closed.is_set():return
                self.fleet.command({'robot_id':rid,'request_id':'aging-'+uuid.uuid4().hex,'text':text},automatic=True,recovery_request_id=intent_id)
            except Exception:pass  # State/attempt remains visible; never resubmit an UNKNOWN request ID.
