# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""CPU-only synthetic ROS endpoint/monitor/planner, never opens a device."""
import argparse
import json
import math
import os
from pathlib import Path
import time
import uuid
import rclpy
from rclpy.node import Node
from rclpy.clock import Clock, ClockType
from rclpy.duration import Duration
from rclpy.qos import QoSProfile, ReliabilityPolicy, DurabilityPolicy
from geometry_msgs.msg import Twist
from std_msgs.msg import String
from pail_msgs.msg import GateState, Permit, BridgeState


def elapsed():
    if not hasattr(time, 'CLOCK_BOOTTIME'): raise RuntimeError('BOOTTIME required')
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--role', choices=['endpoint','monitor','planner','attack','permit_fixture'],required=True)
    ap.add_argument('--topic',choices=['/cmd_vel','/safe_cmd_vel','/drive_cmd_vel','/pail/permit','/pail/drive_cmd_vel'],default='/drive_cmd_vel')
    a=ap.parse_args(); meta=json.loads(Path('/reference/nv-meta.json').read_text())
    out=Path('/evidence/runtime')/(a.role+'.jsonl')
    def record(event, **values):
        row=dict(event=event,elapsed_ms=elapsed(),wall_ns=time.time_ns(),run_id=meta['run_id'],generation=meta['generation'],**values)
        fd=os.open(out,os.O_CREAT|os.O_APPEND|os.O_WRONLY,0o644);os.fchmod(fd,0o644)
        with os.fdopen(fd,'a') as f: f.write(json.dumps(row,allow_nan=False)+'\n')
    qos=QoSProfile(depth=1,reliability=ReliabilityPolicy.RELIABLE,durability=DurabilityPolicy.VOLATILE)
    class Actor(Node):
        def __init__(self):
            super().__init__('nv_'+a.role,start_parameter_services=False)
            self.instance=uuid.uuid4().hex;self.seq=0;self.last=None;self.velocity=[0.,0.];self.state='ZERO_READY'
            self.last_clock=elapsed();self.clock_fault=False;self.count=0;self.last_status=None;self.last_hb=None;self.last_hb_at=None;self.last_instruction=None;self.locked_instruction=None
            if a.role=='endpoint':
                self.pub=self.create_publisher(String,'/pail/nvidia/endpoint_state',qos)
                self.create_subscription(Twist,'/drive_cmd_vel',self.command,qos)
            elif a.role=='monitor':
                self.create_subscription(String,'/pail/nvidia/endpoint_state',self.status,qos)
                self.create_subscription(GateState,'/pail/gate_state',lambda m:record('gate',state=m.state,reason=m.reason,token=m.active_token_id),10)
                self.create_subscription(BridgeState,'/pail/bridge_state',lambda m:record('bridge',state=m.state),10)
            elif a.role=='planner': self.pub=self.create_publisher(Twist,'/cmd_vel',10)
            elif a.role=='attack':
                record('ATTEMPT',topic=a.topic)
                kind=Permit if a.topic=='/pail/permit' else Twist
                try:self.pub=self.create_publisher(kind,a.topic,10)
                except Exception as ex:
                    record('PUBLISHER_REFUSED',error=type(ex).__name__,detail=str(ex));raise
            elif a.role=='permit_fixture':
                self.pub=self.create_publisher(Permit,'/pail/permit',QoSProfile(depth=1,reliability=ReliabilityPolicy.BEST_EFFORT,deadline=Duration(nanoseconds=100000000)))
            self.timer=self.create_timer(.025,self.tick,clock=Clock(clock_type=ClockType.STEADY_TIME))
            record('ready',instance=self.instance,role=a.role)
        def now(self):
            now=elapsed()
            if now<self.last_clock:self.clock_fault=True;self.velocity=[0.,0.];self.state='FAULT_LOCKED'
            self.last_clock=now
            return now
        def command(self,msg):
            now=self.now()
            if self.clock_fault:return
            vals=[msg.linear.x,msg.linear.y,msg.linear.z,msg.angular.x,msg.angular.y,msg.angular.z]
            if not all(math.isfinite(v) for v in vals) or any(vals[i]!=0 for i in (1,2,3,4)):
                self.state='FAULT_LOCKED';self.clock_fault=True;self.velocity=[0.,0.];self.emit('INVALID_INPUT');return
            self.expire(now)
            self.last=now;self.count+=1;self.velocity=[msg.linear.x,msg.angular.z]
            self.state='ACTIVE' if any(self.velocity) else 'ZERO_READY';self.emit('RECEIVED')
        def expire(self,now):
            if self.last is not None and now-self.last>=meta['timeout_ms'] and self.state=='ACTIVE':
                self.velocity=[0.,0.];self.state='EXPIRED';self.emit('TIMEOUT')
        def emit(self,event):
            self.seq+=1
            row=dict(schema_version=2,run_id=meta['run_id'],generation=meta['generation'],node_instance=self.instance,seq=self.seq,event=event,state=self.state,received_count=self.count,applied_linear_x=self.velocity[0],applied_angular_z=self.velocity[1],last_receive_elapsed_ms=self.last,elapsed_ms=elapsed(),clock_id='CLOCK_BOOTTIME:'+Path('/proc/sys/kernel/random/boot_id').read_text().strip())
            m=String();m.data=json.dumps(row);self.pub.publish(m)
            record('endpoint',snapshot=row)
        def status(self,msg):
            try:d=json.loads(msg.data)
            except ValueError:record('INVALID_OBSERVATION');return
            if d.get('generation')!=meta['generation'] or d.get('run_id')!=meta['run_id']:
                record('STALE_OBSERVATION');return
            if self.last_status and self.last_status.get('node_instance')==d.get('node_instance') and d.get('seq',0)<=self.last_status['seq']:
                record('STALE_SEQUENCE');return
            self.last_status=d;self.last=elapsed();record('observed',snapshot=d)
        def tick(self):
            now=self.now()
            if a.role=='endpoint':
                self.expire(now)
                self.count_tick=getattr(self,'count_tick',0)+1
                if self.count_tick%2==0:self.emit('SNAPSHOT')
            elif a.role=='monitor':
                if self.last is None or now-self.last>=500:
                    if self.state!='OBSERVATION_LOST':record('OBSERVATION_LOST',stop_confirmed=False)
                    self.state='OBSERVATION_LOST'
                else:self.state='OBSERVED'
            elif a.role=='planner':
                try:c=json.loads(Path('/control/managed.json').read_text())
                except (OSError,ValueError):return
                if c.get('generation')!=meta['generation']:return
                if self.last_hb!=c.get('heartbeat'):
                    self.last_hb=c.get('heartbeat');self.last_hb_at=now
                instruction=c.get('instruction')
                if self.last_hb_at is None or now-self.last_hb_at>=500:
                    self.locked_instruction=instruction;return
                if not c.get('on') or instruction==self.locked_instruction:return
                speed=c.get('speed',.05)
                if type(speed) not in (int,float) or not math.isfinite(speed):return
                m=Twist();m.linear.x=speed;self.pub.publish(m);record('input',linear=speed)
            elif a.role=='attack':
                m=Permit() if a.topic=='/pail/permit' else Twist()
                if a.topic=='/pail/permit':m.active_token_id='unauthorized';m.permit_seq=1
                else:m.linear.x=.077
                self.pub.publish(m);record('PUBLISH_RETURNED',topic=a.topic)
            elif a.role=='permit_fixture':
                # Explicit closed test only; normal profiles never launch this role.
                try:c=json.loads(Path('/control/permit-fixture.json').read_text())
                except (OSError,ValueError):return
                if self.pub.get_subscription_count()==0:return
                if getattr(self,'duplicate_pending',False):
                    self.duplicate_pending=False
                elif c.get('event')==self.last_instruction:return
                else:
                    self.last_instruction=c['event'];self.duplicate_pending=True
                m=Permit();m.active_token_id='fixture';m.permit_seq=int(c['seq']);self.pub.publish(m);record('FIXTURE_PERMIT',seq=m.permit_seq)
    rclpy.init()
    node=Actor()
    try:rclpy.spin(node)
    except KeyboardInterrupt:pass
    finally:node.destroy_node();rclpy.shutdown()

if __name__=='__main__': main()
