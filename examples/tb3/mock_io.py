#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Synthetic input actors and a base-command sink. This is not a physics simulator."""
import argparse,json,time,os
from pathlib import Path
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import Twist
from pail_msgs.msg import Evidence,SafetyState,GateState
P=argparse.ArgumentParser();P.add_argument('--role',choices=['planner','base','evidence','safety'],required=True)
a=P.parse_args();out=Path('/evidence/runtime')/(a.role+'.jsonl')
def record(event,**kw):
 fd=os.open(out,os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o644)
 os.fchmod(fd,0o644)  # Shared synthetic observations only; never private key material.
 with os.fdopen(fd,'a') as f:f.write(json.dumps(dict(t=time.time(),mono=time.monotonic(),event=event,**kw))+'\n')
def control():return json.loads(Path('/control/input.json').read_text())
class Actor(Node):
 def __init__(self):
  super().__init__('tb3_reference_'+a.role,start_parameter_services=False)
  if a.role=='planner':
   self.pub=self.create_publisher(Twist,'/cmd_vel',10);self.create_subscription(GateState,'/pail/gate_state',lambda m:record('gate',state=m.state,reason=m.reason,token=m.active_token_id,seal=m.config_digest),10)
  elif a.role=='base':self.create_subscription(Twist,'/drive_cmd_vel',lambda m:record('drive',x=m.linear.x,z=m.angular.z),10)
  elif a.role=='evidence':self.pub=self.create_publisher(Evidence,'/pail/evidence',10)
  else:self.pub=self.create_publisher(SafetyState,'/pail/safety_state',10)
  self.create_timer(.1 if a.role=='planner' else .2,self.tick);record('ready',role=a.role)
 def tick(self):
  if a.role=='planner':
   try:c=control()
   except (OSError,ValueError) as ex:
    record('control_unreadable',detail=str(ex));return
   if not c['on']:return
   m=Twist();m.linear.x=c['speed'];self.pub.publish(m);record('input',x=m.linear.x)
  elif a.role=='evidence':
   m=Evidence();m.stamp=self.get_clock().now().to_msg();m.source='RFID';m.object_id='sample-box';m.confidence=.99;self.pub.publish(m)
  elif a.role=='safety':
   m=SafetyState();m.stamp=self.get_clock().now().to_msg();m.level='OK';m.source='SYNTHETIC_REFERENCE';self.pub.publish(m)
rclpy.init();n=Actor()
try:rclpy.spin(n)
finally:n.destroy_node();rclpy.shutdown()
