# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Candidate actual SDK/rclpy endpoint. Requires a pinned local SDK+USD+SROS2 view.

No mock fallback, raw cmd subscription, public management API or automatic resume.
Actual GPU, asset and ROS library compatibility must be tested on the target VM.
"""
import argparse
import json
import math
import os
from pathlib import Path
import time
import traceback
import uuid
from live_control import LiveControl,require_security
from network_guard import require_no_management_listener,listeners

# SDK extensions that would add a second ROS command writer or a remote control
# surface next to the reviewed rclpy endpoint. Their presence on disk is expected;
# their activation in this process is not.
FORBIDDEN_EXTENSION_PREFIXES=('isaacsim.ros2.bridge','isaacsim.ros2.sim_control','isaacsim.ros2.examples','isaacsim.ros2.nodes','isaacsim.ros2.tf_viewer','isaacsim.ros2.ui','isaacsim.ros2.urdf','isaacsim.kit.xr.teleop')
WATCHED_EXTENSION_WORDS=('ros2','teleop','omni.graph')


def elapsed():return time.clock_gettime_ns(time.CLOCK_BOOTTIME)*1e-6


def extension_name(ext_id):return str(ext_id).split('-',1)[0]


def forbidden_extensions(enabled):
    return sorted(x for x in enabled if any(extension_name(x)==p or extension_name(x).startswith(p+'.') for p in FORBIDDEN_EXTENSION_PREFIXES))


def watched_extensions(enabled):
    return sorted(x for x in enabled if any(word in str(x) for word in WATCHED_EXTENSION_WORDS))


def unique_articulation_root(paths,model_root):
    roots=[str(p) for p in paths if str(p)==model_root or str(p).startswith(model_root+'/')]
    if len(roots)!=1:raise ValueError('Exactly one robot articulation root required')
    return roots[0]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--config',type=Path,required=True);a=ap.parse_args()
    meta=json.loads(a.config.read_text());sim=meta['sim']
    require_security(os.environ,Path('/etc/pail/sros2_keystore'))
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if boot!=meta['boot_id']:raise ValueError('CLOCK_DOMAIN_MISMATCH')
    state=LiveControl(meta['run_id'],meta['generation'],boot,elapsed,meta['timeout_ms'])
    log=Path('/evidence/runtime/endpoint.jsonl');seq=0;instance=uuid.uuid4().hex
    def record(event,**kw):
        row=dict(event=event,elapsed_ms=elapsed(),wall_ns=time.time_ns(),run_id=meta['run_id'],generation=meta['generation'],authority_source='ISAAC_SDK',**kw)
        with log.open('a') as f:f.write(json.dumps(row,allow_nan=False)+'\n');f.flush()
    from isaacsim import SimulationApp
    # Kit's default portable root is inside the immutable SDK installation.
    # Keep generated settings/shaders/scripts in the endpoint-owned cache.
    app=SimulationApp({'headless':True,'limit_cpu_threads':4,'extra_args':['--portable-root','/cache/kit']});robot=None;node=None;timeline_sub=None;closing=False
    try:
        import numpy as np
        import omni.kit.app
        import omni.timeline
        manager=omni.kit.app.get_app().get_extension_manager()
        manager.set_extension_enabled_immediate('isaacsim.ros2.core',True)
        enabled=sorted(str(e.get('id')) for e in manager.get_extensions() if e.get('enabled'))
        record('EXTENSION_INVENTORY',enabled_count=len(enabled),watched=watched_extensions(enabled),forbidden_enabled=forbidden_extensions(enabled))
        if forbidden_extensions(enabled):raise ValueError('UNREVIEWED_ROS_WRITER_EXTENSION')
        from isaacsim.core.version import get_version
        if get_version()[0]!=sim['version']:raise ValueError('SDK_VERSION_MISMATCH')
        from isaacsim.core.api import World
        from isaacsim.core.utils.types import ArticulationAction
        from isaacsim.core.utils.stage import add_reference_to_stage
        from pxr import UsdPhysics
        from isaacsim.robot.wheeled_robots.robots import WheeledRobot
        from isaacsim.robot.wheeled_robots.controllers import DifferentialController
        import rclpy
        from rclpy.node import Node
        from rclpy.context import Context
        from rclpy.executors import SingleThreadedExecutor
        from rclpy.qos import QoSProfile,ReliabilityPolicy,DurabilityPolicy
        from geometry_msgs.msg import Twist
        from std_msgs.msg import String
        physics_dt=1./60.
        world=World(stage_units_in_meters=1.,physics_dt=physics_dt,rendering_dt=physics_dt)
        # The SDK's default ground fetches a remote asset. The isolated runtime
        # must stay offline; author a local plane with explicit test materials.
        world.scene.add_ground_plane(size=10.,static_friction=.5,dynamic_friction=.5,restitution=0.)
        # Test-scene light only (no physics effect); without it the capture is a black frame.
        from isaacsim.core.utils.prims import create_prim
        create_prim('/World/PAILTestLight','DistantLight',attributes={'inputs:intensity':3000.})
        model_root='/World/PAILRobot'
        add_reference_to_stage(usd_path='/assets/'+sim['usd'],prim_path=model_root)
        articulation_path=unique_articulation_root([p.GetPath() for p in world.stage.Traverse() if p.HasAPI(UsdPhysics.ArticulationRootAPI)],model_root)
        robot=world.scene.add(WheeledRobot(prim_path=articulation_path,name='pail_robot',create_robot=False,wheel_dof_names=sim['wheel_joints']))
        # First profile rejects asset-embedded control graphs and nonzero drive
        # targets before reset/first physics step. Not a proof against SDK admin code.
        prim_count=0
        for prim in world.stage.Traverse():
            prim_count+=1
            if str(prim.GetTypeName()).startswith('OmniGraph'):
                raise ValueError('Unreviewed asset control graph')
            for attr in prim.GetAttributes():
                name=str(attr.GetName())
                if name.startswith('drive:') and name.endswith(('targetVelocity','targetPosition')):
                    value=attr.Get()
                    if value is not None and float(value)!=0:raise ValueError('Nonzero initial drive target')
        record('ASSET_INVENTORY',prim_count=prim_count,articulation_root=articulation_path,embedded_control_graphs=0,nonzero_initial_drive_targets=0)
        record('LISTENER_INVENTORY',listeners=listeners({family:Path('/proc/net',family).read_text() for family in ('tcp','tcp6')}))
        require_no_management_listener()
        controller=DifferentialController(name='pail_differential',wheel_radius=sim['wheel_radius_um']/1e6,wheel_base=sim['wheel_base_um']/1e6)
        record('PHYSICS_RESET_START')
        world.reset()
        record('PHYSICS_RESET_DONE')
        zero=ArticulationAction(joint_velocities=np.zeros(2))
        for settling_step in range(60):
            robot.apply_wheel_actions(zero);world.step(render=True)
            if settling_step%10==0:record('SETTLING',completed_steps=settling_step+1)
        # Rendering evidence for BS-01: one viewport capture into the endpoint-owned cache.
        # Failure to capture is recorded, never hidden and never a fallback to "rendered".
        try:
            from omni.kit.viewport.utility import get_active_viewport,capture_viewport_to_file
            capture_viewport_to_file(get_active_viewport(),'/cache/render-ready.png')
            for _ in range(30):robot.apply_wheel_actions(zero);world.step(render=True)
            shot=Path('/cache/render-ready.png');size=shot.stat().st_size if shot.exists() else 0
            # A written file is not a rendered scene: the first capture (m2, 2026-10-15) was all black.
            ratio=None
            try:
                from PIL import Image
                image=np.asarray(Image.open(shot).convert('RGB'));ratio=float((image.max(axis=2)>8).mean())
            except Exception as exc:record('RENDER_PIXELS',status='UNAVAILABLE',error=(type(exc).__name__+': '+str(exc))[:200])
            record('RENDER_CAPTURE',status=('RENDERED' if ratio>.01 else 'BLACK_FRAME') if ratio is not None else ('WRITTEN' if size>0 else 'NOT_WRITTEN'),bytes=size,path=str(shot),nonblack_ratio=ratio)
        except Exception as exc:
            record('RENDER_CAPTURE',status='UNAVAILABLE',error=(type(exc).__name__+': '+str(exc))[:300])
        def abort(reason):
            fresh=state.state!='FAULT_LOCKED';state.lock(reason);robot.apply_wheel_actions(zero)
            if fresh:record('LOCKED',reason=reason)  # once per lock; later causes are kept out of the evidence stream
        fixture=None
        if meta.get('fixture_allowed') is True:
            from test_fixture import Fixture
            fixture=Fixture(Path('/sim-control/fixture.json'),meta,record);record('FIXTURE_ARMED',fixture=True)
        def timeline(event):
            if not closing and event.type in (int(omni.timeline.TimelineEventType.PAUSE),int(omni.timeline.TimelineEventType.STOP)):
                abort('TIMELINE_CHANGED_NEW_RUN_REQUIRED')
        timeline_sub=omni.timeline.get_timeline_interface().get_timeline_event_stream().create_subscription_to_pop(timeline)
        context=Context();rclpy.init(args=['--ros-args','--enclave','/nv_endpoint'],context=context)
        node=Node('nv_endpoint',context=context,start_parameter_services=False,enable_rosout=False)
        executor=SingleThreadedExecutor(context=context);executor.add_node(node)
        qos=QoSProfile(depth=1,reliability=ReliabilityPolicy.RELIABLE,durability=DurabilityPolicy.VOLATILE)
        pub=node.create_publisher(String,'/pail/nvidia/endpoint_state',qos)
        def command(msg):state.receive([msg.linear.x,msg.linear.y,msg.linear.z,msg.angular.x,msg.angular.y,msg.angular.z])
        subscription=node.create_subscription(Twist,'/drive_cmd_vel',command,qos)
        record('ready',instance=instance,role='endpoint',epoch=state.epoch,sdk_version=get_version()[0])
        applied=(0.,0.);last_step=world.current_time_step_index;last_latch=(state.state,state.reason);prev_angles=None;prev_pose=None;prev_yaw=None
        started_wall=elapsed();started_sim=world.current_time
        while app.is_running():
            try:
                cycle_start=elapsed()
                require_no_management_listener()
                control=json.loads(Path('/sim-control/control.json').read_text())
                state.control(control)
                if fixture is not None:fixture.poll(world,omni.timeline.get_timeline_interface())
                executor.spin_once(timeout_sec=0)
                if not world.is_playing():abort('NOT_PLAYING')
                if world.current_time_step_index<last_step:abort('PHYSICS_RESET')
                applied=state.output()
                if (state.state,state.reason)!=last_latch:
                    last_latch=(state.state,state.reason);record('LATCH_STATE',state=state.state,reason=state.reason)
                action=controller.forward(command=np.array(applied))
                if fixture is not None:action=fixture.override(action,ArticulationAction,np)
                robot.apply_wheel_actions(action)
                record('CONTROLLER_APPLIED',epoch=state.epoch,linear_x=applied[0],angular_z=applied[1],wheel_targets=np.asarray(action.joint_velocities).tolist(),tick=world.current_time_step_index)
                world.step(render=True);last_step=world.current_time_step_index
                # Read actual simulation state, not the requested velocity.
                position,quaternion=robot.get_world_pose();pose=position.tolist();orientation=[float(q) for q in quaternion];velocity=robot.get_linear_velocity().tolist();angular=robot.get_angular_velocity().tolist();wheels=list(robot.get_wheel_velocities());angles=[float(x) for x in robot.get_wheel_positions()]
                if len(orientation)!=4 or not all(math.isfinite(float(v)) for v in pose+orientation+velocity+angular+wheels+angles):raise ValueError('INVALID_PHYSICS_OBSERVATION')
                qw,qx,qy,qz=orientation;yaw=math.atan2(2*(qw*qz+qx*qy),1-2*(qy*qy+qz*qz))   # scalar-first quaternion (Isaac Sim core)
                # Schema 3 (2026-10-19): motion is also derived from position changes over one physics step. After an
                # abrupt stop the solver reported one wheel at -0.05..-0.12 rad/s for seconds while the joint angle moved
                # 1e-5 rad and the body 0 m (gate_kill, Brev L40S); the reported velocities stay in the record as evidence,
                # the position-derived rates are what the zero/rest judges read. Wrap-safe for revolute joints.
                from_angle=[0.,0.] if prev_angles is None else [math.atan2(math.sin(a-b),math.cos(a-b))/physics_dt for a,b in zip(angles,prev_angles)]
                speed_pose=0. if prev_pose is None else math.hypot(pose[0]-prev_pose[0],pose[1]-prev_pose[1])/physics_dt
                yaw_rate_pose=0. if prev_yaw is None else math.atan2(math.sin(yaw-prev_yaw),math.cos(yaw-prev_yaw))/physics_dt
                prev_angles=angles;prev_pose=pose;prev_yaw=yaw
                seq+=1
                snapshot=dict(schema_version=3,run_id=meta['run_id'],generation=meta['generation'],node_instance=instance,seq=seq,event='SIM_OBSERVED',state=state.state,epoch=state.epoch,reason=state.reason,applied_linear_x=applied[0],applied_angular_z=applied[1],pose=pose,orientation=orientation,linear_velocity=velocity,angular_velocity=angular,wheel_velocity=[float(v) for v in wheels],wheel_angle=angles,wheel_velocity_from_angle=from_angle,speed_from_pose=speed_pose,yaw_rate_from_pose=yaw_rate_pose,physics_tick=last_step,elapsed_ms=elapsed(),clock_id='CLOCK_BOOTTIME:'+boot,authority_source='ISAAC_SDK')
                snapshot.update(simulation_time_s=float(world.current_time),physics_dt_s=physics_dt,real_time_factor=(world.current_time-started_sim)/max((elapsed()-started_wall)/1000.,.001))
                record('endpoint',snapshot=snapshot);m=String();m.data=json.dumps(snapshot,allow_nan=False);pub.publish(m)
                # No accelerated catch-up: token/heartbeat clocks remain real elapsed.
                time.sleep(max(0.,physics_dt-(elapsed()-cycle_start)/1000.))
            except Exception as exc:
                abort(type(exc).__name__+': '+str(exc));raise
    except BaseException as exc:
        # Kit fast shutdown can exit before a pending Python exception reaches
        # stderr. Persist the failure before closing; never report it as ready.
        traceback.print_exc()
        record('SDK_ERROR',error=type(exc).__name__+': '+str(exc))
        raise
    finally:
        closing=True
        if robot is not None:
            try:robot.apply_wheel_actions(zero)
            except Exception:pass
        if node is not None:executor.shutdown();node.destroy_node();context.shutdown()
        app.close()

if __name__=='__main__':main()
