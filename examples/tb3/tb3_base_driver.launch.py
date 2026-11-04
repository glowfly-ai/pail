# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Optional vendor base-driver hookup. Hardware is disabled unless explicitly enabled.
This launch is NOT used by run.py. Vendor packages, firmware and robot-side security
material must already be installed. No arm or lidar is started here.
"""
import os
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, LogInfo, OpaqueFunction
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node

def configure(context):
    enabled=LaunchConfiguration('enable_hardware').perform(context)
    if enabled not in ('true','false'):
        raise RuntimeError('enable_hardware must be true or false')
    if enabled=='false':
        return [LogInfo(msg='TB3 hardware disabled; no vendor driver is started.')]
    if os.environ.get('ROS_SECURITY_ENABLE')!='true' or os.environ.get('ROS_SECURITY_STRATEGY')!='Enforce':
        raise RuntimeError('Hardware hookup requires SROS2 Enforce; refusing to start a driver.')
    ks=os.environ.get('ROS_SECURITY_KEYSTORE','')
    if not ks or not os.path.isdir(ks):
        raise RuntimeError('Provide the robot-side SROS2 keystore.')
    params=LaunchConfiguration('params_file').perform(context)
    if not params or not os.path.isfile(params):
        raise RuntimeError('Provide the parameter file for the installed vendor model/ROS version.')
    return [Node(package='turtlebot3_node', executable='turtlebot3_ros',
                 parameters=[params,{'namespace':'','enable_stamped_cmd_vel':False}],
                 arguments=['-i',LaunchConfiguration('usb_port'),'--ros-args','--enclave','/driver'],
                 additional_env={'ROS_SECURITY_ENCLAVE_OVERRIDE':'/driver'},
                 remappings=[('/cmd_vel','/drive_cmd_vel')],output='screen')]

def generate_launch_description():
    return LaunchDescription([
        DeclareLaunchArgument('enable_hardware',default_value='false'),
        DeclareLaunchArgument('params_file',default_value=''),
        DeclareLaunchArgument('usb_port',default_value='/dev/ttyACM0'),
        OpaqueFunction(function=configure),
    ])
