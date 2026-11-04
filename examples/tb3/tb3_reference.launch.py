# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""PAIL base reference: real gate + bridge, no hardware driver or motion source.
Run in the public gate image with generated configuration mounted at /etc/pail.
The guarded image entrypoints remain the execution path; this is not a guard bypass.
"""
from launch import LaunchDescription
from launch.actions import ExecuteProcess

def generate_launch_description():
    return LaunchDescription([
        ExecuteProcess(cmd=['/usr/local/bin/motion_bridge_entrypoint.sh'], output='screen'),
        ExecuteProcess(cmd=['/usr/local/bin/pep_gate_entrypoint.sh'], output='screen',
                       additional_env={'PAIL_ROBOT_CLASS': 'diff_drive_amr'}),
    ])
