# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

from launch import LaunchDescription
from launch_ros.actions import Node


def generate_launch_description():
    return LaunchDescription([
        Node(
            package='pail_pep_gate',
            executable='pep_gate_node',
            name='pep_gate_node',
            output='screen',
            # SD1: 노드 기본값과 같은 안전한 모드로 기동한다. static은 인가
            # 검증을 건너뛰므로 dev 배치에서만, 명시적으로
            #   ros2 run ... -p token_provider_mode:=static
            # 로 지정한다(production 프로파일에서는 기동 거부).
            parameters=[{
                'robot_id': 'robot-1',
                'token_provider_mode': 'notoken',
                'static_target_object_id': '',
                # implementation contract D-L1: evidence_window_ms / evidence_conf_threshold 는
                # 여기 있으면 안 된다. 이 파일은 P-19 의 사본 3벌 중 세 번째였다 —
                # 셋이 우연히 같은 수를 들고 있어서 정책을 조여도 판정이 안 움직였다.
                # 이 값들의 유일한 출처는 policy_file 이다.
            }],
        )
    ])
