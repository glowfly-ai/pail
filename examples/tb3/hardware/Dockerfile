# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
#
# Gate image + the vendor TurtleBot3 base driver, for the robot's computer (arm64 or amd64).
# Build on the operator PC from a gate image that examples/tb3/demo.py or run.py built:
#
#   docker build --build-arg PAIL_TB3_GATE_IMAGE=pail/tb3-gate:<tag> \
#     -t pail/tb3-hardware:<tag> -f examples/tb3/hardware/Dockerfile examples/tb3/hardware
#
# Only the two vendor packages are added; the gate, bridge, entrypoints and the unprivileged
# user of the base image are unchanged. No firmware, lidar or arm package is installed.
ARG PAIL_TB3_GATE_IMAGE=pail/tb3-gate:local
FROM ${PAIL_TB3_GATE_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      ros-humble-turtlebot3-node ros-humble-turtlebot3-bringup \
  && rm -rf /var/lib/apt/lists/* \
  && dpkg-query -W -f='${Package} ${Version}\n' 'ros-humble-turtlebot3*' > /opt/tb3-package-versions.txt
USER 10001:10001
