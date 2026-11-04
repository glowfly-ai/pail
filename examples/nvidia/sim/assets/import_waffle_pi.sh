#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
#
# Reproducible TurtleBot3 Waffle Pi asset tree for the v4 profile (preview.14 stage-2 finding I-2;
# preview.15 findings P15-M1, P15-L1, P15-L4).
# Runs NVIDIA's own headless URDF importer inside your locally derived Isaac Sim image, then places the
# test-only drive overlay (pail_tb3_waffle_pi.usda, this directory) on top. Nothing is downloaded here:
# you supply the ROBOTIS turtlebot3_description checkout (humble branch, commit 90a68bd2e3c61c12966779da89d8eeaec82730e9,
# Apache-2.0) and the SDK image you built with ../sdk/. See ASSETS.md for the review criteria and expected values.
#
# At that commit `urdf/turtlebot3_waffle_pi.urdf` is a xacro document (`${namespace}` prefixes); the importer
# keeps the `${namespace}` text in the prim names and the tree ends up without `wheel_left_joint`. The package
# is therefore copied, the URDF expanded (expand_urdf.py, xacro subset only) and the joint names verified
# before and after the import. The output directory is written under a scratch name and renamed into place
# only when every step passed, so a failed run leaves nothing that blocks the next one.
#
# usage: import_waffle_pi.sh <isaac-image-id-or-tag> <path/to/turtlebot3_description> <new output dir>
set -Eeuo pipefail
IMAGE=$1; DESC=$(cd "$2" && pwd); HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$(dirname "$3")"; OUT=$(cd "$(dirname "$3")" && pwd)/$(basename "$3")   # absolute: docker -v needs it
[ -f "$DESC/urdf/turtlebot3_waffle_pi.urdf" ] || { echo "turtlebot3_description/urdf/turtlebot3_waffle_pi.urdf not found under $DESC" >&2; exit 2; }
[ ! -e "$OUT" ] || { echo "output directory exists: $OUT (a converted tree is never overwritten)" >&2; exit 2; }
WORK="$OUT.importing"
if [ -e "$WORK" ]; then echo "removing scratch directory left by an earlier failed run: $WORK" >&2; rm -rf "$WORK"; fi
mkdir -p "$WORK/assets" "$WORK/import-cache" "$WORK/source"
trap 'rc=$?; [ $rc -eq 0 ] || echo "import failed (rc=$rc); scratch kept for inspection: $WORK" >&2' EXIT

# 1. Expand the xacro subset and verify the joint names the overlay/profile drive (P15-M1).
cp -R "$DESC" "$WORK/source/turtlebot3_description"
chmod -R u+w "$WORK/source"
python3 "$HERE/expand_urdf.py" "$DESC/urdf/turtlebot3_waffle_pi.urdf" "$WORK/source/turtlebot3_description/urdf/turtlebot3_waffle_pi.urdf" \
  --require-joint wheel_left_joint --require-joint wheel_right_joint
URDF_SHA=$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$WORK/source/turtlebot3_description/urdf/turtlebot3_waffle_pi.urdf")

# 2. Import. The importer needs the ROS package root so that package:// mesh references resolve; no network.
docker run --rm --gpus all --network none --cpus 8 --memory 24g --shm-size 1g --user "$(id -u):$(id -g)" \
  -e ACCEPT_EULA=Y -e HOME=/cache -e XDG_CACHE_HOME=/cache/xdg \
  -v "$WORK/source/turtlebot3_description:/input/turtlebot3_description:ro" -v "$WORK/assets:/output" -v "$WORK/import-cache:/cache" \
  --entrypoint /isaac-sim/python.sh "$IMAGE" \
  /isaac-sim/standalone_examples/api/isaacsim.asset.importer.urdf/urdf_import.py \
  --urdf /input/turtlebot3_description/urdf/turtlebot3_waffle_pi.urdf \
  --ros-package turtlebot3_description:/input/turtlebot3_description \
  --usd-path /output --no-fix-base --no-merge-fixed-joints --no-merge-mesh \
  --no-collision-from-visuals --no-allow-self-collision \
  --joint-drive-type force --joint-target-type velocity \
  --override-joint-stiffness 0 --run-asset-transformer --run-multi-physics-conversion
test -s "$WORK/assets/turtlebot3_waffle_pi/turtlebot3_waffle_pi.usda" || { echo "importer produced no turtlebot3_waffle_pi.usda" >&2; exit 3; }

# 3. The converted tree (overlay excluded) must define the wheel joints under their plain names.
for j in wheel_left_joint wheel_right_joint; do
  grep -rqF "\"$j\"" "$WORK/assets/turtlebot3_waffle_pi" || { echo "converted tree does not define joint \"$j\" (importer kept a prefixed name?)" >&2; exit 4; }
done
cp "$HERE/pail_tb3_waffle_pi.usda" "$WORK/assets/pail_tb3_waffle_pi.usda"
find "$WORK/assets" -type d -exec chmod 755 {} + ; find "$WORK/assets" -type f -exec chmod 644 {} +

# 4. Hashes and semantics (asset_tree_hash.py, run with the image's own python and USD libraries; no GPU, no Kit).
#    The importer writes the names of TWO scratch directories into the USD `doc` strings ("/tmp/tmpXXXXXXXX/" and
#    "/tmp/urdf_import_<robot>_<random>/"), also inside the binary crate payloads/geometries.usd, so the raw tree
#    hash differs on every run (P15-L1, P16-M1). assets_sha256_normalized exports binary layers to USDA text with
#    pxr and normalizes both paths; it is the value to compare across runs. assets_sha256 (raw) is what the
#    profile pins for THIS tree. semantics (joints, prims, meshes, masses) is what the gate's test depends on.
chmod 644 "$HERE/asset_tree_hash.py" 2>/dev/null || true   # the image runs unprivileged; a 0600 checkout cannot be read there
docker run --rm --network none --user "$(id -u):$(id -g)" --entrypoint bash \
  -v "$HERE/asset_tree_hash.py:/tool/asset_tree_hash.py:ro" -v "$WORK/assets:/tree:ro" -v "$WORK:/work" "$IMAGE" -c '
U=$(ls -d /isaac-sim/extscache/omni.usd.libs-* | tail -1)
export LD_LIBRARY_PATH=$U/bin:$U/lib:/isaac-sim/kit:/isaac-sim/kit/libs:/isaac-sim/kit/plugins:${LD_LIBRARY_PATH:-}
export PXR_PLUGINPATH_NAME=$U/plugins
exec /isaac-sim/kit/python/bin/python3 /tool/asset_tree_hash.py /tree pail_tb3_waffle_pi.usda "$1" /work/ASSET_TREE.json' _ "$URDF_SHA"
test -s "$WORK/ASSET_TREE.json" || { echo "asset_tree_hash.py produced no ASSET_TREE.json" >&2; exit 5; }
rm -rf "$WORK/source"
mv "$WORK" "$OUT"
echo "asset tree written under $OUT/assets; review ASSETS.md before using it in a profile (asset dir must contain nothing else)"
