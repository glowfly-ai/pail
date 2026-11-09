# Waffle Pi asset tree for the v4 profile

PAIL does not bundle any USD. The measured asset tree is reproduced from public
inputs with your own Isaac Sim derivative image (`../sdk/`):

| Input | Value |
|---|---|
| Robot description | ROBOTIS `turtlebot3` repository, `humble` branch, commit `90a68bd2e3c61c12966779da89d8eeaec82730e9`, package `turtlebot3_description` (`urdf/turtlebot3_waffle_pi.urdf`, four STL meshes), Apache-2.0. **At this commit the URDF is a xacro document** (`xmlns:xacro`, `${namespace}` prefix on every link and joint, default empty); `import_waffle_pi.sh` expands it with `expand_urdf.py` before the import and refuses any xacro construct beyond that subset |
| Expanded URDF | `expand_urdf.py` output for the pinned commit: sha256 `44cdd79bcb2c8833b69d3fe7c69e4e4f77628df002dcb87d3c7b86998235fe45` (10 joints, 11 links; the script prints `expanded_urdf_sha256` and records it in `ASSET_TREE.json`). Joints `wheel_left_joint` / `wheel_right_joint` must exist after expansion, or the script stops before the import |
| Importer | `standalone_examples/api/isaacsim.asset.importer.urdf/urdf_import.py` of Isaac Sim 6.0.1, headless, options as in `import_waffle_pi.sh` (force drives, velocity targets, stiffness 0, no fixed base, no mesh merging, PhysX + multi-physics conversion) |
| Overlay | `pail_tb3_waffle_pi.usda` (this directory): references the converted `turtlebot3_waffle_pi/turtlebot3_waffle_pi.usda`, selects the PhysX variant and sets **test-only** wheel drives: stiffness 0, damping 1 N·m·s/rad (`0.01745329252` in USD degree units), max force 1 N·m, targets 0 |
| Expected result (6.0.1, measured twice 2026-10-17 on one L40S host from the expanded URDF above) | 10 files; `assets_sha256_normalized = 3d46465df837ab948e67d5cb123fb68f003d08785d3a13e5d07269e24baed799`; `semantics_sha256 = 87249d4e3d050c7d7e39d226d6923446eebdae39ed9621c4d21481f1ad5bf754`; entry file `pail_tb3_waffle_pi.usda`; composed stage 49 prims; joints `camera_joint`, `caster_back_left_joint`, `caster_back_right_joint`, `scan_joint`, `wheel_left_joint`, `wheel_right_joint` (the converted tree, overlay excluded, defines the two wheel joints under their plain names); 4 meshes (`waffle_pi_base` 76,915 points / 157,576 faces, `lds` 7,231 / 14,566, `left_tire` and `right_tire` 10,812 / 21,672 each); link masses `base_link` 1.372909546 kg, `base_scan` 0.114, `wheel_*_link` 0.02849894, `caster_back_*_link` 0.005; radius 0.033 m, separation 0.288 m (profile: 33000 µm / 288000 µm). The same values came out of two independent imports made from the same inputs on 2026-10-17 (their trees differed under the preview.16 normalization) |

Run (absolute or relative paths; the output directory must not exist):

```sh
bash import_waffle_pi.sh <your isaac image> /path/to/turtlebot3_description /path/to/new-output
```

The script writes `ASSET_TREE.json` (`asset_tree_hash.py`, run by the image's
own python and USD libraries — no GPU, no Kit) with per-file hashes, two tree
hashes and a semantic summary:

- `assets_sha256` — the raw bytes of this tree. **It is not reproducible across
  runs, even with the same image and input:** the importer writes the names of
  its two scratch directories (`/tmp/tmpXXXXXXXX/` and
  `/tmp/urdf_import_<robot>_<random>/`) into the USD `doc` string of nine files,
  and the same strings sit inside the binary crate `payloads/geometries.usd`.
  This is the value `make_isaac_profile.py` pins for the tree you actually use,
  and the endpoint verifies before every run.
- `assets_sha256_normalized` — text layers with both scratch paths replaced by
  constants; binary crate layers (`*.usd`, `*.usdc`) exported to USDA text with
  pxr (`Sdf.Layer.ExportToString`) and normalized the same way; every other
  file by raw bytes. This is the value to compare with the expected result
  above and across your own runs; it was measured twice here and agreed. A
  different importer version may still produce different content; record your
  values with your evidence instead of editing the expected ones. (An
  earlier recipe normalized only the first scratch path and hashed the
  crate bytes, so its value `c7c07021…` was not reproducible.)
- `semantics` / `semantics_sha256` — what the gate's test depends on, read from
  the composed stage (instance proxies included): joint prim names, prim count,
  mesh point/face counts, link masses.

The script works in `<output>.importing` and renames it into place only when the
expansion, the import, the joint-name check and the hashing all passed; a failed
run leaves the scratch directory for inspection and the next run replaces it.
The hashing step refuses (rc 5) when the USD libraries are not found instead of
silently hashing bytes.

## What the overlay is and is not

The drive values are a simulation test setting chosen so that the gate's small
authorized commands (0.05 m/s) produce observable motion and a clean stop. They
are **not** measured TurtleBot3 motor, friction or braking parameters, and the
matrix results are not a physical calibration. Five URDF links carry no
inertial data; the converted mass/inertia of the six that do were checked
against the URDF (max error 2.4e-9 kg·m²).

## Review before use

- The asset directory must contain only this tree (no keys, no other projects);
  `make_isaac_profile.py` hashes every file and the endpoint refuses symlinks.
- `make_isaac_profile.py` and `session.py doctor` refuse a tree in which the
  profile's wheel joints are not defined under their plain names (overlay
  excluded) — a tree imported from the unexpanded xacro file fails here instead
  of at the endpoint (`KeyError: 'wheel_left_joint'`).
  Refusals are one line on stderr (`refused: …`), rc 1.
- The endpoint rejects embedded OmniGraph nodes and nonzero initial drive
  targets; the importer output has none, the overlay keeps targets at 0.
- The ground plane is created at runtime by the endpoint (local 10 m plane,
  friction 0.5), not loaded from the asset or from the network.
- Licensing: the URDF and meshes are ROBOTIS Apache-2.0; the converted USD is
  derived with NVIDIA's importer under NVIDIA's terms. PAIL ships the recipe and
  this overlay only; publish converted trees only after your own review.
