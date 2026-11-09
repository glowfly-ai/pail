# Isaac Sim image derivation for the v4 profile

PAIL does not distribute any NVIDIA Isaac Sim image or asset. The v4 profile
requires an immutable local image ID that you build yourself in two steps from
the pinned upstream digest, after reading and accepting the SDK EULA.

## Pinned upstream (measured)

| Reference | Digest |
|---|---|
| `nvcr.io/nvidia/isaac-sim` 6.0.1 multi-arch index | `sha256:783444c706538aa76cf5126e911ddc5e618779e6105305ad4af4260362a30aa9` |
| linux/amd64 manifest (**pull this one**) | `sha256:b1c542b2ecc549b3d1ebb78c25664aa3bacba1709e6ad8e0a68e09426d57dedb` |
| image config | `sha256:2d4ebfef053f740b634e30723e38ed736255f677553425ef35552437d74c3b21` |

```sh
docker login nvcr.io     # user: $oauthtoken — password: your NGC API key at the masked prompt (never in a file or a shell history line)
docker pull nvcr.io/nvidia/isaac-sim@sha256:b1c542b2ecc549b3d1ebb78c25664aa3bacba1709e6ad8e0a68e09426d57dedb
```

## Two steps

1. `Dockerfile.sdk-readable` — makes `/isaac-sim` readable by the isolated
   endpoint UID (top-level directory mode only) and labels the image with the
   base reference (`org.pail.isaac.base`).
2. `Dockerfile.sdk-security` — overlays the security-capable Fast DDS, the two
   `rmw_fastrtps` libraries and `libtracetools` from the PAIL ROS gate image of
   the same release and architecture, with their package notices under
   `/opt/pail-ros-security-notices/`, and labels the overlay source.

```sh
cd examples/nvidia/sim/sdk
docker build --build-arg ISAAC_BASE=nvcr.io/nvidia/isaac-sim@sha256:b1c542b2ecc549b3d1ebb78c25664aa3bacba1709e6ad8e0a68e09426d57dedb \
             -t pail/isaac-sim:6.0.1-readable -f Dockerfile.sdk-readable .
docker build --build-arg PAIL_GATE_IMAGE=pail/core-tb3-gate:<release>-amd64 --build-arg ISAAC_READABLE=pail/isaac-sim:6.0.1-readable \
             -t pail/isaac-sim:6.0.1-security-candidate -f Dockerfile.sdk-security .
docker image inspect pail/isaac-sim:6.0.1-security-candidate --format '{{.Id}} {{json .Config.Labels}}'
```

Record both image IDs with your evidence. The images measured for an
earlier pre-release matrix (`8217a328…` readable, `0825f6ee…` security-candidate)
were built before the provenance labels existed, so IDs built from these files
differ from them by the label layer only; the overlaid bytes are identical (an
independent rebuild against that pre-release gate reproduced `0825f6ee…`).

## Terms and limits

The overlaid libraries are ROS 2 Humble components under the Apache-2.0 license
(see the copied `package.xml`/notice files); the rest of the image remains
under NVIDIA's terms. This derivation was measured on Isaac Sim 6.0.1 amd64
only; it is not an NVIDIA-supported or certified image and must be rebuilt and
re-probed for any other SDK version. The endpoint refuses to start when
`ROS_SECURITY_STRATEGY` is not `Enforce`, when the RMW is not
`rmw_fastrtps_cpp`, or when any of the overlaid libraries is missing. There is
no non-secure fallback.

Image IDs look different between Docker storage drivers: with the containerd
image store (Docker Desktop) `docker images` shows the manifest-derived ID
recorded in `images.lock.json`; with overlay2 (most Linux servers) it shows the
config hash. `evaluation.py load` and the lock check compare the right one for
your store; do not compare them by eye.
