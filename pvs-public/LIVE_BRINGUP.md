# PVS testing in the public distribution

## Start with the supported release examples

From the repository root use `python3 examples/tb3/run.py` or
`bash e2e/run_e2e.sh`. See [../TRY_IT.md](../TRY_IT.md). These commands provision their
own test identities and have explicit software/hardware boundaries.

## Host-side PVS tests

The public tree includes scenario definitions, verifiers and host-side unit tests.
From `pvs-public/`, create a virtual environment, install `requirements.txt`, then run
the following commands. The host-side mock client also imports generated protobuf
modules, so generation is required even when live scenarios are not selected:

```sh
python -m grpc_tools.protoc -I ../sdk/proto --python_out=runner/live --grpc_python_out=runner/live ../sdk/proto/*.proto
python -m pytest -m "unit or not live"
```

Live tests need extra ROS and deployment setup
and are not evidence of success when skipped. Record selected, executed and skipped counts.
The vector readers use the public `spec/vectors/` location without private files.

## Advanced live integration

The generic live backend is supplied for integrators, not as another one-command release
stack. It needs ROS 2 Humble, generated Python gRPC stubs, robot message packages,
explicitly provisioned identities, and an operator-supplied `PVS_COMPOSE_FILE` matching
its service names and fault-injection seams. That topology is not the TB3 example.
Set `PVS_LIVE=1` only after those prerequisites exist. Missing setup must not be reported
as successful live testing. Do not weaken production authentication to fit a test rig.

There is no launcher for this live topology in the tree: a live rig is site-specific.
The release examples are the first-use path; operating such a rig is not required to
install or evaluate PAIL.

Microduck and Viam adapter implementations are separate release targets. Their scenario
helpers or registry rows do not mean their full implementations or real hardware support
are included here. See [../spec/ADAPTERS.tsv](../spec/ADAPTERS.tsv).
