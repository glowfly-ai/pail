# PVS runner

The runner executes YAML scenarios against a PAIL stack and records expected and observed results.
The maintained runtime procedure is [PVS Live Bring-Up](../LIVE_BRINGUP.md).
Do not use the old standalone `runner.py` examples as the integration entry point.

## Host checks

From the PVS directory (the parent of this file), in a virtual environment:

```sh
python -m pip install -r requirements.txt
python -m pytest -m "unit or not live"
```

## Scenario results

```sh
PVS_RESULT_JSON=/tmp/pvs-result.json python -m pytest tests/test_scenarios.py
```

Without a configured live runtime, scenario rows are SKIP, not successful live measurements.
For actual ROS 2 / gRPC integration, follow the linked bring-up guide, including identity,
compose and token-source setup. `-m "live or nightly"` enables nightly steps; `-m "live and nightly"`
selects no scenarios. Select an axis using `-k` as the guide describes.

Generate protobuf stubs only in a separate execution copy, not in the verified delivery tree.
The public source archive places its protocol files in `../sdk/proto` relative to the PVS directory;
the internal checkout uses `../proto`. Dependencies, environment and missing prerequisites must
be recorded with the result. A zero exit code with skipped scenarios is not a live pass.
