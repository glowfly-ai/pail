# Command-path latency probe

Measures how much later a driver sees a velocity command when the PAIL gate and
motion bridge sit between the publisher and the driver topic:

```
publisher --/cmd_vel--> pep_gate --/safe_cmd_vel--> motion_bridge --/drive_cmd_vel--> base
              tap cmd                 tap safe                        tap drive
```

`geometry_msgs/Twist` has no header, so the sequence number is carried in
`linear.x` (`0.02 + seq * 1e-7`); the gate and the bridge republish the message
unchanged. One probe container joins the rig's network and IPC namespaces and
runs every tap and the publisher, so all timestamps come from one
`CLOCK_MONOTONIC`. Taps run under the enclaves that may subscribe to each topic
(`/pep_gate`, `/motion_bridge`, `/driver`); the publisher runs as `/oem_planner`.

What the numbers are: the time for the command **topic** to reach the driver
node, compared with subscribing to `/cmd_vel` directly. What they are not: the
driver, firmware or motor control loop below the driver node, which this probe
does not touch and PAIL does not touch.

## Run

Reference rig (`examples/tb3/demo.py`, e.g. `evaluation.py tb3 --state STATE`):

```sh
python3 lat_run.py --kind compose --state STATE --out OUT --rates 10,20,50 --seconds 14 --settle 10
```

Real TurtleBot3 rig (`hardware/start_demo_rig.sh up` on the robot; plans are
submitted with `tb3-probe` from the services image against the operator-PC issuer):

```sh
python3 lat_run.py --kind hw --rig-dir ~/pail-hw --config ~/pail-robot-config \
  --gate-image pail/tb3-hardware:<tag> \
  --submit "docker run --rm -v ~/pail-robot-config/grpc_certs:/certs:ro --entrypoint tb3-probe <services image> -addr <pc-ip>:50064 -ca /certs/ca.crt -cert /certs/robot-01/client.crt -key /certs/robot-01/client.key" \
  --out OUT --rates 10,20 --seconds 14 --settle 30 --taps cmd,drive --buffer
python3 lat_analyze.py --dir OUT --json OUT/ANALYSIS.json
```

Read `hop` (publisher to a direct subscriber) first: it is the probe's own
health. On a Raspberry Pi 3 four Python taps saturate the board; use two taps
(`--taps cmd,drive --buffer`) and keep only runs whose `hop` p99 stays under
10 ms. Steady state starts one second after the first delivered command; commands
sent before the gate holds the token are refused by design (`ERR_NO_TOKEN`) and
are reported separately, not as loss.
