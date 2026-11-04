# TB3 timing budget and recovery profile

This is a measured software integration profile, not a physical braking guarantee.
The gate's signed limits are not enlarged to accommodate scheduling jitter.

## Three different facts

1. A command was permitted or blocked. Preserve that original decision.
2. A step was locally consumed, and separately the issuer accepted its completion.
3. A physical task succeeded. Neither a planner's `plan_done` nor a zero command proves it.

`GateState.completed_token_id` reports **local** consumption, not an issuer ack.
`step_deadline_elapsed_ms` and `step_clock_id` describe the actual active gate
budget. They are advisory; they do not grant authority. Rebuild every ROS message
consumer for this release. Do not mix older `pail_msgs` with the new nodes.

## Current raised-wheel demo budget

| Component | Value / meaning |
|---|---|
| Planner publication/stop check | 100 ms |
| Planner delivery budget | 100 ms |
| Planner scheduling allowance | 50 ms |
| Nonzero publication cutoff | 250 ms before the **observed gate deadline**, not a deadline inferred from receiving PERMIT |
| Stop command | Sent only while at least the delivery budget remains; no post-expiry zero tail |
| Permit heartbeat | 20 Hz (nominal 50 ms) |
| DDS deadline / independent bridge watchdog | 100 / 200 ms; also checked at the forwarding door |
| Gate recheck | 100 ms; inputs/RPC may consume time, so ordinary completion is serviced afterward |
| Gate RPC | 50 ms to the **local agent**, not a direct factory-Wi-Fi RTT budget |
| Agent mirror | 200 ms configuration; the upstream issuer path is separate |
| Grace | Three consecutive recheck outcomes; not a standalone physical-stop bound |
| Clock drift | 500 ms against the startup wall/steady baseline; not proof of UTC accuracy |

The hardware console submits a separate **0.35 s authorization reserve per step**
(0.10 discovery + 0.25 stop budget) to the issuer before a token exists. The
original desired motion duration is carried separately to the demo planner.
The issuer may refuse a request whose motion plus reserve exceeds policy; the
console displays the correspondingly smaller per-call motion maximum. No
existing token is extended, and the policy's time/speed ceilings are unchanged.
A new token's requested authorization duration IS larger than the bare motion
duration; this is explicit budget allocation, not an unreported tolerance.
The planner stops at the earlier of its desired motion duration and the actual
gate-budget cutoff, so a narrower superseding grant still wins.

The first command used to discover an unobserved budget is zero. The planner
matches the gate's Linux boot and BOOTTIME namespace offset before using the
deadline, never extends a cached deadline for the same token, and waits for
actual local consumption before probing the next step. An unavailable or foreign
clock never justifies a nonzero command. A superseding grant may shorten the
budget of an already running command stream. The gate still judges every command.

These planner constants are a declared reference profile, **not universal measured
worst-case bounds**. A port must measure transport and callback tails under its
specified load. The early stop can shorten a time-driven move; measure distance
and rotation as well as refusals. Do not compensate by increasing speed beyond
the signed limit or by extending an already issued token. Reserve must be requested
explicitly before issuance, fit policy, and remain visible in the submitted plan.

If a platform needs a different profile, change and validate its explicit budget
as a versioned integration change. This release does not pretend that these demo
constants are a remotely signed runtime policy. Reject incompatible settings;
do not advertise a setting that the running component does not consume.

## Metrics and negative controls

Keep the original reason, command/token identity, decision path, deadline,
overrun, clock cause and effective configuration. Group repeated notifications
in the UI if useful, but count **all** HOLD intervals, downtime and retries.
Small overruns are not automatically successful completion. Tests still reject
genuine late commands, excessive speed, wrong targets and invalid authority.
Normal duration expiry is consumption, not proof that wheels or a gripper did
what the application intended.

At least distinguish cold startup, established operation, controlled CPU/network
load and recovery. Declare repeat counts before running; preserve failures.
Report command/step/run denominators separately. A run of 13/13 is not a
failure-rate estimate and p99 is not a worst-case guarantee.

## Clock faults and recovery

Wall drift is a repeatedly evaluated condition. If the original clock relation
returns within the bound, that condition can clear; remaining authority must
still satisfy the existing token/step/safety/evidence rules. Elapsed-clock read
failure or reversal is a separate session latch. Neither path resets a budget.

The hardware reference planner additionally aborts the **whole instruction** on
`ERR_CLOCK_DRIFT`, including remaining steps. It persists the interrupted token
set in `/state/demo_planner_clock_abort.json` in the existing private runtime mount.
Clock recovery, feed/velocity updates, and planner restart cannot by themselves
clear that marker. Only a fresh plan with disjoint tokens and an actual matching gate PERMIT
clears it; until then only zero-velocity probing is allowed. Instruction counters
can restart and are not plan identities. Raw-drive requests do not clear it. State I/O errors block reference
motion. Repair storage and reconcile/cancel old authority; a restart after an I/O
failure is not evidence that the abort was durably recorded. Do not delete state
to bypass the requirement. A clock abort is not a successful `plan_done` event.

This is reference-planner policy, not gate-side fencing: another client with
still-valid authority remains subject to the unchanged token/step rules above.
No automatic baseline reset or service restart is added.
A supervisor should distinguish restoring service readiness from restarting a
physical task. The operational recovery procedure is:

1. Keep the robot in HOLD using the machine's own stop provisions. Save evidence.
2. Identify the clock fault and verify the chosen time source and uncertainty.
   Avoid competing host-sync/NTP writers. Permit a boot-time correction before
   starting the rig; do not intentionally step a clock under active authority.
3. Check trust material and persistent rollback floors. **Never delete the state
   file to bypass a refusal.** A restart is not itself proof that time is trustworthy.
4. Account for/cancel old authority with the issuer and reconcile the agent's
   chain, lease and consumption state. A configuration or read failure is not a
   successful reconciliation.
5. Restore readiness, then submit a fresh plan when the machine/application
   allows resumption. Do not automatically replay the interrupted instruction.

This is operator/supervisor guidance, not a new enforced recovery protocol.
Authenticated time recovery, generation fencing of old authority and automatic
resumption require a separate protocol/security design. A network outage with
a still-valid delegated lease is not the same as absence of authority.
Sleep/resume and clock slew must be tested for the actual OS: the elapsed budget
includes suspend, while the drift baseline uses `steady_clock`.

## Repeated clock warnings

Only human-facing `ERR_CLOCK_DRIFT` WARN lines are aggregated. Each callback path
(command, recheck, step_timer) logs the first fault and a cause change immediately,
then at most one periodic summary per second of `steady_clock`. Changing numeric
drift values do not restart the interval. `interval_count` counts newly observed
refusals since the preceding line; `total_count` is the cumulative count in that
path/cause episode. The final `event=end` line flushes any remaining count. It
means that warning stream ended, **not** that UTC was authenticated or motion is
ready. A process exit can leave an unflushed partial interval; WARN text is not
an authoritative lossless decision ledger. Each GateState and existing decision
report still carries its original reason and numeric detail at the original rate.
Count HOLD/downtime from those observations, not the number of WARN lines. Paths
can each emit one summary per second; this is not a global one-line-per-second cap.

## Keyring lifetime setting

`PAIL_HW_KEYRING_MAX_LIFETIME_SEC` selects the C++ gate's
`PAIL_KEYRING_MAX_LIFETIME_SEC`. The comparison at load is `expires_at - now`,
not the bundle's age. The C++ loader defaults to 86400 seconds for compatibility;
an explicit value must be a positive decimal integer representable by the Go
duration domain. Invalid values and excessive remaining lifetime refuse startup.
The Go loader requires its ceiling explicitly. Declare the intended ceiling at
each component rather than assuming the defaults are identical.
Root signature, rollback and absolute-expiry checks remain independent. A one-second
ceiling must refuse an eight-hour bundle; it must not advance the accepted version.
