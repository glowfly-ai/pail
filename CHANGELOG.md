# Changes

## 0.2.4

Changes since 0.2.2, the previous public release. The id 0.2.3 was sealed and retired without
publication, so a 0.2.2 deployment meets its changes here for the first time; they are listed
below under "Runtime images and tools". The token and wire protocols are unchanged. Read
"Upgrading from 0.2.2" before you replace a running 0.2.2 deployment or reuse a script written
for it.

### Trust anchor and revocation

- Bundle expiry while running. A gate compares the `expires_at_unix` of its loaded keyring
  bundle with its clock and refuses commands with `ERR_BUNDLE_EXPIRED` once it passes. An
  expired bundle used to be noticed at start-up only, so a robot that was already driving kept
  honouring tokens signed by a key whose bundle had run out. Renew a bundle before it expires:
  a robot that misses the renewal stops at the expiry instant (measured on a real TurtleBot3:
  the first refusal 0.074 s after it).
- Take-up without a restart. A bundle placed at the configured path with a higher
  `bundle_version` is verified against the root public key and applied by the gate itself
  (`PAIL_GATE_TRUST applied bundle_version=… revoked=…`), and a permit the gate is holding ends
  at once if that bundle revokes the key it was issued under. Retiring an Issuer key therefore
  reaches a running robot without restarting its gate: 0.100 s to the named refusal on a real
  TurtleBot3, with the drive command interval unchanged during a renewal (largest gap 0.124 s at
  a 0.1 s period).
- The gate restart command is optional. `PAIL_GATE_RESTART_CMD` was required for a new bundle to
  be loaded; the gate now does that itself. Keep it only for a deployment that still runs a
  0.2.2 gate. If it is set, the shell that would interpret it must exist in the image the agent
  runs in — a fallback that cannot be executed is not a fallback, and an agent configured that
  way refuses to start (rule `S20g`, exit 78). The Issuer image has no shell, so leave it unset
  there.
- Version floor. The accepted `bundle_version` is held in a state file so that losing a bundle
  cannot bring a revoked key back. A consumer that reads bundles refuses to start when that file
  is missing (`bundle state: missing …`), and a production gate refuses the bundle
  (`ERR_BUNDLE_STATE:missing`) instead of accepting any version. Initialise the file once per
  deployment with `pail-keyring-sign init-floor --bundle … --root-pub … --state …`; a deployment
  that already has one is unaffected.
- Revocation in one command. `pail-keyring-sign prepare-revoke --key-id …` moves one key of the
  current bundle to `revoked_keys`, raises `bundle_version` by one and leaves the expiry
  unchanged, so the operator signs a payload rather than editing JSON. `RevokeIssuerKey` answers
  a request only after its journal record is written; a failed append is answered
  `JOURNAL_APPEND_FAILED` instead of being reported as accepted.
- Bundle rules shared by both loaders. A bundle with two entries of the same `key_id`, or an
  entry without a role, is refused by the gate and by the Go consumers alike; 14 signed vectors
  pin that the two loaders answer the same bundle the same way.
- The agent confirms the application. After placing a bundle the agent reads the gate's state
  file and reports `KEYRING_APPLY_NOT_CONFIRMED` when it cannot see the version it placed, so a
  placement that nothing took up is visible. Give the agent read access to
  `PAIL_KEYRING_STATE`.
- The reference demos stop when their initial bundle expires (8 hours; 1 hour for the test
  tools). Start them again with a new state directory.
- A refusal over a declared path names what it is about. `trust_admin.py` and the trust
  observation of the console report the specific code (`SYMLINK_TARGET`, `HELPER_CHANGED`,
  `DECLARED_FILE_MISSING`, …) and the item — the profile field or the command argument — as
  `field`, where they used to answer `TRUST_INSPECTION_FAILED` or a bare
  `SYMLINK_DECLARATION`; a plan refused because the base signature could not be confirmed
  carries the reason as `cause`. A signer that is not there is no longer reported as a missing
  bundle (`MISSING`). The refusals themselves are unchanged, and no path is printed.
- The renewal guide can be followed from the delivery. `docs/TRUST_OPERATIONS.md` §4 gives the
  command that builds the signer from the Core source, points at the profile template, and
  explains every field of the consumer observation file with a new example,
  `examples/common/trust_renewal_consumers.example.json`. Loaded values come from the running
  consumer, not from the bundle file. On macOS write `/private/tmp/…`: `/tmp` is a symlink and
  a declared path with a symlink in it is refused.
- `pail-keyring-sign init-floor` says in its help that it reads only the bundle it is given and
  compares the floor with no other consumer. Run it on the bundle you intend to be current.
- Refusals after a bundle has expired are reported. A gate that refuses for `ERR_BUNDLE_EXPIRED`
  now reports the decision like its other refusals, so the Issuer's decision record and the
  audit journal say why the robot stopped; they used to end at the last `PERMIT` while only the
  gate's own log held the refusals. The refusal is not fatal: a renewed bundle brings the same
  session back. A refusal for a stepped clock (`ERR_CLOCK_DRIFT`) is still in the gate's log only.
- A renewal the signer refuses says why. `trust_admin.py plan-renewal` and `stage-renewal`
  answer `TRUST_HELPER_REJECTED` with the signer's reason as `cause` (for example
  `CONSUMER_LIFETIME_REJECTED`, `RENEWAL_IMMUTABLE_OR_VERSION_CHANGED`); they used to answer
  `HELPER_RESPONSE_INVALID`, which read as a broken signer.
- The renewal guide gives its command lines. `docs/TRUST_OPERATIONS.md` §4 now holds the
  commands of stages 1 to 3, the signer build and the root fingerprint before them, written so
  that they can be run as they stand; `plan-renewal --payload-out FILE` writes the payload the root signs. A relative
  `--profile` or `--state` is refused (`ABSOLUTE_PATH_REQUIRED`), as the guide already said.
- The plan summary of `trust_admin.py` and the comment of the reference policy no longer say
  that a renewal or an Issuer-key revocation takes effect at a gate restart. The declared
  mechanism and bound of `issuer_key` in the policy are unchanged, and the gate's start-up
  notice still reads that declaration.

### Runtime images and tools

- Issuer image. `pail/issuer-eval` is built `FROM scratch`: it holds the Issuer
  executables, their licence files and nothing of a distribution (no shell, no package
  manager, no Python, no CA bundle). An outbound HTTPS client of the Issuer (Vault
  signer, anchor service) is given its CA file with `SSL_CERT_FILE`.
- Split supervisor. The single-host profile (TB3 demo, E2E compose, NVIDIA example)
  starts `pail_cloud` and `pail_robot_agent` with the executable `pail_split` instead of
  the shell script `pail_split_entrypoint.sh`. It waits for the Issuer's stop sequence
  and exits with the Issuer's code, as the script did. `pail_split hold` holds a
  network namespace; any other argument starts nothing and exits 64.
- Demo probes. `demo_probe.py` (plan submit, cancel, unlock, verify) no longer runs
  inside the Issuer container. The Microduck demo and the Issuer rig start a `tools`
  container of the Microduck image beside the Issuer; the command of the adapter guide
  is now `docker exec "$PROJECT-tools-1" python /reference/demo_probe.py …`.
- Microduck image. `pail/core-microduck` is built on Debian 13 (trixie) with Python 3.13;
  it was Debian 12. Executables and libraries taken out of the image need glibc 2.38:
  they do not load on Debian 12 (the Microduck install guide lists what was measured).
  `zlib1g` is the fixed build of the Debian security repository (CVE-2026-85091).
- Image identity. Every runtime image carries the label `org.pail.image-input-sha256`,
  the hash of the files its build reads. The launchers compare that label with the
  tree beside them; a change of a guide, a judge or a launcher no longer makes an image
  stale. The label `org.pail.source-manifest-sha256`, which hashed the whole Core tree,
  is gone.
- Image origin. `images.lock.json` can record that an image is an earlier release's
  image under this release's label (`reuse`), `load` checks the record against the
  image, and `doctor` prints an `image-provenance` row. The row is read from the lock, so
  it is printed on a host with no working Docker daemon too. A reuse is recorded only after a
  proof of equal layers and equal configuration outside the labels (the build inputs are the
  same record); what this bundle's three runtime images are is stated in its validation
  record and printed by `doctor`.
- Port advice. A busy default port is answered with an alternative that `doctor` and the
  launcher bind before they name it. The alternative used to be a fixed number per option,
  and on a host where the default and that number were both taken the refusal named the
  busy one. When the whole window is taken, the advice is "another free port".
- TurtleBot3 hardware example. `fault_inject.py` signals a process with
  `tb3-probe -mode signal` (the Issuer image has no shell to run `kill` in);
  `tb3-probe -mode isolation` serves the isolation check of the NVIDIA example. Its
  header says which mode freezes the container (`permit`, `outage`) and which signals
  the Issuer process inside it (`agent-crash`).
- Hardware console. `console_hw.py` ends the `ssh docker logs -f` mirrors it started and
  closes the ssh multiplexing master when it stops. The mirrors used to be left running
  under PID 1, each holding the master open, and after a few console restarts the robot's
  sshd refused new sessions — which the next start reported only as a clock it could not
  measure. That refusal now names the ssh failure behind it.
- `test-supersede`. A run whose gate was refusing commands with `ERR_CLOCK_DRIFT` is
  diagnosed with the conformance harness's `CLOCK_PREREQUISITE_FAILED` sentence, before the
  per-check story. It used to report its own fixed explanation ("the gateway did not reach
  the Issuer in time after the reconnect") for a clock that was being stepped.
- End-to-end run. `e2e/run_e2e.sh` counts the journal segments and anchor records in a
  one-shot container of the gate image that has the Issuer container's user and mounts
  (it ran a shell in the Issuer container). With `--vault`, the outage step asks for a
  new operation: the repeated operation id it sent before is answered from history
  without the signer, so that step failed for a reason unrelated to the vault.
- Judges. A scene that fails on a refused command prints every reason field of the
  answer; before, the line could read `refused: None`.
- Demo planners. The planner's copy of a step window starts at a clock reading taken
  before the command is sent, and the zero-velocity window is checked just before each
  send. Before, a zero command could reach the adapter a few milliseconds after the
  step deadline and be refused.
- Evaluation guide. The command of section 7 that deletes a state directory left with
  root-owned files uses the Microduck image; the Issuer image has no `find`.
- Vulnerability triage. Every Critical or High finding of the image scan that has no
  fixed package has a recorded verdict with its evidence. The bundle's validation record
  gives the raw counts and the verdicts; the release publishes them as an OpenVEX document
  (`PAIL-0.2.4-linux-arm64.openvex.json`) that a scanner can apply. The document is
  delivered beside the archives — it names the built image tags, so it is not a file inside
  a bundle — and is signed with the release key as `…openvex.json.sig`; it belongs to the
  hand-over set with the five archives and their sidecars.
- An empty publisher fingerprint is refused. `verify_evaluation.py` and the bundled
  `pail_verify` exit 2 when `--expected-fingerprint` is given with an empty value (or
  whitespace only), before anything is verified and without writing a receipt. Such a call —
  an unset variable expanded into the flag — used to end `PASS` with
  `PUBLISHER_KEY: NOT_COMPARED`. Leaving the flag out is still accepted and still recorded as
  `NOT_COMPARED`.
- A verification receipt is not weakened by a later run. For the same manifest, a run without
  `--expected-fingerprint` no longer replaces the receipt of a run that compared the key, and
  an `--allow-unsigned` run no longer replaces one that verified the signature; the tool says
  `RECEIPT: kept …` with the reason. In the other direction, a run that compares the key now
  replaces a receipt that had only compared the tree — it used to be dropped, and `load` went
  on reporting the key as not compared. Both verifiers follow one table.
- The TurtleBot3 scene judge puts back the inputs it changes. A scene that injects a wrong tag
  or `UNSAFE` restores it when the scene fails as well, and a judge that starts on injected
  inputs resets them and prints `INPUTS_RESET …`. A failed run on a faulted demo used to leave
  `tag=other-box` in place, and every later plan was then refused for the tag.
- `doctor` warns about a clock that is still being brought in. On a host whose time source is
  chronyd, the clock row reads what chronyd has just corrected (`RMS offset`, `Last offset` of
  `chronyc tracking`) and reports `CLOCK_NOT_SETTLED` when it exceeds the gate bound of 0.5 s.
  Shortly after it starts, chronyd steps an offset of seconds at its first updates, about a
  minute apart; the row's watch of a few seconds did not see that and answered `READY` before a
  run that then lost its clock prerequisite.
- `test-supersede` names a stepped clock. On a host whose clock is being stepped the check
  counts the refusals its own probe received, not only the service logs — the gate does not
  report a clock refusal, so those logs hold none — and states the clock prerequisite before
  its own diagnosis, as `test-conformance` does.
- Documents. `spec/API_SURFACES.md` lists the six RPCs of `OperatorService` (it said
  three) and states that `LOCKDOWN` survives a restart of the Issuer on the same journal;
  `CONFIG.md` states that the generated configuration files are relative to
  the `--state` directory, not to the Core source tree.

### Upgrading from 0.2.2

- Initialise the keyring version floor once per deployment:
  `pail-keyring-sign init-floor --bundle … --root-pub … --state …`. Without that file the
  Issuer, the agent and the other bundle consumers refuse to start, and a production gate
  refuses the bundle.
- Renew a keyring bundle before it expires. An expired bundle now stops the robot instead of
  being carried until the next restart.
- A gate restart command is no longer needed for a new bundle to be loaded. If you keep
  `PAIL_GATE_RESTART_CMD`, run the agent in an image that has `/bin/sh`; otherwise unset it.
- Declare `PAIL_KEYRING_MAX_LIFETIME_SEC` for a production gate.
- A bundle made by another signing tool must give every entry a role and must not repeat a
  `key_id`; bundles made by `pail-keyring-sign` already satisfy both.
- `docker exec <issuer container> sh …`, `python …` or `find …` no longer works: the
  Issuer image has no such program. Use the `tools` container of the demo, or a
  container of the Microduck image on the Issuer's network.
- A compose file or unit that names `/usr/local/bin/pail_split_entrypoint.sh` must name
  `/usr/local/bin/pail_split`; one that runs `sleep infinity` in the Issuer image must
  run `pail_split hold`.
- Set `SSL_CERT_FILE` for an Issuer that reaches Vault or an anchor service over HTTPS,
  and mount the CA file it names.
- Rebuild an adapter or a library that was linked against the Debian 12 Microduck
  image, or check it with `ldd` against the new image.
- A script that read the image label `org.pail.source-manifest-sha256` must read
  `org.pail.image-input-sha256`.
- A script that passes `--expected-fingerprint "$VAR"` to the verifier now fails with exit 2
  when the variable is empty. Set the variable, or leave the flag out on purpose.
- A call of `trust_admin.py` with a relative `--profile` or `--state` is refused; give absolute
  paths.
- A script or a page that compared the trust observation's `file.reason` with
  `TRUST_INSPECTION_FAILED` must accept the specific codes, and must not read `MISSING` as
  "the signer is not installed": that is now `UNOBSERVED` with `DECLARED_FILE_MISSING`.
