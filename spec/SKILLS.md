# Skill registry — `config/skills.<robot_class>.yaml`

Status: enforced. A row is what the issuer authorizes by and what the gate judges by —
not a declaration. The issuer matches the row and bakes its envelope into the token
; the gate compares the command against that envelope **by name** ; the row's
`complete.signal` decides what consumes the step ; under policy `token_schema: 5`
the envelope rides on the token as a named list with the skill's own name ; the
row's `feeds` and `safe_state` are checked at start and bind the permit . See [ARCHITECTURE.md](ARCHITECTURE.md) for the complete component overview.

A skill registry names, per robot class, every skill a plan may call. **A name that is
not in the registry is not authorized** — the registry is an allow-list, and there is no
`"*"` row. Registration is a deployment act: the robot vendor (or the operator porting
PAIL) writes the file, it is sealed with the rest of the robot configuration, and the
issuer and the gate read the same bytes.

The registry does not enumerate behaviour. For robots without a skill API (policy
streaming), a row names an *episode kind* (`tidy_episode`) — the envelope, feeds, safe
state and requester grant bundled under one name — and the physical bounds carry the
weight.

## Fields

One file per robot class: `version: 1`, `robot_class: <SKILL_VOCAB.tsv robot_class>`,
`skills: [...]`. Unknown keys are refused. A skill row:

<!-- source: cloud/internal/skills/skills.go -->
<!-- source: libpail_gate/src/skills_load.cpp -->
<!-- example: config/skills.diff_drive_amr.yaml -->

| Field | Required | Vocabulary / form | Meaning |
|---|---|---|---|
| `name` | yes | `[a-z][a-z0-9_]{0,63}` | `ActionSpec.name` without namespace, or a primitive (`twist`, `pick`, `place`) |
| `classes` | yes | `SKILL_VOCAB.tsv` `action_class`, one or more | Baked into the v4 token mask; v5 compares the name |
| `evidence.when` | yes | `none` / `before` / `at_complete` | When target evidence is required. `none` means the step carries no `target_object_id` |
| `evidence.trust` | when `when ≠ none` | a `policy.yaml` `trust_classes` id | Lowest acceptable grade; not below `evidence.min_trust_class` |
| `envelope` | yes (may be empty) | `GUARDRAILS.tsv` names | Bounds carried on each call of this skill; each must be in the serving adapter's `measures` |
| `feeds` | yes (may be empty) | `policy.yaml` `preconditions[].id` | State feeds that must be fresh while the skill holds a permit. the gate refuses at start a feed it does not observe (`safety_feed`, `evidence_claim`); `evidence_claim` on a row makes fresh evidence a condition of every v5 permit for that skill, target or not; `safety_feed` is the floor every permit already has |
| `complete.signal` | yes | `duration` / `robot_report` / `robot_report+evidence` | What consumes the step |
| `safe_state` | yes | a state the serving adapter declares in `ADAPTERS.tsv` | What the adapter executes when the permit is revoked. the adapter checks its declaration against what it can execute at start (Microduck `--safe-state`, refused otherwise); the ROS gate refuses at start a row naming a state outside `adapter_safe_state` |
| `slot` | no | `[a-z][a-z0-9_]{0,63}`, default `main` | Permit slot this skill occupies (concurrent skills) |
| `params_schema` | unsupported | reserved JSON Schema field | This release refuses a row that declares this field. It does not validate a supplied JSON Schema. Ordinary `params_json` shape/size checks and registered numeric envelope checks are separate. |

## Vocabularies

- `spec/GUARDRAILS.tsv` — guardrail names (`name kind unit compare classes standard desc
  since`). `kind` A = command-bounded, B = state-bounded (a feed); `compare` `le` / `ge` /
  `range` / `feed`. Names are borrowed from IEC 61800-5-2 and ISO 10218/3691-4/13482, not
  invented — borrowed for their meaning, not for their standing. A bound PAIL carries in a
  token is a limit on what was *authorized*; the certified function of the same name, and the
  machine's conformity to it, stay with the machine.
- `spec/SKILL_VOCAB.tsv` — `robot_class` and `action_class` words.
- `spec/ADAPTERS.tsv` — per adapter: `robot_class`, `measures`, `safe_state`.

## Checker

Run `python3 spec/tools/spec_skills_check.py` from the public repository root.
It compares this field table, the Go/C++ parsers and the shipped example, and exits
0 on success, 1 on mismatch, or 2 when prerequisites cannot be established.

The included example is `config/skills.diff_drive_amr.yaml` (TurtleBot3 primitives).
Microduck and Viam examples belong to their separate adapter distributions and are
not prerequisites for the public TB3 reference.
