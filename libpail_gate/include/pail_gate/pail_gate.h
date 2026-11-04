/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Glowfly Identity Systems Co.,Ltd
 *
 * libpail_gate — the PAIL decision core behind a C ABI (see spec/ARCHITECTURE.md).
 *
 * One handle = one gate session for one robot: the same `decide()` the ROS gate node calls,
 * plus the permit/step/consumption state machine the node keeps between calls. No network,
 * no clock reads beyond wall time for judgment, no policy of its own: the caller (an adapter)
 * feeds the token service answer, the safety feed and the evidence feed, asks for a verdict
 * per command, ticks the recheck/step timers, and obeys the Outcome.
 *
 * Wire format: every `in`/`out` buffer is protobuf BINARY of the message named in the
 * comment (abi/pail_gate_abi.proto). Output buffers are malloc'd by the library and must be
 * released with pail_gate_free_buf(). Return codes: 0 ok, PAIL_GATE_EPARSE the input did not
 * parse, PAIL_GATE_EHANDLE null handle, PAIL_GATE_EINTERNAL anything else.
 *
 * Threading: a handle is NOT thread-safe. Serialise calls on it.
 */
#ifndef PAIL_GATE_H_
#define PAIL_GATE_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PAIL_GATE_ABI_VERSION 1u

#define PAIL_GATE_OK 0
#define PAIL_GATE_EPARSE (-1)
#define PAIL_GATE_EHANDLE (-2)
#define PAIL_GATE_EINTERNAL (-3)

typedef struct pail_gate pail_gate_t;

/* ABI version compiled into the library. A caller built against a different major refuses. */
uint32_t pail_gate_abi_version(void);

/* in: Config. Returns NULL on refusal; *err (malloc'd, free with pail_gate_free_buf) then names
 * the refusal in the gate node's preflight vocabulary (POLICY_ABSENT, POLICY_INCOMPLETE, …).
 * A keyring that fails to load is NOT a refusal — the session starts with an empty trust map
 * and every token is refused (fail-closed, as the node does); pail_gate_info() reports it. */
pail_gate_t *pail_gate_new(const uint8_t *in, size_t in_len, char **err);
void pail_gate_free(pail_gate_t *h);

/* in: TokenInput. The latest answer from the token service; call every permit_recheck_ms. */
int pail_gate_set_token(pail_gate_t *h, const uint8_t *in, size_t in_len);

/* in: SafetyInput → out: Outcome (state "ESTOP" when the feed triggered the latch). */
int pail_gate_observe_safety(pail_gate_t *h, const uint8_t *in, size_t in_len,
                             uint8_t **out, size_t *out_len);

/* in: EvidenceInput. */
int pail_gate_observe_evidence(pail_gate_t *h, const uint8_t *in, size_t in_len);

/* in: CommandInput → out: Outcome. `forward` is the whole answer for the adapter. */
int pail_gate_command(pail_gate_t *h, const uint8_t *in, size_t in_len,
                      uint8_t **out, size_t *out_len);

/* in: TickInput → out: TickOutcome (service the step timer, then recheck). Call every
 * permit_recheck_ms after pail_gate_set_token(). */
int pail_gate_tick(pail_gate_t *h, const uint8_t *in, size_t in_len,
                   uint8_t **out, size_t *out_len);

/* SK-3: in: CompleteInput → out: Outcome (path "complete"). Consumes the active step only
 * when the registry row's complete.signal is robot_report[+evidence]; otherwise nothing is
 * published and Outcome.detail says why. */
int pail_gate_complete_step(pail_gate_t *h, const uint8_t *in, size_t in_len,
                            uint8_t **out, size_t *out_len);

/* out: Info. */
int pail_gate_info(pail_gate_t *h, uint8_t **out, size_t *out_len);

void pail_gate_free_buf(void *p);

#ifdef __cplusplus
}
#endif

#endif /* PAIL_GATE_H_ */
