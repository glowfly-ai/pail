# Dev key fingerprint list (`known_dev_keys.tsv`)

The PAIL repository has development/test key material committed in it. The
startup gate `S8` is what prevents shipping that material to a live site
as-is, and this document defines the format of the list that gate reads.

> 한국어판: [`KNOWN_DEV_KEYS.ko.md`](KNOWN_DEV_KEYS.ko.md). The English
> document is canonical; if the two diverge, the English text governs.

## 1. The question this list answers

What `S8` asks is **not "is this key in the repository now" but "has this key
ever been used for development".** Those are different questions with
different answers.

Deleting a private key from the repository does not recall the copies already
deployed. The list is therefore **monotone** — a fingerprint that has entered
never leaves (§4). The proposition "we deleted it from the tree, so it is now
safe" is not true, and the list must not make it appear true.

The list carries only **fingerprints of public keys.** Not private keys, and
not public keys themselves.

## 2. File syntax

<!-- syntax: robot/pail_deploy_guard/known_dev_keys.tsv cols=3 fingerprint=^[0-9a-f]{64}$ kind=ed25519,spki -->

- One entry per line, columns separated by **TAB**. Exactly three columns.
- Lines starting with `#` and blank lines are not entries.
- The first column is **64 lowercase hex characters**. Uppercase, whitespace,
  or abbreviation is an error, not an entry.
- The second column is the fingerprint namespace (§3): `ed25519` or `spki`.
- The third column is a label. It is a human-readable value and plays no part
  in the verdict. When the same key appears in multiple files, the labels are
  joined with ` | `.

The file preamble states the columns verbatim (the shipped file's comments
are in Korean; the column list is on its last line):

<!-- pin: robot/pail_deploy_guard/known_dev_keys.tsv -->
```
# S8 공용 지문 목록 (PAIL-SD2-LLD-v1 §2). scripts/gen_known_dev_keys.py 가 생성한다.
# 손으로 고치지 말 것 — Go/C++ 상수와 이 파일을 대조하는 드리프트 테스트가 깨진다.
#
# 여기 적힌 것은 공개키의 지문이다. 개인키를 저장소에서 지워도(AS-16) 이미 배포된
# 사본이 남으므로 목록은 그대로 유지한다. 키를 옮기거나 이름을 바꿔도 지문은 같다.
#
# 열: fingerprint(sha256 hex)  kind(ed25519|spki)  label
```

This file is not edited by hand; `spec/tools/gen_known_dev_keys.py` generates
it. What the gate actually reads is not this file but a **compiled constant**
(§7); the TSV is the source of that constant. A check that depends on a file
disappears when the file is deleted.

## 3. Fingerprint namespaces

The same key is carried differently depending on file format. The
fingerprint must attach to **the key itself**, not to the shape it is carried
in, so that moving the file or reissuing a certificate yields the same value.

<!-- pin: spec/tools/gen_known_dev_keys.py -->
```
지문 정의:
  ed25519  sha256(32바이트 공개키) hex
  spki     sha256(SubjectPublicKeyInfo DER) hex   — 인증서를 재발급해도 키를
           바꾸지 않으면 같은 값이므로, 인증서 파일 해시보다 키에 붙는다.
```

(In English: `ed25519` = sha256 of the 32-byte public key, hex; `spki` =
sha256 of the SubjectPublicKeyInfo DER, hex — reissuing a certificate without
changing the key yields the same value, so the fingerprint attaches to the
key rather than to a certificate file hash.)

`ed25519` attaches to the **raw 32 bytes** obtained by base64-decoding the
`ed25519_public_key_base64` of a keyring or key file. It does not attach to
the base64 string or to the JSON bytes — measuring the same key with two
different rulers yields two values, and then the list counts the same key
twice while still missing it once.

`spki` attaches to the **SubjectPublicKeyInfo DER** extracted from a
certificate. It is not a hash of the certificate file. A certificate
reissued at renewal, with the key unchanged, is the same key — and the gate
must keep recognizing the same key.

There are no namespaces beyond these two. Adding a new one requires changing
the generator's parser and this document together, and check `K4` prevents
the two from diverging.

## 4. Monotonicity

The list **does not lose** fingerprints. The generator's `--scan` does not
delete the row of a key that has disappeared from the repository; it appends
history to the label and keeps the row:

```
[저장소에서 제거됨 — 배포 사본 유효]
```

(The Korean label reads: "removed from the repository — deployed copies
remain valid.")

What catches a loss is not a human but `--check-monotone <baseline TSV>`. If
even one fingerprint is missing relative to the baseline, rc=1, and its
meaning is: **"an already-deployed dev key now exists that `S8` can no longer
refuse."**

There is exactly one legitimate way to shrink the list — rotate the key,
declare the revocation, and keep that declaration as the evidence (§6).
Deleting a row is not rotation.

## 5. What is scanned

The generator scans **only files tracked by git.** The list must be a
function of what is committed, not of working-tree state — a key a developer
created locally is not committed, so there are no deployed copies of it, and
no reason for it to enter the list.

The SROS2 enclave's `key.pem` is **out of scope.** DDS identity is loaded by
the middleware, so its checkpoint is elsewhere; counting it here would merge
two checks into one.

If there is not a single place to scan in this tree, the generator does not
write out zero entries — it **stops.** Zero entries has the same bytes as
"there are no dev keys", when in reality nothing was scanned. In the public
snapshot only `--check` and `--check-monotone` run.

## 6. Residual allow list (`known_dev_keys.allow`)

The place to record keys that unavoidably remain until rotation completes.
The columns are:

<!-- pin: robot/pail_deploy_guard/known_dev_keys.allow -->
```
# 열: fingerprint(sha256 hex 64자)  사유  폐기 선언 링크
# 지문 이름공간 = `sha256(파생된 32바이트 공개키)` — `known_dev_keys.tsv` 와 같다.
```

(The columns read: fingerprint — 64 hex chars of sha256; reason; link to the
revocation declaration. The fingerprint namespace equals that of
`known_dev_keys.tsv`.)

**An entry is one fingerprint line. Directories, globs, and file paths cannot
be entries.** A path-level exception exempts *keys that later arrive at that
path* along with it — an exception written today reaches keys someone drops
into that directory tomorrow. A fingerprint-level entry cannot do that.

All three columns must be present. An allowance without a reason cannot be
removed by the next person, and one without a revocation-declaration link
cannot answer "why is this key still alive."

What enforces this rule is not the letters in the file but the **parser.**
The fact that no path is written in the file does not mean the parser rejects
paths.

**Today the entry count is zero. That is the target state.**

## 7. What this list blocks, and what it does not

Exactly one startup gate consumes the list:

<!-- pin: TRUST_BOUNDARY.md -->
```
| `S8` | a known dev key or an unsigned trust anchor is in use | implemented |
```

When `S8` trips, the process **refuses to start.** It does not stay up and
merely log a warning.

The `.allow` file does not by itself enforce runtime revocation. Do not treat
an entry in that file as proof that deployed processes reject the key.

The shipped startup table separately describes protection of private key files:

<!-- pin: TRUST_BOUNDARY.md -->
```
| `S19` | private key material this process opens is readable by an account other than its owner (not `0600`) | implemented |
```

File permissions and known-key rejection are different controls. Neither a
format declaration nor a test fixture is an additional deployed protection.
The startup table in `TRUST_BOUNDARY.md` is the reference for the shipped source.

## 8. How this document is maintained

| Check | What it enforces |
| --- | --- |
| `K1` | Every quoted block with a `pin` is a **byte substring** of that file |
| `K2` | Every path a `pin` points at **ships in the public tree** — a quote that cannot be compared is a claim |
| `K3` | Every row of the shipped fingerprint list matches the syntax declared in §2 |
| `K4` | The vocabulary of §3 == the generator parser's vocabulary == the vocabulary actually appearing in the list |

`K4` measures all three values because measuring only two lets any pair be
wrong together. Measure only the document and the list, and the two can
agree on a vocabulary the parser does not know; measure only the document
and the parser, and the list goes quietly stale.

If the checker cannot read the document, or finds zero quotes, or the list
has zero rows, or the vocabulary cannot be read from the generator, it stops
with rc=2 — it does not sink to "FAIL 0". **Not having checked and having
checked with no findings are different values.**

To run:

```
python3 spec/tools/spec_keys_check.py
```
