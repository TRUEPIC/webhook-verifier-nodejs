# Security Analysis — Webhook Verifier for Node.js

This document is the entry point for security analysis of
`@truepic/webhook-verifier`. It is written for Claude (and other agentic
reviewers) to orient quickly before auditing a change, triaging a report, or
reasoning about the library's place in the Truepic trust chain.

This library is the **consumer (verification) side** of Truepic's webhook
authentication. It is the last line of defense a customer's server has to decide
whether an inbound `captures.processed` / `inspection` webhook genuinely came
from Truepic. A weakness here lets a forged webhook be accepted as authentic,
which is why the runtime is deliberately tiny and heavily commented.

## Companion documents

| Document                             | Use it when you need…                                                                                  |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| [`SKILLS.md`](SKILLS.md)             | Attacker profiles — concrete techniques, the files each one touches, and PASTA/STRIDE/EU threat tags.  |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | The trust boundary, the cross-repo signing↔verification contract, and the `T#` / STRIDE / `EU-#` keys. |
| [`AGENTS.md`](AGENTS.md)             | Build/test/release commands and the architectural "why" behind each verification step.                 |
| [`README.md`](README.md)             | The public API and framework integration examples (Express/Fastify raw-body handling).                 |

The threat tags used throughout `SKILLS.md` (for example
`[P:T1.2 \| S:S4 \| EU:5.1]`) are defined in
[`THREAT_MODEL.md` › Threat Model Reference](THREAT_MODEL.md#threat-model-reference).

## Code map

The entire runtime is two files. Audit them in pipeline order.

| Symbol                        | File                                          | Security role                                                                                      |
| ----------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `parseHeader`                 | [`src/main.js`](src/main.js) (lines ~19–68)   | Splits and strictly validates the `truepic-signature` header into `timestamp` + `signature`.       |
| `verifyTimestamp`             | [`src/main.js`](src/main.js) (lines ~82–93)   | Rejects stale/future requests outside `leewayMinutes` — replay-window protection.                  |
| `verifySignature`             | [`src/main.js`](src/main.js) (lines ~110–136) | Recomputes HMAC-SHA256 over `url,timestamp,body` and compares in constant time.                    |
| `verifyTruepicWebhook`        | [`src/main.js`](src/main.js) (lines ~151–174) | Public entry point; runs the three steps in order, throwing on the first failure.                  |
| `TruepicWebhookVerifierError` | [`src/error.js`](src/error.js)                | The only error type thrown; callers `instanceof`-check it. Messages are diagnostic, not secret.    |
| Type declarations             | [`src/main.d.ts`](src/main.d.ts)              | Must mirror the CommonJS public shape; drift is a (low-severity) correctness/security issue.       |
| Tests                         | [`src/main.test.js`](src/main.test.js)        | Encodes the security expectations (leeway boundaries, tamper rejection, length-mismatch handling). |

> Line numbers are approximate — confirm against the current file before citing
> them in a finding.

## Security invariants

These are the properties the library must preserve. A change that weakens any of
them is a security regression; each maps to one or more attacker profiles in
[`SKILLS.md`](SKILLS.md).

1. **Constant-time signature comparison.** The final compare must use
   `crypto.timingSafeEqual` over equal-length buffers — never `===`, `==`, or a
   short-circuiting string compare. See `WV-T` in `SKILLS.md`.
2. **Raw-body coverage.** The HMAC is computed over the _raw request body
   string_. Re-stringified/parsed JSON will not match. The verifier cannot
   enforce this on the caller; integration docs must. See `WV-I`.
3. **Strict header parsing.** `parseHeader` must reject empty parts, missing
   `t=`/`s=` prefixes, non-numeric timestamps, and extra comma-separated fields,
   and must split on the _first_ `=` only (base64 `=` padding is significant).
   See `WV-H`.
4. **Bounded replay window.** `verifyTimestamp` must reject timestamps outside
   `±leewayMinutes`. A large or caller-supplied unbounded leeway re-opens the
   replay window. See `WV-R`.
5. **Fail-closed.** Every verification failure throws
   `TruepicWebhookVerifierError`; the function only returns `true` on full
   success. No code path may return `true` (or swallow the throw) without all
   three checks passing. See `WV-S`, `WV-I`.
6. **No secret leakage.** Error messages, logs, and stack traces must never echo
   the shared `secret` or the computed comparison digest. See `WV-K`.

## How to use this during a review

1. Identify which pipeline step(s) the diff touches via the **Code map**.
2. Open the matching attacker profile(s) in [`SKILLS.md`](SKILLS.md) and walk
   the techniques against the change.
3. Confirm none of the **Security invariants** above are weakened.
4. For cross-repo questions ("does the producer still sign the same bytes?"),
   consult
   [`THREAT_MODEL.md` › Signing ↔ verification contract](THREAT_MODEL.md#signing--verification-contract).
   </content> </invoke>
