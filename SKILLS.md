# Webhook Verifier (Node.js) — Attacker Profiles

This document defines attacker profiles scoped to `@truepic/webhook-verifier`,
the **consumer-side** library that verifies Truepic Vision/Lens webhook
requests. The whole runtime is [`src/main.js`](src/main.js) plus
[`src/error.js`](src/error.js); callers pass in the raw request pieces.

Start at [`SECURITY_ANALYSIS.md`](SECURITY_ANALYSIS.md) for the code map and
security invariants. Threat-model tags use the compact form
`[P:<PASTA> \| S:<STRIDE> \| EU:<story-id>]`; the full `T#`, STRIDE, and `EU-#`
tables live in
[`THREAT_MODEL.md` › Threat Model Reference](THREAT_MODEL.md#threat-model-reference).

The producer (signing) counterparts are
`lens-api/src/services/webhooks/webhook_signer.js` and
`vision-api/src/services/team-webhook-signer.ts`; the shared invariant they
encode is documented in
[`THREAT_MODEL.md` › Signing ↔ verification contract](THREAT_MODEL.md#signing--verification-contract).

---

## WV-S: Signature Forgery

Attackers attempting to get a forged or tampered payload accepted as authentic
without possessing the shared secret.

### WV-S.1 — Payload Tamperer (Intermediate)

| #       | Technique                                                                                     | Files to Check                                                | Threat Tags                          |
| ------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------ |
| WV-S.1a | Modify body (e.g. flip a fraud result to "passed") while keeping the original signature       | `src/main.js` `verifySignature` — HMAC recomputed over body   | `[P:T2,T6 \| S:S4,T1 \| EU:4.2,5.1]` |
| WV-S.1b | Swap the `url` to a different registered endpoint to reuse a signature cross-tenant           | `src/main.js` `verifySignature` — `url` is part of the HMAC   | `[P:T2 \| S:S4,T3 \| EU:4.2,7.1]`    |
| WV-S.1c | Submit a base64 signature that decodes to a different length than the digest to dodge compare | `src/main.js` `verifySignature` — length guard before compare | `[P:T1.2,T9 \| S:S4 \| EU:5.1]`      |

### WV-S.2 — Crypto Bypasser (Advanced)

| #       | Technique                                                                                | Files to Check                                                          | Threat Tags                      |
| ------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | -------------------------------- |
| WV-S.2a | Attempt a length-extension attack against the HMAC construction                          | `src/main.js` — HMAC-SHA256 (not raw SHA), so extension shouldn't apply | `[P:T9 \| S:S4,T1 \| EU:5.1]`    |
| WV-S.2b | Force the `secret`/`body`/`url` types so `createHmac().update()` hashes unexpected bytes | `src/main.js` `verifySignature` — string coercion of inputs             | `[P:T1.2,T9 \| S:S4 \| EU:5.1]`  |
| WV-S.2c | Exploit a path that returns `true` (or swallows the throw) before all three checks pass  | `src/main.js` `verifyTruepicWebhook` — fail-closed ordering             | `[P:T2,T6 \| S:S4,E3 \| EU:4.2]` |

### Key Files

- `src/main.js` (`verifySignature`, `verifyTruepicWebhook`)
- `src/error.js`

---

## WV-R: Replay & Timestamp Attacks

Attackers replaying a previously valid (signed) request, or manipulating the
timestamp window.

### WV-R.1 — Replayer (Intermediate)

| #       | Technique                                                                           | Files to Check                                                 | Threat Tags                      |
| ------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------- | -------------------------------- |
| WV-R.1a | Capture a valid webhook and re-deliver it within the leeway window                  | `src/main.js` `verifyTimestamp` — window only; no nonce/dedup  | `[P:T8,T2 \| S:T3,D2 \| EU:4.2]` |
| WV-R.1b | Caller passes a very large `leewayMinutes`, widening the replay window indefinitely | Caller integration + `verifyTruepicWebhook` default (`5`)      | `[P:T8,T6 \| S:T3 \| EU:4.2]`    |
| WV-R.1c | Replay across many endpoints relying on the library having no cross-request state   | `src/main.js` — stateless by design; dedup is the caller's job | `[P:T8 \| S:T3,D2 \| EU:5.2]`    |

### WV-R.2 — Clock Manipulator (Advanced)

| #       | Technique                                                                                 | Files to Check                                            | Threat Tags                   |
| ------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------- | ----------------------------- |
| WV-R.2a | Send a future-dated timestamp that still falls within `±leewayMinutes`                    | `src/main.js` `verifyTimestamp` — `Math.abs` of diff      | `[P:T8 \| S:T3 \| EU:4.2]`    |
| WV-R.2b | Exploit `Math.ceil` minute rounding to gain up to ~60s beyond the intended window         | `src/main.js` `verifyTimestamp` — `Math.ceil(diff/60000)` | `[P:T8 \| S:T3 \| EU:4.2]`    |
| WV-R.2c | Pass a fractional/huge numeric timestamp that survives `Number()` but skews the diff math | `src/main.js` `parseHeader` → `verifyTimestamp`           | `[P:T8,T9 \| S:T3 \| EU:5.1]` |

### Key Files

- `src/main.js` (`verifyTimestamp`, `verifyTruepicWebhook`)

---

## WV-H: Header Parsing Attacks

Attackers crafting malformed `truepic-signature` headers to bypass or confuse
the parser.

### WV-H.1 — Malformed Header Crafter (Intermediate)

| #       | Technique                                                                                   | Files to Check                                           | Threat Tags                     |
| ------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------- |
| WV-H.1a | Inject extra comma-separated fields (`t=..,s=..,x=..`) hoping a lenient parser ignores them | `src/main.js` `parseHeader` — requires exactly two parts | `[P:T1.2 \| S:S4,T1 \| EU:5.1]` |
| WV-H.1b | Truncate base64 `=` padding by splitting the signature on every `=` instead of the first    | `src/main.js` `parseHeader` — `indexOf('=')` split       | `[P:T1.2 \| S:S4 \| EU:5.1]`    |
| WV-H.1c | Supply a non-numeric or `NaN`-inducing timestamp (`t=Infinity`, `t=0x10`, `t=`)             | `src/main.js` `parseHeader` — `Number()` + `isNaN` guard | `[P:T1.2,T9 \| S:T1 \| EU:5.1]` |

### WV-H.2 — Type Confusion (Advanced)

| #       | Technique                                                                           | Files to Check                                        | Threat Tags                   |
| ------- | ----------------------------------------------------------------------------------- | ----------------------------------------------------- | ----------------------------- |
| WV-H.2a | Pass a non-string `header` (array/object) to exploit `.length`/`.split` behavior    | `src/main.js` `parseHeader` — `header?.length` guard  | `[P:T9 \| S:T1,D2 \| EU:5.1]` |
| WV-H.2b | Use whitespace/Unicode around `t`/`s` keys hoping prefix checks normalize them away | `src/main.js` `parseHeader` — strict `t`/`s` equality | `[P:T1.2 \| S:S4 \| EU:5.1]`  |

### Key Files

- `src/main.js` (`parseHeader`)
- `src/main.test.js` (encodes the rejection cases above)

---

## WV-T: Timing & Side-Channel Attacks

Attackers using timing or error signals to learn the secret or the correct
signature byte-by-byte.

### WV-T.1 — Timing Oracle (Advanced)

| #       | Technique                                                                             | Files to Check                                               | Threat Tags                     |
| ------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------- |
| WV-T.1a | Measure response timing to brute-force the signature if compare short-circuits        | `src/main.js` `verifySignature` — `timingSafeEqual` required | `[P:T1.2,T9 \| S:I2 \| EU:5.1]` |
| WV-T.1b | Distinguish failure modes via different error _messages_ to map which check failed    | `src/main.js` + `src/error.js` — granular messages           | `[P:T1.2 \| S:I1 \| EU:5.1]`    |
| WV-T.1c | Use the length-mismatch branch (skips `timingSafeEqual`) as a fast-path timing signal | `src/main.js` `verifySignature` — length guard short-circuit | `[P:T9 \| S:I2 \| EU:5.1]`      |

### Key Files

- `src/main.js` (`verifySignature`)
- `src/error.js`

---

## WV-I: Integration Misuse

Failure modes introduced by the _caller_ that defeat verification even though
the library is correct. These are the highest-frequency real-world issues.

### WV-I.1 — Raw-Body Mishandler (Intermediate)

| #       | Technique / mistake                                                                                               | Files to Check                                              | Threat Tags                          |
| ------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------ |
| WV-I.1a | Caller passes re-stringified/parsed JSON as `body`, breaking the digest (often "fixed" by disabling verification) | `README.md` Express/Fastify examples — raw body preserved   | `[P:T6 \| S:T1 \| EU:4.3]`           |
| WV-I.1b | Caller swallows `TruepicWebhookVerifierError` and processes the webhook anyway                                    | `README.md` — catch block returns 200 _without_ processing  | `[P:T2,T6 \| S:S4,E3 \| EU:4.2,4.3]` |
| WV-I.1c | Caller hardcodes/ships the `secret` in client-reachable code or logs it                                           | Integration code (out of repo); `THREAT_MODEL.md` non-goals | `[P:T1.2,T6 \| S:I2 \| EU:4.6]`      |

### Key Files

- `README.md` (the integration examples are the security guidance)
- `src/main.js` (`verifyTruepicWebhook` — fail-closed contract)

---

## WV-K: Secret Management

Attackers targeting the shared `secret`, the single root of trust for the whole
scheme.

### WV-K.1 — Secret Hunter (Advanced)

| #       | Technique                                                                     | Files to Check                                          | Threat Tags                         |
| ------- | ----------------------------------------------------------------------------- | ------------------------------------------------------- | ----------------------------------- |
| WV-K.1a | Extract the shared secret from logs, error output, or stack traces            | `src/error.js`, `src/main.js` — must not echo `secret`  | `[P:T1.2,T6 \| S:I2 \| EU:4.6]`     |
| WV-K.1b | Exploit a weak/short secret to brute-force the HMAC offline                   | Out of repo (provisioning); `THREAT_MODEL.md` non-goals | `[P:T1.2,T3 \| S:S4 \| EU:5.1]`     |
| WV-K.1c | Once the secret is known, forge arbitrary webhooks (verification cannot help) | `THREAT_MODEL.md` — secret compromise = total bypass    | `[P:T1.2,T3 \| S:S4 \| EU:4.2,5.1]` |

### Key Files

- `src/error.js`
- `src/main.js`

---

## PASTA Risk Priority for this repo

`@truepic/webhook-verifier` is the customer's trust anchor for inbound Truepic
webhooks. Highest-priority threats first.

- **P0 — T1.2 Signature/secret compromise.** If the constant-time compare,
  raw-body coverage, or strict parsing weakens, forgery becomes possible without
  the secret. Covered by `WV-S`, `WV-H`, `WV-T`.
- **P0 — Fail-open integration.** The most likely real-world break: callers that
  swallow the error or feed the wrong body. Covered by `WV-I`.
- **P1 — T8 replay.** The library only enforces a time window; downstream
  idempotency/dedup is the caller's responsibility. Covered by `WV-R`.
- **P1 — T1.2 timing leakage.** Constant-time compare and uniform-ish failure
  handling. Covered by `WV-T`.
- **P2 — T3/T6 secret management.** Provisioning, rotation, and not leaking the
  secret. Mostly out of repo. Covered by `WV-K`.

## Evil-User-Story → Code Path

See [`THREAT_MODEL.md`](THREAT_MODEL.md#evil-user-stories-eu) for the full
`EU-#` descriptions.

| EU       | Story                                  | Files in this repo                                            |
| -------- | -------------------------------------- | ------------------------------------------------------------- |
| 4.2      | Forge/replay a webhook to flip results | `src/main.js` (`verifySignature`, `verifyTimestamp`)          |
| 4.3      | Integration backdoor / verify disabled | `README.md` examples, `src/main.js` fail-closed contract      |
| 4.6      | Secret exfiltration                    | `src/error.js`, `src/main.js` (no secret in output)           |
| 5.1, 5.2 | Public forgery / quiet replay campaign | `src/main.js` (all three steps), `src/main.test.js` coverage  |
| 7.1      | Cross-tenant signature reuse           | `src/main.js` `verifySignature` (`url` bound into the digest) |

</content>
