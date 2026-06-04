# Threat Model — Webhook Verifier for Node.js

This document defines the trust boundary, the cross-repo signing↔verification
contract, and the threat-tag vocabulary (`T#`, STRIDE, `EU-#`) referenced by the
attacker profiles in [`SKILLS.md`](SKILLS.md). Start at
[`SECURITY_ANALYSIS.md`](SECURITY_ANALYSIS.md) for the code map and invariants.

This repo is standalone (it has no parent `SKILLS.md`), so the reference tables
below are the authoritative copy for `@truepic/webhook-verifier`. They are kept
deliberately aligned with the `T#` / STRIDE / `EU-#` codes used in `lens-api`
and `vision-api` so a finding can be traced across all three repositories.

## Trust boundary & data flow

`@truepic/webhook-verifier` runs **inside the customer's server**, at the very
front of their webhook route handler. Everything to the left of the verifier is
attacker-reachable; everything to the right should only execute once
`verifyTruepicWebhook` has returned `true`.

```
  Truepic (Lens / Vision)                Public network                 Customer server
 ┌────────────────────────┐           ┌────────────────┐         ┌──────────────────────────┐
 │ webhook_signer.js /     │  signed   │  HTTPS POST    │ inbound │  route handler           │
 │ team-webhook-signer.ts  ├──────────►│  truepic-      ├────────►│  verifyTruepicWebhook()  │
 │  HMAC-SHA256(secret,    │  request  │  signature hdr │         │   parseHeader →          │
 │   url,timestamp,body)   │           │  + raw body    │         │   verifyTimestamp →      │
 └────────────────────────┘           └───────┬────────┘         │   verifySignature        │
            ▲                                  │                  └────────────┬─────────────┘
            │ shared secret (out of band)      │ attacker can craft/replay     │ true ⇒ process
            └──────────────────────────────────┴───────────────────────────────┘ throw ⇒ reject
```

- **Trust anchor:** the shared `secret`, provisioned out of band and held by
  both Truepic and the customer. Its compromise is a total bypass (see `WV-K` in
  [`SKILLS.md`](SKILLS.md)).
- **Attacker position:** anyone who can send an HTTPS request to the customer's
  webhook URL. They fully control the header and body bytes and can replay
  previously observed (signed) requests.
- **What the verifier decides:** authenticity (sender is Truepic), integrity
  (body/url/timestamp unmodified), and recency (within the leeway window).
- **What it does _not_ decide:** see
  [Non-goals](#non-goals-callers-responsibility).

## Signing ↔ verification contract

The verifier is only correct if it recomputes the **exact bytes** the producer
signed. This invariant spans three repositories and must not drift:

| Side                 | Repo / file                                        | Operation                                                            |
| -------------------- | -------------------------------------------------- | -------------------------------------------------------------------- |
| Producer (Lens)      | `lens-api/src/services/webhooks/webhook_signer.js` | `HMAC_SHA256(secret).update([url, timestamp, body].join(','))` → b64 |
| Producer (Vision)    | `vision-api/src/services/team-webhook-signer.ts`   | Same construction; header `t=${timestamp},s=${signature}`            |
| Consumer (this repo) | `src/main.js` `verifySignature`                    | Recomputes the identical HMAC and compares with `timingSafeEqual`    |

Contract details that any change must preserve:

1. **Signed message:** `[url, timestamp, body].join(',')` — a comma-delimited
   concatenation, in that exact order.
2. **`body` is the raw request body string** as transmitted. JSON re-encoding
   changes whitespace/key order and breaks the digest (see `WV-I.1a`).
3. **`timestamp`** is Unix **seconds** in the header (`t=`); `verifyTimestamp`
   multiplies by 1000 to compare against `Date.now()` milliseconds.
4. **Encoding:** signature is base64 (`s=`), and may carry one or two `=`
   padding chars — hence the first-`=`-only split in `parseHeader` (`WV-H.1b`).
5. **Algorithm:** HMAC-SHA256. Changing the algorithm, delimiter, field order,
   or encoding on either side silently breaks verification for every customer.

> If you are reviewing a change to the producer signer in
> `lens-api`/`vision-api`, the corresponding consumer expectation lives in
> `src/main.js` and `src/main.test.js` here. Treat the two as a single change
> set even though they ship separately.

## Non-goals (caller's responsibility)

The library is intentionally narrow. These are explicitly **out of scope** and
must be handled by the integrating application — flag them as integration
guidance, not library bugs:

- **Replay deduplication.** The verifier enforces a time _window_ only; it keeps
  no state. Idempotency keys / dedup on `(id, timestamp)` are the caller's job
  (`WV-R.1`).
- **Secret provisioning, strength, rotation, and storage.** The library trusts
  whatever `secret` it is handed (`WV-K.1b`).
- **Raw-body preservation.** The framework must deliver the unparsed body; the
  README examples exist to show how (`WV-I.1a`).
- **Transport security (TLS), rate limiting, and DoS protection** on the webhook
  endpoint.
- **What happens after verification** — authorization, result persistence, and
  audit logging all live downstream.

## Threat Model Reference

The compact tags in [`SKILLS.md`](SKILLS.md) (e.g. `[P:T1.2 \| S:S4 \| EU:5.1]`)
decode against the tables below.

### PASTA threat categories (`T#`)

Aligned with the org-wide categories used across `lens-api` / `vision-api`; only
those relevant to webhook verification are reproduced here.

| Tag    | Category                           | Relevance to this repo                                                     |
| ------ | ---------------------------------- | -------------------------------------------------------------------------- |
| `T1.2` | Truepic-Signature reverse-eng.     | Forging/learning the HMAC or secret; defeats authenticity at the source.   |
| `T2`   | Cross-tenant / unauthorized accept | Reusing a signature across endpoints, or accepting an unauthenticated one. |
| `T3`   | Trust-anchor compromise            | The shared `secret` (and its provisioning) is the root of trust.           |
| `T6`   | Insider / integration abuse        | Verification disabled, errors swallowed, or secret mishandled by caller.   |
| `T8`   | Denial of service / replay         | Replay storms and large-leeway abuse against the recency check.            |
| `T9`   | Cryptographic / spec attacks       | Attacks on HMAC, base64 decoding, numeric parsing, or the compare itself.  |

### STRIDE codes

| Code      | Meaning                | Typical use here                                                  |
| --------- | ---------------------- | ----------------------------------------------------------------- |
| `S1`–`S4` | Spoofing               | `S4`: spoofing Truepic by forging a signature (primary concern).  |
| `T1`–`T5` | Tampering              | `T1`: tampering with body/url/timestamp; `T3`: replayed request.  |
| `R1`–`R2` | Repudiation            | Weak/ambiguous failure handling that obscures what was accepted.  |
| `I1`–`I2` | Information disclosure | `I1`: failure-mode oracle via messages; `I2`: secret/timing leak. |
| `D2`–`D3` | Denial of service      | Replay flooding; malformed-input handling cost.                   |
| `E1`–`E3` | Elevation of privilege | `E3`: a forged/replayed webhook gaining "verified" trust.         |

### Evil-User-Stories (`EU-#`)

Aligned with the cross-repo `EU-#` catalog; only the stories reachable through
this library are listed.

| EU    | Story                                                                                            |
| ----- | ------------------------------------------------------------------------------------------------ |
| `4.2` | An attacker forges or replays a webhook to flip a capture/inspection result (e.g. → passed).     |
| `4.3` | An insider disables or backdoors verification in the integration (swallowed errors, wrong body). |
| `4.6` | An attacker exfiltrates the shared secret from logs, errors, or source, enabling forgery.        |
| `5.1` | A public attacker forges a single authentic-looking webhook to inject false provenance.          |
| `5.2` | A public attacker runs a quiet replay campaign within the leeway window to corrupt results.      |
| `7.1` | A B2B/cross-tenant attacker reuses a signature against another registered endpoint.              |

## Cross-references

- Attacker techniques and the files they touch → [`SKILLS.md`](SKILLS.md)
- Code map, security invariants, review workflow →
  [`SECURITY_ANALYSIS.md`](SECURITY_ANALYSIS.md)
- Architecture and the "why" behind each step → [`AGENTS.md`](AGENTS.md)
- Public API and raw-body integration examples → [`README.md`](README.md)
  </content>
