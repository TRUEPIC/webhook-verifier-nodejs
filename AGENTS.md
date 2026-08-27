# AGENTS.md

This file provides guidance to agentic agents like Claude Code when working with
code in this repository.

## Commands

- `npm test` — run the test suite (uses Node's built-in `node --test` runner;
  tests live next to source as `*.test.js`).
- `npm test -- --watch` — re-run tests on file change.
- `npm run test:coverage` — run the suite with coverage, printing a report and
  writing `coverage/lcov.info`. CI runs this in a separate job that posts the
  report to the run summary and uploads it as an artifact. There is no
  threshold: coverage is reported, not enforced.
- `node --test src/main.test.js` — run a single test file. Add
  `--test-name-pattern '<regex>'` to filter by test name.
- `npm run lint` — Prettier format check + ESLint. `npm run lint:format:fix` and
  `npm run lint:quality:fix` apply autofixes.
- `npm run docs` — generate JSDoc HTML to the (git-ignored) `docs/` directory.
- `npm run release` — from the `development` branch, Release It! orchestrates
  versioning/tagging. Confirm you are on `development` before running it; the
  command does not enforce the branch. After release, merge `development` →
  `main` (which always reflects the latest release).

CommonJS module (`"main": "./src/main.js"`, no build step). Node `>=22` is
required.

## Architecture

This is a small published library (`@truepic/webhook-verifier`) that verifies
Truepic Vision/Lens webhook requests. The whole runtime is `src/main.js` plus
`src/error.js`; there is no framework or transport — callers pass in the raw
request pieces.

The verification pipeline in `verifyTruepicWebhook` runs three steps in order,
each throwing `TruepicWebhookVerifierError` on failure:

1. `parseHeader` splits the `truepic-signature` header (format:
   `t=<unix-seconds>,s=<base64-hmac>`) into `timestamp` and `signature`. The
   parser is strict about the `t=`/`s=` prefixes and rejects empty parts.
2. `verifyTimestamp` rejects requests whose timestamp differs from `Date.now()`
   by more than `leewayMinutes` (default 5) — replay-attack protection.
   Comparison uses `Math.ceil` of the minute diff.
3. `verifySignature` recomputes the HMAC-SHA256 of
   `[url, timestamp, body].join(',')` keyed by the shared `secret`,
   base64-encodes it, and compares against the header signature using
   `crypto.timingSafeEqual` (constant-time). The `body` must be the **raw
   request body string** — re-stringified JSON will not match because
   whitespace/key-order differences change the digest. The README's
   Express/Fastify examples exist specifically to show how to preserve the raw
   body.

`TruepicWebhookVerifierError` is exported as a named property on the default
export so callers can `instanceof`-check it. The TypeScript declarations in
`src/main.d.ts` mirror this CommonJS shape (`export = verifyTruepicWebhook` with
a `declare namespace` for the error class) and must be kept in sync with
`main.js` when the public API changes.

This package is also positioned as a reference implementation for porting to
other languages — keep `main.js` heavily commented and explicit about _why_ each
step matters (raw body, constant-time compare, leeway window).
