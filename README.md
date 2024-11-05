<h1 align="center" width="100%">
  Truepic Webhook Verifier for Node.js
</h1>

<h3 align="center" width="100%">
  <i>Verify webhooks from Truepic Vision or Lens in your Node.js app</i>
</h3>

<h3 align="center" width="100%">
  <a href="https://www.npmjs.com/package/@truepic/webhook-verifier">
    <img src="https://img.shields.io/npm/v/@truepic/webhook-verifier?color=196dff" alt="npm">
  </a>
  <a href="https://github.com/TRUEPIC/webhook-verifier-nodejs/actions">
    <img src="https://github.com/TRUEPIC/webhook-verifier-nodejs/actions/workflows/ci.yml/badge.svg" alt="GitHub Actions">
  </a>
</h3>

This module verifies

- the integrity of the data being received,
- the authenticity of the sender (Truepic),
- the authenticity of the receiver (you), and
- the time between the request being sent and received to prevent replay
  attacks.

If you're not using Node.js, this also serves as a reference implementation with
thorough documentation to make the translation into another language as painless
as possible.

## Installation

```bash
npm install @truepic/webhook-verifier
```

## Usage

The `@truepic/webhook-verifier` module exports a default function that should be
imported to begin:

```js
import verifyTruepicWebhook from '@truepic/webhook-verifier'
```

CommonJS is also supported:

```js
const verifyTruepicWebhook = require('@truepic/webhook-verifier')
```

This `verifyTruepicWebhook` function (or whatever you imported it as) is then
called with the following arguments:

```js
verifyTruepicWebhook({
  url: 'The full URL that received the request and is registered with Truepic.',
  secret: "The shared secret that's registered with Truepic.",
  header: 'The value of the `truepic-signature` header from the request.',
  body: 'The raw body (unparsed JSON) from the request.',
  leewayMinutes:
    'The number of minutes allowed between the request being sent and received. Defaults to `5`.',
})
```

A boolean `true` is returned if the webhook is verified in all of the ways
described above. Otherwise, if anything fails to check out, a
`TruepicWebhookVerifierError` is thrown with a message describing why (as much
as possible).

You should place this function call at the beginning of your webhook route
handler. Exactly how this is done depends on the web framework that you're
using. Below are a few examples for popular web frameworks that should be easy
to adapt if you're using a different one.

### Example: Express.js

```js
import verifyTruepicWebhook from '@truepic/webhook-verifier'
import express from 'express'
import { env } from 'node:process'

const app = express()

app.post(
  '/truepic/webhook',
  // This is important! We need the raw request body for `verifyTruepicWebhook`.
  express.raw({
    type: 'application/json',
  }),
  (req, res, next) => {
    try {
      verifyTruepicWebhook({
        url: env.TRUEPIC_WEBHOOK_URL,
        secret: env.TRUEPIC_WEBHOOK_SECRET,
        header: req.header('truepic-signature'),
        body: req.body.toString(),
      })
    } catch (error) {
      // The request cannot be verified. We're simply logging a warning here,
      // but you can handle however makes sense.
      console.warn(error)

      // Return OK so a (potential) bad actor doesn't gain any insight.
      return res.sendStatus(200)
    }

    // Process the webhook now that it's verified...

    res.sendStatus(200)
  },
)

// The rest of your app...
```

### Example: Fastify

```bash
npm install fastify-raw-body
```

```js
import verifyTruepicWebhook from '@truepic/webhook-verifier'
import Fastify from 'fastify'
import { env } from 'node:process'

const app = Fastify({
  logger: true,
})

// This is important! We need the raw request body for `verifyTruepicWebhook`.
await app.register(import('fastify-raw-body'))

app.post('/truepic/webhook', async (request) => {
  try {
    verifyTruepicWebhook({
      url: env.TRUEPIC_WEBHOOK_URL,
      secret: env.TRUEPIC_WEBHOOK_SECRET,
      header: request.headers['truepic-signature'],
      body: request.rawBody,
    })
  } catch (error) {
    // The request cannot be verified. We're simply logging a warning here,
    // but you can handle however makes sense.
    request.log.warn(error)

    // Return OK so a (potential) bad actor doesn't gain any insight.
    return {}
  }

  // Process the webhook now that it's verified...

  return {}
})

// The rest of your app...
```

## Development

### Prerequisites

The only prerequisite is a compatible version of Node.js (see `engines.node` in
[`package.json`](package.json)).

### Dependencies

Install dependencies with npm:

```bash
npm install
```

### Tests

The built-in Node.js [test runner](https://nodejs.org/docs/latest/api/test.html)
and [assertions module](https://nodejs.org/docs/latest/api/assert.html) is used
for testing.

To run the tests:

```bash
npm test
```

During development, it's recommended to run the tests automatically on file
change:

```bash
npm test -- --watch
```

### Docs

[JSDoc](https://jsdoc.app/) is used to document the code.

To generate the docs as HTML to the (git-ignored) `docs` directory:

```bash
npm run docs
```

### Code Style & Linting

[Prettier](https://prettier.io/) is setup to enforce a consistent code style.
It's highly recommended to
[add an integration to your editor](https://prettier.io/docs/en/editors.html)
that automatically formats on save.

[ESLint](https://eslint.org/) is setup with the
["recommended" rules](https://eslint.org/docs/latest/rules/) to enforce a level
of code quality. It's also highly recommended to
[add an integration to your editor](https://eslint.org/docs/latest/use/integrations#editors)
that automatically formats on save.

To run via the command line:

```bash
npm run lint
```

### Releasing

When the `development` branch is ready for release,
[Release It!](https://github.com/release-it/release-it) is used to orchestrate
the release process:

```bash
npm run release
```

Once the release process is complete, merge the `development` branch into the
`main` branch, which should always reflect the latest release.
