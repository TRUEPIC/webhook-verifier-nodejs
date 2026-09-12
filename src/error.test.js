const assert = require('node:assert/strict')
const { describe, it } = require('node:test')
const TruepicWebhookVerifierError = require('./error')
const verifyTruepicWebhook = require('./main')

describe('TruepicWebhookVerifierError', () => {
  const message = 'Signature is not valid'

  it('sets the `message`', () => {
    assert.strictEqual(
      new TruepicWebhookVerifierError(message).message,
      message,
    )
  })

  it('sets the `name` to the class name', () => {
    assert.strictEqual(
      new TruepicWebhookVerifierError(message).name,
      'TruepicWebhookVerifierError',
    )
  })

  it('is an instance of `Error`', () => {
    assert.ok(new TruepicWebhookVerifierError(message) instanceof Error)
  })

  it('captures a stack trace pointing at the caller', () => {
    const error = new TruepicWebhookVerifierError(message)

    assert.ok(error.stack.startsWith(`TruepicWebhookVerifierError: ${message}`))
    assert.match(error.stack, /error\.test\.js/)
  })

  it('is exported from the main module', () => {
    assert.strictEqual(
      verifyTruepicWebhook.TruepicWebhookVerifierError,
      TruepicWebhookVerifierError,
    )
  })
})
