const assert = require('node:assert/strict')
const { describe, it } = require('node:test')
const verifyTruepicWebhook = require('./main')

const { TruepicWebhookVerifierError } = verifyTruepicWebhook

describe('verifyTruepicWebhook', () => {
  // Successful values.
  const url = 'http://localhost:3001/webhook'
  const secret = 'secret'
  const header = 't=1698259719,s=S9lwmAyba6aYa/Ts2jlJ6venPhSvlGjd0QdNsvi8iq8='
  const body =
    '{"type":"captures.created","data":{"id":"dd4b8e37-0e2e-47de-91d1-b3eb00aa9d36","type":"PHOTO","status":"WAITING","custom_data":null,"uploaded_by_ip_address":"::1","file_size":2878119,"file_hash":"fVEXbAR0bs0EqIYtJoCRUz067zCJWGp6yW+xwKMHPtw=","created_at":"2023-10-25T18:48:39.479Z","updated_at":"2023-10-25T18:48:39.479Z","processed_at":null,"url":"http://localhost:4566/lens-captures-development/dd4b8e37-0e2e-47de-91d1-b3eb00aa9d36.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=abc%2F20231025%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20231025T184839Z&X-Amz-Expires=36000&X-Amz-Signature=857b33be14592b1618093293d665a41c1043a5cb5c0fef31951a5390bcc8be03&X-Amz-SignedHeaders=host&x-id=GetObject"}}'
  // The `t` value (in milliseconds) baked into the fixture header above.
  const sentAtMs = 1698259719 * 1000
  // For tests that don't care about the timestamp window, opt out of leeway
  // entirely instead of mocking the clock.
  const leewayMinutes = 999999999

  it('returns `true` if verification is successful', (t) => {
    t.mock.timers.enable({ apis: ['Date'], now: sentAtMs })

    assert.strictEqual(
      verifyTruepicWebhook({
        url,
        secret,
        header,
        body,
      }),
      true,
    )
  })

  describe('timestamp leeway window', () => {
    it('accepts a webhook that arrives exactly 5 minutes late', (t) => {
      t.mock.timers.enable({
        apis: ['Date'],
        now: sentAtMs + 1000 * 60 * 5,
      })

      assert.strictEqual(
        verifyTruepicWebhook({
          url,
          secret,
          header,
          body,
          leewayMinutes: 5,
        }),
        true,
      )
    })

    it('accepts a webhook whose sender clock is exactly 5 minutes ahead', (t) => {
      t.mock.timers.enable({
        apis: ['Date'],
        now: sentAtMs - 1000 * 60 * 5,
      })

      assert.strictEqual(
        verifyTruepicWebhook({
          url,
          secret,
          header,
          body,
          leewayMinutes: 5,
        }),
        true,
      )
    })

    it('defaults to a 5 minute leeway if none is given', (t) => {
      t.mock.timers.enable({
        apis: ['Date'],
        now: sentAtMs + 1000 * 60 * 5,
      })

      assert.strictEqual(
        verifyTruepicWebhook({
          url,
          secret,
          header,
          body,
        }),
        true,
      )
    })

    it('accepts a webhook that arrives instantly with no leeway', (t) => {
      t.mock.timers.enable({ apis: ['Date'], now: sentAtMs })

      assert.strictEqual(
        verifyTruepicWebhook({
          url,
          secret,
          header,
          body,
          leewayMinutes: 0,
        }),
        true,
      )
    })
  })

  describe('throws a `TruepicWebhookVerifierError`', () => {
    it('that is an instance of the exported error class', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: '',
            body,
            leewayMinutes,
          }),
        (error) => {
          assert.ok(error instanceof TruepicWebhookVerifierError)
          assert.ok(error instanceof Error)

          return true
        },
      )
    })

    it('if the `header` is missing', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: null,
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Header is missing or empty'),
      )
    })

    it('if the `header` is empty', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: '',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Header is missing or empty'),
      )
    })

    it('if the `header` is not a string', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: ['t=1698259719,s=abc'],
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Header is missing or empty'),
      )
    })

    it('if the `header` cannot be parsed into timestamp and signature', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: 'bad',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError(
          'Header cannot be parsed into timestamp and signature',
        ),
      )
    })

    it('if the `header` has more than two comma-separated parts', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: 't=1698259719,s=abc,extra=stuff',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError(
          'Header cannot be parsed into timestamp and signature',
        ),
      )
    })

    it('if the `header` is missing the timestamp part entirely', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: ',s=test',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError(
          'Header cannot be parsed into timestamp and signature',
        ),
      )
    })

    it('if the `header` is missing the signature part entirely', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: 't=1698259719,',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError(
          'Header cannot be parsed into timestamp and signature',
        ),
      )
    })

    it('if the `header` is missing the timestamp (`t`)', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: 'b=bad,s=test',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Timestamp is missing or empty'),
      )
    })

    it('if the `header` timestamp (`t`) is empty', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: 't=,s=test',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Timestamp is missing or empty'),
      )
    })

    it('if the `header` timestamp part has no `=`', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: 't,s=test',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Timestamp is missing or empty'),
      )
    })

    it('if the `header` timestamp (`t`) is not a number', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: 't=bad,s=test',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Timestamp is not a number'),
      )
    })

    it('if the `header` is missing the signature (`s`)', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: 't=123,b=bad',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Signature is missing or empty'),
      )
    })

    it('if the `header` signature (`s`) is empty', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: 't=123,s=',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Signature is missing or empty'),
      )
    })

    it('if the `header` signature part has no `=`', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: 't=1698259719,s',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Signature is missing or empty'),
      )
    })

    it('if the webhook arrives more than 5 minutes late', (t) => {
      t.mock.timers.enable({
        apis: ['Date'],
        now: sentAtMs + 1000 * 60 * 5 + 1,
      })

      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header,
            body,
            leewayMinutes: 5,
          }),
        new TruepicWebhookVerifierError(
          'Timestamp is not within allowed window',
        ),
      )
    })

    it('if the sender clock is more than 5 minutes ahead', (t) => {
      t.mock.timers.enable({
        apis: ['Date'],
        now: sentAtMs - 1000 * 60 * 5 - 1,
      })

      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header,
            body,
            leewayMinutes: 5,
          }),
        new TruepicWebhookVerifierError(
          'Timestamp is not within allowed window',
        ),
      )
    })

    it('if the webhook arrives more than 5 minutes late and no leeway is given', (t) => {
      t.mock.timers.enable({
        apis: ['Date'],
        now: sentAtMs + 1000 * 60 * 5 + 1,
      })

      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header,
            body,
          }),
        new TruepicWebhookVerifierError(
          'Timestamp is not within allowed window',
        ),
      )
    })

    it('if the webhook is late at all and no leeway is allowed', (t) => {
      t.mock.timers.enable({ apis: ['Date'], now: sentAtMs + 1 })

      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header,
            body,
            leewayMinutes: 0,
          }),
        new TruepicWebhookVerifierError(
          'Timestamp is not within allowed window',
        ),
      )
    })

    it('if the `url` is not where the request was sent', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url: 'http://bad/webhook',
            secret,
            header,
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Signature is not valid'),
      )
    })

    it('if the `timestamp` is not what was signed', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: header.replace('t=1698259719', 't=1698259718'),
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Signature is not valid'),
      )
    })

    it('if the `body` is not what was signed', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header,
            body: '{"bad":"webhook"}',
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Signature is not valid'),
      )
    })

    it('if the `header` signature decodes to the wrong length', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret,
            header: 't=1698259719,s=Zm9v',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Signature is not valid'),
      )
    })

    it('if the `secret` is missing', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret: undefined,
            header,
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Secret is missing or empty'),
      )
    })

    it('if the `secret` is empty', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret: '',
            header,
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Secret is missing or empty'),
      )
    })

    it('if the `secret` is not a string', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret: 1698259719,
            header,
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Secret is missing or empty'),
      )
    })

    it('if the `secret` is not what was used to sign', () => {
      assert.throws(
        () =>
          verifyTruepicWebhook({
            url,
            secret: 'bad',
            header,
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Signature is not valid'),
      )
    })
  })
})
