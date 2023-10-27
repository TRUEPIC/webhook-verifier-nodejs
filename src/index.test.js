import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { verifyWebhook, TruepicWebhookVerifierError } from './index.js'

describe('verifyWebhook', () => {
  // Successful values.
  const url = 'http://localhost:3001/webhook'
  const secret = 'secret'
  const header = 't=1698259719,s=S9lwmAyba6aYa/Ts2jlJ6venPhSvlGjd0QdNsvi8iq8='
  const body =
    '{"type":"captures.created","data":{"id":"dd4b8e37-0e2e-47de-91d1-b3eb00aa9d36","type":"PHOTO","status":"WAITING","custom_data":null,"uploaded_by_ip_address":"::1","file_size":2878119,"file_hash":"fVEXbAR0bs0EqIYtJoCRUz067zCJWGp6yW+xwKMHPtw=","created_at":"2023-10-25T18:48:39.479Z","updated_at":"2023-10-25T18:48:39.479Z","processed_at":null,"url":"http://localhost:4566/lens-captures-development/dd4b8e37-0e2e-47de-91d1-b3eb00aa9d36.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=abc%2F20231025%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20231025T184839Z&X-Amz-Expires=36000&X-Amz-Signature=857b33be14592b1618093293d665a41c1043a5cb5c0fef31951a5390bcc8be03&X-Amz-SignedHeaders=host&x-id=GetObject"}}'
  const leewayMinutes = 999999999

  it('returns `true` if verification is successful', () => {
    assert.strictEqual(
      verifyWebhook({
        url,
        secret,
        header,
        body,
        leewayMinutes,
      }),
      true,
    )
  })

  describe('throws a `TruepicWebhookVerifierError`', () => {
    it('if the `header` is missing', () => {
      assert.throws(
        () =>
          verifyWebhook({
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
          verifyWebhook({
            url,
            secret,
            header: '',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Header is missing or empty'),
      )
    })

    it('if the `header` cannot be parsed into timestamp and signature', () => {
      assert.throws(
        () =>
          verifyWebhook({
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

    it('if the `header` is missing the timestamp (`t`)', () => {
      assert.throws(
        () =>
          verifyWebhook({
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
          verifyWebhook({
            url,
            secret,
            header: 't=,s=test',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Timestamp is missing or empty'),
      )
    })

    it('if the `header` timestamp (`t`) is not a number', () => {
      assert.throws(
        () =>
          verifyWebhook({
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
          verifyWebhook({
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
          verifyWebhook({
            url,
            secret,
            header: 't=123,s=',
            body,
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Signature is missing or empty'),
      )
    })

    it('if the timestamp is not within allowed window', () => {
      assert.throws(
        () =>
          verifyWebhook({
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

    it('if the `url` is not where the request was sent', () => {
      assert.throws(
        () =>
          verifyWebhook({
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
          verifyWebhook({
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
          verifyWebhook({
            url,
            secret,
            header,
            body: '{"bad":"webhook"}',
            leewayMinutes,
          }),
        new TruepicWebhookVerifierError('Signature is not valid'),
      )
    })

    it('if the `secret` is not what was used to sign', () => {
      assert.throws(
        () =>
          verifyWebhook({
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
