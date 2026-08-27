// Compile-time tests for `main.d.ts`. These never run — `tsc` failing to
// compile this file IS the failure. They exist so the declarations can't drift
// from `main.js` unnoticed.
import verifyTruepicWebhook = require('./main')

function expectType<T>(_value: T): void {}

const url = 'http://localhost:3001/webhook'
const secret = 'secret'
const header = 't=1698259719,s=S9lwmAyba6aYa/Ts2jlJ6venPhSvlGjd0QdNsvi8iq8='
const body = '{"type":"captures.created"}'

// Resolves to exactly `true`, not a widened `boolean`.
expectType<true>(verifyTruepicWebhook({ url, secret, header, body }))

expectType<true>(
  verifyTruepicWebhook({ url, secret, header, body, leewayMinutes: 10 }),
)

// Every option but `leewayMinutes` is required. Each omission is tested
// separately so that any one of them turning optional fails the check.

// @ts-expect-error `url` is required.
verifyTruepicWebhook({ secret, header, body })

// @ts-expect-error `secret` is required.
verifyTruepicWebhook({ url, header, body })

// @ts-expect-error `header` is required.
verifyTruepicWebhook({ url, secret, body })

// @ts-expect-error `body` is required.
verifyTruepicWebhook({ url, secret, header })

// Every option is narrowly typed. These also catch a widening to `unknown` or
// `any`, which would otherwise swallow the wrong type silently.

// @ts-expect-error `url` is a string.
verifyTruepicWebhook({ url: 1, secret, header, body })

// @ts-expect-error `secret` is a string.
verifyTruepicWebhook({ url, secret: 1, header, body })

// @ts-expect-error `header` is a string.
verifyTruepicWebhook({ url, secret, header: 1, body })

// @ts-expect-error `body` is a string.
verifyTruepicWebhook({ url, secret, header, body: 1 })

// @ts-expect-error `leewayMinutes` is a number.
verifyTruepicWebhook({ url, secret, header, body, leewayMinutes: '5' })

// @ts-expect-error Unknown options are rejected.
verifyTruepicWebhook({ url, secret, header, body, nope: true })

try {
  verifyTruepicWebhook({ url, secret, header, body })
} catch (cause) {
  if (cause instanceof verifyTruepicWebhook.TruepicWebhookVerifierError) {
    expectType<'TruepicWebhookVerifierError'>(cause.name)
    expectType<string>(cause.message)
  }
}
