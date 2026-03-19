/**
 * Options for verifying a Truepic webhook.
 */
interface VerifyTruepicWebhookOptions {
  /** The full URL that received the request and is registered with Truepic. */
  url: string
  /** The shared secret that's registered with Truepic. */
  secret: string
  /** The value of the `truepic-signature` header from the request. */
  header: string
  /** The raw body (unparsed JSON) from the request. */
  body: string
  /** The number of minutes allowed between the request being sent and received. Defaults to `5`. */
  leewayMinutes?: number
}

/**
 * The custom error thrown when webhook verification fails.
 */
declare class TruepicWebhookVerifierError extends Error {
  constructor(message: string)
  name: 'TruepicWebhookVerifierError'
}

/**
 * Verify a webhook from Truepic Vision or Lens.
 */
declare function verifyTruepicWebhook(
  options: VerifyTruepicWebhookOptions,
): true

declare namespace verifyTruepicWebhook {
  export { TruepicWebhookVerifierError }
}

export = verifyTruepicWebhook
