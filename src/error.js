/**
 * The custom error thrown when verification fails.
 *
 * @memberof module:@truepic/webhook-verifier
 * @extends Error
 */
class TruepicWebhookVerifierError extends Error {
  /**
   * Create an error for a failed verification.
   *
   * @param {string} message The description of what failed.
   */
  constructor(message) {
    super(message)

    Error.captureStackTrace(this, this.constructor)

    this.name = this.constructor.name
  }
}

export default TruepicWebhookVerifierError
