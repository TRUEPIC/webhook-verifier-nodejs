const { createHmac, timingSafeEqual } = require('node:crypto')
const TruepicWebhookVerifierError = require('./error')

/**
 * Parse the `truepic-signature` header into timestamp and signature values.
 *
 * The header value looks like this:
 *
 *     t=1634066973,s=6FBEiVZ8EO79dk5XllfnG18b83ZvLt2kdxcE8FJ/BwU
 *
 * The `t` value is the timestamp of when the request was sent (in seconds), and
 * the `s` value is the signature of the request.
 *
 * @private
 * @param {string} header The value of the `truepic-signature` header from the request.
 * @throws {TruepicWebhookVerifierError} If parsing fails.
 * @returns {Object} The parsed `timestamp` and `signature` values.
 */
function parseHeader(header) {
  if (typeof header !== 'string' || !header.length) {
    throw new TruepicWebhookVerifierError('Header is missing or empty')
  }

  // Split the header value on the comma (`,`). This must leave exactly two
  // non-empty parts:
  //     - t=1634066973
  //     - s=6FBEiVZ8EO79dk5XllfnG18b83ZvLt2kdxcE8FJ/BwU
  const parts = header.split(',')

  if (parts.length !== 2 || !parts[0].length || !parts[1].length) {
    throw new TruepicWebhookVerifierError(
      'Header cannot be parsed into timestamp and signature',
    )
  }

  const [timestampPart, signaturePart] = parts

  // Split the timestamp (`t`) on the first equals (`=`). Splitting on every `=`
  // would risk dropping characters from the value if it ever contained one
  // (the timestamp itself never does, but the signature can — see below).
  const tEq = timestampPart.indexOf('=')
  const t = tEq === -1 ? timestampPart : timestampPart.slice(0, tEq)
  const rawTimestamp = tEq === -1 ? '' : timestampPart.slice(tEq + 1)

  if (t !== 't' || !rawTimestamp.length) {
    throw new TruepicWebhookVerifierError('Timestamp is missing or empty')
  }

  // Cast and verify that the timestamp value is a number.
  const timestamp = Number(rawTimestamp)

  if (isNaN(timestamp)) {
    throw new TruepicWebhookVerifierError('Timestamp is not a number')
  }

  // Split the signature (`s`) on the first equals (`=`). The signature value is
  // base64 and can end in one or two `=` padding characters, which would
  // otherwise be silently dropped.
  const sEq = signaturePart.indexOf('=')
  const s = sEq === -1 ? signaturePart : signaturePart.slice(0, sEq)
  const signature = sEq === -1 ? '' : signaturePart.slice(sEq + 1)

  if (s !== 's' || !signature.length) {
    throw new TruepicWebhookVerifierError('Signature is missing or empty')
  }

  return { timestamp, signature }
}

/**
 * Verify the timestamp to ensure the request is recent and not a potentially
 * delayed replay attack. Some leeway is required in case the clocks on either
 * end of the request aren't quite in sync.
 *
 * @private
 * @param {Object} options
 * @param {number} options.timestamp The timestamp parsed from the `truepic-signature` request header.
 * @param {number} options.leewayMinutes The number of minutes allowed between the request being sent and received.
 * @throws {TruepicWebhookVerifierError} If verification fails.
 * @returns {true} If verification succeeds.
 */
function verifyTimestamp({ timestamp, leewayMinutes }) {
  const diff = Math.abs(Date.now() - timestamp * 1000)
  const diffMinutes = Math.ceil(diff / (1000 * 60))

  if (diffMinutes > leewayMinutes) {
    throw new TruepicWebhookVerifierError(
      'Timestamp is not within allowed window',
    )
  }

  return true
}

/**
 * Verify the signature to ensure the integrity of the data being received, the
 * authenticity of the sender (Truepic), and the authenticity of the receiver
 * (you).
 *
 * @private
 * @param {Object} options
 * @param {string} options.url The full URL that received the request and is registered with Truepic.
 * @param {string} options.secret The shared secret that's registered with Truepic.
 * @param {string} options.body The raw body (unparsed JSON) from the request.
 * @param {number} options.timestamp The timestamp parsed from the `truepic-signature` request header.
 * @param {string} options.signature The signature parsed from the `truepic-signature` request header.
 * @throws {TruepicWebhookVerifierError} If verification fails.
 * @returns {true} If verification succeeds.
 */
function verifySignature({ url, secret, body, timestamp, signature }) {
  // Guard the secret before handing it to `createHmac`, which would otherwise
  // throw a raw `TypeError` and break the documented contract that every
  // failure is a `TruepicWebhookVerifierError`.
  if (typeof secret !== 'string' || !secret.length) {
    throw new TruepicWebhookVerifierError('Secret is missing or empty')
  }

  // Rebuild the signature (SHA-256 HMAC digest) with a secret that only Truepic
  // and the intended receiver are privy to.
  const comparisonSignature = createHmac('sha256', secret)

  // Concatenate the full URL that received the request, timestamp parsed from
  // the header, and raw body (unparsed JSON) from the request using a comma
  // (`,`). It's important to use the raw body before it's parsed as JSON, as
  // different languages/frameworks can parse/stringify JSON in subtly different
  // ways, which can result in a different signature.
  comparisonSignature.update([url, timestamp, body].join(','))

  const comparisonBuffer = comparisonSignature.digest()
  const signatureBuffer = Buffer.from(signature, 'base64')

  // Compare with a constant-time algorithm to prevent a timing attack. It
  // requires equal-length buffers, otherwise it throws an error.
  const isEqual =
    comparisonBuffer.length === signatureBuffer.length &&
    timingSafeEqual(comparisonBuffer, signatureBuffer)

  if (!isEqual) {
    throw new TruepicWebhookVerifierError('Signature is not valid')
  }

  return true
}

/**
 * Verify a webhook from Truepic Vision or Lens.
 *
 * @memberof module:@truepic/webhook-verifier
 * @param {Object} options
 * @param {string} options.url The full URL that received the request and is registered with Truepic.
 * @param {string} options.secret The shared secret that's registered with Truepic.
 * @param {string} options.header The value of the `truepic-signature` header from the request.
 * @param {string} options.body The raw body (unparsed JSON) from the request.
 * @param {number} [options.leewayMinutes=5] The number of minutes allowed between the request being sent and received.
 * @throws {TruepicWebhookVerifierError} If verification fails.
 * @returns {true} If verification succeeds.
 */
function verifyTruepicWebhook({
  url,
  secret,
  header,
  body,
  leewayMinutes = 5,
}) {
  const { timestamp, signature } = parseHeader(header)

  verifyTimestamp({
    timestamp,
    leewayMinutes,
  })

  verifySignature({
    url,
    secret,
    body,
    timestamp,
    signature,
  })

  return true
}

/** @module @truepic/webhook-verifier */
module.exports = verifyTruepicWebhook
module.exports.TruepicWebhookVerifierError = TruepicWebhookVerifierError
