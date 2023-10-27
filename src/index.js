import { createHmac, timingSafeEqual } from 'node:crypto'
import TruepicWebhookVerifierError from './error.js'

// Parse the `truepic-signature` header into timestamp and signature values.
//
// The header value looks like this:
//
//     t=1634066973,s=6FBEiVZ8EO79dk5XllfnG18b83ZvLt2kdxcE8FJ/BwU
//
// The `t` value is the timestamp of when the request was sent (in seconds), and
// the `s` value is the signature of the request.
function parseHeader(header) {
  if (!header?.length) {
    throw new TruepicWebhookVerifierError('Header is missing or empty')
  }

  // Split the the header value on the comma (`,`). This should leave two parts:
  //     - t=1634066973
  //     - s=6FBEiVZ8EO79dk5XllfnG18b83ZvLt2kdxcE8FJ/BwU
  const [timestampParts, signatureParts] = header.split(',')

  if (!timestampParts?.length || !signatureParts?.length) {
    throw new TruepicWebhookVerifierError(
      'Header cannot be parsed into timestamp and signature',
    )
  }

  // Split the timestamp (`t`) on the equals (`=`). This should leave two parts:
  //    - t
  //    - 1634066973
  let [t, timestamp] = timestampParts.split('=')

  if (t !== 't' || !timestamp?.length) {
    throw new TruepicWebhookVerifierError('Timestamp is missing or empty')
  }

  // Cast and verify that the timestamp value is a number.
  timestamp = Number(timestamp)

  if (isNaN(timestamp)) {
    throw new TruepicWebhookVerifierError('Timestamp is not a number')
  }

  // Split the signature (`s`) on the equals (`=`). This should leave two parts:
  //    - s
  //    - 6FBEiVZ8EO79dk5XllfnG18b83ZvLt2kdxcE8FJ/BwU
  const [s, signature] = signatureParts.split('=')

  if (s !== 's' || !signature?.length) {
    throw new TruepicWebhookVerifierError('Signature is missing or empty')
  }

  return { timestamp, signature }
}

// Verify the timestamp to ensure the request is recent and not a potentially
// delayed replay attack. Some leeway is required in case the clocks on either
// end of the request aren't quite in sync.
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

// Verify the signature to ensure the integrity of the data being received, the
// authenticity of the sender (Truepic), and the authenticity of the receiver
// (you).
function verifySignature({ url, secret, body, timestamp, signature }) {
  // Rebuild the signature (SHA-256, base64-encoded HMAC digest) with a secret
  // that only Truepic and the intended receiver are privy to.
  const comparisonSignature = createHmac('sha256', secret)

  // Concatenate the full URL that received the request, timestamp parsed from
  // the header, and raw body (unparsed JSON) from the request using a comma
  // (`,`). It's important to use the raw body before it's parsed as JSON, as
  // different languages/frameworks can parse/stringify JSON in subtly different
  // ways, which can result in a different signature.
  comparisonSignature.update([url, timestamp, body].join(','))

  // Compare with a constant-time algorithm to prevent a timing attack.
  const isEqual = timingSafeEqual(
    Buffer.from(comparisonSignature.digest('base64'), 'base64'),
    Buffer.from(signature, 'base64'),
  )

  if (!isEqual) {
    throw new TruepicWebhookVerifierError('Signature is not valid')
  }

  return true
}

// Verify a webhook from Truepic Vision or Lens.
function verifyWebhook({ url, secret, header, body, leewayMinutes = 5 }) {
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

export { verifyWebhook, TruepicWebhookVerifierError }
