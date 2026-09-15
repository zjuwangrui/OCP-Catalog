/**
 * Stable error codes for `@ocp-catalog/ocp-crypto`.
 *
 * Every failure in this package carries a machine-readable `code`. The reason is
 * in the canonicalization spec §11 / attribution spec §8: "报错终止" is not
 * assertable in a conformance test — three implementations can all throw and
 * still disagree about *what* failed. Only a code makes a bad input testable.
 */

/**
 * Canonicalization failures.
 *
 * The first six are the spec's stable set (canonicalization.md §11). A
 * TypeScript / Python / Go implementation MUST map the same input to the same
 * one of these six.
 *
 * The last two are implementation additions, deliberately kept outside that
 * set:
 * - `malformed_json` — the input is not JSON at all. The spec does not code it
 *   because it fails before canonicalization has anything to canonicalize.
 * - `unsupported_value` — only reachable through {@link canonicalizeValue};
 *   wire bytes cannot produce a `undefined` / `bigint` / `Date` member.
 */
export type CanonicalErrorCode =
  | 'duplicate_key'
  | 'lone_surrogate'
  | 'non_integer_number'
  | 'number_out_of_range'
  | 'non_finite_number'
  | 'top_level_not_object'
  | 'malformed_json'
  | 'unsupported_value';

/** The six codes a conformant cross-language implementation must agree on. */
export const SPEC_CANONICAL_ERROR_CODES: readonly CanonicalErrorCode[] = [
  'duplicate_key',
  'lone_surrogate',
  'non_integer_number',
  'number_out_of_range',
  'non_finite_number',
  'top_level_not_object',
];

export class CanonicalError extends Error {
  readonly code: CanonicalErrorCode;

  constructor(code: CanonicalErrorCode, message: string, options?: ErrorOptions) {
    super(`[${code}] ${message}`, options);
    this.name = 'CanonicalError';
    this.code = code;
  }
}

/**
 * Key handling and JWKS failures.
 *
 * `key_not_found` and `alg_not_supported` are two of the eleven attribution
 * error codes (attribution/v1.md §8) and are spelled identically on purpose —
 * the attribution verifier (T4) re-emits them with a `hop` attached.
 *
 * `jwks_expired` vs `jwks_unavailable` is a real distinction, not pedantry:
 * the first means we hold key material we are refusing to use, the second means
 * we hold none. Only the first indicates a node that was reachable and is not
 * anymore.
 */
export type CryptoErrorCode =
  | 'key_not_found'
  | 'alg_not_supported'
  | 'jwks_expired'
  | 'jwks_unavailable'
  | 'jwks_malformed'
  | 'invalid_key'
  | 'invalid_encoding';

export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string, options?: ErrorOptions) {
    super(`[${code}] ${message}`, options);
    this.name = 'CryptoError';
    this.code = code;
  }
}

/**
 * Attribution verification failures — the eleven codes of attribution/v1.md §8.
 *
 * Spelled out as a literal union rather than imported from `ocp-schema`,
 * because this package has no dependencies (see the package README). The two
 * lists are kept in sync by hand; §8 is the source of truth for both.
 *
 * `key_not_found` and `alg_not_supported` overlap {@link CryptoErrorCode} on
 * purpose: the verifier re-emits the key layer's codes with a `hop` attached
 * instead of inventing parallel names for the same condition.
 */
export type AttributionErrorCode =
  | 'chain_broken'
  | 'complete_mismatch'
  | 'signature_invalid'
  | 'key_not_found'
  | 'alg_not_supported'
  | 'token_expired'
  | 'token_not_yet_valid'
  | 'replayed_jti'
  | 'duplicate_order'
  | 'provider_mismatch'
  | 'purpose_not_settleable';

/** §8's full set, in §7.1 evaluation order. */
export const ATTRIBUTION_ERROR_CODES: readonly AttributionErrorCode[] = [
  'chain_broken',
  'complete_mismatch',
  'alg_not_supported',
  'key_not_found',
  'signature_invalid',
  'purpose_not_settleable',
  'provider_mismatch',
  'token_not_yet_valid',
  'token_expired',
  'replayed_jti',
  'duplicate_order',
];

/**
 * A verdict about one attribution token.
 *
 * `hop` is 1-based and present only for the three per-hop codes. It is the
 * whole point of §5.2's second implied property: a chain where hop K was
 * altered fails at hops K..N, so the *lowest* failing hop names the tampered
 * node. An error without it says "this chain is bad"; with it, "node 2 of 3
 * is bad", which is the difference between a dispute and an investigation.
 */
export class AttributionError extends Error {
  readonly code: AttributionErrorCode;
  readonly hop: number | undefined;

  constructor(
    code: AttributionErrorCode,
    message: string,
    options?: ErrorOptions & { hop?: number },
  ) {
    super(`[${code}]${options?.hop === undefined ? '' : ` hop ${options.hop}:`} ${message}`, options);
    this.name = 'AttributionError';
    this.code = code;
    this.hop = options?.hop;
  }
}

/** Reads the stable code off a thrown value, for tests and error mapping. */
export function errorCodeOf(err: unknown): string | undefined {
  if (err instanceof CanonicalError || err instanceof CryptoError) return err.code;
  if (err instanceof AttributionError) return err.code;
  return undefined;
}
