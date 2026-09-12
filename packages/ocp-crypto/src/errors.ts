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

/** Reads the stable code off a thrown value, for tests and error mapping. */
export function errorCodeOf(err: unknown): string | undefined {
  if (err instanceof CanonicalError || err instanceof CryptoError) return err.code;
  return undefined;
}
