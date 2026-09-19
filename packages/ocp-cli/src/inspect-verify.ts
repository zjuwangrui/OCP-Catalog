/**
 * `ocp catalog inspect --verify` — the decision half.
 *
 * Same shape and the same two reasons as `attribution.ts`: no
 * `@ocp-catalog/ocp-client` and no `node:fs`, so the caller does the I/O and
 * hands in loaded JSON. Here the first reason is sharper than usual — the
 * client's `inspectCatalog()` parses the manifest through
 * `catalogManifestSchema`, and spec §4.5 forbids verifying a parsed document
 * at all. Keeping the verifier out of reach of the client makes that mistake
 * hard to make by accident.
 *
 * The eight-step order, the error codes and the trust ceiling are not
 * reimplemented: they are `verifyDocumentSignature` and `trustCeilingFor` from
 * `ocp-crypto`. What this module adds is the shape the CLI prints and the exit
 * code a shell reads.
 */
import {
  selectVerificationKey,
  trustCeilingFor,
  verifyDocumentSignature,
  type DocumentKeyResolver,
  type SignatureErrorCode,
} from '@ocp-catalog/ocp-crypto';

export type DocumentVerification =
  | {
      ok: true;
      issuer: string;
      kid: string;
      alg: string;
      signed_at: string;
      expires_at?: string;
      /** The hash this verifier recomputed, not the one the envelope claimed. */
      payload_hash: string;
      trust_tier: 'verified';
      invalidates_cache: false;
    }
  | {
      ok: false;
      error: {
        /** One of the eight §8 codes — which one is the whole point of printing it. */
        code: SignatureErrorCode;
        message: string;
      };
      /** §9. `unsigned` and `signature_expired` are not evidence of tampering. */
      trust_tier: 'unknown' | 'unverified';
      invalidates_cache: boolean;
    };

/**
 * The `catalog_id` whose key set is needed to verify this document.
 *
 * Read off the envelope rather than off the document body, because the envelope
 * is what names the signer. They must agree (§4.4) and `verifyDocumentSignature`
 * rejects it when they do not — but that check is the verifier's to make, and a
 * caller that needs to know *which keys to fetch* has to ask before verification
 * can start. Falls back to `catalog_id` so an unsigned document still says which
 * node it claims to be, which is what the "you gave me no keys" message needs.
 */
export function documentSignatureIssuer(document: unknown): string | undefined {
  const record = document as Record<string, unknown> | null;
  if (!record || typeof record !== 'object') return undefined;
  const envelope = record.signature as Record<string, unknown> | undefined;
  const issuer = envelope && typeof envelope === 'object' ? envelope.issuer : undefined;
  if (typeof issuer === 'string' && issuer.length > 0) return issuer;
  return typeof record.catalog_id === 'string' ? record.catalog_id : undefined;
}

export interface VerifyCatalogDocumentInput {
  /**
   * The document **as received**. Not the output of a schema `parse()`: 96
   * `.default()` calls inject members the signer never signed, and the result
   * fails as `payload_mismatch`, which reads exactly like tampering (§4.5).
   */
  document: unknown;
  /** `catalog_id` → that node's JWKS document, already loaded. */
  jwks: Record<string, unknown>;
  /** The moment to judge `expires_at` at. Defaults to now. */
  at?: Date;
  /**
   * The node the caller already had in mind (§4.4). A manifest correctly signed
   * by somebody else is still the wrong manifest.
   */
  expectedIssuer?: string;
}

/** Runs §7's eight steps and shapes the verdict — plus its §9 ceiling — for JSON output. */
export async function verifyCatalogDocument(
  input: VerifyCatalogDocumentInput,
): Promise<DocumentVerification> {
  const resolveKey: DocumentKeyResolver = ({ issuer, kid }) =>
    selectVerificationKey(input.jwks[issuer] as { keys?: unknown } | undefined, kid, issuer);

  const result = await verifyDocumentSignature({
    document: input.document,
    resolveKey,
    ...(input.at === undefined ? {} : { at: input.at }),
    ...(input.expectedIssuer === undefined ? {} : { expectedIssuer: input.expectedIssuer }),
  });
  const ceiling = trustCeilingFor(result);

  if (!result.ok) {
    return {
      ok: false,
      error: { code: result.error.code, message: result.error.message },
      trust_tier: ceiling.trustTier as 'unknown' | 'unverified',
      invalidates_cache: ceiling.invalidatesCache,
    };
  }

  return {
    ok: true,
    issuer: result.issuer,
    kid: result.kid,
    alg: result.alg,
    signed_at: result.signedAt,
    ...(result.expiresAt === undefined ? {} : { expires_at: result.expiresAt }),
    payload_hash: result.payloadHash,
    trust_tier: 'verified',
    invalidates_cache: false,
  };
}

/**
 * `0` when the document verified, `2` when it did not.
 *
 * `2` rather than `1` because `1` is already what this CLI exits with when it
 * throws — an unreachable URL, a bad flag, a key set that was never supplied.
 * A script that treats "the signature does not check out" the same as "the
 * command was typed wrong" will eventually do the dangerous version of that
 * confusion: read a fetch failure as a verified node.
 */
export function exitCodeForVerification(verification: DocumentVerification): 0 | 2 {
  return verification.ok ? 0 : 2;
}
