/**
 * Document signing — `docs/specs/crypto/v1.md`.
 *
 * An OCP document carries its own proof: the envelope is embedded as the
 * document's `signature` member (spec §2), so the proof survives everything
 * that happens to a document after the HTTP response ends — caching, mirroring,
 * being committed into a registry, being pasted into a ticket.
 *
 * The binding is two layers (spec §4.1):
 *
 * ```text
 * payload_hash = sha256(OCP-JCS(document minus "signature"))
 * signature    = Ed25519(OCP-JCS(envelope minus "signature"))
 * ```
 *
 * which is what makes a tampered payload (`payload_mismatch`) distinguishable
 * from a tampered envelope (`signature_invalid`). Signing `{document, meta}` in
 * one pass would be shorter and would report both as the same failure.
 *
 * Distinct from the attribution chain in `attribution.ts`: same keys, same
 * canonicalization, different signing material. A chain node signs its prefix
 * plus the token's core claims; there is no envelope and no payload hash. The
 * two are not interchangeable and neither verifier will accept the other's
 * signature.
 */
import { canonicalizeValue, canonicalValueHash } from './canonical';
import { CryptoError, SignatureError } from './errors';
import {
  jwkThumbprint,
  OCP_SIGNATURE_ALG,
  publicJwkOf,
  selectVerificationKey,
  signCanonical,
  verifyCanonical,
  type Ed25519PrivateJwk,
  type Ed25519PublicJwk,
} from './keys';

/** The member a signed document carries its envelope in (spec §2). */
export const SIGNATURE_MEMBER = 'signature' as const;

export interface SignatureEnvelope {
  alg: typeof OCP_SIGNATURE_ALG;
  kid: string;
  /** The signing node's `catalog_id` — not a URL (spec §4.4). */
  issuer: string;
  signed_at: string;
  /** Absent means the signature does not expire (spec §5.3). */
  expires_at?: string;
  /** `sha256:<64 lowercase hex>` over the canonical payload. */
  payload_hash: string;
  signature: string;
}

/** The envelope before its signature exists — the §4.1 signing material. */
export type UnsignedSignatureEnvelope = Omit<SignatureEnvelope, 'signature'>;

export type SignedDocument<T> = T & { signature: SignatureEnvelope };

/** Spec §3 — the document minus its `signature` member. */
export function documentPayload<T extends object>(document: T): Omit<T, 'signature'> {
  const { signature: _signature, ...payload } = document as T & { signature?: unknown };
  return payload as Omit<T, 'signature'>;
}

/**
 * Spec §4.1 — `sha256:` + hex of SHA-256 over the canonical payload.
 *
 * Takes the document, not the payload, so a caller cannot forget to strip the
 * signature member — hashing a document *with* its envelope inside produces a
 * hash nothing will ever match, and the symptom is an unexplained
 * `payload_mismatch`.
 *
 * Throws `CanonicalError` for a document OCP-JCS refuses (a non-integer
 * number, a lone surrogate, a duplicate key surviving a permissive parser).
 * That is a refusal to produce a verdict, not a verdict: an unrepresentable
 * document has no canonical bytes, so there is nothing a signature could be
 * about. See canonicalization spec §2.2.
 */
export function documentPayloadHash(document: object): string {
  return canonicalValueHash(documentPayload(document));
}

/** Spec §4.1 — the envelope minus `signature`, which is what gets signed. */
export function signatureSigningInput(
  envelope: SignatureEnvelope | UnsignedSignatureEnvelope,
): UnsignedSignatureEnvelope {
  const { signature: _signature, ...rest } = envelope as SignatureEnvelope;
  return rest;
}

/** The exact bytes the signer signs. Exposed for debugging a mismatch. */
export function signatureSigningBytes(
  envelope: SignatureEnvelope | UnsignedSignatureEnvelope,
): string {
  return canonicalizeValue(signatureSigningInput(envelope));
}

export interface SignDocumentParams<T extends object> {
  document: T;
  privateJwk: Ed25519PrivateJwk;
  /**
   * Defaults to the JWK's own `kid`, or the RFC 7638 thumbprint of the key if
   * it has none. Derived rather than demanded so a node cannot publish two
   * different keys under one identifier by typo.
   */
  kid?: string;
  /**
   * Defaults to the document's `catalog_id`. Required only for a document that
   * has no `catalog_id` member.
   */
  issuer?: string;
  /** Optional (spec §5.3). Written only when given. */
  expiresAt?: Date;
  now?: () => Date;
}

/**
 * Signs a document and returns a copy carrying its envelope.
 *
 * Refuses to sign when `issuer` disagrees with the document's `catalog_id`.
 * That combination is not a signature anyone can use — every verifier runs
 * spec §7 step 4 and rejects it as `issuer_mismatch` — so producing it would
 * only move the failure from the node that can fix it to the merchant who
 * cannot.
 *
 * The input document is not mutated; re-signing an already-signed document
 * replaces the envelope, and the old envelope does not enter the new payload
 * hash (`documentPayload` strips it first).
 */
export function signDocument<T extends object>(params: SignDocumentParams<T>): SignedDocument<T> {
  const { document, privateJwk, expiresAt, now = () => new Date() } = params;

  const kid = params.kid ?? privateJwk.kid ?? jwkThumbprint(publicJwkOf(privateJwk));
  const catalogId = (document as { catalog_id?: unknown }).catalog_id;
  const issuer = params.issuer ?? (typeof catalogId === 'string' ? catalogId : undefined);

  if (issuer === undefined) {
    throw new SignatureError(
      'issuer_mismatch',
      'document has no "catalog_id" member, so `issuer` must be supplied explicitly',
    );
  }
  if (typeof catalogId === 'string' && catalogId !== issuer) {
    throw new SignatureError(
      'issuer_mismatch',
      `refusing to sign: issuer "${issuer}" does not match the document's catalog_id "${catalogId}"`,
    );
  }

  const payload = documentPayload(document);
  const unsigned: UnsignedSignatureEnvelope = {
    alg: OCP_SIGNATURE_ALG,
    kid,
    issuer,
    signed_at: now().toISOString(),
    ...(expiresAt ? { expires_at: expiresAt.toISOString() } : {}),
    payload_hash: canonicalValueHash(payload),
  };

  const signature = signCanonical(privateJwk, signatureSigningInput(unsigned));

  return { ...(payload as T), signature: { ...unsigned, signature } };
}

/**
 * Resolves the public key a document was signed with.
 *
 * Injected rather than fetched, for the same reason the attribution resolver
 * is: a verifier that reaches for the network on its own cannot be tested
 * offline, and offline verification is the property signing exists to provide.
 */
export type DocumentKeyResolver = (params: {
  issuer: string;
  kid: string;
}) => Ed25519PublicJwk | Promise<Ed25519PublicJwk>;

/** A resolver over one JWKS document already in hand — the offline path. */
export function staticDocumentKeyResolver(jwks: { keys?: unknown } | undefined): DocumentKeyResolver {
  return ({ issuer, kid }) => selectVerificationKey(jwks, kid, issuer);
}

export interface SignatureVerdict {
  issuer: string;
  kid: string;
  alg: string;
  signedAt: string;
  expiresAt?: string;
  /** The hash this verifier recomputed — equal to the envelope's by this point. */
  payloadHash: string;
}

export type VerifyDocumentSignatureResult =
  | ({ ok: true; error?: undefined } & SignatureVerdict)
  | { ok: false; error: SignatureError };

export interface VerifyDocumentSignatureParams {
  document: unknown;
  resolveKey: DocumentKeyResolver;
  /** The moment to judge `expires_at` at. Defaults to now. */
  at?: Date;
  /**
   * The `catalog_id` the verifier expects this document to belong to.
   *
   * Required for a document with no `catalog_id` member; optional otherwise,
   * where it pins the document to a node the verifier already had in mind
   * (spec §4.4) — a manifest that is correctly signed by *somebody else* is
   * still the wrong manifest.
   */
  expectedIssuer?: string;
}

function fail(code: SignatureError['code'], message: string): VerifyDocumentSignatureResult {
  return { ok: false, error: new SignatureError(code, message) };
}

const ENVELOPE_FIELDS = [
  'alg',
  'kid',
  'issuer',
  'signed_at',
  'expires_at',
  'payload_hash',
  'signature',
] as const;

const PAYLOAD_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

function timestamp(value: unknown): Date | undefined {
  if (typeof value !== 'string') return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

/**
 * Spec §7 step 2 — envelope shape. Returns the reason it is malformed, or
 * `undefined`.
 *
 * Unknown fields are rejected (spec §5.1): the envelope *is* the signed
 * material, so a field this verifier does not recognise still entered the
 * signature and still went unchecked.
 *
 * `alg`'s *value* is deliberately not checked here — that is step 3, and it has
 * its own code. This only asserts it is a string.
 */
function envelopeReason(envelope: Record<string, unknown>): string | undefined {
  for (const field of Object.keys(envelope)) {
    if (!(ENVELOPE_FIELDS as readonly string[]).includes(field)) {
      return `unknown field "${field}"`;
    }
  }
  for (const field of ['alg', 'kid', 'issuer', 'signed_at', 'payload_hash', 'signature'] as const) {
    const value = envelope[field];
    if (typeof value !== 'string' || value.length === 0) {
      return `"${field}" is missing or not a non-empty string`;
    }
  }
  if (!timestamp(envelope.signed_at)) return `"signed_at" is not an RFC 3339 instant`;
  if (envelope.expires_at !== undefined && !timestamp(envelope.expires_at)) {
    return `"expires_at" is not an RFC 3339 instant`;
  }
  if (!PAYLOAD_HASH_PATTERN.test(envelope.payload_hash as string)) {
    return `"payload_hash" is not sha256:<64 lowercase hex>`;
  }
  if (!BASE64URL_PATTERN.test(envelope.signature as string)) {
    return `"signature" is not unpadded base64url`;
  }
  return undefined;
}

/**
 * Runs spec §7's eight steps in order, stopping at the first failure.
 *
 * Returns a verdict rather than throwing, because "this document is not signed"
 * and "this document was tampered with" are both answers a caller has to record
 * and act on (spec §9 turns each into a trust ceiling).
 *
 * **Except** for key-material failures that are not about the document: if the
 * key set is unreachable, stale or malformed, this rejects the promise. A node
 * whose key server is down has not forged anything, and recording its outage as
 * `key_not_found` would degrade it as though it had (spec §7.3).
 *
 * `CanonicalError` also propagates — see {@link documentPayloadHash}.
 */
export async function verifyDocumentSignature(
  params: VerifyDocumentSignatureParams,
): Promise<VerifyDocumentSignatureResult> {
  const { document, resolveKey, at = new Date(), expectedIssuer } = params;

  // Step 1 — is there an envelope at all.
  if (typeof document !== 'object' || document === null) {
    return fail('unsigned', 'document is not a JSON object, so it carries no signature');
  }
  const carrier = document as Record<string, unknown>;
  if (carrier[SIGNATURE_MEMBER] === undefined) {
    return fail('unsigned', 'document has no "signature" member');
  }

  // Step 2 — envelope shape.
  const raw = carrier[SIGNATURE_MEMBER];
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return fail('envelope_malformed', '"signature" is not an object');
  }
  const envelope = raw as Record<string, unknown>;
  const reason = envelopeReason(envelope);
  if (reason) return fail('envelope_malformed', reason);

  // Step 3 — algorithm, read from inside the signed material, never guessed.
  if (envelope.alg !== OCP_SIGNATURE_ALG) {
    return fail('alg_not_supported', `alg is "${String(envelope.alg)}", expected "${OCP_SIGNATURE_ALG}"`);
  }

  // Step 4 — issuer. A string comparison, run before spending a whole-document
  // canonicalization on a manifest that is hanging off the wrong name.
  const issuer = envelope.issuer as string;
  const catalogId = carrier.catalog_id;
  if (typeof catalogId === 'string') {
    if (catalogId !== issuer) {
      return fail('issuer_mismatch', `envelope issuer is "${issuer}", document catalog_id is "${catalogId}"`);
    }
  } else if (expectedIssuer === undefined) {
    // Not skipped silently: a §4.4 check that quietly does not run is worse
    // than one that fails loudly, because the verdict still reads `ok: true`.
    return fail(
      'issuer_mismatch',
      'document has no "catalog_id" member and no expectedIssuer was supplied, so the issuer cannot be checked',
    );
  }
  if (expectedIssuer !== undefined && issuer !== expectedIssuer) {
    return fail('issuer_mismatch', `envelope issuer is "${issuer}", expected "${expectedIssuer}"`);
  }

  // Step 5 — recompute the payload hash. Before the key lookup, so no arbitrary
  // document can drive this verifier into making a network request.
  const recomputed = documentPayloadHash(carrier);
  if (recomputed !== envelope.payload_hash) {
    return fail(
      'payload_mismatch',
      `payload hashes to ${recomputed}, envelope claims ${String(envelope.payload_hash)} — the document was altered after signing`,
    );
  }

  // Step 6 — the key.
  const kid = envelope.kid as string;
  let jwk: Ed25519PublicJwk;
  try {
    jwk = await resolveKey({ issuer, kid });
  } catch (err) {
    if (err instanceof CryptoError) {
      // A key we cannot verify with is a key we did not find, same reading
      // attribution §7.1 row 4 takes.
      if (err.code === 'key_not_found' || err.code === 'invalid_key') {
        return fail('key_not_found', err.message);
      }
      if (err.code === 'alg_not_supported') return fail('alg_not_supported', err.message);
    }
    throw err; // jwks_unavailable / jwks_expired / jwks_malformed — not a verdict.
  }

  // Step 7 — the signature itself.
  const verified = verifyCanonical({
    jwk,
    value: signatureSigningInput(envelope as unknown as SignatureEnvelope),
    signature: envelope.signature as string,
    alg: envelope.alg,
  });
  if (!verified) {
    return fail(
      'signature_invalid',
      `envelope does not verify under kid "${kid}" of "${issuer}" — the envelope was altered, or this is not that node's signature`,
    );
  }

  // Step 8 — expiry, last: an expired-but-genuine signature and a forgery are
  // different findings, and checking this earlier would report the forgery as
  // the milder one.
  const expiresAt = envelope.expires_at === undefined ? undefined : timestamp(envelope.expires_at);
  if (expiresAt && at.getTime() > expiresAt.getTime()) {
    return fail(
      'signature_expired',
      `signature expired at ${String(envelope.expires_at)}, checked at ${at.toISOString()}`,
    );
  }

  return {
    ok: true,
    issuer,
    kid,
    alg: OCP_SIGNATURE_ALG,
    signedAt: envelope.signed_at as string,
    ...(envelope.expires_at === undefined ? {} : { expiresAt: envelope.expires_at as string }),
    payloadHash: recomputed,
  };
}

/**
 * Spec §9 — the trust ceiling a verification result allows.
 *
 * Returns the highest `trust_tier` the result permits and whether cached
 * content from this node must be discarded (the condition
 * `trust_strategy.downgrade_invalidates_cache` names). It is a *ceiling*, not a
 * verdict: a passing signature only unlocks `verified`, it does not assert the
 * manifest's contents are true (spec §7.2).
 */
export function trustCeilingFor(
  result: VerifyDocumentSignatureResult,
): { trustTier: 'unknown' | 'unverified' | 'verified'; invalidatesCache: boolean } {
  if (result.ok) return { trustTier: 'verified', invalidatesCache: false };
  // Neither of these is evidence that anything was altered: one node has not
  // started signing, the other forgot to re-sign. Dropping their caches would
  // punish an absence of proof as though it were proof of tampering.
  if (result.error.code === 'unsigned' || result.error.code === 'signature_expired') {
    return { trustTier: 'unverified', invalidatesCache: false };
  }
  return { trustTier: 'unknown', invalidatesCache: true };
}
