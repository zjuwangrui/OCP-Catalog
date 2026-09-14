/**
 * `@ocp-catalog/ocp-crypto` — canonical JSON, Ed25519 signing, and JWKS
 * resolution for the OCP Catalog protocols.
 *
 * Specs: `docs/specs/crypto/canonicalization.md` (OCP-JCS v1) and
 * `docs/specs/attribution/v1.md` §5 (per-hop signing input).
 *
 * This package has **no dependencies**, including no `zod`. That is a
 * requirement, not a coincidence: canonicalization spec §9.1 forbids
 * canonicalizing Zod `parse()` output, because `.default()` injects members
 * that were never on the wire. Accepting a schema here would invite exactly
 * that mistake, so the API cannot express it.
 */
export {
  canonicalize,
  canonicalizeToBytes,
  canonicalizeValue,
  canonicalizeValueToBytes,
  canonicalHash,
  canonicalValueHash,
  canonicalNumberLiteral,
} from './canonical';

export {
  OCP_SIGNATURE_ALG,
  assertEd25519PublicJwk,
  fromBase64Url,
  generateEd25519KeyPair,
  jwkThumbprint,
  publicJwkOf,
  signBytes,
  signCanonical,
  toBase64Url,
  verifyBytes,
  verifyCanonical,
} from './keys';
export type {
  Ed25519PrivateJwk,
  Ed25519PublicJwk,
  GeneratedKeyPair,
  OcpSignatureAlg,
  VerifyParams,
} from './keys';

export { JwksCache, createDiscoveryJwksLoader } from './jwks';
export type {
  DiscoveryJwksLoaderOptions,
  JwksCacheOptions,
  JwksCacheStats,
  JwksLoader,
} from './jwks';

export {
  MAX_CHAIN_LENGTH,
  attributionSigningBytes,
  attributionSigningInput,
  coreClaims,
  issueOriginToken,
  recomputeComplete,
  signChainNode,
  unsignedNode,
  verifyChainNodeSignature,
} from './attribution';
export type {
  AgentIdentitySource,
  AttributionPurpose,
  AttributionRole,
  AttributionToken,
  ChainNode,
  CoreClaims,
  IssueOriginTokenParams,
  UnsignedChainNode,
} from './attribution';

export { CanonicalError, CryptoError, SPEC_CANONICAL_ERROR_CODES, errorCodeOf } from './errors';
export type { CanonicalErrorCode, CryptoErrorCode } from './errors';
