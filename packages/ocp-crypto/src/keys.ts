/**
 * Ed25519 key handling for OCP: generate, sign, verify, and the JWK form used
 * in a catalog node's JWKS.
 *
 * `EdDSA` over `Ed25519` is the only algorithm. That is a deliberate floor, not
 * a starting point — attribution spec §5.1 puts `alg` inside the signed
 * material precisely so a verifier cannot be talked into a weaker one, and a
 * single-algorithm implementation cannot be talked into it at all.
 *
 * Built on `node:crypto`. Raw keys are wrapped into DER by hand rather than
 * going through `format: 'jwk'`, so the package behaves identically on bun and
 * node without depending on either one's JWK import coverage.
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { canonicalizeValue } from './canonical';
import { CryptoError } from './errors';

export const OCP_SIGNATURE_ALG = 'EdDSA' as const;
export type OcpSignatureAlg = typeof OCP_SIGNATURE_ALG;

export interface Ed25519PublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  /** Raw 32-byte public key, base64url unpadded. */
  x: string;
  kid?: string;
  alg?: OcpSignatureAlg;
  use?: 'sig';
}

export interface Ed25519PrivateJwk extends Ed25519PublicJwk {
  /** Raw 32-byte seed, base64url unpadded. */
  d: string;
}

export interface GeneratedKeyPair {
  kid: string;
  publicJwk: Ed25519PublicJwk;
  privateJwk: Ed25519PrivateJwk;
}

// SubjectPublicKeyInfo / PKCS#8 prefixes for id-Ed25519 (OID 1.3.101.112).
// Fixed-length because Ed25519 keys are fixed-length; there is nothing to parse.
const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

const RAW_KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;

/** base64url, unpadded — the encoding attribution spec §5.2 mandates. */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/**
 * Decodes base64url and rejects padding.
 *
 * `Buffer.from(s, 'base64url')` happily accepts `=` padding and even plain
 * base64 with `+/`. Accepting those would make two distinct encodings of the
 * same signature both valid, which is a signature malleability foothold, and
 * would also let a value through that `AttributionChainNode.signature`'s
 * pattern (`^[A-Za-z0-9_-]+$`) rejects.
 */
export function fromBase64Url(value: string, what = 'value'): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new CryptoError('invalid_encoding', `${what} is not unpadded base64url`);
  }
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

/**
 * RFC 7638 thumbprint, base64url of SHA-256 over the required members in
 * lexicographic order with no whitespace.
 *
 * That description is OCP-JCS v1 applied to `{crv, kty, x}`, so this reuses
 * `canonicalizeValue` instead of hand-rolling the JSON — one fewer place where
 * member order could drift.
 */
export function jwkThumbprint(jwk: Ed25519PublicJwk): string {
  const canonical = canonicalizeValue({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return toBase64Url(new Uint8Array(createHash('sha256').update(canonical, 'utf8').digest()));
}

/**
 * Validates that an arbitrary JWKS entry is an Ed25519 signing key.
 *
 * Throws `alg_not_supported` — not `key_not_found` — when the key exists but is
 * the wrong kind. Attribution spec §8 keeps those two codes separate, and the
 * distinction is operationally real: one means "you are looking at the wrong
 * node", the other means "that node published something I will not verify
 * with".
 */
export function assertEd25519PublicJwk(candidate: unknown, what = 'JWK'): Ed25519PublicJwk {
  if (typeof candidate !== 'object' || candidate === null) {
    throw new CryptoError('invalid_key', `${what} is not an object`);
  }
  const jwk = candidate as Record<string, unknown>;

  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    throw new CryptoError(
      'alg_not_supported',
      `${what} is kty=${String(jwk.kty)} crv=${String(jwk.crv)}; only OKP/Ed25519 is supported`,
    );
  }
  if (jwk.alg !== undefined && jwk.alg !== OCP_SIGNATURE_ALG) {
    throw new CryptoError('alg_not_supported', `${what} declares alg=${String(jwk.alg)}; only EdDSA is supported`);
  }
  if (jwk.use !== undefined && jwk.use !== 'sig') {
    throw new CryptoError('alg_not_supported', `${what} declares use=${String(jwk.use)}; a signing key is required`);
  }
  if (typeof jwk.x !== 'string') {
    throw new CryptoError('invalid_key', `${what} has no "x" member`);
  }
  const raw = fromBase64Url(jwk.x, `${what}.x`);
  if (raw.length !== RAW_KEY_BYTES) {
    throw new CryptoError('invalid_key', `${what}.x decodes to ${raw.length} bytes, expected ${RAW_KEY_BYTES}`);
  }

  return jwk as unknown as Ed25519PublicJwk;
}

/**
 * Picks the verification key with this `kid` out of a JWKS document.
 *
 * Shared by the attribution verifier and the document-signature verifier so
 * that "I could not find the key" means the same thing, and produces the same
 * message, in both. `owner` is the `catalog_id` whose key set this is, and only
 * appears in the error text.
 *
 * Throws `key_not_found` both when the `kid` is absent and when the JWKS itself
 * is not in hand. It does **not** distinguish "the node has no such key" from
 * "we hold no key set for that node" — a caller that needs that distinction
 * must check before calling, as `packages/ocp-cli/src/attribution.ts` does,
 * because the fix for one is a dispute and the fix for the other is a flag.
 */
export function selectVerificationKey(
  jwks: { keys?: unknown } | undefined,
  kid: string,
  owner: string,
): Ed25519PublicJwk {
  const keys = jwks && Array.isArray(jwks.keys) ? (jwks.keys as unknown[]) : undefined;
  if (!keys) {
    throw new CryptoError('key_not_found', `no JWKS on hand for catalog "${owner}"`);
  }
  const match = keys.find(
    (key): key is Record<string, unknown> =>
      typeof key === 'object' && key !== null && (key as Record<string, unknown>).kid === kid,
  );
  if (!match) {
    throw new CryptoError('key_not_found', `kid "${kid}" is not in the JWKS of "${owner}"`);
  }
  return assertEd25519PublicJwk(match);
}

function publicKeyObject(jwk: Ed25519PublicJwk): KeyObject {
  const raw = fromBase64Url(jwk.x, 'JWK.x');
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

function privateKeyObject(jwk: Ed25519PrivateJwk): KeyObject {
  if (typeof jwk.d !== 'string') throw new CryptoError('invalid_key', 'private JWK has no "d" member');
  const seed = fromBase64Url(jwk.d, 'JWK.d');
  if (seed.length !== RAW_KEY_BYTES) {
    throw new CryptoError('invalid_key', `JWK.d decodes to ${seed.length} bytes, expected ${RAW_KEY_BYTES}`);
  }
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

/**
 * Generates a key pair. `kid` defaults to the RFC 7638 thumbprint, so a rotated
 * key gets a new `kid` automatically and an operator cannot accidentally
 * republish two different keys under one identifier.
 */
export function generateEd25519KeyPair(options: { kid?: string } = {}): GeneratedKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');

  const spki = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }));
  const pkcs8 = new Uint8Array(privateKey.export({ format: 'der', type: 'pkcs8' }));
  const x = toBase64Url(spki.subarray(SPKI_PREFIX.length));
  const d = toBase64Url(pkcs8.subarray(PKCS8_PREFIX.length));

  const base: Ed25519PublicJwk = { kty: 'OKP', crv: 'Ed25519', x, alg: OCP_SIGNATURE_ALG, use: 'sig' };
  const kid = options.kid ?? jwkThumbprint(base);

  return {
    kid,
    publicJwk: { ...base, kid },
    privateJwk: { ...base, kid, d },
  };
}

/** Drops `d` so a private JWK can be published. */
export function publicJwkOf(jwk: Ed25519PrivateJwk): Ed25519PublicJwk {
  const { d: _d, ...pub } = jwk;
  return pub;
}

/** Signs raw bytes. Returns the signature as unpadded base64url. */
export function signBytes(privateJwk: Ed25519PrivateJwk, message: Uint8Array): string {
  return toBase64Url(new Uint8Array(sign(null, message, privateKeyObject(privateJwk))));
}

export interface VerifyParams {
  jwk: unknown;
  message: Uint8Array;
  signature: string;
  /** Must be `EdDSA`. Taken from the signed material, never guessed. */
  alg?: string;
}

/**
 * Verifies a detached signature.
 *
 * Returns `false` for a signature that does not match, and *throws* for an
 * unusable algorithm or key. The split is intentional: "this signature is
 * wrong" is a fact about the data that a verifier must be able to record and
 * keep going from, while "I cannot evaluate this algorithm" is a
 * configuration/trust failure that must not be silently recorded as a mismatch.
 */
export function verifyBytes({ jwk, message, signature, alg = OCP_SIGNATURE_ALG }: VerifyParams): boolean {
  if (alg !== OCP_SIGNATURE_ALG) {
    throw new CryptoError('alg_not_supported', `alg=${alg} is not supported; only EdDSA is`);
  }
  const publicJwk = assertEd25519PublicJwk(jwk);

  let raw: Uint8Array;
  try {
    raw = fromBase64Url(signature, 'signature');
  } catch {
    return false; // a malformed signature is a mismatch, not a config error
  }
  if (raw.length !== SIGNATURE_BYTES) return false;

  try {
    return verify(null, message, publicKeyObject(publicJwk), raw);
  } catch {
    return false;
  }
}

/**
 * Signs the canonical bytes of an in-memory value.
 *
 * This is the composition the attribution chain actually uses (spec §5.2): the
 * signing input is a constructed object, not received bytes.
 */
export function signCanonical(privateJwk: Ed25519PrivateJwk, value: unknown): string {
  return signBytes(privateJwk, new TextEncoder().encode(canonicalizeValue(value)));
}

export function verifyCanonical(params: { jwk: unknown; value: unknown; signature: string; alg?: string }): boolean {
  return verifyBytes({
    jwk: params.jwk,
    message: new TextEncoder().encode(canonicalizeValue(params.value)),
    signature: params.signature,
    alg: params.alg,
  });
}
