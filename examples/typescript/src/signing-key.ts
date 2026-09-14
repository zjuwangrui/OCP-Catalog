/**
 * The example node's signing key.
 *
 * A catalog node that issues attribution tokens needs exactly two things: a
 * private key to sign with, and a public way for a merchant to find the
 * matching public key. This file is both halves — the key itself, and the JWK
 * Set served at `/.well-known/jwks.json` and advertised as `jwks_url` in the
 * discovery document.
 *
 * **The default key is ephemeral, and that is wrong for production.** It is
 * generated in memory at startup, so every restart invalidates every token this
 * node ever issued: a merchant who resolved before the restart looks up the
 * `kid`, does not find it, and gets `key_not_found`. That is the correct
 * failure — a signature nobody can check must not be treated as valid — but for
 * a real node it is an outage, not a design. Set `OCP_SIGNING_JWK` to a
 * persisted private JWK to keep the key across restarts.
 */
import {
  generateEd25519KeyPair,
  jwkThumbprint,
  publicJwkOf,
  type Ed25519PrivateJwk,
} from '@ocp-catalog/ocp-crypto';

function loadFromEnv(raw: string): Ed25519PrivateJwk {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('OCP_SIGNING_JWK is not valid JSON');
  }
  const jwk = parsed as Partial<Ed25519PrivateJwk>;
  if (jwk?.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.d !== 'string' || typeof jwk.x !== 'string') {
    throw new Error('OCP_SIGNING_JWK must be an Ed25519 private JWK ({kty:"OKP", crv:"Ed25519", d, x})');
  }
  // Fail loudly rather than falling back to a generated key: a node started
  // with a broken key env var almost certainly meant to use a persisted key,
  // and silently minting a throwaway one would look like it worked.
  return jwk as Ed25519PrivateJwk;
}

const configured = process.env.OCP_SIGNING_JWK;
const privateJwk: Ed25519PrivateJwk = configured
  ? loadFromEnv(configured)
  : generateEd25519KeyPair().privateJwk;

/**
 * `kid` is the RFC 7638 thumbprint of the key, recomputed here rather than
 * trusted from the JWK. Deriving it from the key material means two different
 * keys can never be published under one identifier — including when the key
 * came from `OCP_SIGNING_JWK` with a hand-written `kid` that no longer matches
 * the key beside it.
 */
const publicJwk = {
  ...publicJwkOf(privateJwk),
  alg: 'EdDSA',
  use: 'sig',
  kid: jwkThumbprint(publicJwkOf(privateJwk)),
} as const;

export const SIGNING_KEY = {
  kid: publicJwk.kid,
  privateJwk,
  publicJwk,
} as const;

/** The document served at `/.well-known/jwks.json`. */
export function jwkSet(): { keys: unknown[] } {
  return { keys: [SIGNING_KEY.publicJwk] };
}
