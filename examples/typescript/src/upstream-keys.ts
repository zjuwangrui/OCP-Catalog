/**
 * Public keys for the catalog nodes upstream of this one.
 *
 * A relay hop is a signature over somebody else's chain (§5.2: hop N's
 * signature covers hops 1..N−1). Co-signing without checking that chain first
 * puts this node's name, permanently, on whatever it turns out to be. So this
 * node needs key material for every upstream `catalog_id` it is willing to
 * relay for — and where it has none, the honest answer is not to sign.
 *
 * ## The default is "trust nobody", and that is the point
 *
 * With nothing configured, this map is empty, every upstream chain fails at
 * `key_not_found`, and no relay hop is ever appended. A resolve still succeeds;
 * it just carries no attribution, which is exactly what §10.2 asks of a node
 * that cannot attribute — the agent gets the response it got before this node
 * learned to sign.
 *
 * The opposite default — relay first, verify if keys happen to be around — is
 * the one worth naming, because it looks like graceful degradation and is not.
 * A forger picks the catalog_id that is *not* configured.
 *
 * ## Two ways to configure it
 *
 * - `OCP_UPSTREAM_JWKS`: a JSON object, `catalog_id` → JWKS document. The
 *   offline path; this is what the demo and the tests use, and it is what a
 *   node with a handful of known partners would actually ship.
 * - {@link trustUpstream} at runtime, for a node that discovers partners some
 *   other way (a registry poll, an operator API). Fetching
 *   `/.well-known/ocp-catalog` → `jwks_url` per upstream is the natural next
 *   step — `createDiscoveryJwksLoader` and `JwksCache` in `@ocp-catalog/ocp-crypto`
 *   are that path — but it is left out here so the example keeps running with
 *   the network unplugged, which is the property the offline verification demo
 *   depends on.
 */
import { staticKeyResolver, type AttributionKeyResolver } from '@ocp-catalog/ocp-crypto';

type Jwks = { keys?: unknown };

const UPSTREAM_JWKS: Record<string, Jwks> = {};

function loadFromEnv(raw: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('OCP_UPSTREAM_JWKS is not valid JSON');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('OCP_UPSTREAM_JWKS must be a JSON object mapping catalog_id to a JWKS document');
  }
  for (const [catalogId, jwks] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof jwks !== 'object' || jwks === null || !Array.isArray((jwks as Jwks).keys)) {
      // Loud, because the quiet version of this mistake is a node that relays
      // nothing and has no idea why.
      throw new Error(`OCP_UPSTREAM_JWKS["${catalogId}"] is not a JWKS document ({keys: [...]})`);
    }
    UPSTREAM_JWKS[catalogId] = jwks as Jwks;
  }
}

if (process.env.OCP_UPSTREAM_JWKS) loadFromEnv(process.env.OCP_UPSTREAM_JWKS);

/** Registers an upstream node's public keys. Replaces any previous set for that `catalog_id`. */
export function trustUpstream(catalogId: string, jwks: Jwks): void {
  UPSTREAM_JWKS[catalogId] = jwks;
}

/** The catalog ids this node can verify an upstream hop for. For diagnostics. */
export function trustedUpstreams(): string[] {
  return Object.keys(UPSTREAM_JWKS);
}

/**
 * The resolver handed to `verifyAttributionToken` before co-signing.
 *
 * Reads the map on every call rather than closing over a snapshot, so
 * {@link trustUpstream} takes effect without restarting the node. It never
 * awaits anything: an upstream chain is verified from key material already in
 * hand, so a resolve cannot block on somebody else's key server.
 */
export const upstreamKeyResolver: AttributionKeyResolver = (params) =>
  staticKeyResolver(UPSTREAM_JWKS)(params);
