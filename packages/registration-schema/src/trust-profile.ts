/**
 * `CatalogRouteHint.trust_profile` — filled in from an actual verification, and
 * downgraded when that verification fails.
 *
 * A route hint arrives from a registry carrying that registry's opinion
 * (`verification_status`, `trust_tier`). `trust_profile` is where a consumer
 * records what it established for itself by verifying the node's signed
 * manifest. Until now the three evidence fields (`manifest_hash`, `issuer`,
 * `signature_alg`) and `downgrade_invalidates_cache` were declared and never
 * written; this module writes them.
 *
 * The §9 mapping is not reimplemented here — `trustCeilingFor()` from
 * `ocp-crypto` owns it. There is one copy of that rule in the codebase on
 * purpose: two would eventually disagree, and the shape of the disagreement is
 * "the CLI says the node was downgraded, the router says it wasn't".
 */
import { trustCeilingFor, type VerifyDocumentSignatureResult } from '@ocp-catalog/ocp-crypto';
import type { CatalogRouteHint } from './index';

type TrustProfile = NonNullable<CatalogRouteHint['trust_profile']>;
type CeilingTier = 'unknown' | 'unverified' | 'verified';

/** §9's three tiers, worst to best. Registry-specific tiers are deliberately absent — see `applyCeiling`. */
const CEILING_RANK: Record<CeilingTier, number> = { unknown: 0, unverified: 1, verified: 2 };

/**
 * A ceiling only ever lowers.
 *
 * When the signature verifies, the claimed tier is returned untouched: §7.2 is
 * explicit that a passing signature unlocks `verified`, it does not assert that
 * the manifest's contents are true. A registry that said `verified_domain`
 * still says `verified_domain`; the signature did not earn that, domain
 * verification did.
 *
 * When it does not verify and the claimed tier is from a vocabulary this
 * function cannot rank (registries are free to define their own — the spec
 * types `trust_tier` as an open string), the ceiling replaces it outright.
 * Keeping an unrankable tier next to a failed verification is how a forged
 * manifest keeps the word "verified" in front of a consumer.
 */
function applyCeiling(claimed: string, ceiling: CeilingTier): string {
  if (ceiling === 'verified') return claimed;
  const claimedRank = CEILING_RANK[claimed as CeilingTier];
  if (claimedRank === undefined) return ceiling;
  return claimedRank <= CEILING_RANK[ceiling] ? claimed : ceiling;
}

export interface RouteHintTrustOutcome {
  /** The hint with `trust_profile` written and, where the ceiling required it, the tier lowered. */
  hint: CatalogRouteHint;
  /** True when the ceiling lowered the tier the registry claimed. */
  downgraded: boolean;
  /**
   * §9. True means cached content from this node must be discarded before the
   * hint is used. `unsigned` and `signature_expired` do **not** set it: one node
   * has not started signing and the other forgot to re-sign, and neither is
   * evidence that anything was altered.
   */
  invalidates_cache: boolean;
}

/**
 * Fold a manifest verification into a route hint.
 *
 * `result` must come from verifying the manifest **as received**. Verifying the
 * output of `catalogManifestSchema.parse()` fails as `payload_mismatch` because
 * the schema's `.default()` calls inject members nobody signed (crypto/v1 §4.5)
 * — and that arrives here indistinguishable from a forgery, so the node gets
 * downgraded and its cache dropped for a mistake the consumer made.
 *
 * Pure: no fetching, no clock, no cache. The caller drops the cache when
 * `invalidates_cache` comes back true.
 */
export function applyManifestVerification(
  hint: CatalogRouteHint,
  result: VerifyDocumentSignatureResult,
): RouteHintTrustOutcome {
  const ceiling = trustCeilingFor(result);
  const existing = hint.trust_profile;

  const claimedTier = existing?.trust_tier ?? hint.trust_tier;
  const tier = applyCeiling(claimedTier, ceiling.trustTier);

  const profile: TrustProfile = {
    // Domain ownership is a different axis from signing, and this function saw
    // no evidence about it. Both fields pass through untouched.
    verification_status: existing?.verification_status ?? hint.verification_status,
    trust_tier: tier,
    domain_verified: existing?.domain_verified ?? false,
    // "The node signed it", not "the signature checked out" — true even for a
    // forgery. Only a document with no `signature` member at all is unsigned.
    manifest_signed: result.ok || result.error.code !== 'unsigned',
    // A node may declare that a downgrade need not invalidate caches; it may
    // not declare that away for its own forged manifest. Same rule as T1's
    // `trust_tier`: this is the verifier's conclusion, not the node's claim.
    downgrade_invalidates_cache:
      ceiling.invalidatesCache || (existing?.downgrade_invalidates_cache ?? true),
    // The three evidence fields below are only written when there is evidence.
    // Carrying a `manifest_hash` from an earlier good fetch alongside a failed
    // one is the poisoning this whole field exists to prevent, so a failure
    // clears them rather than leaving them stale.
    ...(result.ok
      ? {
          signature_alg: result.alg,
          manifest_hash: result.payloadHash,
          issuer: result.issuer,
        }
      : {}),
  };

  return {
    hint: {
      ...hint,
      // Kept in step with the profile on purpose: a consumer that reads only
      // the top-level `trust_tier` must not see `verified` while the profile
      // below it says `unknown`.
      trust_tier: applyCeiling(hint.trust_tier, ceiling.trustTier),
      trust_profile: profile,
    },
    downgraded: tier !== claimedTier,
    invalidates_cache: ceiling.invalidatesCache,
  };
}
