/**
 * The attribution verifier — `docs/specs/attribution/v1.md` §7.1 and §8.
 *
 * §7.1 is written as a settlement eligibility filter, but it is also the
 * normative *verification order*: §8 fixes the order to that table's rows and
 * requires termination at the first failure. The reason is conformance, not
 * taste — a token that violates three rules at once must produce the same one
 * error code in every implementation, or the shared test vectors cannot assert
 * anything about it.
 *
 * Signing material is never rebuilt here. Every signature check goes through
 * `attribution.ts`, because a verifier with its own copy of §5.2 drifts from
 * the signer eventually, and the only symptom is "signature invalid" pointing
 * at the wrong thing entirely.
 */
import {
  checkChainStructure,
  coreClaims,
  recomputeComplete,
  verifyChainNodeSignature,
  type AttributionPurpose,
  type AttributionToken,
  type ChainNode,
} from './attribution';
import { AttributionError, CryptoError } from './errors';
import { assertEd25519PublicJwk, OCP_SIGNATURE_ALG, type Ed25519PublicJwk } from './keys';
import type { JwksCache } from './jwks';

/**
 * Resolves the public key for one hop.
 *
 * Injected rather than fetched, for the same reason `JwksCache` takes its
 * `fetchJson`: a verifier that reaches for the network on its own cannot be
 * tested offline, and offline verification is the property this whole
 * mechanism exists to provide.
 *
 * May throw {@link CryptoError}. `key_not_found`, `alg_not_supported` and
 * `invalid_key` become verdicts about the token; every other code is re-thrown
 * — see {@link verifyAttributionToken}.
 */
export type AttributionKeyResolver = (params: {
  catalogId: string;
  kid: string;
  hop: number;
}) => Ed25519PublicJwk | Promise<Ed25519PublicJwk>;

/**
 * A resolver over key material already in hand — one JWKS document per
 * `catalog_id`, exactly what a merchant has after curling each node once.
 *
 * This is the offline path. It never awaits anything, so a verification built
 * on it cannot silently acquire a network dependency.
 */
export function staticKeyResolver(
  jwksByCatalogId: Readonly<Record<string, { keys?: unknown } | undefined>>,
): AttributionKeyResolver {
  return ({ catalogId, kid }) => {
    const jwks = jwksByCatalogId[catalogId];
    const keys = jwks && Array.isArray(jwks.keys) ? (jwks.keys as unknown[]) : undefined;
    if (!keys) {
      throw new CryptoError('key_not_found', `no JWKS on hand for catalog "${catalogId}"`);
    }
    const match = keys.find(
      (key): key is Record<string, unknown> =>
        typeof key === 'object' && key !== null && (key as Record<string, unknown>).kid === kid,
    );
    if (!match) {
      throw new CryptoError('key_not_found', `kid "${kid}" is not in the JWKS of "${catalogId}"`);
    }
    return assertEd25519PublicJwk(match);
  };
}

/** A resolver backed by the TTL cache, for a verifier that is allowed online. */
export function jwksCacheKeyResolver(cache: JwksCache): AttributionKeyResolver {
  return ({ catalogId, kid }) => cache.getVerificationKey(catalogId, kid);
}

/**
 * §7.1 row 10 — the `jti` replay guard.
 *
 * The rule the spec draws is narrow and worth restating: the same `jti` against
 * the **same** `order_id` is normal traffic (a retry, a status update from
 * pending to confirmed). The same `jti` against a **different** `order_id` is
 * one attribution token being spent twice, which is the whole attack.
 *
 * ## This is in-memory. Production needs persistent storage.
 *
 * Not a caveat — a correctness gap with a name. Two ways it fails as written:
 *
 * 1. **Restart empties it.** Every token issued before the restart becomes
 *    replayable exactly once more. A settlement process that restarts nightly
 *    has a nightly replay window.
 * 2. **It is per-process.** Two settlement workers behind a load balancer hold
 *    two separate maps, so the same token can be claimed once in each.
 *
 * The replacement is a row in the same transactional store that records the
 * settlement, keyed on `jti` with the `order_id` beside it — the claim and the
 * payout have to commit together or the guard can be lost after the money
 * moves. What is here is enough for tests and a single-process reference
 * implementation, and nothing more.
 *
 * Retention is derived, not configured: an entry is kept until the token's own
 * `exp`. Past that, §7.1 row 9 rejects the token anyway, so remembering its
 * `jti` any longer protects nothing.
 */
export class JtiRegistry {
  readonly #claims = new Map<string, { orderId: string; expiresAtMs: number }>();
  readonly #now: () => number;
  readonly #maxEntries: number;

  constructor(options?: { now?: () => number; maxEntries?: number }) {
    this.#now = options?.now ?? (() => Date.now());
    this.#maxEntries = options?.maxEntries ?? 100_000;
  }

  /** Live entries, after dropping any whose token has expired. */
  get size(): number {
    this.prune();
    return this.#claims.size;
  }

  /** Drops entries past their token's `exp`. Called automatically on write. */
  prune(): void {
    const now = this.#now();
    for (const [jti, claim] of this.#claims) {
      if (claim.expiresAtMs <= now) this.#claims.delete(jti);
    }
  }

  /**
   * Binds `jti` to `orderId` until `expiresAt`. Returns `false` if that `jti`
   * is already bound to a different order — a replay.
   *
   * Throws once the registry is full rather than evicting a live entry.
   * Evicting would open a replay window silently, at whatever moment the
   * process happened to be busiest; an operator who sees this error is being
   * told to move the guard into a database, which is the actual fix.
   */
  claim(jti: string, orderId: string, expiresAt: Date): boolean {
    this.prune();
    const existing = this.#claims.get(jti);
    if (existing) return existing.orderId === orderId;

    if (this.#claims.size >= this.#maxEntries) {
      throw new Error(
        `JtiRegistry is full (${this.#maxEntries} live claims). This guard is in-memory by ` +
          `design and does not evict, because evicting a live claim reopens the replay it ` +
          `exists to prevent. Move it to persistent storage.`,
      );
    }

    this.#claims.set(jti, { orderId, expiresAtMs: expiresAt.getTime() });
    return true;
  }

  /** The order a `jti` is bound to, if any. For diagnostics. */
  orderOf(jti: string): string | undefined {
    this.prune();
    return this.#claims.get(jti)?.orderId;
  }
}

export interface VerifyAttributionTokenParams {
  token: AttributionToken;
  resolveKey: AttributionKeyResolver;
  /**
   * The moment the token is being claimed for — a report's `occurred_at`, not
   * the moment of verification. §7.1 rows 8 and 9 are about when the
   * transaction happened; checking them against "now" would reject a valid
   * sale reported an hour late. Defaults to now for the no-report case.
   */
  at?: Date;
  /** §7.1 row 7 — a report's `provider_id`. Skipped when there is no report yet. */
  expectedProviderId?: string;
  /**
   * §7.1 row 6. Defaults to `"checkout"`, the only settleable purpose.
   * Pass `null` to check the cryptography of a non-settleable token (a `view`
   * token is legitimately signed; it just cannot be settled against).
   */
  requirePurpose?: AttributionPurpose | null;
  /**
   * §7.1 row 10. Claimed only after every other check has passed, so a token
   * rejected for any other reason does not burn its `jti`.
   *
   * `claim: false` checks the row without taking the slot. A settler holding
   * several candidate tokens for one order must evaluate row 10 on all of them
   * but claim only the one that wins adjudication (§7.2) — claiming on behalf
   * of a loser would bind its `jti` to an order it was never settled against.
   */
  replayGuard?: { registry: JtiRegistry; orderId: string; claim?: boolean };
}

export interface AttributionVerdict {
  /** §5.3 recomputed, never read off the token. */
  complete: boolean;
  agentId: string;
  /** §7.3 — the catalog-side settlement subjects, in hop order. */
  settlingCatalogIds: string[];
  /** §7.2 — the last hop's `signed_at`, the last-touch sort key. */
  lastSignedAt: string;
  hops: number;
}

export type VerifyAttributionTokenResult =
  | ({ ok: true; error?: undefined } & AttributionVerdict)
  | { ok: false; error: AttributionError };

function fail(
  code: AttributionError['code'],
  message: string,
  hop?: number,
): VerifyAttributionTokenResult {
  return { ok: false, error: new AttributionError(code, message, { hop }) };
}

/** Parses an RFC 3339 claim, or `undefined` if it is not a usable instant. */
function instant(value: string): Date | undefined {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

/**
 * Runs the §7.1 eligibility filter over one token, in §8's fixed order,
 * stopping at the first failure.
 *
 * Returns a verdict rather than throwing, because a settler holds several
 * candidate tokens and must record why each one lost before adjudicating among
 * the survivors (§7.2). A rejection is data.
 *
 * **Except** for key-material failures that are not about the token: if the
 * JWKS is unreachable, stale, or malformed, this rejects the *promise*. A node
 * whose key server is down has not forged anything, and turning its outage
 * into `key_not_found` would settle against it as though it had. Only
 * `key_not_found`, `alg_not_supported` and `invalid_key` — all statements
 * about key material actually published under that `kid` — become verdicts.
 *
 * ### One deviation from §7.1's printed row order, and why
 *
 * Rows 3, 4, 5 are listed as signature → key → alg, which cannot be executed
 * in that order: verifying a signature requires the key, and verifying it
 * under an unchecked algorithm is the algorithm-confusion hole §5.1 exists to
 * close. This runs each hop as alg → key → signature, hops ascending, and the
 * spec has been corrected to match (§7.1, v1.0.1).
 *
 * Ascending hop order is itself normative content: §5.2's second implied
 * property is that altering hop K breaks hops K..N, so the lowest failing hop
 * *is* the tampered one. Reporting any other failing hop would name an
 * innocent node.
 */
export async function verifyAttributionToken(
  params: VerifyAttributionTokenParams,
): Promise<VerifyAttributionTokenResult> {
  const {
    token,
    resolveKey,
    at = new Date(),
    expectedProviderId,
    requirePurpose = 'checkout',
    replayGuard,
  } = params;

  const chain: ReadonlyArray<ChainNode> = token.chain ?? [];

  // Row 1 — structure, before any signature work (§5.4).
  const broken = checkChainStructure(chain);
  if (broken) return fail('chain_broken', broken);

  // Row 2 — recompute `complete`; never read it (§5.3).
  const complete = recomputeComplete(chain);
  if (token.complete !== complete) {
    return fail(
      'complete_mismatch',
      `token says complete=${String(token.complete)}, the chain's chain_complete flags recompute to ${String(complete)}`,
    );
  }

  // Rows 3–5, per hop, ascending. See the note above on their order.
  const core = coreClaims(token);
  for (const [index, node] of chain.entries()) {
    const hop = index + 1;

    if (node.alg !== OCP_SIGNATURE_ALG) {
      return fail('alg_not_supported', `alg is "${String(node.alg)}", expected "${OCP_SIGNATURE_ALG}"`, hop);
    }

    let jwk: Ed25519PublicJwk;
    try {
      jwk = await resolveKey({ catalogId: node.catalog_id, kid: node.kid, hop });
    } catch (err) {
      if (err instanceof CryptoError) {
        // "Resolvable" in row 4 covers a kid that is present but unusable:
        // a key we cannot verify with is a key we did not find.
        if (err.code === 'key_not_found' || err.code === 'invalid_key') {
          return fail('key_not_found', err.message, hop);
        }
        if (err.code === 'alg_not_supported') return fail('alg_not_supported', err.message, hop);
      }
      throw err; // jwks_unavailable / jwks_expired / jwks_malformed — not a verdict.
    }

    if (!verifyChainNodeSignature({ jwk, core, chain, hopIndex: index })) {
      return fail(
        'signature_invalid',
        `hop ${hop} (${node.catalog_id}) does not verify against its chain prefix`,
        hop,
      );
    }
  }

  // Row 6 — only checkout settles.
  if (requirePurpose !== null && token.purpose !== requirePurpose) {
    return fail(
      'purpose_not_settleable',
      `purpose is "${token.purpose}", only "${requirePurpose}" settles`,
    );
  }

  // Row 7 — the report and the token must name the same provider.
  if (expectedProviderId !== undefined && token.provider_id !== expectedProviderId) {
    return fail(
      'provider_mismatch',
      `report names provider "${expectedProviderId}", token names "${token.provider_id}"`,
    );
  }

  // Rows 8, 9 — the validity window, measured at `at`.
  const iat = instant(token.iat);
  const exp = instant(token.exp);
  if (!iat || !exp) {
    return fail('chain_broken', `iat/exp are not usable timestamps: iat="${token.iat}" exp="${token.exp}"`);
  }
  if (at.getTime() < iat.getTime()) {
    return fail('token_not_yet_valid', `${at.toISOString()} is before iat ${token.iat}`);
  }
  if (at.getTime() > exp.getTime()) {
    return fail('token_expired', `${at.toISOString()} is after exp ${token.exp}`);
  }

  // Row 10 — last, so nothing below can reject a token whose jti we just spent.
  if (replayGuard) {
    const { registry, orderId, claim = true } = replayGuard;
    const held = claim ? (registry.claim(token.jti, orderId, exp) ? undefined : registry.orderOf(token.jti))
                       : registry.orderOf(token.jti);
    if (held !== undefined && held !== orderId) {
      return fail(
        'replayed_jti',
        `jti "${token.jti}" is already settled against order "${held}", not "${orderId}"`,
      );
    }
  }

  const last = chain[chain.length - 1]!;
  return {
    ok: true,
    complete,
    agentId: token.agent_id,
    settlingCatalogIds: chain.filter((node) => node.settles).map((node) => node.catalog_id),
    lastSignedAt: last.signed_at,
    hops: chain.length,
  };
}
