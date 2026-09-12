/**
 * JWKS loading, `kid` resolution, and TTL caching.
 *
 * Attribution spec §7.1 row 4 states the requirement this file implements:
 * "每一跳的 `kid` 在其 `catalog_id` 的 JWKS 中可解析". So the cache is keyed by
 * `catalog_id`, not by URL — a verifier holding a chain node knows the catalog
 * id and nothing else, and the URL is an implementation detail of discovery.
 *
 * Fetching is injected rather than imported. The verifier has to be runnable
 * offline (that is the whole point of the T3 demo: `curl` the key once, verify
 * with the network down), and a package that reaches for `fetch` on its own
 * cannot be tested for the failure paths that matter.
 */
import { assertEd25519PublicJwk, type Ed25519PublicJwk } from './keys';
import { CryptoError } from './errors';

/** Fetches the JWK Set document for a catalog. May throw; the cache maps it. */
export type JwksLoader = (catalogId: string) => Promise<unknown>;

export interface JwksCacheOptions {
  load: JwksLoader;
  /** How long a fetched set is served without refetching. Default 5 minutes. */
  ttlMs?: number;
  /**
   * Floor between two loads for the same catalog. Default 30 seconds.
   *
   * A `kid` miss against a *fresh* set is the normal symptom of key rotation,
   * so it triggers one opportunistic refetch. Without a floor, that is a free
   * amplification channel: tokens carrying random `kid`s would make the
   * verifier hammer the catalog once per token.
   */
  minRefetchIntervalMs?: number;
  /** Injectable clock, so TTL expiry is testable without sleeping. */
  now?: () => number;
}

interface CacheEntry {
  /** Raw JWKS entries by `kid`. Validated at lookup, not at load — see below. */
  keys: Map<string, unknown>;
  fetchedAt: number;
}

export interface JwksCacheStats {
  loads: number;
  cachedCatalogs: number;
}

/**
 * Parses a JWK Set into a `kid` index.
 *
 * Two decisions worth keeping:
 *
 * - **Non-Ed25519 keys are indexed, not dropped.** Dropping them would turn
 *   "this node published an ES256 key under that kid" into `key_not_found`,
 *   collapsing two of the eleven attribution error codes into one and making
 *   the failure unreadable. Suitability is decided at lookup.
 * - **A duplicate `kid` fails the whole set.** Picking either one means the
 *   verifier's answer depends on array order, which an attacker who can append
 *   to a JWKS would control.
 */
function indexJwkSet(doc: unknown, catalogId: string): Map<string, unknown> {
  if (typeof doc !== 'object' || doc === null || !Array.isArray((doc as { keys?: unknown }).keys)) {
    throw new CryptoError('jwks_malformed', `JWKS for ${catalogId} has no "keys" array`);
  }
  const keys = new Map<string, unknown>();
  for (const entry of (doc as { keys: unknown[] }).keys) {
    if (typeof entry !== 'object' || entry === null) {
      throw new CryptoError('jwks_malformed', `JWKS for ${catalogId} contains a non-object key`);
    }
    const kid = (entry as { kid?: unknown }).kid;
    if (typeof kid !== 'string' || kid.length === 0) {
      throw new CryptoError('jwks_malformed', `JWKS for ${catalogId} contains a key without a "kid"`);
    }
    if (keys.has(kid)) {
      throw new CryptoError('jwks_malformed', `JWKS for ${catalogId} declares kid ${kid} twice`);
    }
    keys.set(kid, entry);
  }
  return keys;
}

export class JwksCache {
  private readonly entries = new Map<string, CacheEntry>();
  /**
   * Last load *attempt* per catalog, successful or not. The rotation-probe
   * cooldown is measured from here rather than from `fetchedAt`, or a catalog
   * whose JWKS endpoint is down would be probed on every single token.
   */
  private readonly lastAttemptAt = new Map<string, number>();
  private readonly load: JwksLoader;
  private readonly ttlMs: number;
  private readonly minRefetchIntervalMs: number;
  private readonly now: () => number;
  private loads = 0;

  constructor(options: JwksCacheOptions) {
    this.load = options.load;
    this.ttlMs = options.ttlMs ?? 300_000;
    this.minRefetchIntervalMs = options.minRefetchIntervalMs ?? 30_000;
    this.now = options.now ?? (() => Date.now());
  }

  private isFresh(entry: CacheEntry): boolean {
    return this.now() - entry.fetchedAt < this.ttlMs;
  }

  private async fetchInto(catalogId: string): Promise<CacheEntry> {
    this.loads += 1;
    this.lastAttemptAt.set(catalogId, this.now());
    const doc = await this.load(catalogId);
    const entry: CacheEntry = { keys: indexJwkSet(doc, catalogId), fetchedAt: this.now() };
    this.entries.set(catalogId, entry);
    return entry;
  }

  /**
   * Resolves `kid` to a usable Ed25519 public key.
   *
   * Failure codes: `key_not_found`, `alg_not_supported`, `jwks_expired`,
   * `jwks_unavailable`, `jwks_malformed`.
   */
  async getVerificationKey(catalogId: string, kid: string): Promise<Ed25519PublicJwk> {
    const cached = this.entries.get(catalogId);

    if (cached && this.isFresh(cached)) {
      const hit = cached.keys.get(kid);
      if (hit !== undefined) return assertEd25519PublicJwk(hit, `${catalogId}#${kid}`);

      if (this.now() - (this.lastAttemptAt.get(catalogId) ?? cached.fetchedAt) < this.minRefetchIntervalMs) {
        throw new CryptoError('key_not_found', `kid ${kid} is not in the cached JWKS for ${catalogId}`);
      }
      // Opportunistic rotation probe. If it fails we still hold a valid set
      // that simply does not contain this kid, so the honest answer stays
      // `key_not_found` rather than a transport error.
      let refreshed: CacheEntry;
      try {
        refreshed = await this.fetchInto(catalogId);
      } catch {
        throw new CryptoError('key_not_found', `kid ${kid} is not in the JWKS for ${catalogId}`);
      }
      const found = refreshed.keys.get(kid);
      if (found === undefined) {
        throw new CryptoError('key_not_found', `kid ${kid} is not in the JWKS for ${catalogId}`);
      }
      return assertEd25519PublicJwk(found, `${catalogId}#${kid}`);
    }

    let entry: CacheEntry;
    try {
      entry = await this.fetchInto(catalogId);
    } catch (cause) {
      if (cause instanceof CryptoError && cause.code === 'jwks_malformed') throw cause;
      if (cached) {
        // Stale material is never used. A verifier that falls back to an
        // expired key set keeps accepting signatures from a key the node has
        // already revoked, which is exactly the window revocation exists to
        // close.
        this.entries.delete(catalogId);
        throw new CryptoError(
          'jwks_expired',
          `JWKS for ${catalogId} is past its ${this.ttlMs}ms TTL and could not be refetched; refusing to verify with expired key material`,
          { cause },
        );
      }
      throw new CryptoError('jwks_unavailable', `JWKS for ${catalogId} could not be loaded`, { cause });
    }

    const found = entry.keys.get(kid);
    if (found === undefined) {
      throw new CryptoError('key_not_found', `kid ${kid} is not in the JWKS for ${catalogId}`);
    }
    return assertEd25519PublicJwk(found, `${catalogId}#${kid}`);
  }

  /** Forgets one catalog, or all of them. For key-rotation hooks and tests. */
  invalidate(catalogId?: string): void {
    if (catalogId === undefined) {
      this.entries.clear();
      this.lastAttemptAt.clear();
    } else {
      this.entries.delete(catalogId);
      this.lastAttemptAt.delete(catalogId);
    }
  }

  stats(): JwksCacheStats {
    return { loads: this.loads, cachedCatalogs: this.entries.size };
  }
}

export interface DiscoveryJwksLoaderOptions {
  /** Maps a catalog id to its `/.well-known/ocp-catalog` URL. */
  wellKnownUrl: (catalogId: string) => string;
  /** Injected so this stays dependency-free and offline-testable. */
  fetchJson: (url: string) => Promise<unknown>;
}

/**
 * Builds a loader that goes `catalog_id` → discovery document → `jwks_url` →
 * JWK Set.
 *
 * `jwks_url` was added to `wellKnownCatalogDiscoverySchema` in the same change
 * as this file; before that, a catalog node had no protocol-level way to say
 * where its public keys live, which is the gap that made "商户自己去找公钥"
 * unanswerable.
 */
export function createDiscoveryJwksLoader(options: DiscoveryJwksLoaderOptions): JwksLoader {
  return async (catalogId: string) => {
    const discovery = await options.fetchJson(options.wellKnownUrl(catalogId));
    const jwksUrl = (discovery as { jwks_url?: unknown } | null)?.jwks_url;
    if (typeof jwksUrl !== 'string' || jwksUrl.length === 0) {
      throw new CryptoError('jwks_unavailable', `discovery document for ${catalogId} declares no jwks_url`);
    }
    return options.fetchJson(jwksUrl);
  };
}
