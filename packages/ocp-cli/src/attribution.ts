/**
 * `ocp attribution verify` and `--verify-attribution` — the decision half.
 *
 * Deliberately free of `@ocp-catalog/ocp-client` and of `node:fs`. Two reasons,
 * and the second is the one that matters:
 *
 *   - `index.ts` cannot be run by a plain Node harness (the client uses a
 *     constructor parameter property, which strip-only TypeScript rejects), so
 *     anything that lives beside it is untestable here. This module is tested.
 *   - "did this token verify" is a pure question. Mixing the HTTP fetch and the
 *     file reads into it would mean the only way to test a `key_not_found` is to
 *     stand up a server that fails to serve a key.
 *
 * So the caller does the I/O and hands in loaded JSON. The §7.1 filter itself is
 * not reimplemented — it is `verifyAttributionToken` from `ocp-crypto`.
 */
import {
  staticKeyResolver,
  verifyAttributionToken,
  type AttributionPurpose,
  type AttributionToken,
} from '@ocp-catalog/ocp-crypto';

/** One `--jwks <catalog_id>=<file-or-url>` pair, already split. */
export type JwksSpec = { catalogId: string; source: string };

export type AttributionVerification =
  | {
      ok: true;
      jti: string;
      agent_id: string;
      /** §7.3 — who the catalog-side payout is owed to, in hop order. */
      settles: string[];
      /** §5.3 recomputed, never read off the token. */
      complete: boolean;
      hops: number;
      /** §7.2 — the last-touch sort key. */
      last_signed_at: string;
      purpose: string;
      expires_at: string;
    }
  | {
      ok: false;
      error: {
        code: string;
        /** The lowest failing hop (§5.2), i.e. the tamper site. Absent when the failure is not per-hop. */
        hop?: number;
        message: string;
      };
    };

/**
 * Splits `cat_origin=./origin-jwks.json` into its two halves.
 *
 * Splits on the **first** `=` because a JWKS source is a URL and URLs contain
 * `=` in query strings; splitting on the last one would silently truncate
 * `https://a.example/jwks?v=2` to a catalog id of `https://a.example/jwks?v`.
 */
export function parseJwksSpec(spec: string): JwksSpec {
  const at = spec.indexOf('=');
  if (at <= 0 || at === spec.length - 1) {
    throw new Error(
      `--jwks expects "<catalog_id>=<file-or-url>", got "${spec}". ` +
        `Run "ocp attribution verify --token <file>" without --jwks to list the catalog ids this token needs.`,
    );
  }
  return { catalogId: spec.slice(0, at), source: spec.slice(at + 1) };
}

/**
 * Pulls the token out of whatever the user pointed at: a bare `AttributionToken`,
 * a `ResolvableReference` carrying one on an action binding, or a
 * `ConversionReport`.
 *
 * Accepting all three is not convenience. The three are what a merchant
 * actually has on disk at the three moments it might want to check — the
 * resolve response it just received, the report it is about to file, and the
 * token somebody emailed it to dispute a payout.
 */
export function extractAttributionToken(payload: unknown): AttributionToken | undefined {
  const isToken = (value: unknown): value is AttributionToken =>
    typeof value === 'object' && value !== null && (value as { kind?: unknown }).kind === 'AttributionToken';

  if (isToken(payload)) return payload;

  const record = payload as Record<string, unknown> | null;
  if (!record || typeof record !== 'object') return undefined;

  if (isToken(record.attribution_token)) return record.attribution_token;
  if (isToken(record.attribution)) return record.attribution;

  const bindings = record.action_bindings;
  if (Array.isArray(bindings)) {
    for (const binding of bindings) {
      const token = (binding as { attribution?: unknown } | null)?.attribution;
      if (isToken(token)) return token;
    }
  }
  return undefined;
}

/**
 * Every `catalog_id` whose JWKS is needed to verify this token, in hop order and
 * without duplicates.
 *
 * This exists so the CLI can tell a user *what to fetch* instead of making them
 * discover it one `key_not_found` at a time. On a relayed chain it is not one
 * id and it is not `iss`: §5.2 has every hop sign, so every hop's key is needed,
 * and `iss` names only the origin.
 */
export function requiredCatalogIds(token: AttributionToken): string[] {
  const seen: string[] = [];
  for (const node of token.chain) {
    if (!seen.includes(node.catalog_id)) seen.push(node.catalog_id);
  }
  return seen;
}

export interface VerifyAttributionInput {
  /** An `AttributionToken`, or any of the documents that carry one. */
  payload: unknown;
  /** `catalog_id` → that node's JWKS document, already loaded. */
  jwks: Record<string, unknown>;
  /**
   * The moment to judge the token at (§7.1 rows 8/9). A settler passes its
   * report's `occurred_at`; a bare `verify` has no report and defaults to now.
   */
  at?: Date;
  /** §7.1 row 7. Omitted when the caller has no report to match against. */
  expectedProviderId?: string;
  /**
   * §7.1 row 6. `null` checks the cryptography of a non-settleable token — a
   * `view` token is legitimately signed, it just cannot be settled against, and
   * "is this signature real" is still a fair question to ask about one.
   */
  requirePurpose?: AttributionPurpose | null;
}

/** Runs §7.1 rows 1–9 and shapes the result for JSON output. Row 10 needs a store; row 11 needs a report. */
export async function verifyAttributionPayload(
  input: VerifyAttributionInput,
): Promise<AttributionVerification> {
  const token = extractAttributionToken(input.payload);
  if (!token) {
    return {
      ok: false,
      error: {
        code: 'no_attribution',
        message:
          'no AttributionToken found — expected a token, a resolve response with an action binding ' +
          'carrying one, or a ConversionReport',
      },
    };
  }

  const missing = requiredCatalogIds(token).filter((id) => !(id in input.jwks));
  if (missing.length > 0) {
    // Reported before verification rather than as `key_not_found`, because the
    // two say different things. `key_not_found` means the node published a key
    // set that does not contain this `kid`; this means the operator never
    // supplied that node's key set at all, and the fix is a flag, not a dispute.
    return {
      ok: false,
      error: {
        code: 'jwks_not_supplied',
        message:
          `no JWKS supplied for ${missing.map((id) => `"${id}"`).join(', ')}. ` +
          `This chain is ${token.chain.length} hop(s) and needs one --jwks per catalog id: ` +
          requiredCatalogIds(token).join(', '),
      },
    };
  }

  const verdict = await verifyAttributionToken({
    token,
    resolveKey: staticKeyResolver(input.jwks as Record<string, { keys?: unknown }>),
    at: input.at,
    ...(input.expectedProviderId === undefined ? {} : { expectedProviderId: input.expectedProviderId }),
    ...(input.requirePurpose === undefined ? {} : { requirePurpose: input.requirePurpose }),
  });

  if (!verdict.ok) {
    return {
      ok: false,
      error: {
        code: verdict.error.code,
        ...(verdict.error.hop === undefined ? {} : { hop: verdict.error.hop }),
        message: verdict.error.message,
      },
    };
  }

  return {
    ok: true,
    jti: token.jti,
    agent_id: verdict.agentId,
    settles: verdict.settlingCatalogIds,
    complete: verdict.complete,
    hops: verdict.hops,
    last_signed_at: verdict.lastSignedAt,
    purpose: token.purpose,
    expires_at: token.exp,
  };
}

/**
 * Binds a token to the resolve it arrived on — the part §7.1 structurally
 * cannot check, because it sees the token and not the response beside it.
 *
 * Without this, a valid token for a cheap item can be presented against an
 * expensive one: every signature still verifies, because nothing in the chain
 * was forged. The mismatch is in what the token is being *pointed at*.
 */
export function checkResolveBinding(
  token: AttributionToken,
  resolved: unknown,
): { ok: true } | { ok: false; error: { code: string; message: string } } {
  const field = (name: string) => (resolved as Record<string, unknown> | null)?.[name];

  for (const name of ['object_id', 'provider_id'] as const) {
    if (token[name] !== field(name)) {
      return {
        ok: false,
        error: {
          code: 'object_mismatch',
          message: `token ${name} "${token[name]}" does not match the resolved "${String(field(name))}"`,
        },
      };
    }
  }

  // `entry_id` binds only when this node minted the token. Core claims are
  // immutable across hops (§4.3), so a relayed token still names the origin
  // catalog's entry id, which the relaying node has no reason to reuse.
  if (token.iss === field('catalog_id') && token.entry_id !== field('entry_id')) {
    return {
      ok: false,
      error: {
        code: 'object_mismatch',
        message: `token entry_id "${token.entry_id}" does not match the resolved "${String(field('entry_id'))}"`,
      },
    };
  }

  return { ok: true };
}
