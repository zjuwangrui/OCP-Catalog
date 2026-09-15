/**
 * Offline verification of an attribution token — the merchant's half.
 *
 * The point of the exercise: a merchant who was handed a resolve response must
 * be able to decide *by itself* whether the attribution claim is real, using
 * nothing but the public key it already fetched. No callback to the catalog
 * node, no shared secret, no trust in the party presenting the token. If
 * verification needed the issuer online, the issuer could change its answer
 * after the fact, and there would be nothing to settle against.
 *
 * So this file is split in two, and the split is the whole demonstration:
 *
 *   `fetch`  — the online half. Pulls discovery → `jwks_url` → JWKS, and does
 *              one resolve. Plain HTTP; `curl` does the same job (see README).
 *   `verify` — the offline half. **Disables `globalThis.fetch` before reading
 *              anything**, then verifies from the saved files. If any check
 *              secretly needed the network, this crashes instead of passing.
 *
 * `verifyOffline` itself does no I/O and reads no clock beyond the `now` you
 * pass, which is what lets server.test.ts run it in-process.
 *
 * Scope: the §7.1 eligibility filter is **not** reimplemented here — it is
 * `verifyAttributionToken` in `@ocp-catalog/ocp-crypto`, called below. What
 * this file adds is the part that filter cannot know: whether the token is
 * about *this* resolve, from *this* node. Settlement-time state (replayed
 * `jti`, duplicate `order_id`) needs a report and a store, so it belongs to
 * the merchant script, not to a one-shot offline check.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  staticKeyResolver,
  verifyAttributionToken,
  type AttributionToken,
} from '@ocp-catalog/ocp-crypto';

export interface OfflineVerifyInput {
  /** `GET /.well-known/ocp-catalog` */
  discovery: unknown;
  /** `GET` whatever `discovery.jwks_url` pointed at */
  jwks: unknown;
  /** `POST /ocp/resolve` with `purpose: "checkout"` */
  resolved: unknown;
  now?: Date;
}

export type OfflineVerifyResult =
  | { ok: true; token: AttributionToken; agentId: string; settlingCatalogIds: string[]; hops: number }
  | { ok: false; error: string; detail: string };

const fail = (error: string, detail: string): OfflineVerifyResult => ({ ok: false, error, detail });

function findToken(resolved: unknown): AttributionToken | undefined {
  const bindings = (resolved as { action_bindings?: unknown })?.action_bindings;
  if (!Array.isArray(bindings)) return undefined;
  for (const binding of bindings) {
    const token = (binding as { attribution?: unknown })?.attribution;
    if (token && typeof token === 'object') return token as AttributionToken;
  }
  return undefined;
}

export async function verifyOffline(input: OfflineVerifyInput): Promise<OfflineVerifyResult> {
  const { discovery, jwks, resolved } = input;
  const now = input.now ?? new Date();
  const field = (source: unknown, name: string) => (source as Record<string, unknown>)?.[name];

  const token = findToken(resolved);
  if (!token) return fail('no_attribution', 'no action binding carried an `attribution` token');

  const discoveredId = field(discovery, 'catalog_id');
  if (typeof discoveredId !== 'string') {
    return fail('no_discovery', 'the discovery document declares no catalog_id');
  }

  // ---- §7.1, in §8's fixed order, from the shared implementation -----------
  // One JWKS, keyed by the node we discovered. A multi-node chain needs one
  // entry per hop's catalog_id, which is exactly what makes key discovery a
  // per-node lookup rather than a global key list.
  const verdict = await verifyAttributionToken({
    token,
    resolveKey: staticKeyResolver({ [discoveredId]: jwks as { keys?: unknown } }),
    at: now,
  });
  if (!verdict.ok) {
    const { code, hop } = verdict.error;
    return fail(code, hop === undefined ? verdict.error.message : `hop ${hop}: ${verdict.error.message}`);
  }

  // ---- bindings the spec filter cannot check -------------------------------
  // §7.1 answers "is this token real and settleable". It cannot answer "is it
  // about the thing I am looking at" — that needs the resolve beside it.
  const chain = token.chain;
  const lastHop = chain[chain.length - 1]!;
  if (lastHop.catalog_id !== discoveredId) {
    // Note this is the *last* hop, not `iss`. On a relayed chain `iss` is the
    // origin catalog, which is not the node we just talked to.
    return fail(
      'issuer_mismatch',
      `last hop is "${lastHop.catalog_id}", but we are talking to "${discoveredId}"`,
    );
  }

  // A token is a claim about a specific object. Without this, a valid token for
  // a €5 item could be presented against a €5000 one.
  for (const name of ['object_id', 'provider_id'] as const) {
    if (token[name] !== field(resolved, name)) {
      return fail(
        'object_mismatch',
        `token ${name} "${token[name]}" ≠ resolved "${String(field(resolved, name))}"`,
      );
    }
  }
  // `entry_id` only binds when this node minted the token. Core claims are
  // immutable across hops (§4.3), so a relayed token still names the *origin*
  // catalog's entry, which has no reason to match this node's id for it.
  if (token.iss === discoveredId && token.entry_id !== field(resolved, 'entry_id')) {
    return fail(
      'object_mismatch',
      `token entry_id "${token.entry_id}" ≠ resolved "${String(field(resolved, 'entry_id'))}"`,
    );
  }

  return {
    ok: true,
    token,
    agentId: verdict.agentId,
    settlingCatalogIds: verdict.settlingCatalogIds,
    hops: verdict.hops,
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const FILES = { discovery: 'discovery.json', jwks: 'jwks.json', resolved: 'resolve.json' } as const;

async function fetchArtifacts(baseUrl: string, dir: string): Promise<void> {
  const getJson = async (url: string) => {
    const res = await globalThis.fetch(url);
    if (!res.ok) throw new Error(`GET ${url} → ${res.status}`);
    return res.json();
  };

  const discovery = (await getJson(`${baseUrl}/.well-known/ocp-catalog`)) as { jwks_url?: string };
  if (!discovery.jwks_url) throw new Error('discovery declares no jwks_url — this node does not sign');
  const jwks = await getJson(discovery.jwks_url);

  const res = await globalThis.fetch(`${baseUrl}/ocp/resolve`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      entry_id: 'entry_example_inmemory_sku-001',
      purpose: 'checkout',
      attribution_context: { agent_id: 'agent_demo_shopper' },
    }),
  });
  const resolved = await res.json();

  mkdirSync(dir, { recursive: true });
  for (const [key, name] of Object.entries(FILES)) {
    writeFileSync(join(dir, name), `${JSON.stringify({ discovery, jwks, resolved }[key], null, 2)}\n`);
  }
  console.log(`Wrote ${Object.values(FILES).join(', ')} to ${dir}`);
}

function verifyFromDisk(dir: string): Promise<number> {
  // Cut the network before touching the files. Anything below that reaches for
  // it now throws, which is the only way "offline" is a claim and not a hope.
  globalThis.fetch = (() => {
    throw new Error('offline: verification must not touch the network');
  }) as unknown as typeof globalThis.fetch;

  const read = (name: string) => JSON.parse(readFileSync(join(dir, name), 'utf8')) as unknown;
  return verifyOffline({
    discovery: read(FILES.discovery),
    jwks: read(FILES.jwks),
    resolved: read(FILES.resolved),
  }).then((result) => {
    if (!result.ok) {
      console.error(`FAIL  ${result.error}: ${result.detail}`);
      return 1;
    }
    console.log('OK    attribution verified offline');
    console.log(`      agent:    ${result.agentId}`);
    console.log(`      hops:     ${result.hops}`);
    console.log(`      settles:  ${result.settlingCatalogIds.join(', ') || '(nobody)'}`);
    console.log(`      jti:      ${result.token.jti}`);
    console.log(`      expires:  ${result.token.exp}`);
    return 0;
  });
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (command === 'fetch') {
    await fetchArtifacts((rest[0] ?? 'http://localhost:4400').replace(/\/$/, ''), rest[1] ?? './.attribution');
    return 0;
  }
  if (command === 'verify') return verifyFromDisk(rest[0] ?? './.attribution');

  console.error('usage: offline-verify.ts fetch [baseUrl] [dir]');
  console.error('       offline-verify.ts verify [dir]');
  return 2;
}

if (import.meta.main) {
  process.exit(await main(process.argv.slice(2)));
}
