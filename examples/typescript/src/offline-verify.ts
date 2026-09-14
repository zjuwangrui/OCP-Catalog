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
 * `verifyOffline` itself is pure — no I/O, no clock beyond the `now` you pass —
 * which is what lets server.test.ts run it in-process.
 *
 * Scope: this is a *demonstration* verifier for one origin-issued token, not
 * the reusable one. Replay detection across resolves, key rotation, relay
 * chains, and per-hop error codes are the verifier's job in T4.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  MAX_CHAIN_LENGTH,
  assertEd25519PublicJwk,
  coreClaims,
  recomputeComplete,
  verifyChainNodeSignature,
  type AttributionToken,
  type Ed25519PublicJwk,
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
  | { ok: true; token: AttributionToken; agentId: string; settlingCatalogIds: string[] }
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

function findKey(jwks: unknown, kid: string): Ed25519PublicJwk | undefined {
  const keys = (jwks as { keys?: unknown })?.keys;
  if (!Array.isArray(keys)) return undefined;
  const match = keys.find((k) => (k as { kid?: unknown })?.kid === kid);
  return match ? assertEd25519PublicJwk(match, `JWKS entry ${kid}`) : undefined;
}

export function verifyOffline(input: OfflineVerifyInput): OfflineVerifyResult {
  const { discovery, jwks, resolved } = input;
  const now = input.now ?? new Date();

  const token = findToken(resolved);
  if (!token) return fail('no_attribution', 'no action binding carried an `attribution` token');

  // ---- structure, before any signature work (§5.4) -------------------------
  // Cheap checks first, and not only for speed: a malformed chain must be
  // rejected as malformed, not verified hop by hop until something happens to
  // fail. Otherwise an 800-hop chain is a free way to make a verifier work.
  const chain = token.chain;
  if (!Array.isArray(chain) || chain.length < 1 || chain.length > MAX_CHAIN_LENGTH) {
    return fail('chain_broken', `chain length must be 1..${MAX_CHAIN_LENGTH}`);
  }
  for (const [index, node] of chain.entries()) {
    if (node.hop !== index + 1) return fail('chain_broken', `hop ${node.hop} at position ${index + 1}`);
    const expectedRole = index === 0 ? 'origin' : 'relay';
    if (node.role !== expectedRole) return fail('chain_broken', `hop ${node.hop} must be ${expectedRole}`);
  }
  if (new Set(chain.map((n) => n.catalog_id)).size !== chain.length) {
    return fail('chain_broken', 'a catalog_id appears twice — a node cannot be its own upstream');
  }

  // ---- `complete` is recomputed, never read (§5.3) -------------------------
  // It sits outside every signature, so believing the field as sent would let
  // anyone flip an incomplete chain to complete with a text editor.
  const recomputed = recomputeComplete(chain);
  if (recomputed !== token.complete) {
    return fail('complete_mismatch', `token says complete=${token.complete}, chain says ${recomputed}`);
  }

  // ---- claim bindings ------------------------------------------------------
  if (token.purpose !== 'checkout') {
    return fail('not_settleable', `purpose is "${token.purpose}"; only checkout settles (§7.1)`);
  }
  if (new Date(token.exp).getTime() <= now.getTime()) {
    return fail('token_expired', `exp ${token.exp} is in the past`);
  }
  const catalogId = (discovery as { catalog_id?: unknown })?.catalog_id;
  if (token.iss !== catalogId) {
    return fail('issuer_mismatch', `token iss "${token.iss}" is not the node we discovered ("${catalogId}")`);
  }
  // A token is a claim about *this* entry. Without these three, a valid token
  // for a €5 item could be replayed against a €5000 one.
  for (const [field, expected] of [
    ['entry_id', (resolved as Record<string, unknown>).entry_id],
    ['object_id', (resolved as Record<string, unknown>).object_id],
    ['provider_id', (resolved as Record<string, unknown>).provider_id],
  ] as const) {
    if (token[field] !== expected) {
      return fail('object_mismatch', `token ${field} "${token[field]}" ≠ resolved "${String(expected)}"`);
    }
  }

  // ---- signatures ----------------------------------------------------------
  const core = coreClaims(token);
  for (const [index, node] of chain.entries()) {
    const jwk = findKey(jwks, node.kid);
    if (!jwk) return fail('key_not_found', `hop ${node.hop}: no key "${node.kid}" in the fetched JWKS`);
    if (!verifyChainNodeSignature({ jwk, core, chain, hopIndex: index })) {
      return fail('signature_invalid', `hop ${node.hop} (${node.catalog_id}) does not verify`);
    }
  }

  return {
    ok: true,
    token,
    agentId: token.agent_id,
    settlingCatalogIds: chain.filter((n) => n.settles).map((n) => n.catalog_id),
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

function verifyFromDisk(dir: string): number {
  // Cut the network before touching the files. Anything below that reaches for
  // it now throws, which is the only way "offline" is a claim and not a hope.
  globalThis.fetch = (() => {
    throw new Error('offline: verification must not touch the network');
  }) as unknown as typeof globalThis.fetch;

  const read = (name: string) => JSON.parse(readFileSync(join(dir, name), 'utf8')) as unknown;
  const result = verifyOffline({
    discovery: read(FILES.discovery),
    jwks: read(FILES.jwks),
    resolved: read(FILES.resolved),
  });

  if (!result.ok) {
    console.error(`FAIL  ${result.error}: ${result.detail}`);
    return 1;
  }
  console.log('OK    attribution verified offline');
  console.log(`      agent:    ${result.agentId}`);
  console.log(`      settles:  ${result.settlingCatalogIds.join(', ') || '(nobody)'}`);
  console.log(`      jti:      ${result.token.jti}`);
  console.log(`      expires:  ${result.token.exp}`);
  return 0;
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
