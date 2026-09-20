/**
 * A minimal, spec-valid OCP Catalog Node in TypeScript.
 *
 * Serves five endpoints from ~3 in-memory products, with no database, no
 * vendor client, and no auth. It is the smallest thing that answers the OCP
 * Catalog read surface:
 *
 *   GET  /.well-known/ocp-catalog   discovery（已签名）
 *   GET  /.well-known/jwks.json     the node's public signing keys
 *   GET  /ocp/manifest              capabilities（已签名）
 *   GET  /ocp/health                liveness
 *   GET  /ocp/contracts             object contracts (empty — read-only node)
 *   POST /ocp/query                 keyword search over products
 *   POST /ocp/resolve               resolve one entry into actions
 *
 * The response shapes match @ocp-catalog/ocp-schema; see server.test.ts, which
 * parses every response through those schemas to prove conformance.
 */
import {
  appendRelayHop,
  issueOriginToken,
  signDocument,
  verifyAttributionToken,
  type AttributionToken,
} from '@ocp-catalog/ocp-crypto';
import { PRODUCTS, type Product } from './products';
import { SIGNING_KEY, jwkSet } from './signing-key';
import { trustUpstream, trustedUpstreams, upstreamKeyResolver } from './upstream-keys';

const CATALOG_ID = process.env.CATALOG_ID ?? 'cat_example_typescript';
const CATALOG_NAME = process.env.CATALOG_NAME ?? 'Example TypeScript Catalog';
const PROVIDER_ID = 'example_inmemory';
const PORT = Number(process.env.PORT ?? 4400);
const BASE_URL = (process.env.PUBLIC_BASE_URL ?? `http://localhost:${PORT}`).replace(/\/$/, '');

const entryId = (product: Product) => `entry_${PROVIDER_ID}_${product.id}`;

// This node can always verify its own hops, so its key belongs in the upstream
// set. Without it, a chain that already passed through here fails at
// `key_not_found` before the §4.4 loop check ever runs — the same refusal, but
// reported as "I don't know that catalog" about itself.
trustUpstream(CATALOG_ID, jwkSet());

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function discoveryPayload() {
  return {
    ocp_version: '1.0',
    kind: 'WellKnownCatalogDiscovery',
    catalog_id: CATALOG_ID,
    catalog_name: CATALOG_NAME,
    manifest_url: `${BASE_URL}/ocp/manifest`,
    health_url: `${BASE_URL}/ocp/health`,
    query_url: `${BASE_URL}/ocp/query`,
    resolve_url: `${BASE_URL}/ocp/resolve`,
    contracts_url: `${BASE_URL}/ocp/contracts`,
    // Published because this node signs attribution tokens. Without it a
    // merchant holding a token has no protocol-level route to the public key,
    // and an unverifiable token is worth nothing at settlement time.
    jwks_url: `${BASE_URL}/.well-known/jwks.json`,
  };
}

function manifestPayload() {
  return {
    ocp_version: '1.0',
    kind: 'CatalogManifest',
    id: `manifest_${CATALOG_ID}`,
    catalog_id: CATALOG_ID,
    catalog_name: CATALOG_NAME,
    description: 'Minimal in-memory OCP Catalog Node example (TypeScript).',
    registry_visibility: 'public',
    endpoints: {
      health: { url: `${BASE_URL}/ocp/health`, method: 'GET' },
      query: { url: `${BASE_URL}/ocp/query`, method: 'POST' },
      resolve: { url: `${BASE_URL}/ocp/resolve`, method: 'POST' },
      contracts: { url: `${BASE_URL}/ocp/contracts`, method: 'GET' },
    },
    query_capabilities: [
      {
        capability_id: 'ocp.example.product.search.v1',
        name: 'Keyword product search',
        description: 'Case-insensitive keyword match over the in-memory product list.',
        query_packs: [
          {
            pack_id: 'ocp.query.keyword.v1',
            description: 'Keyword search over title, summary, brand, and category.',
            query_modes: ['keyword'],
          },
        ],
        supports_explain: true,
        supports_resolve: true,
      },
    ],
    // Required by the schema even for a read-only node that ingests nothing.
    object_contracts: [],
    /**
     * Signing is not a federation feature, but `trust_strategy` lives under
     * `federation` — both this object and the manifest's top level are
     * `additionalProperties: false`, so the declaration has to go here.
     *
     * `trust_tier` is deliberately absent. The schema allows a node to write
     * `verified` about itself, and a self-asserted tier is precisely the thing
     * a signature exists to replace: whoever verifies the signature below
     * decides the tier (`trustCeilingFor()`, crypto/v1 §9). The two booleans
     * are different — they describe what this node *does*, and the signature
     * on this very document makes them checkable rather than claimed.
     */
    federation: {
      mode: 'disabled',
      node_role: 'source_catalog',
      trust_strategy: {
        manifest_signed: true,
        signature_algorithms: ['EdDSA'],
        downgrade_invalidates_cache: true,
      },
    },
  };
}

/**
 * Both documents are signed once, at startup, rather than per request.
 *
 * They are static — every member derives from an environment variable read at
 * module load — so re-signing per request would only jitter `signed_at` and
 * burn a signature per hit. A cached copy stays verifiable for as long as the
 * key does, which is the whole point of signing the document rather than the
 * transport.
 *
 * No `expires_at`: it is optional (crypto/v1 §5.3), and this example's key is
 * ephemeral unless `OCP_SIGNING_JWK` is set. A real node that rotates keys
 * should set one shorter than its rotation window, so a document cannot
 * outlive the key that proves it.
 */
const SIGNED_DISCOVERY = signDocument({
  document: discoveryPayload(),
  privateJwk: SIGNING_KEY.privateJwk,
  kid: SIGNING_KEY.kid,
});

const SIGNED_MANIFEST = signDocument({
  document: manifestPayload(),
  privateJwk: SIGNING_KEY.privateJwk,
  kid: SIGNING_KEY.kid,
});

function health() {
  return {
    ocp_version: '1.0',
    kind: 'CatalogHealth',
    catalog_id: CATALOG_ID,
    status: 'healthy',
    ready: true,
    checked_at: new Date().toISOString(),
  };
}

function contracts() {
  return {
    ocp_version: '1.0',
    kind: 'ObjectContractList',
    catalog_id: CATALOG_ID,
    object_contracts: [],
    note: 'Read-only example node; it does not accept provider object ingestion.',
  };
}

function toEntry(product: Product) {
  return {
    kind: 'CatalogEntry',
    catalog_id: CATALOG_ID,
    entry_id: entryId(product),
    provider_id: PROVIDER_ID,
    object_id: product.id,
    object_type: 'ocp.commerce.product',
    title: product.title,
    summary: product.summary,
    attributes: {
      brand: product.brand,
      category: product.category,
      price: { currency: product.currency, amount: product.amount },
      inventory: { availability_status: product.availability },
      product_url: product.url,
    },
  };
}

function query(body: { query?: string; limit?: number }) {
  const term = (body.query ?? '').trim().toLowerCase();
  const limit = Math.min(Math.max(body.limit ?? 20, 1), 50);
  const matches = term
    ? PRODUCTS.filter((p) =>
        [p.title, p.summary, p.brand, p.category].some((f) => f.toLowerCase().includes(term)),
      )
    : PRODUCTS;
  const page = matches.slice(0, limit);
  return {
    ocp_version: '1.0',
    kind: 'CatalogQueryResult',
    id: `qry_${crypto.randomUUID()}`,
    catalog_id: CATALOG_ID,
    query_pack: 'ocp.query.keyword.v1',
    query_mode: 'keyword',
    query: body.query ?? '',
    result_count: page.length,
    page: { limit, offset: 0, has_more: false },
    entries: page.map((product) => ({
      entry: toEntry(product),
      score: 1,
      explain: [`Keyword match for "${body.query ?? ''}".`],
    })),
  };
}

/** The `attribution_context` an agent may send on a resolve request (§6.1). */
interface AttributionContext {
  agent_id?: unknown;
  agent_identity_source?: unknown;
  upstream_token?: unknown;
}

interface ResolveBody {
  entry_id?: string;
  purpose?: unknown;
  attribution_context?: unknown;
}

/**
 * Mints an attribution token for this resolve, or returns `undefined`.
 *
 * Two gates decide whether anything is signed at all, and each is a reason not
 * to sign rather than a formality:
 *
 *  - `purpose` must be `checkout`. Spec §7.1: only checkout is settleable, and
 *    a signed token for a `view` would be a settlement claim over a page load.
 *  - `attribution_context.agent_id` must be present. Attribution says *who*
 *    brought the buyer; there is nobody to name without it. This is also the
 *    §10.2 compatibility path — an agent that sends no context gets exactly the
 *    response it got before this node learned to sign.
 *
 * Past those, the presence of an `upstream_token` decides *what* is signed: a
 * fresh one-hop `origin` chain, or one more `relay` hop on the chain that
 * arrived. Minting a fresh chain over an upstream token would erase the hops
 * before it and claim origin for traffic somebody else found.
 */
function mintAttribution(product: Product, body: ResolveBody): Promise<AttributionToken | undefined> | AttributionToken | undefined {
  if (body.purpose !== 'checkout') return undefined;

  const context = body.attribution_context as AttributionContext | undefined;
  if (!context || typeof context.agent_id !== 'string' || context.agent_id.length === 0) return undefined;

  if (context.upstream_token !== undefined) return relayAttribution(product, context.upstream_token);

  return issueOriginToken({
    privateJwk: SIGNING_KEY.privateJwk,
    kid: SIGNING_KEY.kid,
    catalogId: CATALOG_ID,
    agentId: context.agent_id,
    agentIdentitySource: context.agent_identity_source === 'external' ? 'external' : undefined,
    entryId: entryId(product),
    objectId: product.id,
    providerId: PROVIDER_ID,
    purpose: 'checkout',
  });
}

/** A shallow shape check before handing anything to `appendRelayHop`. */
function asUpstreamToken(value: unknown): AttributionToken | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const candidate = value as Partial<AttributionToken>;
  if (candidate.kind !== 'AttributionToken' || !Array.isArray(candidate.chain)) return undefined;
  return candidate as AttributionToken;
}

/**
 * Appends this node as a `relay` hop on an upstream token — **after verifying
 * the chain it is about to co-sign.**
 *
 * `entry_id` is *not* required to match this node's entry, and deliberately so.
 * Core claims are immutable across hops (§4.3) — every upstream hop has already
 * signed over them — so they keep naming the origin catalog's entry. What must
 * match is `object_id`: relaying a token minted for a different product would
 * attribute this sale to whoever found that one.
 *
 * ## Why the upstream chain is verified first
 *
 * §5.2 makes hop N's signature cover hops 1..N−1. Co-signing an unverified
 * chain therefore does not merely pass a forgery along — it puts this node's
 * key on it, permanently, and a merchant verifying later sees a valid hop from
 * a node it has a relationship with sitting on top of a hop nobody can check.
 * The forger needs no key of their own; they need one relay that signs
 * whatever arrives.
 *
 * The check is the full §7.1 filter, not a signature loop, because the other
 * rows matter here too: an expired chain (row 9) or a `view` token (row 6)
 * cannot be made settleable by adding a hop, so appending one only produces a
 * token that will be rejected further downstream with this node named on it.
 *
 * Row 7 (`provider_id`) and row 10 (`jti` replay) are *not* checked, and that
 * is not an omission. Both are settlement-time rows: row 7 compares against a
 * report's `provider_id`, which does not exist yet, and claiming the `jti`
 * here would burn a token at resolve time for an order that may never happen.
 *
 * Keys come from {@link upstreamKeyResolver} — see `upstream-keys.ts` for the
 * configuration, and for why "no keys configured" means "no relay" rather than
 * "relay anyway".
 *
 * Returns `undefined` rather than an error response whenever the upstream
 * token is unusable, which keeps this node's resolve contract unchanged
 * (§10.2). The agent gets the same response it would have got without
 * attribution.
 */
async function relayAttribution(product: Product, upstream: unknown): Promise<AttributionToken | undefined> {
  const token = asUpstreamToken(upstream);
  if (!token || token.object_id !== product.id) return undefined;

  let verdict;
  try {
    verdict = await verifyAttributionToken({ token, resolveKey: upstreamKeyResolver });
  } catch {
    // §7.3 — a key server that is unreachable, stale or malformed is not a
    // statement about the token, so this is not evidence of forgery. It is
    // also not evidence of authenticity, and signing is the irreversible
    // direction, so the answer is still no.
    return undefined;
  }

  if (!verdict.ok) {
    // The chain is forged, broken, expired, or comes from a catalog this node
    // holds no keys for. Naming the reason in a log is the useful thing here;
    // a production node should count these per upstream `catalog_id`, because
    // a partner that suddenly produces key_not_found has rotated a key and a
    // partner that produces signature_invalid has a different problem.
    console.warn(
      `refusing to relay for "${token.iss}": ${verdict.error.code} — ${verdict.error.message}` +
        (trustedUpstreams().length === 0
          ? ' (no upstream JWKS configured; set OCP_UPSTREAM_JWKS or call trustUpstream)'
          : ''),
    );
    return undefined;
  }

  try {
    return appendRelayHop({
      privateJwk: SIGNING_KEY.privateJwk,
      kid: SIGNING_KEY.kid,
      catalogId: CATALOG_ID,
      token,
      // This node received the token directly in the resolve request, with no
      // catalog hop in between that went unrecorded.
      chainComplete: true,
      // It is in the money flow: it put the object in front of the buyer too.
      settles: true,
    });
  } catch {
    // Looping or already-full chains (§5.4 / §4.4) — both structural, and both
    // survive verification because a full chain is a valid chain. Refusing to
    // sign is the point; the chain is not made better by this node's key.
    return undefined;
  }
}

async function resolve(body: ResolveBody): Promise<Response> {
  const product = PRODUCTS.find((p) => entryId(p) === body.entry_id);
  if (!product) {
    return json(
      { error: { code: 'not_found', message: `Unknown entry_id: ${body.entry_id ?? '(missing)'}` } },
      404,
    );
  }
  const now = new Date().toISOString();

  const actionBindings: Record<string, unknown>[] = [
    {
      action_id: 'view',
      action_type: 'url',
      label: 'View product',
      entrypoint: { url: product.url, method: 'GET' },
    },
  ];

  // The token rides on the binding that leads to money, not on the response as
  // a whole: a resolve can offer several actions and only some of them settle.
  const attribution = await mintAttribution(product, body);
  if (body.purpose === 'checkout') {
    actionBindings.push({
      action_id: 'checkout',
      action_type: 'url',
      label: 'Buy now',
      entrypoint: { url: product.url, method: 'GET' },
      requires_user_confirmation: true,
      ...(attribution ? { attribution } : {}),
    });
  }

  return json({
    ocp_version: '1.0',
    kind: 'ResolvableReference',
    id: `res_${crypto.randomUUID()}`,
    catalog_id: CATALOG_ID,
    entry_id: entryId(product),
    commercial_object_id: `co_${product.id}`,
    object_id: product.id,
    object_type: 'ocp.commerce.product',
    provider_id: PROVIDER_ID,
    title: product.title,
    visible_attributes: {
      brand: product.brand,
      category: product.category,
      price: { currency: product.currency, amount: product.amount },
      availability: product.availability,
    },
    action_bindings: actionBindings,
    freshness: { object_updated_at: product.updated_at, resolved_at: now },
    // Resolutions are short-lived; expire in one hour.
    expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  });
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  try {
    const parsed = await request.json();
    return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

export async function handle(request: Request): Promise<Response> {
  const { pathname } = new URL(request.url);
  const { method } = request;

  if (method === 'GET' && pathname === '/.well-known/ocp-catalog') return json(SIGNED_DISCOVERY);
  if (method === 'GET' && pathname === '/.well-known/jwks.json') return json(jwkSet());
  if (method === 'GET' && pathname === '/ocp/manifest') return json(SIGNED_MANIFEST);
  if (method === 'GET' && pathname === '/ocp/health') return json(health());
  if (method === 'GET' && pathname === '/ocp/contracts') return json(contracts());
  if (method === 'POST' && pathname === '/ocp/query') return json(query(await readJson(request)));
  if (method === 'POST' && pathname === '/ocp/resolve') return resolve(await readJson(request));

  return json({ error: { code: 'not_found', message: `No route for ${method} ${pathname}` } }, 404);
}

// Start the server unless imported by a test.
if (import.meta.main) {
  Bun.serve({ port: PORT, fetch: handle });
  console.log(`Example TypeScript OCP Catalog Node listening on ${BASE_URL}`);
}
