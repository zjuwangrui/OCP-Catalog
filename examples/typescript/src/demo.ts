/**
 * The six assertions — `docs/proposals/ocp-attribution-2w-plan.md`, week 2 Friday.
 *
 * Two of them prove the attribution chain **works**. Four prove it **cannot be
 * fooled**. In a revenue-share setting the last four are where the value is: a
 * mechanism that only demonstrates the happy path is a mechanism nobody should
 * settle money against.
 *
 * | # | assertion | what would be broken if it failed |
 * |---|---|---|
 * | 1 | query → resolve → issue → verify → report → adjudicate | the loop does not close |
 * | 2 | three-hop chain verifies per hop, `complete = true` | relays cannot be paid |
 * | 3 | tampering `agent_id` fails verification | anyone can reassign a sale |
 * | 4 | past `exp` is rejected | a token is a permanent claim |
 * | 5 | the same `jti` on a second order is rejected | one referral, many payouts |
 * | 6 | the same `order_id` reported twice settles once | one sale, many payouts |
 *
 * ## No network by default, and that is not a shortcut
 *
 * `server.ts` exports `handle(request): Response` — the whole node, minus the
 * socket. Calling it directly runs the same code path a real request does, and
 * makes this script a single command instead of "start a server in another
 * terminal first". Pass a base URL to route over real HTTP instead; both
 * transports run the identical assertions.
 *
 *     bun run demo                          # in-process
 *     bun run demo http://localhost:4400    # over the wire
 *
 * The §7.1 filter, adjudication and dedup are **not** reimplemented here. They
 * are `ocp-crypto`, called below. A demo that reimplemented them could pass
 * while the library was broken, which is the one thing a demo must not do.
 */
import {
  JtiRegistry,
  SettlementLedger,
  appendRelayHop,
  generateEd25519KeyPair,
  publicJwkOf,
  settleOrder,
  staticKeyResolver,
  verifyAttributionToken,
  type AttributionToken,
  type ConversionReport,
} from '@ocp-catalog/ocp-crypto';
import { handle } from './server';
import { buildReport } from './settle';

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

type Transport = (path: string, body?: unknown) => Promise<unknown>;

function inProcess(): Transport {
  return async (path, body) => {
    const response = await handle(
      new Request(`http://localhost${path}`, {
        ...(body === undefined
          ? {}
          : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
      }),
    );
    return response.json();
  };
}

function overHttp(baseUrl: string): Transport {
  return async (path, body) => {
    const response = await fetch(`${baseUrl}${path}`, {
      ...(body === undefined
        ? {}
        : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
    });
    if (!response.ok) throw new Error(`${path} responded ${response.status}`);
    return response.json();
  };
}

// ---------------------------------------------------------------------------
// Assertion bookkeeping
// ---------------------------------------------------------------------------

let failures = 0;

function assert(index: number, claim: string, ok: boolean, detail: string): void {
  if (!ok) failures += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${index}. ${claim}`);
  console.log(`      ${detail}`);
}

const field = (value: unknown, name: string) => (value as Record<string, unknown>)?.[name];

function tokenOf(resolved: unknown): AttributionToken {
  const bindings = field(resolved, 'action_bindings');
  if (!Array.isArray(bindings)) throw new Error('resolve returned no action_bindings');
  for (const binding of bindings) {
    const token = (binding as { attribution?: AttributionToken }).attribution;
    if (token) return token;
  }
  throw new Error('no action binding carried an attribution token — is purpose "checkout"?');
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/** Exported so a runner can drive the assertions without being the entry module. */
export async function main(argv: string[]): Promise<number> {
  const baseUrl = argv[0];
  const send = baseUrl ? overHttp(baseUrl.replace(/\/$/, '')) : inProcess();
  console.log(`OCP attribution — six assertions (${baseUrl ? `over HTTP to ${baseUrl}` : 'in-process'})\n`);

  // ---- keys -----------------------------------------------------------------
  const discovery = await send('/.well-known/ocp-catalog');
  const catalogId = String(field(discovery, 'catalog_id'));
  const jwksUrl = String(field(discovery, 'jwks_url'));
  const nodeJwks = await send(new URL(jwksUrl).pathname);

  // Two downstream catalogs, played by this script. They are what makes a
  // three-hop chain possible against a single example node, and they sign with
  // their own keys — nothing here can mint a hop for the node above.
  const relayB = generateEd25519KeyPair();
  const relayC = generateEd25519KeyPair();
  const jwksFor = (pair: typeof relayB) => ({
    keys: [{ ...publicJwkOf(pair.privateJwk), kid: pair.kid, alg: 'EdDSA', use: 'sig' }],
  });
  const keys = {
    [catalogId]: nodeJwks as { keys?: unknown },
    cat_demo_relay_b: jwksFor(relayB),
    cat_demo_relay_c: jwksFor(relayC),
  };
  const resolveKey = staticKeyResolver(keys);

  // ---- 1. the whole loop ----------------------------------------------------
  const found = await send('/ocp/query', { query: 'headphones', limit: 1 });
  const entries = field(found, 'entries');
  // A query result row is `{ entry, score, explain }` — the entry is nested,
  // because the score belongs to this match rather than to the object.
  const first = Array.isArray(entries) && entries.length > 0 ? field(entries[0], 'entry') : undefined;
  const entryId = first ? String(field(first, 'entry_id')) : '';
  if (!entryId) throw new Error('query returned no entries — nothing to resolve');

  const resolved = await send('/ocp/resolve', {
    entry_id: entryId,
    purpose: 'checkout',
    attribution_context: { agent_id: 'agent_demo_shopper' },
  });
  const token = tokenOf(resolved);

  const ledger = new SettlementLedger();
  const jtiRegistry = new JtiRegistry();
  const report = buildReport({
    resolved,
    orderId: 'ord_demo_1',
    reportId: 'rep_demo_1',
    amountMinor: 12900,
    currency: 'CNY',
    occurredAt: new Date(),
  });
  const settled = await settleOrder({ reports: [report], resolveKey, ledger, jtiRegistry });

  assert(
    1,
    'query → resolve → issue → verify → report → adjudicate, credited to the right catalog',
    settled.ok &&
      settled.action === 'settled' &&
      settled.record.agentId === 'agent_demo_shopper' &&
      settled.record.settlingCatalogIds.includes(catalogId),
    settled.ok && settled.action === 'settled'
      ? `agent ${settled.record.agentId} → settles ${settled.record.settlingCatalogIds.join(', ')} via ${settled.record.rule}`
      : `expected a settlement, got ${settled.ok ? settled.action : settled.error.code}`,
  );

  // ---- 2. three hops --------------------------------------------------------
  // The node signed hop 1. This script appends hops 2 and 3 as two further
  // catalogs. §5.2 makes each hop sign every hop before it, so a chain that
  // verifies hop by hop is a chain nobody rewrote after the fact.
  const twoHops = appendRelayHop({
    privateJwk: relayB.privateJwk,
    kid: relayB.kid,
    catalogId: 'cat_demo_relay_b',
    token,
    chainComplete: true,
    settles: true,
  });
  const threeHops = appendRelayHop({
    privateJwk: relayC.privateJwk,
    kid: relayC.kid,
    catalogId: 'cat_demo_relay_c',
    token: twoHops,
    chainComplete: true,
    settles: false,
  });
  const chainVerdict = await verifyAttributionToken({ token: threeHops, resolveKey });

  assert(
    2,
    'three-hop chain verifies hop by hop, complete = true',
    chainVerdict.ok && chainVerdict.hops === 3 && chainVerdict.complete,
    chainVerdict.ok
      ? `hops ${chainVerdict.hops}, complete ${chainVerdict.complete}, settles ${chainVerdict.settlingCatalogIds.join(', ')}`
      : `${chainVerdict.error.code}${chainVerdict.error.hop ? ` at hop ${chainVerdict.error.hop}` : ''}`,
  );

  // ---- 3. tampered agent_id -------------------------------------------------
  // agent_id is a core claim, so every hop signed over it. Rewriting it on a
  // three-hop chain invalidates all three, and the *lowest* failing hop is the
  // tamper site — reporting a later one would accuse an innocent node.
  const reassigned: AttributionToken = { ...threeHops, agent_id: 'agent_someone_else' };
  const tamperVerdict = await verifyAttributionToken({ token: reassigned, resolveKey });

  assert(
    3,
    'rewriting agent_id fails verification, localised to the tampered hop',
    !tamperVerdict.ok && tamperVerdict.error.code === 'signature_invalid' && tamperVerdict.error.hop === 1,
    tamperVerdict.ok
      ? 'a rewritten agent_id verified — this is a total break'
      : `${tamperVerdict.error.code} at hop ${tamperVerdict.error.hop}`,
  );

  // ---- 4. expiry ------------------------------------------------------------
  const afterExpiry = new Date(Date.parse(token.exp) + 1000);
  const expiredVerdict = await verifyAttributionToken({ token, resolveKey, at: afterExpiry });

  assert(
    4,
    'a token claimed after its exp is rejected',
    !expiredVerdict.ok && expiredVerdict.error.code === 'token_expired',
    expiredVerdict.ok
      ? 'an expired token verified'
      : `${expiredVerdict.error.code} — judged at ${afterExpiry.toISOString()}, exp ${token.exp}`,
  );

  // ---- 5. replayed jti ------------------------------------------------------
  // The same token, a *different* order. The jti was claimed against
  // ord_demo_1 in assertion 1, so this is one referral being billed twice.
  const replay = await settleOrder({
    reports: [{ ...report, report_id: 'rep_demo_replay', order_id: 'ord_demo_2' } as ConversionReport],
    resolveKey,
    ledger,
    jtiRegistry,
  });

  assert(
    5,
    'the same jti claimed against a second order is rejected',
    !replay.ok && replay.error.code === 'replayed_jti',
    replay.ok ? `expected a rejection, got ${replay.action}` : replay.error.message,
  );

  // ---- 6. duplicate order ---------------------------------------------------
  // Two different reports, one order. Note the retry case is *not* this: the
  // same report_id redelivered returns its original answer, because §6.1 gives
  // the two identifiers different jobs.
  const retry = await settleOrder({ reports: [report], resolveKey, ledger, jtiRegistry });
  const secondClaim = await settleOrder({
    reports: [{ ...report, report_id: 'rep_demo_2' } as ConversionReport],
    resolveKey,
    ledger,
    jtiRegistry,
  });

  assert(
    6,
    'one order_id settles once — a retry is idempotent, a second claim is refused',
    retry.ok &&
      retry.action === 'settled' &&
      retry.idempotent &&
      !secondClaim.ok &&
      secondClaim.error.code === 'duplicate_order' &&
      ledger.settledOrders === 1,
    `retry → ${retry.ok && retry.action !== 'held' && retry.idempotent ? 'idempotent replay' : 'NOT idempotent'}; ` +
      `new report → ${secondClaim.ok ? secondClaim.action : secondClaim.error.code}; ` +
      `orders settled: ${ledger.settledOrders}`,
  );

  console.log(`\n${failures === 0 ? 'All 6 assertions passed.' : `${failures} of 6 assertions FAILED.`}`);
  return failures === 0 ? 0 : 1;
}

if (import.meta.main) {
  process.exit(await main(process.argv.slice(2)));
}
