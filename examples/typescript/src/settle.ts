/**
 * The merchant's half of settlement — `docs/specs/attribution/v1.md` §6, §7.
 *
 * `offline-verify.ts` answers "is this token real, and is it about this
 * resolve". That is everything a merchant can check *before* a sale. This
 * script is what happens *after* one: the merchant files a `ConversionReport`,
 * and somebody has to decide whether it gets paid, once.
 *
 * Deliberately a standalone script with a `Map` for a database, because the two
 * interesting failures do not need a database to show up:
 *
 *   - the same sale reported twice (a retry, or a merchant double-filing)
 *   - two attribution tokens claiming the same order
 *
 * Both are decided by `settleOrder` in `@ocp-catalog/ocp-crypto`. Nothing in
 * this file reimplements §7 — if it did, this example and the library could
 * disagree, and the example is supposed to show what conformance looks like.
 *
 * ## Where the money actually lives
 *
 * `SettlementLedger` here is a `Map`, written back to `ledger.json` between CLI
 * runs so a retry lands on the same answer. That file is a demo convenience,
 * not a design: it is rewritten *after* the settlement decision, so a crash in
 * between loses the dedup row while the payout stands. A real settler replaces
 * it with a table holding a unique constraint on `order_id`, written in the
 * same transaction as the payout. See the note on the class.
 */
import { readFileSync, readdirSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  JtiRegistry,
  SettlementLedger,
  settleOrder,
  staticKeyResolver,
  type AdjudicationRule,
  type AttributionToken,
  type ConversionReport,
  type SettlementRecord,
} from '@ocp-catalog/ocp-crypto';
import { conversionReportSchema } from '@ocp-catalog/ocp-schema';

/**
 * Builds a report from a resolve response the merchant already has.
 *
 * `occurred_at` is the moment of the **sale**, not of the filing. §7.1 rows 8
 * and 9 are measured against it, so passing "now" at reporting time would
 * reject every sale reported after the token's hour-long window — which is to
 * say, most of them.
 */
export function buildReport(params: {
  resolved: unknown;
  orderId: string;
  reportId: string;
  amountMinor: number;
  currency: string;
  occurredAt: Date;
  status?: ConversionReport['status'];
}): ConversionReport {
  const bindings = (params.resolved as { action_bindings?: unknown[] }).action_bindings ?? [];
  const token = bindings
    .map((binding) => (binding as { attribution?: AttributionToken }).attribution)
    .find((candidate): candidate is AttributionToken => Boolean(candidate));
  if (!token) throw new Error('this resolve response carries no attribution token to report against');

  const report: ConversionReport = {
    ocp_version: '1.0',
    kind: 'ConversionReport',
    report_id: params.reportId,
    order_id: params.orderId,
    // §6.1: the report's provider must be the token's, or merchant A could file
    // reports against tokens minted for merchant B.
    provider_id: token.provider_id,
    attribution_token: token,
    amount_minor: params.amountMinor,
    currency: params.currency,
    occurred_at: params.occurredAt.toISOString(),
    status: params.status ?? 'confirmed',
  };

  // The schema is the wire contract; ocp-crypto takes the shape on trust
  // because it has no dependencies, so validation happens exactly here.
  conversionReportSchema.parse(report);
  return report;
}

/**
 * One settler's state: the keys it has fetched, the orders it has paid, and the
 * `jti`s it has spent. Grouping reports by `order_id` is this layer's job —
 * `settleOrder` takes one order's worth of reports and refuses a mixed batch.
 */
export class MerchantSettler {
  readonly #ledger: SettlementLedger;
  readonly #jti = new JtiRegistry();
  readonly #resolveKey;

  constructor(
    jwksByCatalogId: Record<string, { keys?: unknown }>,
    previous: readonly SettlementRecord[] = [],
  ) {
    this.#resolveKey = staticKeyResolver(jwksByCatalogId);
    this.#ledger = new SettlementLedger(previous);
  }

  get ledger(): SettlementLedger {
    return this.#ledger;
  }

  async settle(reports: readonly ConversionReport[], rule: AdjudicationRule = 'last_touch') {
    const byOrder = new Map<string, ConversionReport[]>();
    for (const report of reports) {
      const group = byOrder.get(report.order_id) ?? [];
      group.push(report);
      byOrder.set(report.order_id, group);
    }

    const results = [];
    for (const [orderId, group] of byOrder) {
      results.push({
        orderId,
        result: await settleOrder({
          reports: group,
          resolveKey: this.#resolveKey,
          ledger: this.#ledger,
          jtiRegistry: this.#jti,
          rule,
        }),
      });
    }
    return results;
  }
}

// ---------------------------------------------------------------------------
// CLI — works on the artifacts `offline-verify.ts fetch` left on disk
// ---------------------------------------------------------------------------

const read = (dir: string, name: string) =>
  JSON.parse(readFileSync(join(dir, name), 'utf8')) as Record<string, unknown>;

/** Where this script keeps the orders it has already paid, between runs. */
const LEDGER = 'ledger.json';

function goOffline(): void {
  globalThis.fetch = (() => {
    throw new Error('offline: settlement must not touch the network');
  }) as unknown as typeof globalThis.fetch;
}

function writeReport(dir: string, args: string[]): number {
  const [orderId = 'ord_demo_1', amount = '12900', currency = 'CNY'] = args;
  const report = buildReport({
    resolved: read(dir, 'resolve.json'),
    orderId,
    reportId: `rep_${orderId}_${Date.now()}`,
    amountMinor: Number(amount),
    currency,
    occurredAt: new Date(),
  });
  const file = join(dir, `report-${orderId}.json`);
  writeFileSync(file, `${JSON.stringify(report, null, 2)}\n`);
  console.log(`Wrote ${file}`);
  return 0;
}

function settleFromDisk(dir: string, rule: AdjudicationRule): Promise<number> {
  goOffline();

  const discovery = read(dir, 'discovery.json');
  const catalogId = String(discovery.catalog_id);
  // The ledger outlives the process here only because it is written back to a
  // file — enough to show a retry landing on the same answer, and nothing like
  // the transactional store a real settler needs (see SettlementLedger).
  const ledgerFile = join(dir, LEDGER);
  const previous = existsSync(ledgerFile)
    ? (JSON.parse(readFileSync(ledgerFile, 'utf8')) as SettlementRecord[])
    : [];
  const settler = new MerchantSettler({ [catalogId]: read(dir, 'jwks.json') as { keys?: unknown } }, previous);

  const reports = readdirSync(dir)
    .filter((name) => name.startsWith('report-') && name.endsWith('.json'))
    .map((name) => read(dir, name) as unknown as ConversionReport);

  if (reports.length === 0) {
    console.error(`no report-*.json in ${dir} — run "settle report <dir>" first`);
    return Promise.resolve(2);
  }

  return settler.settle(reports, rule).then((outcomes) => {
    let failures = 0;
    for (const { orderId, result } of outcomes) {
      if (!result.ok) {
        failures += 1;
        console.log(`REJECT ${orderId}  ${result.error.code}: ${result.error.message}`);
        continue;
      }
      if (result.action === 'held') {
        console.log(`HOLD   ${orderId}  ${result.reason}`);
        continue;
      }
      const { record } = result;
      console.log(
        `${result.action === 'settled' ? 'SETTLE' : 'REVERSE'} ${orderId}  ` +
          `${record.amountMinor} ${record.currency}${result.idempotent ? '  (idempotent replay)' : ''}`,
      );
      console.log(`       agent:   ${record.agentId}`);
      console.log(`       settles: ${record.settlingCatalogIds.join(', ') || '(nobody)'}`);
      console.log(`       jti:     ${record.jti}  via ${record.rule}`);
    }
    writeFileSync(ledgerFile, `${JSON.stringify(settler.ledger.records(), null, 2)}\n`);
    return failures === 0 ? 0 : 1;
  });
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  const dir = rest[0] ?? './.attribution';

  if (command === 'report') return writeReport(dir, rest.slice(1));
  if (command === 'settle') {
    const rule = (rest[1] as AdjudicationRule) ?? 'last_touch';
    return settleFromDisk(dir, rule);
  }

  console.error('usage: settle.ts report [dir] [orderId] [amountMinor] [currency]');
  console.error('       settle.ts settle [dir] [last_touch|first_touch]');
  console.error('');
  console.error('Run "offline-verify.ts fetch" first — this reads the same artifacts.');
  return 2;
}

if (import.meta.main) {
  process.exit(await main(process.argv.slice(2)));
}
