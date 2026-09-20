/**
 * Settlement — `docs/specs/attribution/v1.md` §6, §7.1 row 11, §7.2, §7.3.
 *
 * `verify.ts` answers "is this one token real and eligible". This module answers
 * the question that actually pays somebody: **several merchants' reports, each
 * carrying a token, all claiming the same order — who gets the money, and how
 * do we make sure nobody gets it twice.**
 *
 * The split matters because the two questions have different shapes. Eligibility
 * is a pure function of one token; adjudication is a comparison across
 * candidates; dedup is a write against durable state. Folding them together
 * produces a verifier that cannot be tested without a database.
 *
 * ## The two-key dedup, which is easy to collapse and wrong to collapse
 *
 * §6.1 gives a report two identifiers on purpose:
 *
 * - `report_id` is the **report's** idempotency key. Networks retry; the same
 *   report delivered twice must settle once and return the same answer.
 * - `order_id` is the **settlement's** dedup key (§7.1 row 11). A *different*
 *   report for an order that already settled is a second claim on one sale.
 *
 * So the same `report_id` twice is a retry, and a new `report_id` on a settled
 * `order_id` is `duplicate_order`. Key on only one of them and you either
 * reject every retry or pay every duplicate.
 */
import { ATTRIBUTION_ERROR_CODES, AttributionError } from './errors';
import type { AttributionToken } from './attribution';
import { nonTransactional, type LedgerStore, type ReplayStore, type SettlementTransaction } from './stores';
import {
  verifyAttributionToken,
  type AttributionKeyResolver,
  type AttributionVerdict,
} from './verify';

/** §6.1 — `refunded` and `cancelled` exist because reversal is not optional. */
export type ConversionStatus = 'confirmed' | 'pending' | 'refunded' | 'cancelled';

/**
 * §6.1 — a merchant's report of one conversion.
 *
 * Structural, like every other type in this package: a caller may hand in a
 * `conversionReportSchema`-inferred object, but the schema never reaches the
 * canonicalizer (§9.1). Validate the wire bytes with `ocp-schema` first; this
 * module assumes the shape and checks only what §7 asks it to check.
 */
export interface ConversionReport {
  ocp_version: string;
  kind: 'ConversionReport';
  report_id: string;
  order_id: string;
  provider_id: string;
  attribution_token: AttributionToken;
  amount_minor: number;
  currency: string;
  /** The moment of the sale, not of the report. §7.1 rows 8/9 are measured here. */
  occurred_at: string;
  status: ConversionStatus;
}

/**
 * §7.2 default, §7.4 alternatives.
 *
 * "按跳均分" from §7.4 is deliberately absent: it is an *allocation* rule, not
 * an adjudication rule — it decides how the winner's payout is divided, and §7.3
 * puts division explicitly outside this protocol. Adding it here would look like
 * the protocol had an opinion about splits, which it does not.
 */
export type AdjudicationRule = 'last_touch' | 'first_touch';

/** What happened to one candidate report. Every candidate gets one of these. */
export interface CandidateOutcome {
  reportId: string;
  jti: string;
  status: ConversionStatus;
  /** Present when the token passed §7.1 rows 1–10. */
  verdict?: AttributionVerdict;
  /** Present when it did not. */
  error?: AttributionError;
  /** True for the single candidate that won adjudication. */
  won: boolean;
}

/** What the ledger holds for an order, and what a settler should act on. */
export interface SettlementRecord {
  orderId: string;
  reportId: string;
  jti: string;
  /** §7.3 — the agent-side settlement subject. */
  agentId: string;
  /** §7.3 — the catalog-side subjects, in hop order. */
  settlingCatalogIds: string[];
  amountMinor: number;
  currency: string;
  occurredAt: string;
  status: ConversionStatus;
  /** §5.3 recomputed. `false` means there may be unrecorded hops. */
  complete: boolean;
  /** §7.2 sort key of the winner. */
  lastSignedAt: string;
  /** §7.4 requires the rule in use to be published; recording it is the floor. */
  rule: AdjudicationRule;
}

export type SettleOrderResult =
  | {
      ok: true;
      action: 'settled' | 'reversed';
      record: SettlementRecord;
      /** True when this was a redelivery of an already-processed `report_id`. */
      idempotent: boolean;
      candidates: CandidateOutcome[];
    }
  | { ok: true; action: 'held'; reason: string; candidates: CandidateOutcome[] }
  | { ok: false; error: AttributionError; candidates: CandidateOutcome[] };

/**
 * §7.2 — picks the winner among eligible candidates.
 *
 * last-touch: the largest `signed_at` on the **last** hop. first-touch (§7.4):
 * the smallest `signed_at` on `chain[0]`.
 *
 * Ties break on the lexicographically smallest `jti`, and that rule is not
 * decoration. Two tokens signed in the same millisecond are ordinary at second
 * resolution; without a total order, two settlers reading identical inputs
 * return different winners and the two ledgers never reconcile.
 */
export function adjudicate<T extends { token: AttributionToken }>(
  candidates: readonly T[],
  rule: AdjudicationRule = 'last_touch',
): T | undefined {
  let best: T | undefined;
  let bestKey = '';

  for (const candidate of candidates) {
    const chain = candidate.token.chain;
    const node = rule === 'last_touch' ? chain[chain.length - 1] : chain[0];
    if (!node) continue;
    const key = node.signed_at;

    if (best === undefined) {
      best = candidate;
      bestKey = key;
      continue;
    }
    const better = rule === 'last_touch' ? key > bestKey : key < bestKey;
    const tied = key === bestKey && candidate.token.jti < best.token.jti;
    if (better || tied) {
      best = candidate;
      bestKey = key;
    }
  }

  return best;
}

/**
 * The in-memory settled-orders ledger — §7.1 row 11's state, plus report
 * idempotency. **Demonstration only.**
 *
 * ## In-memory, and this one holds the money
 *
 * The same gap `JtiRegistry` carries, with higher stakes: this map is the
 * only thing standing between one sale and two payouts. It empties on restart
 * and does not span processes, so as written a restart makes every past order
 * settleable a second time.
 *
 * The replacement implements {@link LedgerStore} over a table with a **unique
 * constraint on `order_id`**, written in the same transaction as the payout.
 * Not a cache in front of one: if the insert and the payout can commit
 * separately, there is a window where the money moved and the dedup row did
 * not, and that window is exactly the double-payment this class exists to
 * prevent. The `jti` claim (§7.1 row 10) belongs in that same transaction for
 * the same reason — `stores.ts` states the contract in full, and
 * {@link SettleOrderParams.transaction} is how a deployment supplies it.
 *
 * Unlike `JtiRegistry` this has no expiry and no cap. Settled orders are not
 * allowed to age out — an order forgotten is an order that can be settled again
 * — so the growth is real and is another reason the durable version is a
 * database table and not a `Map`.
 */
export class SettlementLedger implements LedgerStore {
  readonly #orders = new Map<string, SettlementRecord>();
  readonly #reports = new Map<string, SettlementRecord>();

  /**
   * Seeds from previously committed records — the rehydration path a durable
   * store needs, and the reason it takes records rather than replaying
   * `commit`: reloading state is not a settlement, so it must not trip the
   * double-payout guard below.
   */
  constructor(records: readonly SettlementRecord[] = []) {
    for (const record of records) {
      this.#orders.set(record.orderId, record);
      this.#reports.set(record.reportId, record);
    }
  }

  /** The current record for an order, settled or reversed. */
  recordOf(orderId: string): SettlementRecord | undefined {
    return this.#orders.get(orderId);
  }

  /** The record a previously-seen `report_id` produced, for retry idempotency. */
  outcomeOf(reportId: string): SettlementRecord | undefined {
    return this.#reports.get(reportId);
  }

  get settledOrders(): number {
    return this.#orders.size;
  }

  /** All records, in insertion order. For a settlement run's summary output. */
  records(): SettlementRecord[] {
    return [...this.#orders.values()];
  }

  /**
   * Commits a record. Refuses to overwrite a settled order with a second
   * settlement — `settleOrder` checks row 11 first, so reaching this throw means
   * the ledger was driven directly and the row-11 check was skipped.
   */
  commit(record: SettlementRecord): void {
    const existing = this.#orders.get(record.orderId);
    if (existing && record.status === 'confirmed') {
      throw new Error(
        `order "${record.orderId}" is already settled (report "${existing.reportId}"). ` +
          `Check §7.1 row 11 before committing, or this is a double payout.`,
      );
    }
    this.#orders.set(record.orderId, record);
    this.#reports.set(record.reportId, record);
  }
}

export interface SettleOrderParams {
  /** Every report claiming one order. They must all name the same `order_id`. */
  reports: readonly ConversionReport[];
  resolveKey: AttributionKeyResolver;
  /** §7.1 row 11's state. `SettlementLedger` is the in-memory demonstration. */
  ledger: LedgerStore;
  /** §7.1 row 10's state. Claimed for the winner only. */
  jtiRegistry: ReplayStore;
  /** §7.2 default. Any other value MUST be published (§7.4). */
  rule?: AdjudicationRule;
  /**
   * Runs the row-10 claim and the row-11 commit as one unit of work, so a
   * deployment can put them — and its payout — in one transaction.
   *
   * Defaults to {@link nonTransactional}, which runs them in sequence with no
   * atomicity. That is correct for the in-memory stores, where a crash loses
   * both writes anyway, and wrong for any durable store: see `stores.ts` for
   * why the payout-without-claim direction is the unrecoverable one.
   */
  transaction?: SettlementTransaction;
}

function furthestError(rejected: readonly CandidateOutcome[]): AttributionError {
  // ATTRIBUTION_ERROR_CODES is in §7.1 row order, so a later index means the
  // candidate survived more of the filter. Reporting the one that got furthest
  // beats reporting whichever happened to be first in the array: with several
  // candidates, array order is the caller's accident and the answer has to be
  // the same for every settler reading the same inputs.
  let best = rejected[0]!;
  for (const candidate of rejected) {
    const here = ATTRIBUTION_ERROR_CODES.indexOf(candidate.error!.code);
    const there = ATTRIBUTION_ERROR_CODES.indexOf(best.error!.code);
    if (here > there || (here === there && candidate.jti < best.jti)) best = candidate;
  }
  return best.error!;
}

/**
 * Settles one order from the reports claiming it.
 *
 * The sequence, and why it is this sequence:
 *
 * 1. **§7.1 rows 1–10 on every candidate**, each measured at its own report's
 *    `occurred_at` and against its own `provider_id`. Row 10 is evaluated but
 *    *not* claimed — see below.
 * 2. **§7.2 adjudication among the survivors.** `confirmed` reports compete
 *    first; only if none survive do `refunded` / `cancelled` reports get to
 *    decide, and a batch of nothing but `pending` is held rather than paid.
 * 3. **`report_id` idempotency, then §7.1 row 11** on the winner alone. In that
 *    order: a retried report must return its original answer, not
 *    `duplicate_order`.
 * 4. **Claim the `jti` and commit, inside one transaction.**
 *
 * Row 10 is read for every candidate but claimed only for the winner. Claiming
 * on a loser's behalf would bind its `jti` to an order it was never paid for,
 * so the first settler to see a token could permanently spend it by losing.
 *
 * A reversal does **not** reopen the order. Allowing a refunded order to be
 * settled again would make refund-then-reconfirm a laundering route for the
 * duplicate that row 11 exists to stop; a genuinely new sale is a new
 * `order_id`.
 */
export async function settleOrder(params: SettleOrderParams): Promise<SettleOrderResult> {
  const {
    reports,
    resolveKey,
    ledger,
    jtiRegistry,
    rule = 'last_touch',
    transaction = nonTransactional,
  } = params;

  if (reports.length === 0) throw new Error('settleOrder needs at least one report');
  const orderId = reports[0]!.order_id;
  for (const report of reports) {
    if (report.order_id !== orderId) {
      throw new Error(
        `settleOrder takes the reports for one order; got "${orderId}" and "${report.order_id}"`,
      );
    }
    if (!Number.isSafeInteger(report.amount_minor) || report.amount_minor < 0) {
      throw new Error(
        `report "${report.report_id}" has amount_minor ${report.amount_minor}; §2.3 requires a ` +
          `non-negative integer in the minor unit. Validate with conversionReportSchema first.`,
      );
    }
  }

  // ---- Step 1: §7.1 rows 1–10, per candidate ------------------------------
  const candidates: CandidateOutcome[] = [];
  const eligible: { report: ConversionReport; token: AttributionToken; verdict: AttributionVerdict }[] = [];

  for (const report of reports) {
    const token = report.attribution_token;
    const result = await verifyAttributionToken({
      token,
      resolveKey,
      at: new Date(report.occurred_at),
      expectedProviderId: report.provider_id,
      replayGuard: { registry: jtiRegistry, orderId, claim: false },
    });

    const outcome: CandidateOutcome = {
      reportId: report.report_id,
      jti: token.jti,
      status: report.status,
      won: false,
    };
    if (result.ok) {
      outcome.verdict = result;
      eligible.push({ report, token, verdict: result });
    } else {
      outcome.error = result.error;
    }
    candidates.push(outcome);
  }

  if (eligible.length === 0) return { ok: false, error: furthestError(candidates), candidates };

  // ---- Step 2: §7.2 adjudication ------------------------------------------
  const settling = eligible.filter((c) => c.report.status === 'confirmed');
  const reversing = eligible.filter(
    (c) => c.report.status === 'refunded' || c.report.status === 'cancelled',
  );
  const pool = settling.length > 0 ? settling : reversing;

  if (pool.length === 0) {
    return {
      ok: true,
      action: 'held',
      reason: `every eligible report for order "${orderId}" is still pending; nothing to settle yet`,
      candidates,
    };
  }

  const winner = adjudicate(pool, rule)!;
  const winning = candidates.find((c) => c.reportId === winner.report.report_id)!;
  winning.won = true;

  // ---- Step 3: report idempotency, then §7.1 row 11 ------------------------
  const seen = await ledger.outcomeOf(winner.report.report_id);
  if (seen) {
    return {
      ok: true,
      action: seen.status === 'confirmed' ? 'settled' : 'reversed',
      record: seen,
      idempotent: true,
      candidates,
    };
  }

  const settled = await ledger.recordOf(orderId);
  const reversal = pool === reversing;

  if (!reversal && settled) {
    winning.error = new AttributionError(
      'duplicate_order',
      `order "${orderId}" was already settled by report "${settled.reportId}" ` +
        `(jti "${settled.jti}"); this is a second claim on one sale`,
    );
    winning.won = false;
    return { ok: false, error: winning.error, candidates };
  }

  if (reversal && !settled) {
    return {
      ok: true,
      action: 'held',
      reason: `order "${orderId}" reports ${winner.report.status} but was never settled; nothing to reverse`,
      candidates,
    };
  }

  // ---- Step 4: claim and commit, together ---------------------------------
  const record: SettlementRecord = {
    orderId,
    reportId: winner.report.report_id,
    jti: winner.token.jti,
    agentId: winner.verdict.agentId,
    settlingCatalogIds: winner.verdict.settlingCatalogIds,
    amountMinor: winner.report.amount_minor,
    currency: winner.report.currency,
    occurredAt: winner.report.occurred_at,
    status: winner.report.status,
    complete: winner.verdict.complete,
    lastSignedAt: winner.verdict.lastSignedAt,
    rule,
  };

  // ---- Step 4: claim and commit, in one transaction ------------------------
  //
  // Both writes go inside `transaction`, and a deployment's payout belongs in
  // the same callback. Sequenced without one, the money can move and the guard
  // be lost; see stores.ts for why that direction is the unrecoverable one.
  const replayed = await transaction(async () => {
    if (!reversal) {
      if (!(await jtiRegistry.claim(winner.token.jti, orderId, new Date(winner.token.exp)))) {
        return String(await jtiRegistry.orderOf(winner.token.jti));
      }
    }
    await ledger.commit(record);
    return undefined;
  });

  if (replayed !== undefined) {
    winning.error = new AttributionError(
      'replayed_jti',
      `jti "${winner.token.jti}" is already settled against order "${replayed}", not "${orderId}"`,
    );
    winning.won = false;
    return { ok: false, error: winning.error, candidates };
  }

  return { ok: true, action: reversal ? 'reversed' : 'settled', record, idempotent: false, candidates };
}
