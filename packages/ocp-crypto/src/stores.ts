/**
 * The two durable-state contracts settlement depends on —
 * `docs/specs/attribution/v1.md` §7.1 row 10 and row 11.
 *
 * Every other module in this package is a pure function of its inputs. These
 * two are not: row 10 asks "has this `jti` been spent before?" and row 11 asks
 * "has this `order_id` been paid before?", and both questions are answered by
 * state that has to survive a restart and be shared across processes.
 *
 * `JtiRegistry` and `SettlementLedger` are the in-memory implementations. They
 * are **demonstration only** — see each class for the specific way it fails —
 * and they exist so the adjudication logic can be tested without a database,
 * not so anybody ships them. These interfaces are the seam a real deployment
 * replaces them at.
 *
 * ## Why the methods may return promises
 *
 * A durable store is a network call. An interface whose `claim` returns a bare
 * `boolean` cannot be implemented by a SQL table, so the abstraction would be
 * decorative: the only thing it could abstract over is another `Map`. Every
 * method here returns `T | Promise<T>` and every caller awaits, so the
 * in-memory implementations stay synchronous and a Postgres one is possible.
 *
 * ## The transaction contract, which is the actual point of this file
 *
 * A settlement writes **two** rows: the `jti` claim (row 10) and the
 * settlement record (row 11). Those two writes, plus the payout itself, MUST
 * commit together.
 *
 * The failure is not hypothetical, and it is not symmetric:
 *
 *  - **Claim commits, payout does not.** The token is burned against an order
 *    that was never paid. The merchant retries, row 10 now says the `jti`
 *    belongs to that order — which it does — so the retry settles. Recoverable.
 *  - **Payout commits, claim does not.** The money moved and nothing remembers
 *    it. The same token settles again against a different order, which is
 *    precisely the double-spend row 10 exists to stop. Not recoverable: you
 *    cannot tell this apart from a legitimate second sale after the fact.
 *
 * So the ordering inside the transaction does not save you and neither does a
 * retry queue. The two writes have to be one commit, which means both stores
 * must be backed by **one transactional resource** — the same database, the
 * same connection, the same `BEGIN`. Two stores over two databases with a
 * two-phase commit bolted on is a different design with different failure
 * modes; if that is what a deployment has, the payout belongs on whichever
 * side holds the ledger.
 *
 * {@link SettlementTransaction} is how a deployment says so. `settleOrder`
 * wraps the claim and the commit in it, and the default —
 * {@link nonTransactional} — runs them in sequence with no atomicity at all.
 * That default is correct for the in-memory stores, where a process crash
 * loses both writes anyway, and wrong for everything else. It is a named
 * export rather than an inline arrow so that it shows up in a code review of a
 * production configuration.
 *
 * ## What is deliberately not here
 *
 * No SQL, no migrations, no connection pooling. This repository defines the
 * contract; the transactional implementation belongs to the runtime that owns
 * the database — the same split as production key custody. `SettlementLedger`
 * already takes previously committed records in its constructor, so the
 * rehydration path a durable store needs does not require touching the
 * adjudication logic.
 */
import type { SettlementRecord } from './settlement';

/**
 * §7.1 row 10 — the `jti` replay guard.
 *
 * The rule is narrow: the same `jti` against the **same** `order_id` is
 * ordinary traffic (a retry, a `pending` → `confirmed` update). The same `jti`
 * against a **different** `order_id` is one attribution token spent twice.
 *
 * Retention is derived, not configured. An entry is needed until the token's
 * own `exp`; past that, row 9 rejects the token anyway, so remembering the
 * `jti` longer protects nothing. A durable implementation may delete expired
 * rows on any schedule it likes — but it must not evict live ones under
 * pressure, because an eviction reopens the replay silently and at whatever
 * moment the system happened to be busiest.
 */
export interface ReplayStore {
  /**
   * Binds `jti` to `orderId` until `expiresAt`, and reports whether the bind
   * holds. `false` means that `jti` is already bound to a *different* order —
   * a replay. Re-claiming the same pair MUST return `true`: that is a retry.
   *
   * A durable implementation writes this as an insert with a unique constraint
   * on `jti`, in the settlement transaction. It is the write that must not
   * outlive a rolled-back payout, nor be outlived by a committed one.
   */
  claim(jti: string, orderId: string, expiresAt: Date): boolean | Promise<boolean>;

  /** The order a `jti` is bound to, if any. Read-only; used for diagnostics and for row 10 without claiming. */
  orderOf(jti: string): string | undefined | Promise<string | undefined>;
}

/**
 * §7.1 row 11 — settled orders, plus report idempotency.
 *
 * Two keys, on purpose (§6.1), and collapsing them is the mistake this
 * interface is shaped to prevent:
 *
 * - `report_id` is the **report's** idempotency key. A redelivered report must
 *   settle once and return the same answer.
 * - `order_id` is the **settlement's** dedup key. A *different* report for an
 *   order that already settled is a second claim on one sale.
 *
 * Key on only one and you either reject every retry or pay every duplicate.
 *
 * Settled orders do not age out. An order forgotten is an order that can be
 * settled again, so there is no expiry here and the growth is real — another
 * reason the durable version is a table and not a map.
 */
export interface LedgerStore {
  /** The current record for an order, settled or reversed. The row-11 read. */
  recordOf(orderId: string): SettlementRecord | undefined | Promise<SettlementRecord | undefined>;

  /** The record a previously-seen `report_id` produced, for retry idempotency. */
  outcomeOf(reportId: string): SettlementRecord | undefined | Promise<SettlementRecord | undefined>;

  /**
   * Writes the record. MUST refuse to overwrite an already-settled order with
   * a second `confirmed` settlement rather than silently replacing it: by the
   * time control reaches here the row-11 check has passed, so a conflict means
   * something raced or the store was driven directly, and either way the safe
   * answer is to fail the transaction.
   *
   * A durable implementation backs this with a unique constraint on
   * `order_id`, and writes it in the same transaction as the payout and the
   * {@link ReplayStore.claim}.
   */
  commit(record: SettlementRecord): void | Promise<void>;
}

/**
 * Runs the claim and the commit as one unit of work.
 *
 * A deployment supplies this so the two writes land together — typically
 * `(work) => db.transaction(work)`, with both stores reading the ambient
 * connection that transaction opened. The shape is a wrapper rather than a
 * handle passed into each method because the store implementations are the
 * things that know about connections, and threading a driver-specific
 * transaction object through this package's types would make the interfaces
 * un-implementable for the next driver.
 *
 * Whatever the work returns is returned unchanged. A thrown error must roll
 * back: `settleOrder` lets it propagate rather than reporting a verdict,
 * because a failed transaction is not a statement about the token.
 */
export type SettlementTransaction = <T>(work: () => Promise<T>) => Promise<T>;

/**
 * The default: runs the work with no transaction at all.
 *
 * Correct only when losing both writes together is the sole failure mode —
 * which is true of `JtiRegistry` and `SettlementLedger`, since a crash empties
 * both. With any durable store it is the double-payment window described at
 * the top of this file, and that window is open for exactly as long as the
 * payout takes.
 *
 * Exported and named so a production configuration that never overrode
 * `transaction` reads as a deliberate choice in review, rather than as an
 * absent option nobody noticed.
 */
export const nonTransactional: SettlementTransaction = (work) => work();
