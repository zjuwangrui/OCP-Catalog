import { describe, expect, test } from 'bun:test';
import { appendRelayHop, issueOriginToken, type AttributionToken } from './attribution';
import { generateEd25519KeyPair, publicJwkOf } from './keys';
import {
  SettlementLedger,
  adjudicate,
  settleOrder,
  type ConversionReport,
  type ConversionStatus,
} from './settlement';
import { JtiRegistry, staticKeyResolver, verifyAttributionToken } from './verify';
import { nonTransactional, type LedgerStore, type ReplayStore } from './stores';

const ORIGIN = generateEd25519KeyPair();
const RELAY_A = generateEd25519KeyPair();
const RELAY_B = generateEd25519KeyPair();
const OUTSIDER = generateEd25519KeyPair();

const CATALOGS = {
  cat_origin: ORIGIN,
  cat_relay_a: RELAY_A,
  cat_relay_b: RELAY_B,
} as const;

const IAT = new Date('2026-09-23T10:00:00.000Z');
const SOLD_AT = '2026-09-23T10:30:00.000Z';

function jwksOf(...catalogIds: Array<keyof typeof CATALOGS>): Record<string, { keys: unknown[] }> {
  const out: Record<string, { keys: unknown[] }> = {};
  for (const id of catalogIds) {
    const key = CATALOGS[id];
    out[id] = { keys: [{ ...publicJwkOf(key.privateJwk), kid: key.kid, alg: 'EdDSA', use: 'sig' }] };
  }
  return out;
}

const allKeys = staticKeyResolver(jwksOf('cat_origin', 'cat_relay_a', 'cat_relay_b'));

function originToken(over: Partial<Parameters<typeof issueOriginToken>[0]> = {}): AttributionToken {
  return issueOriginToken({
    privateJwk: ORIGIN.privateJwk,
    kid: ORIGIN.kid,
    catalogId: 'cat_origin',
    agentId: 'agent_alpha',
    entryId: 'entry_example_sku-001',
    objectId: 'sku-001',
    providerId: 'prov_merchant',
    purpose: 'checkout',
    jti: 'atr_origin',
    now: () => IAT,
    ...over,
  });
}

/** A two-hop token whose last hop signed at `signedAt` — the last-touch key. */
function relayedToken(params: {
  jti: string;
  signedAt: string;
  relay?: keyof typeof CATALOGS;
  issuedAt?: Date;
}): AttributionToken {
  const relay = params.relay ?? 'cat_relay_a';
  const key = CATALOGS[relay];
  return appendRelayHop({
    privateJwk: key.privateJwk,
    kid: key.kid,
    catalogId: relay,
    token: originToken({ jti: params.jti, ...(params.issuedAt ? { now: () => params.issuedAt! } : {}) }),
    chainComplete: true,
    settles: true,
    now: () => new Date(params.signedAt),
  });
}

function report(
  over: Partial<ConversionReport> & { attribution_token: AttributionToken },
): ConversionReport {
  return {
    ocp_version: '1.0',
    kind: 'ConversionReport',
    report_id: 'rep_1',
    order_id: 'ord_1',
    provider_id: 'prov_merchant',
    amount_minor: 12900,
    currency: 'CNY',
    occurred_at: SOLD_AT,
    status: 'confirmed',
    ...over,
  };
}

function freshSettler(): { ledger: SettlementLedger; jtiRegistry: JtiRegistry } {
  return { ledger: new SettlementLedger(), jtiRegistry: new JtiRegistry() };
}

/** The harness has no `.rejects`, and an async throw is still a contract. */
async function rejection(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (err) {
    return err as Error;
  }
  throw new Error('expected the call to reject, but it resolved');
}

describe('同一 order_id 回报两次只记一次（T5 判据一）', () => {
  test('同一份回报重投 → 第二次是幂等返回，不是第二笔结算', async () => {
    const settler = freshSettler();
    const input = report({ attribution_token: originToken() });

    const first = await settleOrder({ reports: [input], resolveKey: allKeys, ...settler });
    expect(first.ok).toBe(true);
    if (!first.ok || first.action !== 'settled') throw new Error('expected a settlement');
    expect(first.idempotent).toBe(false);
    expect(first.record.amountMinor).toBe(12900);

    const retry = await settleOrder({ reports: [input], resolveKey: allKeys, ...settler });
    expect(retry.ok).toBe(true);
    if (!retry.ok || retry.action !== 'settled') throw new Error('expected the same settlement back');
    // Idempotent, not duplicate_order: §6.1 gives report_id and order_id
    // different jobs, and a network retry is the report_id's job.
    expect(retry.idempotent).toBe(true);
    expect(retry.record.reportId).toBe(first.record.reportId);

    expect(settler.ledger.settledOrders).toBe(1);
  });

  test('换一个 report_id 再报同一订单 → duplicate_order（§7.1 第 11 条）', async () => {
    const settler = freshSettler();
    await settleOrder({
      reports: [report({ attribution_token: originToken() })],
      resolveKey: allKeys,
      ...settler,
    });

    const second = await settleOrder({
      reports: [
        report({
          report_id: 'rep_2',
          attribution_token: relayedToken({ jti: 'atr_other', signedAt: '2026-09-23T10:05:00.000Z' }),
        }),
      ],
      resolveKey: allKeys,
      ...settler,
    });

    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.error.code).toBe('duplicate_order');
    expect(settler.ledger.settledOrders).toBe(1);
    expect(settler.ledger.recordOf('ord_1')!.reportId).toBe('rep_1');
  });

  test('同一 jti 同一订单的状态更新不算重放（第 10 条与第 11 条的分界）', async () => {
    const settler = freshSettler();
    const token = originToken();

    const pending = await settleOrder({
      reports: [report({ report_id: 'rep_pending', status: 'pending', attribution_token: token })],
      resolveKey: allKeys,
      ...settler,
    });
    expect(pending.ok).toBe(true);
    if (!pending.ok) return;
    expect(pending.action).toBe('held');

    // Same token, same order, now confirmed. A guard that keyed only on jti
    // would call this a replay and lose the sale.
    const confirmed = await settleOrder({
      reports: [report({ report_id: 'rep_confirmed', attribution_token: token })],
      resolveKey: allKeys,
      ...settler,
    });
    expect(confirmed.ok).toBe(true);
    if (!confirmed.ok || confirmed.action !== 'settled') throw new Error('expected a settlement');
    expect(confirmed.record.jti).toBe('atr_origin');
  });

  test('pending 不占位——被 hold 的回报没有结算也没有认领 jti', async () => {
    const settler = freshSettler();
    await settleOrder({
      reports: [report({ status: 'pending', attribution_token: originToken() })],
      resolveKey: allKeys,
      ...settler,
    });
    expect(settler.ledger.settledOrders).toBe(0);
    expect(settler.jtiRegistry.orderOf('atr_origin')).toBeUndefined();
  });

  test('重建账本后两把钥匙都还在——重投仍幂等，新回报仍 duplicate_order', async () => {
    const before = freshSettler();
    const first = await settleOrder({
      reports: [report({ attribution_token: originToken() })],
      resolveKey: allKeys,
      ...before,
    });
    if (!first.ok || first.action !== 'settled') throw new Error('expected a settlement');

    // What a restart looks like: the records survive, the JtiRegistry does not.
    // Both keys have to come back from the records alone, or a restart reopens
    // every order ever settled.
    const after = {
      ledger: new SettlementLedger(before.ledger.records()),
      jtiRegistry: new JtiRegistry(),
    };

    const retry = await settleOrder({
      reports: [report({ attribution_token: originToken() })],
      resolveKey: allKeys,
      ...after,
    });
    if (!retry.ok || retry.action !== 'settled') throw new Error('expected the same settlement back');
    expect(retry.idempotent).toBe(true);

    const fresh = await settleOrder({
      reports: [
        report({
          report_id: 'rep_2',
          attribution_token: relayedToken({ jti: 'atr_other', signedAt: '2026-09-23T10:05:00.000Z' }),
        }),
      ],
      resolveKey: allKeys,
      ...after,
    });
    expect(fresh.ok).toBe(false);
    if (fresh.ok) return;
    expect(fresh.error.code).toBe('duplicate_order');
    expect(after.ledger.settledOrders).toBe(1);
  });

  test('重建不是结算——喂回已结算的记录不会撞上双付守卫', () => {
    const record = {
      orderId: 'ord_1',
      reportId: 'rep_1',
      jti: 'atr_origin',
      agentId: 'agent_alpha',
      settlingCatalogIds: ['cat_origin'],
      amountMinor: 12900,
      currency: 'CNY',
      occurredAt: '2026-09-23T10:30:00.000Z',
      status: 'confirmed' as const,
      complete: true,
      lastSignedAt: '2026-09-23T10:00:00.000Z',
      rule: 'last_touch' as const,
    };
    const ledger = new SettlementLedger([record]);
    expect(ledger.recordOf('ord_1')!.reportId).toBe('rep_1');
    expect(ledger.outcomeOf('rep_1')!.orderId).toBe('ord_1');
    // commit() would throw here; seeding must not, or no process could ever
    // reload its own ledger.
    expect(ledger.settledOrders).toBe(1);
    expect(() => ledger.commit(record)).toThrow();
  });
});

describe('两个凭证争同一订单 → 唯一赢家（T5 判据二）', () => {
  const earlier = relayedToken({ jti: 'atr_early', signedAt: '2026-09-23T10:05:00.000Z' });
  const later = relayedToken({
    jti: 'atr_late',
    signedAt: '2026-09-23T10:20:00.000Z',
    relay: 'cat_relay_b',
  });

  const contest = () => [
    report({ report_id: 'rep_early', attribution_token: earlier }),
    report({ report_id: 'rep_late', attribution_token: later }),
  ];

  test('last-touch：最后一跳 signed_at 最大的那张赢，且只有一个赢家', async () => {
    const settler = freshSettler();
    const result = await settleOrder({ reports: contest(), resolveKey: allKeys, ...settler });

    expect(result.ok).toBe(true);
    if (!result.ok || result.action !== 'settled') throw new Error('expected a settlement');
    expect(result.record.jti).toBe('atr_late');
    expect(result.record.settlingCatalogIds).toEqual(['cat_origin', 'cat_relay_b']);
    expect(result.candidates.filter((c) => c.won)).toHaveLength(1);
    expect(result.candidates.every((c) => c.error === undefined)).toBe(true);
    expect(settler.ledger.settledOrders).toBe(1);
  });

  test('赢家与输入顺序无关', async () => {
    const forwards = await settleOrder({ reports: contest(), resolveKey: allKeys, ...freshSettler() });
    const backwards = await settleOrder({
      reports: contest().reverse(),
      resolveKey: allKeys,
      ...freshSettler(),
    });
    if (!forwards.ok || forwards.action !== 'settled') throw new Error('expected a settlement');
    if (!backwards.ok || backwards.action !== 'settled') throw new Error('expected a settlement');
    expect(forwards.record.jti).toBe(backwards.record.jti);
  });

  test('输家的 jti 没有被认领——它还能去结算属于它的那笔订单', async () => {
    const settler = freshSettler();
    await settleOrder({ reports: contest(), resolveKey: allKeys, ...settler });

    expect(settler.jtiRegistry.orderOf('atr_late')).toBe('ord_1');
    expect(settler.jtiRegistry.orderOf('atr_early')).toBeUndefined();

    const elsewhere = await settleOrder({
      reports: [report({ report_id: 'rep_2', order_id: 'ord_2', attribution_token: earlier })],
      resolveKey: allKeys,
      ...settler,
    });
    expect(elsewhere.ok).toBe(true);
  });

  test('赢家的 jti 被认领后，它自己也不能再去结算另一笔订单', async () => {
    const settler = freshSettler();
    await settleOrder({
      reports: [report({ attribution_token: later })],
      resolveKey: allKeys,
      ...settler,
    });

    const replay = await settleOrder({
      reports: [report({ report_id: 'rep_2', order_id: 'ord_2', attribution_token: later })],
      resolveKey: allKeys,
      ...settler,
    });
    expect(replay.ok).toBe(false);
    if (replay.ok) return;
    expect(replay.error.code).toBe('replayed_jti');
  });

  test('first-touch（§7.4 可配置）裁出的是另一个赢家，且记录里写明用了哪条规则', async () => {
    const settler = freshSettler();
    const result = await settleOrder({
      reports: contest(),
      resolveKey: allKeys,
      rule: 'first_touch',
      ...settler,
    });

    expect(result.ok).toBe(true);
    if (!result.ok || result.action !== 'settled') throw new Error('expected a settlement');
    // Both chains share one origin hop issued at IAT, so first-touch ties on
    // signed_at and falls to the jti tie-break: "atr_early" < "atr_late".
    expect(result.record.jti).toBe('atr_early');
    expect(result.record.rule).toBe('first_touch');
  });
});

describe('adjudicate 的排序与并列', () => {
  const candidate = (signedAt: string, jti: string, issuedAt?: Date) => ({
    token: relayedToken({ jti, signedAt, ...(issuedAt ? { issuedAt } : {}) }),
  });

  test('last-touch 取最大 signed_at', () => {
    const winner = adjudicate([
      candidate('2026-09-23T10:05:00.000Z', 'atr_a'),
      candidate('2026-09-23T10:20:00.000Z', 'atr_b'),
    ]);
    expect(winner!.token.jti).toBe('atr_b');
  });

  test('并列时取字典序最小的 jti，且与输入顺序无关', () => {
    const a = candidate('2026-09-23T10:20:00.000Z', 'atr_aaa');
    const b = candidate('2026-09-23T10:20:00.000Z', 'atr_bbb');
    // Two settlers reading the same two tokens in different orders must land on
    // the same winner, or their ledgers never reconcile.
    expect(adjudicate([a, b])!.token.jti).toBe('atr_aaa');
    expect(adjudicate([b, a])!.token.jti).toBe('atr_aaa');
  });

  test('first-touch 看的是第一跳，不是最后一跳——两条规则会给出不同答案', () => {
    // a: origin 10:00, last hop 10:05.  b: origin 10:10, last hop 10:20.
    const a = candidate('2026-09-23T10:05:00.000Z', 'atr_a');
    const b = candidate('2026-09-23T10:20:00.000Z', 'atr_b', new Date('2026-09-23T10:10:00.000Z'));
    expect(adjudicate([a, b], 'last_touch')!.token.jti).toBe('atr_b');
    expect(adjudicate([a, b], 'first_touch')!.token.jti).toBe('atr_a');
    expect(adjudicate([b, a], 'first_touch')!.token.jti).toBe('atr_a');
  });

  test('空候选集返回 undefined', () => {
    expect(adjudicate([])).toBeUndefined();
  });
});

describe('退款与撤单（§6.1 status）', () => {
  test('refunded 冲掉已结算的订单，但不重新打开它', async () => {
    const settler = freshSettler();
    const token = originToken();
    await settleOrder({ reports: [report({ attribution_token: token })], resolveKey: allKeys, ...settler });

    const refund = await settleOrder({
      reports: [report({ report_id: 'rep_refund', status: 'refunded', attribution_token: token })],
      resolveKey: allKeys,
      ...settler,
    });
    expect(refund.ok).toBe(true);
    if (!refund.ok || refund.action !== 'reversed') throw new Error('expected a reversal');
    expect(refund.record.status).toBe('refunded');
    expect(settler.ledger.recordOf('ord_1')!.status).toBe('refunded');

    // Refund-then-reconfirm must not launder a second payout past row 11.
    const again = await settleOrder({
      reports: [report({ report_id: 'rep_again', attribution_token: token })],
      resolveKey: allKeys,
      ...settler,
    });
    expect(again.ok).toBe(false);
    if (again.ok) return;
    expect(again.error.code).toBe('duplicate_order');
  });

  test('从未结算过的订单报退款 → 挂起，不凭空造一条冲正记录', async () => {
    const settler = freshSettler();
    const result = await settleOrder({
      reports: [report({ status: 'cancelled', attribution_token: originToken() })],
      resolveKey: allKeys,
      ...settler,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.action).toBe('held');
    expect(settler.ledger.settledOrders).toBe(0);
  });

  test('同一批里 confirmed 与 refunded 并存时，先结算', async () => {
    const settler = freshSettler();
    const result = await settleOrder({
      reports: [
        report({
          report_id: 'rep_refund',
          status: 'refunded',
          attribution_token: relayedToken({ jti: 'atr_r', signedAt: '2026-09-23T10:20:00.000Z' }),
        }),
        report({ report_id: 'rep_ok', attribution_token: originToken() }),
      ],
      resolveKey: allKeys,
      ...settler,
    });
    expect(result.ok).toBe(true);
    if (!result.ok || result.action !== 'settled') throw new Error('expected a settlement');
    expect(result.record.reportId).toBe('rep_ok');
  });
});

describe('回报本身不合格时（§7.1 rows 1–10）', () => {
  test('provider_id 与凭证不符 → provider_mismatch，钱不动', async () => {
    const settler = freshSettler();
    const result = await settleOrder({
      reports: [report({ provider_id: 'prov_someone_else', attribution_token: originToken() })],
      resolveKey: allKeys,
      ...settler,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('provider_mismatch');
    expect(settler.ledger.settledOrders).toBe(0);
  });

  test('窗口按成交时刻判，不按验证时刻', async () => {
    const settler = freshSettler();
    // The token's TTL is an hour from IAT. A sale inside that window settles
    // however late the report arrives; a sale outside it does not.
    const inWindow = await settleOrder({
      reports: [report({ attribution_token: originToken() })],
      resolveKey: allKeys,
      ...settler,
    });
    expect(inWindow.ok).toBe(true);

    const outOfWindow = await settleOrder({
      reports: [
        report({
          report_id: 'rep_late',
          order_id: 'ord_2',
          occurred_at: '2026-09-23T13:00:00.000Z',
          attribution_token: originToken({ jti: 'atr_2' }),
        }),
      ],
      resolveKey: allKeys,
      ...settler,
    });
    expect(outOfWindow.ok).toBe(false);
    if (outOfWindow.ok) return;
    expect(outOfWindow.error.code).toBe('token_expired');
  });

  test('候选全军覆没时，报走得最远的那条错——与输入顺序无关', async () => {
    const base = originToken({ jti: 'atr_forged' });
    const forged: AttributionToken = {
      ...base,
      chain: base.chain.map((node) => ({
        ...node,
        signature: (node.signature.endsWith('A') ? 'B' : 'A') + node.signature.slice(1),
      })),
    };
    const structurallyBroken: AttributionToken = { ...originToken({ jti: 'atr_broken' }), chain: [] };

    const reports = [
      report({ report_id: 'rep_forged', attribution_token: forged }),
      report({ report_id: 'rep_broken', attribution_token: structurallyBroken }),
    ];

    const settler = freshSettler();
    const forwards = await settleOrder({ reports, resolveKey: allKeys, ...settler });
    const backwards = await settleOrder({
      reports: [...reports].reverse(),
      resolveKey: allKeys,
      ...freshSettler(),
    });

    expect(forwards.ok).toBe(false);
    expect(backwards.ok).toBe(false);
    if (forwards.ok || backwards.ok) return;
    // signature_invalid is row 5, chain_broken is row 1: the forged token
    // survived more of the filter, so it is the more informative diagnosis.
    expect(forwards.error.code).toBe('signature_invalid');
    expect(backwards.error.code).toBe('signature_invalid');
    expect(settler.ledger.settledOrders).toBe(0);
  });

  test('一张坏凭证不会拖垮同一订单里的好凭证', async () => {
    const settler = freshSettler();
    const unknownIssuer = appendRelayHop({
      privateJwk: OUTSIDER.privateJwk,
      kid: OUTSIDER.kid,
      catalogId: 'cat_unknown',
      token: originToken({ jti: 'atr_unknown' }),
      chainComplete: true,
      now: () => new Date('2026-09-23T10:25:00.000Z'),
    });

    const result = await settleOrder({
      reports: [
        report({ report_id: 'rep_bad', attribution_token: unknownIssuer }),
        report({ report_id: 'rep_good', attribution_token: originToken() }),
      ],
      resolveKey: allKeys,
      ...settler,
    });

    expect(result.ok).toBe(true);
    if (!result.ok || result.action !== 'settled') throw new Error('expected a settlement');
    expect(result.record.reportId).toBe('rep_good');
    // The bad one is recorded as rejected rather than dropped: a settler has to
    // be able to tell the merchant why its report lost.
    const bad = result.candidates.find((c) => c.reportId === 'rep_bad')!;
    expect(bad.error!.code).toBe('key_not_found');
    expect(bad.error!.hop).toBe(2);
    expect(bad.won).toBe(false);
  });
});

describe('输入契约', () => {
  test('一次只能结一个订单', async () => {
    const err = await rejection(
      settleOrder({
        reports: [
          report({ attribution_token: originToken() }),
          report({ report_id: 'rep_2', order_id: 'ord_2', attribution_token: originToken() }),
        ],
        resolveKey: allKeys,
        ...freshSettler(),
      }),
    );
    expect(err.message).toContain('reports for one order');
  });

  test('空回报集直接抛错，而不是静悄悄地当成「没什么可结的」', async () => {
    const err = await rejection(settleOrder({ reports: [], resolveKey: allKeys, ...freshSettler() }));
    expect(err.message).toContain('at least one report');
  });

  test('金额必须是最小单位整数（§2.3）', async () => {
    const err = await rejection(
      settleOrder({
        reports: [report({ amount_minor: 129.5, attribution_token: originToken() })],
        resolveKey: allKeys,
        ...freshSettler(),
      }),
    );
    expect(err.message).toContain('amount_minor');
  });

  test('ledger.commit 挡住绕过第 11 条的直接写入', () => {
    const ledger = new SettlementLedger();
    const record = {
      orderId: 'ord_1',
      reportId: 'rep_1',
      jti: 'atr_1',
      agentId: 'agent_alpha',
      settlingCatalogIds: ['cat_origin'],
      amountMinor: 100,
      currency: 'CNY',
      occurredAt: SOLD_AT,
      status: 'confirmed' as ConversionStatus,
      complete: true,
      lastSignedAt: SOLD_AT,
      rule: 'last_touch' as const,
    };
    ledger.commit(record);
    expect(() => ledger.commit({ ...record, reportId: 'rep_2' })).toThrow('already settled');
    expect(ledger.records()).toHaveLength(1);
  });
});

describe('replayGuard 的只读模式（claim: false）', () => {
  test('只读检查不占坑——查过之后那张凭证仍可被正式认领', async () => {
    const registry = new JtiRegistry();
    const token = originToken();

    const peek = await verifyAttributionToken({
      token,
      resolveKey: allKeys,
      at: new Date(SOLD_AT),
      replayGuard: { registry, orderId: 'ord_1', claim: false },
    });
    expect(peek.ok).toBe(true);
    expect(registry.size).toBe(0);

    const claimed = await verifyAttributionToken({
      token,
      resolveKey: allKeys,
      at: new Date(SOLD_AT),
      replayGuard: { registry, orderId: 'ord_1' },
    });
    expect(claimed.ok).toBe(true);
    expect(registry.orderOf('atr_origin')).toBe('ord_1');
  });

  test('只读模式照样看得见别人已经认领的坑', async () => {
    const registry = new JtiRegistry();
    registry.claim('atr_origin', 'ord_other', new Date('2026-09-23T11:00:00.000Z'));

    const result = await verifyAttributionToken({
      token: originToken(),
      resolveKey: allKeys,
      at: new Date(SOLD_AT),
      replayGuard: { registry, orderId: 'ord_1', claim: false },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('replayed_jti');
  });
});

describe('ReplayStore / LedgerStore 接口与事务契约（T5 判据二）', () => {
  /**
   * A store pair that is async and records the call order, standing in for the
   * durable implementation the contract is written for. If `settleOrder` only
   * worked against the in-memory classes, the interfaces would be decorative.
   */
  function asyncStores() {
    const ledger = new SettlementLedger();
    const registry = new JtiRegistry();
    const calls: string[] = [];
    const tick = <T>(value: T): Promise<T> => Promise.resolve(value);

    const replayStore: ReplayStore = {
      claim: (jti, orderId, expiresAt) => {
        calls.push('claim');
        return tick(registry.claim(jti, orderId, expiresAt));
      },
      orderOf: (jti) => tick(registry.orderOf(jti)),
    };
    const ledgerStore: LedgerStore = {
      recordOf: (orderId) => tick(ledger.recordOf(orderId)),
      outcomeOf: (reportId) => tick(ledger.outcomeOf(reportId)),
      commit: (record) => {
        calls.push('commit');
        ledger.commit(record);
        return tick(undefined);
      },
    };
    return { ledger: ledgerStore, jtiRegistry: replayStore, calls, inner: ledger };
  }

  test('两个接口都可以是异步的——持久化 store 是一次网络调用', async () => {
    const stores = asyncStores();
    const result = await settleOrder({
      reports: [report({ attribution_token: originToken() })],
      resolveKey: allKeys,
      ledger: stores.ledger,
      jtiRegistry: stores.jtiRegistry,
    });
    expect(result.ok).toBe(true);
    if (!result.ok || result.action === 'held') return;
    expect(result.record.orderId).toBe('ord_1');
    expect(stores.inner.settledOrders).toBe(1);
  });

  test('认领与提交都发生在同一个 transaction 回调里', async () => {
    const stores = asyncStores();
    const inside: string[] = [];
    let opened = 0;

    const result = await settleOrder({
      reports: [report({ attribution_token: originToken() })],
      resolveKey: allKeys,
      ledger: stores.ledger,
      jtiRegistry: stores.jtiRegistry,
      transaction: async (work) => {
        opened += 1;
        const before = stores.calls.length;
        const out = await work();
        inside.push(...stores.calls.slice(before));
        return out;
      },
    });

    expect(result.ok).toBe(true);
    // One transaction, both writes inside it. A deployment's payout goes in the
    // same callback, which is the whole reason the hook is shaped this way.
    expect(opened).toBe(1);
    expect(inside).toEqual(['claim', 'commit']);
  });

  test('事务抛错会往上抛，不会变成一条裁决', async () => {
    const stores = asyncStores();
    const err = await rejection(
      settleOrder({
        reports: [report({ attribution_token: originToken() })],
        resolveKey: allKeys,
        ledger: stores.ledger,
        jtiRegistry: stores.jtiRegistry,
        transaction: async () => {
          throw new Error('deadlock detected');
        },
      }),
    );
    // A failed transaction says nothing about the token. Reporting it as a
    // verdict would tell the merchant their token was bad when the database
    // was.
    expect(err.message).toBe('deadlock detected');
    expect(stores.inner.settledOrders).toBe(0);
  });

  test('回滚后没有半截状态——认领没留下，记录也没留下', async () => {
    const ledger = new SettlementLedger();
    const registry = new JtiRegistry();
    const staged: Array<() => void> = [];

    // The minimum a transactional store must do: buffer the writes and apply
    // them only on commit. A store that applies `claim` eagerly leaves the jti
    // burned against an order that was never paid.
    const stores = {
      ledger: {
        recordOf: (orderId: string) => ledger.recordOf(orderId),
        outcomeOf: (reportId: string) => ledger.outcomeOf(reportId),
        commit: (record) => {
          staged.push(() => ledger.commit(record));
        },
      } satisfies LedgerStore,
      jtiRegistry: {
        claim: (jti: string, orderId: string, expiresAt: Date) => {
          staged.push(() => void registry.claim(jti, orderId, expiresAt));
          return registry.orderOf(jti) === undefined || registry.orderOf(jti) === orderId;
        },
        orderOf: (jti: string) => registry.orderOf(jti),
      } satisfies ReplayStore,
    };

    await rejection(
      settleOrder({
        reports: [report({ attribution_token: originToken() })],
        resolveKey: allKeys,
        ...stores,
        transaction: async (work) => {
          await work();
          throw new Error('rolled back after the work, before the commit');
        },
      }),
    );

    expect(ledger.settledOrders).toBe(0);
    expect(registry.orderOf('atr_origin')).toBeUndefined();
    expect(staged).toHaveLength(2);
  });

  test('nonTransactional 是默认值——内存实现下与显式传入等价', async () => {
    const withDefault = freshSettler();
    const withExplicit = freshSettler();
    const input = () => report({ attribution_token: originToken() });

    const a = await settleOrder({ reports: [input()], resolveKey: allKeys, ...withDefault });
    const b = await settleOrder({
      reports: [input()],
      resolveKey: allKeys,
      ...withExplicit,
      transaction: nonTransactional,
    });

    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok || a.action === 'held' || b.action === 'held') return;
    expect(a.record).toEqual(b.record);
  });

  test('内存实现满足接口——这是它们唯一被允许的用途', () => {
    const replay: ReplayStore = new JtiRegistry();
    const ledger: LedgerStore = new SettlementLedger();
    expect(replay.claim('atr_x', 'ord_x', new Date(Date.now() + 60_000))).toBe(true);
    expect(ledger.recordOf('ord_x')).toBeUndefined();
  });
});
