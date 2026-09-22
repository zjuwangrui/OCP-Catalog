import { describe, expect, test } from 'bun:test';
import { ATTRIBUTION_ERROR_CODES } from '@ocp-catalog/ocp-crypto';
import {
  assertNoAttributionSubjects,
  countBucketOf,
  durationBucketOf,
  hashCorrelationId,
  ocpActivityAttributionOutcomeSchema,
  ocpActivityAttributionSchema,
  ocpActivityEventInputSchema,
  ocpActivityEventSchema,
  ocpPublicActivityEventSchema,
  statusClassOf,
  toPublicActivityEvent,
  type OcpActivityEvent,
} from './index';

const JTI = 'atk_01J9Z0000000000000000000';
const AGENT_ID = 'agent_demo_shopper';
const ORDER_ID = 'ord_7f3a91c4';
const REPORT_ID = 'rep_20260930_0001';
const SECRET = 'projection-secret-for-tests';

function rawEvent(overrides: Record<string, unknown> = {}): OcpActivityEvent {
  return ocpActivityEventSchema.parse({
    event_id: 'evt_0001',
    event_type: 'attribution.settlement_decided',
    occurred_at: '2026-09-30T10:00:00.000Z',
    observed_at: '2026-09-30T10:00:00.100Z',
    correlation_id: 'corr_9d2f4b7a',
    source_kind: 'catalog_node',
    client_kind: 'http',
    protocol_family: 'attribution',
    catalog_id: 'cat_commerce_demo',
    provider_id: 'prov_demo',
    status_code: 200,
    duration_ms: 42,
    public_visibility: 'public',
    attribution: {
      jti: JTI,
      agent_id: AGENT_ID,
      order_id: ORDER_ID,
      report_id: REPORT_ID,
      hop_count: 2,
      chain_complete: true,
      purpose: 'checkout',
      outcome: 'ok',
    },
    ...overrides,
  });
}

describe('归因关联字段（T6）', () => {
  test('原始事件可以带归因主体，聚成一个 attribution 块', () => {
    const event = rawEvent();
    expect(event.attribution?.jti).toBe(JTI);
    expect(event.attribution?.agent_id).toBe(AGENT_ID);
    expect(event.attribution?.order_id).toBe(ORDER_ID);
  });

  test('attribution 块是 strict 的——多一个字段就不通过', () => {
    const parsed = ocpActivityAttributionSchema.safeParse({ jti: JTI, user_id: 'u_1' });
    expect(parsed.success).toBe(false);
  });

  test('归因字段全部可选，老事件一字不改照样通过', () => {
    const parsed = ocpActivityEventInputSchema.safeParse({
      event_type: 'catalog.resolved',
    });
    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.attribution).toBeUndefined();
  });

  test('§4.4 封顶八跳——hop_count 9 不通过', () => {
    expect(ocpActivityAttributionSchema.safeParse({ hop_count: 9 }).success).toBe(false);
    expect(ocpActivityAttributionSchema.safeParse({ hop_count: 8 }).success).toBe(true);
  });

  test('outcome 枚举与 §8 的十一个码对齐——两份手抄不许漂', () => {
    expect(ocpActivityAttributionOutcomeSchema.options).toEqual([
      'ok',
      ...ATTRIBUTION_ERROR_CODES,
    ]);
  });

  test('归因事件类型与 attribution 协议族都在枚举里', () => {
    for (const type of [
      'attribution.token_issued',
      'attribution.token_relayed',
      'attribution.relay_refused',
      'attribution.token_verified',
      'attribution.settlement_decided',
    ]) {
      expect(ocpActivityEventInputSchema.safeParse({ event_type: type }).success).toBe(true);
    }
    expect(
      ocpActivityEventInputSchema.safeParse({
        event_type: 'attribution.token_issued',
        protocol_family: 'attribution',
      }).success,
    ).toBe(true);
  });
});

describe('公开投影里没有明文归因主体（T6 判据）', () => {
  test('jti / agent_id / order_id 一个都不出现——键不出现，值也不出现', async () => {
    const projected = await toPublicActivityEvent(rawEvent(), {
      publicEventId: 'pub_0001',
      correlationSecret: SECRET,
      createdAt: '2026-09-30T10:00:01.000Z',
    });
    expect(projected).toBeTruthy();

    const keys = Object.keys(projected!);
    expect(keys).not.toContain('attribution');
    expect(keys).not.toContain('jti');
    expect(keys).not.toContain('agent_id');
    expect(keys).not.toContain('order_id');

    // 值层面的断言才是真正的那一条：允许保留的字段里也不能夹带。
    const serialized = JSON.stringify(projected);
    for (const subject of [JTI, AGENT_ID, ORDER_ID, REPORT_ID]) {
      expect(serialized).not.toContain(subject);
    }
  });

  test('correlation_id 只以 HMAC 出现，明文不出现', async () => {
    const event = rawEvent();
    const projected = await toPublicActivityEvent(event, {
      publicEventId: 'pub_0002',
      correlationSecret: SECRET,
    });
    expect(projected!.correlation_id_hash).toBe(await hashCorrelationId(event.correlation_id!, SECRET));
    expect(projected!.correlation_id_hash).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify(projected)).not.toContain(event.correlation_id!);
  });

  test('同一条 correlation_id 哈希稳定，不同密钥哈希不同', async () => {
    const a = await hashCorrelationId('corr_9d2f4b7a', SECRET);
    const b = await hashCorrelationId('corr_9d2f4b7a', SECRET);
    const c = await hashCorrelationId('corr_9d2f4b7a', 'another-secret');
    expect(a).toBe(b);
    expect(c).not.toBe(a);
  });

  test('没给密钥就丢掉关联，而不是发一个无密钥摘要', async () => {
    const projected = await toPublicActivityEvent(rawEvent(), { publicEventId: 'pub_0003' });
    expect(projected!.correlation_id_hash).toBe(null);
  });

  test('outcome 是唯一活下来的归因字段——它是闭枚举', async () => {
    const projected = await toPublicActivityEvent(
      rawEvent({ attribution: { jti: JTI, agent_id: AGENT_ID, outcome: 'signature_invalid' } }),
      { publicEventId: 'pub_0004' },
    );
    expect(projected!.attribution_outcome).toBe('signature_invalid');
  });

  test('没有归因的事件投影出 attribution_outcome: null', async () => {
    const projected = await toPublicActivityEvent(
      rawEvent({ event_type: 'catalog.resolved', attribution: undefined }),
      { publicEventId: 'pub_0005' },
    );
    expect(projected!.attribution_outcome).toBe(null);
  });

  test('自定义摘要夹带了 agent_id 就抛错，不发出去', async () => {
    await expect(
      toPublicActivityEvent(rawEvent(), {
        publicEventId: 'pub_0006',
        publicSummary: `settled for ${AGENT_ID}`,
      }),
    ).rejects.toThrow('leaks attribution.agent_id');
  });

  test('异常信息本身不回显泄漏的值', () => {
    let message = '';
    try {
      assertNoAttributionSubjects({ public_summary: `order ${ORDER_ID}` }, { order_id: ORDER_ID });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toBe('public projection leaks attribution.order_id');
    expect(message).not.toContain(ORDER_ID);
  });

  test('公开投影 schema 是 strict 的——多塞一个字段就不通过', () => {
    const projected = ocpPublicActivityEventSchema.safeParse({
      public_event_id: 'pub_0007',
      raw_event_id: 'evt_0007',
      occurred_at: '2026-09-30T10:00:00.000Z',
      event_type: 'attribution.token_verified',
      source_kind: 'catalog_node',
      client_kind: 'http',
      protocol_family: 'attribution',
      status_class: 'success',
      duration_bucket: 'lt_100ms',
      result_count_bucket: 'none',
      public_summary: 'ok',
      created_at: '2026-09-30T10:00:01.000Z',
      agent_id: AGENT_ID,
    });
    expect(projected.success).toBe(false);
  });
});

describe('可见性决定发不发，默认不发', () => {
  test('public_visibility 的默认值是 aggregate_only，投影返回 null', async () => {
    const event = ocpActivityEventSchema.parse({
      event_id: 'evt_0008',
      event_type: 'catalog.resolved',
      occurred_at: '2026-09-30T10:00:00.000Z',
      observed_at: '2026-09-30T10:00:00.000Z',
    });
    expect(event.public_visibility).toBe('aggregate_only');
    expect(await toPublicActivityEvent(event, { publicEventId: 'pub_0008' })).toBe(null);
  });

  test('private 也返回 null', async () => {
    const projected = await toPublicActivityEvent(rawEvent({ public_visibility: 'private' }), {
      publicEventId: 'pub_0009',
      correlationSecret: SECRET,
    });
    expect(projected).toBe(null);
  });

  test('只有 public 才产出一行', async () => {
    const projected = await toPublicActivityEvent(rawEvent(), { publicEventId: 'pub_0010' });
    expect(projected?.public_event_id).toBe('pub_0010');
    expect(projected?.raw_event_id).toBe('evt_0001');
  });
});

describe('投影里的分桶', () => {
  test('归因验签失败不算 server_error——那次 HTTP 调用是成功的', () => {
    const event = rawEvent({
      event_type: 'attribution.token_verified',
      status_code: 200,
      attribution: { jti: JTI, outcome: 'signature_invalid' },
    });
    expect(statusClassOf(event)).toBe('success');
  });

  test('policy.denied 压过它带的状态码', () => {
    expect(statusClassOf({ event_type: 'policy.denied', status_code: 200 })).toBe('policy_denied');
  });

  test('没有状态码就是 unknown，不是 success', () => {
    expect(statusClassOf({ event_type: 'catalog.resolved', status_code: undefined })).toBe('unknown');
  });

  test('状态码按 4xx / 5xx 分', () => {
    expect(statusClassOf({ event_type: 'catalog.resolved', status_code: 404 })).toBe('client_error');
    expect(statusClassOf({ event_type: 'catalog.resolved', status_code: 503 })).toBe('server_error');
  });

  test('时长分桶取边界', () => {
    expect(durationBucketOf(undefined)).toBe('none');
    expect(durationBucketOf(99)).toBe('lt_100ms');
    expect(durationBucketOf(100)).toBe('lt_500ms');
    expect(durationBucketOf(1_000)).toBe('lt_5s');
    expect(durationBucketOf(5_000)).toBe('gte_5s');
  });

  test('计数分桶把 0 和 1 单列——「没结果」和「唯一结果」是两件事', () => {
    expect(countBucketOf(undefined)).toBe('none');
    expect(countBucketOf(0)).toBe('zero');
    expect(countBucketOf(1)).toBe('one');
    expect(countBucketOf(9)).toBe('lt_10');
    expect(countBucketOf(99)).toBe('lt_100');
    expect(countBucketOf(100)).toBe('gte_100');
  });
});
