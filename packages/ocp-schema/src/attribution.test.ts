import { describe, expect, test } from 'bun:test';
import {
  actionBindingSchema,
  attributionChainNodeSchema,
  attributionContextSchema,
  attributionTokenSchema,
  catalogQueryRequestSchema,
  conversionReportSchema,
  resolvableReferenceSchema,
  resolveRequestSchema,
} from './index';

const originNode = {
  catalog_id: 'cat_commerce_demo',
  hop: 1,
  role: 'origin',
  settles: true,
  chain_complete: true,
  alg: 'EdDSA',
  kid: 'key_2026_09',
  signed_at: '2026-09-15T00:00:00.000Z',
  signature: 'c2lnbmF0dXJlLXBsYWNlaG9sZGVy',
};

const validToken = {
  ocp_version: '1.0',
  kind: 'AttributionToken',
  jti: 'atk_01J9Z0000000000000000000',
  iss: 'cat_commerce_demo',
  iat: '2026-09-15T00:00:00.000Z',
  exp: '2026-09-22T00:00:00.000Z',
  agent_id: 'agent_shopping_assistant',
  entry_id: 'entry_1',
  object_id: 'provider_product_1',
  provider_id: 'provider_acme',
  purpose: 'checkout',
  complete: true,
  chain: [originNode],
};

const validReport = {
  ocp_version: '1.0',
  kind: 'ConversionReport',
  report_id: 'rep_1',
  order_id: 'order_1',
  provider_id: 'provider_acme',
  attribution_token: validToken,
  amount_minor: 12900,
  currency: 'CNY',
  occurred_at: '2026-09-16T10:00:00.000Z',
  status: 'confirmed',
};

// --- T1 的核心完成判据：不含 attribution 的旧 payload 必须仍然通过校验 ---

describe('零破坏：旧 payload 不受归因字段影响', () => {
  const legacyResolveRequest = {
    ocp_version: '1.0',
    kind: 'ResolveRequest',
    catalog_id: 'cat_commerce_demo',
    entry_id: 'entry_1',
    purpose: 'checkout',
  };

  const legacyActionBinding = {
    action_id: 'buy',
    action_type: 'url',
    label: 'Buy now',
    entrypoint: { url: 'https://provider.example/checkout/product_1' },
  };

  test('不含 attribution_context 的 ResolveRequest 仍然通过', () => {
    const result = resolveRequestSchema.safeParse(legacyResolveRequest);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).not.toHaveProperty('attribution_context');
      // 既有默认值行为不得改变
      expect(result.data.live_check).toBe(true);
      expect(result.data.requested_fields).toEqual([]);
    }
  });

  test('不含 attribution 的 ActionBinding 仍然通过', () => {
    const result = actionBindingSchema.safeParse(legacyActionBinding);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).not.toHaveProperty('attribution');
      expect(result.data.requires_user_confirmation).toBe(false);
    }
  });

  test('不含 attribution 的 ResolvableReference 仍然通过', () => {
    expect(resolvableReferenceSchema.safeParse({
      ocp_version: '1.0',
      kind: 'ResolvableReference',
      id: 'ref_1',
      catalog_id: 'cat_commerce_demo',
      entry_id: 'entry_1',
      commercial_object_id: 'obj_1',
      object_id: 'provider_product_1',
      object_type: 'product',
      provider_id: 'provider_acme',
      title: 'Provider-owned product',
      visible_attributes: {},
      action_bindings: [legacyActionBinding],
      freshness: {
        object_updated_at: '2026-09-14T00:00:00.000Z',
        resolved_at: '2026-09-15T00:00:00.000Z',
      },
      expires_at: '2026-09-15T01:00:00.000Z',
    }).success).toBe(true);
  });

  test('catalogQueryRequestSchema 未被触碰，仍然拒绝未知字段', () => {
    const baseQuery = {
      ocp_version: '1.0',
      kind: 'CatalogQueryRequest',
      catalog_id: 'cat_commerce_demo',
      query: 'running shoes',
    };
    expect(catalogQueryRequestSchema.safeParse(baseQuery).success).toBe(true);
    expect(catalogQueryRequestSchema.safeParse({
      ...baseQuery,
      attribution_context: { agent_id: 'agent_shopping_assistant' },
    }).success).toBe(false);
  });
});

// --- 新增字段的挂载 ---

describe('归因字段挂载', () => {
  test('ResolveRequest 接受 attribution_context', () => {
    expect(resolveRequestSchema.safeParse({
      entry_id: 'entry_1',
      purpose: 'checkout',
      attribution_context: { agent_id: 'agent_shopping_assistant' },
    }).success).toBe(true);
  });

  test('ActionBinding 接受 attribution token', () => {
    expect(actionBindingSchema.safeParse({
      action_id: 'buy',
      action_type: 'url',
      label: 'Buy now',
      entrypoint: { url: 'https://provider.example/checkout/product_1' },
      attribution: validToken,
    }).success).toBe(true);
  });

  test('中继场景：attribution_context 可携带 upstream_token', () => {
    expect(attributionContextSchema.safeParse({
      agent_id: 'agent_shopping_assistant',
      agent_identity_source: 'ocp',
      upstream_token: validToken,
    }).success).toBe(true);
  });

  test('attribution_context 必须带 agent_id', () => {
    expect(attributionContextSchema.safeParse({
      agent_identity_source: 'ocp',
    }).success).toBe(false);
  });
});

// --- AttributionToken ---

describe('attributionTokenSchema', () => {
  test('接受一条合法的单跳凭证', () => {
    expect(attributionTokenSchema.safeParse(validToken).success).toBe(true);
  });

  test('拒绝缺少 jti 的凭证（防重放的唯一依据）', () => {
    const { jti: _jti, ...withoutJti } = validToken;
    expect(attributionTokenSchema.safeParse(withoutJti).success).toBe(false);
  });

  test('拒绝空链', () => {
    expect(attributionTokenSchema.safeParse({ ...validToken, chain: [] }).success).toBe(false);
  });

  test('拒绝超过 8 跳的链（放大型拒绝服务的攻击面控制）', () => {
    const chain = Array.from({ length: 9 }, (_, i) => ({
      ...originNode,
      hop: i + 1,
      role: i === 0 ? 'origin' : 'relay',
      catalog_id: `cat_${i}`,
    }));
    expect(attributionTokenSchema.safeParse({ ...validToken, chain }).success).toBe(false);
  });

  test('拒绝协议契约之外的字段', () => {
    expect(attributionTokenSchema.safeParse({ ...validToken, user_id: 'u_1' }).success).toBe(false);
  });

  test('agent_identity_source 可省略，也接受 external', () => {
    expect(attributionTokenSchema.safeParse({
      ...validToken,
      agent_identity_source: 'external',
    }).success).toBe(true);
    expect(attributionTokenSchema.safeParse({
      ...validToken,
      agent_identity_source: 'visa_tap',
    }).success).toBe(false);
  });
});

describe('attributionChainNodeSchema', () => {
  test('拒绝 EdDSA 以外的算法（alg 参与签名材料，防算法混淆）', () => {
    expect(attributionChainNodeSchema.safeParse({ ...originNode, alg: 'HS256' }).success).toBe(false);
  });

  test('拒绝 origin / relay 以外的角色', () => {
    expect(attributionChainNodeSchema.safeParse({ ...originNode, role: 'terminal' }).success).toBe(false);
  });

  test('拒绝非 base64url 的签名（带填充或标准 base64 字符）', () => {
    expect(attributionChainNodeSchema.safeParse({
      ...originNode,
      signature: 'c2lnbmF0dXJl+Cg==',
    }).success).toBe(false);
  });

  test('拒绝 hop = 0', () => {
    expect(attributionChainNodeSchema.safeParse({ ...originNode, hop: 0 }).success).toBe(false);
  });

  test('settles 与 chain_complete 是必填，不能靠默认值猜', () => {
    const { settles: _s, ...withoutSettles } = originNode;
    expect(attributionChainNodeSchema.safeParse(withoutSettles).success).toBe(false);
    const { chain_complete: _c, ...withoutComplete } = originNode;
    expect(attributionChainNodeSchema.safeParse(withoutComplete).success).toBe(false);
  });
});

// --- ConversionReport ---

describe('conversionReportSchema', () => {
  test('接受一条合法的转化回报', () => {
    expect(conversionReportSchema.safeParse(validReport).success).toBe(true);
  });

  test('拒绝浮点金额（canonical §7 Level 1 只接受安全整数）', () => {
    expect(conversionReportSchema.safeParse({
      ...validReport,
      amount_minor: 129.5,
    }).success).toBe(false);
  });

  test('拒绝超出安全整数上界的金额', () => {
    expect(conversionReportSchema.safeParse({
      ...validReport,
      amount_minor: 9007199254740992,
    }).success).toBe(false);
  });

  test('拒绝非 ISO 4217 形态的币种', () => {
    expect(conversionReportSchema.safeParse({ ...validReport, currency: 'cny' }).success).toBe(false);
    expect(conversionReportSchema.safeParse({ ...validReport, currency: 'RMB1' }).success).toBe(false);
  });

  test('接受 refunded 状态（结算必须能冲正）', () => {
    expect(conversionReportSchema.safeParse({ ...validReport, status: 'refunded' }).success).toBe(true);
  });

  test('report_id 与 order_id 都必填，且不可互相替代', () => {
    const { report_id: _r, ...withoutReportId } = validReport;
    expect(conversionReportSchema.safeParse(withoutReportId).success).toBe(false);
    const { order_id: _o, ...withoutOrderId } = validReport;
    expect(conversionReportSchema.safeParse(withoutOrderId).success).toBe(false);
  });
});
