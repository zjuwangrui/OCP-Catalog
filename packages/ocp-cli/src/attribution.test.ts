import { describe, expect, test } from 'bun:test';
import {
  appendRelayHop,
  generateEd25519KeyPair,
  issueOriginToken,
  publicJwkOf,
  type AttributionToken,
  type GeneratedKeyPair,
} from '@ocp-catalog/ocp-crypto';
import {
  checkResolveBinding,
  extractAttributionToken,
  parseJwksSpec,
  requiredCatalogIds,
  verifyAttributionPayload,
} from './attribution';

const ORIGIN = generateEd25519KeyPair();
const RELAY = generateEd25519KeyPair();

const IAT = new Date('2026-09-24T10:00:00.000Z');
const AT = new Date('2026-09-24T10:30:00.000Z');

function jwksOf(pair: GeneratedKeyPair) {
  return { keys: [{ ...publicJwkOf(pair.privateJwk), kid: pair.kid, alg: 'EdDSA', use: 'sig' }] };
}

const ORIGIN_JWKS = jwksOf(ORIGIN);
const RELAY_JWKS = jwksOf(RELAY);

function originToken(over: Partial<Parameters<typeof issueOriginToken>[0]> = {}): AttributionToken {
  return issueOriginToken({
    privateJwk: ORIGIN.privateJwk,
    kid: ORIGIN.kid,
    catalogId: 'cat_origin',
    agentId: 'agent_alpha',
    entryId: 'entry_origin_sku-001',
    objectId: 'sku-001',
    providerId: 'prov_merchant',
    purpose: 'checkout',
    jti: 'atr_cli',
    now: () => IAT,
    ...over,
  });
}

function relayedToken(): AttributionToken {
  return appendRelayHop({
    privateJwk: RELAY.privateJwk,
    kid: RELAY.kid,
    catalogId: 'cat_relay',
    token: originToken(),
    chainComplete: true,
    settles: true,
    now: () => new Date('2026-09-24T10:05:00.000Z'),
  });
}

/** A resolve response shaped like the one the example node returns. */
function resolveResponse(token: AttributionToken, over: Record<string, unknown> = {}) {
  return {
    ocp_version: '1.0',
    kind: 'ResolvableReference',
    catalog_id: 'cat_origin',
    entry_id: 'entry_origin_sku-001',
    object_id: 'sku-001',
    provider_id: 'prov_merchant',
    action_bindings: [
      { action_id: 'view', action_type: 'url', label: 'View' },
      { action_id: 'checkout', action_type: 'url', label: 'Buy', attribution: token },
    ],
    ...over,
  };
}

describe('从各种文档里取出凭证', () => {
  test('裸 token、resolve 响应、ConversionReport 三种入口都认', () => {
    const token = originToken();
    expect(extractAttributionToken(token)!.jti).toBe('atr_cli');
    expect(extractAttributionToken(resolveResponse(token))!.jti).toBe('atr_cli');
    expect(extractAttributionToken({ kind: 'ConversionReport', attribution_token: token })!.jti).toBe('atr_cli');
  });

  test('没有凭证时返回 undefined，而不是把别的对象当凭证', () => {
    expect(extractAttributionToken({ action_bindings: [{ action_id: 'view' }] })).toBeUndefined();
    expect(extractAttributionToken({ attribution: { kind: 'CatalogManifest' } })).toBeUndefined();
    expect(extractAttributionToken(null)).toBeUndefined();
    expect(extractAttributionToken('not json')).toBeUndefined();
  });

  test('需要哪些 catalog_id 的密钥，按跳序去重列出', () => {
    expect(requiredCatalogIds(originToken())).toEqual(['cat_origin']);
    expect(requiredCatalogIds(relayedToken())).toEqual(['cat_origin', 'cat_relay']);
  });
});

describe('--jwks 的解析', () => {
  test('按第一个 = 切分，URL 查询串里的 = 不会把 catalog_id 截断', () => {
    expect(parseJwksSpec('cat_a=./jwks.json')).toEqual({ catalogId: 'cat_a', source: './jwks.json' });
    expect(parseJwksSpec('cat_a=https://a.example/jwks?v=2')).toEqual({
      catalogId: 'cat_a',
      source: 'https://a.example/jwks?v=2',
    });
  });

  test('缺了任一半就报错，并告诉用户怎么查出该填什么', () => {
    for (const bad of ['cat_a', '=./jwks.json', 'cat_a=']) {
      expect(() => parseJwksSpec(bad)).toThrow();
    }
  });
});

describe('ocp attribution verify 的判定', () => {
  test('单跳：验通并报出 agent、settles、complete 与 last-touch 排序键', async () => {
    const result = await verifyAttributionPayload({
      payload: resolveResponse(originToken()),
      jwks: { cat_origin: ORIGIN_JWKS },
      at: AT,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.agent_id).toBe('agent_alpha');
    expect(result.settles).toEqual(['cat_origin']);
    expect(result.complete).toBe(true);
    expect(result.hops).toBe(1);
    expect(result.last_signed_at).toBe(IAT.toISOString());
  });

  test('缺某一跳的密钥 → jwks_not_supplied，并列出要补哪些', async () => {
    const result = await verifyAttributionPayload({
      payload: relayedToken(),
      jwks: { cat_origin: ORIGIN_JWKS },
      at: AT,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    // Not key_not_found: the relay never published a key set here, it simply
    // was not supplied. One is a dispute, the other is a missing flag.
    expect(result.error.code).toBe('jwks_not_supplied');
    expect(result.error.message).toContain('cat_relay');
  });

  test('两跳都给了密钥 → 验通，settles 按跳序', async () => {
    const result = await verifyAttributionPayload({
      payload: relayedToken(),
      jwks: { cat_origin: ORIGIN_JWKS, cat_relay: RELAY_JWKS },
      at: AT,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.hops).toBe(2);
    // Both hops declared `settles`, so both are owed (§7.3) — a relay taking a
    // cut does not displace the node that found the object.
    expect(result.settles).toEqual(['cat_origin', 'cat_relay']);
  });

  test('篡改后一跳 → 报出最小的失效跳号，那才是篡改位置', async () => {
    const token = relayedToken();
    const tampered: AttributionToken = {
      ...token,
      chain: token.chain.map((node, index) =>
        index === 1
          ? { ...node, signature: (node.signature.startsWith('A') ? 'B' : 'A') + node.signature.slice(1) }
          : node,
      ),
    };

    const result = await verifyAttributionPayload({
      payload: tampered,
      jwks: { cat_origin: ORIGIN_JWKS, cat_relay: RELAY_JWKS },
      at: AT,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('signature_invalid');
    expect(result.error.hop).toBe(2);
  });

  test('过了 exp → token_expired；而「此刻」不是判定时点', async () => {
    const expired = await verifyAttributionPayload({
      payload: originToken(),
      jwks: { cat_origin: ORIGIN_JWKS },
      at: new Date('2026-09-25T10:30:00.000Z'),
    });
    expect(expired.ok).toBe(false);
    if (expired.ok) return;
    expect(expired.error.code).toBe('token_expired');

    // The same token judged at the moment of the sale is fine. This is the whole
    // reason --at exists: a sale reported a day late is still a valid sale.
    const atSale = await verifyAttributionPayload({
      payload: originToken(),
      jwks: { cat_origin: ORIGIN_JWKS },
      at: AT,
    });
    expect(atSale.ok).toBe(true);
  });

  test('provider 不符 → provider_mismatch', async () => {
    const result = await verifyAttributionPayload({
      payload: originToken(),
      jwks: { cat_origin: ORIGIN_JWKS },
      at: AT,
      expectedProviderId: 'prov_someone_else',
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('provider_mismatch');
  });

  test('view 凭证默认拒（不可结算），--any-purpose 下只验密码学部分', async () => {
    const view = originToken({ purpose: 'view', jti: 'atr_view' });

    const settleable = await verifyAttributionPayload({
      payload: view,
      jwks: { cat_origin: ORIGIN_JWKS },
      at: AT,
    });
    expect(settleable.ok).toBe(false);
    if (settleable.ok) return;
    expect(settleable.error.code).toBe('purpose_not_settleable');

    const cryptoOnly = await verifyAttributionPayload({
      payload: view,
      jwks: { cat_origin: ORIGIN_JWKS },
      at: AT,
      requirePurpose: null,
    });
    expect(cryptoOnly.ok).toBe(true);
  });

  test('文档里根本没有凭证 → no_attribution，而不是崩', async () => {
    const result = await verifyAttributionPayload({ payload: { kind: 'ResolvableReference' }, jwks: {} });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('no_attribution');
  });
});

describe('凭证与这次 resolve 的绑定（§7.1 看不到的那部分）', () => {
  test('object_id 对得上 → 通过', () => {
    const token = originToken();
    expect(checkResolveBinding(token, resolveResponse(token)).ok).toBe(true);
  });

  test('拿一张真凭证去认另一个对象 → object_mismatch', () => {
    const token = originToken();
    // Every signature still verifies. What is wrong is what the token is being
    // pointed at, and no amount of per-hop verification can see that.
    const elsewhere = resolveResponse(token, { object_id: 'sku-999' });
    const result = checkResolveBinding(token, elsewhere);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('object_mismatch');
    expect(result.error.message).toContain('sku-999');
  });

  test('中继链上 entry_id 不参与绑定——core claims 跨跳不可变', () => {
    const token = relayedToken();
    // The relay is answering with its own entry id; the token still carries the
    // origin's, because §4.3 forbids rewriting it. Binding on entry_id here
    // would reject every relayed token.
    const viaRelay = resolveResponse(token, {
      catalog_id: 'cat_relay',
      entry_id: 'entry_relay_sku-001',
    });
    expect(checkResolveBinding(token, viaRelay).ok).toBe(true);
  });

  test('但自签的那一跳上 entry_id 仍然绑定', () => {
    const token = originToken();
    const wrongEntry = resolveResponse(token, { entry_id: 'entry_origin_sku-002' });
    const result = checkResolveBinding(token, wrongEntry);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('object_mismatch');
  });
});
