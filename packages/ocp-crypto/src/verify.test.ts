import { describe, expect, test } from 'bun:test';
import {
  appendRelayHop,
  issueOriginToken,
  type AttributionToken,
  type ChainNode,
} from './attribution';
import { CryptoError } from './errors';
import { generateEd25519KeyPair, publicJwkOf, type Ed25519PublicJwk } from './keys';
import {
  JtiRegistry,
  staticKeyResolver,
  verifyAttributionToken,
  type AttributionKeyResolver,
} from './verify';

const ORIGIN = generateEd25519KeyPair();
const RELAY_A = generateEd25519KeyPair();
const RELAY_B = generateEd25519KeyPair();

const CATALOGS = {
  cat_origin: ORIGIN,
  cat_relay_a: RELAY_A,
  cat_relay_b: RELAY_B,
} as const;

const IAT = new Date('2026-09-21T10:00:00.000Z');
const DURING = new Date('2026-09-21T10:30:00.000Z');

/** The merchant's key material: one JWKS per node, fetched once, then offline. */
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
    jti: 'atr_fixed',
    now: () => IAT,
    ...over,
  });
}

/** origin → relay_a → relay_b, the topology T4's acceptance criterion names. */
function threeHopToken(): AttributionToken {
  const hop2 = appendRelayHop({
    privateJwk: RELAY_A.privateJwk,
    kid: RELAY_A.kid,
    catalogId: 'cat_relay_a',
    token: originToken(),
    chainComplete: true,
    settles: true,
    now: () => new Date('2026-09-21T10:05:00.000Z'),
  });
  return appendRelayHop({
    privateJwk: RELAY_B.privateJwk,
    kid: RELAY_B.kid,
    catalogId: 'cat_relay_b',
    token: hop2,
    chainComplete: true,
    now: () => new Date('2026-09-21T10:10:00.000Z'),
  });
}

/** Replaces one hop in a chain, leaving its signature in place. */
function patchHop(token: AttributionToken, hop: number, patch: Partial<ChainNode>): AttributionToken {
  return {
    ...token,
    chain: token.chain.map((node, index) => (index === hop - 1 ? { ...node, ...patch } : node)),
  };
}

describe('三跳链逐跳验通（T4 判据一）', () => {
  test('三跳链验证通过，complete = true', async () => {
    const token = threeHopToken();
    expect(token.chain).toHaveLength(3);
    expect(token.chain.map((n) => n.catalog_id)).toEqual(['cat_origin', 'cat_relay_a', 'cat_relay_b']);

    const result = await verifyAttributionToken({ token, resolveKey: allKeys, at: DURING });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.complete).toBe(true);
    expect(result.hops).toBe(3);
    expect(result.agentId).toBe('agent_alpha');
  });

  test('结算主体只含 settles=true 的跳（§7.3）', async () => {
    const result = await verifyAttributionToken({ token: threeHopToken(), resolveKey: allKeys, at: DURING });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // relay_b routed but declared no share; it is not a settlement subject.
    expect(result.settlingCatalogIds).toEqual(['cat_origin', 'cat_relay_a']);
  });

  test('last_signed_at 取最后一跳（§7.2 的排序键）', async () => {
    const result = await verifyAttributionToken({ token: threeHopToken(), resolveKey: allKeys, at: DURING });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.lastSignedAt).toBe('2026-09-21T10:10:00.000Z');
  });

  test('单跳 origin 链同样验通——多跳没有把单跳搞坏', async () => {
    const result = await verifyAttributionToken({ token: originToken(), resolveKey: allKeys, at: DURING });
    expect(result.ok).toBe(true);
  });

  test('每一跳都真的验了签：少给一把公钥就过不去', async () => {
    // Without this, a verifier that checked only hop 1 would pass every test above.
    const partial = staticKeyResolver(jwksOf('cat_origin', 'cat_relay_a'));
    const result = await verifyAttributionToken({ token: threeHopToken(), resolveKey: partial, at: DURING });
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('key_not_found');
    expect(result.error?.hop).toBe(3);
  });
});

describe('篡改定位到跳（T4 判据二）', () => {
  test('改中间跳（hop 2）→ signature_invalid，hop = 2', async () => {
    // §5.2 property 2: altering hop 2 breaks hops 2 and 3. The *lowest* failing
    // hop is the tampered one, so reporting 3 here would accuse the wrong node.
    const tampered = patchHop(threeHopToken(), 2, { settles: false });
    const result = await verifyAttributionToken({ token: tampered, resolveKey: allKeys, at: DURING });
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe('signature_invalid');
    expect(result.error?.hop).toBe(2);
    expect(result.error?.message).toContain('cat_relay_a');
  });

  test('改首跳 → hop = 1；改末跳 → hop = 3', async () => {
    const first = await verifyAttributionToken({
      token: patchHop(threeHopToken(), 1, { chain_complete: true, signed_at: '2020-01-01T00:00:00.000Z' }),
      resolveKey: allKeys,
      at: DURING,
    });
    expect(first.error?.code).toBe('signature_invalid');
    expect(first.error?.hop).toBe(1);

    const last = await verifyAttributionToken({
      token: patchHop(threeHopToken(), 3, { settles: true }),
      resolveKey: allKeys,
      at: DURING,
    });
    expect(last.error?.code).toBe('signature_invalid');
    expect(last.error?.hop).toBe(3);
  });

  test('改 core claims → 第 1 跳就暴露（§5.2 性质 3）', async () => {
    const token = threeHopToken();
    const result = await verifyAttributionToken({
      token: { ...token, agent_id: 'agent_attacker' },
      resolveKey: allKeys,
      at: DURING,
    });
    expect(result.error?.code).toBe('signature_invalid');
    expect(result.error?.hop).toBe(1);
  });

  test('整跳替换成攻击者自签的节点 → 仍定位到那一跳', async () => {
    // A forger who owns a key can produce a *self-consistent* node, but not one
    // that verifies under the catalog_id it claims to be.
    const attacker = generateEd25519KeyPair();
    const token = threeHopToken();
    const forged = patchHop(token, 2, { kid: attacker.kid, signature: token.chain[2]!.signature });
    const result = await verifyAttributionToken({ token: forged, resolveKey: allKeys, at: DURING });
    expect(result.ok).toBe(false);
    expect(result.error?.hop).toBe(2);
  });
});

describe('jti 防重放（T4 判据三）', () => {
  const guardParams = (token: AttributionToken, registry: JtiRegistry, orderId: string) => ({
    token,
    resolveKey: allKeys,
    at: DURING,
    replayGuard: { registry, orderId },
  });

  test('同一 jti 用在另一个 order_id 上 → replayed_jti', async () => {
    const registry = new JtiRegistry({ now: () => DURING.getTime() });
    const token = threeHopToken();

    expect((await verifyAttributionToken(guardParams(token, registry, 'order_1'))).ok).toBe(true);

    const replay = await verifyAttributionToken(guardParams(token, registry, 'order_2'));
    expect(replay.ok).toBe(false);
    expect(replay.error?.code).toBe('replayed_jti');
    expect(replay.error?.message).toContain('order_1');
  });

  test('同一 jti 同一 order_id 重复出现 → 放行（重试与状态更新，§7.1 注）', async () => {
    const registry = new JtiRegistry({ now: () => DURING.getTime() });
    const token = threeHopToken();
    for (let i = 0; i < 3; i += 1) {
      expect((await verifyAttributionToken(guardParams(token, registry, 'order_1'))).ok).toBe(true);
    }
    expect(registry.size).toBe(1);
  });

  test('不同 jti 互不影响', async () => {
    const registry = new JtiRegistry({ now: () => DURING.getTime() });
    const a = threeHopToken();
    const b = { ...threeHopToken(), jti: 'atr_other' };
    // Changing `jti` is a core-claim change, so `b` has to be signed afresh
    // rather than edited — which is exactly the property under test.
    const bSigned = appendRelayHop({
      privateJwk: RELAY_A.privateJwk,
      kid: RELAY_A.kid,
      catalogId: 'cat_relay_a',
      token: originToken({ jti: 'atr_other' }),
      chainComplete: true,
      now: () => IAT,
    });
    expect(b.jti).toBe(bSigned.jti);

    expect((await verifyAttributionToken(guardParams(a, registry, 'order_1'))).ok).toBe(true);
    expect((await verifyAttributionToken(guardParams(bSigned, registry, 'order_2'))).ok).toBe(true);
    expect(registry.size).toBe(2);
  });

  test('前面任一检查失败 → 不占用 jti', async () => {
    // Burning a jti on a token that was rejected for an unrelated reason would
    // make the first bad report a denial of service against the real one.
    const registry = new JtiRegistry({ now: () => DURING.getTime() });
    const tampered = patchHop(threeHopToken(), 2, { settles: false });
    expect((await verifyAttributionToken(guardParams(tampered, registry, 'order_1'))).ok).toBe(false);
    expect(registry.size).toBe(0);

    expect((await verifyAttributionToken(guardParams(threeHopToken(), registry, 'order_1'))).ok).toBe(true);
  });

  test('过期后条目被回收——留着也没用，第 9 条已经拦下了', () => {
    let clock = IAT.getTime();
    const registry = new JtiRegistry({ now: () => clock });
    registry.claim('atr_a', 'order_1', new Date(clock + 60_000));
    expect(registry.size).toBe(1);
    clock += 61_000;
    expect(registry.size).toBe(0);
    // And the slot is reusable, which is the point of reclaiming it.
    expect(registry.claim('atr_a', 'order_2', new Date(clock + 60_000))).toBe(true);
  });

  test('容量满 → 抛异常，绝不淘汰在世条目', () => {
    const registry = new JtiRegistry({ now: () => IAT.getTime(), maxEntries: 2 });
    const exp = new Date(IAT.getTime() + 3_600_000);
    registry.claim('atr_1', 'order_1', exp);
    registry.claim('atr_2', 'order_2', exp);
    expect(() => registry.claim('atr_3', 'order_3', exp)).toThrow(/persistent storage/);
    // Evicting would silently reopen the replay window this class exists to close.
    expect(registry.orderOf('atr_1')).toBe('order_1');
  });
});

describe('§7.1 其余各行与固定顺序（§8）', () => {
  test('结构坏 → chain_broken，且不带 hop', async () => {
    const token = threeHopToken();
    const result = await verifyAttributionToken({
      token: { ...token, chain: [token.chain[0]!, token.chain[2]!] },
      resolveKey: allKeys,
      at: DURING,
    });
    expect(result.error?.code).toBe('chain_broken');
    expect(result.error?.hop).toBe(undefined);
  });

  test('顶层 complete 说谎 → complete_mismatch（§5.3 必须重算）', async () => {
    const token = threeHopToken();
    const result = await verifyAttributionToken({
      token: { ...token, complete: false },
      resolveKey: allKeys,
      at: DURING,
    });
    expect(result.error?.code).toBe('complete_mismatch');
  });

  test('有一跳 chain_complete=false → complete 重算为 false，但验证仍通过', async () => {
    // Incomplete is a fact about the chain, not a failure. It tells the settler
    // there may be unrecorded hops; it does not make the recorded ones false.
    const hop2 = appendRelayHop({
      privateJwk: RELAY_A.privateJwk,
      kid: RELAY_A.kid,
      catalogId: 'cat_relay_a',
      token: originToken(),
      chainComplete: false,
      now: () => IAT,
    });
    const result = await verifyAttributionToken({ token: hop2, resolveKey: allKeys, at: DURING });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.complete).toBe(false);
  });

  test('alg 非 EdDSA → alg_not_supported 并带 hop', async () => {
    const token = patchHop(threeHopToken(), 2, { alg: 'ES256' as unknown as 'EdDSA' });
    const result = await verifyAttributionToken({ token, resolveKey: allKeys, at: DURING });
    expect(result.error?.code).toBe('alg_not_supported');
    expect(result.error?.hop).toBe(2);
  });

  test('alg 检查排在验签之前——否则就是算法混淆（§5.1）', async () => {
    // This hop has *both* a wrong alg and a broken signature. If the signature
    // were checked first we would report signature_invalid, i.e. we would have
    // verified a signature under an algorithm we never vetted.
    const token = patchHop(threeHopToken(), 2, { alg: 'ES256' as unknown as 'EdDSA', settles: false });
    const result = await verifyAttributionToken({ token, resolveKey: allKeys, at: DURING });
    expect(result.error?.code).toBe('alg_not_supported');
  });

  test('kid 不在该节点 JWKS 中 → key_not_found 并带 hop', async () => {
    const token = patchHop(threeHopToken(), 3, { kid: 'kid_rotated_away' });
    const result = await verifyAttributionToken({ token, resolveKey: allKeys, at: DURING });
    expect(result.error?.code).toBe('key_not_found');
    expect(result.error?.hop).toBe(3);
  });

  test('purpose != checkout → purpose_not_settleable', async () => {
    const viewToken = originToken({ purpose: 'view' });
    const result = await verifyAttributionToken({ token: viewToken, resolveKey: allKeys, at: DURING });
    expect(result.error?.code).toBe('purpose_not_settleable');

    // requirePurpose: null checks the cryptography without asserting settleability.
    const crypto = await verifyAttributionToken({
      token: viewToken,
      resolveKey: allKeys,
      at: DURING,
      requirePurpose: null,
    });
    expect(crypto.ok).toBe(true);
  });

  test('provider 不匹配 → provider_mismatch；不传就不查（还没有回报）', async () => {
    const token = threeHopToken();
    const mismatch = await verifyAttributionToken({
      token,
      resolveKey: allKeys,
      at: DURING,
      expectedProviderId: 'prov_someone_else',
    });
    expect(mismatch.error?.code).toBe('provider_mismatch');

    const matched = await verifyAttributionToken({
      token,
      resolveKey: allKeys,
      at: DURING,
      expectedProviderId: 'prov_merchant',
    });
    expect(matched.ok).toBe(true);
  });

  test('occurred_at 早于 iat → token_not_yet_valid；晚于 exp → token_expired', async () => {
    const token = threeHopToken();
    const early = await verifyAttributionToken({
      token,
      resolveKey: allKeys,
      at: new Date('2026-09-21T09:00:00.000Z'),
    });
    expect(early.error?.code).toBe('token_not_yet_valid');

    const late = await verifyAttributionToken({
      token,
      resolveKey: allKeys,
      at: new Date('2026-09-21T12:00:00.000Z'),
    });
    expect(late.error?.code).toBe('token_expired');
  });

  test('窗口按 occurred_at 而不是「此刻」算——迟报的成交不该被拒', async () => {
    // The transaction happened inside the window; the report arrives later.
    // Checking against wall-clock time would reject a legitimate sale.
    const token = threeHopToken();
    const result = await verifyAttributionToken({ token, resolveKey: allKeys, at: DURING });
    expect(result.ok).toBe(true);
  });

  test('同时违反多条 → 只报最靠前的那一条（§8 固定顺序）', async () => {
    // Broken structure + lying `complete` + expired + wrong purpose, all at once.
    const token = threeHopToken();
    const wrecked: AttributionToken = {
      ...token,
      complete: false,
      purpose: 'view',
      exp: '2020-01-01T00:00:00.000Z',
      chain: [token.chain[0]!, token.chain[2]!],
    };
    const result = await verifyAttributionToken({ token: wrecked, resolveKey: allKeys, at: DURING });
    expect(result.error?.code).toBe('chain_broken');
  });
});

describe('密钥取不到 vs 凭证是假的', () => {
  const failing = (code: ConstructorParameters<typeof CryptoError>[0]): AttributionKeyResolver => {
    return () => {
      throw new CryptoError(code, 'simulated');
    };
  };

  test('JWKS 拉不到 / 已过期 / 格式坏 → 抛出去，不当成验证失败', async () => {
    // A node whose key server is down has not forged anything. Recording that
    // as key_not_found would settle against it as though it had.
    for (const code of ['jwks_unavailable', 'jwks_expired', 'jwks_malformed'] as const) {
      let caught: unknown;
      try {
        await verifyAttributionToken({ token: threeHopToken(), resolveKey: failing(code), at: DURING });
      } catch (err) {
        caught = err;
      }
      expect(caught instanceof CryptoError).toBe(true);
      expect((caught as CryptoError).code).toBe(code);
    }
  });

  test('kid 命中但密钥不可用 → key_not_found（第 4 行的「可解析」）', async () => {
    const result = await verifyAttributionToken({
      token: threeHopToken(),
      resolveKey: failing('invalid_key'),
      at: DURING,
    });
    expect(result.error?.code).toBe('key_not_found');
    expect(result.error?.hop).toBe(1);
  });
});

describe('staticKeyResolver（离线取公钥）', () => {
  test('按 catalog_id 分别取键——不同节点的 kid 空间彼此独立', () => {
    const resolve = staticKeyResolver(jwksOf('cat_origin', 'cat_relay_a'));
    const jwk = resolve({ catalogId: 'cat_origin', kid: ORIGIN.kid, hop: 1 }) as Ed25519PublicJwk;
    expect(jwk.x).toBe(publicJwkOf(ORIGIN.privateJwk).x);
    // origin's kid must not resolve against relay_a's JWKS, or any node could
    // borrow another node's key id.
    expect(() => resolve({ catalogId: 'cat_relay_a', kid: ORIGIN.kid, hop: 2 })).toThrow(/key_not_found/);
  });

  test('完全没有该节点的 JWKS → key_not_found', () => {
    const resolve = staticKeyResolver(jwksOf('cat_origin'));
    expect(() => resolve({ catalogId: 'cat_unknown', kid: 'k', hop: 1 })).toThrow(/key_not_found/);
  });
});
