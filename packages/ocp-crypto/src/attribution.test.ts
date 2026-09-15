import { describe, expect, test } from 'bun:test';
import {
  appendRelayHop,
  attributionSigningBytes,
  checkChainStructure,
  coreClaims,
  issueOriginToken,
  recomputeComplete,
  signChainNode,
  unsignedNode,
  verifyChainNodeSignature,
  type AttributionToken,
  type ChainNode,
  type CoreClaims,
} from './attribution';
import { errorCodeOf } from './errors';
import { generateEd25519KeyPair, publicJwkOf } from './keys';

const issuer = generateEd25519KeyPair();

function freshToken(overrides: Partial<Parameters<typeof issueOriginToken>[0]> = {}): AttributionToken {
  return issueOriginToken({
    privateJwk: issuer.privateJwk,
    kid: issuer.kid,
    catalogId: 'cat_origin',
    agentId: 'agent_alpha',
    entryId: 'entry_example_sku-001',
    objectId: 'sku-001',
    providerId: 'prov_merchant',
    purpose: 'checkout',
    ...overrides,
  });
}

describe('issueOriginToken', () => {
  test('签发单跳链：hop=1、role=origin、complete=true', () => {
    const token = freshToken();
    expect(token.kind).toBe('AttributionToken');
    expect(token.chain).toHaveLength(1);
    expect(token.chain[0]!.hop).toBe(1);
    expect(token.chain[0]!.role).toBe('origin');
    expect(token.chain[0]!.chain_complete).toBe(true);
    expect(token.complete).toBe(true);
    expect(token.iss).toBe('cat_origin');
    expect(token.chain[0]!.kid).toBe(issuer.kid);
    expect(token.chain[0]!.alg).toBe('EdDSA');
  });

  test('签名可用签发方公钥验通', () => {
    const token = freshToken();
    expect(
      verifyChainNodeSignature({
        jwk: publicJwkOf(issuer.privateJwk),
        core: coreClaims(token),
        chain: token.chain,
        hopIndex: 0,
      }),
    ).toBe(true);
  });

  test('exp = iat + ttl，默认一小时', () => {
    const at = new Date('2026-09-18T10:00:00.000Z');
    const token = freshToken({ now: () => at });
    expect(token.iat).toBe('2026-09-18T10:00:00.000Z');
    expect(token.exp).toBe('2026-09-18T11:00:00.000Z');
    expect(freshToken({ now: () => at, ttlSeconds: 60 }).exp).toBe('2026-09-18T10:01:00.000Z');
  });

  test('jti 默认唯一——防重放的唯一依据（§4.1）', () => {
    const seen = new Set(Array.from({ length: 50 }, () => freshToken().jti));
    expect(seen.size).toBe(50);
  });

  test('agent_identity_source 不填就不出现在 claims 里', () => {
    // §4.1 says the default is `ocp`. Writing the default into the token would
    // make two byte-different tokens mean the same thing, and both would be
    // validly signed — an avoidable ambiguity at the settlement layer.
    expect('agent_identity_source' in freshToken()).toBe(false);
    expect(freshToken({ agentIdentitySource: 'external' }).agent_identity_source).toBe('external');
  });

  test('settles 可为 false——不是每个跳都要分钱（§5.1）', () => {
    expect(freshToken({ settles: false }).chain[0]!.settles).toBe(false);
  });
});

describe('core claims 与签名材料（§4.3 / §5.2）', () => {
  test('coreClaims 去掉且只去掉 complete 与 chain', () => {
    const token = freshToken();
    const core = coreClaims(token);
    expect('complete' in core).toBe(false);
    expect('chain' in core).toBe(false);
    expect(Object.keys(core).sort()).toEqual(
      [
        'agent_id',
        'entry_id',
        'exp',
        'iat',
        'iss',
        'jti',
        'kind',
        'object_id',
        'ocp_version',
        'provider_id',
        'purpose',
      ].sort(),
    );
  });

  test('unsignedNode 去掉且只去掉 signature', () => {
    const node = freshToken().chain[0]!;
    const unsigned = unsignedNode(node);
    expect('signature' in unsigned).toBe(false);
    expect(Object.keys(unsigned).sort()).toEqual(
      ['alg', 'catalog_id', 'chain_complete', 'hop', 'kid', 'role', 'settles', 'signed_at'].sort(),
    );
  });

  test('签名材料的顶层键序是 chain 在前、core 在后（§5.2 注）', () => {
    const token = freshToken();
    const bytes = attributionSigningBytes(token.chain, coreClaims(token));
    expect(bytes.startsWith('{"chain":[')).toBe(true);
    expect(bytes.indexOf('"chain"') < bytes.indexOf('"core"')).toBe(true);
  });

  test('签名材料不含 signature 字段——否则自指，永远签不出来', () => {
    const token = freshToken();
    expect(attributionSigningBytes(token.chain, coreClaims(token))).not.toContain('"signature"');
  });

  test('字段书写顺序不影响签名——规范化吸收了它', () => {
    const at = new Date('2026-09-18T10:00:00.000Z');
    const a = freshToken({ now: () => at, jti: 'atr_fixed' });
    const reordered: CoreClaims = {
      purpose: a.purpose,
      provider_id: a.provider_id,
      object_id: a.object_id,
      entry_id: a.entry_id,
      agent_id: a.agent_id,
      exp: a.exp,
      iat: a.iat,
      iss: a.iss,
      jti: a.jti,
      kind: a.kind,
      ocp_version: a.ocp_version,
    };
    expect(attributionSigningBytes(a.chain, reordered)).toBe(
      attributionSigningBytes(a.chain, coreClaims(a)),
    );
  });
});

describe('篡改检测', () => {
  const publicJwk = publicJwkOf(issuer.privateJwk);
  const verify = (token: AttributionToken) =>
    verifyChainNodeSignature({ jwk: publicJwk, core: coreClaims(token), chain: token.chain, hopIndex: 0 });

  test('改 agent_id → 验签失败（结算主体，§5.2 性质 3）', () => {
    const token = freshToken();
    expect(verify({ ...token, agent_id: 'agent_attacker' })).toBe(false);
  });

  test('改 provider_id / entry_id / object_id / purpose → 验签失败', () => {
    for (const patch of [
      { provider_id: 'prov_other' },
      { entry_id: 'entry_other' },
      { object_id: 'sku-999' },
      { purpose: 'view' as const },
    ]) {
      expect(verify({ ...freshToken(), ...patch })).toBe(false);
    }
  });

  test('延长 exp → 验签失败（否则泄露的凭证可被续期）', () => {
    const token = freshToken();
    expect(verify({ ...token, exp: new Date(Date.now() + 86_400_000).toISOString() })).toBe(false);
  });

  test('改链内 settles / chain_complete → 验签失败（钱挂在这两个字段上）', () => {
    for (const patch of [{ settles: false }, { chain_complete: false }]) {
      const token = freshToken();
      const tampered: AttributionToken = { ...token, chain: [{ ...token.chain[0]!, ...patch }] };
      expect(verify(tampered)).toBe(false);
    }
  });

  test('改 kid / signed_at → 验签失败（均在签名材料内）', () => {
    for (const patch of [{ kid: 'kid_other' }, { signed_at: '2020-01-01T00:00:00.000Z' }]) {
      const token = freshToken();
      expect(verify({ ...token, chain: [{ ...token.chain[0]!, ...patch }] })).toBe(false);
    }
  });

  test('换一把公钥 → 验签失败', () => {
    const other = generateEd25519KeyPair();
    const token = freshToken();
    expect(
      verifyChainNodeSignature({
        jwk: publicJwkOf(other.privateJwk),
        core: coreClaims(token),
        chain: token.chain,
        hopIndex: 0,
      }),
    ).toBe(false);
  });

  test('改顶层 complete 不影响签名——所以验证方必须重算（§5.3）', () => {
    // `complete` is outside every signature by design. This test pins that:
    // the signature still verifies, which is exactly why reading the field
    // instead of recomputing it would be a hole.
    const token = freshToken();
    expect(verify({ ...token, complete: false })).toBe(true);
    expect(recomputeComplete(token.chain)).toBe(true);
  });

  test('hopIndex 越界 → false，不抛异常', () => {
    const token = freshToken();
    expect(
      verifyChainNodeSignature({ jwk: publicJwk, core: coreClaims(token), chain: token.chain, hopIndex: 3 }),
    ).toBe(false);
  });
});

describe('recomputeComplete（§5.3）', () => {
  const node = (chain_complete: boolean): Pick<ChainNode, 'chain_complete'> => ({ chain_complete });

  test('全 true → true；任一 false → false', () => {
    expect(recomputeComplete([node(true), node(true), node(true)])).toBe(true);
    expect(recomputeComplete([node(true), node(false), node(true)])).toBe(false);
    expect(recomputeComplete([node(false)])).toBe(false);
  });
});

describe('signChainNode 的前缀语义', () => {
  test('第 N 跳签的是含自己在内的前缀 1..N', () => {
    const relay = generateEd25519KeyPair();
    const token = freshToken();
    const core = coreClaims(token);
    const hop2 = signChainNode({
      privateJwk: relay.privateJwk,
      core,
      chainPrefix: token.chain,
      node: {
        catalog_id: 'cat_relay',
        hop: 2,
        role: 'relay',
        settles: true,
        chain_complete: true,
        alg: 'EdDSA',
        kid: relay.kid,
        signed_at: new Date().toISOString(),
      },
    });

    const chain = [token.chain[0]!, hop2];
    // Hop 2 verifies over the two-node prefix...
    expect(
      verifyChainNodeSignature({ jwk: publicJwkOf(relay.privateJwk), core, chain, hopIndex: 1 }),
    ).toBe(true);
    // ...and hop 1 still verifies over its own one-node prefix, unaffected.
    expect(
      verifyChainNodeSignature({ jwk: publicJwkOf(issuer.privateJwk), core, chain, hopIndex: 0 }),
    ).toBe(true);
  });

  test('篡改上游跳 → 下游跳签名失效（§5.2 性质 2）', () => {
    const relay = generateEd25519KeyPair();
    const token = freshToken();
    const core = coreClaims(token);
    const hop2 = signChainNode({
      privateJwk: relay.privateJwk,
      core,
      chainPrefix: token.chain,
      node: {
        catalog_id: 'cat_relay',
        hop: 2,
        role: 'relay',
        settles: true,
        chain_complete: true,
        alg: 'EdDSA',
        kid: relay.kid,
        signed_at: new Date().toISOString(),
      },
    });

    const tamperedHop1: ChainNode = { ...token.chain[0]!, settles: false };
    expect(
      verifyChainNodeSignature({
        jwk: publicJwkOf(relay.privateJwk),
        core,
        chain: [tamperedHop1, hop2],
        hopIndex: 1,
      }),
    ).toBe(false);
  });
});

describe('checkChainStructure（§5.4）', () => {
  const node = (over: Partial<ChainNode>): ChainNode => ({
    catalog_id: 'cat_a',
    hop: 1,
    role: 'origin',
    settles: true,
    chain_complete: true,
    alg: 'EdDSA',
    kid: 'kid_a',
    signed_at: '2026-09-21T10:00:00.000Z',
    signature: 'x',
    ...over,
  });

  test('合法单跳 / 三跳链 → undefined', () => {
    expect(checkChainStructure(freshToken().chain)).toBe(undefined);
    expect(
      checkChainStructure([
        node({}),
        node({ catalog_id: 'cat_b', hop: 2, role: 'relay' }),
        node({ catalog_id: 'cat_c', hop: 3, role: 'relay' }),
      ]),
    ).toBe(undefined);
  });

  test('空链 → 报错', () => {
    expect(checkChainStructure([])).toContain('empty');
  });

  test('超过 8 跳 → 报错（§4.4 攻击面上限，不是性能）', () => {
    const long = Array.from({ length: 9 }, (_, i) =>
      node({ catalog_id: `cat_${i}`, hop: i + 1, role: i === 0 ? 'origin' : 'relay' }),
    );
    expect(checkChainStructure(long)).toContain('over the §4.4 cap');
    // 8 is still fine — the cap is inclusive.
    expect(checkChainStructure(long.slice(0, 8))).toBe(undefined);
  });

  test('hop 号不连续 / 重排 → 报错', () => {
    expect(
      checkChainStructure([node({}), node({ catalog_id: 'cat_b', hop: 3, role: 'relay' })]),
    ).toContain('expected 2');
    // Swapping two nodes is caught by the hop numbers, which is the whole
    // reason `hop` is a field rather than an array index.
    expect(
      checkChainStructure([
        node({ catalog_id: 'cat_b', hop: 2, role: 'relay' }),
        node({ hop: 1 }),
      ]),
    ).toContain('expected 1');
  });

  test('首跳非 origin / 后续跳非 relay → 报错', () => {
    expect(checkChainStructure([node({ role: 'relay' })])).toContain('expected "origin"');
    expect(
      checkChainStructure([node({}), node({ catalog_id: 'cat_b', hop: 2, role: 'origin' })]),
    ).toContain('expected "relay"');
  });

  test('catalog_id 重复 → 报错（环路）', () => {
    expect(
      checkChainStructure([
        node({}),
        node({ catalog_id: 'cat_b', hop: 2, role: 'relay' }),
        node({ catalog_id: 'cat_a', hop: 3, role: 'relay' }),
      ]),
    ).toContain('appears twice');
  });
});

describe('appendRelayHop（多跳签发）', () => {
  const relay = generateEd25519KeyPair();

  test('追加一跳：hop=2、role=relay、core claims 原样带过', () => {
    const origin = freshToken();
    const two = appendRelayHop({
      privateJwk: relay.privateJwk,
      kid: relay.kid,
      catalogId: 'cat_relay',
      token: origin,
      chainComplete: true,
    });

    expect(two.chain).toHaveLength(2);
    expect(two.chain[1]!.hop).toBe(2);
    expect(two.chain[1]!.role).toBe('relay');
    expect(two.chain[1]!.catalog_id).toBe('cat_relay');
    // The claims every upstream hop already signed over must survive byte-identical.
    expect(coreClaims(two)).toEqual(coreClaims(origin));
    expect(two.chain[0]).toEqual(origin.chain[0]!);
  });

  test('settles 默认 false——漏报自己该拿的钱可以补，冒领不行（§5.1）', () => {
    const two = appendRelayHop({
      privateJwk: relay.privateJwk,
      kid: relay.kid,
      catalogId: 'cat_relay',
      token: freshToken(),
      chainComplete: true,
    });
    expect(two.chain[1]!.settles).toBe(false);
  });

  test('chain_complete: false → 顶层 complete 重算为 false', () => {
    const two = appendRelayHop({
      privateJwk: relay.privateJwk,
      kid: relay.kid,
      catalogId: 'cat_relay',
      token: freshToken(),
      chainComplete: false,
    });
    expect(two.complete).toBe(false);
    expect(recomputeComplete(two.chain)).toBe(false);
  });

  test('新跳的签名覆盖整条前缀，旧跳签名不受影响', () => {
    const origin = freshToken();
    const two = appendRelayHop({
      privateJwk: relay.privateJwk,
      kid: relay.kid,
      catalogId: 'cat_relay',
      token: origin,
      chainComplete: true,
    });
    const core = coreClaims(two);
    expect(
      verifyChainNodeSignature({ jwk: publicJwkOf(relay.privateJwk), core, chain: two.chain, hopIndex: 1 }),
    ).toBe(true);
    expect(
      verifyChainNodeSignature({ jwk: publicJwkOf(issuer.privateJwk), core, chain: two.chain, hopIndex: 0 }),
    ).toBe(true);
  });

  test('本节点已在链内 → 拒签（环路）', () => {
    const origin = freshToken();
    expect(() =>
      appendRelayHop({
        privateJwk: issuer.privateJwk,
        kid: issuer.kid,
        catalogId: 'cat_origin',
        token: origin,
        chainComplete: true,
      }),
    ).toThrow(/loop/);
  });

  test('链已满 8 跳 → 拒签，错误码 chain_broken', () => {
    let token = freshToken();
    for (let i = 2; i <= 8; i += 1) {
      const key = generateEd25519KeyPair();
      token = appendRelayHop({
        privateJwk: key.privateJwk,
        kid: key.kid,
        catalogId: `cat_relay_${i}`,
        token,
        chainComplete: true,
      });
    }
    expect(token.chain).toHaveLength(8);

    const extra = generateEd25519KeyPair();
    try {
      appendRelayHop({
        privateJwk: extra.privateJwk,
        kid: extra.kid,
        catalogId: 'cat_relay_9',
        token,
        chainComplete: true,
      });
      throw new Error('expected appendRelayHop to refuse a 9th hop');
    } catch (err) {
      expect(errorCodeOf(err)).toBe('chain_broken');
    }
  });

  test('上游链本身就坏 → 拒签，不在坏链上盖自己的名字', () => {
    const origin = freshToken();
    const broken: AttributionToken = {
      ...origin,
      chain: [{ ...origin.chain[0]!, hop: 7 }],
    };
    expect(() =>
      appendRelayHop({
        privateJwk: relay.privateJwk,
        kid: relay.kid,
        catalogId: 'cat_relay',
        token: broken,
        chainComplete: true,
      }),
    ).toThrow(/malformed chain/);
  });
});
