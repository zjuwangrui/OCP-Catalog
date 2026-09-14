import { describe, expect, test } from 'bun:test';
import {
  attributionSigningBytes,
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
