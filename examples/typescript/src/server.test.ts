import { describe, expect, test } from 'bun:test';
import {
  catalogHealthResponseSchema,
  catalogManifestSchema,
  catalogQueryResultSchema,
  resolvableReferenceSchema,
  wellKnownCatalogDiscoverySchema,
} from '@ocp-catalog/ocp-schema';
import { assertEd25519PublicJwk } from '@ocp-catalog/ocp-crypto';
import { handle } from './server';
import { verifyOffline } from './offline-verify';

const get = (path: string) => handle(new Request(`http://localhost${path}`));
const post = (path: string, body: unknown) =>
  handle(
    new Request(`http://localhost${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );

async function body(res: Response) {
  return res.json();
}

describe('minimal TypeScript OCP Catalog Node', () => {
  test('manifest conforms to catalogManifestSchema', async () => {
    const parsed = catalogManifestSchema.parse(await body(await get('/ocp/manifest')));
    expect(parsed.object_contracts).toEqual([]);
    expect(parsed.query_capabilities.length).toBeGreaterThan(0);
  });

  test('health conforms to catalogHealthResponseSchema', async () => {
    const parsed = catalogHealthResponseSchema.parse(await body(await get('/ocp/health')));
    expect(parsed.ready).toBe(true);
    expect(parsed.status).toBe('healthy');
  });

  test('well-known discovery conforms to wellKnownCatalogDiscoverySchema', async () => {
    const parsed = wellKnownCatalogDiscoverySchema.parse(await body(await get('/.well-known/ocp-catalog')));
    expect(parsed.query_url).toContain('/ocp/query');
    expect(parsed.resolve_url).toContain('/ocp/resolve');
    // This node signs attribution tokens, so it must say where its public keys
    // are. A token whose key cannot be found is not verifiable, and a token
    // nobody can verify is not worth issuing.
    expect(parsed.jwks_url).toContain('/.well-known/jwks.json');
  });

  test('jwks.json publishes an Ed25519 signing key and no private material', async () => {
    const jwks = (await body(await get('/.well-known/jwks.json'))) as { keys: Record<string, unknown>[] };
    expect(jwks.keys).toHaveLength(1);
    const jwk = assertEd25519PublicJwk(jwks.keys[0]);
    expect(jwk.alg).toBe('EdDSA');
    expect(jwk.use).toBe('sig');
    expect(typeof jwk.kid).toBe('string');
    // The one mistake in this file that would be catastrophic and silent.
    expect('d' in jwks.keys[0]!).toBe(false);
  });

  test('query conforms to catalogQueryResultSchema and filters by keyword', async () => {
    const parsed = catalogQueryResultSchema.parse(await body(await post('/ocp/query', { query: 'headphones' })));
    expect(parsed.result_count).toBe(1);
    expect(parsed.entries[0]!.entry.title).toContain('Headphones');
    expect(parsed.page.offset).toBe(0);
  });

  test('empty query returns all products', async () => {
    const parsed = catalogQueryResultSchema.parse(await body(await post('/ocp/query', {})));
    expect(parsed.result_count).toBe(3);
  });

  test('resolve conforms to resolvableReferenceSchema', async () => {
    const parsed = resolvableReferenceSchema.parse(
      await body(await post('/ocp/resolve', { entry_id: 'entry_example_inmemory_sku-001' })),
    );
    expect(parsed.title).toContain('Headphones');
    expect(parsed.action_bindings[0]!.action_type).toBe('url');
  });

  test('resolve of an unknown entry returns 404', async () => {
    const res = await post('/ocp/resolve', { entry_id: 'entry_example_inmemory_nope' });
    expect(res.status).toBe(404);
  });
});

const ENTRY = 'entry_example_inmemory_sku-001';
const AGENT = { agent_id: 'agent_demo_shopper' };

const resolveRaw = async (request: Record<string, unknown>) =>
  (await post('/ocp/resolve', { entry_id: ENTRY, ...request }).then((r) => r.json())) as Record<string, unknown>;

const bindingsOf = (res: Record<string, unknown>) => res.action_bindings as Record<string, unknown>[];
const attributionOf = (res: Record<string, unknown>) =>
  bindingsOf(res).find((b) => b.attribution)?.attribution as Record<string, unknown> | undefined;

describe('resolve 上的归因签发（T3）', () => {
  test('purpose=checkout + attribution_context → 签出 token，挂在 checkout 绑定上', async () => {
    const raw = await resolveRaw({ purpose: 'checkout', attribution_context: AGENT });
    const parsed = resolvableReferenceSchema.parse(raw);

    const checkout = parsed.action_bindings.find((b) => b.action_id === 'checkout');
    expect(checkout).toBeDefined();
    // On the binding that leads to money, not on the response — a resolve can
    // offer several actions and only some of them settle.
    expect(parsed.action_bindings.find((b) => b.action_id === 'view')?.attribution).toBe(undefined);

    const token = checkout!.attribution!;
    expect(token.kind).toBe('AttributionToken');
    expect(token.iss).toBe('cat_example_typescript');
    expect(token.agent_id).toBe(AGENT.agent_id);
    expect(token.entry_id).toBe(ENTRY);
    expect(token.object_id).toBe('sku-001');
    expect(token.provider_id).toBe('example_inmemory');
    expect(token.purpose).toBe('checkout');
    expect(token.chain).toHaveLength(1);
    expect(token.chain[0]!.role).toBe('origin');
    expect(token.complete).toBe(true);
  });

  test('token 的 kid 指向 JWKS 里真的存在的那把钥匙', async () => {
    const token = attributionOf(await resolveRaw({ purpose: 'checkout', attribution_context: AGENT }))!;
    const jwks = (await body(await get('/.well-known/jwks.json'))) as { keys: { kid: string }[] };
    const kid = (token.chain as { kid: string }[])[0]!.kid;
    expect(jwks.keys.map((k) => k.kid)).toContain(kid);
  });

  test('§10.2：不带 attribution_context 的 resolve 照常通过，且不签发', async () => {
    // The compatibility guarantee, stated normatively. An existing agent that
    // has never heard of attribution must see the response it saw before.
    for (const request of [{}, { purpose: 'checkout' }, { purpose: 'view' }]) {
      const parsed = resolvableReferenceSchema.parse(await resolveRaw(request));
      expect(parsed.action_bindings.every((b) => b.attribution === undefined)).toBe(true);
      expect(parsed.action_bindings.some((b) => b.action_id === 'view')).toBe(true);
    }
  });

  test('§7.1：purpose 不是 checkout 就不签——签了就是给一次浏览开结算凭证', async () => {
    for (const purpose of ['view', 'contact', 'workflow']) {
      const parsed = resolvableReferenceSchema.parse(await resolveRaw({ purpose, attribution_context: AGENT }));
      expect(parsed.action_bindings.every((b) => b.attribution === undefined)).toBe(true);
    }
  });

  test('带 upstream_token 时不签——本节点只签 origin，不能抹掉上游', async () => {
    const parsed = resolvableReferenceSchema.parse(
      await resolveRaw({
        purpose: 'checkout',
        attribution_context: { ...AGENT, upstream_token: { kind: 'AttributionToken' } },
      }),
    );
    expect(parsed.action_bindings.every((b) => b.attribution === undefined)).toBe(true);
  });

  test('jti 每次 resolve 都不同——否则无法去重', async () => {
    const a = attributionOf(await resolveRaw({ purpose: 'checkout', attribution_context: AGENT }))!;
    const b = attributionOf(await resolveRaw({ purpose: 'checkout', attribution_context: AGENT }))!;
    expect(a.jti).not.toBe(b.jti);
  });

  test('agent_identity_source 透传', async () => {
    const token = attributionOf(
      await resolveRaw({
        purpose: 'checkout',
        attribution_context: { ...AGENT, agent_identity_source: 'external' },
      }),
    )!;
    expect(token.agent_identity_source).toBe('external');
  });
});

describe('离线验通：取到公钥之后不再联网（T3 验收）', () => {
  /** discovery → jwks_url → JWKS, plus one resolve. The only network half. */
  async function fetchArtifacts() {
    const discovery = (await body(await get('/.well-known/ocp-catalog'))) as { jwks_url: string };
    const jwks = await body(await get(new URL(discovery.jwks_url).pathname));
    const resolved = await resolveRaw({ purpose: 'checkout', attribution_context: AGENT });
    return { discovery, jwks, resolved };
  }

  test('拿到 discovery / JWKS / resolve 三份文档后，断网可以独立验通', async () => {
    const artifacts = await fetchArtifacts();

    // Prove the claim instead of asserting it: nothing below may reach out.
    const realFetch = globalThis.fetch;
    globalThis.fetch = (() => {
      throw new Error('offline: verification must not touch the network');
    }) as unknown as typeof globalThis.fetch;
    try {
      const result = verifyOffline(artifacts);
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.agentId).toBe(AGENT.agent_id);
      expect(result.settlingCatalogIds).toEqual(['cat_example_typescript']);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  test('改一个字段就验不过——逐个字段试', async () => {
    const artifacts = await fetchArtifacts();

    type Token = Record<string, unknown> & { chain: Record<string, unknown>[] };
    const cases: [string, (token: Token) => void, string][] = [
      ['agent_id 换人', (t) => { t.agent_id = 'agent_thief'; }, 'signature_invalid'],
      ['exp 续期', (t) => { t.exp = new Date(Date.now() + 864e5).toISOString(); }, 'signature_invalid'],
      ['settles 翻成 false', (t) => { t.chain[0]!.settles = false; }, 'signature_invalid'],
      ['complete 翻成 false', (t) => { t.complete = false; }, 'complete_mismatch'],
      ['kid 指向不存在的钥匙', (t) => { t.chain[0]!.kid = 'kid_nope'; }, 'key_not_found'],
      ['hop 号对不上位置', (t) => { t.chain[0]!.hop = 2; }, 'chain_broken'],
      ['origin 改成 relay', (t) => { t.chain[0]!.role = 'relay'; }, 'chain_broken'],
    ];

    for (const [label, tamper, expected] of cases) {
      const fresh = structuredClone(artifacts);
      tamper(attributionOf(fresh.resolved) as unknown as Token);
      const result = verifyOffline(fresh);
      // Compare with the label attached so a failure names the case.
      expect([label, result.ok ? 'verified' : result.error]).toEqual([label, expected]);
    }
  });

  test('换一个目录节点的密钥集 → key_not_found', async () => {
    const artifacts = await fetchArtifacts();
    const result = verifyOffline({ ...artifacts, jwks: { keys: [] } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('key_not_found');
  });

  test('凭证过期 → token_expired，且在验签之前就拦下', async () => {
    const artifacts = await fetchArtifacts();
    const result = verifyOffline({ ...artifacts, now: new Date(Date.now() + 2 * 60 * 60 * 1000) });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('token_expired');
  });

  test('token 与 resolve 说的不是同一个商品 → object_mismatch', async () => {
    const artifacts = await fetchArtifacts();
    const resolved = structuredClone(artifacts.resolved);
    resolved.object_id = 'sku-999';
    const result = verifyOffline({ ...artifacts, resolved });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('object_mismatch');
  });
});
