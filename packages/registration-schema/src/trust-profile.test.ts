/**
 * `trust_profile` 落地与降级语义（T3）。
 *
 * 用 §11 的一致性向量喂验签结果，不自己造：这个文件测的是「验签结论怎么落到路由
 * 提示上」，不是「验签对不对」。后者有它自己的测试，在 ocp-crypto 里。
 */
import { readFileSync } from 'node:fs';
import { describe, expect, test } from 'bun:test';
import { verifyDocumentSignature, selectVerificationKey } from '@ocp-catalog/ocp-crypto';
import { applyManifestVerification, catalogRouteHintSchema } from './index';

const FIXTURE_URL = new URL(
  '../../ocp-crypto/fixtures/signature/manifest-v1.json',
  import.meta.url,
);

interface Fixture {
  key: { catalog_id: string };
  jwks: Record<string, unknown>;
  expected_signed_document: Record<string, unknown>;
  expected_payload_hash: string;
  verify: { at: string };
  negative: {
    name: string;
    document: unknown;
    verify_overrides?: { at?: string };
    expected_error: string;
    expected_trust_tier: string;
    expected_invalidates_cache: boolean;
  }[];
}

const fixture = JSON.parse(readFileSync(FIXTURE_URL, 'utf8')) as Fixture;
const CATALOG = fixture.key.catalog_id;
const AT = new Date(fixture.verify.at);

const resolveKey = ({ issuer, kid }: { issuer: string; kid: string }) =>
  selectVerificationKey(fixture.jwks[issuer] as { keys?: unknown }, kid, issuer);

const verify = (document: unknown, at = AT) =>
  verifyDocumentSignature({ document, resolveKey, at });

/** 注册方交出来的提示：自述 verified，trust_profile 三个证据字段一个没填。 */
function hint(overrides: Record<string, unknown> = {}) {
  return catalogRouteHintSchema.parse({
    catalog_id: CATALOG,
    catalog_name: 'Interop Signed Catalog',
    manifest_url: 'https://catalog.example.com/manifest',
    query_url: 'https://catalog.example.com/query',
    verification_status: 'verified',
    trust_tier: 'verified',
    health_status: 'healthy',
    cache_ttl_seconds: 86_400,
    snapshot_id: 'snap_1',
    snapshot_fetched_at: '2026-03-01T12:00:00.000Z',
    ...overrides,
  });
}

describe('trust_profile · 验通之后填的是真值', () => {
  test('manifest_hash / issuer / signature_alg 三个字段有了值', async () => {
    const outcome = applyManifestVerification(hint(), await verify(fixture.expected_signed_document));
    const profile = outcome.hint.trust_profile;
    expect(profile?.manifest_hash).toBe(fixture.expected_payload_hash);
    expect(profile?.issuer).toBe(CATALOG);
    expect(profile?.signature_alg).toBe('EdDSA');
    expect(profile?.manifest_signed).toBe(true);
    expect(outcome.downgraded).toBe(false);
    expect(outcome.invalidates_cache).toBe(false);
  });

  test('验通不抬等级：注册方说 verified_domain，还是 verified_domain', async () => {
    // §7.2：签名验通只是解锁 verified 这个上限，不断言 manifest 里的内容为真。
    // 域名验证是另一条轴，这个函数没看到它的任何证据，不能替它发话。
    const outcome = applyManifestVerification(
      hint({ trust_tier: 'verified_domain' }),
      await verify(fixture.expected_signed_document),
    );
    expect(outcome.hint.trust_tier).toBe('verified_domain');
    expect(outcome.hint.trust_profile?.trust_tier).toBe('verified_domain');
    expect(outcome.downgraded).toBe(false);
  });

  test('填完仍然过 schema —— trust_profile 是 additionalProperties: false', async () => {
    const outcome = applyManifestVerification(hint(), await verify(fixture.expected_signed_document));
    expect(() => catalogRouteHintSchema.parse(outcome.hint)).not.toThrow();
  });
});

describe('trust_profile · 降级语义', () => {
  test('篡改的 manifest：verified → unknown，缓存作废', async () => {
    const tampered = structuredClone(fixture.expected_signed_document);
    tampered.catalog_name = `${tampered.catalog_name as string}.`;
    const outcome = applyManifestVerification(hint(), await verify(tampered));
    expect(outcome.hint.trust_tier).toBe('unknown');
    expect(outcome.hint.trust_profile?.trust_tier).toBe('unknown');
    expect(outcome.downgraded).toBe(true);
    expect(outcome.invalidates_cache).toBe(true);
  });

  test('没签名 / 签名过期：verified → unverified，缓存保留', async () => {
    for (const name of ['unsigned', 'signature-expired']) {
      const entry = fixture.negative.find((n) => n.name === name);
      if (!entry) throw new Error(`fixture lost the "${name}" case`);
      const at = entry.verify_overrides?.at ? new Date(entry.verify_overrides.at) : AT;
      const outcome = applyManifestVerification(hint(), await verify(entry.document, at));
      expect(outcome.hint.trust_tier).toBe('unverified');
      expect(outcome.downgraded).toBe(true);
      // 一个还没开始签，一个忘了续签。都不是「有人改过东西」的证据，
      // 把它们的缓存丢掉，等于把「没有证明」当成「证明了有问题」。
      expect(outcome.invalidates_cache).toBe(false);
    }
  });

  test('12 条反例的降级结论和向量里写的一致', async () => {
    for (const entry of fixture.negative) {
      const at = entry.verify_overrides?.at ? new Date(entry.verify_overrides.at) : AT;
      const outcome = applyManifestVerification(hint(), await verify(entry.document, at));
      expect(outcome.hint.trust_profile?.trust_tier).toBe(entry.expected_trust_tier);
      expect(outcome.invalidates_cache).toBe(entry.expected_invalidates_cache);
    }
  });

  test('降级时清掉三个证据字段，不留上一次的 manifest_hash', async () => {
    const good = applyManifestVerification(hint(), await verify(fixture.expected_signed_document));
    const tampered = structuredClone(fixture.expected_signed_document);
    tampered.catalog_name = `${tampered.catalog_name as string}.`;
    // 拿上一轮验通的提示再验一次被改过的 manifest：旧哈希必须消失。
    const after = applyManifestVerification(good.hint, await verify(tampered));
    expect(after.hint.trust_profile?.manifest_hash).toBeUndefined();
    expect(after.hint.trust_profile?.issuer).toBeUndefined();
    expect(after.hint.trust_profile?.signature_alg).toBeUndefined();
  });

  test('顶层 trust_tier 和 trust_profile.trust_tier 不许各说各的', async () => {
    const tampered = structuredClone(fixture.expected_signed_document);
    tampered.catalog_name = `${tampered.catalog_name as string}.`;
    const outcome = applyManifestVerification(hint(), await verify(tampered));
    // 只读顶层字段的消费方不能看到 verified，而下面的 profile 写着 unknown。
    expect(outcome.hint.trust_tier).toBe(outcome.hint.trust_profile?.trust_tier);
  });

  test('上限只往下压：注册方本来就说 unknown，验通也还是 unknown', async () => {
    const outcome = applyManifestVerification(
      hint({ trust_tier: 'unknown' }),
      await verify(fixture.expected_signed_document),
    );
    expect(outcome.hint.trust_tier).toBe('unknown');
    expect(outcome.downgraded).toBe(false);
  });
});

describe('trust_profile · downgrade_invalidates_cache', () => {
  test('节点声明 false，也挡不住自己伪造的 manifest 作废缓存', async () => {
    const tampered = structuredClone(fixture.expected_signed_document);
    tampered.catalog_name = `${tampered.catalog_name as string}.`;
    const outcome = applyManifestVerification(
      hint({
        trust_profile: {
          verification_status: 'verified',
          trust_tier: 'verified',
          downgrade_invalidates_cache: false,
        },
      }),
      await verify(tampered),
    );
    // 和 T1 里 trust_tier 的口径一样：这是验签方的结论，不是被验方的声明。
    expect(outcome.hint.trust_profile?.downgrade_invalidates_cache).toBe(true);
    expect(outcome.invalidates_cache).toBe(true);
  });

  test('声明 false 且验通时，声明保留', async () => {
    const outcome = applyManifestVerification(
      hint({
        trust_profile: {
          verification_status: 'verified',
          trust_tier: 'verified',
          downgrade_invalidates_cache: false,
        },
      }),
      await verify(fixture.expected_signed_document),
    );
    expect(outcome.hint.trust_profile?.downgrade_invalidates_cache).toBe(false);
  });
});
