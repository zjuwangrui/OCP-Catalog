/**
 * `ocp catalog inspect --verify`, driven by the §11 conformance vectors.
 *
 * The vectors are reused rather than rebuilt here on purpose: the CLI's job is
 * to report the code the spec says, and the file that decides what that code is
 * lives in `ocp-crypto`. A separate set of hand-written cases here would let the
 * CLI and the specification drift apart while both stayed green.
 *
 * `index.ts` cannot be run by this harness (the client uses a constructor
 * parameter property, which strip-only TypeScript rejects), which is why the
 * verdict and the exit code are decided in this module and not in the command.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, test } from 'bun:test';
import { SIGNATURE_ERROR_CODES, type SignatureErrorCode } from '@ocp-catalog/ocp-crypto';
import {
  documentSignatureIssuer,
  exitCodeForVerification,
  verifyCatalogDocument,
} from './inspect-verify';

const FIXTURE_URL = new URL(
  '../../ocp-crypto/fixtures/signature/manifest-v1.json',
  import.meta.url,
);

interface Fixture {
  key: { catalog_id: string; kid: string };
  jwks: Record<string, { keys: unknown[] }>;
  expected_signed_document: Record<string, unknown>;
  expected_payload_hash: string;
  verify: { at: string };
  negative: {
    name: string;
    document: unknown;
    verify_overrides?: { at?: string };
    expected_error: SignatureErrorCode;
    expected_trust_tier: string;
    expected_invalidates_cache: boolean;
  }[];
}

const fixture = JSON.parse(readFileSync(FIXTURE_URL, 'utf8')) as Fixture;
const CATALOG = fixture.key.catalog_id;
const JWKS: Record<string, unknown> = { [CATALOG]: fixture.jwks[CATALOG] };
const AT = new Date(fixture.verify.at);

const verify = (document: unknown, over: { at?: Date; expectedIssuer?: string } = {}) =>
  verifyCatalogDocument({ document, jwks: JWKS, at: AT, ...over });

describe('inspect --verify · 正例', () => {
  test('验通的 manifest 退出码 0，信任上限 verified', async () => {
    const result = await verify(fixture.expected_signed_document);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error.message);
    expect(result.issuer).toBe(CATALOG);
    expect(result.kid).toBe(fixture.key.kid);
    expect(result.alg).toBe('EdDSA');
    // 重算出来的哈希，不是信封自称的那个。
    expect(result.payload_hash).toBe(fixture.expected_payload_hash);
    expect(result.trust_tier).toBe('verified');
    expect(result.invalidates_cache).toBe(false);
    expect(exitCodeForVerification(result)).toBe(0);
  });
});

describe('inspect --verify · 篡改检测', () => {
  test('改一个字节就退出码非 0，并且报 payload_mismatch', async () => {
    const tampered = structuredClone(fixture.expected_signed_document);
    tampered.catalog_name = `${tampered.catalog_name as string}.`;
    const result = await verify(tampered);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('payload_mismatch');
    expect(exitCodeForVerification(result)).toBe(2);
    // 2 而不是 1：1 是命令本身失败。把「验不过」和「打错命令」放进同一个退出码，
    // 迟早会有脚本把取不到 manifest 读成节点可信。
    expect(exitCodeForVerification(result)).not.toBe(1);
  });

  test('签名对、但签的是别的节点 → issuer_mismatch', async () => {
    const result = await verify(fixture.expected_signed_document, {
      expectedIssuer: 'cat_somebody_else',
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('issuer_mismatch');
    expect(exitCodeForVerification(result)).toBe(2);
  });
});

describe('inspect --verify · 八个码都能从输出里读到', () => {
  test('12 条反例覆盖 §8 的全部八个码', async () => {
    const seen = new Set<string>();
    for (const entry of fixture.negative) {
      const result = await verify(entry.document, {
        ...(entry.verify_overrides?.at ? { at: new Date(entry.verify_overrides.at) } : {}),
      });
      if (!result.ok) seen.add(result.error.code);
    }
    expect([...SIGNATURE_ERROR_CODES].filter((code) => !seen.has(code))).toEqual([]);
  });

  test('不是一句「验签失败」：每个码有自己的一句话', async () => {
    const codesByMessage = new Map<string, Set<string>>();
    for (const entry of fixture.negative) {
      const result = await verify(entry.document, {
        ...(entry.verify_overrides?.at ? { at: new Date(entry.verify_overrides.at) } : {}),
      });
      if (result.ok) continue;
      const codes = codesByMessage.get(result.error.message) ?? new Set<string>();
      codes.add(result.error.code);
      codesByMessage.set(result.error.message, codes);
    }
    // 码是给脚本看的，message 是给人看的。同一句话覆盖两个码，就说明有一个码在
    // 拿别人的解释糊弄人——比如把「过期」说成「签名不对」。
    // （反过来，两条反例改坏了同一个字段、拿到同一句话，是对的。）
    expect([...codesByMessage.values()].filter((codes) => codes.size > 1)).toEqual([]);
    expect(codesByMessage.size).toBeGreaterThanOrEqual(SIGNATURE_ERROR_CODES.length);
  });

  for (const entry of fixture.negative) {
    test(`${entry.name} → ${entry.expected_error}`, async () => {
      const result = await verify(entry.document, {
        ...(entry.verify_overrides?.at ? { at: new Date(entry.verify_overrides.at) } : {}),
      });
      expect(result.ok).toBe(false);
      if (result.ok) return;
      // 输出里是具体哪个码，而不是一句「验签失败」——运维据此决定是去取密钥还是去发起争议。
      expect(result.error.code).toBe(entry.expected_error);
      expect(result.error.message.length).toBeGreaterThan(0);
      // §9 的信任上限和码一起出，否则「码对了、毒缓存留着」也算通过。
      expect(result.trust_tier).toBe(entry.expected_trust_tier as 'unknown');
      expect(result.invalidates_cache).toBe(entry.expected_invalidates_cache);
      expect(exitCodeForVerification(result)).toBe(2);
    });
  }
});

describe('inspect --verify · 该去取谁的密钥', () => {
  test('从信封读 issuer', () => {
    expect(documentSignatureIssuer(fixture.expected_signed_document)).toBe(CATALOG);
  });

  test('没签名时退回文档的 catalog_id —— 「你没给密钥」那句话要说得出是谁的', () => {
    const unsigned = structuredClone(fixture.expected_signed_document);
    delete unsigned.signature;
    expect(documentSignatureIssuer(unsigned)).toBe(CATALOG);
  });

  test('不是对象就没有答案', () => {
    expect(documentSignatureIssuer(null)).toBeUndefined();
    expect(documentSignatureIssuer('cat_nope')).toBeUndefined();
  });

  test('一把密钥都没给时报 key_not_found —— 所以命令要在验签之前先拦一道', async () => {
    // 这条不是在肯定这个行为，是在钉住它：没给密钥和节点发的密钥集里没这个 kid，
    // 在这一层是同一个码，而两者的处理方式完全不同（补个 flag / 发起争议）。
    // 命令侧因此在调用之前先查一次并抛错（退出码 1），不让它落到退出码 2。
    const result = await verifyCatalogDocument({
      document: fixture.expected_signed_document,
      jwks: {},
      at: AT,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe('key_not_found');
  });
});
