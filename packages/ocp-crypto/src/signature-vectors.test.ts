/**
 * Conformance run over `fixtures/signature/manifest-v1.json` — the vectors
 * `docs/specs/crypto/v1.md` §11 requires every implementation to pass.
 *
 * Separate from `signature.test.ts`, which tests the TypeScript API. This file
 * tests only what the fixture file says, in the order a port would: reproduce
 * the payload hash, reproduce the signing material, reproduce the signature
 * byte for byte, then get the same code *and* the same trust ceiling on every
 * negative. A port that passes this and fails `signature.test.ts` is still
 * conformant; the reverse is not.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, test } from 'bun:test';
import {
  SIGNATURE_ERROR_CODES,
  canonicalValueHash,
  documentPayloadHash,
  signDocument,
  signatureSigningBytes,
  staticDocumentKeyResolver,
  trustCeilingFor,
  verifyDocumentSignature,
  type Ed25519PrivateJwk,
  type SignatureEnvelope,
} from './index';

const FIXTURE_URL = new URL('../fixtures/signature/manifest-v1.json', import.meta.url);
const MANIFEST_SCHEMA_URL = new URL(
  '../../../ocp.catalog.handshake.v1/catalog-manifest.schema.json',
  import.meta.url,
);

interface NegativeCase {
  name: string;
  reason: string;
  document: unknown;
  verify_overrides?: { at?: string };
  expected_error: string;
  expected_trust_tier: string;
  expected_invalidates_cache: boolean;
}

interface Fixture {
  key: { catalog_id: string; kid: string; private_jwk: Ed25519PrivateJwk };
  jwks: Record<string, { keys: unknown[] }>;
  sign: {
    document: Record<string, unknown>;
    signed_at: string;
    expiring_document: Record<string, unknown>;
    expiring_expires_at: string;
  };
  expected_payload_hash: string;
  expected_signing_input: string;
  expected_envelope: SignatureEnvelope;
  expected_signed_document: Record<string, unknown>;
  expected_signed_document_sha256: string;
  expected_expiring_signed_document: Record<string, unknown>;
  verify: {
    at: string;
    expect: {
      ok: boolean;
      issuer: string;
      kid: string;
      alg: string;
      signed_at: string;
      payload_hash: string;
      trust_tier: string;
      invalidates_cache: boolean;
    };
  };
  negative: NegativeCase[];
}

const fixture = JSON.parse(readFileSync(FIXTURE_URL, 'utf8')) as Fixture;
const resolveKey = staticDocumentKeyResolver(fixture.jwks[fixture.key.catalog_id]);

/** Re-signs the fixture's recipe, which is what a port is asked to do. */
function resign(): Record<string, unknown> {
  return signDocument({
    document: fixture.sign.document,
    privateJwk: fixture.key.private_jwk,
    now: () => new Date(fixture.sign.signed_at),
  });
}

describe('签名向量 · 签发（§4.1）', () => {
  test('payload_hash 与向量一致', () => {
    expect(documentPayloadHash(fixture.sign.document)).toBe(fixture.expected_payload_hash);
  });

  test('签名材料与向量逐字节一致', () => {
    expect(signatureSigningBytes(fixture.expected_envelope)).toBe(fixture.expected_signing_input);
  });

  test('重新签发得到逐字节相同的文档', () => {
    const again = resign();
    expect(again).toEqual(fixture.expected_signed_document);
    expect(canonicalValueHash(again)).toBe(fixture.expected_signed_document_sha256);
  });

  test('带 expires_at 的那份也一样', () => {
    const again = signDocument({
      document: fixture.sign.expiring_document,
      privateJwk: fixture.key.private_jwk,
      now: () => new Date(fixture.sign.signed_at),
      expiresAt: new Date(fixture.sign.expiring_expires_at),
    });
    expect(again).toEqual(fixture.expected_expiring_signed_document);
  });
});

describe('签名向量 · 正例（§7 §9）', () => {
  test('验签通过，结论与信任上限都与向量一致', async () => {
    const result = await verifyDocumentSignature({
      document: fixture.expected_signed_document,
      resolveKey,
      at: new Date(fixture.verify.at),
    });
    const want = fixture.verify.expect;
    expect(result.ok).toBe(want.ok);
    if (!result.ok) throw new Error(result.error.message);
    expect(result.issuer).toBe(want.issuer);
    expect(result.kid).toBe(want.kid);
    expect(result.alg).toBe(want.alg);
    expect(result.signedAt).toBe(want.signed_at);
    expect(result.payloadHash).toBe(want.payload_hash);
    expect(trustCeilingFor(result)).toEqual({
      trustTier: want.trust_tier as 'verified',
      invalidatesCache: want.invalidates_cache,
    });
  });
});

describe('签名向量 · 被签的是一份真 manifest', () => {
  /**
   * `catalog-manifest.schema.json` 顶层与 `federation` 都是
   * `additionalProperties: false`，所以一个放错层级的成员会让向量在签一份
   * 任何节点都发不出来的文档。这里只查成员名 —— 完整校验属于 ocp-schema，
   * 而 ocp-crypto 不依赖它。
   */
  const schema = JSON.parse(readFileSync(MANIFEST_SCHEMA_URL, 'utf8')) as {
    required: string[];
    properties: Record<string, { properties?: Record<string, unknown> }>;
  };

  test('顶层成员都是 schema 声明过的，必填项一个不缺', () => {
    const document = fixture.expected_signed_document;
    expect(Object.keys(document).filter((key) => !(key in schema.properties))).toEqual([]);
    expect(schema.required.filter((key) => !(key in document))).toEqual([]);
  });

  test('trust_strategy 在 federation 里面，不在顶层', () => {
    const federation = (fixture.sign.document as { federation: Record<string, unknown> }).federation;
    const declared = schema.properties.federation?.properties ?? {};
    expect(Object.keys(federation).filter((key) => !(key in declared))).toEqual([]);
    expect(federation).toHaveProperty('trust_strategy.manifest_signed', true);
  });

  test('signature 成员本身也是 schema 声明过的', () => {
    expect('signature' in schema.properties).toBe(true);
  });
});

describe('签名向量 · 反例（§8）', () => {
  test('每个码都被覆盖到', () => {
    const covered = new Set(fixture.negative.map((entry) => entry.expected_error));
    expect([...SIGNATURE_ERROR_CODES].filter((code) => !covered.has(code))).toEqual([]);
  });

  test('有一条「载荷任意一字节被改」', () => {
    const names = fixture.negative.map((entry) => entry.name);
    expect(names).toContain('payload-one-byte-changed');
  });

  for (const entry of fixture.negative) {
    test(`${entry.name} → ${entry.expected_error}`, async () => {
      const at = entry.verify_overrides?.at ?? fixture.verify.at;
      const result = await verifyDocumentSignature({
        document: entry.document,
        resolveKey,
        at: new Date(at),
      });
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error.code).toBe(entry.expected_error);
      expect(trustCeilingFor(result)).toEqual({
        trustTier: entry.expected_trust_tier as 'unknown',
        invalidatesCache: entry.expected_invalidates_cache,
      });
    });
  }
});
