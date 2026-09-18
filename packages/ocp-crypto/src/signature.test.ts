/**
 * Document signing — `docs/specs/crypto/v1.md`.
 *
 * The question this file answers is "does this implementation obey the spec",
 * one test per normative clause. The §7 ordering tests matter most: a document
 * that breaks several rules at once must report the *first* failing step, or
 * three implementations will disagree about a document all three reject.
 */
import { describe, expect, test } from 'bun:test';
import {
  SIGNATURE_MEMBER,
  SignatureError,
  documentPayload,
  documentPayloadHash,
  generateEd25519KeyPair,
  signDocument,
  signatureSigningBytes,
  staticDocumentKeyResolver,
  trustCeilingFor,
  verifyDocumentSignature,
  type Ed25519PrivateJwk,
  type SignatureEnvelope,
  type SignedDocument,
} from './index';

const SIGNED_AT = new Date('2026-09-18T00:00:00.000Z');

/** A minimal stand-in for a manifest: the shape matters, the contents do not. */
const DOCUMENT = {
  ocp_version: '1.0',
  kind: 'CatalogManifest',
  id: 'manifest_example',
  catalog_id: 'cat_example',
  catalog_name: 'Example Catalog',
  endpoints: {
    query: { url: 'https://example.com/ocp/query', method: 'POST' },
    resolve: { url: 'https://example.com/ocp/resolve', method: 'POST' },
  },
  query_capabilities: [{ capability_id: 'keyword' }],
  object_contracts: [],
} as const;

interface Fixture {
  privateJwk: Ed25519PrivateJwk;
  jwks: { keys: unknown[] };
  signed: SignedDocument<typeof DOCUMENT>;
  resolveKey: ReturnType<typeof staticDocumentKeyResolver>;
}

function fixture(overrides: { issuer?: string; expiresAt?: Date } = {}): Fixture {
  const { publicJwk, privateJwk } = generateEd25519KeyPair();
  const signed = signDocument({
    document: DOCUMENT,
    privateJwk,
    now: () => SIGNED_AT,
    ...(overrides.issuer === undefined ? {} : { issuer: overrides.issuer }),
    ...(overrides.expiresAt === undefined ? {} : { expiresAt: overrides.expiresAt }),
  });
  const jwks = { keys: [publicJwk] };
  return { privateJwk, jwks, signed, resolveKey: staticDocumentKeyResolver(jwks) };
}

/** Deep-copies a signed document so a test can tamper with one member. */
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

async function codeOf(document: unknown, fx: Fixture, at = SIGNED_AT): Promise<string> {
  const result = await verifyDocumentSignature({ document, resolveKey: fx.resolveKey, at });
  return result.ok ? '<ok>' : result.error.code;
}

describe('签名 · 签发', () => {
  test('往返：签完能验，verdict 报出信封里的事实', async () => {
    const fx = fixture();
    const result = await verifyDocumentSignature({
      document: fx.signed,
      resolveKey: fx.resolveKey,
      at: SIGNED_AT,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.issuer).toBe('cat_example');
    expect(result.kid).toBe(fx.privateJwk.kid);
    expect(result.alg).toBe('EdDSA');
    expect(result.signedAt).toBe('2026-09-18T00:00:00.000Z');
    expect(result.expiresAt).toBeUndefined();
    expect(result.payloadHash).toBe(fx.signed.signature.payload_hash);
  });

  test('信封字段齐全，且 payload_hash 是 §10 的表示形式', () => {
    const { signature } = fixture().signed;
    expect(Object.keys(signature).sort()).toEqual([
      'alg',
      'issuer',
      'kid',
      'payload_hash',
      'signature',
      'signed_at',
    ]);
    expect(/^sha256:[0-9a-f]{64}$/.test(signature.payload_hash)).toBe(true);
    expect(/^[A-Za-z0-9_-]+$/.test(signature.signature)).toBe(true);
  });

  test('issuer 默认取文档的 catalog_id', () => {
    expect(fixture().signed.signature.issuer).toBe(DOCUMENT.catalog_id);
  });

  test('issuer 与 catalog_id 不符 → 拒签，而不是签出一份没人能验的文档', () => {
    const { privateJwk } = generateEd25519KeyPair();
    let code = '<no error>';
    try {
      signDocument({ document: DOCUMENT, privateJwk, issuer: 'cat_someone_else' });
    } catch (err) {
      code = err instanceof SignatureError ? err.code : `<${(err as Error).name}>`;
    }
    expect(code).toBe('issuer_mismatch');
  });

  test('文档没有 catalog_id 时必须显式给 issuer', () => {
    const { privateJwk } = generateEd25519KeyPair();
    const anonymous = { ocp_version: '1.0', kind: 'Whatever' };
    expect(() => signDocument({ document: anonymous, privateJwk })).toThrow(SignatureError);
    const signed = signDocument({ document: anonymous, privateJwk, issuer: 'cat_example' });
    expect(signed.signature.issuer).toBe('cat_example');
  });

  test('kid 缺省取密钥自带的 kid，密钥没有 kid 时取指纹', () => {
    const { publicJwk, privateJwk, kid } = generateEd25519KeyPair();
    expect(signDocument({ document: DOCUMENT, privateJwk }).signature.kid).toBe(kid);

    const { kid: _dropped, ...keyless } = privateJwk;
    const signed = signDocument({ document: DOCUMENT, privateJwk: keyless as Ed25519PrivateJwk });
    expect(signed.signature.kid).toBe(publicJwk.kid);
  });

  test('不改原文档，且重签不会把旧信封算进新哈希', async () => {
    const fx = fixture();
    expect(DOCUMENT).not.toHaveProperty(SIGNATURE_MEMBER);

    const resigned = signDocument({
      document: fx.signed,
      privateJwk: fx.privateJwk,
      now: () => SIGNED_AT,
    });
    expect(resigned.signature.payload_hash).toBe(fx.signed.signature.payload_hash);
    expect(resigned.signature.signature).toBe(fx.signed.signature.signature);
    expect(await codeOf(resigned, fx)).toBe('<ok>');
  });

  test('Ed25519 是确定性的：同文档同密钥同时刻 → 同一串签名字节', () => {
    const { privateJwk } = generateEd25519KeyPair();
    const a = signDocument({ document: DOCUMENT, privateJwk, now: () => SIGNED_AT });
    const b = signDocument({ document: DOCUMENT, privateJwk, now: () => SIGNED_AT });
    expect(a.signature).toEqual(b.signature);
  });

  test('expires_at 只在给了的时候出现', () => {
    const until = new Date('2026-09-25T00:00:00.000Z');
    expect(fixture({ expiresAt: until }).signed.signature.expires_at).toBe(until.toISOString());
  });
});

describe('签名 · 两层绑定（§4.1）', () => {
  test('payload_hash 算的是「文档去掉 signature」，不是整份文档', () => {
    const fx = fixture();
    expect(fx.signed.signature.payload_hash).toBe(documentPayloadHash(DOCUMENT));
    expect(documentPayload(fx.signed)).toEqual(DOCUMENT);
  });

  test('签名材料是「信封去掉 signature」，不含 signature 字段', () => {
    const bytes = signatureSigningBytes(fixture().signed.signature);
    expect(bytes.includes('"payload_hash"')).toBe(true);
    expect(bytes.includes('"signature"')).toBe(false);
    // OCP-JCS：无空白、键序固定。
    expect(bytes.startsWith('{"alg":"EdDSA","issuer":')).toBe(true);
  });

  test('成员顺序不影响哈希，多一个成员就影响', () => {
    // 同样的成员，插入顺序整个倒过来。
    const reordered = Object.fromEntries(Object.entries(DOCUMENT).reverse());
    expect(Object.keys(reordered)).not.toEqual(Object.keys(DOCUMENT));
    expect(documentPayloadHash(reordered)).toBe(documentPayloadHash(DOCUMENT));
    expect(documentPayloadHash({ ...DOCUMENT, description: '' })).not.toBe(
      documentPayloadHash(DOCUMENT),
    );
  });
});

describe('签名 · 验签（§7 八步）', () => {
  test('步骤 1 — 没有 signature 成员 → unsigned', async () => {
    const fx = fixture();
    expect(await codeOf(DOCUMENT, fx)).toBe('unsigned');
    expect(await codeOf('not an object', fx)).toBe('unsigned');
  });

  test('步骤 2 — 信封结构不对 → envelope_malformed', async () => {
    const fx = fixture();

    const notAnObject = clone(fx.signed) as unknown as Record<string, unknown>;
    notAnObject.signature = 'MEUCIQ';
    expect(await codeOf(notAnObject, fx)).toBe('envelope_malformed');

    const missing = clone(fx.signed) as unknown as { signature: Record<string, unknown> };
    delete missing.signature.kid;
    expect(await codeOf(missing, fx)).toBe('envelope_malformed');

    const extra = clone(fx.signed) as unknown as { signature: Record<string, unknown> };
    extra.signature.nonce = 'abc';
    expect(await codeOf(extra, fx)).toBe('envelope_malformed');

    const badHash = clone(fx.signed);
    badHash.signature.payload_hash = 'SHA256:ABC';
    expect(await codeOf(badHash, fx)).toBe('envelope_malformed');

    const badTime = clone(fx.signed);
    badTime.signature.signed_at = 'last tuesday';
    expect(await codeOf(badTime, fx)).toBe('envelope_malformed');

    const padded = clone(fx.signed);
    padded.signature.signature = `${padded.signature.signature}==`;
    expect(await codeOf(padded, fx)).toBe('envelope_malformed');
  });

  test('步骤 3 — alg 非 EdDSA → alg_not_supported', async () => {
    const fx = fixture();
    const document = clone(fx.signed) as unknown as { signature: Record<string, unknown> };
    document.signature.alg = 'HS256';
    expect(await codeOf(document, fx)).toBe('alg_not_supported');
  });

  test('步骤 4 — 只改信封 issuer → issuer_mismatch', async () => {
    const fx = fixture();
    const document = clone(fx.signed);
    document.signature.issuer = 'cat_attacker';
    expect(await codeOf(document, fx)).toBe('issuer_mismatch');
  });

  test('步骤 4 — expectedIssuer 把文档钉在验签方心里的那个节点上', async () => {
    const fx = fixture();
    const pinned = await verifyDocumentSignature({
      document: fx.signed,
      resolveKey: fx.resolveKey,
      at: SIGNED_AT,
      expectedIssuer: 'cat_other',
    });
    expect(pinned.ok).toBe(false);
    if (!pinned.ok) expect(pinned.error.code).toBe('issuer_mismatch');
  });

  test('步骤 4 — 没有 catalog_id 又没给 expectedIssuer：不静默跳过，报 issuer_mismatch', async () => {
    const { publicJwk, privateJwk } = generateEd25519KeyPair();
    const resolveKey = staticDocumentKeyResolver({ keys: [publicJwk] });
    const signed = signDocument({
      document: { ocp_version: '1.0', kind: 'Whatever' },
      privateJwk,
      issuer: 'cat_example',
      now: () => SIGNED_AT,
    });

    const unchecked = await verifyDocumentSignature({ document: signed, resolveKey, at: SIGNED_AT });
    expect(unchecked.ok).toBe(false);
    if (!unchecked.ok) expect(unchecked.error.code).toBe('issuer_mismatch');

    const checked = await verifyDocumentSignature({
      document: signed,
      resolveKey,
      at: SIGNED_AT,
      expectedIssuer: 'cat_example',
    });
    expect(checked.ok).toBe(true);
  });

  test('步骤 5 — 载荷改一个字节 → payload_mismatch', async () => {
    const fx = fixture();
    const document = clone(fx.signed);
    (document as { catalog_name: string }).catalog_name = 'Example Cataloh';
    expect(await codeOf(document, fx)).toBe('payload_mismatch');
  });

  test('步骤 5 — 把节点名整体改掉（catalog_id 与 issuer 一起改）也挡得住', async () => {
    const fx = fixture();
    const document = clone(fx.signed) as unknown as {
      catalog_id: string;
      signature: SignatureEnvelope;
    };
    document.catalog_id = 'cat_attacker';
    document.signature.issuer = 'cat_attacker';
    // issuer 与 catalog_id 自洽，所以过了第 4 步，倒在载荷哈希上。
    expect(await codeOf(document, fx)).toBe('payload_mismatch');
  });

  test('步骤 6 — kid 不在 JWKS 里 → key_not_found', async () => {
    const fx = fixture();
    const stranger = generateEd25519KeyPair();
    const result = await verifyDocumentSignature({
      document: fx.signed,
      resolveKey: staticDocumentKeyResolver({ keys: [stranger.publicJwk] }),
      at: SIGNED_AT,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('key_not_found');
  });

  test('步骤 7 — 换一把密钥验 → signature_invalid', async () => {
    const fx = fixture();
    const impostor = generateEd25519KeyPair();
    // 同一个 kid，不同的密钥：冒名节点发布了一把顶替的公钥。
    const keys = [{ ...impostor.publicJwk, kid: fx.signed.signature.kid }];
    const result = await verifyDocumentSignature({
      document: fx.signed,
      resolveKey: staticDocumentKeyResolver({ keys }),
      at: SIGNED_AT,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('signature_invalid');
  });

  test('步骤 7 — 改信封里的 signed_at → signature_invalid（时刻在签名材料内）', async () => {
    const fx = fixture();
    const document = clone(fx.signed);
    document.signature.signed_at = '2026-09-19T00:00:00.000Z';
    expect(await codeOf(document, fx, new Date('2026-09-19T00:00:00.000Z'))).toBe(
      'signature_invalid',
    );
  });

  test('步骤 8 — 过期只在其余全对时才报，且到期前仍然有效', async () => {
    const until = new Date('2026-09-25T00:00:00.000Z');
    const fx = fixture({ expiresAt: until });
    expect(await codeOf(fx.signed, fx, new Date('2026-09-24T23:59:59.000Z'))).toBe('<ok>');
    expect(await codeOf(fx.signed, fx, new Date('2026-09-25T00:00:01.000Z'))).toBe(
      'signature_expired',
    );
  });
});

describe('签名 · 顺序是规范要求（§7.1）', () => {
  test('同时坏了 alg 与载荷 → 报 alg_not_supported（第 3 步先于第 5 步）', async () => {
    const fx = fixture();
    const document = clone(fx.signed) as unknown as {
      catalog_name: string;
      signature: Record<string, unknown>;
    };
    document.catalog_name = 'tampered';
    document.signature.alg = 'HS256';
    expect(await codeOf(document, fx)).toBe('alg_not_supported');
  });

  test('载荷坏了且密钥取不到 → 报 payload_mismatch（第 5 步先于第 6 步）', async () => {
    const fx = fixture();
    const document = clone(fx.signed);
    (document as { catalog_name: string }).catalog_name = 'tampered';
    const result = await verifyDocumentSignature({
      document,
      resolveKey: staticDocumentKeyResolver({ keys: [] }),
      at: SIGNED_AT,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('payload_mismatch');
    // 这不只是报错顺序：哈希在取密钥之前，意味着一份被篡改的文档无法驱使
    // 验签方为它发起一次网络请求。
  });

  test('伪造且恰好过期 → 报伪造，不报过期（第 8 步在最后）', async () => {
    const fx = fixture({ expiresAt: new Date('2026-09-19T00:00:00.000Z') });
    const document = clone(fx.signed);
    (document as { catalog_name: string }).catalog_name = 'tampered';
    expect(await codeOf(document, fx, new Date('2026-09-30T00:00:00.000Z'))).toBe(
      'payload_mismatch',
    );
  });
});

describe('签名 · JWKS 故障不是验签结论（§7.3）', () => {
  test('密钥服务器宕机 → 抛出，不产生 verdict', async () => {
    const fx = fixture();
    const outage = () => {
      throw new (class extends Error {
        code = 'jwks_unavailable';
        name = 'CryptoError';
      })('key server is down');
    };
    await expect(
      verifyDocumentSignature({ document: fx.signed, resolveKey: outage, at: SIGNED_AT }),
    ).rejects.toThrow('key server is down');
  });
});

describe('签名 · 信任上限（§9）', () => {
  test('通过 → verified，缓存保留', async () => {
    const fx = fixture();
    const result = await verifyDocumentSignature({
      document: fx.signed,
      resolveKey: fx.resolveKey,
      at: SIGNED_AT,
    });
    expect(trustCeilingFor(result)).toEqual({ trustTier: 'verified', invalidatesCache: false });
  });

  test('没签名 / 过期 → unverified，缓存保留（都不是篡改的证据）', () => {
    for (const code of ['unsigned', 'signature_expired'] as const) {
      expect(trustCeilingFor({ ok: false, error: new SignatureError(code, '') })).toEqual({
        trustTier: 'unverified',
        invalidatesCache: false,
      });
    }
  });

  test('其余错误码 → unknown，且必须作废缓存', () => {
    for (const code of [
      'envelope_malformed',
      'alg_not_supported',
      'issuer_mismatch',
      'payload_mismatch',
      'key_not_found',
      'signature_invalid',
    ] as const) {
      expect(trustCeilingFor({ ok: false, error: new SignatureError(code, '') })).toEqual({
        trustTier: 'unknown',
        invalidatesCache: true,
      });
    }
  });
});
