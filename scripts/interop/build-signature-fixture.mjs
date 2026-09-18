/**
 * Regenerates `packages/ocp-crypto/fixtures/signature/manifest-v1.json`.
 *
 *     node --experimental-strip-types --import ./scripts/interop/register-ts.mjs \
 *          scripts/interop/build-signature-fixture.mjs
 *
 * The conformance vectors `docs/specs/crypto/v1.md` §11 requires. Same shape as
 * the attribution vectors next to them, for the same reason: one file that any
 * implementation can be held to without reading the reference implementation.
 *
 * What the fixture pins, beyond the obvious:
 *
 * - **`expected_payload_hash` and `expected_signing_input` separately.** The two
 *   layers of §4.1 fail for different reasons, and a port that only sees "the
 *   signature does not match" cannot tell which layer drifted. With both here,
 *   a mismatched hash means the document canonicalization differs and a matched
 *   hash with a mismatched signature means the envelope canonicalization does.
 * - **`expected_signed_document` byte for byte.** Ed25519 is deterministic and
 *   OCP-JCS fixes the bytes, so two correct signers have no room to differ —
 *   there is no reason to settle for mutual verifiability.
 * - **The trust ceiling on every case.** §9 is as normative as §8; an
 *   implementation that reports the right code and keeps a poisoned cache has
 *   not passed.
 *
 * The negative set covers each §8 code once, plus three ordering cases where a
 * document breaks several rules at once. Those are the ones that actually catch
 * a divergent port: everyone rejects a doubly-broken document, and only a
 * correct implementation rejects it with the *first* failing step's code.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import {
  canonicalValueHash,
  documentPayloadHash,
  jwkThumbprint,
  signDocument,
  signatureSigningBytes,
  toBase64Url,
  trustCeilingFor,
} from '@ocp-catalog/ocp-crypto';

const OUT_DIR = new URL('../../packages/ocp-crypto/fixtures/signature/', import.meta.url);
const OUT_FILE = new URL('manifest-v1.json', OUT_DIR);

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX_LENGTH = 12;

/** A key pair from a literal 32-byte seed — reproducible, unlike generation. */
function keyPairFromSeed(seedHex) {
  const seed = Buffer.from(seedHex, 'hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const base = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: toBase64Url(new Uint8Array(spki.subarray(SPKI_PREFIX_LENGTH))),
    alg: 'EdDSA',
    use: 'sig',
  };
  const kid = jwkThumbprint(base);
  return { kid, publicJwk: { ...base, kid }, privateJwk: { ...base, kid, d: toBase64Url(seed) } };
}

// Seed 0x…11 rather than 0x…01, so a signature from these vectors can never be
// confused with one from the attribution vectors that share this directory.
const CATALOG_ID = 'cat_interop_signed';
const SEED_HEX = `${'00'.repeat(31)}11`;
const KEY = keyPairFromSeed(SEED_HEX);

const SIGNED_AT = new Date('2026-03-01T12:00:00.000Z');
const EXPIRES_AT = new Date('2026-03-01T13:00:00.000Z');
const VERIFY_AT = '2026-03-01T12:30:00.000Z';

/**
 * A manifest the handshake schema accepts, kept small but not degenerate: a
 * nested `endpoints` object and an array of objects are what exercise the parts
 * of OCP-JCS that ports get wrong.
 */
const DOCUMENT = {
  ocp_version: '1.0',
  kind: 'CatalogManifest',
  id: `manifest_${CATALOG_ID}`,
  catalog_id: CATALOG_ID,
  catalog_name: 'Interop Signed Catalog',
  description: 'Fixture manifest for the crypto/v1 signature vectors.',
  registry_visibility: 'public',
  endpoints: {
    health: { url: 'https://interop.example/ocp/health', method: 'GET' },
    query: { url: 'https://interop.example/ocp/query', method: 'POST' },
    resolve: { url: 'https://interop.example/ocp/resolve', method: 'POST' },
  },
  query_capabilities: [
    {
      capability_id: 'ocp.interop.product.search.v1',
      name: 'Keyword product search',
      query_packs: [{ pack_id: 'ocp.query.keyword.v1', query_modes: ['keyword'] }],
      supports_explain: true,
      supports_resolve: true,
    },
  ],
  object_contracts: [],
  trust_strategy: {
    manifest_signed: true,
    signature_algorithms: ['EdDSA'],
    downgrade_invalidates_cache: true,
  },
};

const signed = signDocument({ document: DOCUMENT, privateJwk: KEY.privateJwk, now: () => SIGNED_AT });

// A second, separately signed document for the expiry cases. The expiry cannot
// be produced by editing the good one — `expires_at` is inside the signed
// material, so adding it would fail at step 7 as `signature_invalid` and never
// reach step 8.
const expiring = signDocument({
  document: { ...DOCUMENT, id: `manifest_${CATALOG_ID}_expiring` },
  privateJwk: KEY.privateJwk,
  now: () => SIGNED_AT,
  expiresAt: EXPIRES_AT,
});

/** A deep copy with one member replaced, for the mutation cases. */
function mutate(base, fn) {
  const copy = structuredClone(base);
  fn(copy);
  return copy;
}

/** Flips the first character of a base64url string to something else. */
function flip(text) {
  return (text[0] === 'A' ? 'B' : 'A') + text.slice(1);
}

function ceiling(code) {
  const { trustTier, invalidatesCache } = trustCeilingFor({ ok: false, error: { code } });
  return { expected_trust_tier: trustTier, expected_invalidates_cache: invalidatesCache };
}

function negative(entry) {
  return { ...entry, ...ceiling(entry.expected_error) };
}

const negatives = [
  negative({
    name: 'unsigned',
    reason: '没有 signature 成员 —— 缺证据不是伪造，缓存保留（§9）',
    document: DOCUMENT,
    expected_error: 'unsigned',
  }),
  negative({
    name: 'envelope-missing-kid',
    reason: '信封缺字段在取密钥之前拒绝，否则「取哪把钥匙」本身没有答案（§7 步骤 2）',
    document: mutate(signed, (d) => {
      delete d.signature.kid;
    }),
    expected_error: 'envelope_malformed',
  }),
  negative({
    name: 'envelope-unknown-field',
    reason: '未知字段进了签名材料却没被检查，必须拒绝（§5.1）',
    document: mutate(signed, (d) => {
      d.signature.nbf = '2026-03-01T12:00:00.000Z';
    }),
    expected_error: 'envelope_malformed',
  }),
  negative({
    name: 'alg-swapped',
    reason: 'alg 在签名材料内，但必须在取密钥之前拒绝（算法混淆，§7 步骤 3）',
    document: mutate(signed, (d) => {
      d.signature.alg = 'ES256';
    }),
    expected_error: 'alg_not_supported',
  }),
  negative({
    name: 'issuer-not-catalog-id',
    reason: 'issuer 必须等于文档的 catalog_id（§4.4）',
    document: mutate(signed, (d) => {
      d.signature.issuer = 'cat_interop_someone_else';
    }),
    expected_error: 'issuer_mismatch',
  }),
  negative({
    name: 'payload-one-byte-changed',
    reason: '载荷任意一字节被改 —— §11 点名要求的那条，也是 W3-T3 篡改检测的机读形态',
    document: mutate(signed, (d) => {
      d.catalog_name = 'Interop Signed Catalof';
    }),
    expected_error: 'payload_mismatch',
  }),
  negative({
    name: 'unknown-kid',
    reason: '发布的密钥集里没有这个 kid',
    document: mutate(signed, (d) => {
      d.signature.kid = 'kid_not_published';
    }),
    expected_error: 'key_not_found',
  }),
  negative({
    name: 'signature-one-byte-changed',
    reason: '载荷完好、只有签名被改 —— 与 payload_mismatch 分开报，正是两层绑定的目的（§4.2）',
    document: mutate(signed, (d) => {
      d.signature.signature = flip(d.signature.signature);
    }),
    expected_error: 'signature_invalid',
  }),
  negative({
    name: 'signature-expired',
    reason: '签名真实，只是过期 —— 缓存保留，信任降到 unverified（§9）',
    document: expiring,
    verify_overrides: { at: '2026-03-01T13:00:01.000Z' },
    expected_error: 'signature_expired',
  }),
  // The three below break more than one rule at once. They are the vectors that
  // distinguish a correct port from one that happens to reject bad documents.
  negative({
    name: 'order-alg-before-payload',
    reason: 'alg 与载荷同时被改 → 报 alg_not_supported，不是 payload_mismatch（§7.1）',
    document: mutate(signed, (d) => {
      d.signature.alg = 'ES256';
      d.catalog_name = 'Tampered';
    }),
    expected_error: 'alg_not_supported',
  }),
  negative({
    name: 'order-payload-before-key',
    reason: '载荷被改且 kid 不存在 → 先算哈希，任意文档都不该把验签方推去发请求（§7 步骤 5）',
    document: mutate(signed, (d) => {
      d.signature.kid = 'kid_not_published';
      d.catalog_name = 'Tampered';
    }),
    expected_error: 'payload_mismatch',
  }),
  negative({
    name: 'order-expiry-last',
    reason: '伪造且过期 → 报 payload_mismatch，把伪造报成过期是把重的说成轻的（§7.1）',
    document: mutate(expiring, (d) => {
      d.catalog_name = 'Tampered';
    }),
    verify_overrides: { at: '2026-03-01T13:00:01.000Z' },
    expected_error: 'payload_mismatch',
  }),
];

const fixture = {
  description:
    'OCP 文档签名一致性向量：同一把密钥、同一份待签文档，TypeScript / Python / Go 必须产出逐字节相同的签名文档，并对同一批反例给出相同的错误码与信任上限。',
  spec: 'docs/specs/crypto/v1.md §4.1 §5.1 §7 §8 §9 §11',
  generated_by: 'scripts/interop/build-signature-fixture.mjs',
  key: {
    catalog_id: CATALOG_ID,
    seed_hex: SEED_HEX,
    kid: KEY.kid,
    public_jwk: KEY.publicJwk,
    private_jwk: KEY.privateJwk,
  },
  jwks: { [CATALOG_ID]: { keys: [KEY.publicJwk] } },
  sign: {
    document: DOCUMENT,
    signed_at: SIGNED_AT.toISOString(),
    expiring_document: { ...DOCUMENT, id: `manifest_${CATALOG_ID}_expiring` },
    expiring_expires_at: EXPIRES_AT.toISOString(),
  },
  expected_payload_hash: documentPayloadHash(DOCUMENT),
  expected_signing_input: signatureSigningBytes(signed.signature),
  expected_envelope: signed.signature,
  expected_signed_document: signed,
  expected_signed_document_sha256: canonicalValueHash(signed),
  expected_expiring_signed_document: expiring,
  verify: {
    at: VERIFY_AT,
    expect: {
      ok: true,
      issuer: CATALOG_ID,
      kid: KEY.kid,
      alg: 'EdDSA',
      signed_at: SIGNED_AT.toISOString(),
      payload_hash: documentPayloadHash(DOCUMENT),
      trust_tier: 'verified',
      invalidates_cache: false,
    },
  },
  negative: negatives,
};

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(OUT_FILE, `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');
console.log(
  `wrote ${OUT_FILE.pathname} — ${negatives.length} negative cases, document ${fixture.expected_signed_document_sha256}`,
);
