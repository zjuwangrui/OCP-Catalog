import { describe, expect, test } from 'bun:test';
import {
  CryptoError,
  assertEd25519PublicJwk,
  fromBase64Url,
  generateEd25519KeyPair,
  jwkThumbprint,
  publicJwkOf,
  signBytes,
  signCanonical,
  toBase64Url,
  verifyBytes,
  verifyCanonical,
} from './index';

const enc = new TextEncoder();
const message = enc.encode('ocp attribution signing input');

function cryptoCodeOf(fn: () => unknown): string {
  try {
    fn();
    return '<no error>';
  } catch (err) {
    if (err instanceof CryptoError) return err.code;
    return `<${(err as Error).name}>`;
  }
}

describe('Ed25519 · 密钥生成', () => {
  test('生成的 JWK 形状与 OCP 约定一致', () => {
    const { kid, publicJwk, privateJwk } = generateEd25519KeyPair();
    expect(publicJwk.kty).toBe('OKP');
    expect(publicJwk.crv).toBe('Ed25519');
    expect(publicJwk.alg).toBe('EdDSA');
    expect(publicJwk.use).toBe('sig');
    expect(publicJwk.kid).toBe(kid);
    expect(fromBase64Url(publicJwk.x).length).toBe(32);
    expect(fromBase64Url(privateJwk.d).length).toBe(32);
  });

  test('kid 默认取 RFC 7638 指纹：同一公钥恒等，不同公钥必异', () => {
    const a = generateEd25519KeyPair();
    const b = generateEd25519KeyPair();
    expect(a.kid).toBe(jwkThumbprint(a.publicJwk));
    // Recomputed from only the three required members — the thumbprint must
    // not depend on kid/alg/use being present.
    expect(a.kid).toBe(jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: a.publicJwk.x }));
    expect(a.kid).not.toBe(b.kid);
  });

  test('publicJwkOf 去掉 d，可以安全发布', () => {
    const { privateJwk } = generateEd25519KeyPair();
    expect(publicJwkOf(privateJwk)).not.toHaveProperty('d');
    expect(privateJwk).toHaveProperty('d');
  });

  test('显式 kid 覆盖指纹', () => {
    const { kid, publicJwk } = generateEd25519KeyPair({ kid: 'cat_origin_2026_09' });
    expect(kid).toBe('cat_origin_2026_09');
    expect(publicJwk.kid).toBe('cat_origin_2026_09');
  });
});

describe('Ed25519 · 签名与验签', () => {
  test('往返验通', () => {
    const { publicJwk, privateJwk } = generateEd25519KeyPair();
    const signature = signBytes(privateJwk, message);
    expect(verifyBytes({ jwk: publicJwk, message, signature })).toBe(true);
  });

  test('签名是无填充 base64url，符合 AttributionChainNode.signature 的正则', () => {
    const { privateJwk } = generateEd25519KeyPair();
    const signature = signBytes(privateJwk, message);
    expect(/^[A-Za-z0-9_-]+$/.test(signature)).toBe(true);
    expect(signature.includes('=')).toBe(false);
    expect(fromBase64Url(signature).length).toBe(64);
  });

  test('改一个字节的消息 → false', () => {
    const { publicJwk, privateJwk } = generateEd25519KeyPair();
    const signature = signBytes(privateJwk, message);
    expect(verifyBytes({ jwk: publicJwk, message: enc.encode('ocp attribution signing inpuT'), signature })).toBe(
      false,
    );
  });

  test('改签名 / 换密钥 / 空签名 → false，且不抛', () => {
    const { publicJwk, privateJwk } = generateEd25519KeyPair();
    const other = generateEd25519KeyPair();
    const signature = signBytes(privateJwk, message);
    const flipped = `${signature.slice(0, -1)}${signature.endsWith('A') ? 'B' : 'A'}`;

    expect(verifyBytes({ jwk: publicJwk, message, signature: flipped })).toBe(false);
    expect(verifyBytes({ jwk: other.publicJwk, message, signature })).toBe(false);
    expect(verifyBytes({ jwk: publicJwk, message, signature: 'AAAA' })).toBe(false);
    // Padded base64 is rejected as a mismatch, not accepted as an alias.
    expect(verifyBytes({ jwk: publicJwk, message, signature: `${signature}==` })).toBe(false);
  });

  test('alg 非 EdDSA → 抛 alg_not_supported（配置问题，不是数据问题）', () => {
    const { publicJwk, privateJwk } = generateEd25519KeyPair();
    const signature = signBytes(privateJwk, message);
    expect(cryptoCodeOf(() => verifyBytes({ jwk: publicJwk, message, signature, alg: 'ES256' }))).toBe(
      'alg_not_supported',
    );
    expect(cryptoCodeOf(() => verifyBytes({ jwk: publicJwk, message, signature, alg: 'none' }))).toBe(
      'alg_not_supported',
    );
  });

  test('非 Ed25519 的 JWK → alg_not_supported；缺 x 的 JWK → invalid_key', () => {
    expect(cryptoCodeOf(() => assertEd25519PublicJwk({ kty: 'EC', crv: 'P-256', x: 'AA', y: 'BB' }))).toBe(
      'alg_not_supported',
    );
    expect(cryptoCodeOf(() => assertEd25519PublicJwk({ kty: 'OKP', crv: 'X25519', x: 'AA' }))).toBe(
      'alg_not_supported',
    );
    expect(cryptoCodeOf(() => assertEd25519PublicJwk({ kty: 'OKP', crv: 'Ed25519', x: 'AA', alg: 'ES256' }))).toBe(
      'alg_not_supported',
    );
    expect(cryptoCodeOf(() => assertEd25519PublicJwk({ kty: 'OKP', crv: 'Ed25519', x: 'AA', use: 'enc' }))).toBe(
      'alg_not_supported',
    );
    expect(cryptoCodeOf(() => assertEd25519PublicJwk({ kty: 'OKP', crv: 'Ed25519' }))).toBe('invalid_key');
    // Right kind of key, wrong length — caught before it reaches node:crypto.
    expect(cryptoCodeOf(() => assertEd25519PublicJwk({ kty: 'OKP', crv: 'Ed25519', x: 'AAAA' }))).toBe('invalid_key');
  });

  test('base64url 拒绝填充与标准 base64 字母表', () => {
    expect(cryptoCodeOf(() => fromBase64Url('AA=='))).toBe('invalid_encoding');
    expect(cryptoCodeOf(() => fromBase64Url('a+b/c'))).toBe('invalid_encoding');
    expect(toBase64Url(Uint8Array.from([251, 255, 190]))).toBe('-_--');
  });
});

describe('Ed25519 · 与规范化的组合（归因签名的实际形态）', () => {
  test('字段序不同的同一对象 → 同一签名，且互相验通', () => {
    const { publicJwk, privateJwk } = generateEd25519KeyPair();
    const a = { chain: [{ catalog_id: 'cat_a', hop: 1 }], core: { jti: 'j1', agent_id: 'ag_1' } };
    const b = { core: { agent_id: 'ag_1', jti: 'j1' }, chain: [{ hop: 1, catalog_id: 'cat_a' }] };

    const signature = signCanonical(privateJwk, a);
    expect(signCanonical(privateJwk, b)).toBe(signature);
    expect(verifyCanonical({ jwk: publicJwk, value: b, signature })).toBe(true);
  });

  test('改一个 claim → 验签失败（这是「篡改可检测」的最小证明）', () => {
    const { publicJwk, privateJwk } = generateEd25519KeyPair();
    const value = { core: { agent_id: 'ag_1', jti: 'j1' } };
    const signature = signCanonical(privateJwk, value);
    expect(verifyCanonical({ jwk: publicJwk, value: { core: { agent_id: 'ag_2', jti: 'j1' } }, signature })).toBe(
      false,
    );
  });

  test('数组顺序参与签名：重排 chain 即验签失败', () => {
    const { publicJwk, privateJwk } = generateEd25519KeyPair();
    const chain = [{ hop: 1 }, { hop: 2 }];
    const signature = signCanonical(privateJwk, { chain });
    expect(verifyCanonical({ jwk: publicJwk, value: { chain: [{ hop: 2 }, { hop: 1 }] }, signature })).toBe(false);
  });
});
