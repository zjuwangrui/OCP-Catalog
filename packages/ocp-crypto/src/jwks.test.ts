import { describe, expect, test } from 'bun:test';
import {
  CryptoError,
  JwksCache,
  createDiscoveryJwksLoader,
  generateEd25519KeyPair,
} from './index';

/**
 * The three error paths the two-week plan requires tests for — `kid` 未命中 /
 * JWKS 过期 / 算法不支持 — plus the cache behaviour each of them depends on.
 *
 * Time is injected, so TTL expiry is asserted rather than slept through.
 */

const CATALOG = 'cat_origin';

function jwkSetOf(...keys: unknown[]) {
  return { keys };
}

function clock(start = 1_000_000) {
  let t = start;
  return {
    now: () => t,
    advance(ms: number) {
      t += ms;
    },
  };
}

async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return '<no error>';
  } catch (err) {
    if (err instanceof CryptoError) return err.code;
    return `<${(err as Error).name}: ${(err as Error).message}>`;
  }
}

describe('JwksCache · 命中与缓存', () => {
  test('解析到 kid，且 TTL 内不回源', async () => {
    const { kid, publicJwk } = generateEd25519KeyPair();
    const time = clock();
    let loads = 0;
    const cache = new JwksCache({
      now: time.now,
      ttlMs: 60_000,
      load: async () => {
        loads += 1;
        return jwkSetOf(publicJwk);
      },
    });

    expect((await cache.getVerificationKey(CATALOG, kid)).x).toBe(publicJwk.x);
    time.advance(59_000);
    expect((await cache.getVerificationKey(CATALOG, kid)).x).toBe(publicJwk.x);
    expect(loads).toBe(1);
    expect(cache.stats()).toEqual({ loads: 1, cachedCatalogs: 1 });
  });

  test('TTL 到点后回源一次', async () => {
    const { kid, publicJwk } = generateEd25519KeyPair();
    const time = clock();
    let loads = 0;
    const cache = new JwksCache({
      now: time.now,
      ttlMs: 60_000,
      load: async () => {
        loads += 1;
        return jwkSetOf(publicJwk);
      },
    });

    await cache.getVerificationKey(CATALOG, kid);
    time.advance(60_000);
    await cache.getVerificationKey(CATALOG, kid);
    expect(loads).toBe(2);
  });

  test('invalidate 后立即回源', async () => {
    const { kid, publicJwk } = generateEd25519KeyPair();
    let loads = 0;
    const cache = new JwksCache({
      load: async () => {
        loads += 1;
        return jwkSetOf(publicJwk);
      },
    });

    await cache.getVerificationKey(CATALOG, kid);
    cache.invalidate(CATALOG);
    await cache.getVerificationKey(CATALOG, kid);
    expect(loads).toBe(2);
  });
});

describe('JwksCache · 错误路径一：kid 未命中', () => {
  test('kid 不在 JWKS 里 → key_not_found', async () => {
    const { publicJwk } = generateEd25519KeyPair();
    const cache = new JwksCache({ load: async () => jwkSetOf(publicJwk) });
    expect(await codeOf(() => cache.getVerificationKey(CATALOG, 'kid_does_not_exist'))).toBe('key_not_found');
  });

  test('冷却期内的 kid 未命中不回源（防放大）', async () => {
    const { kid, publicJwk } = generateEd25519KeyPair();
    const time = clock();
    let loads = 0;
    const cache = new JwksCache({
      now: time.now,
      ttlMs: 600_000,
      minRefetchIntervalMs: 30_000,
      load: async () => {
        loads += 1;
        return jwkSetOf(publicJwk);
      },
    });

    await cache.getVerificationKey(CATALOG, kid);
    expect(loads).toBe(1);
    for (let i = 0; i < 5; i += 1) {
      expect(await codeOf(() => cache.getVerificationKey(CATALOG, `kid_random_${i}`))).toBe('key_not_found');
    }
    expect(loads).toBe(1);
  });

  test('冷却期后的 kid 未命中触发一次轮换探测，能取到新密钥', async () => {
    const first = generateEd25519KeyPair();
    const rotated = generateEd25519KeyPair();
    const time = clock();
    let loads = 0;
    const cache = new JwksCache({
      now: time.now,
      ttlMs: 600_000,
      minRefetchIntervalMs: 30_000,
      load: async () => {
        loads += 1;
        return loads === 1 ? jwkSetOf(first.publicJwk) : jwkSetOf(first.publicJwk, rotated.publicJwk);
      },
    });

    await cache.getVerificationKey(CATALOG, first.kid);
    time.advance(30_000);
    expect((await cache.getVerificationKey(CATALOG, rotated.kid)).x).toBe(rotated.publicJwk.x);
    expect(loads).toBe(2);
  });

  test('轮换探测回源失败时仍报 key_not_found，不报传输错误', async () => {
    const { kid, publicJwk } = generateEd25519KeyPair();
    const time = clock();
    let loads = 0;
    const cache = new JwksCache({
      now: time.now,
      ttlMs: 600_000,
      minRefetchIntervalMs: 30_000,
      load: async () => {
        loads += 1;
        if (loads > 1) throw new Error('ECONNREFUSED');
        return jwkSetOf(publicJwk);
      },
    });

    await cache.getVerificationKey(CATALOG, kid);
    time.advance(30_000);
    expect(await codeOf(() => cache.getVerificationKey(CATALOG, 'kid_unknown'))).toBe('key_not_found');
    // The still-valid cached key remains usable.
    expect((await cache.getVerificationKey(CATALOG, kid)).x).toBe(publicJwk.x);
  });
});

describe('JwksCache · 错误路径二：JWKS 过期', () => {
  test('缓存过期 + 回源失败 → jwks_expired，且拒绝使用过期密钥', async () => {
    const { kid, publicJwk } = generateEd25519KeyPair();
    const time = clock();
    let loads = 0;
    const cache = new JwksCache({
      now: time.now,
      ttlMs: 60_000,
      load: async () => {
        loads += 1;
        if (loads > 1) throw new Error('502 Bad Gateway');
        return jwkSetOf(publicJwk);
      },
    });

    expect((await cache.getVerificationKey(CATALOG, kid)).x).toBe(publicJwk.x);
    time.advance(60_001);

    expect(await codeOf(() => cache.getVerificationKey(CATALOG, kid))).toBe('jwks_expired');
    // Critically: the key that was cached is now gone, so a retry cannot
    // accidentally verify against material the node may already have revoked.
    expect(await codeOf(() => cache.getVerificationKey(CATALOG, kid))).toBe('jwks_unavailable');
  });

  test('从未成功加载过 + 回源失败 → jwks_unavailable（有别于过期）', async () => {
    const cache = new JwksCache({
      load: async () => {
        throw new Error('DNS failure');
      },
    });
    expect(await codeOf(() => cache.getVerificationKey(CATALOG, 'any'))).toBe('jwks_unavailable');
  });

  test('底层异常作为 cause 保留，便于定位', async () => {
    const cache = new JwksCache({
      load: async () => {
        throw new Error('DNS failure');
      },
    });
    try {
      await cache.getVerificationKey(CATALOG, 'any');
      expect('should have thrown').toBe('threw');
    } catch (err) {
      expect((err as CryptoError).code).toBe('jwks_unavailable');
      expect(((err as Error).cause as Error).message).toBe('DNS failure');
    }
  });
});

describe('JwksCache · 错误路径三：算法不支持', () => {
  test('kid 命中但不是 Ed25519 → alg_not_supported，而不是 key_not_found', async () => {
    const cache = new JwksCache({
      load: async () =>
        jwkSetOf({ kty: 'EC', crv: 'P-256', kid: 'kid_es256', x: 'AAAA', y: 'BBBB', alg: 'ES256' }),
    });
    expect(await codeOf(() => cache.getVerificationKey(CATALOG, 'kid_es256'))).toBe('alg_not_supported');
  });

  test('Ed25519 但声明了别的 alg → alg_not_supported', async () => {
    const { kid, publicJwk } = generateEd25519KeyPair();
    const cache = new JwksCache({
      load: async () => jwkSetOf({ ...publicJwk, alg: 'ES256' }),
    });
    expect(await codeOf(() => cache.getVerificationKey(CATALOG, kid))).toBe('alg_not_supported');
  });

  test('不支持的密钥不影响同一 JWKS 内可用的密钥', async () => {
    const usable = generateEd25519KeyPair();
    const cache = new JwksCache({
      load: async () => jwkSetOf({ kty: 'RSA', kid: 'kid_rsa', n: 'x', e: 'AQAB' }, usable.publicJwk),
    });
    expect(await codeOf(() => cache.getVerificationKey(CATALOG, 'kid_rsa'))).toBe('alg_not_supported');
    expect((await cache.getVerificationKey(CATALOG, usable.kid)).x).toBe(usable.publicJwk.x);
  });
});

describe('JwksCache · 文档本身不合法', () => {
  test('缺 keys 数组 / 无 kid 的密钥 / kid 重复 → jwks_malformed', async () => {
    const { publicJwk } = generateEd25519KeyPair();
    const noKeys = new JwksCache({ load: async () => ({ jwks: [] }) });
    expect(await codeOf(() => noKeys.getVerificationKey(CATALOG, 'k'))).toBe('jwks_malformed');

    const noKid = new JwksCache({
      load: async () => jwkSetOf({ kty: 'OKP', crv: 'Ed25519', x: publicJwk.x }),
    });
    expect(await codeOf(() => noKid.getVerificationKey(CATALOG, 'k'))).toBe('jwks_malformed');

    const dupKid = new JwksCache({
      load: async () => jwkSetOf({ ...publicJwk, kid: 'same' }, { ...publicJwk, kid: 'same' }),
    });
    expect(await codeOf(() => dupKid.getVerificationKey(CATALOG, 'same'))).toBe('jwks_malformed');
  });

  test('文档不合法不会被当成过期而落回缓存', async () => {
    const { kid, publicJwk } = generateEd25519KeyPair();
    const time = clock();
    let loads = 0;
    const cache = new JwksCache({
      now: time.now,
      ttlMs: 60_000,
      load: async () => {
        loads += 1;
        return loads === 1 ? jwkSetOf(publicJwk) : { keys: 'not an array' };
      },
    });

    await cache.getVerificationKey(CATALOG, kid);
    time.advance(60_001);
    expect(await codeOf(() => cache.getVerificationKey(CATALOG, kid))).toBe('jwks_malformed');
  });
});

describe('createDiscoveryJwksLoader · catalog_id → jwks_url → JWKS', () => {
  test('顺着 discovery 的 jwks_url 取到密钥', async () => {
    const { kid, publicJwk } = generateEd25519KeyPair();
    const fetched: string[] = [];
    const loader = createDiscoveryJwksLoader({
      wellKnownUrl: (catalogId) => `https://${catalogId}.example.com/.well-known/ocp-catalog`,
      fetchJson: async (url) => {
        fetched.push(url);
        if (url.endsWith('/.well-known/ocp-catalog')) {
          return {
            ocp_version: '1.0',
            kind: 'WellKnownCatalogDiscovery',
            catalog_id: CATALOG,
            manifest_url: `https://${CATALOG}.example.com/ocp/manifest`,
            jwks_url: `https://${CATALOG}.example.com/.well-known/jwks.json`,
          };
        }
        return jwkSetOf(publicJwk);
      },
    });

    const cache = new JwksCache({ load: loader });
    expect((await cache.getVerificationKey(CATALOG, kid)).x).toBe(publicJwk.x);
    expect(fetched).toEqual([
      `https://${CATALOG}.example.com/.well-known/ocp-catalog`,
      `https://${CATALOG}.example.com/.well-known/jwks.json`,
    ]);
  });

  test('discovery 里没有 jwks_url → jwks_unavailable', async () => {
    const loader = createDiscoveryJwksLoader({
      wellKnownUrl: () => 'https://example.com/.well-known/ocp-catalog',
      fetchJson: async () => ({ ocp_version: '1.0', kind: 'WellKnownCatalogDiscovery', catalog_id: CATALOG }),
    });
    const cache = new JwksCache({ load: loader });
    expect(await codeOf(() => cache.getVerificationKey(CATALOG, 'k'))).toBe('jwks_unavailable');
  });
});
