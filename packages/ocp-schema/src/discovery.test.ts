import { describe, expect, test } from 'bun:test';
import { wellKnownCatalogDiscoverySchema } from './index';

/**
 * `GET /.well-known/ocp-catalog` had no schema until T2. These assertions exist
 * to pin down the two decisions that were easy to get wrong when adding one
 * late: the document must stay non-strict, and `jwks_url` must be optional.
 */

const minimal = {
  ocp_version: '1.0',
  kind: 'WellKnownCatalogDiscovery',
  catalog_id: 'cat_example',
  manifest_url: 'https://catalog.example.com/ocp/manifest',
};

describe('wellKnownCatalogDiscoverySchema', () => {
  test('最小文档通过：只要有 manifest_url 就是可发现的', () => {
    const parsed = wellKnownCatalogDiscoverySchema.parse(minimal);
    expect(parsed.catalog_id).toBe('cat_example');
    expect(parsed.jwks_url).toBe(undefined);
  });

  test('既有节点在实的 payload（example server 的九个字段）通过', () => {
    const parsed = wellKnownCatalogDiscoverySchema.parse({
      ...minimal,
      catalog_name: 'Example TypeScript Catalog',
      health_url: 'https://catalog.example.com/ocp/health',
      query_url: 'https://catalog.example.com/ocp/query',
      resolve_url: 'https://catalog.example.com/ocp/resolve',
      contracts_url: 'https://catalog.example.com/ocp/contracts',
    });
    expect(parsed.query_url).toBe('https://catalog.example.com/ocp/query');
  });

  test('jwks_url 可选，填了就必须是 URL', () => {
    const parsed = wellKnownCatalogDiscoverySchema.parse({
      ...minimal,
      jwks_url: 'https://catalog.example.com/.well-known/jwks.json',
    });
    expect(parsed.jwks_url).toBe('https://catalog.example.com/.well-known/jwks.json');
    expect(wellKnownCatalogDiscoverySchema.safeParse({ ...minimal, jwks_url: 'not-a-url' }).success).toBe(false);
  });

  test('不是 strict：未知字段不导致既有节点的响应被拒', () => {
    // The document is already served in production by nodes this repo does not
    // control. Rejecting unknown keys here would break them at schema-add time.
    expect(wellKnownCatalogDiscoverySchema.safeParse({ ...minimal, vendor_extension: true }).success).toBe(true);
  });

  test('kind / ocp_version / catalog_id / manifest_url 缺一不可', () => {
    for (const key of ['ocp_version', 'kind', 'catalog_id', 'manifest_url'] as const) {
      const payload: Record<string, unknown> = { ...minimal };
      delete payload[key];
      expect(`${key}:${wellKnownCatalogDiscoverySchema.safeParse(payload).success}`).toBe(`${key}:false`);
    }
  });

  test('kind 写错 → 拒绝（回报通道会同时收到多种 OCP 对象）', () => {
    expect(wellKnownCatalogDiscoverySchema.safeParse({ ...minimal, kind: 'CatalogManifest' }).success).toBe(false);
  });

  test('manifest_url 必须是 URL，不是任意字符串', () => {
    expect(wellKnownCatalogDiscoverySchema.safeParse({ ...minimal, manifest_url: '/ocp/manifest' }).success).toBe(
      false,
    );
  });
});
