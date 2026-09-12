import { describe, expect, test } from 'bun:test';
import {
  catalogHealthResponseSchema,
  catalogManifestSchema,
  catalogQueryResultSchema,
  resolvableReferenceSchema,
  wellKnownCatalogDiscoverySchema,
} from '@ocp-catalog/ocp-schema';
import { handle } from './server';

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
    // This node does not sign anything yet, so it advertises no key set. A node
    // that issues attribution tokens must publish `jwks_url` or no merchant can
    // verify them.
    expect(parsed.jwks_url).toBe(undefined);
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
