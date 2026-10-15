import { describe, expect, test } from 'bun:test';
import {
  catalogCapabilityMatchResultSchema,
  deriveCatalogCapabilityProfile,
  matchCatalogCapabilityProfile,
  type CatalogCapabilityProfile,
} from './capabilities';

const profile: CatalogCapabilityProfile = deriveCatalogCapabilityProfile({
  ocp_version: '1.0',
  kind: 'CatalogManifest',
  id: 'manifest_match',
  catalog_id: 'catalog_match',
  catalog_name: 'Match Catalog',
  endpoints: {
    query: { url: 'https://catalog.example.test/query', method: 'POST' },
    resolve: { url: 'https://catalog.example.test/resolve', method: 'POST' },
  },
  query_capabilities: [{
    capability_id: 'commerce.search',
    query_packs: [{ pack_id: 'product-search', query_modes: ['filter'], metadata: {} }],
    filterable_field_refs: ['ocp.commerce.product.core.v1#/brand'],
    input_fields: [],
    supports_explain: true,
    supports_resolve: true,
    metadata: {},
  }],
  object_contracts: [],
});

describe('CatalogCapabilityProfile matching', () => {
  test('marks required capabilities eligible and explains matches', () => {
    const result = matchCatalogCapabilityProfile(profile, {
      required: {
        query_packs: ['product-search'],
        query_modes: ['filter'],
        filterable_fields: ['ocp.commerce.product.core.v1#/brand'],
        resolve: true,
      },
      preferred: { query_modes: ['keyword'] },
    });

    expect(result.eligible).toBe(true);
    expect(result.score).toBe(80);
    expect(result.missing).toEqual([]);
    expect(result.warnings).toEqual(['query_mode:keyword']);
    expect(result.explanations).toContain('Supports the requested query pack product-search.');
    expect(catalogCapabilityMatchResultSchema.safeParse(result).success).toBe(true);
  });

  test('makes required gaps ineligible while treating preferred gaps as warnings', () => {
    const result = matchCatalogCapabilityProfile(profile, {
      required: { query_packs: ['missing-pack'], filterable_fields: ['brand'] },
      preferred: { sync_capabilities: ['stream'] },
    });

    expect(result.eligible).toBe(false);
    expect(result.score).toBe(0);
    expect(result.missing.map((item) => item.requirement)).toEqual([
      'filterable_field:brand',
      'query_pack:missing-pack',
    ]);
    expect(result.warnings).toEqual(['sync_capability:stream']);
  });

  test('is deterministic for repeated calls', () => {
    const requirements = { required: {}, preferred: { query_packs: ['product-search'] } };
    expect(matchCatalogCapabilityProfile(profile, requirements)).toEqual(
      matchCatalogCapabilityProfile(profile, requirements),
    );
  });
});
