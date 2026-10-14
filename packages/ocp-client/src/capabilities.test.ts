import { describe, expect, test } from 'bun:test';
import { catalogManifestSchema, type CatalogManifest } from '@ocp-catalog/ocp-schema';
import {
  catalogCapabilityProfileSchema,
  deriveCatalogCapabilityProfile,
} from './capabilities';

function manifest(overrides: Partial<CatalogManifest> = {}): CatalogManifest {
  return {
    ocp_version: '1.0',
    kind: 'CatalogManifest',
    id: 'manifest_test',
    catalog_id: 'catalog_test',
    catalog_name: 'Test Catalog',
    endpoints: {
      query: { url: 'https://catalog.example.test/query', method: 'POST' },
      resolve: { url: 'https://catalog.example.test/resolve', method: 'POST' },
    },
    query_capabilities: [{
      capability_id: 'commerce.search',
      query_packs: [{
        pack_id: 'product-search',
        query_modes: ['hybrid', 'keyword', 'hybrid'],
        metadata: {},
      }],
      searchable_field_refs: ['ocp.commerce.product.core.v1#/title'],
      filterable_field_refs: ['ocp.commerce.product.core.v1#/brand'],
      sortable_field_refs: ['ocp.commerce.product.core.v1#/price'],
      input_fields: [{ name: 'filters.brand', type: 'string' }],
      supports_explain: true,
      supports_resolve: true,
      metadata: {},
    }],
    object_contracts: [{
      required_fields: ['ocp.commerce.product.core.v1#/title'],
      optional_fields: ['ocp.commerce.product.core.v1#/brand'],
      additional_fields_policy: 'allow',
    }],
    ...overrides,
  };
}

describe('CatalogCapabilityProfile', () => {
  test('derives a schema-valid profile with stable, deduplicated collections', () => {
    const profile = deriveCatalogCapabilityProfile(manifest());

    expect(catalogCapabilityProfileSchema.safeParse(profile).success).toBe(true);
    expect(profile.protocol_versions).toEqual(['1.0']);
    expect(profile.query_packs[0]).toMatchObject({
      id: 'product-search',
      modes: ['hybrid', 'keyword'],
      filterable_fields: ['brand', 'ocp.commerce.product.core.v1#/brand'],
    });
    expect(profile.resolve.supported).toBe(true);
    expect(profile.trust.manifest_signed).toBe(false);
    expect(profile.source_refs).toContainEqual({ path: 'catalog_id' });
  });

  test('uses the signature envelope as signing evidence, not the declaration', () => {
    const unsigned = manifest({
      federation: {
        trust_strategy: {
          trust_tier: 'trusted',
          domain_verified: true,
          manifest_signed: true,
          signature_algorithms: ['EdDSA'],
          downgrade_invalidates_cache: true,
        },
      },
    });

    expect(deriveCatalogCapabilityProfile(unsigned).trust).toMatchObject({
      manifest_signed: false,
      declared_manifest_signed: true,
      trust_tier: 'trusted',
    });
  });

  test('does not mutate the manifest and is independent of query mode order', () => {
    const input = manifest();
    const before = structuredClone(input);
    const reordered = manifest({
      query_capabilities: [{
        ...input.query_capabilities[0],
        query_packs: [{
          ...input.query_capabilities[0].query_packs[0],
          query_modes: ['keyword', 'hybrid'],
        }],
      }],
    });

    expect(deriveCatalogCapabilityProfile(input)).toEqual(deriveCatalogCapabilityProfile(reordered));
    expect(input).toEqual(before);
  });

  test('rejects an invalid manifest before deriving a profile', () => {
    const invalid = { ...manifest(), catalog_id: '' };
    expect(() => deriveCatalogCapabilityProfile(invalid as CatalogManifest)).toThrow();
    expect(catalogManifestSchema.safeParse(invalid).success).toBe(false);
  });
});
