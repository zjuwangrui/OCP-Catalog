import {
  catalogManifestSchema,
  type CatalogManifest,
} from '@ocp-catalog/ocp-schema';
import { z } from 'zod';

const sourceRefSchema = z.object({
  path: z.string().min(1),
}).strict();

const queryPackProfileSchema = z.object({
  id: z.string().min(1),
  modes: z.array(z.string().min(1)),
  searchable_fields: z.array(z.string().min(1)),
  filterable_fields: z.array(z.string().min(1)),
  sortable_fields: z.array(z.string().min(1)),
  supports_explain: z.boolean(),
  supports_resolve: z.boolean(),
  source_refs: z.array(sourceRefSchema).min(1),
}).strict();

const objectContractProfileSchema = z.object({
  index: z.number().int().nonnegative(),
  required_fields: z.array(z.union([
    z.string().min(1),
    z.array(z.string().min(1)).min(1),
  ])),
  optional_fields: z.array(z.string().min(1)),
  additional_fields_policy: z.enum(['allow', 'ignore', 'reject']),
  source_refs: z.array(sourceRefSchema).min(1),
}).strict();

const syncCapabilityProfileSchema = z.object({
  id: z.string().min(1),
  direction: z.string().min(1),
  transport: z.string().min(1),
  source_refs: z.array(sourceRefSchema).min(1),
}).strict();

export const catalogCapabilityProfileSchema = z.object({
  profile_version: z.literal('v1'),
  catalog_id: z.string().min(1),
  catalog_name: z.string().min(1),
  protocol_versions: z.array(z.string().min(1)),
  query_packs: z.array(queryPackProfileSchema),
  object_contracts: z.array(objectContractProfileSchema),
  resolve: z.object({
    supported: z.boolean(),
    source_refs: z.array(sourceRefSchema).min(1),
  }).strict(),
  sync_capabilities: z.array(syncCapabilityProfileSchema),
  trust: z.object({
    manifest_signed: z.boolean(),
    declared_manifest_signed: z.boolean().optional(),
    trust_tier: z.string().min(1).optional(),
    source_refs: z.array(sourceRefSchema).min(1),
  }).strict(),
  source_refs: z.array(sourceRefSchema).min(1),
}).strict();

export type ProfileSourceRef = z.infer<typeof sourceRefSchema>;
export type CatalogCapabilityProfile = z.infer<typeof catalogCapabilityProfileSchema>;

const sortStrings = (values: string[]) => [...new Set(values)].sort((a, b) => a.localeCompare(b));

const sortRefs = (refs: ProfileSourceRef[]) => {
  const unique = new Map(refs.map((ref) => [ref.path, ref]));
  return [...unique.values()].sort((a, b) => a.path.localeCompare(b.path));
};

const ref = (path: string): ProfileSourceRef => ({ path });

function fieldNamesFromInputFields(inputFields: Array<Record<string, unknown>>): string[] {
  return inputFields.flatMap((field) => {
    const name = field.name;
    return typeof name === 'string' && name.startsWith('filters.')
      ? [name.slice('filters.'.length)]
      : [];
  });
}

function mergeQueryPacks(manifest: CatalogManifest) {
  const packs = new Map<string, {
    modes: string[];
    searchable_fields: string[];
    filterable_fields: string[];
    sortable_fields: string[];
    supports_explain: boolean;
    supports_resolve: boolean;
    source_refs: ProfileSourceRef[];
  }>();

  manifest.query_capabilities.forEach((capability, capabilityIndex) => {
    capability.query_packs.forEach((pack, packIndex) => {
      const path = `query_capabilities[${capabilityIndex}].query_packs[${packIndex}]`;
      const current = packs.get(pack.pack_id) ?? {
        modes: [],
        searchable_fields: [],
        filterable_fields: [],
        sortable_fields: [],
        supports_explain: false,
        supports_resolve: false,
        source_refs: [],
      };
      current.modes.push(...pack.query_modes);
      current.searchable_fields.push(...capability.searchable_field_refs);
      current.filterable_fields.push(
        ...capability.filterable_field_refs,
        ...fieldNamesFromInputFields(capability.input_fields),
      );
      current.sortable_fields.push(...capability.sortable_field_refs);
      current.supports_explain ||= capability.supports_explain;
      current.supports_resolve ||= capability.supports_resolve;
      current.source_refs.push(ref(path));
      packs.set(pack.pack_id, current);
    });
  });

  return [...packs.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([id, value]) => ({
      id,
      modes: sortStrings(value.modes),
      searchable_fields: sortStrings(value.searchable_fields),
      filterable_fields: sortStrings(value.filterable_fields),
      sortable_fields: sortStrings(value.sortable_fields),
      supports_explain: value.supports_explain,
      supports_resolve: value.supports_resolve,
      source_refs: sortRefs(value.source_refs),
    }));
}

export function deriveCatalogCapabilityProfile(manifest: CatalogManifest): CatalogCapabilityProfile {
  const parsed = catalogManifestSchema.parse(manifest);
  const queryPacks = mergeQueryPacks(parsed);
  const objectContracts = parsed.object_contracts.map((contract, index) => ({
    index,
    required_fields: contract.required_fields.map((requirement) => (
      Array.isArray(requirement) ? sortStrings(requirement) : requirement
    )),
    optional_fields: sortStrings(contract.optional_fields),
    additional_fields_policy: contract.additional_fields_policy,
    source_refs: [ref(`object_contracts[${index}]`)],
  }));
  const syncCapabilities = (parsed.provider_contract?.sync_capabilities ?? []).map((capability, index) => ({
    id: capability.capability_id,
    direction: capability.direction,
    transport: capability.transport,
    source_refs: [ref(`provider_contract.sync_capabilities[${index}]`)],
  }));
  const resolveRefs = [ref('endpoints.resolve')];
  parsed.query_capabilities.forEach((capability, index) => {
    if (capability.supports_resolve) resolveRefs.push(ref(`query_capabilities[${index}].supports_resolve`));
  });
  const trustRefs = [ref('signature')];
  if (parsed.federation) trustRefs.push(ref('federation.trust_strategy'));

  const trust = {
    manifest_signed: parsed.signature !== undefined,
    ...(parsed.federation?.trust_strategy.manifest_signed === undefined
      ? {}
      : { declared_manifest_signed: parsed.federation.trust_strategy.manifest_signed }),
    ...(parsed.federation?.trust_strategy.trust_tier === undefined
      ? {}
      : { trust_tier: parsed.federation.trust_strategy.trust_tier }),
    source_refs: sortRefs(trustRefs),
  };

  return catalogCapabilityProfileSchema.parse({
    profile_version: 'v1',
    catalog_id: parsed.catalog_id,
    catalog_name: parsed.catalog_name,
    protocol_versions: [parsed.ocp_version],
    query_packs: queryPacks,
    object_contracts: objectContracts,
    resolve: {
      supported: parsed.query_capabilities.some((capability) => capability.supports_resolve),
      source_refs: sortRefs(resolveRefs),
    },
    sync_capabilities: syncCapabilities.sort((left, right) => (
      left.id.localeCompare(right.id) || left.direction.localeCompare(right.direction) || left.transport.localeCompare(right.transport)
    )),
    trust,
    source_refs: sortRefs([
      ref('ocp_version'),
      ref('catalog_id'),
      ref('catalog_name'),
      ...queryPacks.flatMap((pack) => pack.source_refs),
      ...objectContracts.flatMap((contract) => contract.source_refs),
      ...syncCapabilities.flatMap((capability) => capability.source_refs),
    ]),
  });
}
