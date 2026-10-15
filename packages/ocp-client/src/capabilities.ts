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

const capabilityRequirementSchema = z.object({
  protocol_versions: z.array(z.string().min(1)).default([]),
  query_packs: z.array(z.string().min(1)).default([]),
  query_modes: z.array(z.string().min(1)).default([]),
  searchable_fields: z.array(z.string().min(1)).default([]),
  filterable_fields: z.array(z.string().min(1)).default([]),
  sortable_fields: z.array(z.string().min(1)).default([]),
  object_types: z.array(z.string().min(1)).default([]),
  resolve: z.boolean().optional(),
  sync_capabilities: z.array(z.string().min(1)).default([]),
}).strict();

export const catalogCapabilityRequirementsSchema = z.object({
  required: capabilityRequirementSchema.default({}),
  preferred: capabilityRequirementSchema.default({}),
}).strict();

const capabilityMatchItemSchema = z.object({
  requirement: z.string().min(1),
  source_refs: z.array(sourceRefSchema),
}).strict();

export const catalogCapabilityMatchResultSchema = z.object({
  profile_version: z.literal('v1'),
  catalog_id: z.string().min(1),
  eligible: z.boolean(),
  score: z.number().int().min(0).max(100),
  matched: z.array(capabilityMatchItemSchema),
  missing: z.array(capabilityMatchItemSchema),
  warnings: z.array(z.string().min(1)),
  explanations: z.array(z.string().min(1)),
}).strict();

export type CatalogCapabilityRequirements = z.infer<typeof catalogCapabilityRequirementsSchema>;
export type CatalogCapabilityMatchResult = z.infer<typeof catalogCapabilityMatchResultSchema>;

export function matchCatalogCapabilityProfile(
  profile: CatalogCapabilityProfile,
  requirements: CatalogCapabilityRequirements,
): CatalogCapabilityMatchResult {
  const requested = catalogCapabilityRequirementsSchema.parse(requirements);
  const matched: CatalogCapabilityMatchResult['matched'] = [];
  const missing: CatalogCapabilityMatchResult['missing'] = [];
  const warnings: string[] = [];
  const explanations: string[] = [];

  const addResult = (collection: CatalogCapabilityMatchResult['matched'] | CatalogCapabilityMatchResult['missing'], item: { requirement: string; source_refs: ProfileSourceRef[] }) => {
    collection.push(item);
  };
  const addWarning = (item: { requirement: string; source_refs: ProfileSourceRef[] }) => {
    warnings.push(item.requirement);
  };

  const packById = new Map(profile.query_packs.map((pack) => [pack.id, pack]));
  const packsFor = (ids: string[], required: boolean) => {
    ids.forEach((id) => {
      const pack = packById.get(id);
      const item = { requirement: `query_pack:${id}`, source_refs: pack?.source_refs ?? [] };
      if (pack) addResult(matched, item);
      else if (required) addResult(missing, item);
      else addWarning(item);
      if (pack) explanations.push(`Supports the requested query pack ${id}.`);
      else explanations.push(`Does not declare the requested query pack ${id}.`);
    });
  };
  packsFor(requested.required.query_packs, true);
  packsFor(requested.preferred.query_packs, false);

  const modes = new Set(profile.query_packs.flatMap((pack) => pack.modes));
  const fields = (key: 'searchable_fields' | 'filterable_fields' | 'sortable_fields', label: string) => {
    const available = new Set(profile.query_packs.flatMap((pack) => pack[key]));
    const check = (values: string[], required: boolean) => values.forEach((value) => {
      const item = { requirement: `${label}:${value}`, source_refs: profile.query_packs.flatMap((pack) => (
        pack[key].includes(value) ? pack.source_refs : []
      )) };
      if (available.has(value)) addResult(matched, item);
      else if (required) addResult(missing, item);
      else addWarning(item);
      explanations.push(available.has(value)
        ? `Supports ${label} field ${value}.`
        : `Does not declare ${label} field ${value}.`);
    });
    check(requested.required[key], true);
    check(requested.preferred[key], false);
  };
  fields('searchable_fields', 'searchable_field');
  fields('filterable_fields', 'filterable_field');
  fields('sortable_fields', 'sortable_field');

  const checkModes = (values: string[], required: boolean) => values.forEach((mode) => {
    const item = { requirement: `query_mode:${mode}`, source_refs: profile.query_packs.flatMap((pack) => (
      pack.modes.includes(mode) ? pack.source_refs : []
    )) };
    if (modes.has(mode)) addResult(matched, item);
    else if (required) addResult(missing, item);
    else addWarning(item);
    explanations.push(modes.has(mode)
      ? `Supports the requested query mode ${mode}.`
      : `Does not declare the requested query mode ${mode}.`);
  });
  checkModes(requested.required.query_modes, true);
  checkModes(requested.preferred.query_modes, false);

  const resolveRequired = requested.required.resolve === true;
  if (requested.required.resolve !== undefined || requested.preferred.resolve !== undefined) {
    const resolveItem = { requirement: 'resolve', source_refs: profile.resolve.source_refs };
    if (profile.resolve.supported) matched.push(resolveItem);
    else if (resolveRequired) missing.push(resolveItem);
    else addWarning(resolveItem);
    explanations.push(profile.resolve.supported ? 'Supports resolve.' : 'Does not declare resolve support.');
  }

  const syncIds = new Set(profile.sync_capabilities.map((capability) => capability.id));
  const checkSync = (values: string[], required: boolean) => values.forEach((id) => {
    const source_refs = profile.sync_capabilities.filter((capability) => capability.id === id).flatMap((capability) => capability.source_refs);
    const item = { requirement: `sync_capability:${id}`, source_refs };
    if (syncIds.has(id)) addResult(matched, item);
    else if (required) addResult(missing, item);
    else addWarning(item);
    explanations.push(syncIds.has(id) ? `Supports sync capability ${id}.` : `Does not declare sync capability ${id}.`);
  });
  checkSync(requested.required.sync_capabilities, true);
  checkSync(requested.preferred.sync_capabilities, false);

  const requiredCount = requested.required.query_packs.length
    + requested.required.query_modes.length
    + requested.required.searchable_fields.length
    + requested.required.filterable_fields.length
    + requested.required.sortable_fields.length
    + (requested.required.resolve === undefined ? 0 : 1)
    + requested.required.sync_capabilities.length;
  const matchedRequiredCount = matched.filter((item) => (
    item.requirement.startsWith('query_pack:') && requested.required.query_packs.includes(item.requirement.slice('query_pack:'.length))
      || item.requirement.startsWith('query_mode:') && requested.required.query_modes.includes(item.requirement.slice('query_mode:'.length))
      || item.requirement.startsWith('searchable_field:') && requested.required.searchable_fields.includes(item.requirement.slice('searchable_field:'.length))
      || item.requirement.startsWith('filterable_field:') && requested.required.filterable_fields.includes(item.requirement.slice('filterable_field:'.length))
      || item.requirement.startsWith('sortable_field:') && requested.required.sortable_fields.includes(item.requirement.slice('sortable_field:'.length))
      || item.requirement === 'resolve' && requested.required.resolve !== undefined
      || item.requirement.startsWith('sync_capability:') && requested.required.sync_capabilities.includes(item.requirement.slice('sync_capability:'.length))
  )).length;
  const preferredCount = requested.preferred.query_packs.length
    + requested.preferred.query_modes.length
    + requested.preferred.searchable_fields.length
    + requested.preferred.filterable_fields.length
    + requested.preferred.sortable_fields.length
    + (requested.preferred.resolve === undefined ? 0 : 1)
    + requested.preferred.sync_capabilities.length;
  const matchedPreferredCount = matched.length - matchedRequiredCount;
  const score = requiredCount === 0 && preferredCount === 0
    ? 100
    : Math.round(((matchedRequiredCount + matchedPreferredCount) / (requiredCount + preferredCount)) * 100);

  return catalogCapabilityMatchResultSchema.parse({
    profile_version: profile.profile_version,
    catalog_id: profile.catalog_id,
    eligible: missing.length === 0,
    score,
    matched: matched.sort((left, right) => left.requirement.localeCompare(right.requirement)),
    missing: missing.sort((left, right) => left.requirement.localeCompare(right.requirement)),
    warnings: [...new Set(warnings)].sort(),
    explanations: [...new Set(explanations)].sort(),
  });
}

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
