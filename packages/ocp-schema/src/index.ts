import { z } from 'zod';

export const ocpVersionSchema = z.literal('1.0');
export const requirementLevelSchema = z.enum(['required', 'optional', 'accepted']);
export const registrationStatusSchema = z.enum([
  'accepted_full',
  'accepted_limited',
  'rejected',
  'pending_verification',
]);

export const endpointSchema = z.object({
  url: z.string().url(),
  method: z.enum(['GET', 'POST', 'PUT']),
});

export const catalogHealthStatusSchema = z.enum(['healthy', 'degraded', 'unhealthy']);

export const catalogHealthDependencySchema = z.object({
  name: z.string().min(1),
  status: catalogHealthStatusSchema,
  latency_ms: z.number().nonnegative().optional(),
  message: z.string().optional(),
}).strict();

export const catalogHealthResponseSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('CatalogHealth'),
  catalog_id: z.string().min(1),
  status: catalogHealthStatusSchema,
  ready: z.boolean(),
  checked_at: z.string().datetime(),
  manifest_version: z.string().optional(),
  details: z.record(z.string(), z.unknown()).default({}),
  dependencies: z.array(catalogHealthDependencySchema).default([]),
}).strict();

export const catalogQueryModeSchema = z.enum(['keyword', 'filter', 'semantic', 'hybrid']);
export const trustTierSchema = z.enum(['unknown', 'unverified', 'verified', 'trusted']);
export const authorityTypeSchema = z.enum([
  'provider_authoritative',
  'external_source',
  'imported_snapshot',
  'source_proxy',
]);
export const verificationStatusSchema = z.enum([
  'unknown',
  'unverified',
  'pending',
  'verified',
  'failed',
  'not_required',
]);
export const identityKeyTypeSchema = z.enum([
  'provider_object_id',
  'provider_sku',
  'external_source_key',
  'canonical_url',
  'content_hash',
]);
export const syncCapabilityDirectionSchema = z.enum([
  'provider_to_catalog',
  'catalog_pull_provider',
  'provider_stream_to_catalog',
]);

export const fieldRefSchema = z.string().regex(/^[a-z0-9][a-z0-9._-]*#\/[A-Za-z0-9_.~/-]+$/);

export const fieldRuleSchema = z.object({
  field_ref: z.string().min(1),
  requirement: requirementLevelSchema,
  usage: z
    .array(z.enum([
      'identity',
      'index',
      'filter',
      'rank',
      'display',
      'resolve',
      'reference',
      'explain',
      'search_visible',
      'resolve_visible',
      'never_expose',
    ]))
    .default([]),
  accepted_aliases: z.array(z.string().min(1)).optional(),
  note: z.string().optional(),
});

export const fieldRequirementSchema = z.union([
  fieldRefSchema,
  z.array(fieldRefSchema).min(1),
]);

export const objectContractSchema = z.object({
  required_fields: z.array(fieldRequirementSchema).min(1),
  optional_fields: z.array(fieldRefSchema).default([]),
  additional_fields_policy: z.enum(['allow', 'ignore', 'reject']).default('allow'),
  field_usage_policy: z.array(fieldRuleSchema).optional(),
  identity_policy: z.object({
    accepted_identity_keys: z.array(identityKeyTypeSchema).min(1),
    dedupe_scope: z.enum(['provider', 'source', 'catalog']).default('provider'),
    provider_sku_trust: z.enum(['not_accepted', 'accepted_as_claim', 'requires_verified_provider']).default('accepted_as_claim'),
    requires_authority_verification: z.boolean().default(false),
  }).strict().optional(),
  resolve_policy: z.object({
    strategies: z.array(z.enum(['provider_api', 'source_url', 'catalog_cached', 'unavailable'])).min(1),
    requires_live_check: z.boolean().default(false),
    provider_endpoint_required: z.boolean().default(false),
    minimum_trust_tier: trustTierSchema.optional(),
  }).strict().optional(),
  provenance_requirements: z.object({
    accepted_authority_types: z.array(authorityTypeSchema).default([]),
    requires_verification: z.boolean().default(false),
    minimum_trust_tier: trustTierSchema.optional(),
  }).strict().optional(),
});

export const syncModelSchema = z.object({
  snapshot: z.boolean(),
  delta: z.boolean(),
  stream: z.boolean(),
});

export const mutationSemanticsSchema = z.object({
  upsert: z.boolean(),
  delete: z.boolean(),
});

export const providerEndpointSchema = z.object({
  url: z.string().url(),
}).catchall(z.unknown());

export const syncCapabilitySchema = z.object({
  capability_id: z.string().min(1),
  description: z.string().optional(),
  direction: syncCapabilityDirectionSchema,
  transport: z.string().min(1),
  sync_model: syncModelSchema,
  mutation_semantics: mutationSemanticsSchema,
  batching: z.object({
    enabled: z.boolean(),
    max_items: z.number().int().min(1).optional(),
    max_bytes: z.number().int().min(1).optional(),
  }).optional(),
  cursoring: z.object({
    enabled: z.boolean(),
  }).optional(),
  streaming: z.object({
    enabled: z.boolean(),
  }).optional(),
  auth: z.object({
    schemes: z.array(z.string().min(1)).default([]),
  }).optional(),
  endpoint_contract: z.object({
    hosted_by: z.enum(['catalog', 'provider']),
    path_hint: z.string().optional(),
    required_endpoint_fields: z.array(z.string().min(1)).default([]),
  }).optional(),
  metadata: z.record(z.string(), z.unknown()).default({}),
}).strict();

export const selectedSyncCapabilitySchema = z.object({
  capability_id: z.string().min(1),
  reason: z.string().min(1),
});

export const queryCapabilityMetadataSchema = z.record(z.string(), z.unknown()).default({});

export const queryPackDescriptorSchema = z.object({
  pack_id: z.string().min(1),
  description: z.string().optional(),
  query_modes: z.array(catalogQueryModeSchema).default([]),
  request_schema_uri: z.string().url().optional(),
  metadata: queryCapabilityMetadataSchema,
});

export const catalogQueryCapabilitySchema = z.object({
  capability_id: z.string().min(1),
  name: z.string().min(1).optional(),
  description: z.string().optional(),
  query_packs: z.array(queryPackDescriptorSchema).default([]),
  searchable_field_refs: z.array(fieldRefSchema).default([]),
  filterable_field_refs: z.array(fieldRefSchema).default([]),
  sortable_field_refs: z.array(fieldRefSchema).default([]),
  input_fields: z.array(z.record(z.string(), z.unknown())).default([]),
  supports_explain: z.boolean().default(true),
  supports_resolve: z.boolean().default(true),
  metadata: queryCapabilityMetadataSchema,
});

export const catalogDataProfileSchema = z.object({
  catalog_entry_count: z.number().int().min(0),
  object_counts: z.array(z.object({
    object_type: z.string().min(1),
    count: z.number().int().min(0),
  }).strict()).default([]),
  counted_at: z.string().datetime().optional(),
}).strict();

export const federationProfileSchema = z.object({
  mode: z.enum(['disabled', 'profile_only', 'summary_exchange', 'remote_routing']).default('disabled'),
  node_role: z.enum(['source_catalog', 'registration_node', 'federation_peer']).default('source_catalog'),
  peer_policy: z.object({
    accepts_peers: z.boolean().default(false),
    requires_verification: z.boolean().default(true),
    allowed_peer_ids: z.array(z.string().min(1)).default([]),
  }).default({
    accepts_peers: false,
    requires_verification: true,
    allowed_peer_ids: [],
  }),
  supported_protocols: z.array(z.string().min(1)).default([]),
  remote_query: z.object({
    supported: z.boolean().default(false),
    routing_modes: z.array(z.enum(['route_hint', 'summary_cache', 'live_forward'])).default([]),
    accepted_query_packs: z.array(z.string().min(1)).default([]),
    max_fanout: z.number().int().min(1).optional(),
    timeout_ms: z.number().int().min(1).optional(),
    requires_trust_tier: trustTierSchema.default('verified'),
    returns_authoritative_results: z.boolean().default(false),
  }).default({
    supported: false,
    routing_modes: [],
    accepted_query_packs: [],
    requires_trust_tier: 'verified',
    returns_authoritative_results: false,
  }),
  remote_resolve: z.object({
    supported: z.boolean().default(false),
    allowed_reference_types: z.array(z.string().min(1)).default(['commercial_object']),
    requires_live_check: z.boolean().default(true),
    cache_policy: z.enum(['no_cache', 'short_ttl', 'source_ttl']).default('source_ttl'),
    auth_context_required: z.boolean().default(true),
    requires_trust_tier: trustTierSchema.default('verified'),
  }).default({
    supported: false,
    allowed_reference_types: ['commercial_object'],
    requires_live_check: true,
    cache_policy: 'source_ttl',
    auth_context_required: true,
    requires_trust_tier: 'verified',
  }),
  summary_cache: z.object({
    supported: z.boolean().default(false),
    summary_types: z.array(z.enum(['profile', 'contract', 'availability', 'catalog_entry'])).default([]),
    ttl_seconds: z.number().int().min(1).optional(),
    includes_object_payloads: z.boolean().default(false),
  }).default({
    supported: false,
    summary_types: [],
    includes_object_payloads: false,
  }),
  mutation_log: z.object({
    supported: z.boolean().default(false),
    event_types: z.array(z.enum(['snapshot_created', 'entry_upserted', 'entry_deleted', 'trust_changed'])).default([]),
    cursor_required: z.boolean().default(true),
    includes_tombstones: z.boolean().default(true),
  }).default({
    supported: false,
    event_types: [],
    cursor_required: true,
    includes_tombstones: true,
  }),
  trust_strategy: z.object({
    trust_tier: trustTierSchema.default('unknown'),
    domain_verified: z.boolean().default(false),
    manifest_signed: z.boolean().default(false),
    signature_algorithms: z.array(z.string().min(1)).default([]),
    downgrade_invalidates_cache: z.boolean().default(true),
  }).default({
    trust_tier: 'unknown',
    domain_verified: false,
    manifest_signed: false,
    signature_algorithms: [],
    downgrade_invalidates_cache: true,
  }),
}).default({
  mode: 'disabled',
  node_role: 'source_catalog',
  peer_policy: {
    accepts_peers: false,
    requires_verification: true,
    allowed_peer_ids: [],
  },
  supported_protocols: [],
  remote_query: {
    supported: false,
    routing_modes: [],
    accepted_query_packs: [],
    requires_trust_tier: 'verified',
    returns_authoritative_results: false,
  },
  remote_resolve: {
    supported: false,
    allowed_reference_types: ['commercial_object'],
    requires_live_check: true,
    cache_policy: 'source_ttl',
    auth_context_required: true,
    requires_trust_tier: 'verified',
  },
  summary_cache: {
    supported: false,
    summary_types: [],
    includes_object_payloads: false,
  },
  mutation_log: {
    supported: false,
    event_types: [],
    cursor_required: true,
    includes_tombstones: true,
  },
  trust_strategy: {
    trust_tier: 'unknown',
    domain_verified: false,
    manifest_signed: false,
    signature_algorithms: [],
    downgrade_invalidates_cache: true,
  },
});

export const catalogManifestSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('CatalogManifest'),
  id: z.string().min(1),
  catalog_id: z.string().min(1),
  catalog_name: z.string().min(1),
  description: z.string().optional(),
  registry_visibility: z.enum(['public', 'partner', 'private']).default('public'),
  endpoints: z.object({
    health: endpointSchema.optional(),
    query: endpointSchema,
    resolve: endpointSchema,
    provider_registration: endpointSchema.optional(),
    contracts: endpointSchema.optional(),
    object_sync: endpointSchema.optional(),
    object_sync_stream: endpointSchema.optional(),
    object_sync_run: endpointSchema.optional(),
    object_sync_run_complete: endpointSchema.optional(),
  }),
  query_capabilities: z.array(catalogQueryCapabilitySchema).min(1),
  data_profile: catalogDataProfileSchema.optional(),
  provider_contract: z.object({
    field_rules: z.array(fieldRuleSchema),
    sync_capabilities: z.array(syncCapabilitySchema).default([]),
  }).optional(),
  object_contracts: z.array(objectContractSchema),
  federation: federationProfileSchema.optional(),
});

export const providerRegistrationSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('ProviderRegistration'),
  id: z.string().min(1),
  catalog_id: z.string().min(1),
  registration_version: z.number().int().min(1),
  updated_at: z.string().datetime(),
  provider: z.object({
    provider_id: z.string().min(1),
    entity_type: z.enum(['merchant', 'organization', 'individual', 'platform', 'other']),
    display_name: z.string().min(1),
    homepage: z.string().url(),
    contact_email: z.string().email().optional(),
    domains: z.array(z.string().min(1)).optional(),
  }).passthrough(),
  object_declarations: z.array(z.object({
    guaranteed_fields: z.array(z.string().min(1)),
    optional_fields: z.array(z.string().min(1)).optional(),
    sync: z.object({
      preferred_capabilities: z.array(z.string().min(1)).default([]),
      avoid_capabilities_unless_necessary: z.array(z.string().min(1)).default([]),
      provider_endpoints: z.record(z.string(), providerEndpointSchema).default({}),
    }).superRefine((value, ctx) => {
      if (value.preferred_capabilities.length === 0 && value.avoid_capabilities_unless_necessary.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'At least one sync capability must be declared.',
        });
      }
    }),
  })).min(1),
});

export const commercialObjectSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('CommercialObject'),
  id: z.string().min(1),
  object_id: z.string().min(1),
  object_type: z.string().min(1),
  provider_id: z.string().min(1),
  title: z.string().min(1),
  summary: z.string().optional(),
  status: z.enum(['active', 'inactive', 'draft']).default('active'),
  source_url: z.string().url().optional(),
  provenance: z.object({
    authority_type: authorityTypeSchema,
    provider_id: z.string().min(1).optional(),
    source: z.string().min(1).optional(),
    source_site: z.string().min(1).optional(),
    source_uri: z.string().url().optional(),
    source_object_id: z.string().min(1).optional(),
    source_variant_id: z.string().min(1).optional(),
    collected_at: z.string().datetime().optional(),
    verified_at: z.string().datetime().optional(),
    verification_status: verificationStatusSchema.optional(),
    trust_tier: trustTierSchema.optional(),
    evidence: z.record(z.string(), z.unknown()).optional(),
  }).strict().optional(),
  descriptors: z.array(z.object({
    pack_id: z.string().min(1),
    schema_uri: z.string().url().optional(),
    data: z.record(z.string(), z.unknown()),
  })).min(1).max(20),
});

export const registrationResultSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('RegistrationResult'),
  id: z.string().min(1),
  catalog_id: z.string().min(1),
  provider_id: z.string().optional(),
  status: registrationStatusSchema,
  matched_object_contract_count: z.number().int().min(0).default(0),
  effective_registration_version: z.number().int().min(1).optional(),
  selected_sync_capability: selectedSyncCapabilitySchema.optional(),
  missing_required_fields: z.array(z.string()).default([]),
  warnings: z.array(z.string()).default([]),
  provider_api_key: z.string().optional(),
  provider_api_key_issued_at: z.string().datetime().optional(),
  auth: z.record(z.string(), z.unknown()).optional(),
  message: z.string().optional(),
});

export const objectSyncRequestSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('ObjectSyncRequest').default('ObjectSyncRequest'),
  id: z.string().min(1).optional(),
  catalog_id: z.string().min(1),
  provider_id: z.string().min(1),
  registration_version: z.number().int().min(1),
  batch_id: z.string().min(1).optional(),
  objects: z.array(z.unknown()).min(1).max(1000),
});

export const objectSyncItemResultSchema = z.object({
  object_id: z.string().optional(),
  status: z.enum(['accepted', 'rejected']),
  commercial_object_id: z.string().optional(),
  catalog_entry_id: z.string().optional(),
  errors: z.array(z.string()).default([]),
  warnings: z.array(z.string()).default([]),
});

export const objectSyncResultSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('ObjectSyncResult'),
  id: z.string().min(1),
  catalog_id: z.string().min(1),
  provider_id: z.string().min(1),
  registration_version: z.number().int().min(1),
  batch_id: z.string().min(1),
  status: z.enum(['accepted', 'partial', 'rejected']),
  accepted_count: z.number().int().min(0),
  rejected_count: z.number().int().min(0),
  error_count: z.number().int().min(0),
  items: z.array(objectSyncItemResultSchema),
});

export const objectSyncStreamChunkResultSchema = z.object({
  batch_id: z.string().min(1),
  chunk_ordinal: z.number().int().min(0).nullable().optional(),
  status: z.enum(['accepted', 'partial', 'rejected']),
  accepted_count: z.number().int().min(0),
  rejected_count: z.number().int().min(0),
});

export const objectSyncRunStatusSchema = z.enum(['running', 'accepted', 'partial', 'rejected', 'failed']);

export const objectSyncRunCheckpointSchema = z.object({
  committed_chunk_count: z.number().int().min(0),
  last_committed_chunk_ordinal: z.number().int().min(0).nullable(),
  chunks: z.array(z.object({
    batch_id: z.string().min(1),
    chunk_ordinal: z.number().int().min(0).nullable(),
    status: z.enum(['accepted', 'partial', 'rejected']),
    accepted_count: z.number().int().min(0),
    rejected_count: z.number().int().min(0),
    error_count: z.number().int().min(0),
    request_hash: z.string().min(1),
    finished_at: z.string().nullable(),
  })),
});

export const objectSyncStreamResultSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('ObjectSyncStreamResult'),
  catalog_id: z.string().min(1),
  provider_id: z.string().min(1),
  registration_version: z.number().int().min(1),
  sync_run_id: z.string().min(1),
  stream_batch_id: z.string().min(1),
  status: objectSyncRunStatusSchema,
  chunk_count: z.number().int().min(0),
  accepted_count: z.number().int().min(0),
  rejected_count: z.number().int().min(0),
  checkpoint: objectSyncRunCheckpointSchema,
  chunks: z.array(objectSyncStreamChunkResultSchema),
});

export const objectSyncRunSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('ObjectSyncRun'),
  catalog_id: z.string().min(1),
  provider_id: z.string().min(1),
  registration_version: z.number().int().min(1),
  sync_run_id: z.string().min(1),
  run_mode: z.enum(['batch', 'stream']),
  status: objectSyncRunStatusSchema,
  stream_batch_id: z.string().optional(),
  batch_count: z.number().int().min(0),
  accepted_count: z.number().int().min(0),
  rejected_count: z.number().int().min(0),
  error_count: z.number().int().min(0),
  checkpoint: objectSyncRunCheckpointSchema,
  result_summary: z.record(z.string(), z.unknown()),
  error: z.string().optional(),
  created_at: z.string(),
  updated_at: z.string(),
  finished_at: z.string().optional(),
});

export const catalogQueryFiltersSchema = z.object({
  category: z.string().min(1).optional(),
  brand: z.string().min(1).optional(),
  currency: z.string().min(1).optional(),
  availability_status: z.string().min(1).optional(),
  provider_id: z.string().min(1).optional(),
  sku: z.string().min(1).optional(),
  min_amount: z.number().nonnegative().optional(),
  max_amount: z.number().nonnegative().optional(),
  in_stock_only: z.boolean().optional(),
  has_image: z.boolean().optional(),
}).strict();

export const catalogQueryRequestSchema = z.object({
  ocp_version: ocpVersionSchema.optional(),
  kind: z.literal('CatalogQueryRequest').optional(),
  catalog_id: z.string().min(1).optional(),
  query_pack: z.string().min(1).optional(),
  query_mode: catalogQueryModeSchema.optional(),
  query: z.string().max(500).optional().default(''),
  filters: catalogQueryFiltersSchema.optional().default({}),
  limit: z.number().int().min(1).max(50).optional().default(20),
  offset: z.literal(0).optional().default(0),
  cursor: z.string().min(1).max(512).optional(),
  explain: z.boolean().optional().default(true),
}).strict();

export const catalogEntrySchema = z.object({
  kind: z.literal('CatalogEntry'),
  catalog_id: z.string().min(1),
  entry_id: z.string().min(1),
  provider_id: z.string().min(1),
  object_id: z.string().min(1),
  object_type: z.string().min(1).optional(),
  commercial_object_id: z.string().min(1).optional(),
  title: z.string().min(1),
  summary: z.string().optional(),
  image_url: z.string().url().optional(),
  attributes: z.record(z.string(), z.unknown()),
});

export const catalogEntryMatchSchema = z.object({
  entry: catalogEntrySchema,
  score: z.number(),
  explain: z.array(z.string()).default([]),
});

export const queryPolicySummarySchema = z.object({
  selected_capability_id: z.string().min(1).optional(),
  selected_query_pack: z.string().min(1).optional(),
  query_mode: catalogQueryModeSchema,
  supports_explain: z.boolean().default(true),
  accepted_filters: z.array(z.string()).default([]),
  rejected_filters: z.array(z.string()).default([]),
  warnings: z.array(z.string()).default([]),
});

export const catalogQueryResultSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('CatalogQueryResult'),
  id: z.string(),
  catalog_id: z.string(),
  query_pack: z.string().optional(),
  query_mode: catalogQueryModeSchema.optional(),
  query: z.string(),
  result_count: z.number().int().min(0),
  page: z.object({
    limit: z.number().int().min(1),
    offset: z.literal(0),
    has_more: z.boolean(),
    next_cursor: z.string().min(1).optional(),
  }),
  entries: z.array(catalogEntryMatchSchema),
  policy_summary: queryPolicySummarySchema.optional(),
  audit_id: z.string().min(1).optional(),
  explain: z.array(z.string()).default([]),
});

export const agentIdentitySourceSchema = z.enum(['ocp', 'external']);
export const attributionSignatureAlgorithmSchema = z.enum(['EdDSA']);
export const attributionChainNodeRoleSchema = z.enum(['origin', 'relay']);
export const conversionStatusSchema = z.enum(['confirmed', 'pending', 'refunded', 'cancelled']);
export const attributionErrorCodeSchema = z.enum([
  'chain_broken',
  'complete_mismatch',
  'signature_invalid',
  'key_not_found',
  'alg_not_supported',
  'token_expired',
  'token_not_yet_valid',
  'replayed_jti',
  'duplicate_order',
  'provider_mismatch',
  'purpose_not_settleable',
]);

export const attributionChainNodeSchema = z.object({
  catalog_id: z.string().min(1),
  hop: z.number().int().min(1).max(8),
  role: attributionChainNodeRoleSchema,
  settles: z.boolean(),
  chain_complete: z.boolean(),
  alg: attributionSignatureAlgorithmSchema,
  kid: z.string().min(1),
  signed_at: z.string().datetime(),
  signature: z.string().regex(/^[A-Za-z0-9_-]+$/),
}).strict();

export const attributionTokenSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('AttributionToken'),
  jti: z.string().min(1),
  iss: z.string().min(1),
  iat: z.string().datetime(),
  exp: z.string().datetime(),
  agent_id: z.string().min(1),
  agent_identity_source: agentIdentitySourceSchema.optional(),
  entry_id: z.string().min(1),
  object_id: z.string().min(1),
  provider_id: z.string().min(1),
  purpose: z.enum(['view', 'checkout', 'contact', 'workflow']),
  complete: z.boolean(),
  chain: z.array(attributionChainNodeSchema).min(1).max(8),
}).strict();

export const attributionContextSchema = z.object({
  agent_id: z.string().min(1),
  agent_identity_source: agentIdentitySourceSchema.optional(),
  upstream_token: attributionTokenSchema.optional(),
}).strict();

export const conversionReportSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('ConversionReport'),
  report_id: z.string().min(1),
  order_id: z.string().min(1),
  provider_id: z.string().min(1),
  attribution_token: attributionTokenSchema,
  amount_minor: z.number().int().min(0).max(9007199254740991),
  currency: z.string().regex(/^[A-Z]{3}$/),
  occurred_at: z.string().datetime(),
  status: conversionStatusSchema,
}).strict();

export const resolveRequestSchema = z.object({
  ocp_version: ocpVersionSchema.optional(),
  kind: z.literal('ResolveRequest').optional(),
  catalog_id: z.string().min(1).optional(),
  entry_id: z.string().min(1),
  purpose: z.enum(['view', 'checkout', 'contact', 'workflow']).default('view'),
  live_check: z.boolean().default(true),
  requested_fields: z.array(z.string().min(1)).default([]),
  attribution_context: attributionContextSchema.optional(),
});

export const actionEntrypointSchema = z.object({
  url: z.string().url(),
  method: z.enum(['GET', 'POST']).default('GET'),
});

export const actionBindingSchema = z.object({
  action_id: z.string().min(1),
  action_type: z.enum(['url', 'api', 'workflow', 'contact']),
  label: z.string().min(1),
  description: z.string().optional(),
  entrypoint: actionEntrypointSchema,
  input_schema_url: z.string().url().optional(),
  input_schema: z.record(z.string(), z.unknown()).optional(),
  auth_requirements: z.record(z.string(), z.unknown()).default({}),
  requires_user_confirmation: z.boolean().default(false),
  expires_at: z.string().datetime().optional(),
  attribution: attributionTokenSchema.optional(),
});

export const liveCheckSchema = z.object({
  check_id: z.string().min(1),
  status: z.enum(['passed', 'failed', 'unknown', 'not_applicable']),
  checked_at: z.string().datetime(),
  summary: z.string().optional(),
  details: z.record(z.string(), z.unknown()).default({}),
});

export const resolveAccessSchema = z.object({
  visibility: z.enum(['public', 'partner', 'private']).default('public'),
  permission_state: z.enum(['granted', 'limited', 'denied']).default('granted'),
  redacted_fields: z.array(z.string()).default([]),
  policy_notes: z.array(z.string()).default([]),
});

export const resolvableReferenceSchema = z.object({
  ocp_version: ocpVersionSchema,
  kind: z.literal('ResolvableReference'),
  id: z.string().min(1),
  catalog_id: z.string().min(1),
  entry_id: z.string().min(1),
  commercial_object_id: z.string().min(1),
  object_id: z.string().min(1),
  object_type: z.string().min(1),
  provider_id: z.string().min(1),
  registration_version: z.number().int().min(1).optional(),
  title: z.string().min(1),
  visible_attributes: z.record(z.string(), z.unknown()),
  access: resolveAccessSchema.optional(),
  live_checks: z.array(liveCheckSchema).default([]),
  action_bindings: z.array(actionBindingSchema),
  freshness: z.object({
    object_updated_at: z.string().datetime(),
    resolved_at: z.string().datetime(),
  }),
  expires_at: z.string().datetime(),
});

export const productCorePackSchema = z.object({
  title: z.string().min(1),
  summary: z.string().optional(),
  brand: z.string().optional(),
  category: z.string().optional(),
  sku: z.string().optional(),
  product_url: z.string().url().optional(),
  image_urls: z.array(z.string().url()).optional(),
  video_urls: z.array(z.string().url()).optional(),
  attributes: z.record(z.string(), z.unknown()).optional(),
}).strict();

export const pricePackSchema = z.object({
  currency: z.string().regex(/^[A-Z]{3}$/),
  amount: z.number(),
  list_amount: z.number().optional(),
  price_type: z.enum(['fixed', 'range']).optional(),
}).strict();

export const inventoryPackSchema = z.object({
  availability_status: z.enum(['in_stock', 'low_stock', 'out_of_stock', 'preorder', 'unknown']),
  quantity: z.number().int().min(0).optional(),
}).strict();

export type CatalogManifest = z.infer<typeof catalogManifestSchema>;
export type CatalogDataProfile = z.infer<typeof catalogDataProfileSchema>;
export type CatalogHealthResponse = z.infer<typeof catalogHealthResponseSchema>;
export type CatalogHealthStatus = z.infer<typeof catalogHealthStatusSchema>;
export type AuthorityType = z.infer<typeof authorityTypeSchema>;
export type VerificationStatus = z.infer<typeof verificationStatusSchema>;
export type TrustTier = z.infer<typeof trustTierSchema>;
export type IdentityKeyType = z.infer<typeof identityKeyTypeSchema>;
export type FederationProfile = z.infer<typeof federationProfileSchema>;
export type ObjectContract = z.infer<typeof objectContractSchema>;
export type SyncCapability = z.infer<typeof syncCapabilitySchema>;
export type SelectedSyncCapability = z.infer<typeof selectedSyncCapabilitySchema>;
export type ProviderRegistration = z.infer<typeof providerRegistrationSchema>;
export type CommercialObject = z.infer<typeof commercialObjectSchema>;
export type RegistrationResult = z.infer<typeof registrationResultSchema>;
export type ObjectSyncRequest = z.infer<typeof objectSyncRequestSchema>;
export type ObjectSyncResult = z.infer<typeof objectSyncResultSchema>;
export type ObjectSyncItemResult = z.infer<typeof objectSyncItemResultSchema>;
export type ObjectSyncStreamChunkResult = z.infer<typeof objectSyncStreamChunkResultSchema>;
export type ObjectSyncStreamResult = z.infer<typeof objectSyncStreamResultSchema>;
export type ObjectSyncRun = z.infer<typeof objectSyncRunSchema>;
export type ObjectSyncRunCheckpoint = z.infer<typeof objectSyncRunCheckpointSchema>;
export type CatalogQueryRequest = z.infer<typeof catalogQueryRequestSchema>;
export type CatalogQueryResult = z.infer<typeof catalogQueryResultSchema>;
export type QueryPolicySummary = z.infer<typeof queryPolicySummarySchema>;
export type CatalogEntry = z.infer<typeof catalogEntrySchema>;
export type CatalogEntryMatch = z.infer<typeof catalogEntryMatchSchema>;
export type ResolveRequest = z.infer<typeof resolveRequestSchema>;
export type ResolvableReference = z.infer<typeof resolvableReferenceSchema>;
export type ActionBinding = z.infer<typeof actionBindingSchema>;
export type LiveCheck = z.infer<typeof liveCheckSchema>;
export type ResolveAccess = z.infer<typeof resolveAccessSchema>;
export type AttributionToken = z.infer<typeof attributionTokenSchema>;
export type AttributionChainNode = z.infer<typeof attributionChainNodeSchema>;
export type AttributionContext = z.infer<typeof attributionContextSchema>;
export type ConversionReport = z.infer<typeof conversionReportSchema>;
export type AttributionErrorCode = z.infer<typeof attributionErrorCodeSchema>;
export type AgentIdentitySource = z.infer<typeof agentIdentitySourceSchema>;
export type ConversionStatus = z.infer<typeof conversionStatusSchema>;
