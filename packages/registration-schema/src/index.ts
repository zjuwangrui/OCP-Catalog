import { z } from 'zod';

export const registrationProtocolVersionSchema = z.literal('1.0');

export const registrationDiscoverySchema = z.object({
  ocp_version: registrationProtocolVersionSchema,
  kind: z.literal('RegistrationDiscovery'),
  registration_id: z.string().min(1),
  registration_name: z.string().min(1),
  registration_protocol: z.literal('ocp.catalog.registration.v1'),
  registration_protocol_version: z.string().min(1),
  manifest_url: z.string().url(),
  catalog_registration_url: z.string().url(),
  catalog_search_url: z.string().url(),
});

export const registrationManifestSchema = z.object({
  ocp_version: registrationProtocolVersionSchema,
  kind: z.literal('RegistrationManifest'),
  registration_id: z.string().min(1),
  registration_name: z.string().min(1),
  supported_protocols: z.array(z.string().min(1)),
  endpoints: z.object({
    catalog_registration: z.string().url(),
    catalog_search: z.string().url(),
    catalog_resolve: z.string().url(),
    catalog_verify: z.string().url(),
    catalog_refresh: z.string().url(),
    catalog_token_rotate: z.string().url(),
  }),
  catalog_registration: z.object({
    registration_modes: z.array(z.enum(['open_intake', 'invite_only'])),
    default_status: z.enum(['pending_verification', 'accepted_indexed']),
    requires_domain_verification: z.boolean(),
    requires_https: z.boolean(),
  }),
  catalog_search_capabilities: z.array(z.record(z.string(), z.unknown())),
});

export const catalogRegistrationSchema = z.object({
  ocp_version: registrationProtocolVersionSchema,
  kind: z.literal('CatalogRegistration'),
  id: z.string().min(1),
  registration_id: z.string().min(1),
  catalog_id: z.string().min(1),
  registration_version: z.number().int().min(1),
  updated_at: z.string().datetime(),
  homepage: z.string().url(),
  well_known_url: z.string().url(),
  claimed_domains: z.array(z.string().min(1)).min(1),
  operator: z.object({
    operator_id: z.string().min(1).optional(),
    display_name: z.string().min(1),
    contact_email: z.string().email().optional(),
  }).passthrough().optional(),
  intended_visibility: z.enum(['public', 'partner', 'private']).default('public'),
  tags: z.array(z.string().min(1)).default([]),
});

export const catalogRegistrationStatusSchema = z.enum([
  'accepted_indexed',
  'accepted_pending_verification',
  'accepted_limited',
  'rejected',
  'stale_ignored',
]);

export const catalogVerificationChallengeSchema = z.object({
  challenge_id: z.string().min(1),
  challenge_type: z.enum(['dns_txt', 'https_well_known']),
  domain: z.string().min(1),
  name: z.string().optional(),
  value: z.string().optional(),
  url: z.string().url().optional(),
  token: z.string().optional(),
  expires_at: z.string().datetime(),
}).superRefine((value, context) => {
  if (value.challenge_type === 'dns_txt' && (!value.name || !value.value)) {
    context.addIssue({
      code: 'custom',
      message: 'dns_txt challenge requires name and value',
      path: ['name'],
    });
  }

  if (value.challenge_type === 'https_well_known' && (!value.url || !value.token)) {
    context.addIssue({
      code: 'custom',
      message: 'https_well_known challenge requires url and token',
      path: ['url'],
    });
  }
});

export const catalogRegistrationResultSchema = z.object({
  ocp_version: registrationProtocolVersionSchema,
  kind: z.literal('CatalogRegistrationResult'),
  id: z.string().min(1),
  registration_id: z.string().min(1),
  catalog_id: z.string().optional(),
  status: catalogRegistrationStatusSchema,
  effective_registration_version: z.number().int().min(1).optional(),
  manifest_fetch_status: z.enum(['not_attempted', 'fetched', 'failed']).default('not_attempted'),
  verification_status: z.enum(['verified', 'challenge_required', 'failed', 'not_required']).default('not_required'),
  health_status: z.enum(['healthy', 'unhealthy', 'unknown']).default('unknown'),
  indexed: z.boolean(),
  warnings: z.array(z.string()).default([]),
  verification_challenges: z.array(catalogVerificationChallengeSchema).default([]),
  catalog_access_token: z.string().optional(),
  token_issued_at: z.string().datetime().optional(),
  message: z.string().optional(),
});

export const catalogRouteHintSchema = z.object({
  catalog_id: z.string().min(1),
  catalog_name: z.string().min(1),
  description: z.string().optional(),
  manifest_url: z.string().url(),
  query_url: z.string().url(),
  health_url: z.string().url().optional(),
  resolve_url: z.string().url().optional(),
  supported_query_packs: z.array(z.string()).default([]),
  auth_requirements: z.record(z.string(), z.unknown()).default({}),
  metadata: z.record(z.string(), z.unknown()).default({}),
  verification_status: z.string(),
  trust_tier: z.string(),
  trust_profile: z.object({
    verification_status: z.string(),
    trust_tier: z.string(),
    domain_verified: z.boolean().default(false),
    manifest_signed: z.boolean().default(false),
    signature_alg: z.string().optional(),
    manifest_hash: z.string().optional(),
    issuer: z.string().optional(),
    downgrade_invalidates_cache: z.boolean().default(true),
  }).optional(),
  federation: z.object({
    mode: z.string().default('disabled'),
    node_role: z.string().optional(),
    remote_query_supported: z.boolean().default(false),
    remote_resolve_supported: z.boolean().default(false),
    summary_cache_supported: z.boolean().default(false),
    mutation_log_supported: z.boolean().default(false),
  }).optional(),
  health_status: z.string(),
  cache_ttl_seconds: z.number().int().min(1).default(86400),
  snapshot_id: z.string().min(1),
  snapshot_fetched_at: z.string().datetime(),
});

export const catalogProfileSnapshotSchema = z.object({
  ocp_version: registrationProtocolVersionSchema,
  kind: z.literal('CatalogProfileSnapshot'),
  id: z.string().min(1),
  registration_id: z.string().min(1),
  catalog_id: z.string().min(1),
  catalog_name: z.string().min(1),
  description: z.string().optional(),
  homepage: z.string().url(),
  well_known_url: z.string().url(),
  manifest_url: z.string().url(),
  query_capabilities: z.array(z.record(z.string(), z.unknown())).default([]),
  object_contract_summaries: z.array(z.record(z.string(), z.unknown())).default([]),
  metadata: z.record(z.string(), z.unknown()).default({}),
  verification_status: z.string(),
  health_status: z.string(),
  trust_tier: z.string(),
  freshness: z.object({
    manifest_fetched_at: z.string().datetime(),
    health_checked_at: z.string().datetime().optional(),
  }),
});

export const catalogIndexEntrySchema = z.object({
  catalog_id: z.string().min(1),
  catalog_name: z.string().min(1),
  description: z.string().optional(),
  homepage: z.string().url(),
  manifest_url: z.string().url(),
  well_known_url: z.string().url(),
  supported_query_modes: z.array(z.string()).default([]),
  supported_query_packs: z.array(z.string()).default([]),
  supports_resolve: z.boolean().default(false),
  metadata: z.record(z.string(), z.unknown()).default({}),
  tags: z.array(z.string()).default([]),
  domains: z.array(z.string()).default([]),
  verification_status: z.string(),
  trust_tier: z.string(),
  health_status: z.string(),
});

export const catalogSearchFiltersSchema = z.object({
  query_pack: z.string().min(1).optional(),
  supports_resolve: z.boolean().optional(),
  verification_status: z.string().min(1).optional(),
  trust_tier: z.string().min(1).optional(),
  health_status: z.string().min(1).optional(),
  domain: z.string().min(1).optional(),
  tag: z.string().min(1).optional(),
}).strict();

export const catalogSearchRequestSchema = z.object({
  ocp_version: registrationProtocolVersionSchema.optional(),
  kind: z.literal('CatalogSearchRequest').optional(),
  query: z.string().max(500).optional().default(''),
  filters: catalogSearchFiltersSchema.optional().default({}),
  limit: z.number().int().min(1).max(50).optional().default(20),
  explain: z.boolean().optional().default(true),
});

export const catalogSearchResultItemSchema = z.object({
  catalog_id: z.string().min(1),
  catalog_name: z.string().min(1),
  description: z.string().optional(),
  score: z.number(),
  matched_query_packs: z.array(z.string()).default([]),
  verification_status: z.string(),
  trust_tier: z.string(),
  health_status: z.string(),
  route_hint: catalogRouteHintSchema,
  explain: z.array(z.string()).default([]),
});

export const catalogSearchResultSchema = z.object({
  ocp_version: registrationProtocolVersionSchema,
  kind: z.literal('CatalogSearchResult'),
  id: z.string().min(1),
  registration_id: z.string().min(1),
  result_count: z.number().int().min(0),
  items: z.array(catalogSearchResultItemSchema),
  explain: z.array(z.string()).default([]),
});

export const catalogResolveRequestSchema = z.object({
  ocp_version: registrationProtocolVersionSchema.optional(),
  kind: z.literal('CatalogResolveRequest').optional(),
  catalog_id: z.string().min(1),
});

export const catalogVerificationRequestSchema = z.object({
  ocp_version: registrationProtocolVersionSchema.optional(),
  kind: z.literal('CatalogVerificationRequest').optional(),
  challenge_id: z.string().min(1).optional(),
});

export const catalogVerificationResultSchema = z.object({
  ocp_version: registrationProtocolVersionSchema,
  kind: z.literal('CatalogVerificationResult'),
  id: z.string().min(1),
  registration_id: z.string().min(1),
  catalog_id: z.string().min(1),
  verification_status: z.enum(['verified', 'challenge_required', 'failed', 'not_required']),
  indexed: z.boolean(),
  verified_domains: z.array(z.string()).default([]),
  failed_challenges: z.array(z.string()).default([]),
  catalog_access_token: z.string().optional(),
  message: z.string().optional(),
});

export const catalogRefreshResultSchema = z.object({
  ocp_version: registrationProtocolVersionSchema,
  kind: z.literal('CatalogRefreshResult'),
  id: z.string().min(1),
  registration_id: z.string().min(1),
  catalog_id: z.string().min(1),
  status: z.enum(['refreshed', 'rejected']),
  snapshot_id: z.string().optional(),
  health_status: z.string(),
  health_failure_count: z.number().int().min(0).optional(),
  indexed: z.boolean(),
  warnings: z.array(z.string()).default([]),
  refreshed_at: z.string().datetime(),
});

export const catalogTokenRotationResultSchema = z.object({
  ocp_version: registrationProtocolVersionSchema,
  kind: z.literal('CatalogTokenRotationResult'),
  id: z.string().min(1),
  registration_id: z.string().min(1),
  catalog_id: z.string().min(1),
  catalog_access_token: z.string(),
  token_issued_at: z.string().datetime(),
});

export type RegistrationDiscovery = z.infer<typeof registrationDiscoverySchema>;
export type RegistrationManifest = z.infer<typeof registrationManifestSchema>;
export type CatalogRegistration = z.infer<typeof catalogRegistrationSchema>;
export type CatalogRegistrationResult = z.infer<typeof catalogRegistrationResultSchema>;
export type CatalogVerificationChallenge = z.infer<typeof catalogVerificationChallengeSchema>;
export type CatalogProfileSnapshot = z.infer<typeof catalogProfileSnapshotSchema>;
export type CatalogIndexEntry = z.infer<typeof catalogIndexEntrySchema>;
export type CatalogRouteHint = z.infer<typeof catalogRouteHintSchema>;
export type CatalogSearchRequest = z.infer<typeof catalogSearchRequestSchema>;
export type CatalogSearchResult = z.infer<typeof catalogSearchResultSchema>;
export type CatalogSearchResultItem = z.infer<typeof catalogSearchResultItemSchema>;
export type CatalogResolveRequest = z.infer<typeof catalogResolveRequestSchema>;
export type CatalogVerificationRequest = z.infer<typeof catalogVerificationRequestSchema>;
export type CatalogVerificationResult = z.infer<typeof catalogVerificationResultSchema>;
export type CatalogRefreshResult = z.infer<typeof catalogRefreshResultSchema>;
export type CatalogTokenRotationResult = z.infer<typeof catalogTokenRotationResultSchema>;

export {
  applyManifestVerification,
  type RouteHintTrustOutcome,
} from './trust-profile';
