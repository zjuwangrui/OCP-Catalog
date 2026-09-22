import { z } from 'zod';

export const ocpActivityEventVersionSchema = z.literal('ocp.activity.v1');

export const ocpActivityEventTypeSchema = z.enum([
  'registration.discovered',
  'registration.manifest_read',
  'registration.catalog_registered',
  'registration.catalog_searched',
  'registration.catalog_resolved',
  'registration.catalog_verified',
  'registration.catalog_refreshed',
  'catalog.manifest_read',
  'catalog.contracts_read',
  'catalog.health_checked',
  'catalog.provider_registered',
  'catalog.object_synced',
  'catalog.queried',
  'catalog.resolved',
  'action.binding_exposed',
  'action.invoked',
  'client.call_attempted',
  'client.call_completed',
  'client.validation_completed',
  'provider.webhook_received',
  'provider.sync_queued',
  'policy.denied',
  // Attribution (attribution/v1). One event per thing a node actually does
  // with a token, because the interesting failures are all different from
  // each other: refusing to relay is a node protecting downstream merchants,
  // a failed verification is a merchant refusing to pay, and a settlement
  // decision is the only one of the three that moves money.
  'attribution.token_issued',
  'attribution.token_relayed',
  'attribution.relay_refused',
  'attribution.token_verified',
  'attribution.settlement_decided',
]);

export const ocpActivitySourceKindSchema = z.enum([
  'registration_node',
  'catalog_node',
  'provider_plugin',
  'provider_api',
  'cli',
  'skill',
  'mcp_gateway',
  'webmcp',
  'site',
  'unknown',
]);

export const ocpActivityClientKindSchema = z.enum([
  'http',
  'cli',
  'skill',
  'mcp',
  'webmcp',
  'plugin',
  'server',
  'scheduler',
  'unknown',
]);

export const ocpActivityEndpointRoleSchema = z.enum(['inbound', 'outbound', 'internal']);

export const ocpActivityProtocolFamilySchema = z.enum([
  'registration',
  'catalog',
  'provider',
  'activity',
  'action',
  'client',
  'attribution',
  'unknown',
]);

export const ocpActivityPublicVisibilitySchema = z.enum(['public', 'aggregate_only', 'private']);

export const ocpActivityStatusClassSchema = z.enum(['success', 'client_error', 'server_error', 'policy_denied', 'unknown']);

export const ocpActivityDurationBucketSchema = z.enum(['none', 'lt_100ms', 'lt_500ms', 'lt_1s', 'lt_5s', 'gte_5s']);

export const ocpActivityCountBucketSchema = z.enum(['none', 'zero', 'one', 'lt_10', 'lt_100', 'gte_100']);

const metadataValueSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);

export const ocpActivityMetadataSchema = z.record(z.string(), metadataValueSchema)
  .default({})
  .superRefine((value, context) => {
    const entries = Object.entries(value);
    if (entries.length > 24) {
      context.addIssue({
        code: 'custom',
        message: 'metadata may contain at most 24 keys',
      });
    }

    for (const [key, item] of entries) {
      if (key.length > 80) {
        context.addIssue({
          code: 'custom',
          message: `metadata key ${key} is too long`,
        });
      }
      if (typeof item === 'string' && item.length > 500) {
        context.addIssue({
          code: 'custom',
          message: `metadata value ${key} is too long`,
        });
      }
    }
  });

/**
 * How a verification or settlement came out — `ok` plus the eleven codes of
 * attribution/v1 §8.
 *
 * Spelled out rather than imported so this package keeps its single `zod`
 * dependency; `src/index.test.ts` asserts the list against
 * `ATTRIBUTION_ERROR_CODES` so the two copies cannot drift in silence.
 *
 * This is the one attribution field that survives into the public projection,
 * and it can, because it is a closed enum: it says *that* a chain failed and
 * how, never whose chain it was.
 */
export const ocpActivityAttributionOutcomeSchema = z.enum([
  'ok',
  'chain_broken',
  'complete_mismatch',
  'alg_not_supported',
  'key_not_found',
  'signature_invalid',
  'purpose_not_settleable',
  'provider_mismatch',
  'token_not_yet_valid',
  'token_expired',
  'replayed_jti',
  'duplicate_order',
]);

/**
 * The attribution subjects an event may carry — **raw side only**.
 *
 * Grouped into one object rather than scattered across the event as
 * `attribution_jti` / `attribution_agent_id` / … so that dropping them is one
 * deletion instead of a checklist. A checklist is how the next field added
 * here ends up in a public feed.
 *
 * `jti`, `agent_id` and `order_id` are the three the plan names: a `jti`
 * identifies one token and, with a catalog's cooperation, one agent's one
 * referral; an `order_id` reaches into a merchant's database where a user is
 * sitting next to it. attribution/v1 §9 keeps end users out of the token —
 * this keeps the token out of the public feed, which is the same argument one
 * layer down.
 *
 * `correlation_id` is deliberately *not* in here. It is the linkage the plan
 * asks us to reuse, it already exists on the event, and it is the only piece
 * that reaches the public projection at all — hashed, see
 * {@link toPublicActivityEvent}.
 */
export const ocpActivityAttributionSchema = z.object({
  jti: z.string().min(1).max(200).optional(),
  agent_id: z.string().min(1).max(200).optional(),
  agent_identity_source: z.enum(['self_declared', 'external']).optional(),
  order_id: z.string().min(1).max(200).optional(),
  report_id: z.string().min(1).max(200).optional(),
  /** 1..8 — §4.4 caps a chain at eight hops. */
  hop_count: z.number().int().min(1).max(8).optional(),
  chain_complete: z.boolean().optional(),
  purpose: z.enum(['view', 'checkout', 'contact', 'workflow']).optional(),
  outcome: ocpActivityAttributionOutcomeSchema.optional(),
}).strict();

export const ocpActivityEventInputSchema = z.object({
  event_id: z.string().min(1).optional(),
  idempotency_key: z.string().min(1).optional(),
  event_version: ocpActivityEventVersionSchema.optional().default('ocp.activity.v1'),
  event_type: ocpActivityEventTypeSchema,
  occurred_at: z.string().datetime().optional(),
  observed_at: z.string().datetime().optional(),
  correlation_id: z.string().min(1).optional(),
  trace_id: z.string().min(1).optional(),
  span_id: z.string().min(1).optional(),
  parent_event_id: z.string().min(1).optional(),
  source_kind: ocpActivitySourceKindSchema.default('unknown'),
  client_kind: ocpActivityClientKindSchema.default('unknown'),
  endpoint_role: ocpActivityEndpointRoleSchema.default('internal'),
  protocol_family: ocpActivityProtocolFamilySchema.default('unknown'),
  protocol_version: z.string().min(1).optional(),
  method: z.string().min(1).max(16).optional(),
  path_template: z.string().min(1).max(200).optional(),
  status_code: z.number().int().min(100).max(599).optional(),
  duration_ms: z.number().int().min(0).max(3_600_000).optional(),
  error_code: z.string().min(1).max(120).optional(),
  registration_id: z.string().min(1).optional(),
  catalog_id: z.string().min(1).optional(),
  provider_id: z.string().min(1).optional(),
  object_type: z.string().min(1).optional(),
  query_pack: z.string().min(1).optional(),
  capability_id: z.string().min(1).optional(),
  result_count: z.number().int().min(0).optional(),
  sync_object_count: z.number().int().min(0).optional(),
  public_visibility: ocpActivityPublicVisibilitySchema.default('aggregate_only'),
  redaction_policy_version: z.string().min(1).default('ocp-redaction-v1'),
  payload_hash: z.string().min(1).optional(),
  attribution: ocpActivityAttributionSchema.optional(),
  metadata: ocpActivityMetadataSchema,
}).strict();

export const ocpActivityEventSchema = ocpActivityEventInputSchema.extend({
  event_id: z.string().min(1),
  occurred_at: z.string().datetime(),
  observed_at: z.string().datetime(),
});

/**
 * What may leave the building.
 *
 * `.strict()` is load-bearing, not tidiness. The whole value of a projection
 * is that it is an allowlist, and an allowlist that quietly accepts an extra
 * key is a denylist nobody wrote down. Adding a member here should be an
 * argument, and `.strict()` is what forces the argument to happen.
 *
 * Of the attribution block only {@link ocpActivityAttributionOutcomeSchema}
 * survives — a closed enum. No `jti`, no `agent_id`, no `order_id`; the
 * linkage that remains is `correlation_id_hash`.
 */
export const ocpPublicActivityEventSchema = z.object({
  public_event_id: z.string().min(1),
  raw_event_id: z.string().min(1),
  occurred_at: z.string().datetime(),
  event_type: ocpActivityEventTypeSchema,
  source_kind: ocpActivitySourceKindSchema,
  client_kind: ocpActivityClientKindSchema,
  protocol_family: ocpActivityProtocolFamilySchema,
  catalog_id: z.string().min(1).nullable().default(null),
  provider_id: z.string().min(1).nullable().default(null),
  object_type: z.string().min(1).nullable().default(null),
  status_class: ocpActivityStatusClassSchema,
  duration_bucket: ocpActivityDurationBucketSchema,
  result_count_bucket: ocpActivityCountBucketSchema,
  public_summary: z.string().min(1),
  correlation_id_hash: z.string().min(1).nullable().default(null),
  attribution_outcome: ocpActivityAttributionOutcomeSchema.nullable().default(null),
  created_at: z.string().datetime(),
}).strict();

export const ocpActivityBatchInputSchema = z.object({
  events: z.array(ocpActivityEventInputSchema).min(1).max(100),
}).strict();

// ---------------------------------------------------------------------------
// Public projection
// ---------------------------------------------------------------------------

/**
 * `status_code` → class. `policy.denied` wins over whatever code it carried.
 *
 * A failed attribution verification is **not** folded in here. The HTTP call
 * that carried it usually succeeded — a merchant asking "is this token real"
 * and being told "no" got a perfectly good answer. Collapsing the two would
 * make a working node with a forging partner look like a broken node, which
 * is the opposite of the finding. That is what `attribution_outcome` is for.
 */
export function statusClassOf(event: Pick<OcpActivityEvent, 'event_type' | 'status_code'>): OcpActivityStatusClass {
  if (event.event_type === 'policy.denied') return 'policy_denied';
  const code = event.status_code;
  if (code === undefined) return 'unknown';
  if (code < 400) return 'success';
  if (code < 500) return 'client_error';
  return 'server_error';
}

export function durationBucketOf(durationMs: number | undefined): OcpActivityDurationBucket {
  if (durationMs === undefined) return 'none';
  if (durationMs < 100) return 'lt_100ms';
  if (durationMs < 500) return 'lt_500ms';
  if (durationMs < 1_000) return 'lt_1s';
  if (durationMs < 5_000) return 'lt_5s';
  return 'gte_5s';
}

export function countBucketOf(count: number | undefined): OcpActivityCountBucket {
  if (count === undefined) return 'none';
  if (count === 0) return 'zero';
  if (count === 1) return 'one';
  if (count < 10) return 'lt_10';
  if (count < 100) return 'lt_100';
  return 'gte_100';
}

/**
 * HMAC-SHA256 over a `correlation_id`, as `hmac-sha256:{64 lowercase hex}`.
 *
 * **Keyed, not a bare digest, and that is the whole design.** A `correlation_id`
 * is whatever the emitting node put there — very often a request id, sometimes
 * the order id. A plain SHA-256 of a value drawn from a small or guessable
 * space is not a redaction; anyone who can enumerate candidate ids can invert
 * it with a loop. With a secret the caller holds, the public feed stays
 * joinable to itself — two events from the same flow still hash alike — and
 * stops being joinable to anything outside it.
 *
 * Rotating the secret deliberately breaks correlation across the rotation.
 * That is the cost of the property; a projection that kept old correlations
 * joinable forever would be the thing this is meant to prevent.
 *
 * Uses Web Crypto rather than `node:crypto` so the package stays importable in
 * a browser bundle — `ocp-client` ships these types to both.
 */
export async function hashCorrelationId(correlationId: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, encoder.encode(correlationId));
  const hex = Array.from(new Uint8Array(mac), (b) => b.toString(16).padStart(2, '0')).join('');
  return `hmac-sha256:${hex}`;
}

export interface PublicProjectionOptions {
  /** Identifier for the public row. The raw `event_id` is carried separately as `raw_event_id`. */
  publicEventId: string;
  /**
   * HMAC key for `correlation_id`. **Without it the correlation is dropped
   * rather than digested** — see {@link hashCorrelationId} for why an
   * unkeyed hash of an operator-chosen id is not a redaction.
   */
  correlationSecret?: string;
  /** Defaults to now. */
  createdAt?: string;
  /**
   * Overrides the generated summary. Still passed through
   * {@link assertNoAttributionSubjects}, so a summary that interpolates the
   * agent id throws instead of publishing.
   */
  publicSummary?: string;
}

/**
 * Throws if any raw attribution subject appears anywhere in the projected event.
 *
 * Belt and braces on top of an allowlist, because the two are guarding
 * different mistakes. The allowlist stops a *field* from being copied; this
 * stops a *value* from riding along inside one that is allowed — a summary
 * template that grew an `${agent_id}`, a `catalog_id` an operator set equal to
 * the order id. The first kind gets caught in review; the second does not.
 *
 * Values shorter than 4 characters are skipped: they are indistinguishable
 * from incidental substrings of a timestamp or an enum, and a check that fires
 * on every event is a check that gets switched off.
 *
 * It throws rather than redacting. A pipeline whose job is to not publish
 * something, and which publishes a patched-up version of it instead, has
 * already told the operator the wrong thing. The message names the field, not
 * the value — an exception string is itself a place data leaks.
 */
export function assertNoAttributionSubjects(
  projected: unknown,
  attribution: OcpActivityAttribution | undefined,
): void {
  if (!attribution) return;
  const haystack = JSON.stringify(projected);
  for (const field of ['jti', 'agent_id', 'order_id', 'report_id'] as const) {
    const value = attribution[field];
    if (typeof value === 'string' && value.length >= 4 && haystack.includes(value)) {
      throw new Error(`public projection leaks attribution.${field}`);
    }
  }
}

function defaultSummary(event: OcpActivityEvent): string {
  const status = statusClassOf(event);
  const where = event.catalog_id ? ` on ${event.catalog_id}` : '';
  const outcome =
    event.attribution?.outcome && event.attribution.outcome !== 'ok'
      ? ` (${event.attribution.outcome})`
      : '';
  return `${event.event_type}${where}: ${status}${outcome}`;
}

/**
 * Projects a raw activity event into the public feed, or returns `null`.
 *
 * `null` is the common answer, and the default. Only `public_visibility:
 * "public"` produces a row; `aggregate_only` (the schema default) means the
 * event may be counted in a rollup but not published one by one, and
 * `private` means neither. A projection that published by default would make
 * every new emitter a disclosure decision made by whoever forgot the field.
 *
 * Attribution survives as exactly two things: `attribution_outcome`, a closed
 * enum, and `correlation_id_hash`, keyed. Everything else in
 * {@link ocpActivityAttributionSchema} stops here.
 */
export async function toPublicActivityEvent(
  event: OcpActivityEvent,
  options: PublicProjectionOptions,
): Promise<OcpPublicActivityEvent | null> {
  if (event.public_visibility !== 'public') return null;

  const correlationHash =
    event.correlation_id && options.correlationSecret
      ? await hashCorrelationId(event.correlation_id, options.correlationSecret)
      : null;

  const projected = ocpPublicActivityEventSchema.parse({
    public_event_id: options.publicEventId,
    raw_event_id: event.event_id,
    occurred_at: event.occurred_at,
    event_type: event.event_type,
    source_kind: event.source_kind,
    client_kind: event.client_kind,
    protocol_family: event.protocol_family,
    catalog_id: event.catalog_id ?? null,
    provider_id: event.provider_id ?? null,
    object_type: event.object_type ?? null,
    status_class: statusClassOf(event),
    duration_bucket: durationBucketOf(event.duration_ms),
    result_count_bucket: countBucketOf(event.result_count),
    public_summary: options.publicSummary ?? defaultSummary(event),
    correlation_id_hash: correlationHash,
    attribution_outcome: event.attribution?.outcome ?? null,
    created_at: options.createdAt ?? new Date().toISOString(),
  });

  assertNoAttributionSubjects(projected, event.attribution);
  return projected;
}

export type OcpActivityEventType = z.infer<typeof ocpActivityEventTypeSchema>;
export type OcpActivitySourceKind = z.infer<typeof ocpActivitySourceKindSchema>;
export type OcpActivityClientKind = z.infer<typeof ocpActivityClientKindSchema>;
export type OcpActivityEndpointRole = z.infer<typeof ocpActivityEndpointRoleSchema>;
export type OcpActivityProtocolFamily = z.infer<typeof ocpActivityProtocolFamilySchema>;
export type OcpActivityPublicVisibility = z.infer<typeof ocpActivityPublicVisibilitySchema>;
export type OcpActivityStatusClass = z.infer<typeof ocpActivityStatusClassSchema>;
export type OcpActivityDurationBucket = z.infer<typeof ocpActivityDurationBucketSchema>;
export type OcpActivityCountBucket = z.infer<typeof ocpActivityCountBucketSchema>;
export type OcpActivityAttribution = z.infer<typeof ocpActivityAttributionSchema>;
export type OcpActivityAttributionOutcome = z.infer<typeof ocpActivityAttributionOutcomeSchema>;
export type OcpActivityEventInput = z.input<typeof ocpActivityEventInputSchema>;
export type OcpActivityEvent = z.infer<typeof ocpActivityEventSchema>;
export type OcpPublicActivityEvent = z.infer<typeof ocpPublicActivityEventSchema>;
export type OcpActivityBatchInput = z.input<typeof ocpActivityBatchInputSchema>;
