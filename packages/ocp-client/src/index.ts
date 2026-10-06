import {
  catalogManifestSchema,
  catalogQueryResultSchema,
  objectSyncRequestSchema,
  objectSyncResultSchema,
  providerRegistrationSchema,
  registrationResultSchema,
  resolvableReferenceSchema,
  type CatalogManifest,
  type CatalogQueryRequest,
  type CatalogQueryResult,
  type ObjectSyncRequest,
  type ObjectSyncResult,
  type ProviderRegistration,
  type RegistrationResult,
  type ResolveRequest,
  type ResolvableReference,
} from '@ocp-catalog/ocp-schema';
import {
  catalogRouteHintSchema,
  catalogSearchResultSchema,
  registrationDiscoverySchema,
  type CatalogRouteHint,
  type CatalogSearchRequest,
  type CatalogSearchResult,
  type RegistrationDiscovery,
} from '@ocp-catalog/registration-schema';
import {
  ocpActivityEventInputSchema,
  ocpPublicActivityEventSchema,
  type OcpActivityClientKind,
  type OcpActivityEventInput,
  type OcpActivityProtocolFamily,
  type OcpActivityPublicVisibility,
  type OcpActivitySourceKind,
  type OcpPublicActivityEvent,
} from '@ocp-catalog/ocp-activity-schema';

export type OcpClientActivityMetadata = Record<string, string | number | boolean | null>;
export type OcpClientActivitySink = (event: OcpActivityEventInput) => void | Promise<void>;
export type OcpClientCorrelationId = string | (() => string | undefined);

export type OcpClientActivityOptions = {
  apiUrl?: string;
  apiKey?: string;
  sink?: OcpClientActivitySink;
  sourceKind?: OcpActivitySourceKind;
  clientKind?: OcpActivityClientKind;
  sourceName?: string;
  clientName?: string;
  publicVisibility?: OcpActivityPublicVisibility;
  correlationId?: OcpClientCorrelationId;
  includeClientCorrelationId?: boolean;
  metadata?: OcpClientActivityMetadata;
  timeoutMs?: number;
};

export type OcpClientOptions = {
  timeoutMs?: number;
  userAgent?: string;
  apiKey?: string;
  correlationId?: OcpClientCorrelationId;
  activity?: OcpClientActivityOptions;
};

type FetchJsonContext = {
  protocolFamily: OcpActivityProtocolFamily;
  pathTemplate?: string;
  metadata?: OcpClientActivityMetadata;
  queryPack?: string;
  catalogId?: string;
};

export class OcpClientError extends Error {
  readonly details: {
    url: string;
    status?: number;
    payload?: unknown;
    cause?: string;
  };

  constructor(
    message: string,
    details: {
      url: string;
      status?: number;
      payload?: unknown;
      cause?: string;
    },
  ) {
    super(message);
    this.name = 'OcpClientError';
    this.details = details;
  }
}

export class OcpClientValidationError extends Error {
  readonly details: Record<string, unknown> & { code: string };

  constructor(message: string, details: Record<string, unknown> & { code: string }) {
    super(message);
    this.name = 'OcpClientValidationError';
    this.details = details;
  }
}

export type CatalogQueryValidationResult = {
  ok: true;
  request: CatalogQueryRequest;
  policy_summary: {
    selected_capability_id?: string;
    selected_query_pack?: string;
    query_mode: QueryMode;
    supports_explain: boolean;
    accepted_filters: string[];
    rejected_filters: string[];
    warnings: string[];
  };
};

export function validateCatalogQueryRequest(
  manifest: CatalogManifest,
  request: CatalogQueryRequest,
  options: { queryUrl?: string } = {},
): CatalogQueryValidationResult {
  if (options.queryUrl && options.queryUrl !== manifest.endpoints.query.url) {
    throw new OcpClientValidationError('query_url does not match the Catalog manifest endpoint', {
      code: 'invalid_query_endpoint',
      received_query_url: options.queryUrl,
      manifest_query_url: manifest.endpoints.query.url,
      correction: 'Use the query endpoint declared by the same manifest used for validation.',
    });
  }

  const descriptors = manifestQueryPackDescriptors(manifest);
  const supportedQueryPacks = descriptors.map((descriptor) => descriptor.pack_id);
  const requestedDescriptor = request.query_pack
    ? descriptors.find((descriptor) => descriptor.pack_id === request.query_pack)
    : undefined;

  if (request.query_pack && !requestedDescriptor) {
    throw new OcpClientValidationError(`unsupported query_pack: ${request.query_pack}`, {
      code: 'invalid_query_pack',
      query_pack: request.query_pack,
      supported_query_packs: supportedQueryPacks,
      correction: 'Use one of the manifest-declared query packs or omit query_pack so the Catalog can select a default.',
    });
  }

  if (request.query_pack && requestedDescriptor?.query_modes.length === 0) {
    throw new OcpClientValidationError(`query_pack ${request.query_pack} does not declare query_modes`, {
      code: 'invalid_query_pack',
      query_pack: request.query_pack,
      supported_query_packs: supportedQueryPacks,
      correction: 'Inspect the Catalog manifest and choose a query pack that declares supported query_modes.',
    });
  }

  const requestedQueryMode = requestedQueryModeFromRequest(request);
  const queryMode = requestedQueryMode ?? inferBaseQueryMode(request.query ?? '', request.filters ?? {});
  const selectedDescriptor = requestedDescriptor
    ?? descriptors.find((descriptor) => descriptor.query_modes.includes(queryMode));

  if (!selectedDescriptor) {
    if (descriptors.length === 0) {
      throw new OcpClientValidationError('catalog manifest does not declare any query packs', {
        code: 'invalid_query_pack',
        supported_query_packs: supportedQueryPacks,
        correction: 'Inspect a different Catalog manifest before sending a query.',
      });
    }

    throw new OcpClientValidationError(`catalog manifest does not support query mode ${queryMode}`, {
      code: 'invalid_query_mode',
      query_mode: queryMode,
      supported_query_modes: unique(descriptors.flatMap((descriptor) => descriptor.query_modes)),
      supported_query_packs: supportedQueryPacks,
      correction: 'Choose a query mode supported by the manifest or change the request shape.',
    });
  }

  if (!selectedDescriptor.query_modes.includes(queryMode)) {
    throw new OcpClientValidationError(`query_pack ${selectedDescriptor.pack_id} does not support query mode ${queryMode}`, {
      code: 'invalid_query_mode',
      query_pack: selectedDescriptor.pack_id,
      query_mode: queryMode,
      supported_query_modes: selectedDescriptor.query_modes,
      correction: 'Choose a query pack whose query_modes match the request shape.',
    });
  }

  if (queryMode === 'semantic' && !(request.query ?? '').trim()) {
    throw new OcpClientValidationError('semantic query requires a non-empty query', {
      code: 'invalid_query',
      query_pack: selectedDescriptor.pack_id,
      query_mode: queryMode,
      correction: 'Provide --query text or choose a non-semantic query pack.',
    });
  }

  const filterFields = Object.entries(request.filters ?? {})
    .filter(([, value]) => value !== undefined && value !== false)
    .map(([field]) => field)
    .sort();
  const supportedFilterFields = manifestSupportedFilterFields(manifest);
  const rejectedFilters = supportedFilterFields.length === 0
    ? []
    : filterFields.filter((field) => !supportedFilterFields.includes(field));

  if (rejectedFilters.length > 0) {
    throw new OcpClientValidationError(`unsupported filter fields: ${rejectedFilters.join(', ')}`, {
      code: 'invalid_filter_field',
      rejected_filter_fields: rejectedFilters,
      supported_filter_fields: supportedFilterFields,
      correction: 'Remove unsupported filters or inspect the manifest for accepted filters.* input fields.',
    });
  }

  const requestWithSelectedPack = {
    ...request,
    query_pack: request.query_pack ?? selectedDescriptor.pack_id,
  };

  return {
    ok: true,
    request: requestWithSelectedPack,
    policy_summary: {
      selected_capability_id: selectedDescriptor.capability_id,
      selected_query_pack: selectedDescriptor.pack_id,
      query_mode: queryMode,
      supports_explain: selectedDescriptor.supports_explain,
      accepted_filters: filterFields,
      rejected_filters: [],
      warnings: selectedDescriptor.supports_explain ? [] : ['Selected query capability does not support explain output.'],
    },
  };
}

export class OcpClient {
  private readonly options: OcpClientOptions;

  constructor(options: OcpClientOptions = {}) {
    this.options = options;
  }

  async discoverRegistration(discoveryUrl: string): Promise<RegistrationDiscovery> {
    const payload = await this.fetchJson(discoveryUrl, { method: 'GET' }, {
      protocolFamily: 'registration',
    });
    return registrationDiscoverySchema.parse(payload);
  }

  async searchCatalogs(registrationBaseUrl: string, body: CatalogSearchRequest): Promise<CatalogSearchResult> {
    const payload = await this.fetchJson(`${trimTrailingSlash(registrationBaseUrl)}/ocp/catalogs/search`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }, {
      protocolFamily: 'registration',
      pathTemplate: '/ocp/catalogs/search',
    });
    return catalogSearchResultSchema.parse(payload);
  }

  async resolveCatalogRoute(registrationBaseUrl: string, catalogId: string): Promise<CatalogRouteHint> {
    const payload = await this.fetchJson(`${trimTrailingSlash(registrationBaseUrl)}/ocp/catalogs/resolve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ocp_version: '1.0',
        kind: 'CatalogResolveRequest',
        catalog_id: catalogId,
      }),
    }, {
      protocolFamily: 'registration',
      pathTemplate: '/ocp/catalogs/resolve',
      catalogId,
    });
    return catalogRouteHintSchema.parse(payload);
  }

  async inspectCatalog(manifestUrl: string): Promise<CatalogManifest> {
    const payload = await this.fetchJson(manifestUrl, { method: 'GET' }, {
      protocolFamily: 'catalog',
    });
    return catalogManifestSchema.parse(payload);
  }

  async registerProvider(registerUrl: string, body: ProviderRegistration): Promise<RegistrationResult> {
    const request = providerRegistrationSchema.parse(body);
    const payload = await this.fetchJson(registerUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request),
    }, {
      protocolFamily: 'catalog',
      pathTemplate: '/ocp/providers/register',
      catalogId: request.catalog_id,
    });
    return registrationResultSchema.parse(payload);
  }

  async syncObjects(syncUrl: string, body: ObjectSyncRequest): Promise<ObjectSyncResult> {
    const request = objectSyncRequestSchema.parse(body);
    const payload = await this.fetchJson(syncUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request),
    }, {
      protocolFamily: 'catalog',
      pathTemplate: '/ocp/objects/sync',
      catalogId: request.catalog_id,
      metadata: {
        provider_id: request.provider_id,
        object_count: request.objects.length,
      },
    });
    return objectSyncResultSchema.parse(payload);
  }

  async queryCatalog(queryUrl: string, body: CatalogQueryRequest): Promise<CatalogQueryResult> {
    const payload = await this.fetchJson(queryUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }, {
      protocolFamily: 'catalog',
      queryPack: body.query_pack,
      catalogId: body.catalog_id,
      metadata: {
        request_limit: body.limit ?? null,
        request_offset: body.offset ?? null,
      },
    });
    return catalogQueryResultSchema.parse(payload);
  }

  async resolveCatalogEntry(resolveUrl: string, body: ResolveRequest): Promise<ResolvableReference> {
    const payload = await this.fetchJson(resolveUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }, {
      protocolFamily: 'catalog',
      catalogId: body.catalog_id,
      metadata: {
        resolve_purpose: body.purpose ?? null,
      },
    });
    return resolvableReferenceSchema.parse(payload);
  }

  async ingestActivityEvent(activityUrl: string, body: OcpActivityEventInput) {
    const event = ocpActivityEventInputSchema.parse(body);
    return this.fetchJson(`${trimTrailingSlash(activityUrl)}/ocp/audit/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(event),
    });
  }

  async listActivityEvents(activityUrl: string, limit = 50): Promise<{ events: OcpPublicActivityEvent[] }> {
    const payload = await this.fetchJson(`${trimTrailingSlash(activityUrl)}/api/activity/recent?limit=${encodeURIComponent(String(limit))}`, {
      method: 'GET',
    });
    if (!isRecord(payload) || !Array.isArray(payload.events)) {
      throw new OcpClientValidationError('Activity recent payload does not expose an events array', {
        code: 'invalid_activity_events_response',
      });
    }
    return {
      events: payload.events.map((event) => ocpPublicActivityEventSchema.parse(event)),
    };
  }

  private async fetchJson(url: string, init: RequestInit, context?: FetchJsonContext): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs ?? 10_000);
    const method = normalizeHttpMethod(init.method);
    const startedAt = Date.now();
    const clientCorrelationId = resolveCorrelationId(this.options.correlationId);
    const activityCorrelationId = context
      ? resolveActivityCorrelationId(this.options.activity, clientCorrelationId)
      : undefined;
    let statusCode: number | undefined;
    let errorCode: string | undefined;

    try {
      const headers = new Headers(init.headers);
      if (this.options.userAgent) headers.set('user-agent', this.options.userAgent);
      if (this.options.apiKey && !headers.has('x-api-key')) headers.set('x-api-key', this.options.apiKey);
      if (clientCorrelationId) headers.set('x-ocp-trace-id', clientCorrelationId);

      this.recordClientCall('client.call_attempted', url, method, context, activityCorrelationId);

      const response = await fetch(url, {
        ...init,
        headers,
        signal: controller.signal,
      });
      statusCode = response.status;
      const text = await response.text();
      const payload = text ? JSON.parse(text) : null;

      if (!response.ok) {
        errorCode = 'http_error';
        throw new OcpClientError(`HTTP ${response.status} from ${url}`, {
          url,
          status: response.status,
          payload,
        });
      }

      return payload;
    } catch (error) {
      if (error instanceof OcpClientError) throw error;
      errorCode = classifyClientError(error);
      throw new OcpClientError(`Failed to fetch ${url}`, {
        url,
        cause: error instanceof Error ? error.message : String(error),
      });
    } finally {
      this.recordClientCall('client.call_completed', url, method, context, activityCorrelationId, {
        statusCode,
        durationMs: Date.now() - startedAt,
        errorCode,
      });
      clearTimeout(timeout);
    }
  }

  private recordClientCall(
    eventType: 'client.call_attempted' | 'client.call_completed',
    url: string,
    method: string,
    context: FetchJsonContext | undefined,
    activityCorrelationId: string | undefined,
    result: { statusCode?: number; durationMs?: number; errorCode?: string } = {},
  ) {
    const activity = this.options.activity;
    if (!activity || (!activity.sink && !activity.apiUrl) || !context) return;

    const metadata = sanitizeActivityMetadata({
      ...activity.metadata,
      ...safeIdentityMetadata(activity),
      ...safeUrlMetadata(url),
      ...context.metadata,
    });
    const event = compactActivityEvent({
      event_type: eventType,
      occurred_at: new Date().toISOString(),
      correlation_id: activityCorrelationId,
      source_kind: activity.sourceKind ?? 'unknown',
      client_kind: activity.clientKind ?? 'http',
      endpoint_role: 'outbound',
      protocol_family: context.protocolFamily,
      method,
      path_template: context.pathTemplate ?? safeUrlPath(url),
      status_code: result.statusCode,
      duration_ms: result.durationMs,
      error_code: result.errorCode,
      catalog_id: context.catalogId,
      query_pack: context.queryPack,
      public_visibility: activity.publicVisibility ?? 'aggregate_only',
      metadata,
    });

    this.emitActivityEvent(event);
  }

  private emitActivityEvent(input: OcpActivityEventInput) {
    const activity = this.options.activity;
    if (!activity) return;

    let event: OcpActivityEventInput;
    try {
      event = ocpActivityEventInputSchema.parse(input);
    } catch {
      return;
    }

    const pending: Promise<unknown>[] = [];
    if (activity.sink) {
      try {
        const result = activity.sink(event);
        if (isPromiseLike(result)) pending.push(result);
      } catch {
        // Activity instrumentation is intentionally best-effort.
      }
    }

    if (activity.apiUrl) {
      pending.push(sendActivityEvent(activity, event));
    }

    if (pending.length > 0) {
      void Promise.allSettled(pending);
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function manifestQueryPackDescriptors(manifest: CatalogManifest) {
  return manifest.query_capabilities.flatMap((capability) => (
    capability.query_packs.map((pack) => ({
      capability_id: capability.capability_id,
      pack_id: pack.pack_id,
      query_modes: pack.query_modes,
      supports_explain: capability.supports_explain,
    }))
  ));
}

function manifestSupportedFilterFields(manifest: CatalogManifest) {
  return unique(manifest.query_capabilities.flatMap((capability) => (
    capability.input_fields
      .map((field) => typeof field.name === 'string' ? field.name : null)
      .filter((name): name is string => Boolean(name?.startsWith('filters.')))
      .map((name) => name.replace(/^filters\./, ''))
  )));
}

type QueryMode = 'keyword' | 'filter' | 'semantic' | 'hybrid';

function inferBaseQueryMode(query: string, filters: Record<string, unknown>): QueryMode {
  const hasQuery = query.trim().length > 0;
  const hasFilters = Object.values(filters).some(Boolean);
  if (hasQuery && hasFilters) return 'hybrid';
  if (hasFilters) return 'filter';
  if (!hasQuery) return 'filter';
  return 'keyword';
}

function requestedQueryModeFromRequest(request: CatalogQueryRequest): QueryMode | undefined {
  const value = (request as CatalogQueryRequest & { query_mode?: unknown }).query_mode;
  if (value === undefined) return undefined;
  if (isQueryMode(value)) return value;
  throw new OcpClientValidationError(`unsupported query_mode: ${String(value)}`, {
    code: 'invalid_query_mode',
    query_mode: value,
    supported_query_modes: QUERY_MODES,
    correction: 'Use one of keyword, filter, semantic, or hybrid.',
  });
}

function isQueryMode(value: unknown): value is QueryMode {
  return typeof value === 'string' && QUERY_MODES.includes(value as QueryMode);
}

const QUERY_MODES: QueryMode[] = ['keyword', 'filter', 'semantic', 'hybrid'];

export function createCorrelationId(prefix = 'corr') {
  return `${prefix}_${crypto.randomUUID().replaceAll('-', '')}`;
}

function trimTrailingSlash(value: string) {
  return value.replace(/\/+$/, '');
}

function resolveCorrelationId(value: OcpClientCorrelationId | undefined) {
  return typeof value === 'function' ? value() : value;
}

function resolveActivityCorrelationId(activity: OcpClientActivityOptions | undefined, clientCorrelationId: string | undefined) {
  if (!activity) return undefined;
  if (activity.correlationId !== undefined) return resolveCorrelationId(activity.correlationId);
  if (activity.includeClientCorrelationId === false) return undefined;
  return clientCorrelationId;
}

function normalizeHttpMethod(method: string | undefined) {
  return (method ?? 'GET').toUpperCase();
}

function safeUrlPath(value: string) {
  try {
    const path = new URL(value).pathname || '/';
    return truncateActivityString(path, 200);
  } catch {
    return undefined;
  }
}

function safeUrlMetadata(value: string): OcpClientActivityMetadata {
  try {
    const url = new URL(value);
    return {
      endpoint_scheme: url.protocol.replace(/:$/, ''),
      endpoint_host: url.host,
    };
  } catch {
    return {};
  }
}

function safeIdentityMetadata(activity: OcpClientActivityOptions): OcpClientActivityMetadata {
  return {
    ...(activity.sourceName ? { source_name: activity.sourceName } : {}),
    ...(activity.clientName ? { client_name: activity.clientName } : {}),
  };
}

function sanitizeActivityMetadata(metadata: OcpClientActivityMetadata): OcpClientActivityMetadata {
  const result: OcpClientActivityMetadata = {};
  for (const [key, value] of Object.entries(metadata).slice(0, 24)) {
    if (value === undefined) continue;
    result[truncateActivityString(key, 80)] = typeof value === 'string' ? truncateActivityString(value, 500) : value;
  }
  return result;
}

function compactActivityEvent(event: OcpActivityEventInput): OcpActivityEventInput {
  return Object.fromEntries(Object.entries(event).filter(([, value]) => value !== undefined)) as OcpActivityEventInput;
}

function unique<T>(values: T[]) {
  return [...new Set(values)];
}

function truncateActivityString(value: string, maxLength: number) {
  return value.length > maxLength ? value.slice(0, maxLength) : value;
}

function classifyClientError(error: unknown) {
  if (error instanceof SyntaxError) return 'invalid_json';
  if (typeof DOMException !== 'undefined' && error instanceof DOMException && error.name === 'AbortError') return 'timeout';
  if (error instanceof Error && error.name === 'AbortError') return 'timeout';
  return 'fetch_error';
}

function isPromiseLike(value: unknown): value is Promise<unknown> {
  return !!value && typeof value === 'object' && 'then' in value && typeof (value as { then?: unknown }).then === 'function';
}

async function sendActivityEvent(activity: OcpClientActivityOptions, event: OcpActivityEventInput) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), activity.timeoutMs ?? 2_000);

  try {
    const headers = new Headers({ 'content-type': 'application/json' });
    if (activity.apiKey) headers.set('x-api-key', activity.apiKey);

    await fetch(activityIngestUrl(activity.apiUrl ?? ''), {
      method: 'POST',
      headers,
      body: JSON.stringify(event),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

function activityIngestUrl(apiUrl: string) {
  const trimmed = trimTrailingSlash(apiUrl);
  return trimmed.endsWith('/ocp/audit/events') ? trimmed : `${trimmed}/ocp/audit/events`;
}
