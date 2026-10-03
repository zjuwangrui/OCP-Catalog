import { afterEach, describe, expect, it } from 'bun:test';
import type { OcpActivityEventInput } from '@ocp-catalog/ocp-activity-schema';
import { OcpClient, OcpClientError, OcpClientValidationError } from './index';

const originalFetch = globalThis.fetch;

const publicEvent = {
  public_event_id: 'pub_1',
  raw_event_id: 'evt_1',
  occurred_at: '2026-09-30T10:00:00.000Z',
  event_type: 'catalog.resolved',
  source_kind: 'catalog_node',
  client_kind: 'http',
  protocol_family: 'catalog',
  catalog_id: 'cat_test',
  provider_id: null,
  object_type: null,
  status_class: 'success',
  duration_bucket: 'lt_100ms',
  result_count_bucket: 'one',
  public_summary: 'catalog.resolved: success',
  correlation_id_hash: null,
  attribution_outcome: null,
  created_at: '2026-09-30T10:00:01.000Z',
};

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('OcpClient activity instrumentation', () => {
  it('fails loudly when catalog query results omit page pagination metadata', async () => {
    globalThis.fetch = (async () => new Response(JSON.stringify({
      ocp_version: '1.0',
      kind: 'CatalogQueryResult',
      id: 'query_1',
      catalog_id: 'cat_test',
      query_pack: 'ocp.query.keyword.v1',
      query_mode: 'keyword',
      query: 'shoe',
      result_count: 1,
      entries: [],
      explain: [],
    }), { status: 200 })) as unknown as typeof fetch;

    const client = new OcpClient();

    await expect(client.queryCatalog('https://catalog.example.test/ocp/query', {
      ocp_version: '1.0',
      kind: 'CatalogQueryRequest',
      query_pack: 'ocp.query.keyword.v1',
      query_mode: 'keyword',
      query: 'shoe',
      filters: {},
      limit: 20,
      offset: 0,
      explain: true,
    })).rejects.toThrow();
  });

  it('records sanitized attempted and completed events for registration calls', async () => {
    const events: OcpActivityEventInput[] = [];
    globalThis.fetch = (async () => new Response(JSON.stringify({
      ocp_version: '1.0',
      kind: 'CatalogSearchResult',
      id: 'search_1',
      registration_id: 'reg_1',
      result_count: 0,
      items: [],
      explain: [],
    }), { status: 200 })) as unknown as typeof fetch;

    const client = new OcpClient({
      correlationId: 'corr_test',
      activity: {
        sink: (event) => {
          events.push(event);
        },
        sourceKind: 'cli',
        clientKind: 'mcp',
        sourceName: 'ocp-cli',
        clientName: 'test-client',
        publicVisibility: 'public',
      },
    });

    await client.searchCatalogs('https://registration.example.test', {
      ocp_version: '1.0',
      kind: 'CatalogSearchRequest',
      query: 'private buyer text',
      filters: {},
      limit: 10,
      explain: false,
    });

    expect(events).toHaveLength(2);
    expect(events.map((event) => event.event_type)).toEqual(['client.call_attempted', 'client.call_completed']);
    expect(events[0]).toMatchObject({
      source_kind: 'cli',
      client_kind: 'mcp',
      endpoint_role: 'outbound',
      protocol_family: 'registration',
      method: 'POST',
      path_template: '/ocp/catalogs/search',
      correlation_id: 'corr_test',
      public_visibility: 'public',
    });
    expect(events[1]).toMatchObject({
      event_type: 'client.call_completed',
      status_code: 200,
    });
    expect(events[1].duration_ms).toBeNumber();
    expect(events[0].metadata).toMatchObject({
      endpoint_scheme: 'https',
      endpoint_host: 'registration.example.test',
      source_name: 'ocp-cli',
      client_name: 'test-client',
    });
    expect(JSON.stringify(events)).not.toContain('private buyer text');
  });

  it('records completion status and error code when a protocol call fails', async () => {
    const events: OcpActivityEventInput[] = [];
    globalThis.fetch = (async () => new Response(JSON.stringify({
      error: { code: 'temporarily_unavailable' },
    }), { status: 503 })) as unknown as typeof fetch;

    const client = new OcpClient({
      activity: {
        sink: (event) => {
          events.push(event);
        },
      },
    });

    await expect(client.inspectCatalog('https://catalog.example.test/ocp/manifest')).rejects.toBeInstanceOf(OcpClientError);

    expect(events).toHaveLength(2);
    expect(events[1]).toMatchObject({
      event_type: 'client.call_completed',
      protocol_family: 'catalog',
      endpoint_role: 'outbound',
      method: 'GET',
      path_template: '/ocp/manifest',
      status_code: 503,
      error_code: 'http_error',
    });
  });

  it('validates the recent activity response envelope and every strict public event', async () => {
    const client = new OcpClient();

    globalThis.fetch = (async () => new Response(JSON.stringify({
      events: [publicEvent],
    }), { status: 200 })) as unknown as typeof fetch;
    await expect(client.listActivityEvents('https://activity.example.test')).resolves.toEqual({
      events: [publicEvent],
    });

    globalThis.fetch = (async () => new Response(JSON.stringify([publicEvent]), {
      status: 200,
    })) as unknown as typeof fetch;
    await expect(client.listActivityEvents('https://activity.example.test')).rejects.toBeInstanceOf(OcpClientValidationError);

    globalThis.fetch = (async () => new Response(JSON.stringify({
      events: [{ ...publicEvent, agent_id: 'agent_private' }],
    }), { status: 200 })) as unknown as typeof fetch;
    await expect(client.listActivityEvents('https://activity.example.test')).rejects.toThrow();
  });

  it('does not instrument activity ingest or listing calls', async () => {
    const events: OcpActivityEventInput[] = [];
    const requestedUrls: string[] = [];
    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      requestedUrls.push(String(input));
      return new Response(JSON.stringify({ events: [] }), { status: 200 });
    }) as unknown as typeof fetch;

    const client = new OcpClient({
      activity: {
        sink: (event) => {
          events.push(event);
        },
      },
    });

    await client.ingestActivityEvent('https://activity.example.test', {
      event_type: 'client.call_attempted',
      metadata: {},
    });
    await client.listActivityEvents('https://activity.example.test');

    expect(requestedUrls).toEqual([
      'https://activity.example.test/ocp/audit/events',
      'https://activity.example.test/api/activity/recent?limit=50',
    ]);
    expect(events).toEqual([]);
  });
});
