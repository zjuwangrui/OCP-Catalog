import { describe, expect, test } from 'bun:test';
import {
  isCurrentActivityRequest,
  parseActivityEvents,
  parseActivityRollups,
} from './activityData';

const publicEvent = {
  public_event_id: 'pub_0001',
  raw_event_id: 'evt_0001',
  occurred_at: '2026-10-08T08:00:00.000Z',
  event_type: 'attribution.token_verified',
  source_kind: 'catalog_node',
  client_kind: 'http',
  protocol_family: 'attribution',
  catalog_id: 'cat_demo',
  provider_id: 'prov_demo',
  object_type: null,
  status_class: 'success',
  duration_bucket: 'lt_100ms',
  result_count_bucket: 'none',
  public_summary: 'attribution.token_verified: success (signature_invalid)',
  correlation_id_hash: 'hmac-sha256:abc123',
  attribution_outcome: 'signature_invalid',
  created_at: '2026-10-08T08:00:01.000Z',
};

const rollups = {
  window_hours: 24,
  event_count: 7,
  by_event_type: { 'attribution.token_verified': 3 },
  by_protocol_family: { attribution: 3 },
  by_status_class: { success: 3 },
};

describe('live activity payload parsing', () => {
  test('parses public events without dropping attribution outcomes', () => {
    const events = parseActivityEvents({ events: [publicEvent] });
    expect(events.length).toBe(1);
    expect(events[0].attribution_outcome).toBe('signature_invalid');
    expect(events[0].status_class).toBe('success');
  });

  test('rejects recent payloads without an events array', () => {
    expect(() => parseActivityEvents({ items: [] })).toThrow(
      'Activity recent payload does not expose an events array',
    );
  });

  test('rejects events outside the strict public schema', () => {
    expect(() => parseActivityEvents({ events: [{ ...publicEvent, agent_id: 'agent_private' }] })).toThrow();
  });

  test('parses a valid rollup payload', () => {
    expect(parseActivityRollups(rollups)).toEqual(rollups);
  });

  test('rejects rollups with missing fields', () => {
    const { by_status_class: _omitted, ...incomplete } = rollups;
    expect(() => parseActivityRollups(incomplete)).toThrow(
      'Activity rollup payload does not match the public projection schema',
    );
  });

  test('rejects non-numeric rollup buckets', () => {
    expect(() =>
      parseActivityRollups({
        ...rollups,
        by_event_type: { 'attribution.token_verified': 'three' },
      }),
    ).toThrow('Activity rollup payload does not match the public projection schema');
  });
});

describe('live activity request sequencing', () => {
  test('allows only the latest request while the effect is active', () => {
    expect(isCurrentActivityRequest(2, 2, false)).toBe(true);
    expect(isCurrentActivityRequest(1, 2, false)).toBe(false);
  });

  test('rejects every request after effect cleanup', () => {
    expect(isCurrentActivityRequest(2, 2, true)).toBe(false);
  });
});
