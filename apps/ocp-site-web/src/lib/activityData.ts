import {
  ocpPublicActivityEventSchema,
  type OcpPublicActivityEvent,
} from '@ocp-catalog/ocp-activity-schema';

export type PublicActivityEvent = OcpPublicActivityEvent;

export type ActivityRollups = {
  window_hours: number;
  event_count: number;
  by_event_type: Record<string, number>;
  by_protocol_family: Record<string, number>;
  by_status_class: Record<string, number>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNumberRecord(value: unknown): value is Record<string, number> {
  return isRecord(value) && Object.values(value).every((item) => typeof item === 'number');
}

export function parseActivityRollups(value: unknown): ActivityRollups {
  if (
    !isRecord(value) ||
    typeof value.window_hours !== 'number' ||
    typeof value.event_count !== 'number' ||
    !isNumberRecord(value.by_event_type) ||
    !isNumberRecord(value.by_protocol_family) ||
    !isNumberRecord(value.by_status_class)
  ) {
    throw new Error('Activity rollup payload does not match the public projection schema');
  }

  return {
    window_hours: value.window_hours,
    event_count: value.event_count,
    by_event_type: value.by_event_type,
    by_protocol_family: value.by_protocol_family,
    by_status_class: value.by_status_class,
  };
}

export function parseActivityEvents(value: unknown): PublicActivityEvent[] {
  if (!isRecord(value) || !Array.isArray(value.events)) {
    throw new Error('Activity recent payload does not expose an events array');
  }

  return value.events.map((event) => ocpPublicActivityEventSchema.parse(event));
}

export function isCurrentActivityRequest(requestId: number, latestRequestId: number, cancelled: boolean): boolean {
  return !cancelled && requestId === latestRequestId;
}
