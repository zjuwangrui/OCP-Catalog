import { useEffect, useState } from 'react';
import {
  isCurrentActivityRequest,
  parseActivityEvents,
  parseActivityRollups,
  type ActivityRollups,
  type PublicActivityEvent,
} from './activityData';

export type { ActivityRollups, PublicActivityEvent } from './activityData';

export type LiveActivityStatus = 'loading' | 'ready' | 'error';

const activityApiUrl = (
  import.meta.env.VITE_OCP_ACTIVITY_API_URL ?? 'http://localhost:4400'
).replace(/\/+$/, '');

type Options = {
  limit?: number;
  windowHours?: number;
  pollMs?: number;
};

export function useLiveActivity({ limit = 40, windowHours = 24, pollMs = 15_000 }: Options = {}) {
  const [events, setEvents] = useState<PublicActivityEvent[]>([]);
  const [rollups, setRollups] = useState<ActivityRollups | null>(null);
  const [status, setStatus] = useState<LiveActivityStatus>('loading');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let latestRequestId = 0;

    async function load() {
      const requestId = ++latestRequestId;
      try {
        const [recentResponse, rollupResponse] = await Promise.all([
          fetch(`${activityApiUrl}/api/activity/recent?limit=${limit}`),
          fetch(`${activityApiUrl}/api/activity/rollups?hours=${windowHours}`),
        ]);

        if (!recentResponse.ok || !rollupResponse.ok) throw new Error('Activity API unavailable');
        const recentPayload = await recentResponse.json();
        const rollupPayload = await rollupResponse.json();
        const parsedEvents = parseActivityEvents(recentPayload);
        const parsedRollups = parseActivityRollups(rollupPayload);
        if (!isCurrentActivityRequest(requestId, latestRequestId, cancelled)) return;

        setEvents(parsedEvents);
        setRollups(parsedRollups);
        setError(null);
        setStatus('ready');
      } catch (loadError) {
        if (isCurrentActivityRequest(requestId, latestRequestId, cancelled)) {
          setError(loadError instanceof Error ? loadError.message : 'Activity API unavailable');
          setStatus('error');
        }
      }
    }

    void load();
    const timer = setInterval(load, pollMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [limit, windowHours, pollMs]);

  return { events, rollups, status, error };
}
