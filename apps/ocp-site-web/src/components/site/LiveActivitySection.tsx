import { useMemo, type CSSProperties } from 'react';
import { AlertTriangle, Radio } from 'lucide-react';
import { useLiveActivity, type PublicActivityEvent } from '../../lib/useLiveActivity';
import { attributionOutcomePresentation } from '../../lib/activityPresentation';
import { useDocsLocale, type DocsLocale } from '../../content/i18n';

const familyTone: Record<string, string> = {
  ocp: 'var(--ocp-cyan)',
  webmcp: 'var(--ocp-green)',
  agent_card: 'var(--ocp-gold)',
  feed: 'var(--ocp-vermilion)',
};

function formatTime(value: string) {
  return new Date(value).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function statusTone(statusClass: string) {
  if (statusClass === 'success') return 'border-emerald-300/30 text-emerald-200';
  if (statusClass === 'client_error' || statusClass === 'policy_denied') return 'border-amber-300/30 text-amber-200';
  if (statusClass === 'server_error') return 'border-red-300/35 text-red-200';
  return 'border-white/14 text-[var(--text-muted)]';
}

export function LiveActivitySection() {
  const { locale } = useDocsLocale();
  const { events, rollups, status, error } = useLiveActivity({ limit: 12, windowHours: 24, pollMs: 15_000 });

  const topTypes = useMemo(
    () =>
      Object.entries(rollups?.by_event_type ?? {})
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5),
    [rollups],
  );

  const copy =
    locale === 'zh'
      ? {
          kicker: '实时协议活动',
          headline: '协议正在跑，不只是文档。',
          description:
            '官网读取脱敏后的 OCP activity 公开投影，展示真实调用类型、协议族分布与健康趋势 — 让你直观看到 OCP 在生产环境的形态。',
          events: '最近事件',
          rollups: '24 小时聚合 · 事件类型',
          empty: '还没有公开活动事件。',
          unavailable: 'Activity API 暂不可用。启动 `bun run activity:api` 并执行迁移后刷新。',
          metricEvents: '事件总数',
          metricProtocols: '协议族',
          metricWindow: '观测窗口',
          offline: '离线',
          loading: '同步中',
          sourceUnavailable: '公开 Activity 投影不可用',
          sourceReady: '公开投影已连接',
        }
      : {
          kicker: 'Live protocol activity',
          headline: 'The protocol is running, not just documented.',
          description:
            'The site reads only redacted OCP activity projections — real call types, protocol family distribution, and health signals.',
          events: 'Recent events',
          rollups: '24h rollup · event types',
          empty: 'No public activity events yet.',
          unavailable: 'Activity API is unavailable. Start `bun run activity:api`, run migrations, then refresh.',
          metricEvents: 'Events',
          metricProtocols: 'Protocols',
          metricWindow: 'Window',
          offline: 'Offline',
          loading: 'Syncing',
          sourceUnavailable: 'Public activity projection unavailable',
          sourceReady: 'Public projection connected',
        };

  const protocolCount = Object.keys(rollups?.by_protocol_family ?? {}).length;
  const sourceLabel =
    status === 'loading' ? copy.loading : status === 'error' ? copy.sourceUnavailable : copy.sourceReady;
  const metrics = [
    { label: copy.metricEvents, value: status === 'error' ? copy.offline : status === 'loading' ? '...' : (rollups?.event_count ?? 0) },
    { label: copy.metricProtocols, value: status === 'error' ? '-' : status === 'loading' ? '...' : protocolCount },
    { label: copy.metricWindow, value: status === 'error' ? '-' : `${rollups?.window_hours ?? 24}h` },
  ];

  return (
    <div className="site-container live-observatory">
      <div className="reveal-on-scroll grid gap-10 border-y border-white/10 py-10 lg:grid-cols-[1.05fr_0.95fr] lg:items-end">
        <div>
          <div className="mono-kicker inline-flex items-center gap-2 text-[var(--ocp-cyan)]/80">
            <Radio className="h-3.5 w-3.5 text-[var(--ocp-cyan)]" />
            {copy.kicker}
          </div>
          <h2 className="mt-5 max-w-3xl text-[clamp(2.4rem,5vw,4.8rem)] font-semibold leading-[1.02] tracking-[-0.02em] text-white">
            {copy.headline}
          </h2>
          <p className="mt-4 max-w-xl text-base leading-7 text-[var(--text-muted)]">{copy.description}</p>
        </div>

        <div className="space-y-6">
          <div className="flex items-center justify-between border-b border-white/10 pb-3 font-mono text-[11px] uppercase tracking-[0.24em] text-white/46">
            <span>{sourceLabel}</span>
            <span className={status === 'error' ? 'text-red-200' : 'text-[var(--ocp-cyan)]'}>
              {status === 'error' ? copy.offline : 'Live'}
            </span>
          </div>
          <div className="grid grid-cols-3 gap-6">
            {metrics.map((metric) => (
              <Metric key={metric.label} label={metric.label} value={metric.value} />
            ))}
          </div>
        </div>
      </div>

      <div className="reveal-on-scroll mt-12 grid gap-12 lg:grid-cols-[20rem_1fr]" style={{ '--reveal-delay': '120ms' } as CSSProperties}>
        <aside className="space-y-5">
          <h3 className="mono-kicker">{copy.rollups}</h3>
          <div className="space-y-1 border-t border-white/10">
            {topTypes.length > 0 ? (
              topTypes.map(([eventType, count], idx) => {
                const max = topTypes[0][1] || 1;
                const ratio = count / max;
                return (
                  <div key={eventType} className={`py-4 ${idx > 0 ? 'border-t border-white/10' : ''}`}>
                    <div className="flex items-center justify-between gap-3">
                      <span className="min-w-0 truncate text-sm font-medium text-white/72">{eventType}</span>
                      <span className="font-mono text-xs font-semibold tabular-nums text-white/48">{count}</span>
                    </div>
                    <div className="mt-2 h-px overflow-hidden bg-white/10">
                      <div
                        className="h-full bg-[var(--ocp-cyan)] transition-all duration-700"
                        style={{ width: `${Math.max(6, ratio * 100)}%` }}
                      />
                    </div>
                  </div>
                );
              })
            ) : (
              <p className="border-t border-white/10 pt-4 text-sm text-[var(--text-faint)]">
                {status === 'error' ? `${copy.unavailable} ${error ?? ''}`.trim() : copy.empty}
              </p>
            )}
          </div>
        </aside>

        <div>
          <div className="mb-5 flex items-center justify-between">
            <h3 className="mono-kicker">{copy.events}</h3>
            {status === 'error' ? (
              <span className="inline-flex items-center gap-1.5 border border-red-300/30 px-2.5 py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-red-200">
                <AlertTriangle className="h-3.5 w-3.5" />
                {copy.offline}
              </span>
            ) : null}
          </div>

          {status === 'error' ? (
            <div className="border-y border-red-300/25 py-8 text-sm leading-7 text-red-100">
              {copy.unavailable}
              {error ? <span className="mt-3 block font-mono text-xs text-red-100/70">{error}</span> : null}
            </div>
          ) : events.length === 0 ? (
            <div className="border-y border-white/10 py-10 text-center text-sm text-[var(--text-faint)]">
              {copy.empty}
            </div>
          ) : (
            <ul className="border-y border-white/10">
              {events.slice(0, 8).map((event) => (
                <EventRow key={event.public_event_id} event={event} locale={locale} />
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="border-t border-white/10 pt-4">
      <div className="font-mono text-3xl font-semibold tabular-nums text-white">{value}</div>
      <div className="mt-2 text-[11px] font-semibold uppercase tracking-[0.2em] text-[var(--text-faint)]">{label}</div>
    </div>
  );
}

function EventRow({ event, locale }: { event: PublicActivityEvent; locale: DocsLocale }) {
  const tone = familyTone[event.protocol_family] ?? 'var(--ocp-ink)';
  const attribution = attributionOutcomePresentation(event.attribution_outcome, locale);
  return (
    <li className="grid gap-3 border-b border-white/10 py-4 last:border-0 md:grid-cols-[9rem_1fr_12rem]">
      <div className="flex items-center gap-2">
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: tone }} />
        <time className="font-mono text-xs tabular-nums text-[var(--text-faint)]">{formatTime(event.occurred_at)}</time>
      </div>
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="border border-white/12 px-2 py-0.5 font-mono text-[11px] font-semibold text-white/82">
            {event.event_type}
          </span>
          <span className="border border-white/10 px-2 py-0.5 text-[11px] font-medium text-[var(--text-muted)]">
            {event.protocol_family}
          </span>
          <span className="border border-white/10 px-2 py-0.5 text-[11px] font-medium text-[var(--text-muted)]">
            {event.source_kind}
          </span>
        </div>
        <p className="mt-1.5 truncate text-sm text-[var(--text-muted)]">{event.public_summary}</p>
      </div>
      <div className="flex flex-wrap gap-1.5 text-left md:justify-end md:text-right">
        <span className={`inline-flex border px-2 py-0.5 font-mono text-[11px] font-bold uppercase tracking-[0.12em] ${statusTone(event.status_class)}`}>
          {event.status_class}
        </span>
        {attribution ? (
          <span
            aria-label={attribution.ariaLabel}
            className={`inline-flex border px-2 py-0.5 text-[11px] font-semibold ${
              attribution.tone === 'success'
                ? 'border-emerald-300/30 text-emerald-200'
                : 'border-amber-300/35 text-amber-100'
            }`}
          >
            {attribution.label}
          </span>
        ) : null}
      </div>
    </li>
  );
}
