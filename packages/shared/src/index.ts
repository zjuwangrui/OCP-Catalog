export type JsonObject = Record<string, unknown>;

export type PaginationInput = {
  limit?: number;
  cursor?: string | null;
};

export type ApiErrorCode =
  | 'validation_error'
  | 'not_found'
  | 'unauthorized'
  | 'rate_limited'
  | 'domain_rate_limited'
  | 'crawl_failed'
  | 'internal_error';

export class AppError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number;
  readonly details?: unknown;

  constructor(code: ApiErrorCode, message: string, status = 500, details?: unknown) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function newId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replaceAll('-', '')}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function clampLimit(limit: number | undefined, fallback = 20, max = 100): number {
  if (!limit || Number.isNaN(limit)) return fallback;
  return Math.max(1, Math.min(Math.trunc(limit), max));
}

export function asArray<T>(value: T | T[] | undefined | null): T[] {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

export * from './static-site';
