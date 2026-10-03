/** Strict RFC 3339 UTC instants accepted in signed protocol material. */
const RFC3339_UTC_INSTANT =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;

/**
 * Parses a UTC RFC 3339 instant without relying on Date's implementation-defined
 * acceptance of offsets, spaces, missing components, or normalized dates.
 */
export function parseStrictRfc3339UtcInstant(value: unknown): Date | undefined {
  if (typeof value !== 'string') return undefined;
  const match = RFC3339_UTC_INSTANT.exec(value);
  if (!match) return undefined;

  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction = ''] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
    return undefined;
  }

  const millisecond = Number(`${fraction}000`.slice(0, 3));
  const parsed = new Date(0);
  parsed.setUTCFullYear(year, month - 1, day);
  parsed.setUTCHours(hour, minute, second, millisecond);
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day ||
    parsed.getUTCHours() !== hour ||
    parsed.getUTCMinutes() !== minute ||
    parsed.getUTCSeconds() !== second
  ) {
    return undefined;
  }
  return parsed;
}

export function parseRfc3339Instant(value: unknown): Date | undefined {
  return parseStrictRfc3339UtcInstant(value);
}

export function isStrictRfc3339UtcInstant(value: unknown): value is string {
  return parseStrictRfc3339UtcInstant(value) !== undefined;
}

export function isValidDate(value: Date): boolean {
  return Number.isFinite(value.getTime());
}
