import { describe, expect, test } from 'bun:test';
import { AppError } from './index';

describe('AppError', () => {
  test('preserves error identity and fields', () => {
    const details = { field: 'query' };
    const error = new AppError('validation_error', 'Invalid query', 400, details);

    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(AppError);
    expect(error.name).toBe('AppError');
    expect(error.message).toBe('Invalid query');
    expect(error.code).toBe('validation_error');
    expect(error.status).toBe(400);
    expect(error.details).toBe(details);
  });

  test('uses the internal-error status by default', () => {
    const error = new AppError('internal_error', 'Unexpected failure');

    expect(error.status).toBe(500);
    expect(error.details).toBeUndefined();
  });
});
