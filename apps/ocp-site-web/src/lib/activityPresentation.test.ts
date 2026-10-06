import { describe, expect, test } from 'bun:test';
import type { OcpActivityAttributionOutcome } from '@ocp-catalog/ocp-activity-schema';
import { attributionOutcomePresentation } from './activityPresentation';

const outcomes: OcpActivityAttributionOutcome[] = [
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
];

describe('attribution outcome presentation', () => {
  test('omits a badge when no attribution outcome was published', () => {
    expect(attributionOutcomePresentation(null, 'en')).toBe(null);
    expect(attributionOutcomePresentation(null, 'zh')).toBe(null);
  });

  test('distinguishes a verified attribution from a failed one', () => {
    expect(attributionOutcomePresentation('ok', 'en')).toEqual({
      label: 'Attribution · Verified',
      ariaLabel: 'Attribution outcome: Verified',
      tone: 'success',
    });
    expect(attributionOutcomePresentation('signature_invalid', 'zh')).toEqual({
      label: '归因 · 签名无效',
      ariaLabel: '归因结果：签名无效',
      tone: 'failure',
    });
  });

  test('presents every public outcome in English and Chinese', () => {
    for (const outcome of outcomes) {
      for (const locale of ['en', 'zh'] as const) {
        const presentation = attributionOutcomePresentation(outcome, locale);
        expect(presentation).not.toBe(null);
        expect(presentation!.label.length > 0).toBe(true);
        expect(presentation!.ariaLabel.length > 0).toBe(true);
        expect(presentation!.label).not.toContain(outcome);
        expect(presentation!.tone).toBe(outcome === 'ok' ? 'success' : 'failure');
      }
    }
  });

  test('never receives or interpolates raw attribution subjects', () => {
    const serialized = JSON.stringify(attributionOutcomePresentation('replayed_jti', 'en'));
    expect(serialized).not.toContain('agent_private');
    expect(serialized).not.toContain('order_private');
    expect(serialized).not.toContain('atr_private');
  });
});
