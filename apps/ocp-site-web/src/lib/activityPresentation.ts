import type { OcpActivityAttributionOutcome } from '@ocp-catalog/ocp-activity-schema';
import type { DocsLocale } from '../content/i18n';

export type AttributionOutcomeTone = 'success' | 'failure';

export type AttributionOutcomePresentation = {
  label: string;
  ariaLabel: string;
  tone: AttributionOutcomeTone;
};

type LocalizedOutcome = {
  en: string;
  zh: string;
};

const outcomeLabels: Record<OcpActivityAttributionOutcome, LocalizedOutcome> = {
  ok: { en: 'Verified', zh: '已验证' },
  chain_broken: { en: 'Broken chain', zh: '归因链断裂' },
  complete_mismatch: { en: 'Completeness mismatch', zh: '完整性标记不符' },
  alg_not_supported: { en: 'Unsupported algorithm', zh: '不支持的算法' },
  key_not_found: { en: 'Verification key not found', zh: '未找到验签密钥' },
  signature_invalid: { en: 'Invalid signature', zh: '签名无效' },
  purpose_not_settleable: { en: 'Purpose not settleable', zh: '用途不可结算' },
  provider_mismatch: { en: 'Provider mismatch', zh: '服务商不匹配' },
  token_not_yet_valid: { en: 'Token not yet valid', zh: '凭证尚未生效' },
  token_expired: { en: 'Token expired', zh: '凭证已过期' },
  replayed_jti: { en: 'Replayed token', zh: '凭证已重放' },
  duplicate_order: { en: 'Duplicate order', zh: '重复订单' },
};

export function attributionOutcomePresentation(
  outcome: OcpActivityAttributionOutcome | null,
  locale: DocsLocale,
): AttributionOutcomePresentation | null {
  if (outcome === null) return null;

  const outcomeLabel = outcomeLabels[outcome][locale];
  return {
    label: locale === 'zh' ? `归因 · ${outcomeLabel}` : `Attribution · ${outcomeLabel}`,
    ariaLabel: locale === 'zh' ? `归因结果：${outcomeLabel}` : `Attribution outcome: ${outcomeLabel}`,
    tone: outcome === 'ok' ? 'success' : 'failure',
  };
}
