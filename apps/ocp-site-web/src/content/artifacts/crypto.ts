import type { PageArtifactDefinition } from './types';

export const cryptoArtifacts: Record<string, PageArtifactDefinition> = {
  '/crypto-attribution/overview': {
    implementationRefs: [
      {
        label: { en: 'Canonical JSON and document signatures', zh: 'Canonical JSON 与文档签名' },
        path: 'packages/ocp-crypto/src/signature.ts',
      },
      {
        label: { en: 'Attribution chain verification', zh: '归因链验证' },
        path: 'packages/ocp-crypto/src/verify.ts',
      },
      {
        label: { en: 'Replay and settlement store contracts', zh: '重放与结算存储契约' },
        path: 'packages/ocp-crypto/src/stores.ts',
      },
      {
        label: { en: 'Public activity projection', zh: '公开 activity 投影' },
        path: 'packages/ocp-activity-schema/src/index.ts',
      },
      {
        label: { en: 'CLI verification command', zh: 'CLI 验证命令' },
        path: 'packages/ocp-cli/src/inspect-verify.ts',
      },
    ],
    endpointExamples: [
      {
        title: { en: 'Verify a signed Catalog manifest', zh: '验证带签名的 Catalog manifest' },
        method: 'GET',
        path: '/ocp/manifest',
        headers: { accept: 'application/json' },
        note: {
          en: 'Fetch the document, then verify its signature and trust policy with the CLI or ocp-crypto.',
          zh: '获取文档后，使用 CLI 或 ocp-crypto 验证签名与 trust policy。',
        },
      },
      {
        title: { en: 'Read public activity projection', zh: '读取公开 activity 投影' },
        method: 'GET',
        path: '/api/activity/recent?limit=40',
        response: {
          events: [
            {
              event_type: 'attribution.token_verified',
              correlation_id_hash: 'hmac-sha256:<keyed-digest>',
              attribution_outcome: 'ok',
            },
          ],
        },
        note: {
          en: 'The public row does not contain raw attribution subjects.',
          zh: '公开行不包含 raw attribution 主体。',
        },
      },
    ],
  },
};
