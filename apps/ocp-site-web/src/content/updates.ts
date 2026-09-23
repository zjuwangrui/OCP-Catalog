import type { LocalizedText } from './i18n';

export type UpdateCategory = 'Protocol' | 'Implementation' | 'Examples' | 'Docs';

export type SiteUpdate = {
  slug: string;
  publishedAt: string;
  category: UpdateCategory;
  version?: string;
  breaking: boolean;
  tags: string[];
  title: LocalizedText;
  summary: LocalizedText;
  /** Optional cover image, relative path under public/ (e.g. images/site/x.png). */
  cover?: string;
};

export const updates: SiteUpdate[] = [
  {
    slug: 'crypto-attribution-closeout',
    publishedAt: '2026-10-09',
    category: 'Protocol',
    version: 'v1.0',
    breaking: false,
    tags: ['crypto', 'signatures', 'attribution', 'activity'],
    title: {
      en: 'Signed protocol documents and commercial attribution are now documented',
      zh: '签名协议文档与商业归因现已形成完整文档',
    },
    summary: {
      en: 'A new bilingual guide connects signed manifests, trust verification, multi-hop attribution, durable settlement contracts, and the privacy boundary of public activity projections.',
      zh: '新的双语指南串联签名 manifest、信任验证、多跳归因、持久化结算契约和公开 activity 投影的隐私边界。',
    },
  },
  {
    slug: 'ocp-catalog-integrates-agent-platforms',
    publishedAt: '2026-05-29',
    category: 'Implementation',
    breaking: false,
    tags: ['coze', 'qclaw', 'agent-platform', 'integration'],
    title: {
      en: 'OCP Catalog is being integrated into agent platforms like Coze and QClaw',
      zh: 'OCP Catalog 正在接入 Coze、QClaw 等智能体平台',
    },
    summary: {
      en: 'The OCP Catalog plugin is being integrated and adapted across agent platforms such as Coze and QClaw, so their agents can discover catalog objects while the final deal still returns to the merchant.',
      zh: 'OCP Catalog 插件正在接入、适配 Coze、QClaw 等智能体平台，让平台上的 Agent 可以发现 Catalog 对象，而最终成交仍回到商家侧。',
    },
  },
  {
    slug: 'ocp-cli-and-skill-coming-soon',
    publishedAt: '2026-05-29',
    category: 'Implementation',
    version: 'cli-0.1.2',
    breaking: false,
    tags: ['cli', 'skill', 'tooling', 'manifest-validation'],
    title: {
      en: 'OCP CLI and agent skill are now published on npm',
      zh: 'OCP CLI 与 Agent skill 已发布到 npm',
    },
    summary: {
      en: 'A CLI and an agent skill give agents a correct, repeatable way to drive the OCP workflow, including manifest-based request validation. Install them from npm or run the CLI directly with npx.',
      zh: 'CLI 与 Agent skill 让 Agent 以正确、可复用的方式驱动 OCP 工作流，并带 manifest 请求校验。现在可以从 npm 安装，也可以用 npx 直接运行。',
    },
  },
  {
    slug: 'shopify-provider-app-syncs-merchant-products',
    publishedAt: '2026-05-29',
    category: 'Implementation',
    version: 'provider-app-v1',
    breaking: false,
    tags: ['shopify', 'provider-app', 'merchant-products', 'commerce'],
    title: {
      en: 'Shopify merchant products can now flow into OCP catalogs',
      zh: 'Shopify 商家的商品现在可以同步进 OCP Catalog',
    },
    summary: {
      en: 'The Shopify provider app turns an installed merchant store into an OCP Provider, registers it with a catalog, and syncs products so agents can discover the items while the final deal still returns to the merchant storefront.',
      zh: 'Shopify provider app 会把已安装的商家店铺变成 OCP Provider，注册到合适的 Catalog，并同步商品，让 Agent 可以发现商品，而最终交易仍回到商家店铺页面完成。',
    },
  },
  {
    slug: 'woocommerce-provider-app-opens-wordpress-commerce-to-ocp',
    publishedAt: '2026-05-29',
    category: 'Implementation',
    version: 'provider-app-v1',
    breaking: false,
    tags: ['woocommerce', 'provider-app', 'wordpress', 'commerce'],
    title: {
      en: 'WooCommerce stores can publish products through an OCP Provider app',
      zh: 'WooCommerce 店铺可以通过 OCP Provider App 发布商品',
    },
    summary: {
      en: 'The WooCommerce provider app mirrors the Shopify flow over WooCommerce REST: it registers the merchant, syncs products and variations, handles webhooks, and sends catalog traffic back to the store page for the final deal.',
      zh: 'WooCommerce provider app 通过 WooCommerce REST 复用 Shopify 同类流程：注册商家、同步商品和变体、处理 webhook，并把最终成交流量带回店铺商品页面。',
    },
  },
  {
    slug: 'unified-public-site',
    publishedAt: '2026-05-28',
    category: 'Docs',
    version: 'site-v1',
    breaking: true,
    tags: ['website', 'docs', 'information-architecture'],
    title: {
      en: 'OCP Catalog now has a clearer home for visitors and builders',
      zh: 'OCP Catalog 现在有了更清晰的访客与开发者入口',
    },
    summary: {
      en: 'The site now introduces OCP in plain language, keeps docs available under a dedicated area, and collects project progress in one public place.',
      zh: '站点现在会先用直观语言介绍 OCP，同时保留独立文档区，并把项目进展集中展示在公开页面。',
    },
  },
  {
    slug: 'catalog-handshake-and-registration-v1',
    publishedAt: '2026-05-25',
    category: 'Protocol',
    version: 'v1.0-dev',
    breaking: false,
    tags: ['handshake', 'registration', 'schema'],
    title: {
      en: 'Handshake v1 and Registration v1 docs are published as first-class protocol areas',
      zh: 'Handshake v1 与 Registration v1 文档成为一等协议区域',
    },
    summary: {
      en: 'The protocol docs now separate provider handshake contracts from registration discovery contracts, while preserving schema fragments and repo implementation references.',
      zh: '协议文档将 provider handshake contract 与 registration discovery contract 分层呈现，同时保留 schema 片段和仓库实现引用。',
    },
  },
  {
    slug: 'commerce-examples-expanded',
    publishedAt: '2026-05-24',
    category: 'Examples',
    version: 'examples-v1',
    breaking: false,
    tags: ['catalog', 'provider', 'agent'],
    title: {
      en: 'Commerce examples expanded across catalog, provider, and agent flows',
      zh: '电商示例扩展到 Catalog、Provider 和 Agent 流程',
    },
    summary: {
      en: 'Minimal catalog/provider examples, Shopify-style provider onboarding, WebMCP demo notes, and reference agent flows now live together under the docs examples area.',
      zh: '最小 Catalog/Provider、Shopify 风格 provider onboarding、WebMCP demo 说明和参考 Agent 流程现在统一放在文档示例区域。',
    },
  },
];

export const updateCategoryLabels: Record<UpdateCategory, LocalizedText> = {
  Protocol: { en: 'Protocol', zh: '协议' },
  Implementation: { en: 'Implementation', zh: '实现' },
  Examples: { en: 'Examples', zh: '示例' },
  Docs: { en: 'Docs', zh: '文档' },
};

export const breakingChangeLabel: LocalizedText = {
  en: 'Major update',
  zh: '重要更新',
};

export function getUpdateBySlug(slug: string | undefined): SiteUpdate | undefined {
  return updates.find((update) => update.slug === slug);
}
