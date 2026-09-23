export type DocsRouteEntry = {
  contentId: string;
  publicPath: string;
};

export const docsRouteEntries = [
  { contentId: '/overview', publicPath: '/docs/overview' },
  { contentId: '/what-is-ocp', publicPath: '/docs/concepts/what-is-ocp' },
  { contentId: '/what-is-catalog', publicPath: '/docs/concepts/what-is-catalog' },
  { contentId: '/roles', publicPath: '/docs/concepts/roles' },
  { contentId: '/catalog-architecture', publicPath: '/docs/concepts/catalog-architecture' },
  { contentId: '/resolve-actions', publicPath: '/docs/concepts/resolve-actions' },
  { contentId: '/getting-started', publicPath: '/docs/getting-started' },
  { contentId: '/cli-and-skill', publicPath: '/docs/cli-and-skill' },
  { contentId: '/mcp-server', publicPath: '/docs/mcp-server' },
  { contentId: '/faq', publicPath: '/docs/faq' },
  { contentId: '/handshake/overview', publicPath: '/docs/protocols/handshake-v1/overview' },
  { contentId: '/handshake/catalog-manifest', publicPath: '/docs/protocols/handshake-v1/catalog-manifest' },
  { contentId: '/handshake/object-contract', publicPath: '/docs/protocols/handshake-v1/object-contract' },
  { contentId: '/handshake/sync-capabilities', publicPath: '/docs/protocols/handshake-v1/sync-capabilities' },
  { contentId: '/handshake/provider-registration', publicPath: '/docs/protocols/handshake-v1/provider-registration' },
  { contentId: '/handshake/commercial-object', publicPath: '/docs/protocols/handshake-v1/commercial-object' },
  { contentId: '/handshake/registration-result', publicPath: '/docs/protocols/handshake-v1/registration-result' },
  { contentId: '/registration/overview', publicPath: '/docs/protocols/registration-v1/overview' },
  { contentId: '/registration/discovery', publicPath: '/docs/protocols/registration-v1/discovery' },
  { contentId: '/registration/catalog-registration', publicPath: '/docs/protocols/registration-v1/catalog-registration' },
  { contentId: '/registration/catalog-search', publicPath: '/docs/protocols/registration-v1/catalog-search' },
  { contentId: '/registration/catalog-route-hint', publicPath: '/docs/protocols/registration-v1/catalog-route-hint' },
  { contentId: '/registration/verification-refresh', publicPath: '/docs/protocols/registration-v1/verification-refresh' },
  { contentId: '/crypto-attribution/overview', publicPath: '/docs/protocols/crypto-attribution/overview' },
  { contentId: '/examples/minimal-catalog', publicPath: '/docs/examples/minimal-catalog' },
  { contentId: '/examples/minimal-provider', publicPath: '/docs/examples/minimal-provider' },
  { contentId: '/examples/shopify-provider', publicPath: '/docs/examples/shopify-provider' },
  { contentId: '/examples/registration-flow', publicPath: '/docs/examples/registration-flow' },
  { contentId: '/examples/commerce-catalog', publicPath: '/docs/examples/commerce-catalog' },
  { contentId: '/examples/provider-flow', publicPath: '/docs/examples/provider-flow' },
  { contentId: '/examples/user-agent-flow', publicPath: '/docs/examples/user-agent-flow' },
  { contentId: '/examples/woocommerce-overview', publicPath: '/docs/examples/woocommerce-overview' },
  { contentId: '/examples/webmcp-demo', publicPath: '/docs/examples/webmcp-demo' },
  { contentId: '/examples/visa-vic-reference-agent', publicPath: '/docs/examples/visa-vic-reference-agent' },
  { contentId: '/protocol-principles', publicPath: '/docs/principles/protocol-principles' },
  { contentId: '/query-contract-principles', publicPath: '/docs/principles/query-contract-principles' },
  { contentId: '/routing-principles', publicPath: '/docs/principles/routing-principles' },
] satisfies DocsRouteEntry[];

const publicPathToContentId = new Map(docsRouteEntries.map((entry) => [entry.publicPath, entry.contentId]));
const contentIdToPublicPath = new Map(docsRouteEntries.map((entry) => [entry.contentId, entry.publicPath]));

function ensureLeadingSlash(path: string): string {
  return path.startsWith('/') ? path : `/${path}`;
}

function trimSlashes(path: string): string {
  return path.replace(/^\/+|\/+$/g, '');
}

export function stripLocalePrefix(pathname: string): string {
  const normalized = ensureLeadingSlash(pathname);

  if (normalized === '/zh') {
    return '/';
  }

  if (normalized.startsWith('/zh/')) {
    return normalized.slice(3) || '/';
  }

  return normalized;
}

export function addLocalePrefix(pathname: string, locale: 'en' | 'zh'): string {
  const normalized = ensureLeadingSlash(stripLocalePrefix(pathname));

  if (locale === 'zh') {
    return normalized === '/' ? '/zh' : `/zh${normalized}`;
  }

  return normalized;
}

export function stripDocsPrefix(pathname: string): string {
  const withoutLocale = stripLocalePrefix(pathname);

  if (withoutLocale === '/docs') {
    return '/overview';
  }

  if (withoutLocale.startsWith('/docs/')) {
    return withoutLocale.slice('/docs'.length);
  }

  return withoutLocale;
}

export function docsPublicPathToContentId(pathname: string): string {
  const publicPath = stripLocalePrefix(pathname);

  if (publicPath === '/docs') {
    return '/overview';
  }

  return publicPathToContentId.get(publicPath) ?? ensureLeadingSlash(stripDocsPrefix(publicPath));
}

export function docsContentIdToPublicPath(contentId: string): string {
  const normalized = ensureLeadingSlash(contentId);
  return contentIdToPublicPath.get(normalized) ?? `/docs/${trimSlashes(normalized)}`;
}

export function docsPublicPathToContentModule(pathname: string): string {
  const contentId = docsPublicPathToContentId(pathname);
  const route = trimSlashes(contentId);

  if (!route) {
    return './docs/overview.md';
  }

  const segments = route.split('/');

  if (segments.length === 1) {
    return `./docs/${segments[0]}.md`;
  }

  const [section, ...rest] = segments;
  return `./${section}/${rest.join('/')}.md`;
}
