import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { artifactRegistry } from '../apps/ocp-site-web/src/content/artifacts';
import { coreArtifacts } from '../apps/ocp-site-web/src/content/artifacts/core';
import { cryptoArtifacts } from '../apps/ocp-site-web/src/content/artifacts/crypto';
import { examplesArtifacts } from '../apps/ocp-site-web/src/content/artifacts/examples';
import { handshakeArtifacts } from '../apps/ocp-site-web/src/content/artifacts/handshake';
import { registrationArtifacts } from '../apps/ocp-site-web/src/content/artifacts/registration';
import { navigation } from '../apps/ocp-site-web/src/content/navigation';
import { docsContentIdToPublicPath, docsPublicPathToContentId, docsPublicPathToContentModule } from '../apps/ocp-site-web/src/content/routing';
import { updates } from '../apps/ocp-site-web/src/content/updates';
import { updateContentCandidates } from '../apps/ocp-site-web/src/content/updates-content';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const contentRoot = path.join(repoRoot, 'apps/ocp-site-web/src/content');
const sitePublicRoot = path.join(repoRoot, 'apps/ocp-site-web/public');

function fail(message: string): never {
  throw new Error(message);
}

function routeToContentPath(route: string, locale?: 'zh'): string {
  const modulePath = docsPublicPathToContentModule(route).replace(/^\.\//, '');
  const prefix = locale ? path.join('locales', locale) : '';
  return path.join(contentRoot, prefix, modulePath);
}

function walkMarkdown(dir: string): string[] {
  if (!existsSync(dir)) {
    return [];
  }

  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      return walkMarkdown(absolute);
    }
    return entry.isFile() && entry.name.endsWith('.md') ? [absolute] : [];
  });
}

function walkFiles(dir: string, extensions: Set<string>): string[] {
  if (!existsSync(dir)) {
    return [];
  }

  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    // Skip dependency, build, and local scratch directories — only repo content
    // should be scanned for docs integrity.
    const skip = new Set([
      'node_modules',
      'dist',
      '.git',
      '.turbo',
      '.workspace',
      '.codegraph',
      'tmp',
      'output',
    ]);
    if (skip.has(entry.name)) {
      return [];
    }

    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      return walkFiles(absolute, extensions);
    }

    return entry.isFile() && extensions.has(path.extname(entry.name)) ? [absolute] : [];
  });
}

function stripAnchor(link: string): string {
  return link.split('#')[0] ?? link;
}

function shouldSkipLink(link: string): boolean {
  return (
    link.startsWith('http://') ||
    link.startsWith('https://') ||
    link.startsWith('#') ||
    link.startsWith('mailto:') ||
    link.startsWith('tel:')
  );
}

const navRoutes = new Set<string>();
const navContentIds = new Set<string>();
for (const group of navigation) {
  for (const link of group.links) {
    navRoutes.add(link.href);
    navContentIds.add(docsPublicPathToContentId(link.href));
  }
}

const errors: string[] = [];

const artifactRouteCounts = new Map<string, string[]>();
for (const [groupName, group] of [
  ['core', coreArtifacts],
  ['crypto', cryptoArtifacts],
  ['handshake', handshakeArtifacts],
  ['registration', registrationArtifacts],
  ['examples', examplesArtifacts],
] as const) {
  for (const route of Object.keys(group)) {
    artifactRouteCounts.set(route, [...(artifactRouteCounts.get(route) ?? []), groupName]);
  }
}

for (const [route, groups] of artifactRouteCounts) {
  if (groups.length > 1) {
    errors.push(`Duplicate artifact route ${route} in groups: ${groups.join(', ')}`);
  }
}

for (const route of navRoutes) {
  const contentId = docsPublicPathToContentId(route);
  const publicPath = docsContentIdToPublicPath(contentId);
  if (publicPath !== route) {
    errors.push(`Docs route round-trip mismatch: ${route} -> ${contentId} -> ${publicPath}`);
  }

  for (const locale of [undefined, 'zh'] as const) {
    const markdownPath = routeToContentPath(route, locale);
    if (!existsSync(markdownPath)) {
      errors.push(`Missing ${locale ? `${locale} ` : ''}markdown for route ${route}: ${path.relative(repoRoot, markdownPath)}`);
    }
  }
}

for (const [route, definition] of Object.entries(artifactRegistry)) {
  if (!navContentIds.has(route)) {
    errors.push(`Artifact route is not in navigation: ${route}`);
  }

  if (!existsSync(routeToContentPath(docsContentIdToPublicPath(route)))) {
    errors.push(`Artifact route has no markdown page: ${route}`);
  }

  for (const section of definition.schemaSections ?? []) {
    const schemaPath = path.join(repoRoot, section.sourcePath);
    if (!existsSync(schemaPath)) {
      errors.push(`Missing schema referenced by ${route}: ${section.sourcePath}`);
    }
  }

  for (const ref of definition.implementationRefs ?? []) {
    // Refs with an href point at source in the ocp-catalog-instances repo and
    // are validated by their URL, not by local existence.
    if (ref.href) {
      if (!ref.href.startsWith('https://') && !ref.href.startsWith('http://')) {
        errors.push(`Invalid implementation ref href referenced by ${route}: ${ref.href}`);
      }
      continue;
    }
    const refPath = path.join(repoRoot, ref.path);
    if (!existsSync(refPath)) {
      errors.push(`Missing implementation ref referenced by ${route}: ${ref.path}`);
    }
  }
}

for (const markdownPath of walkMarkdown(contentRoot)) {
  const relative = path.relative(contentRoot, markdownPath).replace(/\\/g, '/');
  const content = readFileSync(markdownPath, 'utf8');

  const isLocale = relative.startsWith('locales/');
  // Update posts live under updates/ and are surfaced via the /updates index +
  // the updates registry (updates.ts), not the top navigation. Treat a post as
  // reachable when its slug is registered.
  const isUpdatePost = relative.startsWith('updates/');
  if (!isLocale && !isUpdatePost && relative !== 'README.md') {
    const route = relative.startsWith('docs/')
      ? `/${relative.replace(/^docs\//, '').replace(/\.md$/, '')}`
      : `/${relative.replace(/\.md$/, '')}`;
    if (!navContentIds.has(route)) {
      errors.push(`Markdown page is not reachable from navigation: ${relative}`);
    }
  }

  if (isUpdatePost && !relative.startsWith('updates/locales/')) {
    const slug = relative.replace(/^updates\//, '').replace(/\.md$/, '');
    if (!updates.some((update) => update.slug === slug)) {
      errors.push(`Update markdown ${relative} is not registered in updates.ts`);
    }
  }

  const links = content.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g);
  for (const match of links) {
    const rawLink = match[1]?.trim();
    if (!rawLink || shouldSkipLink(rawLink)) {
      continue;
    }

    const target = stripAnchor(rawLink);
    if (!target) {
      continue;
    }

    if (target.startsWith('/images/') || target.startsWith('images/')) {
      const publicAssetPath = path.join(sitePublicRoot, target.replace(/^\/+/, ''));
      if (!existsSync(publicAssetPath)) {
        errors.push(`Broken site image link in ${relative}: ${rawLink}`);
      }
      continue;
    }

    if (target.startsWith('/')) {
      if (target === '/docs' || target === '/updates') {
        continue;
      }

      if (target.startsWith('/updates/')) {
        const updateSlug = target.replace(/^\/updates\//, '').split('/')[0];
        if (!updates.some((update) => update.slug === updateSlug)) {
          errors.push(`Broken site update link in ${relative}: ${rawLink}`);
        }
        continue;
      }

      const publicPath = docsContentIdToPublicPath(docsPublicPathToContentId(target));
      if (!existsSync(routeToContentPath(publicPath))) {
        errors.push(`Broken site docs link in ${relative}: ${rawLink}`);
      }
      continue;
    }

    const resolved = path.resolve(path.dirname(markdownPath), target);
    if (!existsSync(resolved)) {
      errors.push(`Broken relative site link in ${relative}: ${rawLink}`);
    }
  }
}

const updateSlugs = new Set<string>();
let previousUpdateDate = '';
for (const update of updates) {
  if (updateSlugs.has(update.slug)) {
    errors.push(`Duplicate update slug: ${update.slug}`);
  }

  updateSlugs.add(update.slug);

  if (!/^\d{4}-\d{2}-\d{2}$/.test(update.publishedAt)) {
    errors.push(`Update ${update.slug} has invalid publishedAt date: ${update.publishedAt}`);
  }

  if (!update.title.en || !update.title.zh || !update.summary.en || !update.summary.zh) {
    errors.push(`Update ${update.slug} is missing bilingual title or summary`);
  }

  if (previousUpdateDate && update.publishedAt > previousUpdateDate) {
    errors.push(`Updates are not sorted newest-first near ${update.slug}`);
  }

  previousUpdateDate = update.publishedAt;

  for (const locale of ['en', 'zh'] as const) {
    const candidates = updateContentCandidates(update.slug, locale);
    if (!candidates.some((candidate) => existsSync(path.join(contentRoot, candidate.replace(/^\.\//, ''))))) {
      errors.push(`Update ${update.slug} is missing ${locale} markdown body`);
    }
  }
}

const obsoletePathPatterns = [
  /docs\/ocp_catalog_handshake_protocol_v1\.md/,
  /docs\/ocp_catalog_registration_protocol_v1\.md/,
  /docs\/ocp_catalog_system_design\.md/,
  /docs\/repo-architecture\.md/,
  /docs\/design_v2\.md/,
  /docs\/skills\/ocp-catalog-agent/,
  /docs\/superpowers/,
];

for (const textPath of walkFiles(repoRoot, new Set(['.md', '.ts', '.tsx', '.json']))) {
  const relative = path.relative(repoRoot, textPath).replace(/\\/g, '/');
  const content = readFileSync(textPath, 'utf8');

  for (const pattern of obsoletePathPatterns) {
    if (pattern.test(content)) {
      errors.push(`Obsolete docs path pattern ${pattern} found in ${relative}`);
    }
  }
}

for (const markdownPath of walkMarkdown(path.join(repoRoot, 'docs'))) {
  const relative = path.relative(repoRoot, markdownPath).replace(/\\/g, '/');
  const content = readFileSync(markdownPath, 'utf8');
  const links = content.matchAll(/\[[^\]]+\]\(([^)]+)\)/g);

  for (const match of links) {
    const rawLink = match[1]?.trim();
    if (!rawLink || shouldSkipLink(rawLink)) {
      continue;
    }

    const target = stripAnchor(rawLink);
    if (!target) {
      continue;
    }

    const resolved = path.resolve(path.dirname(markdownPath), target);
    if (!existsSync(resolved)) {
      errors.push(`Broken docs markdown link in ${relative}: ${rawLink}`);
    }
  }
}

if (errors.length > 0) {
  fail(`Docs integrity check failed:\n${errors.map((error) => `- ${error}`).join('\n')}`);
}

console.log(`Site integrity check passed: ${navRoutes.size} docs routes, ${Object.keys(artifactRegistry).length} artifact entries, ${updates.length} updates.`);
