#!/usr/bin/env bun
import { readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import {
  OcpClient,
  OcpClientError,
  OcpClientValidationError,
  createCorrelationId,
  validateCatalogQueryRequest,
} from '@ocp-catalog/ocp-client';
import {
  catalogManifestSchema,
  catalogQueryRequestSchema,
  objectSyncRequestSchema,
  providerRegistrationSchema,
  resolveRequestSchema,
  type CatalogManifest,
} from '@ocp-catalog/ocp-schema';
import { doctorOcpSkill, installOcpSkill, uninstallOcpSkill, type SkillTarget } from './skill-installer';
import {
  checkResolveBinding,
  extractAttributionToken,
  parseJwksSpec,
  requiredCatalogIds,
  verifyAttributionPayload,
} from './attribution';
import { CLI_HELP, FULL_CLI_HELP, findCommandHelp, findDomainHelp } from './help';
import { redactSavedProviderApiKey } from './provider-output';

const CLI_PACKAGE_NAME = '@ocp-catalog/ocp-cli';
const CLI_VERSION = '0.1.3';
const args = process.argv.slice(2);

try {
  const result = await run(args);
  if (result !== undefined) printJson(result);
} catch (error) {
  const payload = error instanceof OcpClientValidationError
    ? { error: { code: 'validation_error', message: error.message, details: error.details } }
    : isZodLikeError(error)
    ? { error: { code: 'validation_error', message: 'Request does not match the OCP protocol schema', details: formatZodLikeError(error) } }
    : error instanceof OcpClientError
    ? { error: { code: 'ocp_client_error', message: error.message, details: error.details } }
    : { error: { code: 'cli_error', message: error instanceof Error ? error.message : String(error) } };
  console.error(JSON.stringify(payload, null, 2));
  process.exit(1);
}

async function run(argv: string[]) {
  const [domain, command, ...rest] = argv;
  if (domain === 'version' || domain === '--version' || domain === '-v') {
    return {
      name: CLI_PACKAGE_NAME,
      version: CLI_VERSION,
    };
  }
  if (!domain || domain === 'help' || domain === '--help' || domain === '-h') {
    return help(domain === 'help' ? [command, ...rest].filter((item): item is string => !!item) : []);
  }
  if (command === 'help' || command === '--help' || command === '-h') return help([domain]);
  if (rest.includes('help') || rest.includes('--help') || rest.includes('-h')) return help([domain, command].filter(Boolean));

  if (domain === 'setup') {
    const flags = parseFlags([command, ...rest].filter((item): item is string => !!item));
    return installOcpSkill({
      target: skillTargetFromFlags(flags),
      dryRun: booleanFlag(flags, 'dry-run', false),
      force: booleanFlag(flags, 'force', false),
      sourceDir: stringFlag(flags, 'source-dir'),
    });
  }

  if (domain === 'skill' && (command === 'install' || command === 'update')) {
    const flags = parseFlags(rest);
    return installOcpSkill({
      target: skillTargetFromFlags(flags),
      dryRun: booleanFlag(flags, 'dry-run', false),
      force: booleanFlag(flags, 'force', false),
      sourceDir: stringFlag(flags, 'source-dir'),
    });
  }

  if (domain === 'skill' && command === 'uninstall') {
    const flags = parseFlags(rest);
    return uninstallOcpSkill({
      target: skillTargetFromFlags(flags),
      dryRun: booleanFlag(flags, 'dry-run', false),
      force: booleanFlag(flags, 'force', false),
    });
  }

  if (domain === 'skill' && command === 'doctor') {
    const flags = parseFlags(rest);
    return doctorOcpSkill(skillTargetFromFlags(flags));
  }

  if (domain === 'update') {
    const flags = parseFlags([command, ...rest].filter((item): item is string => !!item));
    return updateOcpCliAndSkill({
      manager: stringFlag(flags, 'manager', 'bun'),
      dryRun: booleanFlag(flags, 'dry-run', false),
      target: skillTargetFromFlags(flags),
    });
  }

  const flags = parseFlags(rest);
  const client = new OcpClient({
    timeoutMs: numberFlag(flags, 'timeout-ms', 10_000),
    userAgent: stringFlag(flags, 'user-agent', `ocp-cli/${CLI_VERSION}`),
    apiKey: stringFlag(flags, 'api-key'),
    correlationId: stringFlag(flags, 'correlation-id', createCorrelationId('cli')),
  });

  if (domain === 'registration' && command === 'discover') {
    const url = flags.positionals[0] ?? requiredFlag(flags, 'url');
    return client.discoverRegistration(url);
  }

  if (domain === 'registration' && command === 'search') {
    const registrationUrl = requiredFlag(flags, 'registration-url');
    return client.searchCatalogs(registrationUrl, {
      ocp_version: '1.0',
      kind: 'CatalogSearchRequest',
      query: stringFlag(flags, 'query') ?? '',
      limit: numberFlag(flags, 'limit', 20),
      explain: booleanFlag(flags, 'explain', true),
      filters: jsonFlag(flags, 'filters', {}),
    });
  }

  if (domain === 'registration' && command === 'resolve') {
    return client.resolveCatalogRoute(requiredFlag(flags, 'registration-url'), requiredFlag(flags, 'catalog-id'));
  }

  if (domain === 'catalog' && command === 'inspect') {
    const manifestUrl = flags.positionals[0] ?? requiredFlag(flags, 'manifest-url');
    return client.inspectCatalog(manifestUrl);
  }

  if (domain === 'provider' && command === 'register') {
    const request = providerRegistrationSchema.parse(await loadJsonFile(requiredFlag(flags, 'input')));
    const result = await client.registerProvider(requiredFlag(flags, 'register-url'), request);
    const saveApiKeyPath = stringFlag(flags, 'save-api-key');
    if (saveApiKeyPath && result.provider_api_key) {
      await writeFile(saveApiKeyPath, `${result.provider_api_key}\n`, { mode: 0o600 });
      return redactSavedProviderApiKey(result, saveApiKeyPath);
    }
    return result;
  }

  if (domain === 'provider' && command === 'sync') {
    requiredFlag(flags, 'api-key');
    const request = objectSyncRequestSchema.parse(await loadJsonFile(requiredFlag(flags, 'input')));
    return client.syncObjects(requiredFlag(flags, 'sync-url'), request);
  }

  if (domain === 'catalog' && command === 'query') {
    const queryPack = stringFlag(flags, 'query-pack');
    const queryMode = stringFlag(flags, 'query-mode');
    let request = catalogQueryRequestSchema.parse({
      ocp_version: '1.0',
      kind: 'CatalogQueryRequest',
      ...(queryPack ? { query_pack: queryPack } : {}),
      ...(queryMode ? { query_mode: queryMode } : {}),
      query: stringFlag(flags, 'query') ?? '',
      filters: jsonFlag(flags, 'filters', {}),
      limit: numberFlag(flags, 'limit', 20),
      offset: numberFlag(flags, 'offset', 0),
      ...(stringFlag(flags, 'cursor') ? { cursor: stringFlag(flags, 'cursor') } : {}),
      explain: booleanFlag(flags, 'explain', true),
    });

    const manifestTarget = stringFlag(flags, 'manifest');
    if (manifestTarget) {
      const manifest = catalogManifestSchema.parse(await loadManifestTarget(client, manifestTarget));
      request = validateCatalogQueryRequest(manifest, request, {
        queryUrl: requiredFlag(flags, 'query-url'),
      }).request;
    }

    return client.queryCatalog(requiredFlag(flags, 'query-url'), request);
  }

  if (domain === 'catalog' && command === 'resolve') {
    const agentId = stringFlag(flags, 'agent-id');
    const upstreamTokenPath = stringFlag(flags, 'upstream-token');
    const request = resolveRequestSchema.parse({
      ocp_version: '1.0',
      kind: 'ResolveRequest',
      entry_id: requiredFlag(flags, 'entry-id'),
      purpose: stringFlag(flags, 'purpose') ?? 'view',
      // Only sent when asked for. §10.2 requires a resolve without an
      // attribution_context to behave exactly as it did before this protocol
      // existed, and the cheapest way to honour that is to omit the member.
      ...(agentId
        ? {
            attribution_context: {
              agent_id: agentId,
              ...(upstreamTokenPath
                ? { upstream_token: await loadJsonFile(upstreamTokenPath) }
                : {}),
            },
          }
        : {}),
    });
    const resolveUrl = requiredFlag(flags, 'resolve-url');
    const resolved = await client.resolveCatalogEntry(resolveUrl, request);

    if (!booleanFlag(flags, 'verify-attribution', false)) return resolved;
    return { ...resolved, attribution_verification: await verifyResolved(flags, resolveUrl, resolved) };
  }

  if (domain === 'attribution' && command === 'verify') {
    const at = stringFlag(flags, 'at');
    if (at && Number.isNaN(Date.parse(at))) throw new Error('--at must be an RFC 3339 timestamp');

    const target = flags.positionals[0] ?? requiredFlag(flags, 'token');
    const payload = await loadJsonFile(target);
    const token = extractAttributionToken(payload);
    const providerId = stringFlag(flags, 'provider-id');

    return verifyAttributionPayload({
      payload,
      jwks: await loadJwksMap(flags, token ? requiredCatalogIds(token) : []),
      ...(at ? { at: new Date(at) } : {}),
      ...(providerId ? { expectedProviderId: providerId } : {}),
      // A `view` token is legitimately signed and cannot be settled against.
      // Asking "is this signature real" about one is a fair question, so the
      // purpose gate is opt-out rather than unconditional.
      ...(booleanFlag(flags, 'any-purpose', false) ? { requirePurpose: null } : {}),
    });
  }

  if (domain === 'validate' && command === 'manifest') {
    const target = flags.positionals[0] ?? requiredFlag(flags, 'input');
    const payload = await loadManifestTarget(client, target);
    return {
      ok: true,
      manifest: catalogManifestSchema.parse(payload),
    };
  }

  if (domain === 'validate' && command === 'query') {
    const manifestTarget = requiredFlag(flags, 'manifest');
    const manifest = catalogManifestSchema.parse(await loadManifestTarget(client, manifestTarget));
    const queryPack = stringFlag(flags, 'query-pack');
    const queryMode = stringFlag(flags, 'query-mode');
    const request = catalogQueryRequestSchema.parse({
      ocp_version: '1.0',
      kind: 'CatalogQueryRequest',
      ...(queryPack ? { query_pack: queryPack } : {}),
      ...(queryMode ? { query_mode: queryMode } : {}),
      query: stringFlag(flags, 'query') ?? '',
      filters: jsonFlag(flags, 'filters', {}),
      limit: numberFlag(flags, 'limit', 20),
      offset: numberFlag(flags, 'offset', 0),
      ...(stringFlag(flags, 'cursor') ? { cursor: stringFlag(flags, 'cursor') } : {}),
      explain: booleanFlag(flags, 'explain', true),
    });

    return validateCatalogQueryRequest(manifest, request);
  }

  if (domain === 'events' && command === 'tail') {
    return client.listActivityEvents(requiredFlag(flags, 'activity-url'), numberFlag(flags, 'limit', 50));
  }

  throw new Error(`Unknown command: ${[domain, command].filter(Boolean).join(' ')}`);
}

function help(tokens: string[] = []) {
  const command = findCommandHelp(tokens);
  if (command) return { ...command, workflow: CLI_HELP.workflow };
  const domain = findDomainHelp(tokens);
  if (domain) return { ...domain, workflow: CLI_HELP.workflow };
  return FULL_CLI_HELP;
}

function updateOcpCliAndSkill(options: { manager?: string; dryRun: boolean; target: SkillTarget }) {
  const manager = options.manager ?? 'bun';
  const installCommand = manager === 'npm'
    ? ['npm', 'install', '-g', '@ocp-catalog/ocp-cli@latest']
    : ['bun', 'install', '-g', '@ocp-catalog/ocp-cli@latest'];
  const skillCommand = ['ocp', 'skill', 'update', '--target', String(options.target)];

  if (options.dryRun) {
    return {
      ok: true,
      dry_run: true,
      commands: [installCommand, skillCommand],
      note: 'update installs the latest CLI package, then runs the updated ocp binary to refresh the local skill',
    };
  }

  runCommand(installCommand);
  runCommand(skillCommand);

  return {
    ok: true,
    dry_run: false,
    commands: [installCommand, skillCommand],
  };
}

async function loadManifestTarget(client: OcpClient, target: string): Promise<CatalogManifest | unknown> {
  return target.startsWith('http://') || target.startsWith('https://')
    ? client.inspectCatalog(target)
    : JSON.parse(await readFile(target, 'utf8'));
}

async function loadJsonFile(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function loadJsonTarget(target: string): Promise<unknown> {
  if (!target.startsWith('http://') && !target.startsWith('https://')) return loadJsonFile(target);
  const response = await fetch(target);
  if (!response.ok) throw new Error(`GET ${target} responded ${response.status}`);
  return response.json();
}

/**
 * Builds the `catalog_id` → JWKS map a verification needs, from any mix of
 * `--jwks <id>=<file-or-url>` and `--discover <well-known-url>`.
 *
 * `--discover` exists because the one-hop case is the common case and making
 * the operator read `catalog_id` out of a discovery document by hand, only to
 * type it back in, is a step with no decision in it. It still resolves to the
 * same map: discovery is a *way to find* a key set, never a reason to trust one
 * the chain did not name.
 */
async function loadJwksMap(
  flags: ParsedFlags,
  needed: string[],
  fallbackDiscoveryUrl?: string,
): Promise<Record<string, unknown>> {
  const jwks: Record<string, unknown> = {};
  const explicit = [...repeatedFlag(flags, 'discover'), ...repeatedFlag(flags, 'jwks')];
  const discoveries =
    explicit.length === 0 && fallbackDiscoveryUrl
      ? [fallbackDiscoveryUrl]
      : repeatedFlag(flags, 'discover');

  for (const url of discoveries) {
    const discovery = (await loadJsonTarget(url)) as { catalog_id?: string; jwks_url?: string };
    if (!discovery.catalog_id || !discovery.jwks_url) {
      throw new Error(`${url} is not a discovery document with catalog_id and jwks_url — this node does not sign`);
    }
    jwks[discovery.catalog_id] = await loadJsonTarget(discovery.jwks_url);
  }

  for (const spec of repeatedFlag(flags, 'jwks')) {
    const { catalogId, source } = parseJwksSpec(spec);
    jwks[catalogId] = await loadJsonTarget(source);
  }

  // Reported here rather than left to fail as `key_not_found`: an operator who
  // supplied nothing needs the list of ids to fetch, not a verdict about one.
  const missing = needed.filter((id) => !(id in jwks));
  if (missing.length > 0 && Object.keys(jwks).length === 0) {
    throw new Error(
      `No keys supplied. This token needs one key set per hop: ${needed.join(', ')}. ` +
        `Use --discover <well-known-url> for a node you can reach, or --jwks <catalog_id>=<file-or-url>.`,
    );
  }
  return jwks;
}

/**
 * The resolve-side check: §7.1 over the token, plus the binding §7.1 cannot see.
 *
 * Both halves are reported even when the first fails, because they are different
 * accusations. A bad signature says the token is forged; a good signature on a
 * token about another object says the *presenter* is misusing a real one.
 */
async function verifyResolved(flags: ParsedFlags, resolveUrl: string, resolved: unknown) {
  const token = extractAttributionToken(resolved);
  const verification = await verifyAttributionPayload({
    payload: resolved,
    // Default to the node we just talked to: it issued the last hop, and on a
    // one-hop chain it is the only key set needed. A relayed chain still needs
    // an explicit --jwks per upstream hop, and says so when one is missing.
    jwks: await loadJwksMap(
      flags,
      token ? requiredCatalogIds(token) : [],
      new URL('/.well-known/ocp-catalog', resolveUrl).toString(),
    ),
    ...(stringFlag(flags, 'at') ? { at: new Date(stringFlag(flags, 'at')!) } : {}),
    ...(booleanFlag(flags, 'any-purpose', false) ? { requirePurpose: null } : {}),
  });

  const binding = token ? checkResolveBinding(token, resolved) : { ok: true as const };
  if (binding.ok) return verification;
  return { ...verification, ok: false, binding_error: binding.error };
}

function skillTargetFromFlags(flags: ParsedFlags): SkillTarget {
  const explicitDir = stringFlag(flags, 'dir');
  if (explicitDir) return explicitDir;

  const explicitTarget = stringFlag(flags, 'target');
  if (explicitTarget) return explicitTarget;

  const agent = stringFlag(flags, 'agent');

  const scope = stringFlag(flags, 'scope', 'user');
  if (scope === 'project') {
    // Project scope writes into the repo, using the layout the chosen agent
    // reads: Claude Code looks in .claude/skills, the others in .agents/skills.
    return agent === 'claude'
      ? pathJoin(process.cwd(), '.claude', 'skills')
      : pathJoin(process.cwd(), '.agents', 'skills');
  }

  if (agent === 'all') return 'all';
  if (agent === 'codex' || agent === 'agents' || agent === 'claude') return agent;

  return 'auto';
}

function pathJoin(...parts: string[]) {
  return parts.join(process.platform === 'win32' ? '\\' : '/');
}

function runCommand(command: string[]) {
  const result = spawnSync(command[0], command.slice(1), {
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

  if (result.status !== 0) {
    throw new Error(`${command.join(' ')} failed with exit code ${result.status ?? 1}`);
  }
}

type ParsedFlags = {
  positionals: string[];
  values: Map<string, string | boolean>;
  /**
   * Every occurrence of each flag, in order. `values` keeps last-wins for the
   * flags that have always been single-valued; this is the one place a repeat is
   * meaningful, because a relayed chain needs one `--jwks` per hop and silently
   * keeping only the last would fail as `key_not_found` on a key the operator
   * did supply.
   */
  lists: Map<string, string[]>;
};

function parseFlags(argv: string[]): ParsedFlags {
  const values = new Map<string, string | boolean>();
  const lists = new Map<string, string[]>();
  const positionals: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith('--')) {
      positionals.push(item);
      continue;
    }

    const key = item.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) {
      values.set(key, true);
      continue;
    }

    values.set(key, next);
    lists.set(key, [...(lists.get(key) ?? []), next]);
    index += 1;
  }

  return { positionals, values, lists };
}

function repeatedFlag(flags: ParsedFlags, key: string): string[] {
  return flags.lists.get(key) ?? [];
}

function requiredFlag(flags: ParsedFlags, key: string) {
  const value = stringFlag(flags, key);
  if (!value) throw new Error(`Missing required --${key}`);
  return value;
}

function stringFlag(flags: ParsedFlags, key: string, fallback?: string) {
  const value = flags.values.get(key);
  return typeof value === 'string' ? value : fallback;
}

function numberFlag(flags: ParsedFlags, key: string, fallback: number) {
  const value = stringFlag(flags, key);
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new Error(`--${key} must be a number`);
  return parsed;
}

function booleanFlag(flags: ParsedFlags, key: string, fallback: boolean) {
  const value = flags.values.get(key);
  if (value === undefined) return fallback;
  if (typeof value === 'boolean') return value;
  return value === 'true' || value === '1';
}

function jsonFlag<T>(flags: ParsedFlags, key: string, fallback: T): T {
  const value = stringFlag(flags, key);
  return value ? JSON.parse(value) as T : fallback;
}

function printJson(value: unknown) {
  console.log(JSON.stringify(value, null, 2));
}

type ZodLikeIssue = {
  code?: string;
  path?: Array<string | number>;
  message?: string;
};

type ZodLikeError = {
  issues: ZodLikeIssue[];
};

function isZodLikeError(error: unknown): error is ZodLikeError {
  return Boolean(error)
    && typeof error === 'object'
    && Array.isArray((error as { issues?: unknown }).issues);
}

function formatZodLikeError(error: ZodLikeError) {
  return {
    code: 'protocol_schema_error',
    correction: 'Adjust the request so every field matches the OCP protocol schema before sending it.',
    issues: error.issues.map((issue) => ({
      code: issue.code ?? 'invalid',
      path: issue.path?.join('.') ?? '',
      message: issue.message ?? 'Invalid value',
    })),
  };
}
