export type CliOptionHelp = {
  name: string;
  description: string;
};

export type CliCommandHelp = {
  command: string;
  domain: string;
  action?: string;
  summary: string;
  description: string;
  options: CliOptionHelp[];
  examples: string[];
};

export type CliDomainHelp = {
  domain: string;
  summary: string;
  description: string;
  commands: CliCommandHelp[];
};

export type CliHelp = {
  overview: string;
  workflow: string[];
  commands: CliCommandHelp[];
};

const clientOptions: CliOptionHelp[] = [
  {
    name: '--timeout-ms',
    description: 'HTTP request timeout in milliseconds. Defaults to 10000.',
  },
  {
    name: '--user-agent',
    description: 'User-Agent header sent to OCP endpoints. Defaults to ocp-cli/0.1.3.',
  },
  {
    name: '--api-key',
    description: 'Bearer API key for endpoints that require authorization.',
  },
  {
    name: '--correlation-id',
    description: 'Trace identifier used to link client commands with server-side activity events.',
  },
];

const targetOptions: CliOptionHelp[] = [
  {
    name: '--target',
    description: 'Skill destination: auto, codex, agents, claude, both (codex+agents), all, or an explicit skills directory.',
  },
  {
    name: '--agent',
    description: 'Compatibility alias for choosing codex, agents, claude, or all skill destinations.',
  },
  {
    name: '--scope',
    description: 'Install scope for compatibility mode. Use user or project.',
  },
  {
    name: '--dir',
    description: 'Explicit skill directory. Overrides --target and --scope.',
  },
  {
    name: '--dry-run',
    description: 'Print the planned operation without writing files or running updates.',
  },
  {
    name: '--force',
    description: 'Overwrite an existing installed skill or remove it without interactive safeguards.',
  },
];

export const CLI_HELP: CliHelp = {
  overview:
    'OCP Catalog CLI for discovering Registration nodes, selecting Catalogs, inspecting manifests, querying commercial objects, resolving selected entries, managing the local OCP skill, and reading public Activity API events.',
  workflow: [
    'Discover a Registration node',
    'Search or resolve a Catalog route',
    'Inspect the Catalog manifest',
    'Register as a Provider when publishing objects',
    'Query with a manifest-declared query pack',
    'Resolve a selected entry when details or actions are needed',
  ],
  commands: [
    {
      command: 'ocp version',
      domain: 'version',
      summary: 'Print the installed CLI package identity.',
      description: 'Returns the npm package name and version as structured JSON so agents can verify which CLI they are running.',
      options: [],
      examples: [
        'ocp version',
        'ocp --version',
      ],
    },
    {
      command: 'ocp setup [--target auto|codex|agents|claude|both|all|<skills-dir>] [--dry-run]',
      domain: 'setup',
      summary: 'Install the OCP Catalog skill.',
      description: 'Copies the bundled ocp-catalog skill into the selected local agent skill directory.',
      options: targetOptions,
      examples: [
        'ocp setup --target auto',
        'ocp setup --target both --dry-run',
      ],
    },
    {
      command: 'ocp update [--manager bun|npm] [--target auto|codex|agents|claude|both|all|<skills-dir>] [--dry-run]',
      domain: 'update',
      summary: 'Update the global CLI package and refresh the local skill.',
      description: 'Installs @ocp-catalog/ocp-cli@latest with bun or npm, then runs skill update for the selected target.',
      options: [
        {
          name: '--manager',
          description: 'Global package manager to use for the CLI update. Supported values: bun or npm.',
        },
        ...targetOptions,
      ],
      examples: [
        'ocp update --manager bun --target auto',
        'ocp update --manager npm --target both --dry-run',
      ],
    },
    {
      command: 'ocp skill install [--target auto|codex|agents|claude|both|all|<skills-dir>] [--force] [--dry-run]',
      domain: 'skill',
      action: 'install',
      summary: 'Install the OCP skill into a local skill directory.',
      description: 'Writes the shipped skill files so agents can use the CLI-backed OCP workflow without this monorepo checkout.',
      options: targetOptions,
      examples: [
        'ocp skill install --target codex',
        'ocp skill install --target C:\\Users\\me\\.agents\\skills --force',
      ],
    },
    {
      command: 'ocp skill install [--agent codex|agents|claude|all] [--scope user|project] [--dir <skills-dir>] [--force]',
      domain: 'skill',
      action: 'install',
      summary: 'Install the OCP skill using compatibility flags.',
      description: 'Accepts older agent/scope/dir flags and maps them to the same installer used by --target.',
      options: targetOptions,
      examples: [
        'ocp skill install --agent all --scope user',
        'ocp skill install --agent claude --scope project',
        'ocp skill install --scope project --force',
      ],
    },
    {
      command: 'ocp skill update [--target auto|codex|agents|claude|both|all|<skills-dir>] [--force] [--dry-run]',
      domain: 'skill',
      action: 'update',
      summary: 'Refresh an installed OCP skill.',
      description: 'Replaces the selected local skill copy with the current CLI package version of the skill files.',
      options: targetOptions,
      examples: [
        'ocp skill update --target auto',
        'ocp skill update --target both --dry-run',
      ],
    },
    {
      command: 'ocp skill uninstall [--target auto|codex|agents|claude|both|all|<skills-dir>] [--force] [--dry-run]',
      domain: 'skill',
      action: 'uninstall',
      summary: 'Remove an installed OCP skill.',
      description: 'Deletes the ocp-catalog skill folder from the selected local agent skill directory.',
      options: targetOptions,
      examples: [
        'ocp skill uninstall --target agents --dry-run',
        'ocp skill uninstall --target codex --force',
      ],
    },
    {
      command: 'ocp skill doctor [--target auto|codex|agents|claude|both|all|<skills-dir>]',
      domain: 'skill',
      action: 'doctor',
      summary: 'Check the installed skill.',
      description: 'Inspects the selected installed skill locations and reports whether the OCP Catalog skill is present and readable.',
      options: targetOptions.filter((option) => option.name !== '--dry-run' && option.name !== '--force'),
      examples: [
        'ocp skill doctor --target auto',
        'ocp skill doctor --target both',
      ],
    },
    {
      command: 'ocp registration discover <discovery-url>',
      domain: 'registration',
      action: 'discover',
      summary: 'Discover a Registration node.',
      description: 'Fetches a Registration discovery document so clients can find manifest, catalog search, and route resolution endpoints.',
      options: clientOptions,
      examples: [
        'ocp registration discover https://ocp.deeplumen.io/.well-known/ocp-registration',
      ],
    },
    {
      command: 'ocp registration search --registration-url <url> [--query <text>]',
      domain: 'registration',
      action: 'search',
      summary: 'Search Catalog metadata through a Registration node.',
      description: 'Finds Catalog route candidates by searching catalog profiles, capabilities, domains, health, trust, and routing metadata. It does not search products.',
      options: [
        {
          name: '--registration-url',
          description: 'Registration catalog-search endpoint URL.',
        },
        {
          name: '--query',
          description: 'Natural language or keyword intent for finding matching Catalogs.',
        },
        {
          name: '--filters',
          description: 'JSON object containing Registration-declared catalog metadata filters.',
        },
        {
          name: '--limit',
          description: 'Maximum number of Catalog route candidates to return. Defaults to 20.',
        },
        {
          name: '--explain',
          description: 'Whether to request routing explanations. Defaults to true.',
        },
        ...clientOptions,
      ],
      examples: [
        'ocp registration search --registration-url https://ocp.deeplumen.io/registry --query "commerce"',
      ],
    },
    {
      command: 'ocp registration resolve --registration-url <url> --catalog-id <id>',
      domain: 'registration',
      action: 'resolve',
      summary: 'Resolve a Catalog route hint.',
      description: 'Requests the Registration node for a concrete Catalog route by catalog id, usually before inspecting the Catalog manifest.',
      options: [
        {
          name: '--registration-url',
          description: 'Registration route-resolution endpoint URL.',
        },
        {
          name: '--catalog-id',
          description: 'Catalog identifier returned by registration search.',
        },
        ...clientOptions,
      ],
      examples: [
        'ocp registration resolve --registration-url https://ocp.deeplumen.io/registry --catalog-id cat_local_dev',
      ],
    },
    {
      command: 'ocp provider register --register-url <url> --input <provider-registration.json> [--save-api-key <file>]',
      domain: 'provider',
      action: 'register',
      summary: 'Register a Provider with one Catalog.',
      description: 'Posts a ProviderRegistration payload to a Catalog registration endpoint. Accepted registrations may return a one-time provider_api_key; store it immediately for provider-scoped write calls.',
      options: [
        {
          name: '--register-url',
          description: 'Catalog provider registration endpoint, usually /ocp/providers/register.',
        },
        {
          name: '--input',
          description: 'Local ProviderRegistration JSON file to validate and submit.',
        },
        {
          name: '--save-api-key',
          description: 'Optional file path where a returned provider_api_key should be written with restricted file permissions when supported by the platform. When set, stdout redacts the key.',
        },
        ...clientOptions,
      ],
      examples: [
        'ocp provider register --register-url http://localhost:4000/ocp/providers/register --input ./provider-registration.json',
        'ocp provider register --register-url https://catalog.example/ocp/providers/register --input ./provider-registration.json --save-api-key ./.provider-api-key',
      ],
    },
    {
      command: 'ocp provider sync --sync-url <url> --input <object-sync-request.json> --api-key <provider-api-key>',
      domain: 'provider',
      action: 'sync',
      summary: 'Push one JSON object sync batch to a Catalog.',
      description: 'Validates an ObjectSyncRequest JSON file and posts it to the Catalog object sync endpoint. Use the provider_api_key returned by provider registration as --api-key.',
      options: [
        {
          name: '--sync-url',
          description: 'Catalog object sync endpoint, usually /ocp/objects/sync.',
        },
        {
          name: '--input',
          description: 'Local ObjectSyncRequest JSON file containing catalog_id, provider_id, registration_version, optional batch_id, and objects.',
        },
        ...clientOptions,
      ],
      examples: [
        'ocp provider sync --sync-url http://localhost:4000/ocp/objects/sync --input ./object-sync-request.json --api-key "$PROVIDER_API_KEY"',
      ],
    },
    {
      command: 'ocp catalog inspect <manifest-url> [--verify]',
      domain: 'catalog',
      action: 'inspect',
      summary: 'Inspect a Catalog manifest.',
      description: 'Fetches the Catalog manifest to learn supported object types, query packs, filter fields, resolve capability, auth policy, and endpoints before querying. With --verify it also checks the manifest signature and exits 2 if the manifest does not verify.',
      options: [
        {
          name: '--verify',
          description: 'Check the manifest SignatureEnvelope against the signing node public keys. Exit code 0 when it verifies, 2 when it does not, 1 when the command itself failed. The verdict names which of the eight crypto/v1 section 8 codes applied: unsigned, envelope_malformed, alg_not_supported, issuer_mismatch, payload_mismatch, key_not_found, signature_invalid, signature_expired.',
        },
        {
          name: '--jwks',
          description: 'Key set for the signing node, as <catalog_id>=<file-or-url>. Defaults to discovering keys from the manifest URL host.',
        },
        {
          name: '--discover',
          description: 'Well-known discovery URL to read catalog_id and jwks_url from, instead of naming the catalog id by hand.',
        },
        {
          name: '--expect-issuer',
          description: 'Catalog id this manifest must be signed by. A manifest correctly signed by somebody else is still the wrong manifest.',
        },
        {
          name: '--at',
          description: 'RFC 3339 moment to judge the signature expiry at. Defaults to now.',
        },
        ...clientOptions,
      ],
      examples: [
        'ocp catalog inspect http://localhost:4000/ocp/manifest',
        'ocp catalog inspect http://localhost:4400/ocp/manifest --verify',
        'ocp catalog inspect ./manifest.json --verify --jwks cat_example_typescript=./jwks.json',
      ],
    },
    {
      command: 'ocp catalog query --query-url <url> [--query-pack <id>] [--query-mode <mode>] [--query <text>]',
      domain: 'catalog',
      action: 'query',
      summary: 'Search commercial objects in a Catalog.',
      description: 'Calls a Catalog query endpoint with a manifest-declared query pack, optional text, JSON filters, pagination, and explanation controls.',
      options: [
        {
          name: '--query-url',
          description: 'Catalog query endpoint URL from the selected manifest or route hint.',
        },
        {
          name: '--manifest',
          description: 'Optional local or remote Catalog manifest used to validate query_pack and filters before sending the query.',
        },
        {
          name: '--query-pack',
          description: 'Exact query pack id declared by the Catalog manifest, such as ocp.query.keyword.v1. Optional when the Catalog can select a default pack.',
        },
        {
          name: '--query-mode',
          description: 'Optional query execution mode: keyword, filter, semantic, or hybrid. Omit it to let the client infer the mode from query text and filters.',
        },
        {
          name: '--query',
          description: 'Text search intent sent to the Catalog query endpoint.',
        },
        {
          name: '--filters',
          description: 'JSON object containing only filter fields supported by the selected Catalog.',
        },
        {
          name: '--limit',
          description: 'Maximum number of entries to return. Defaults to 20.',
        },
        {
          name: '--offset',
          description: 'Must be 0. Deep offset pagination is disabled.',
        },
        {
          name: '--cursor',
          description: 'Opaque cursor returned as page.next_cursor by the previous query response. Use it to request the next page.',
        },
        {
          name: '--explain',
          description: 'Whether to request match explanations. Defaults to true.',
        },
        ...clientOptions,
      ],
      examples: [
        'ocp catalog query --query-url http://localhost:4000/ocp/query --query-pack ocp.query.keyword.v1 --query-mode keyword --query "running shoes"',
        'ocp catalog query --query-url http://localhost:4000/ocp/query --query-pack ocp.query.filter.v1 --filters "{\\"category\\":\\"shoes\\"}"',
        'ocp catalog query --query-url http://localhost:4000/ocp/query --query-pack ocp.query.keyword.v1 --query "running shoes" --cursor "opaque-next-cursor"',
      ],
    },
    {
      command: 'ocp catalog resolve --resolve-url <url> --entry-id <id>',
      domain: 'catalog',
      action: 'resolve',
      summary: 'Resolve one selected Catalog entry.',
      description: 'Requests details, freshness, policy context, and action bindings for a concrete entry after query has produced a candidate.',
      options: [
        {
          name: '--resolve-url',
          description: 'Catalog resolve endpoint URL from the selected manifest or route hint.',
        },
        {
          name: '--entry-id',
          description: 'Entry identifier returned by catalog query.',
        },
        {
          name: '--purpose',
          description: 'Resolve purpose, such as view. Defaults to view. Only checkout is settleable, so only checkout gets an attribution token.',
        },
        {
          name: '--agent-id',
          description: 'Agent identifier sent as attribution_context.agent_id, asking the Catalog to sign an attribution token. Omit it and the resolve behaves exactly as it did before attribution existed.',
        },
        {
          name: '--upstream-token',
          description: 'JSON file holding an AttributionToken to relay. The Catalog appends itself as one more hop instead of minting a fresh origin chain.',
        },
        {
          name: '--verify-attribution',
          description: 'Verify the returned attribution token against the signing node public keys, and check that it is about this object. Defaults to discovering keys from the resolve URL host.',
        },
        {
          name: '--jwks',
          description: 'Key set for one hop, as <catalog_id>=<file-or-url>. Repeatable; a relayed chain needs one per hop.',
        },
        {
          name: '--discover',
          description: 'Well-known discovery URL to read catalog_id and jwks_url from. Repeatable.',
        },
        ...clientOptions,
      ],
      examples: [
        'ocp catalog resolve --resolve-url http://localhost:4000/ocp/resolve --entry-id product_123',
        'ocp catalog resolve --resolve-url http://localhost:4400/ocp/resolve --entry-id product_123 --purpose checkout --agent-id agent_demo --verify-attribution',
      ],
    },
    {
      command: 'ocp attribution verify <file> [--jwks <catalog_id>=<file-or-url>] [--discover <url>]',
      domain: 'attribution',
      action: 'verify',
      summary: 'Verify an attribution token offline.',
      description: 'Runs the attribution spec section 7.1 eligibility filter over a token, a resolve response carrying one, or a ConversionReport. Needs only public keys, so it runs with the network unplugged; a failure names the lowest failing hop, which is the tamper site.',
      options: [
        {
          name: '--token',
          description: 'JSON file holding an AttributionToken, a resolve response, or a ConversionReport. Optional when a positional file is provided.',
        },
        {
          name: '--jwks',
          description: 'Key set for one hop, as <catalog_id>=<file-or-url>. Repeatable; a relayed chain needs one per hop, and the token lists which ids it needs.',
        },
        {
          name: '--discover',
          description: 'Well-known discovery URL to read catalog_id and jwks_url from, instead of naming the catalog id by hand. Repeatable.',
        },
        {
          name: '--at',
          description: 'RFC 3339 moment to judge validity at. Pass the sale time, not the verification time, or a late-reported sale is rejected for being expired. Defaults to now.',
        },
        {
          name: '--provider-id',
          description: 'Provider the token must have been minted for. Checked as spec section 7.1 row 7.',
        },
        {
          name: '--any-purpose',
          description: 'Check the cryptography of a non-settleable token. A view token is legitimately signed; it just cannot be settled against.',
        },
      ],
      examples: [
        'ocp attribution verify ./resolve.json --jwks cat_example_typescript=./jwks.json',
        'ocp attribution verify ./report.json --discover http://localhost:4400/.well-known/ocp-catalog --at 2026-09-24T10:30:00Z',
      ],
    },
    {
      command: 'ocp validate manifest <file-or-url>',
      domain: 'validate',
      action: 'manifest',
      summary: 'Validate a Catalog manifest.',
      description: 'Loads a local manifest file or remote manifest URL and validates it against the OCP Catalog manifest schema.',
      options: [
        {
          name: '--input',
          description: 'Local JSON file path or remote manifest URL. Optional when a positional target is provided.',
        },
        ...clientOptions,
      ],
      examples: [
        'ocp validate manifest ./ocp-manifest.json',
        'ocp validate manifest https://catalog.example/ocp/manifest',
      ],
    },
    {
      command: 'ocp validate query --manifest <file-or-url> [--query-pack <id>] [--query-mode <mode>] [--query <text>] [--filters <json>]',
      domain: 'validate',
      action: 'query',
      summary: 'Validate a Catalog query before sending it.',
      description: 'Loads the selected Catalog manifest, checks the query pack and filters against declared query capabilities, selects a default query pack when possible, and returns clear correction details instead of sending a network query.',
      options: [
        {
          name: '--manifest',
          description: 'Local CatalogManifest JSON file or remote manifest URL used as the validation contract.',
        },
        {
          name: '--query-pack',
          description: 'Optional exact query pack id declared by the manifest.',
        },
        {
          name: '--query-mode',
          description: 'Optional query execution mode to validate: keyword, filter, semantic, or hybrid.',
        },
        {
          name: '--query',
          description: 'Text search intent to validate.',
        },
        {
          name: '--filters',
          description: 'JSON object containing candidate filters to validate against manifest input fields.',
        },
        {
          name: '--limit',
          description: 'Maximum number of entries requested. Must satisfy protocol schema limits.',
        },
        {
          name: '--offset',
          description: 'Must be 0. Deep offset pagination is disabled.',
        },
        {
          name: '--cursor',
          description: 'Opaque cursor from page.next_cursor used to validate a next-page request.',
        },
        {
          name: '--explain',
          description: 'Whether to request match explanations. Defaults to true.',
        },
        ...clientOptions,
      ],
      examples: [
        'ocp validate query --manifest ./ocp-manifest.json --query "running shoes" --filters "{\\"category\\":\\"shoes\\"}"',
        'ocp validate query --manifest https://catalog.example/ocp/manifest --query-pack ocp.query.keyword.v1 --query "wireless headphones"',
      ],
    },
    {
      command: 'ocp events tail --activity-url <url>',
      domain: 'events',
      action: 'tail',
      summary: 'Read public OCP activity events.',
      description: 'Reads the redacted public Activity API projection for query, resolve, sync, and tooling events. It does not expose raw audit payloads.',
      options: [
        {
          name: '--activity-url',
          description: 'Activity API base URL.',
        },
        {
          name: '--limit',
          description: 'Maximum number of public events to return. Defaults to 50.',
        },
        ...clientOptions,
      ],
      examples: [
        'ocp events tail --activity-url https://ocp.deeplumen.io',
        'ocp events tail --activity-url http://localhost:4100 --limit 10',
      ],
    },
  ],
};

export const CLI_DOMAINS: Omit<CliDomainHelp, 'commands'>[] = [
  {
    domain: 'registration',
    summary: 'Find and route to Catalogs.',
    description: 'Registration commands operate on Catalog metadata and routing. They do not search products or other commercial objects.',
  },
  {
    domain: 'provider',
    summary: 'Register providers and publish objects.',
    description: 'Provider commands submit provider-owned payloads to a Catalog. Registration can return a one-time provider API key that must be stored before object sync writes.',
  },
  {
    domain: 'catalog',
    summary: 'Inspect, query, and resolve commercial objects in one Catalog.',
    description: 'Catalog commands start with the manifest, then query declared capabilities, then resolve one selected entry for details or actions.',
  },
  {
    domain: 'skill',
    summary: 'Install and maintain the local OCP Catalog agent skill.',
    description: 'Skill commands copy, update, remove, or inspect the standalone skill so agents can use OCP without a monorepo checkout.',
  },
  {
    domain: 'events',
    summary: 'Read public OCP activity events.',
    description: 'Events commands inspect redacted Activity API projections and should be paired with --correlation-id when tracing a CLI workflow.',
  },
  {
    domain: 'validate',
    summary: 'Validate OCP payloads.',
    description: 'Validate commands check local or remote protocol payloads against OCP schemas before they are used by agents or services.',
  },
  {
    domain: 'attribution',
    summary: 'Verify attribution tokens with public keys only.',
    description: 'Attribution commands decide whether a settlement claim is real. They need no callback to the issuing Catalog, which is the point: an issuer that had to be online to confirm a token could change its answer after the sale.',
  },
  {
    domain: 'setup',
    summary: 'Bootstrap local OCP tooling.',
    description: 'Setup installs the OCP Catalog skill into the local agent environment.',
  },
  {
    domain: 'update',
    summary: 'Refresh local OCP tooling.',
    description: 'Update refreshes the CLI package and then updates the installed skill from the new package.',
  },
];

export const CLI_DOMAIN_HELP: CliDomainHelp[] = CLI_DOMAINS.map((domain) => ({
  ...domain,
  commands: CLI_HELP.commands.filter((command) => command.domain === domain.domain),
}));

export const FULL_CLI_HELP: CliHelp & { domains: CliDomainHelp[]; usage: string[] } = {
  ...CLI_HELP,
  domains: CLI_DOMAIN_HELP,
  usage: commandUsage(),
};

export function commandUsage(): string[] {
  return CLI_HELP.commands.map((command) => command.command);
}

export function findCommandHelp(tokens: string[]): CliCommandHelp | undefined {
  const normalizedTokens = tokens.filter((token) => token && token !== 'help' && token !== '--help' && token !== '-h');
  if (normalizedTokens.length === 0) return undefined;
  return CLI_HELP.commands.find((command) => command.domain === normalizedTokens[0] && command.action === normalizedTokens[1]);
}

export function findDomainHelp(tokens: string[]): CliDomainHelp | undefined {
  const normalizedTokens = tokens.filter((token) => token && token !== 'help' && token !== '--help' && token !== '-h');
  if (normalizedTokens.length !== 1) return undefined;
  return CLI_DOMAIN_HELP.find((domain) => domain.domain === normalizedTokens[0]);
}
