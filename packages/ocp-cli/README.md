# OCP Catalog CLI

`@ocp-catalog/ocp-cli` is the command-line tool for the Open Commerce Protocol
Catalog workflow. It helps agents and builders discover Registration nodes,
select Catalog routes, inspect Catalog manifests, query commercial objects,
resolve selected entries, manage the local `ocp-catalog` agent skill, and read
public Activity API events.

## Install

```bash
npm install -g @ocp-catalog/ocp-cli
ocp help
```

You can also run it without a global install:

```bash
npx @ocp-catalog/ocp-cli@latest help
```

## Common Commands

```bash
# Install the bundled agent skill
ocp setup --target auto
ocp skill doctor --target both

# Discover and inspect OCP endpoints
ocp registration search --registration-url https://ocp.deeplumen.io/registry --query "commerce"
ocp catalog inspect http://localhost:4000/ocp/manifest

# Validate before sending a Catalog query
ocp validate query --manifest http://localhost:4000/ocp/manifest --query "running shoes"

# Read redacted public activity events
ocp events tail --activity-url https://ocp.deeplumen.io
```

## Attribution

A Catalog that signs [attribution tokens](https://github.com/Open-Commerce-Protocol/OCP-Catalog/blob/main/docs/specs/attribution/v1.md)
issues one on a `checkout` resolve that names an agent. Ask for it, and check it
in the same breath:

```bash
ocp catalog resolve \
  --resolve-url http://localhost:4400/ocp/resolve \
  --entry-id entry_example_inmemory_sku-001 \
  --purpose checkout --agent-id agent_demo_shopper \
  --verify-attribution
```

Without `--agent-id` the resolve is byte-for-byte what it was before attribution
existed — there is nobody to credit, so nothing is signed.

`--verify-attribution` fetches the signing keys from the resolve host's
`/.well-known/ocp-catalog` and adds an `attribution_verification` block to the
output. To check a token you already have, on a machine with no network:

```bash
ocp attribution verify ./resolve.json --jwks cat_example_typescript=./jwks.json
```

```json
{
  "ok": true,
  "jti": "atr_0d07680c-...",
  "agent_id": "agent_demo_shopper",
  "settles": ["cat_example_typescript"],
  "complete": true,
  "hops": 1,
  "last_signed_at": "2026-09-24T10:00:00.000Z"
}
```

The input can be a bare token, a resolve response, or a `ConversionReport` —
those are the three things a merchant actually has on disk at the three moments
it might want to check. Two flags are worth knowing:

| Flag | Why it exists |
|---|---|
| `--jwks <catalog_id>=<file-or-url>` | Repeatable. Every hop signs (spec §5.2), so a relayed chain needs one key set per hop. Run the command without any and it lists the catalog ids the token needs. |
| `--at <rfc3339>` | The moment of the **sale**, not of the check. Rows 8/9 ask whether the token was valid when the transaction happened; judging against "now" rejects a sale reported an hour late. |

A failure names the lowest failing hop, and that is the tamper site: §5.2 makes
hop N's signature cover hops 1..N−1, so editing hop K invalidates hops K..N.
Reporting any later hop would accuse a node that signed honestly.

```json
{ "ok": false, "error": { "code": "signature_invalid", "hop": 2, "message": "hop 2: signature does not verify" } }
```

Verification needs no callback to the issuing Catalog, and that is the point: an
issuer that had to be online to confirm a token could change its answer after
the sale, and there would be nothing to settle against.

## Skill Workflow

The package ships the standalone `ocp-catalog` skill. Install it into a local
agent skill directory when an agent should use OCP without a monorepo checkout:

```bash
ocp skill install --target both
ocp skill update --target auto
ocp skill doctor --target both
```

`--target` accepts `auto`, `codex`, `agents`, `both`, or an explicit skills
directory.

## Error Handling

The CLI is intentionally fail-loud. Manifest validation rejects unsupported query
packs, undeclared filter fields, invalid pagination, malformed payloads, and
unreachable endpoints with structured JSON errors instead of silently returning
empty successful results.

## Documentation

Full docs live in the OCP Catalog site and repository:

- https://github.com/Open-Commerce-Protocol/OCP-Catalog
- https://www.npmjs.com/package/@ocp-catalog/ocp-cli
