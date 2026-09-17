# Minimal OCP Catalog Node — Python

The smallest spec-valid [OCP Catalog Node](../../docs/specs), serving three
hardcoded in-memory products. Standard library only — no framework, no
third-party dependencies. Requires Python 3.9+.

## Run

```bash
python server.py        # listens on http://localhost:4401
```

Then:

```bash
curl http://localhost:4401/ocp/manifest
curl http://localhost:4401/ocp/health
curl -X POST http://localhost:4401/ocp/query   -H 'content-type: application/json' -d '{"query":"headphones"}'
curl -X POST http://localhost:4401/ocp/resolve -H 'content-type: application/json' -d '{"entry_id":"entry_example_inmemory_sku-001"}'
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/ocp-catalog` | discovery |
| GET | `/ocp/manifest` | capabilities + query packs |
| GET | `/ocp/health` | liveness |
| GET | `/ocp/contracts` | object contracts (empty — read-only node) |
| POST | `/ocp/query` | keyword search over products |
| POST | `/ocp/resolve` | resolve one entry into action bindings |

## Conformance

`conformance_test.py` starts the server and asserts every response carries the
required OCP fields (structural check — there is no OCP pip package yet; the
canonical schemas live in [`@ocp-catalog/ocp-schema`](https://www.npmjs.com/package/@ocp-catalog/ocp-schema)
and [`docs/specs`](../../docs/specs)):

```bash
python conformance_test.py
```

Configuration via env: `CATALOG_ID`, `CATALOG_NAME`, `PORT`, `PUBLIC_BASE_URL`.

## Canonicalization and attribution

A standard-library port of
[`@ocp-catalog/ocp-crypto`](../../packages/ocp-crypto): OCP Canonical JSON v1,
attribution chain verification, and token issuance. A Python node can verify an
attribution token offline, from public keys alone, with nothing pip-installed.

| File | Covers |
|---|---|
| `ocp_canonical.py` | [OCP-JCS v1](../../docs/specs/crypto/canonicalization.md), wire bytes and in-memory values |
| `ocp_ed25519.py` | RFC 8032 Ed25519, because `cryptography` is not a stdlib module |
| `ocp_attribution.py` | [attribution v1](../../docs/specs/attribution/v1.md) §5 signing, §7.1 verification |
| `interop_agent.py` | the Python participant in the cross-language matrix |

```bash
python canonical_test.py       # the 75 shared canonicalization vectors
python attribution_test.py     # the shared attribution fixture + local API tests
python interop_agent.py selftest
```

The vectors in
[`packages/ocp-crypto/fixtures/canonical/`](../../packages/ocp-crypto/fixtures/canonical)
and the attribution fixture are the same ones TypeScript and Go run, so a
divergence surfaces as a test failure here rather than as an unverifiable
signature in production. For all nine cells of the three-language matrix, see
[`scripts/interop/matrix.mjs`](../../scripts/interop/matrix.mjs).

`ocp_ed25519.py` is a readable reference implementation and is **not constant
time**. Its verification path handles no secrets, so offline token verification
is unaffected; a node that signs in production should use `cryptography`'s
`Ed25519PrivateKey` instead.

Two Python-specific traps the port exists to avoid, both called out in
[the fixture README](../../packages/ocp-crypto/fixtures/canonical/README.md):
`json.loads` silently keeps the last of a set of duplicate members, so a decoded
value can no longer tell you a signature bypass was attempted; and `str`
comparison orders code points, which disagrees with the spec's UTF-16 code-unit
order outside the BMP.
