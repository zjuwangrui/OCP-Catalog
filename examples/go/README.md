# Minimal OCP Catalog Node — Go

The smallest spec-valid [OCP Catalog Node](../../docs/specs), serving three
hardcoded in-memory products. Standard library only (`net/http`) — no
dependencies. Requires Go 1.22+ (for method-based `ServeMux` routing).

## Run

```bash
go run .        # listens on http://localhost:4402
```

Then:

```bash
curl http://localhost:4402/ocp/manifest
curl http://localhost:4402/ocp/health
curl -X POST http://localhost:4402/ocp/query   -H 'content-type: application/json' -d '{"query":"headphones"}'
curl -X POST http://localhost:4402/ocp/resolve -H 'content-type: application/json' -d '{"entry_id":"entry_example_inmemory_sku-001"}'
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

`main_test.go` starts the server and asserts every response carries the
required OCP fields (structural check — the canonical schemas live in
[`@ocp-catalog/ocp-schema`](https://www.npmjs.com/package/@ocp-catalog/ocp-schema)
and [`docs/specs`](../../docs/specs)):

```bash
go test ./...
```

Configuration via env: `CATALOG_ID`, `CATALOG_NAME`, `PORT`, `PUBLIC_BASE_URL`.

## Canonicalization, attribution and document signatures

`ocpcrypto/` is a standard-library port of
[`@ocp-catalog/ocp-crypto`](../../packages/ocp-crypto): OCP Canonical JSON v1
(`canonical.go`, `value.go`), attribution chain verification
(`attribution.go`), token issuance (`issue.go`) and document signing
(`signature.go`). A Go node can verify an attribution token or a signed
manifest offline, from public keys alone, with nothing installed.

| File | Covers |
|---|---|
| `ocpcrypto/canonical.go` | [OCP-JCS v1](../../docs/specs/crypto/canonicalization.md) over wire bytes |
| `ocpcrypto/value.go` | the same rules over an in-memory value, for the signing side |
| `ocpcrypto/attribution.go` | [attribution v1](../../docs/specs/attribution/v1.md) §5 signing, §7.1 verification |
| `ocpcrypto/issue.go` | minting an origin token and appending a relay hop |
| `ocpcrypto/signature.go` | [crypto v1](../../docs/specs/crypto/v1.md) §4 document signing, §7 verification, §9 trust ceiling |
| `interop/` | the Go participant in the attribution matrix |
| `interopsig/` | the Go participant in the document signature matrix |

`go test ./...` runs all of it, including the 75 shared canonicalization
vectors in
[`packages/ocp-crypto/fixtures/canonical/`](../../packages/ocp-crypto/fixtures/canonical)
and every case in the shared attribution and signature fixtures. Those are the
same vectors the TypeScript and Python implementations run, so a divergence
surfaces as a test failure here rather than as an unverifiable signature in
production.

To drive this implementation directly:

```bash
go run ./interop selftest             # every attribution assertion Go can make alone
go run ./interop sign > token.json    # the fixture's issuance recipe
go run ./interop verify token.json    # §7.1, exits non-zero on rejection

go run ./interopsig selftest              # the same for document signatures
go run ./interopsig sign > manifest.json  # the fixture's signing recipe
go run ./interopsig verify manifest.json  # crypto v1 §7 + §9, exits non-zero on rejection
go run ./interopsig negatives             # each negative's §8 code and §9 ceiling, as JSON
```

For all nine cells of the three-language matrices, see
[`scripts/interop/matrix.mjs`](../../scripts/interop/matrix.mjs) (attribution
tokens) and
[`scripts/interop/signature-matrix.mjs`](../../scripts/interop/signature-matrix.mjs)
(documents). The two are separate runners because the two signatures are not
interchangeable: a chain node signs the chain prefix plus the token's core
claims, a document signs its envelope minus `signature`.

Two Go-specific traps the port exists to avoid, both called out in
[the fixture README](../../packages/ocp-crypto/fixtures/canonical/README.md):
`encoding/json` resolves duplicate members last-one-wins, so a decoded value
can no longer tell you a signature bypass was attempted; and `sort.Strings`
orders UTF-8 bytes, which disagrees with the spec's UTF-16 code-unit order
outside the BMP.
