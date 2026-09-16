# OCP Catalog Docs

This directory holds the protocol-level documentation for the OCP Catalog. The
implementation-facing docs (architecture, operations, integrations, reference
agents) live with the applications in the
[ocp-catalog-instances](https://github.com/Open-Commerce-Protocol/ocp-catalog-instances)
repo.

## Source Of Truth

Use this order when protocol descriptions conflict:

1. [Registration v1](./specs/registration/v1.md) defines how a Catalog Node registers with an OCP Catalog Registration node and how agents discover Catalog route hints.
2. [Handshake v1](./specs/handshake/v1.md) defines how a Provider registers with a Catalog Node and how object sync is negotiated.

For system design, repository architecture, and engineering standards of the
reference implementation, see the `docs/` directory of the instances repo.

## Directory Map

- `specs/`: protocol specifications.
  - `specs/registration/v1.md` — **stable**
  - `specs/handshake/v1.md` — **stable**
  - `specs/crypto/canonicalization.md` — **draft**; TypeScript implementation in
    [`packages/ocp-crypto`](../packages/ocp-crypto/README.md), all 75 conformance
    vectors green. Python / Go not implemented, so cross-language byte agreement
    is asserted by the vectors only, not yet demonstrated.
  - `specs/attribution/v1.md` — **draft**; data model, origin-token issuance,
    relay chains, the full §7.1 verifier, and §6/§7.2 settlement implemented,
    end to end through [`examples/typescript`](../examples/typescript/README.md)
    (curl the public key, stop the node, verify offline, settle offline). A
    tampered hop is localised by hop number; `order_id` dedup (row 11) and
    last-touch adjudication decide one winner per order. Both dedup stores —
    `JtiRegistry` (row 10) and `SettlementLedger` (row 11) — are **in-memory**,
    so they do not survive a restart or span processes and must become
    transactional rows before real money moves.
- `proposals/`: in-flight design proposals and implementation plans. Not normative;
  a proposal becomes normative only once it lands under `specs/`.

The machine-readable JSON Schemas for these protocols live at the repository root
in `ocp.catalog.registration.v1/`, `ocp.catalog.handshake.v1/`, and
`ocp.catalog.attribution.v1/`.

## Protocol Notes

- Registration and Handshake are separate protocols. Registration selects which
  Catalog to ask; Handshake defines how Provider data enters a Catalog.
- Registration `resolve` returns a `CatalogRouteHint`. Catalog `resolve` returns
  a `ResolvableReference`.
- `CatalogRouteHint` is a compact routing, trust, health, and cache summary. The
  full capability truth remains in the Catalog manifest.
- Search returns CatalogEntry-like projections. `CommercialObject` is the sync
  envelope, not the search result itself.
