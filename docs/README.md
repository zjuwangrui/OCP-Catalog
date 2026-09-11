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
  - `specs/crypto/canonicalization.md` — **draft**, not yet implemented
  - `specs/attribution/v1.md` — **draft**, not yet implemented
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
