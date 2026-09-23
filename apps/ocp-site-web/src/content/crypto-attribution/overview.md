# Crypto and Attribution

OCP Catalog uses signed protocol documents and signed attribution chains when a deployment needs verifiable discovery, trust decisions, or commercial attribution. This page describes the protocol packages in this repository and the boundary between protocol contracts and production runtime services.

## Signed discovery and manifests

A Catalog can publish a signed discovery document and manifest. The signature covers the document payload using OCP canonical JSON (OCP-JCS) and an Ed25519 `SignatureEnvelope`. A verifier can resolve the signing key by `kid`, check the declared algorithm, verify the canonical bytes, and apply the document's trust profile.

Use the CLI when inspecting a remote or local manifest:

```bash
ocp catalog inspect https://catalog.example.com/ocp/manifest --verify
```

Verification is fail-closed for the signed document. A bad signature, unknown key, unsupported algorithm, or invalid canonical payload must not be presented as a trusted manifest. A verifier may retain a lower trust tier only where the protocol's trust policy explicitly permits that degradation; it must not silently turn an unverifiable document into a trusted one.

The `@ocp-catalog/ocp-crypto` package provides canonicalization, Ed25519 signing and verification, JWKS key selection, discovery key caching, and document trust evaluation. The same signing input is intended to be reproducible across TypeScript, Python, and Go implementations. Interoperability is tested with shared fixtures rather than by relying on a language-specific JSON serializer.

## Attribution chains

An `AttributionToken` carries the core claims for an agent, object, provider, purpose, and `jti`, followed by a bounded chain of origin and relay nodes. Every hop signs its own canonical signing input. A relay must verify the upstream chain before appending a hop; it must not sign a broken chain and pass the failure downstream.

Verification follows the protocol's ordered checks and stops at the first failure. Implementations use explicit outcomes such as `key_not_found`, `signature_invalid`, `token_expired`, `replayed_jti`, `duplicate_order`, and `chain_broken`, so operators can distinguish an invalid token from a missing operational key or a settlement conflict. The chain is bounded to eight hops.

Settlement uses `ConversionReport` and separates two idempotency questions:

- `jti` binds a token to an order and prevents the same token being spent against a different order.
- `order_id` and `report_id` make settlement and report delivery idempotent.

`ReplayStore` and `LedgerStore` are interfaces and transaction contracts in this repository. Their in-memory implementations are for tests and demonstrations. A production deployment must provide durable storage and commit the replay claim, ledger record, and payout in one transactional resource. SQL schemas, connection pooling, payout integration, and key custody belong to the runtime that owns those systems, not to this protocol package.

## Public activity privacy

Raw activity events may carry an optional strict `attribution` block for internal correlation. That block can contain `jti`, `agent_id`, `order_id`, `report_id`, hop information, purpose, and a closed outcome code. It is not a public API shape.

Only an event with explicit `public_visibility: "public"` produces a public activity row. The public allowlist can retain the closed `attribution_outcome`; it never copies the raw attribution block or its subject identifiers. When a correlation join is needed, the projection emits a keyed HMAC-SHA-256 `correlation_id_hash`. Without a projection secret, no correlation digest is emitted. A value-level guard rejects a custom summary that attempts to smuggle an attribution subject into the public row.

This boundary is intentional: public rollups and recent activity can explain protocol outcomes without becoming a source of raw commercial attribution, order identifiers, or agent identity data. Consumers should use the Activity API projection and `events tail`, never raw audit payloads.

## Scope and deployment boundary

This repository defines schemas, cryptographic primitives, verification order, and storage interfaces. It does not provide production secret management, database persistence, payout execution, or a hosted key service. Deployments choose those components while preserving the protocol contracts and the public projection privacy boundary.
