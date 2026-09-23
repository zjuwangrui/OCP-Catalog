# Signed protocol documents and commercial attribution are now documented

OCP Catalog now documents the verification path that connects signed discovery and manifest documents, trust policy, attribution chains, settlement safeguards, and privacy-preserving public activity.

The new [Crypto and Attribution](/docs/protocols/crypto-attribution/overview) guide explains:

- OCP canonical JSON and Ed25519 document signatures
- `ocp catalog inspect --verify`
- JWKS key selection and trust degradation rules
- TypeScript, Python, and Go interoperability
- bounded, per-hop signed attribution chains
- `jti`, `order_id`, and `report_id` replay and idempotency semantics
- durable `ReplayStore` and `LedgerStore` contracts
- keyed `correlation_id_hash` and the public Activity API privacy boundary

The protocol repository defines the schemas, signing inputs, verification order, and storage interfaces. Production key custody, durable databases, payout execution, and deployment secrets remain responsibilities of the runtime deployment.

The OCP Catalog skill references and README package list have also been updated so CLI users and package consumers can find these capabilities from their existing entry points.
