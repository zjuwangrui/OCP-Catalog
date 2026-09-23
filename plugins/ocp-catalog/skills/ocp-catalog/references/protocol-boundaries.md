# Protocol Boundaries

OCP Catalog has separate protocol roles:

- Registration Node: catalog discovery, verification, route hints, and metadata search.
- Catalog Node: manifest, contracts, provider registration, object sync, query, resolve, and action binding exposure.
- Provider: authoritative object source and sync participant.
- Activity API: event ingest, redaction, public projection, and rollups.
- CLI / Skill / MCP / WebMCP / plugins: adapter layers that call the protocol and may emit client-side activity events.

Do not make Registration search commercial objects. Do not make Catalog act as the global telemetry hub. Do not make the website accept raw protocol payloads.

Protocol request bodies are strict. Use a separate activity endpoint and trace headers for observability.

## Cryptographic Verification

Signed discovery and manifest documents are verified over OCP canonical JSON with the declared Ed25519 key. Resolve the `kid`, preserve the protocol's verification order, and treat verification failures as explicit results rather than trusted data. A lower trust tier is valid only when the document's trust policy permits that degradation.

An attribution relay must verify every upstream hop before signing its own hop. Verification stops at the first protocol-defined error so independent implementations return the same outcome. Do not rebuild signing input, reorder checks, or append to a broken chain.

## Durable Attribution State

`ReplayStore` and `LedgerStore` are deployment interfaces, not production storage implementations. The in-memory `JtiRegistry` and `SettlementLedger` are for tests and demonstrations. A production settlement path must persist replay claims and settlement records, and commit those writes with the payout in one transaction. Secret custody, SQL, migrations, and payout execution belong to the runtime deployment.

Raw activity may contain attribution subjects for internal audit and correlation. Public activity is a strict projection: it may expose a closed `attribution_outcome` and a keyed `correlation_id_hash`, but never raw attribution, `jti`, `agent_id`, `order_id`, or `report_id`. If there is no projection secret, omit the correlation digest rather than publishing an unkeyed hash.
