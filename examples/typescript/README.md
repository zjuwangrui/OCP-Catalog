# Minimal OCP Catalog Node — TypeScript

The smallest spec-valid [OCP Catalog Node](../../docs/specs), serving three
hardcoded in-memory products. No database, no vendor API, no auth.

## Run

```bash
bun install
bun run start        # listens on http://localhost:4400
```

Then:

```bash
curl http://localhost:4400/ocp/manifest
curl http://localhost:4400/ocp/health
curl -X POST http://localhost:4400/ocp/query   -H 'content-type: application/json' -d '{"query":"headphones"}'
curl -X POST http://localhost:4400/ocp/resolve -H 'content-type: application/json' -d '{"entry_id":"entry_example_inmemory_sku-001"}'
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/ocp-catalog` | discovery |
| GET | `/.well-known/jwks.json` | the node's public signing keys |
| GET | `/ocp/manifest` | capabilities + query packs |
| GET | `/ocp/health` | liveness |
| GET | `/ocp/contracts` | object contracts (empty — read-only node) |
| POST | `/ocp/query` | keyword search over products |
| POST | `/ocp/resolve` | resolve one entry into action bindings |

## Attribution

This node signs [attribution tokens](../../docs/specs/attribution/v1.md). Resolve
with `purpose: "checkout"` and an `attribution_context`, and the `checkout`
action binding comes back carrying a signed `attribution`:

```bash
curl -X POST http://localhost:4400/ocp/resolve -H 'content-type: application/json' -d '{
  "entry_id": "entry_example_inmemory_sku-001",
  "purpose": "checkout",
  "attribution_context": { "agent_id": "agent_demo_shopper" }
}'
```

Two conditions gate issuance, and each is a reason not to sign rather than a
formality:

| Condition | Why |
|---|---|
| `purpose` is `checkout` | Only checkout settles (spec §7.1). A signed token over a page view would be a settlement claim over a page view. |
| `attribution_context.agent_id` is present | Attribution names *who* brought the buyer. There is nobody to name without it. |

A request that meets none of them gets exactly the response it got before this
node learned to sign — spec §10.2 requires that, and `src/server.test.ts` pins it.

### Relaying: one more hop, not a fresh chain

Past those two gates, an `upstream_token` in the context decides *what* is
signed. Send one and this node appends itself as a `relay` hop instead of
minting a new `origin` chain:

```bash
curl -X POST http://localhost:4400/ocp/resolve -H 'content-type: application/json' -d '{
  "entry_id": "entry_example_inmemory_sku-001",
  "purpose": "checkout",
  "attribution_context": {
    "agent_id": "agent_demo_shopper",
    "upstream_token": { "kind": "AttributionToken", "...": "the token another node signed" }
  }
}'
```

The core claims — `jti`, `iat`, `exp`, `entry_id`, `iss` — come back **unchanged**,
naming the upstream node. They have to: every upstream hop has already signed
over them, so rewriting one would invalidate the very signatures this node is
preserving. Minting a fresh one-hop chain here instead would erase the hops
before it and claim origin for traffic somebody else found.

It refuses to sign — and returns the resolve without an `attribution` — when the
upstream token is for a different `object_id`, already contains this node (a
loop), or is already at the §4.4 cap of 8 hops.

> **This example does not verify the upstream chain before co-signing it, and a
> real node must.** §5.2 makes hop N's signature cover hops 1..N−1 permanently,
> so signing over an unverified chain puts this node's name on someone else's
> forgery. The fix is `verifyAttributionToken` with a resolver over each upstream
> `catalog_id`'s JWKS; the example skips it because it has no key discovery
> configured and the demo is meant to run with the network unplugged.

### Verifying offline

The point of signing is that the merchant does not have to ask the catalog node
whether a claim is real. Fetch the public key once, and every token that key
signed can be checked with the network unplugged:

```bash
# 1. discovery tells you where the keys live
curl -s http://localhost:4400/.well-known/ocp-catalog | jq -r .jwks_url
# 2. fetch them
curl -s http://localhost:4400/.well-known/jwks.json  > jwks.json
curl -s http://localhost:4400/.well-known/ocp-catalog > discovery.json
# 3. and one resolve to have something to check
curl -s -X POST http://localhost:4400/ocp/resolve -H 'content-type: application/json' \
  -d '{"entry_id":"entry_example_inmemory_sku-001","purpose":"checkout",
       "attribution_context":{"agent_id":"agent_demo_shopper"}}' > resolve.json
```

Now stop the server, and verify anyway:

```bash
bun run verify:offline verify .        # or: bun run src/offline-verify.ts verify .
```

```text
OK    attribution verified offline
      agent:    agent_demo_shopper
      hops:     1
      settles:  cat_example_typescript
```

`src/offline-verify.ts` **disables `globalThis.fetch` before it reads a single
file**, so "offline" is enforced rather than asserted: a check that secretly
needed the network would crash instead of passing. `bun run verify:offline
fetch` does the three curls above for you.

The §7.1 filter itself is not reimplemented here — it is `verifyAttributionToken`
from `@ocp-catalog/ocp-crypto`, and a failure comes back with the hop it
localised to. What this file adds is the part that filter structurally cannot
know: whether the token is about *this* resolve, from *this* node. Note it binds
the **last hop** to the discovered `catalog_id`, not `iss` — on a relayed chain
`iss` is the origin node, which is not the one you just talked to.

On a relayed token you need every hop's JWKS, not just this node's. With only
one of them the check fails honestly, and names the hop it could not verify:

```text
FAIL  key_not_found: hop 1: no JWKS on hand for catalog "cat_upstream_..."
```

> The signing key is **generated in memory at startup**, so a restart
> invalidates every token this node has issued — a merchant looking up the old
> `kid` gets `key_not_found`. Correct behaviour (an unverifiable signature must
> not pass), but an outage for a real node. Set `OCP_SIGNING_JWK` to a persisted
> Ed25519 private JWK to keep the key across restarts.

### Settling: the merchant's side of the loop

Verification says the token is real. Settlement says who gets paid, once.
`src/settle.ts` is the merchant half — it reads the same artifacts, files a
`ConversionReport` (§6.1), and runs `settleOrder` from `@ocp-catalog/ocp-crypto`
against a ledger it keeps in `ledger.json`:

```bash
bun run settle report .  ord_1 12900 CNY   # build a report from resolve.json
bun run settle settle .                    # settle it, offline
```

```text
SETTLE ord_1  12900 CNY
       agent:   agent_demo_shopper
       settles: cat_example_typescript
       jti:     atr_...  via last_touch
```

Run the second command again and the answer does not change — it comes back
`(idempotent replay)`, not a second payout. That is the `report_id` key doing
its job. File a *different* report against the same `order_id` and you get the
other half:

```text
REJECT ord_1  duplicate_order: order "ord_1" was already settled by report "rep_..."
```

Two reports carrying different tokens for one order are handed to `settleOrder`
together, and exactly one wins under last-touch (§7.2), with the loser's `jti`
left unclaimed so it can still settle the order it actually belongs to. Pass
`first_touch` as the second argument to see §7.4's configurable rule pick the
other one — a real settler that does this **must publish the rule**, or agents
cannot predict their income.

> The ledger here is a `Map` written back to `ledger.json` after each run —
> enough for a retry to land on the same answer across two CLI invocations, and
> nothing like a real settler. In production it is a table with a unique
> constraint on `order_id`, written in the same transaction as the payout: a
> file rewritten after the fact has a window where the payout happened and the
> dedup row did not.

### The six assertions

`src/demo.ts` runs the whole thing end to end and prints six lines. Two show it
works; four show it cannot be fooled:

```bash
bun run demo                          # in-process, no server needed
bun run demo http://localhost:4400    # same assertions, over real HTTP
```

```text
PASS  1. query → resolve → issue → verify → report → adjudicate, credited to the right catalog
PASS  2. three-hop chain verifies hop by hop, complete = true
PASS  3. rewriting agent_id fails verification, localised to the tampered hop
PASS  4. a token claimed after its exp is rejected
PASS  5. the same jti claimed against a second order is rejected
PASS  6. one order_id settles once — a retry is idempotent, a second claim is refused
```

In a revenue-share setting the last four are the valuable ones. A mechanism that
only demonstrates the happy path is a mechanism nobody should settle money
against — assertions 3–6 are each a way for somebody to get paid twice, and the
script fails loudly if any of them stops holding.

It runs in-process by default because `src/server.ts` exports
`handle(request): Response` — the whole node minus the socket, the same code
path a real request takes. Hops 2 and 3 in assertion 2 are signed by two
throwaway catalogs the script plays itself; they sign with their own keys, so
nothing in the demo can mint a hop on the node's behalf.

## Conformance

`src/server.test.ts` parses every response through the published
[`@ocp-catalog/ocp-schema`](https://www.npmjs.com/package/@ocp-catalog/ocp-schema)
Zod schemas, so the example is provably spec-valid:

```bash
bun test
```

Configuration via env: `CATALOG_ID`, `CATALOG_NAME`, `PORT`, `PUBLIC_BASE_URL`,
`OCP_SIGNING_JWK`.
