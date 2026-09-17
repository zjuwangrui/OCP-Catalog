# Attribution interop fixture

`attribution-v1.json` is the cross-language contract for
[attribution v1](../../../../docs/specs/attribution/v1.md). One file, three
implementations, nine matrix cells.

Regenerate with
[`scripts/interop/build-attribution-fixture.mjs`](../../../../scripts/interop/build-attribution-fixture.mjs).
Do not hand-edit: the signatures are over canonical bytes, so a one-character
change to any signed member invalidates the hop that signed it and every hop
after it.

## What it pins

| Member | Claim |
|---|---|
| `keys[]` | three deterministic Ed25519 key pairs, seeds included |
| `jwks` | the same public keys as one JWKS per `catalog_id`, which is what a verifier actually holds |
| `issue` | the issuance recipe: core claims, three hops, every `signed_at` fixed |
| `expected_signing_input[]` | the exact canonical bytes each hop signs |
| `expected_token` | the token that recipe must produce |
| `expected_token_sha256` | its canonical hash |
| `verify` | the verification parameters and the verdict they must produce |
| `negative[]` | 13 tampered or ineligible tokens, each with the error code and hop it must produce |

## Byte identity, not mutual acceptance

Ed25519 is deterministic and OCP-JCS fixes the bytes, so the same recipe under
the same key must produce the *same signature* in every language — not merely a
signature the others accept. `expected_token_sha256` is therefore an equality
assertion, and it is a much stronger one: two implementations can happily
verify each other while both disagreeing with the spec.

`expected_signing_input` exists to make a failure debuggable rather than
mysterious. If the signatures disagree but the signing inputs agree, the bug is
in key handling; if the signing inputs disagree, the bug is in canonicalization.
Without it, "the signature does not verify" is the only symptom of two very
different defects.

## The negative cases

Each names the exact error code and, where the failure localises to one hop,
the hop number. Both halves matter. The code is what §8 fixes so that a token
violating three rules at once produces the same one verdict everywhere; the hop
number is what §5.2 makes meaningful — altering hop K breaks hops K..N, so the
*lowest* failing hop is the tamper site, and an implementation that reports any
other one is naming an innocent node.

Three of them exercise the parameters rather than the token
(`provider-mismatch`, `token-not-yet-valid`, `token-expired`) and carry a
`verify_overrides` member. One is separately signed rather than tampered with:
`purpose-not-settleable` is a legitimately signed single-hop `view` token,
because `purpose` is a core claim and editing it in place would fail as
`signature_invalid` long before reaching §7.1 row 6.

## Who runs it

| Implementation | Command |
|---|---|
| TypeScript | `node --experimental-strip-types --import ./scripts/interop/register-ts.mjs scripts/interop/ts-agent.mjs selftest` |
| Python | `python examples/python/interop_agent.py selftest` |
| Go | `go run ./interop selftest` (from `examples/go`) |
| all nine cells | `node --experimental-strip-types --import ./scripts/interop/register-ts.mjs scripts/interop/matrix.mjs` |

A new implementation joins the matrix by exposing the same three verbs —
`sign`, `verify <token.json>`, `selftest` — over this file. The runner knows
nothing else about the languages it drives.
