# Document signature conformance vectors

`manifest-v1.json` is the conformance set [crypto v1](../../../../docs/specs/crypto/v1.md)
§11 requires. One signed `CatalogManifest`, one key, twelve negative cases.

Regenerate with
[`scripts/interop/build-signature-fixture.mjs`](../../../../scripts/interop/build-signature-fixture.mjs).
Do not hand-edit: every member of the document is inside `payload_hash`, and
every member of the envelope except `signature` is inside the signature, so a
one-character change invalidates the file rather than updating it.

## What it pins

| Member | Claim |
|---|---|
| `key` | one deterministic Ed25519 key pair, seed included |
| `jwks` | the same public key as the JWKS a verifier would hold for that `catalog_id` |
| `sign` | the signing recipe: the document, a fixed `signed_at`, and a second document with an `expires_at` |
| `expected_payload_hash` | `sha256(OCP-JCS(document minus "signature"))` — §4.1 layer one |
| `expected_signing_input` | the exact canonical bytes signed — §4.1 layer two |
| `expected_envelope` | the envelope that recipe must produce |
| `expected_signed_document` | the whole signed document, byte for byte |
| `expected_signed_document_sha256` | its canonical hash |
| `verify` | the verification parameters, the verdict, and the trust ceiling |
| `negative[]` | 12 documents, each with the error code **and** the trust ceiling it must produce |

## Two hashes, because there are two layers

§4.1 binds the document to the envelope by hash and the envelope to the key by
signature. Pinning only the final signature would leave a port unable to tell
which layer drifted. With both here: a wrong `expected_payload_hash` means the
document canonicalization differs, and a correct hash with a wrong signature
means the envelope canonicalization does. This is also why a tampered payload
and a tampered envelope have separate codes — see §4.2.

## The negative cases

Each covers one §8 code, and each also names the §9 trust ceiling. Both halves
are normative: an implementation that reports `payload_mismatch` and then keeps
serving the cached manifest has read §8 and skipped §9.

Three cases break more than one rule at once — `order-alg-before-payload`,
`order-payload-before-key`, `order-expiry-last`. They exist because rejecting a
bad document is easy and every port will do it; reporting the *first* failing
step of §7 is the part ports get wrong, and it is what stops three
implementations from disagreeing about a document all three reject.

Two are separately signed rather than tampered with. `unsigned` is the bare
document, and the expiry cases use `expected_expiring_signed_document`, because
`expires_at` is inside the signed material — adding it to the good document
would fail at step 7 as `signature_invalid` and never reach step 8.

## Who runs it

| Implementation | Command |
|---|---|
| TypeScript | `bun test packages/ocp-crypto/src/signature-vectors.test.ts` |
| TypeScript agent | `node --experimental-strip-types --import ./scripts/interop/register-ts.mjs scripts/interop/ts-signature-agent.mjs selftest` |
| Python | `python examples/python/signature_interop_agent.py selftest` |
| Go | `go run ./interopsig selftest` (from `examples/go`) |
| all nine cells | `node --experimental-strip-types --import ./scripts/interop/register-ts.mjs scripts/interop/signature-matrix.mjs` |

A new implementation joins the matrix by exposing the same four verbs —
`sign [--expiring]`, `verify <document.json>`, `negatives`, `selftest` — over
this file. The runner knows nothing else about the languages it drives.

`negatives` is its own verb rather than twelve `verify` calls because two of the
negatives carry a `verify_overrides.at`, and passing that on a command line is
the likeliest place for one language to get it quietly wrong. The runner
compares the three arrays against this file **and** against each other:
agreement alone would be satisfied by three implementations wrong in the same
way, and matching the file alone would not say which one drifted.

This matrix is deliberately separate from
[the attribution one](../interop/README.md), because the two sign different
material — an attribution chain node signs the chain prefix plus the token's
core claims, a document signs its envelope minus `signature`. One runner
reporting "interop: green" over both would let either regress behind the
other's result.
