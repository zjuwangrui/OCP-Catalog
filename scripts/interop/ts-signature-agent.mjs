/**
 * The TypeScript participant in the three-language **document signature** matrix.
 *
 *     node --experimental-strip-types --import ./scripts/interop/register-ts.mjs \
 *          scripts/interop/ts-signature-agent.mjs sign
 *     ... ts-signature-agent.mjs verify <document.json>
 *     ... ts-signature-agent.mjs selftest
 *
 * Same three verbs as `ts-agent.mjs`, over a different fixture and a different
 * signing material. `examples/python/signature_interop_agent.py` and
 * `examples/go/interopsig` are the other two participants;
 * `scripts/interop/signature-matrix.mjs` drives all three.
 *
 * Two agents rather than one because the two signatures are not
 * interchangeable: an attribution chain node signs the chain prefix plus the
 * token's core claims, a document signs its envelope minus `signature`.
 * Teaching one agent both verbs would invite a caller to hand a manifest to the
 * attribution verifier and read "invalid" as "forged" rather than "wrong
 * verifier".
 *
 * - `sign`     runs the fixture's signing recipe and prints the signed document.
 * - `verify`   runs §7 over a document file, prints the verdict **and the §9
 *              trust ceiling** as JSON, and exits non-zero on rejection.
 * - `negatives` prints one `{name, code, trust_tier, invalidates_cache}` per
 *              fixture negative, which is what the matrix compares across
 *              languages.
 * - `selftest` checks this language against every part of the fixture it can
 *              check alone: byte-identical signing of both documents, the
 *              positive verdict, and all 12 negatives with their exact §8 code,
 *              trust tier and cache-invalidation flag.
 */
import { readFileSync } from 'node:fs';
import {
  canonicalValueHash,
  canonicalizeValue,
  signDocument,
  staticDocumentKeyResolver,
  trustCeilingFor,
  verifyDocumentSignature,
} from '@ocp-catalog/ocp-crypto';

const FIXTURE = new URL('../../packages/ocp-crypto/fixtures/signature/manifest-v1.json', import.meta.url);
const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8'));

/**
 * The fixture holds one JWKS per `catalog_id`, and `staticDocumentKeyResolver`
 * takes a single JWKS — so it is applied per issuer rather than once. Composed
 * from the exported helper rather than reaching into the key set directly,
 * because the `kid` lookup and its `key_not_found` / `alg_not_supported` split
 * is exactly the behaviour the negatives assert on.
 */
const resolveKey = ({ issuer, kid }) => staticDocumentKeyResolver(fixture.jwks[issuer])({ issuer, kid });

/**
 * The fixture's signing recipe, executed. Must be byte-reproducible.
 *
 * `signed_at` comes from the recipe, never from the clock: the whole point of
 * the matrix is that three languages produce the same bytes, and a timestamp
 * read at runtime would make that impossible to assert.
 */
function signManifest(expiring = false) {
  const recipe = fixture.sign;
  const now = () => new Date(recipe.signed_at);
  return expiring
    ? signDocument({
        document: recipe.expiring_document,
        privateJwk: fixture.key.private_jwk,
        expiresAt: new Date(recipe.expiring_expires_at),
        now,
      })
    : signDocument({ document: recipe.document, privateJwk: fixture.key.private_jwk, now });
}

/**
 * §7 plus §9 under the fixture's verification parameters, as plain JSON — the
 * shape all three agents agree on.
 *
 * The ceiling travels with the verdict because a caller that reads only `ok`
 * will treat `unsigned` and `payload_mismatch` identically, and §9 exists
 * precisely to keep them apart.
 */
async function verifyManifest(document, overrides = {}) {
  const at = new Date(overrides.at ?? fixture.verify.at);
  const result = await verifyDocumentSignature({
    document,
    resolveKey,
    at,
    ...(overrides.expected_issuer ? { expectedIssuer: overrides.expected_issuer } : {}),
  });
  const ceiling = trustCeilingFor(result);
  const common = { trust_tier: ceiling.trustTier, invalidates_cache: ceiling.invalidatesCache };
  return result.ok
    ? {
        ok: true,
        issuer: result.issuer,
        kid: result.kid,
        alg: result.alg,
        signed_at: result.signedAt,
        expires_at: result.expiresAt ?? null,
        payload_hash: result.payloadHash,
        ...common,
      }
    : { ok: false, code: result.error.code, message: result.error.message, ...common };
}

/**
 * Each negative's §8 code and §9 ceiling, in the shape the matrix compares
 * across languages.
 *
 * A separate verb from `verify` because the matrix needs all three languages'
 * answers side by side, and two of the negatives carry their own `at`
 * override — driving them through `verify` one file at a time would mean
 * passing that override on the command line and getting it wrong somewhere.
 */
async function negativeOutcomes() {
  const outcomes = [];
  for (const negative of fixture.negative) {
    const got = await verifyManifest(negative.document, negative.verify_overrides ?? {});
    outcomes.push({
      name: negative.name,
      code: got.code ?? null,
      trust_tier: got.trust_tier,
      invalidates_cache: got.invalidates_cache,
    });
  }
  return outcomes;
}

/** Each check prints its own line, so a failure names itself without a stack. */
async function selftest() {
  const failures = [];
  const check = (name, condition, detail) => {
    if (condition) console.log(`  ok   ${name}`);
    else {
      console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
      failures.push(name);
    }
  };

  const signed = signManifest();
  check(
    'signing is byte-identical to the fixture',
    canonicalizeValue(signed) === canonicalizeValue(fixture.expected_signed_document),
    'canonical form differs from expected_signed_document',
  );
  check(
    'the signed document hashes to expected_signed_document_sha256',
    canonicalValueHash(signed) === fixture.expected_signed_document_sha256,
    `got ${canonicalValueHash(signed)}`,
  );
  check(
    'the signed envelope matches expected_envelope',
    canonicalizeValue(signed.signature) === canonicalizeValue(fixture.expected_envelope),
    'envelope differs',
  );
  check(
    'the expiring document is byte-identical too',
    canonicalizeValue(signManifest(true)) === canonicalizeValue(fixture.expected_expiring_signed_document),
    'canonical form differs from expected_expiring_signed_document',
  );

  const verdict = await verifyManifest(fixture.expected_signed_document);
  const want = fixture.verify.expect;
  check(
    'the good document verifies with the expected verdict',
    verdict.ok &&
      ['issuer', 'kid', 'alg', 'signed_at', 'payload_hash'].every((k) => verdict[k] === want[k]) &&
      verdict.trust_tier === want.trust_tier &&
      verdict.invalidates_cache === want.invalidates_cache,
    JSON.stringify(verdict),
  );

  const outcomes = await negativeOutcomes();
  for (const [i, negative] of fixture.negative.entries()) {
    const got = outcomes[i];
    check(
      `negative: ${negative.name}`,
      got.code === negative.expected_error &&
        got.trust_tier === negative.expected_trust_tier &&
        got.invalidates_cache === negative.expected_invalidates_cache,
      `got ${JSON.stringify({
        code: got.code,
        trust_tier: got.trust_tier,
        invalidates_cache: got.invalidates_cache,
      })}`,
    );
  }

  console.log(failures.length ? `\ntypescript: ${failures.length} failed` : '\ntypescript: all checks passed');
  return failures.length === 0;
}

const args = process.argv.slice(2);
const [verb, arg] = args;
if (verb === 'sign') {
  process.stdout.write(`${JSON.stringify(signManifest(args.includes('--expiring')), null, 2)}\n`);
} else if (verb === 'verify' && arg) {
  const verdict = await verifyManifest(JSON.parse(readFileSync(arg, 'utf8')));
  process.stdout.write(`${JSON.stringify(verdict)}\n`);
  process.exit(verdict.ok ? 0 : 1);
} else if (verb === 'negatives') {
  process.stdout.write(`${JSON.stringify(await negativeOutcomes())}\n`);
} else if (verb === 'selftest') {
  process.exit((await selftest()) ? 0 : 1);
} else {
  console.error(
    'usage: ts-signature-agent.mjs sign [--expiring] | verify <document.json> | negatives | selftest',
  );
  process.exit(2);
}
