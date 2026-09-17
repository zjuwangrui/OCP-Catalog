/**
 * The TypeScript participant in the three-language interop matrix.
 *
 *     node --experimental-strip-types --import ./scripts/interop/register-ts.mjs \
 *          scripts/interop/ts-agent.mjs sign
 *     ... ts-agent.mjs verify <token.json>
 *     ... ts-agent.mjs selftest
 *
 * Every language exposes these same three verbs over the same fixture, so the
 * matrix runner does not need to know anything about the language it is
 * driving. `examples/python/interop_agent.py` and `examples/go/interop` are the
 * other two.
 *
 * - `sign`    builds the fixture's token from the issuance recipe and prints it.
 * - `verify`  runs §7.1 over a token file and prints the verdict as JSON,
 *             exiting non-zero on rejection.
 * - `selftest` checks this language against every part of the fixture it can
 *             check alone: byte-identical issuance, the positive verdict, and
 *             all 13 negative cases with their exact code and hop.
 */
import { readFileSync } from 'node:fs';
import {
  canonicalizeValue,
  recomputeComplete,
  signChainNode,
  staticKeyResolver,
  verifyAttributionToken,
} from '@ocp-catalog/ocp-crypto';

const FIXTURE = new URL('../../packages/ocp-crypto/fixtures/interop/attribution-v1.json', import.meta.url);
const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8'));

const privateJwkOf = (catalogId) => fixture.keys.find((k) => k.catalog_id === catalogId).private_jwk;

/** The issuance recipe from the fixture, executed. Must be byte-reproducible. */
function signToken() {
  const { core, hops } = fixture.issue;
  const chain = [];
  for (const hop of hops) {
    const unsigned = {
      catalog_id: hop.catalog_id,
      hop: hop.hop,
      role: hop.role,
      settles: hop.settles,
      chain_complete: hop.chain_complete,
      alg: 'EdDSA',
      kid: hop.kid,
      signed_at: hop.signed_at,
    };
    chain.push(
      signChainNode({ privateJwk: privateJwkOf(hop.catalog_id), core, chainPrefix: chain, node: unsigned }),
    );
  }
  return { ...core, complete: recomputeComplete(chain), chain };
}

async function verifyToken(token, overrides = {}) {
  const at = new Date(overrides.at ?? fixture.verify.at);
  const expectedProviderId = overrides.expected_provider_id ?? fixture.verify.expected_provider_id;
  const result = await verifyAttributionToken({
    token,
    resolveKey: staticKeyResolver(fixture.jwks),
    at,
    expectedProviderId,
  });
  return result.ok
    ? {
        ok: true,
        complete: result.complete,
        hops: result.hops,
        agent_id: result.agentId,
        settling_catalog_ids: result.settlingCatalogIds,
        last_signed_at: result.lastSignedAt,
      }
    : { ok: false, code: result.error.code, hop: result.error.hop ?? null, message: result.error.message };
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

  const signed = signToken();
  check(
    'issuance is byte-identical to the fixture',
    canonicalizeValue(signed) === canonicalizeValue(fixture.expected_token),
    'canonical form differs from expected_token',
  );

  const verdict = await verifyToken(fixture.expected_token);
  const want = fixture.verify.expect;
  check(
    'the good token verifies with the expected verdict',
    verdict.ok &&
      verdict.complete === want.complete &&
      verdict.hops === want.hops &&
      verdict.agent_id === want.agent_id &&
      verdict.last_signed_at === want.last_signed_at &&
      JSON.stringify(verdict.settling_catalog_ids) === JSON.stringify(want.settling_catalog_ids),
    JSON.stringify(verdict),
  );

  for (const negative of fixture.negative) {
    const got = await verifyToken(negative.token, negative.verify_overrides ?? {});
    const hopMatches = negative.expected_hop === undefined || got.hop === negative.expected_hop;
    check(
      `negative: ${negative.name}`,
      !got.ok && got.code === negative.expected_error && hopMatches,
      `got ${JSON.stringify({ code: got.code, hop: got.hop })}`,
    );
  }

  console.log(failures.length ? `\ntypescript: ${failures.length} failed` : '\ntypescript: all checks passed');
  return failures.length === 0;
}

const [verb, arg] = process.argv.slice(2);
if (verb === 'sign') {
  process.stdout.write(`${JSON.stringify(signToken(), null, 2)}\n`);
} else if (verb === 'verify') {
  const verdict = await verifyToken(JSON.parse(readFileSync(arg, 'utf8')));
  process.stdout.write(`${JSON.stringify(verdict)}\n`);
  process.exit(verdict.ok ? 0 : 1);
} else if (verb === 'selftest') {
  process.exit((await selftest()) ? 0 : 1);
} else {
  console.error('usage: ts-agent.mjs sign | verify <token.json> | selftest');
  process.exit(2);
}
