/**
 * The 3x3 cross-language **document signature** matrix (plan T4).
 *
 *     node --experimental-strip-types --import ./scripts/interop/register-ts.mjs \
 *          scripts/interop/signature-matrix.mjs
 *
 * Has each of the three implementations sign the fixture's recipe, then has
 * each of the three verify all three resulting documents. Nine cells, all of
 * which must be green.
 *
 * The risk this closes is the one the plan names: manifest signing was
 * specified, implemented once, and verified once, so "a third party can check
 * this node's manifest" rested on that third party running our TypeScript.
 * Two independent ports agreeing with it is evidence; three agreeing across
 * every cell is the claim the protocol actually needs to make.
 *
 * Sibling of `matrix.mjs`, which does the same for attribution tokens. Kept
 * separate rather than folded in, because the two sign different material: an
 * attribution chain node signs the chain prefix plus the token's core claims, a
 * document signs its envelope minus `signature`. A single runner reporting
 * "interop: green" over both would let one of them regress behind the other's
 * result.
 *
 * Three distinct things are checked, and conflating them would hide a failure:
 *
 *   1. Signing agreement. Ed25519 is deterministic and OCP-JCS fixes the bytes,
 *      so the same recipe under the same key must produce the *same signature*,
 *      not merely a valid one. Each signer's document is compared against
 *      `expected_signed_document_sha256` — byte identity, not mutual acceptance.
 *   2. Verification agreement. Each verifier re-reads each signer's file from
 *      disk, so it parses another language's JSON formatting (indentation,
 *      member order, number spelling) rather than its own.
 *   3. Rejection agreement. Three implementations that all accept the good
 *      document prove very little if they disagree about *why* they reject a
 *      bad one. A verifier is only as good as the failures it can tell apart,
 *      so all twelve negatives must yield the same §8 code and the same §9
 *      trust ceiling in every language.
 *
 * Every agent is driven through the same verbs over the same fixture, so this
 * runner knows nothing about the languages it drives.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalValueHash } from '@ocp-catalog/ocp-crypto';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const GO_DIR = join(ROOT, 'examples', 'go');
const FIXTURE = JSON.parse(
  readFileSync(join(ROOT, 'packages', 'ocp-crypto', 'fixtures', 'signature', 'manifest-v1.json'), 'utf8'),
);

/**
 * The three participants. `python` and `go` are overridable because neither
 * binary has one name everywhere — python3 on most Linux images, and a
 * toolchain that is not on PATH at all is a legitimate reason to skip a row
 * rather than to fail the suite.
 */
const AGENTS = [
  {
    id: 'typescript',
    command: process.execPath,
    args: [
      '--experimental-strip-types',
      '--import',
      './scripts/interop/register-ts.mjs',
      'scripts/interop/ts-signature-agent.mjs',
    ],
    cwd: ROOT,
  },
  {
    id: 'python',
    command: process.env.OCP_PYTHON ?? 'python',
    args: [join('examples', 'python', 'signature_interop_agent.py')],
    cwd: ROOT,
  },
  {
    id: 'go',
    command: process.env.OCP_GO ?? 'go',
    args: ['run', './interopsig'],
    cwd: GO_DIR,
  },
];

function run(agent, verbArgs) {
  const result = spawnSync(agent.command, [...agent.args, ...verbArgs], {
    cwd: agent.cwd,
    encoding: 'utf8',
    // Inherited so a toolchain that needs PATH or GOCACHE still works, but the
    // agents are given no OCP-specific configuration — each one has to find the
    // fixture on its own, the way a third-party implementation would.
    env: process.env,
  });
  if (result.error) throw result.error;
  return result;
}

/** The last non-empty stdout line, so a runtime warning above it is harmless. */
function lastJsonLine(text) {
  const lines = text.split('\n').filter((line) => line.trim() !== '');
  return JSON.parse(lines[lines.length - 1]);
}

const workdir = mkdtempSync(join(tmpdir(), 'ocp-sigmatrix-'));
const failures = [];
const note = (message) => failures.push(message);

try {
  // --- column 1: signing -----------------------------------------------------
  console.log('signing (each implementation runs the fixture recipe):\n');
  const documents = [];
  for (const agent of AGENTS) {
    const result = run(agent, ['sign']);
    if (result.status !== 0) {
      note(`${agent.id} could not sign: ${result.stderr.trim() || `exit ${result.status}`}`);
      console.log(`  FAIL ${agent.id.padEnd(11)} ${result.stderr.trim().split('\n')[0] ?? `exit ${result.status}`}`);
      continue;
    }
    const document = JSON.parse(result.stdout);
    const path = join(workdir, `${agent.id}.json`);
    // Written exactly as the agent printed it. Re-serializing here would erase
    // the formatting differences that make the verification half meaningful.
    writeFileSync(path, result.stdout, 'utf8');

    const hash = canonicalValueHash(document);
    const identical = hash === FIXTURE.expected_signed_document_sha256;
    if (!identical) note(`${agent.id} produced a different document: ${hash}`);
    console.log(`  ${identical ? 'ok  ' : 'FAIL'} ${agent.id.padEnd(11)} ${hash}`);
    documents.push({ signer: agent.id, path });
  }

  if (documents.length !== AGENTS.length) {
    throw new Error('not every implementation produced a signed document; the matrix cannot be completed');
  }

  // --- the grid --------------------------------------------------------------
  console.log('\nverifying (rows verify, columns signed):\n');
  console.log(`  ${['verifier'.padEnd(12), ...documents.map((d) => d.signer.padEnd(12))].join('')}`);

  const want = FIXTURE.verify.expect;
  for (const agent of AGENTS) {
    const cells = [];
    for (const { signer, path } of documents) {
      const result = run(agent, ['verify', path]);
      let ok = false;
      let detail = result.stderr.trim() || `exit ${result.status}`;
      try {
        const verdict = lastJsonLine(result.stdout);
        ok =
          result.status === 0 &&
          verdict.ok === true &&
          ['issuer', 'kid', 'alg', 'signed_at', 'payload_hash'].every((k) => verdict[k] === want[k]) &&
          verdict.trust_tier === want.trust_tier &&
          verdict.invalidates_cache === want.invalidates_cache;
        detail = JSON.stringify(verdict);
      } catch {
        // detail keeps the stderr text: an agent that crashed printed no JSON.
      }
      if (!ok) note(`${agent.id} rejected the document ${signer} signed: ${detail}`);
      cells.push((ok ? 'ok' : 'FAIL').padEnd(12));
    }
    console.log(`  ${agent.id.padEnd(12)}${cells.join('')}`);
  }

  // --- the negatives ---------------------------------------------------------
  //
  // Compared against the fixture *and* against each other. Agreement alone
  // would be satisfied by three implementations that are wrong in the same way,
  // and matching the fixture alone would not say which language drifted.
  console.log('\nrejecting (each negative must give one code and one ceiling everywhere):\n');
  const outcomes = new Map();
  for (const agent of AGENTS) {
    const result = run(agent, ['negatives']);
    if (result.status !== 0) {
      note(`${agent.id} could not run the negatives: ${result.stderr.trim() || `exit ${result.status}`}`);
      continue;
    }
    outcomes.set(agent.id, lastJsonLine(result.stdout));
  }

  if (outcomes.size === AGENTS.length) {
    // 34 wide because "signature-one-byte-changed" is 26 characters and the
    // "ok   " prefix eats five of them.
    const NAME_WIDTH = 34;
    console.log(`  ${['negative'.padEnd(NAME_WIDTH), 'code'.padEnd(20), 'ceiling'.padEnd(12), 'cache'].join('')}`);
    for (const [index, negative] of FIXTURE.negative.entries()) {
      const rows = AGENTS.map((agent) => outcomes.get(agent.id)[index]);
      const agree = rows.every(
        (row) =>
          row.name === negative.name &&
          row.code === rows[0].code &&
          row.trust_tier === rows[0].trust_tier &&
          row.invalidates_cache === rows[0].invalidates_cache,
      );
      const correct =
        rows[0].code === negative.expected_error &&
        rows[0].trust_tier === negative.expected_trust_tier &&
        rows[0].invalidates_cache === negative.expected_invalidates_cache;

      if (!agree) {
        note(
          `the three languages disagree on "${negative.name}": ${AGENTS.map(
            (a, i) => `${a.id}=${rows[i].code}/${rows[i].trust_tier}`,
          ).join(' ')}`,
        );
      } else if (!correct) {
        note(
          `all three got "${negative.name}" wrong: ${rows[0].code}/${rows[0].trust_tier}, ` +
            `expected ${negative.expected_error}/${negative.expected_trust_tier}`,
        );
      }
      const mark = agree && correct ? 'ok  ' : 'FAIL';
      console.log(
        `  ${mark} ${negative.name.padEnd(NAME_WIDTH - 5)}${String(rows[0].code).padEnd(20)}` +
          `${String(rows[0].trust_tier).padEnd(12)}${rows[0].invalidates_cache ? 'invalidated' : 'kept'}`,
      );
    }
  }
} finally {
  rmSync(workdir, { recursive: true, force: true });
}

const cellCount = AGENTS.length * AGENTS.length;
if (failures.length > 0) {
  console.log(`\nsignature matrix: ${failures.length} failure(s)\n`);
  for (const failure of failures) console.log(`  - ${failure}`);
  process.exit(1);
}
console.log(
  `\nsignature matrix: ${cellCount}/${cellCount} cells green, all three signatures byte-identical, ` +
    `${FIXTURE.negative.length}/${FIXTURE.negative.length} negatives agree on code and trust ceiling`,
);
