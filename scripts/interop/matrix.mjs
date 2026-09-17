/**
 * The 3x3 cross-language attribution matrix (plan W4-T3).
 *
 *     node --experimental-strip-types --import ./scripts/interop/register-ts.mjs \
 *          scripts/interop/matrix.mjs
 *
 * Has each of the three implementations sign the fixture's issuance recipe,
 * then has each of the three verify all three resulting tokens. Nine cells, all
 * of which must be green.
 *
 * The risk this closes is the one the plan names: until now only TypeScript
 * could verify an attribution token, so "the spec is implementable" rested on a
 * single implementation agreeing with itself. Two independent ports agreeing
 * with it is evidence; three agreeing across every cell is the claim the
 * protocol actually needs to make.
 *
 * Two distinct things are checked, and conflating them would hide a failure:
 *
 *   1. Signing agreement. Ed25519 is deterministic and OCP-JCS fixes the bytes,
 *      so the same recipe under the same key must produce the *same signature*,
 *      not merely a valid one. Each signer's token is compared canonically
 *      against expected_token_sha256 -- byte identity, not mutual acceptance.
 *   2. Verification agreement. Each verifier re-reads each signer's file from
 *      disk, so it parses another language's JSON formatting (indentation,
 *      member order, number spelling) rather than its own.
 *
 * Every agent is driven through the same three verbs over the same fixture, so
 * this runner knows nothing about the languages it drives.
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
  readFileSync(join(ROOT, 'packages', 'ocp-crypto', 'fixtures', 'interop', 'attribution-v1.json'), 'utf8'),
);

/**
 * The three participants. `python` and `go` are overridable because neither
 * binary has one name everywhere -- python3 on most Linux images, and a
 * toolchain that is not on PATH at all is a legitimate reason to skip a row
 * rather than to fail the suite.
 */
const AGENTS = [
  {
    id: 'typescript',
    command: process.execPath,
    args: ['--experimental-strip-types', '--import', './scripts/interop/register-ts.mjs', 'scripts/interop/ts-agent.mjs'],
    cwd: ROOT,
  },
  {
    id: 'python',
    command: process.env.OCP_PYTHON ?? 'python',
    args: [join('examples', 'python', 'interop_agent.py')],
    cwd: ROOT,
  },
  {
    id: 'go',
    command: process.env.OCP_GO ?? 'go',
    args: ['run', './interop'],
    cwd: GO_DIR,
  },
];

function run(agent, verbArgs) {
  const result = spawnSync(agent.command, [...agent.args, ...verbArgs], {
    cwd: agent.cwd,
    encoding: 'utf8',
    // Inherited so a toolchain that needs PATH or GOCACHE still works, but the
    // agents are given no OCP-specific configuration -- each one has to find
    // the fixture on its own, the way a third-party implementation would.
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

const workdir = mkdtempSync(join(tmpdir(), 'ocp-matrix-'));
const failures = [];
const note = (message) => failures.push(message);

try {
  // --- column 1: signing -----------------------------------------------------
  console.log('signing (each implementation runs the fixture recipe):\n');
  const tokens = [];
  for (const agent of AGENTS) {
    const result = run(agent, ['sign']);
    if (result.status !== 0) {
      note(`${agent.id} could not sign: ${result.stderr.trim() || `exit ${result.status}`}`);
      console.log(`  FAIL ${agent.id.padEnd(11)} ${result.stderr.trim().split('\n')[0] ?? `exit ${result.status}`}`);
      continue;
    }
    const token = JSON.parse(result.stdout);
    const path = join(workdir, `${agent.id}.json`);
    // Written exactly as the agent printed it. Re-serializing here would erase
    // the formatting differences that make the verification half meaningful.
    writeFileSync(path, result.stdout, 'utf8');

    const hash = canonicalValueHash(token);
    const identical = hash === FIXTURE.expected_token_sha256;
    if (!identical) note(`${agent.id} produced a different token: ${hash}`);
    console.log(`  ${identical ? 'ok  ' : 'FAIL'} ${agent.id.padEnd(11)} ${hash}`);
    tokens.push({ signer: agent.id, path });
  }

  if (tokens.length !== AGENTS.length) {
    throw new Error('not every implementation produced a token; the matrix cannot be completed');
  }

  // --- the grid --------------------------------------------------------------
  console.log('\nverifying (rows verify, columns signed):\n');
  const header = ['verifier'.padEnd(12), ...tokens.map((t) => t.signer.padEnd(12))].join('');
  console.log(`  ${header}`);

  const want = FIXTURE.verify.expect;
  for (const agent of AGENTS) {
    const cells = [];
    for (const { signer, path } of tokens) {
      const result = run(agent, ['verify', path]);
      let ok = false;
      let detail = result.stderr.trim() || `exit ${result.status}`;
      try {
        const verdict = lastJsonLine(result.stdout);
        ok =
          result.status === 0 &&
          verdict.ok === true &&
          verdict.complete === want.complete &&
          verdict.hops === want.hops &&
          verdict.agent_id === want.agent_id &&
          verdict.last_signed_at === want.last_signed_at &&
          JSON.stringify(verdict.settling_catalog_ids) === JSON.stringify(want.settling_catalog_ids);
        detail = JSON.stringify(verdict);
      } catch {
        // detail keeps the stderr text: an agent that crashed printed no JSON.
      }
      if (!ok) note(`${agent.id} rejected the token ${signer} signed: ${detail}`);
      cells.push((ok ? 'ok' : 'FAIL').padEnd(12));
    }
    console.log(`  ${agent.id.padEnd(12)}${cells.join('')}`);
  }
} finally {
  rmSync(workdir, { recursive: true, force: true });
}

const cellCount = AGENTS.length * AGENTS.length;
if (failures.length > 0) {
  console.log(`\nmatrix: ${failures.length} failure(s)\n`);
  for (const failure of failures) console.log(`  - ${failure}`);
  process.exit(1);
}
console.log(`\nmatrix: ${cellCount}/${cellCount} cells green, all three signatures byte-identical`);
