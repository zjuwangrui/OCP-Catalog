#!/usr/bin/env bun
// Keeps every distribution copy of the OCP Catalog skill derived from the one
// source of truth, skills/ocp-catalog/.
//
// There are two copies because there are two install channels:
//   packages/ocp-skill/skill/            -> npm  (`npx @ocp-catalog/skill`)
//   plugins/ocp-catalog/skills/ocp-catalog/ -> Claude Code plugin marketplace
//
// The npm copy is a build artifact created at pack time and is gitignored.
// The marketplace copy MUST be committed, because Claude Code reads the plugin
// straight from the git tree — so `--check` exists to fail CI/review when that
// committed copy has drifted from source.

import { copyFile, mkdir, readFile, readdir, rm, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const skillName = 'ocp-catalog';
const sourceDir = path.join(repoRoot, 'skills', skillName);

const copies = [
  {
    label: 'npm package payload',
    dir: path.join(repoRoot, 'packages', 'ocp-skill', 'skill'),
    committed: false,
  },
  {
    label: 'Claude Code plugin payload',
    dir: path.join(repoRoot, 'plugins', skillName, 'skills', skillName),
    committed: true,
  },
];

const checkOnly = process.argv.includes('--check');

async function copyDirectory(source: string, target: string): Promise<void> {
  await mkdir(target, { recursive: true });

  for (const entry of await readdir(source)) {
    const sourcePath = path.join(source, entry);
    const targetPath = path.join(target, entry);
    const entryStat = await stat(sourcePath);

    if (entryStat.isDirectory()) {
      await copyDirectory(sourcePath, targetPath);
    } else if (entryStat.isFile()) {
      await copyFile(sourcePath, targetPath);
    }
  }
}

async function hashDirectory(dir: string): Promise<string> {
  const hash = createHash('sha256');

  const walk = async (currentDir: string): Promise<void> => {
    for (const entry of (await readdir(currentDir)).sort()) {
      const fullPath = path.join(currentDir, entry);
      const entryStat = await stat(fullPath);

      if (entryStat.isDirectory()) {
        await walk(fullPath);
        continue;
      }

      if (entryStat.isFile()) {
        hash.update(path.relative(dir, fullPath).replaceAll('\\', '/'));
        hash.update('\0');
        // Normalize line endings so a CRLF checkout does not read as drift.
        hash.update((await readFile(fullPath, 'utf8')).replaceAll('\r\n', '\n'));
        hash.update('\0');
      }
    }
  };

  await walk(dir);
  return hash.digest('hex');
}

if (!existsSync(path.join(sourceDir, 'SKILL.md'))) {
  console.error(`Skill source is missing: ${path.relative(repoRoot, sourceDir)}/SKILL.md`);
  process.exit(1);
}

const sourceHash = await hashDirectory(sourceDir);

if (checkOnly) {
  const drifted: string[] = [];

  for (const copy of copies) {
    if (!copy.committed) continue;

    const relative = path.relative(repoRoot, copy.dir).replaceAll('\\', '/');
    if (!existsSync(copy.dir)) {
      drifted.push(`${relative} is missing`);
      continue;
    }

    if ((await hashDirectory(copy.dir)) !== sourceHash) {
      drifted.push(`${relative} differs from skills/${skillName}`);
    }
  }

  if (drifted.length > 0) {
    console.error(
      [
        'Skill copies are out of sync:',
        ...drifted.map((item) => `- ${item}`),
        '',
        'Run `bun run skill:sync` and commit the result.',
      ].join('\n'),
    );
    process.exit(1);
  }

  console.log(`Skill copies are in sync with skills/${skillName} (${sourceHash.slice(0, 12)}).`);
} else {
  for (const copy of copies) {
    await rm(copy.dir, { recursive: true, force: true });
    await copyDirectory(sourceDir, copy.dir);
    console.log(`Synced ${copy.label}: ${path.relative(repoRoot, copy.dir).replaceAll('\\', '/')}`);
  }

  console.log(`Source hash ${sourceHash.slice(0, 12)}`);
}
