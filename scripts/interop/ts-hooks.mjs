/**
 * A Node resolve hook that runs this repo's TypeScript sources directly.
 *
 * The workspace is built for bun, which resolves extensionless relative imports
 * (`./canonical`) and workspace package names (`@ocp-catalog/ocp-crypto`) on its
 * own. Plain Node does neither. Node 24 *can* execute `.ts` — it strips types
 * natively — so resolution is the only gap, and this closes it.
 *
 * It exists so the interop matrix has no bun requirement: a contributor whose
 * job is the Python or Go verifier should not have to install a second
 * JavaScript runtime to check their work against the reference implementation.
 * Load it through its sibling:
 *
 *     node --experimental-strip-types --import ./scripts/interop/register-ts.mjs <script>
 *
 * Resolution only — no transform hook, no transpiler. If a source file uses a
 * TypeScript feature Node cannot strip (enums, constructor parameter
 * properties), this will not rescue it, and it should not: that file would not
 * run under `--experimental-strip-types` for any other consumer either.
 */
const PACKAGES = new URL('../../packages/', import.meta.url);

/** `@ocp-catalog/<name>` → `packages/<name>/src/index.ts`. */
function workspaceEntry(specifier) {
  const match = /^@ocp-catalog\/([a-z0-9-]+)$/.exec(specifier);
  return match ? new URL(`${match[1]}/src/index.ts`, PACKAGES).href : undefined;
}

export async function resolve(specifier, context, nextResolve) {
  const workspace = workspaceEntry(specifier);
  if (workspace) return nextResolve(workspace, context);

  try {
    return await nextResolve(specifier, context);
  } catch (error) {
    // Only relative and absolute specifiers get the `.ts` retry. A bare
    // specifier that failed is a missing dependency, and appending `.ts` would
    // turn a clear "package not found" into a confusing path error.
    const relative = specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('file:');
    if (!relative) throw error;
    for (const suffix of ['.ts', '/index.ts']) {
      try {
        return await nextResolve(specifier + suffix, context);
      } catch {
        // fall through to the next candidate
      }
    }
    throw error;
  }
}
