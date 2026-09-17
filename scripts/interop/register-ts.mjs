/**
 * Installs {@link file://./ts-hooks.mjs} into the module loader.
 *
 * Split from the hook itself because `register` runs the hook module on a
 * separate loader thread: a self-registering file would be evaluated twice and
 * would try to register itself from inside the loader.
 *
 *     node --experimental-strip-types --import ./scripts/interop/register-ts.mjs <script>
 */
import { register } from 'node:module';

register('./ts-hooks.mjs', import.meta.url);
