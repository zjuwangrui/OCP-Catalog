/**
 * Attribution token issuance and per-hop signature primitives.
 *
 * Implements `docs/specs/attribution/v1.md` §4.3 (core claims), §5.2 (signing
 * input), §5.3 (`complete` recomputation), and §5.4 (structure validation).
 *
 * Scope note: this module builds and signs chains, and verifies one hop's
 * signature. The full §7.1 eligibility filter — key resolution, expiry,
 * provider matching, replay, and localising a failure to a hop — lives in
 * `verify.ts`, because those checks need policy state and network-shaped
 * inputs that issuance does not. What lives here is the part that must be
 * byte-identical between signer and verifier, so both sides call the same code
 * and cannot drift.
 *
 * No zod here, same as the rest of the package: §9.1 forbids canonicalizing
 * `parse()` output, and the types below are structural so a caller can pass a
 * Zod-inferred object without the schema ever reaching canonicalization.
 */
import { canonicalizeValue } from './canonical';
import { AttributionError } from './errors';
import {
  OCP_SIGNATURE_ALG,
  signCanonical,
  verifyCanonical,
  type Ed25519PrivateJwk,
  type Ed25519PublicJwk,
} from './keys';

/** §4.4 — bounded so a verifier cannot be made to run unbounded verifications. */
export const MAX_CHAIN_LENGTH = 8;

export type AttributionRole = 'origin' | 'relay';
export type AttributionPurpose = 'view' | 'checkout' | 'contact' | 'workflow';
export type AgentIdentitySource = 'ocp' | 'external';

export interface ChainNode {
  catalog_id: string;
  hop: number;
  role: AttributionRole;
  settles: boolean;
  chain_complete: boolean;
  alg: typeof OCP_SIGNATURE_ALG;
  kid: string;
  signed_at: string;
  signature: string;
}

/** A chain node before its signature exists — the §5.2 `unsigned(node)` form. */
export type UnsignedChainNode = Omit<ChainNode, 'signature'>;

export interface CoreClaims {
  ocp_version: string;
  kind: 'AttributionToken';
  jti: string;
  iss: string;
  iat: string;
  exp: string;
  agent_id: string;
  agent_identity_source?: AgentIdentitySource;
  entry_id: string;
  object_id: string;
  provider_id: string;
  purpose: AttributionPurpose;
}

export interface AttributionToken extends CoreClaims {
  complete: boolean;
  chain: ChainNode[];
}

/**
 * §4.3 — core claims are the token minus `complete` and `chain`.
 *
 * Built by *removing* the two derived members rather than by copying a list of
 * wanted keys. A future optional claim would silently drop out of the signed
 * material under a copy-list, and a claim that is signed by one implementation
 * and not another is a verification failure with no useful error message.
 */
export function coreClaims(token: AttributionToken | CoreClaims): CoreClaims {
  const { complete: _complete, chain: _chain, ...core } = token as AttributionToken;
  return core;
}

/** §5.2 — `unsigned(node)`: every field except `signature`. */
export function unsignedNode(node: ChainNode | UnsignedChainNode): UnsignedChainNode {
  const { signature: _signature, ...rest } = node as ChainNode;
  return rest;
}

/**
 * §5.2 — the signing input for hop N.
 *
 * `chain` holds hops 1..N in order, each in unsigned form; `core` holds the
 * immutable claims. Member order inside the object is irrelevant — OCP-JCS
 * sorts it — but the array order is semantics and is preserved.
 */
export function attributionSigningInput(
  chainPrefix: ReadonlyArray<ChainNode | UnsignedChainNode>,
  core: CoreClaims,
): { chain: UnsignedChainNode[]; core: CoreClaims } {
  return { chain: chainPrefix.map(unsignedNode), core };
}

/** The exact bytes hop N signs. Exposed for debugging a signature mismatch. */
export function attributionSigningBytes(
  chainPrefix: ReadonlyArray<ChainNode | UnsignedChainNode>,
  core: CoreClaims,
): string {
  return canonicalizeValue(attributionSigningInput(chainPrefix, core));
}

/**
 * Signs hop N, where `chainPrefix` is hops 1..N−1 and `node` is hop N unsigned.
 *
 * Note that hop N signs *itself* as well as its predecessors — the prefix
 * passed to the canonicalizer is `[...chainPrefix, node]`. Omitting the node's
 * own fields would leave `settles` and `chain_complete` unsigned, and those two
 * are exactly the fields with money attached.
 */
export function signChainNode(params: {
  privateJwk: Ed25519PrivateJwk;
  core: CoreClaims;
  chainPrefix: ReadonlyArray<ChainNode>;
  node: UnsignedChainNode;
}): ChainNode {
  const { privateJwk, core, chainPrefix, node } = params;
  const signature = signCanonical(privateJwk, attributionSigningInput([...chainPrefix, node], core));
  return { ...node, signature };
}

/**
 * Verifies one hop's signature against the chain prefix it committed to.
 *
 * `chain` is the full chain; `hopIndex` is 0-based. Returns a boolean rather
 * than throwing, for the reason given on `verifyBytes`: a bad signature is data
 * the caller must record and keep going from.
 */
export function verifyChainNodeSignature(params: {
  jwk: Ed25519PublicJwk;
  core: CoreClaims;
  chain: ReadonlyArray<ChainNode>;
  hopIndex: number;
}): boolean {
  const { jwk, core, chain, hopIndex } = params;
  const node = chain[hopIndex];
  if (!node) return false;
  return verifyCanonical({
    jwk,
    value: attributionSigningInput(chain.slice(0, hopIndex + 1), core),
    signature: node.signature,
    alg: node.alg,
  });
}

/**
 * §5.3 — `complete` is the AND of every hop's `chain_complete`.
 *
 * A verifier must call this and compare, never read `token.complete`: that
 * field sits outside all signed material, so it is the cheapest possible place
 * to probe for a verifier that trusts what it is told.
 */
export function recomputeComplete(chain: ReadonlyArray<Pick<ChainNode, 'chain_complete'>>): boolean {
  return chain.every((node) => node.chain_complete);
}

/**
 * §5.4 — structure validation, which §7.1 runs *before* any signature check.
 *
 * Returns the reason the chain is malformed, or `undefined` if it is well
 * formed. A reason string rather than a boolean because all four conditions
 * collapse to one error code (`chain_broken`), so the only way a caller can
 * tell a cycle from a renumbered hop is if this function says which.
 *
 * Doing this first is not an optimisation for the happy path — it is a refusal
 * to run eight signature verifications on behalf of a chain that is already
 * known to be junk.
 */
export function checkChainStructure(chain: ReadonlyArray<ChainNode>): string | undefined {
  if (chain.length < 1) return 'chain is empty';
  if (chain.length > MAX_CHAIN_LENGTH) {
    return `chain has ${chain.length} hops, over the §4.4 cap of ${MAX_CHAIN_LENGTH}`;
  }

  const seen = new Set<string>();
  for (const [index, node] of chain.entries()) {
    const expectedHop = index + 1;
    if (node.hop !== expectedHop) {
      return `chain[${index}].hop is ${node.hop}, expected ${expectedHop}`;
    }
    const expectedRole: AttributionRole = index === 0 ? 'origin' : 'relay';
    if (node.role !== expectedRole) {
      return `hop ${expectedHop} has role "${node.role}", expected "${expectedRole}"`;
    }
    // A repeat is a loop, not a topology: the same node cannot both hand off
    // and receive back without an unrecorded hop in between.
    if (seen.has(node.catalog_id)) {
      return `catalog_id "${node.catalog_id}" appears twice (hop ${expectedHop} repeats an earlier hop)`;
    }
    seen.add(node.catalog_id);
  }

  return undefined;
}

export interface AppendRelayHopParams {
  privateJwk: Ed25519PrivateJwk;
  kid: string;
  catalogId: string;
  /** The upstream token this node received. Its core claims are preserved verbatim. */
  token: AttributionToken;
  /**
   * Whether this node received the token **directly** from the hop above it,
   * with no unrecorded intermediary (§5.1).
   *
   * Deliberately required, with no default. It is the one fact in the node that
   * only this relay knows, and both defaults are wrong: `true` would let a
   * careless integrator assert a completeness it cannot back, and `false` would
   * quietly make every chain incomplete and the field worthless.
   */
  chainComplete: boolean;
  /**
   * Whether this node takes a cut. Defaults to `false`, the opposite of
   * {@link issueOriginToken}: §5.1 notes that not every relay is in the money
   * flow, and forgetting to declare a share you are owed is a recoverable
   * mistake, while claiming one you are not is a false settlement claim signed
   * under your own key.
   */
  settles?: boolean;
  now?: () => Date;
}

/**
 * Appends one `relay` hop to an existing token and signs the whole prefix.
 *
 * The core claims — `jti`, `iat`, `exp`, `agent_id`, the object identifiers —
 * are carried through untouched. They must be: every upstream hop already
 * signed over them, so altering one here would invalidate the signatures of
 * the hops this node is trying to preserve.
 *
 * Throws {@link AttributionError} with code `chain_broken` if the upstream
 * chain is malformed, already at the §4.4 cap, or already contains this node.
 * Refusing to sign is the right failure: a signature this node emits over a
 * chain it knows to be invalid is worse than no attribution at all, because it
 * carries this node's name.
 */
export function appendRelayHop(params: AppendRelayHopParams): AttributionToken {
  const {
    privateJwk,
    kid,
    catalogId,
    token,
    chainComplete,
    settles = false,
    now = () => new Date(),
  } = params;

  const broken = checkChainStructure(token.chain);
  if (broken) {
    throw new AttributionError('chain_broken', `refusing to relay a malformed chain: ${broken}`);
  }
  if (token.chain.length >= MAX_CHAIN_LENGTH) {
    throw new AttributionError(
      'chain_broken',
      `chain is already ${token.chain.length} hops, at the §4.4 cap of ${MAX_CHAIN_LENGTH}`,
    );
  }
  if (token.chain.some((node) => node.catalog_id === catalogId)) {
    throw new AttributionError(
      'chain_broken',
      `"${catalogId}" is already in this chain; appending it again would make a loop`,
    );
  }

  const core = coreClaims(token);
  const unsigned: UnsignedChainNode = {
    catalog_id: catalogId,
    hop: token.chain.length + 1,
    role: 'relay',
    settles,
    chain_complete: chainComplete,
    alg: OCP_SIGNATURE_ALG,
    kid,
    signed_at: now().toISOString(),
  };

  const node = signChainNode({ privateJwk, core, chainPrefix: token.chain, node: unsigned });
  const chain = [...token.chain, node];

  return { ...core, complete: recomputeComplete(chain), chain };
}

export interface IssueOriginTokenParams {
  privateJwk: Ed25519PrivateJwk;
  kid: string;
  catalogId: string;
  agentId: string;
  agentIdentitySource?: AgentIdentitySource;
  entryId: string;
  objectId: string;
  providerId: string;
  purpose: AttributionPurpose;
  /** Whether this node takes a cut. `false` for a node that only routes. */
  settles?: boolean;
  ttlSeconds?: number;
  jti?: string;
  now?: () => Date;
  ocpVersion?: string;
}

/**
 * Issues a fresh single-hop token — the `origin` case, where this node is the
 * first to put the object in front of an agent.
 *
 * `chain_complete` is `true` because a chain of one that this node started has
 * no unrecorded upstream by construction. A relay appending to someone else's
 * token cannot make that claim from local knowledge, which is why
 * {@link appendRelayHop} is a separate entry point that demands the answer
 * rather than a flag here that could default to it.
 */
export function issueOriginToken(params: IssueOriginTokenParams): AttributionToken {
  const {
    privateJwk,
    kid,
    catalogId,
    agentId,
    agentIdentitySource,
    entryId,
    objectId,
    providerId,
    purpose,
    settles = true,
    ttlSeconds = 3600,
    now = () => new Date(),
    ocpVersion = '1.0',
  } = params;

  const issuedAt = now();
  const jti = params.jti ?? `atr_${crypto.randomUUID()}`;

  const core: CoreClaims = {
    ocp_version: ocpVersion,
    kind: 'AttributionToken',
    jti,
    iss: catalogId,
    iat: issuedAt.toISOString(),
    exp: new Date(issuedAt.getTime() + ttlSeconds * 1000).toISOString(),
    agent_id: agentId,
    ...(agentIdentitySource ? { agent_identity_source: agentIdentitySource } : {}),
    entry_id: entryId,
    object_id: objectId,
    provider_id: providerId,
    purpose,
  };

  const unsigned: UnsignedChainNode = {
    catalog_id: catalogId,
    hop: 1,
    role: 'origin',
    settles,
    chain_complete: true,
    alg: OCP_SIGNATURE_ALG,
    kid,
    signed_at: issuedAt.toISOString(),
  };

  const node = signChainNode({ privateJwk, core, chainPrefix: [], node: unsigned });

  return { ...core, complete: recomputeComplete([node]), chain: [node] };
}
