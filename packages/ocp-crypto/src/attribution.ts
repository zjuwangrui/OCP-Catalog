/**
 * Attribution token issuance and per-hop signature primitives.
 *
 * Implements `docs/specs/attribution/v1.md` §4.3 (core claims), §5.2 (signing
 * input), and §5.3 (`complete` recomputation).
 *
 * Scope note: this module builds and signs chains, and verifies one hop's
 * signature. It deliberately does **not** implement the full verifier — replay
 * detection, expiry, provider matching, and per-hop error localisation are the
 * verifier's job (T4) and belong with the policy state those checks need. What
 * lives here is the part that must be byte-identical between signer and
 * verifier, so both sides call the same code and cannot drift.
 *
 * No zod here, same as the rest of the package: §9.1 forbids canonicalizing
 * `parse()` output, and the types below are structural so a caller can pass a
 * Zod-inferred object without the schema ever reaching canonicalization.
 */
import { canonicalizeValue } from './canonical';
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
 * token cannot make that claim from local knowledge alone, which is why
 * multi-hop issuance is a separate entry point (T4) rather than a flag here.
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
