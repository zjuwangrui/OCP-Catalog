"""OCP attribution tokens in Python: issue, relay, and verify.

Spec: `docs/specs/attribution/v1.md`. A port of `packages/ocp-crypto`'s
`attribution.ts`, `keys.ts` and `verify.ts`, collapsed into one module because
the Python example has no package boundary to respect. Everything byte-sensitive
goes through `ocp_canonical`, and nothing here re-implements OCP-JCS.

What makes this worth having: attribution is only useful if a merchant can
verify a token **offline, from public keys alone**, in whatever language their
settlement job is already written in. A verifier that exists in one language is
a trust anchor with a vendor attached. This file is the Python half of closing
that -- `examples/go/attribution.go` is the other.

Scope, per the W4 plan: verification is the deliverable, issuance is here so the
cross-language matrix has three signers instead of one. Signing from Python
inherits the timing caveat in `ocp_ed25519`.
"""
from __future__ import annotations

import base64
import hashlib
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

import ocp_ed25519
from ocp_canonical import canonicalize_value_to_bytes

__all__ = [
    "AttributionError",
    "CryptoError",
    "MAX_CHAIN_LENGTH",
    "OCP_SIGNATURE_ALG",
    "AttributionVerdict",
    "JtiRegistry",
    "append_relay_hop",
    "assert_ed25519_public_jwk",
    "attribution_signing_bytes",
    "check_chain_structure",
    "core_claims",
    "from_base64url",
    "generate_key_pair",
    "issue_origin_token",
    "jwk_thumbprint",
    "public_jwk_of",
    "recompute_complete",
    "rfc3339",
    "static_key_resolver",
    "to_base64url",
    "verify_attribution_token",
    "verify_chain_node_signature",
]

OCP_SIGNATURE_ALG = "EdDSA"
#: §4.4 -- bounded so a verifier cannot be made to run unbounded verifications.
MAX_CHAIN_LENGTH = 8

Json = Mapping[str, Any]


class AttributionError(Exception):
    """A verdict about a token: one §7.1 code, optionally localised to a hop."""

    def __init__(self, code: str, message: str, hop: Optional[int] = None) -> None:
        super().__init__(f"[{code}]{f' hop {hop}' if hop else ''} {message}")
        self.code = code
        self.message = message
        self.hop = hop


class CryptoError(Exception):
    """A failure about key material, which is not the same as a bad token."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Encoding and keys
# ---------------------------------------------------------------------------

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")


def to_base64url(data: bytes) -> str:
    """base64url, unpadded -- the encoding attribution spec §5.2 mandates."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_base64url(value: str, what: str = "value") -> bytes:
    """Decode base64url and reject padding.

    `base64.urlsafe_b64decode` tolerates `=` padding and, with the right
    length, plain base64's `+/`. Accepting those would make two distinct
    encodings of one signature both valid -- a malleability foothold -- and
    would admit values that `AttributionChainNode.signature`'s own pattern
    (`^[A-Za-z0-9_-]+$`) rejects.
    """
    if not _BASE64URL.match(value):
        raise CryptoError("invalid_encoding", f"{what} is not unpadded base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def assert_ed25519_public_jwk(candidate: Any, what: str = "JWK") -> Json:
    """Validate that an arbitrary JWKS entry is an Ed25519 signing key.

    Raises `alg_not_supported` -- not `key_not_found` -- when the key exists but
    is the wrong kind. §8 keeps those codes separate and the distinction is
    operationally real: one means "you are looking at the wrong node", the other
    means "that node published something I will not verify with".
    """
    if not isinstance(candidate, Mapping):
        raise CryptoError("invalid_key", f"{what} is not an object")
    if candidate.get("kty") != "OKP" or candidate.get("crv") != "Ed25519":
        raise CryptoError(
            "alg_not_supported",
            f"{what} is kty={candidate.get('kty')} crv={candidate.get('crv')}; only OKP/Ed25519 is supported",
        )
    alg = candidate.get("alg")
    if alg is not None and alg != OCP_SIGNATURE_ALG:
        raise CryptoError("alg_not_supported", f"{what} declares alg={alg}; only EdDSA is supported")
    use = candidate.get("use")
    if use is not None and use != "sig":
        raise CryptoError("alg_not_supported", f"{what} declares use={use}; a signing key is required")
    x = candidate.get("x")
    if not isinstance(x, str):
        raise CryptoError("invalid_key", f'{what} has no "x" member')
    raw = from_base64url(x, f"{what}.x")
    if len(raw) != ocp_ed25519.KEY_BYTES:
        raise CryptoError("invalid_key", f"{what}.x decodes to {len(raw)} bytes, expected {ocp_ed25519.KEY_BYTES}")
    return candidate


def jwk_thumbprint(jwk: Json) -> str:
    """RFC 7638 thumbprint.

    The RFC describes SHA-256 over the required members in lexicographic order
    with no whitespace, which is OCP-JCS v1 applied to `{crv, kty, x}` -- so it
    reuses the canonicalizer rather than hand-rolling the JSON. One fewer place
    for member order to drift.
    """
    canonical = canonicalize_value_to_bytes({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]})
    return to_base64url(hashlib.sha256(canonical).digest())


def generate_key_pair(seed: Optional[bytes] = None, kid: Optional[str] = None) -> tuple[dict, dict]:
    """Return `(public_jwk, private_jwk)`.

    `kid` defaults to the RFC 7638 thumbprint, so a rotated key gets a new `kid`
    automatically and an operator cannot accidentally republish two different
    keys under one identifier.
    """
    import secrets

    seed = seed if seed is not None else secrets.token_bytes(ocp_ed25519.KEY_BYTES)
    x = to_base64url(ocp_ed25519.public_key_from_seed(seed))
    base = {"kty": "OKP", "crv": "Ed25519", "x": x, "alg": OCP_SIGNATURE_ALG, "use": "sig"}
    resolved_kid = kid or jwk_thumbprint(base)
    public = {**base, "kid": resolved_kid}
    private = {**public, "d": to_base64url(seed)}
    return public, private


def public_jwk_of(private_jwk: Json) -> dict:
    """Drop `d` so a private JWK can be published."""
    return {k: v for k, v in private_jwk.items() if k != "d"}


def _sign_bytes(private_jwk: Json, message: bytes) -> str:
    d = private_jwk.get("d")
    if not isinstance(d, str):
        raise CryptoError("invalid_key", 'private JWK has no "d" member')
    seed = from_base64url(d, "JWK.d")
    if len(seed) != ocp_ed25519.KEY_BYTES:
        raise CryptoError("invalid_key", f"JWK.d decodes to {len(seed)} bytes, expected {ocp_ed25519.KEY_BYTES}")
    return to_base64url(ocp_ed25519.sign(seed, message))


def _verify_bytes(jwk: Any, message: bytes, signature: str, alg: str = OCP_SIGNATURE_ALG) -> bool:
    """Verify a detached signature.

    Returns `False` for a signature that does not match, and *raises* for an
    unusable algorithm or key. "This signature is wrong" is a fact about the
    data that a verifier must record and keep going from; "I cannot evaluate
    this algorithm" is a trust failure that must not be filed as a mismatch.
    """
    if alg != OCP_SIGNATURE_ALG:
        raise CryptoError("alg_not_supported", f"alg={alg} is not supported; only EdDSA is")
    public_jwk = assert_ed25519_public_jwk(jwk)
    try:
        raw = from_base64url(signature, "signature")
    except CryptoError:
        return False  # a malformed signature is a mismatch, not a config error
    return ocp_ed25519.verify(from_base64url(public_jwk["x"], "JWK.x"), message, raw)


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------


def rfc3339(moment: datetime) -> str:
    """Format as `YYYY-MM-DDTHH:MM:SS.mmmZ`.

    Millisecond precision with a literal `Z` is not cosmetic here: it is what
    JavaScript's `Date.toISOString()` produces, and `iat` / `exp` / `signed_at`
    are inside the signed material. `datetime.isoformat()` would emit
    microseconds and `+00:00`, and a Python-issued token would then be
    byte-different from the TypeScript one for the same inputs -- which the
    cross-language matrix asserts against.
    """
    utc = moment.astimezone(timezone.utc)
    return f"{utc.strftime('%Y-%m-%dT%H:%M:%S')}.{utc.microsecond // 1000:03d}Z"


def _instant(value: Any) -> Optional[datetime]:
    """Parse an RFC 3339 claim, or `None` if it is not a usable instant."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Chain primitives (§4.3, §5.2, §5.3, §5.4)
# ---------------------------------------------------------------------------


def core_claims(token: Json) -> dict:
    """§4.3 -- core claims are the token minus `complete` and `chain`.

    Built by *removing* the two derived members rather than copying a list of
    wanted keys. A future optional claim would silently drop out of the signed
    material under a copy-list, and a claim signed by one implementation and not
    another is a verification failure with no useful error message.
    """
    return {k: v for k, v in token.items() if k not in ("complete", "chain")}


def unsigned_node(node: Json) -> dict:
    """§5.2 -- `unsigned(node)`: every field except `signature`."""
    return {k: v for k, v in node.items() if k != "signature"}


def _signing_input(chain_prefix: Sequence[Json], core: Json) -> dict:
    """§5.2 -- the signing input for hop N.

    `chain_prefix` holds hops 1..N in order, each reduced to unsigned form.
    Member order inside the object is irrelevant (OCP-JCS sorts it); array
    order is semantics and is preserved.
    """
    return {"chain": [unsigned_node(n) for n in chain_prefix], "core": dict(core)}


def attribution_signing_bytes(chain_prefix: Sequence[Json], core: Json) -> bytes:
    """The exact bytes hop N signs. Exposed for debugging a signature mismatch."""
    return canonicalize_value_to_bytes(_signing_input(chain_prefix, core))


def sign_chain_node(private_jwk: Json, core: Json, chain_prefix: Sequence[Json], node: Json) -> dict:
    """Sign hop N, where `chain_prefix` is hops 1..N-1 and `node` is hop N.

    Hop N signs *itself* as well as its predecessors -- the prefix handed to the
    canonicalizer is `[*chain_prefix, node]`. Omitting the node's own fields
    would leave `settles` and `chain_complete` unsigned, and those two are
    exactly the fields with money attached.
    """
    signature = _sign_bytes(private_jwk, attribution_signing_bytes([*chain_prefix, node], core))
    return {**node, "signature": signature}


def verify_chain_node_signature(jwk: Any, core: Json, chain: Sequence[Json], hop_index: int) -> bool:
    """Verify one hop's signature against the chain prefix it committed to."""
    if hop_index >= len(chain):
        return False
    node = chain[hop_index]
    return _verify_bytes(
        jwk,
        attribution_signing_bytes(chain[: hop_index + 1], core),
        node.get("signature", ""),
        node.get("alg", OCP_SIGNATURE_ALG),
    )


def recompute_complete(chain: Iterable[Json]) -> bool:
    """§5.3 -- `complete` is the AND of every hop's `chain_complete`.

    A verifier must call this and compare, never read `token["complete"]`: that
    field sits outside all signed material, so it is the cheapest possible place
    to probe for a verifier that trusts what it is told.
    """
    return all(node.get("chain_complete") is True for node in chain)


def check_chain_structure(chain: Sequence[Json]) -> Optional[str]:
    """§5.4 -- structure validation, which §7.1 runs *before* any signature check.

    Returns the reason the chain is malformed, or `None`. A reason string rather
    than a boolean because all four conditions collapse to one error code
    (`chain_broken`), so the only way a caller can tell a cycle from a
    renumbered hop is if this function says which.

    Running it first is not a happy-path optimisation -- it is a refusal to run
    eight signature verifications on behalf of a chain already known to be junk.
    """
    if len(chain) < 1:
        return "chain is empty"
    if len(chain) > MAX_CHAIN_LENGTH:
        return f"chain has {len(chain)} hops, over the §4.4 cap of {MAX_CHAIN_LENGTH}"

    seen: set[str] = set()
    for index, node in enumerate(chain):
        expected_hop = index + 1
        if node.get("hop") != expected_hop:
            return f"chain[{index}].hop is {node.get('hop')}, expected {expected_hop}"
        expected_role = "origin" if index == 0 else "relay"
        if node.get("role") != expected_role:
            return f'hop {expected_hop} has role "{node.get("role")}", expected "{expected_role}"'
        # A repeat is a loop, not a topology: the same node cannot both hand off
        # and receive back without an unrecorded hop in between.
        catalog_id = node.get("catalog_id")
        if catalog_id in seen:
            return f'catalog_id "{catalog_id}" appears twice (hop {expected_hop} repeats an earlier hop)'
        seen.add(catalog_id)
    return None


# ---------------------------------------------------------------------------
# Key resolution and the replay guard
# ---------------------------------------------------------------------------

KeyResolver = Callable[[str, str, int], Json]


def static_key_resolver(jwks_by_catalog_id: Mapping[str, Any]) -> KeyResolver:
    """A resolver over key material already in hand -- one JWKS per `catalog_id`.

    This is the offline path, and exactly what a merchant has after curling each
    node once. It touches no network, so a verification built on it cannot
    silently acquire a network dependency.
    """

    def resolve(catalog_id: str, kid: str, hop: int) -> Json:
        jwks = jwks_by_catalog_id.get(catalog_id)
        keys = jwks.get("keys") if isinstance(jwks, Mapping) else None
        if not isinstance(keys, list):
            raise CryptoError("key_not_found", f'no JWKS on hand for catalog "{catalog_id}"')
        for key in keys:
            if isinstance(key, Mapping) and key.get("kid") == kid:
                return assert_ed25519_public_jwk(key)
        raise CryptoError("key_not_found", f'kid "{kid}" is not in the JWKS of "{catalog_id}"')

    return resolve


class JtiRegistry:
    """§7.1 row 10 -- the `jti` replay guard.

    The rule is narrow and worth restating: the same `jti` against the **same**
    `order_id` is normal traffic (a retry, a status update). The same `jti`
    against a **different** `order_id` is one attribution token being spent
    twice, which is the whole attack.

    **This is in-memory, and production needs persistent storage.** Not a
    caveat, a correctness gap with a name: a restart empties it, so every token
    issued before the restart becomes replayable once more; and it is
    per-process, so two settlement workers behind a load balancer hold two maps
    and the same token can be claimed once in each. The replacement is a row in
    the same transactional store that records the settlement, keyed on `jti`
    with the `order_id` beside it -- the claim and the payout have to commit
    together or the guard can be lost after the money moves.

    Retention is derived, not configured: an entry is kept until the token's own
    `exp`, because past that §7.1 row 9 rejects the token anyway.
    """

    def __init__(self, now: Optional[Callable[[], datetime]] = None, max_entries: int = 100_000) -> None:
        self._claims: dict[str, tuple[str, datetime]] = {}
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._max_entries = max_entries

    @property
    def size(self) -> int:
        self.prune()
        return len(self._claims)

    def prune(self) -> None:
        now = self._now()
        for jti in [j for j, (_, exp) in self._claims.items() if exp <= now]:
            del self._claims[jti]

    def claim(self, jti: str, order_id: str, expires_at: datetime) -> bool:
        """Bind `jti` to `order_id`. `False` if already bound elsewhere -- a replay.

        Raises once full rather than evicting a live entry. Evicting would open
        a replay window silently, at whatever moment the process happened to be
        busiest; an operator who sees this error is being told to move the guard
        into a database, which is the actual fix.
        """
        self.prune()
        existing = self._claims.get(jti)
        if existing is not None:
            return existing[0] == order_id
        if len(self._claims) >= self._max_entries:
            raise RuntimeError(
                f"JtiRegistry is full ({self._max_entries} live claims). This guard is in-memory by "
                "design and does not evict, because evicting a live claim reopens the replay it "
                "exists to prevent. Move it to persistent storage."
            )
        self._claims[jti] = (order_id, expires_at)
        return True

    def order_of(self, jti: str) -> Optional[str]:
        self.prune()
        claim = self._claims.get(jti)
        return claim[0] if claim else None


# ---------------------------------------------------------------------------
# The §7.1 eligibility filter
# ---------------------------------------------------------------------------


class AttributionVerdict:
    """The outcome of running §7.1 over one token. A rejection is data, not a raise."""

    __slots__ = ("ok", "error", "complete", "agent_id", "settling_catalog_ids", "last_signed_at", "hops")

    def __init__(
        self,
        ok: bool,
        error: Optional[AttributionError] = None,
        complete: bool = False,
        agent_id: str = "",
        settling_catalog_ids: Optional[list[str]] = None,
        last_signed_at: str = "",
        hops: int = 0,
    ) -> None:
        self.ok = ok
        self.error = error
        self.complete = complete
        self.agent_id = agent_id
        self.settling_catalog_ids = settling_catalog_ids or []
        self.last_signed_at = last_signed_at
        self.hops = hops

    def __repr__(self) -> str:
        if self.ok:
            return (
                f"<AttributionVerdict ok hops={self.hops} complete={self.complete} "
                f"settles={self.settling_catalog_ids}>"
            )
        return f"<AttributionVerdict {self.error.code} hop={self.error.hop}: {self.error.message}>"


def _fail(code: str, message: str, hop: Optional[int] = None) -> AttributionVerdict:
    return AttributionVerdict(ok=False, error=AttributionError(code, message, hop))


def verify_attribution_token(
    token: Json,
    resolve_key: KeyResolver,
    at: Optional[datetime] = None,
    expected_provider_id: Optional[str] = None,
    require_purpose: Optional[str] = "checkout",
    replay_guard: Optional[tuple[JtiRegistry, str]] = None,
    claim_jti: bool = True,
) -> AttributionVerdict:
    """Run the §7.1 eligibility filter over one token, stopping at the first failure.

    §7.1 is written as a settlement filter but it is also the normative
    *verification order*: §8 fixes the order to that table's rows and requires
    termination at the first failure. The reason is conformance, not taste -- a
    token that violates three rules at once must produce the same one error code
    in every implementation, or the shared vectors cannot assert anything about
    it. That is the entire reason this file mirrors `verify.ts` row for row
    instead of checking the same things in whatever order reads best in Python.

    Returns a verdict rather than raising, because a settler holds several
    candidate tokens and must record why each one lost before adjudicating among
    the survivors (§7.2).

    **Except** for key-material failures that are not about the token: if the
    JWKS is unreachable, stale or malformed, this propagates the `CryptoError`.
    A node whose key server is down has not forged anything, and turning its
    outage into `key_not_found` would settle against it as though it had. Only
    `key_not_found`, `alg_not_supported` and `invalid_key` -- all statements
    about key material actually published under that `kid` -- become verdicts.

    ### One deviation from §7.1's printed row order, and why

    Rows 3, 4, 5 are listed as signature -> key -> alg, which cannot be executed
    in that order: verifying a signature requires the key, and verifying it
    under an unchecked algorithm is the algorithm-confusion hole §5.1 exists to
    close. This runs each hop as alg -> key -> signature, hops ascending, and
    the spec has been corrected to match (§7.1, v1.0.1).

    Ascending hop order is itself normative: §5.2's second implied property is
    that altering hop K breaks hops K..N, so the lowest failing hop *is* the
    tampered one. Reporting any other failing hop would name an innocent node.
    """
    at = at or datetime.now(timezone.utc)
    chain = token.get("chain") or []

    # Row 1 -- structure, before any signature work (§5.4).
    broken = check_chain_structure(chain)
    if broken:
        return _fail("chain_broken", broken)

    # Row 2 -- recompute `complete`; never read it (§5.3).
    complete = recompute_complete(chain)
    if token.get("complete") != complete:
        return _fail(
            "complete_mismatch",
            f"token says complete={token.get('complete')}, "
            f"the chain's chain_complete flags recompute to {complete}",
        )

    # Rows 3-5, per hop, ascending. See the note above on their order.
    core = core_claims(token)
    for index, node in enumerate(chain):
        hop = index + 1

        if node.get("alg") != OCP_SIGNATURE_ALG:
            return _fail("alg_not_supported", f'alg is "{node.get("alg")}", expected "{OCP_SIGNATURE_ALG}"', hop)

        try:
            jwk = resolve_key(node.get("catalog_id", ""), node.get("kid", ""), hop)
        except CryptoError as err:
            # "Resolvable" in row 4 covers a kid that is present but unusable:
            # a key we cannot verify with is a key we did not find.
            if err.code in ("key_not_found", "invalid_key"):
                return _fail("key_not_found", err.message, hop)
            if err.code == "alg_not_supported":
                return _fail("alg_not_supported", err.message, hop)
            raise  # jwks_unavailable / jwks_expired / jwks_malformed -- not a verdict

        if not verify_chain_node_signature(jwk, core, chain, index):
            return _fail(
                "signature_invalid",
                f'hop {hop} ({node.get("catalog_id")}) does not verify against its chain prefix',
                hop,
            )

    # Row 6 -- only checkout settles.
    if require_purpose is not None and token.get("purpose") != require_purpose:
        return _fail("purpose_not_settleable", f'purpose is "{token.get("purpose")}", only "{require_purpose}" settles')

    # Row 7 -- the report and the token must name the same provider.
    if expected_provider_id is not None and token.get("provider_id") != expected_provider_id:
        return _fail(
            "provider_mismatch",
            f'report names provider "{expected_provider_id}", token names "{token.get("provider_id")}"',
        )

    # Rows 8, 9 -- the validity window, measured at `at`, which is the moment
    # the token is being claimed for (a report's `occurred_at`), not the moment
    # of verification. Checking against "now" would reject a valid sale
    # reported an hour late.
    iat, exp = _instant(token.get("iat")), _instant(token.get("exp"))
    if iat is None or exp is None:
        return _fail("chain_broken", f'iat/exp are not usable timestamps: iat="{token.get("iat")}" exp="{token.get("exp")}"')
    if at < iat:
        return _fail("token_not_yet_valid", f"{rfc3339(at)} is before iat {token.get('iat')}")
    if at > exp:
        return _fail("token_expired", f"{rfc3339(at)} is after exp {token.get('exp')}")

    # Row 10 -- last, so nothing below can reject a token whose jti we just spent.
    if replay_guard is not None:
        registry, order_id = replay_guard
        jti = token.get("jti", "")
        if claim_jti:
            held = None if registry.claim(jti, order_id, exp) else registry.order_of(jti)
        else:
            # A settler holding several candidates for one order must evaluate
            # row 10 on all of them but claim only the one that wins §7.2 --
            # claiming for a loser binds its jti to an order it never settled.
            held = registry.order_of(jti)
        if held is not None and held != order_id:
            return _fail(
                "replayed_jti",
                f'jti "{jti}" is already settled against order "{held}", not "{order_id}"',
            )

    return AttributionVerdict(
        ok=True,
        complete=complete,
        agent_id=token.get("agent_id", ""),
        settling_catalog_ids=[n["catalog_id"] for n in chain if n.get("settles")],
        last_signed_at=chain[-1].get("signed_at", ""),
        hops=len(chain),
    )


# ---------------------------------------------------------------------------
# Issuance (present so the cross-language matrix has three signers)
# ---------------------------------------------------------------------------


def issue_origin_token(
    private_jwk: Json,
    kid: str,
    catalog_id: str,
    agent_id: str,
    entry_id: str,
    object_id: str,
    provider_id: str,
    purpose: str,
    agent_identity_source: Optional[str] = None,
    settles: bool = True,
    ttl_seconds: int = 3600,
    jti: Optional[str] = None,
    now: Optional[Callable[[], datetime]] = None,
    ocp_version: str = "1.0",
) -> dict:
    """Issue a fresh single-hop token -- the `origin` case.

    `chain_complete` is `True` because a chain of one that this node started has
    no unrecorded upstream by construction. A relay appending to someone else's
    token cannot make that claim from local knowledge, which is why
    `append_relay_hop` is a separate entry point that demands the answer.
    """
    issued_at = (now or (lambda: datetime.now(timezone.utc)))()
    core: dict = {
        "ocp_version": ocp_version,
        "kind": "AttributionToken",
        "jti": jti or f"atr_{uuid.uuid4()}",
        "iss": catalog_id,
        "iat": rfc3339(issued_at),
        "exp": rfc3339(issued_at + timedelta(seconds=ttl_seconds)),
        "agent_id": agent_id,
        **({"agent_identity_source": agent_identity_source} if agent_identity_source else {}),
        "entry_id": entry_id,
        "object_id": object_id,
        "provider_id": provider_id,
        "purpose": purpose,
    }
    unsigned = {
        "catalog_id": catalog_id,
        "hop": 1,
        "role": "origin",
        "settles": settles,
        "chain_complete": True,
        "alg": OCP_SIGNATURE_ALG,
        "kid": kid,
        "signed_at": rfc3339(issued_at),
    }
    node = sign_chain_node(private_jwk, core, [], unsigned)
    return {**core, "complete": recompute_complete([node]), "chain": [node]}


def append_relay_hop(
    private_jwk: Json,
    kid: str,
    catalog_id: str,
    token: Json,
    chain_complete: bool,
    settles: bool = False,
    now: Optional[Callable[[], datetime]] = None,
) -> dict:
    """Append one `relay` hop to an existing token and sign the whole prefix.

    The core claims are carried through untouched. They must be: every upstream
    hop already signed over them, so altering one here would invalidate the
    signatures of the hops this node is trying to preserve.

    `chain_complete` is required with no default -- it is the one fact only this
    relay knows, and both defaults are wrong. `True` would let a careless
    integrator assert a completeness it cannot back; `False` would quietly make
    every chain incomplete and the field worthless. `settles` does default, to
    `False`: forgetting to declare a share you are owed is recoverable, while
    claiming one you are not is a false settlement claim signed under your name.

    Raises `AttributionError('chain_broken')` rather than signing a chain it
    knows to be invalid -- such a signature is worse than no attribution at all,
    because it carries this node's name.
    """
    chain = list(token.get("chain") or [])
    broken = check_chain_structure(chain)
    if broken:
        raise AttributionError("chain_broken", f"refusing to relay a malformed chain: {broken}")
    if len(chain) >= MAX_CHAIN_LENGTH:
        raise AttributionError("chain_broken", f"chain is already {len(chain)} hops, at the §4.4 cap of {MAX_CHAIN_LENGTH}")
    if any(n.get("catalog_id") == catalog_id for n in chain):
        raise AttributionError("chain_broken", f'"{catalog_id}" is already in this chain; appending it again would make a loop')

    core = core_claims(token)
    unsigned = {
        "catalog_id": catalog_id,
        "hop": len(chain) + 1,
        "role": "relay",
        "settles": settles,
        "chain_complete": chain_complete,
        "alg": OCP_SIGNATURE_ALG,
        "kid": kid,
        "signed_at": rfc3339((now or (lambda: datetime.now(timezone.utc)))()),
    }
    node = sign_chain_node(private_jwk, core, chain, unsigned)
    appended = [*chain, node]
    return {**core, "complete": recompute_complete(appended), "chain": appended}
