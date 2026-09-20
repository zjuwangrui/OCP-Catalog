"""OCP document signatures in Python: sign, verify, and the §9 trust ceiling.

Spec: `docs/specs/crypto/v1.md`. A port of `packages/ocp-crypto/src/signature.ts`.
`examples/go/ocpcrypto/signature.go` is the third implementation; the three must
produce **byte-identical** signed documents from the same recipe and the same
key, and must give the same §8 code and the same §9 ceiling for every negative
in `packages/ocp-crypto/fixtures/signature/manifest-v1.json`.

Why a port and not a wrapper: a catalog consumer who wants to check that a
manifest really came from the node it claims should be able to do it in the
language their job is already written in, from public keys alone, with no
network. A verifier that exists only in TypeScript makes "the protocol is
verifiable" a statement about one vendor's code.

Not the same thing as `ocp_attribution`, despite the shared keys and the shared
canonicalizer. A chain node signs its prefix plus the token's core claims; a
document signs an envelope that carries a hash of the document. Neither
verifier accepts the other's signature, and that is deliberate.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Sequence

from ocp_attribution import (
    OCP_SIGNATURE_ALG,
    CryptoError,
    _instant,
    _sign_bytes,
    _verify_bytes,
    assert_ed25519_public_jwk,
    jwk_thumbprint,
    public_jwk_of,
    rfc3339,
)
from ocp_canonical import canonical_value_hash, canonicalize_value_to_bytes

__all__ = [
    "SIGNATURE_MEMBER",
    "SIGNATURE_ERROR_CODES",
    "SignatureError",
    "SignatureVerdict",
    "document_payload",
    "document_payload_hash",
    "select_verification_key",
    "sign_document",
    "signature_signing_bytes",
    "signature_signing_input",
    "static_document_key_resolver",
    "trust_ceiling_for",
    "verify_document_signature",
]

#: The member a signed document carries its envelope in (§2).
SIGNATURE_MEMBER = "signature"

#: §8, in the order §7 can produce them. The matrix asserts all eight are reachable.
SIGNATURE_ERROR_CODES = (
    "unsigned",
    "envelope_malformed",
    "alg_not_supported",
    "issuer_mismatch",
    "payload_mismatch",
    "key_not_found",
    "signature_invalid",
    "signature_expired",
)

_ENVELOPE_FIELDS = ("alg", "kid", "issuer", "signed_at", "expires_at", "payload_hash", "signature")
_REQUIRED_ENVELOPE_FIELDS = ("alg", "kid", "issuer", "signed_at", "payload_hash", "signature")
_PAYLOAD_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")

Json = Mapping[str, Any]


class SignatureError(Exception):
    """A verdict about a document: one of the eight §8 codes."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# §3 / §4.1 -- the two layers
# ---------------------------------------------------------------------------


def document_payload(document: Json) -> dict:
    """§3 -- the document minus its `signature` member."""
    return {k: v for k, v in document.items() if k != SIGNATURE_MEMBER}


def document_payload_hash(document: Json) -> str:
    """§4.1 -- `sha256:` + hex over the canonical payload.

    Takes the whole document rather than the payload so a caller cannot forget
    to strip the envelope. Hashing a document with its envelope still inside
    produces a hash nothing will ever match, and the symptom is an unexplained
    `payload_mismatch`.
    """
    return canonical_value_hash(document_payload(document))


def signature_signing_input(envelope: Json) -> dict:
    """§4.1 -- the envelope minus `signature`, which is what gets signed."""
    return {k: v for k, v in envelope.items() if k != "signature"}


def signature_signing_bytes(envelope: Json) -> bytes:
    """The exact bytes the signer signs. Exposed for debugging a mismatch."""
    return canonicalize_value_to_bytes(signature_signing_input(envelope))


def sign_document(
    document: Json,
    private_jwk: Json,
    *,
    kid: Optional[str] = None,
    issuer: Optional[str] = None,
    signed_at: Optional[datetime] = None,
    expires_at: Optional[datetime] = None,
) -> dict:
    """Return a copy of `document` carrying its envelope (§4.1).

    Refuses to sign when `issuer` disagrees with the document's `catalog_id`:
    every verifier runs §7 step 4 and rejects that combination, so producing it
    would only move the failure from the node that can fix it to the consumer
    who cannot.

    Re-signing an already-signed document replaces the envelope, and the old
    envelope does not enter the new payload hash.
    """
    resolved_kid = kid or private_jwk.get("kid") or jwk_thumbprint(public_jwk_of(private_jwk))
    catalog_id = document.get("catalog_id")
    resolved_issuer = issuer if issuer is not None else (catalog_id if isinstance(catalog_id, str) else None)

    if resolved_issuer is None:
        raise SignatureError(
            "issuer_mismatch",
            'document has no "catalog_id" member, so `issuer` must be supplied explicitly',
        )
    if isinstance(catalog_id, str) and catalog_id != resolved_issuer:
        raise SignatureError(
            "issuer_mismatch",
            f'refusing to sign: issuer "{resolved_issuer}" does not match the document\'s catalog_id "{catalog_id}"',
        )

    payload = document_payload(document)
    moment = signed_at if signed_at is not None else datetime.now(timezone.utc)

    # Member order here is irrelevant to the signature -- OCP-JCS sorts before
    # hashing -- but it is what lands in the output JSON, and the matrix
    # compares canonical forms, not raw files. Kept matching signature.ts so a
    # human diffing two languages' output sees nothing move.
    unsigned: dict = {
        "alg": OCP_SIGNATURE_ALG,
        "kid": resolved_kid,
        "issuer": resolved_issuer,
        "signed_at": rfc3339(moment),
    }
    if expires_at is not None:
        unsigned["expires_at"] = rfc3339(expires_at)
    unsigned["payload_hash"] = canonical_value_hash(payload)

    signature = _sign_bytes(private_jwk, canonicalize_value_to_bytes(unsigned))
    return {**payload, SIGNATURE_MEMBER: {**unsigned, "signature": signature}}


# ---------------------------------------------------------------------------
# Key resolution
# ---------------------------------------------------------------------------

DocumentKeyResolver = Callable[[str, str], Json]


def select_verification_key(jwks: Any, kid: str, owner: str) -> Json:
    """Pick the key with this `kid` out of a JWKS document.

    Raises `key_not_found` both when the `kid` is absent and when no key set is
    in hand at all. The two are not distinguished here -- a caller that needs
    the distinction must check first, because the fix for one is a dispute and
    the fix for the other is a configuration flag.
    """
    keys = jwks.get("keys") if isinstance(jwks, Mapping) else None
    if not isinstance(keys, Sequence) or isinstance(keys, (str, bytes)):
        raise CryptoError("key_not_found", f'no JWKS on hand for catalog "{owner}"')
    for key in keys:
        if isinstance(key, Mapping) and key.get("kid") == kid:
            return assert_ed25519_public_jwk(key)
    raise CryptoError("key_not_found", f'kid "{kid}" is not in the JWKS of "{owner}"')


def static_document_key_resolver(jwks_by_catalog_id: Mapping[str, Any]) -> DocumentKeyResolver:
    """A resolver over key sets already in hand -- the offline path."""

    def resolve(issuer: str, kid: str) -> Json:
        return select_verification_key(jwks_by_catalog_id.get(issuer), kid, issuer)

    return resolve


# ---------------------------------------------------------------------------
# §7 -- verification
# ---------------------------------------------------------------------------


class SignatureVerdict:
    """The outcome of §7: either a verdict about a good document, or an error."""

    def __init__(
        self,
        ok: bool,
        *,
        issuer: str = "",
        kid: str = "",
        alg: str = "",
        signed_at: str = "",
        expires_at: Optional[str] = None,
        payload_hash: str = "",
        error: Optional[SignatureError] = None,
    ) -> None:
        self.ok = ok
        self.issuer = issuer
        self.kid = kid
        self.alg = alg
        self.signed_at = signed_at
        self.expires_at = expires_at
        self.payload_hash = payload_hash
        self.error = error

    def __repr__(self) -> str:
        return f"SignatureVerdict(ok={self.ok}, error={self.error!r})"


def _fail(code: str, message: str) -> SignatureVerdict:
    return SignatureVerdict(False, error=SignatureError(code, message))


def _envelope_reason(envelope: Mapping[str, Any]) -> Optional[str]:
    """§7 step 2 -- envelope shape. The reason it is malformed, or `None`.

    Unknown fields are rejected (§5.1): the envelope *is* the signed material,
    so a field this verifier does not recognise still entered the signature and
    still went unchecked.

    `alg`'s *value* is deliberately not checked here -- that is step 3 and it
    has its own code. This only asserts it is a string.
    """
    for field in envelope:
        if field not in _ENVELOPE_FIELDS:
            return f'unknown field "{field}"'
    for field in _REQUIRED_ENVELOPE_FIELDS:
        value = envelope.get(field)
        if not isinstance(value, str) or value == "":
            return f'"{field}" is missing or not a non-empty string'
    if _instant(envelope["signed_at"]) is None:
        return '"signed_at" is not an RFC 3339 instant'
    if envelope.get("expires_at") is not None and _instant(envelope["expires_at"]) is None:
        return '"expires_at" is not an RFC 3339 instant'
    if not _PAYLOAD_HASH_PATTERN.match(envelope["payload_hash"]):
        return '"payload_hash" is not sha256:<64 lowercase hex>'
    if not _BASE64URL_PATTERN.match(envelope["signature"]):
        return '"signature" is not unpadded base64url'
    return None


def verify_document_signature(
    document: Any,
    resolve_key: DocumentKeyResolver,
    *,
    at: Optional[datetime] = None,
    expected_issuer: Optional[str] = None,
) -> SignatureVerdict:
    """Run §7's eight steps in order, stopping at the first failure.

    Returns a verdict rather than raising, because "this is not signed" and
    "this was tampered with" are both answers a caller has to record and act on
    (§9 turns each into a trust ceiling).

    **Except** for key-material failures that are not about the document: if
    the key set is unreachable, stale or malformed, this raises. A node whose
    key server is down has not forged anything, and filing its outage as
    `key_not_found` would degrade it as though it had (§7.3).
    """
    now = at if at is not None else datetime.now(timezone.utc)

    # Step 1 -- is there an envelope at all.
    if not isinstance(document, Mapping):
        return _fail("unsigned", "document is not a JSON object, so it carries no signature")
    if SIGNATURE_MEMBER not in document:
        return _fail("unsigned", 'document has no "signature" member')

    # Step 2 -- envelope shape.
    envelope = document[SIGNATURE_MEMBER]
    if not isinstance(envelope, Mapping):
        return _fail("envelope_malformed", '"signature" is not an object')
    reason = _envelope_reason(envelope)
    if reason:
        return _fail("envelope_malformed", reason)

    # Step 3 -- algorithm, read from inside the signed material, never guessed.
    if envelope["alg"] != OCP_SIGNATURE_ALG:
        return _fail("alg_not_supported", f'alg is "{envelope["alg"]}", expected "{OCP_SIGNATURE_ALG}"')

    # Step 4 -- issuer. A string comparison, run before spending a whole-document
    # hash on a manifest that belongs to someone else.
    issuer = envelope["issuer"]
    catalog_id = document.get("catalog_id")
    if isinstance(catalog_id, str):
        if catalog_id != issuer:
            return _fail("issuer_mismatch", f'envelope issuer is "{issuer}", document catalog_id is "{catalog_id}"')
    elif expected_issuer is None:
        # Not skipped silently: a §4.4 check that quietly does not run is worse
        # than one that fails loudly.
        return _fail(
            "issuer_mismatch",
            'document has no "catalog_id" member and no expectedIssuer was supplied, so the issuer cannot be checked',
        )
    if expected_issuer is not None and issuer != expected_issuer:
        return _fail("issuer_mismatch", f'envelope issuer is "{issuer}", expected "{expected_issuer}"')

    # Step 5 -- recompute the payload hash. Before the key lookup, so no
    # arbitrary document can make this verifier go fetch a key set.
    recomputed = document_payload_hash(document)
    if recomputed != envelope["payload_hash"]:
        return _fail(
            "payload_mismatch",
            f"payload hashes to {recomputed}, envelope claims {envelope['payload_hash']}"
            " — the document was altered after signing",
        )

    # Step 6 -- the key.
    kid = envelope["kid"]
    try:
        jwk = resolve_key(issuer, kid)
    except CryptoError as err:
        # A key we cannot verify with is a key we did not find -- the same
        # reading attribution §7.1 row 4 takes.
        if err.code in ("key_not_found", "invalid_key"):
            return _fail("key_not_found", err.message)
        if err.code == "alg_not_supported":
            return _fail("alg_not_supported", err.message)
        raise  # jwks_unavailable / jwks_expired / jwks_malformed -- not a verdict.

    # Step 7 -- the signature itself.
    if not _verify_bytes(jwk, signature_signing_bytes(envelope), envelope["signature"]):
        return _fail(
            "signature_invalid",
            f'envelope does not verify under kid "{kid}" of "{issuer}"'
            " — the envelope was altered, or this is not that node's signature",
        )

    # Step 8 -- expiry, last. A forged document with an expired envelope is two
    # different findings, and checking this earlier would report the forgery as
    # the milder one.
    expires_at = _instant(envelope.get("expires_at"))
    if expires_at is not None and now > expires_at:
        return _fail(
            "signature_expired",
            f"signature expired at {envelope['expires_at']}, checked at {rfc3339(now)}",
        )

    return SignatureVerdict(
        True,
        issuer=issuer,
        kid=kid,
        alg=OCP_SIGNATURE_ALG,
        signed_at=envelope["signed_at"],
        expires_at=envelope.get("expires_at"),
        payload_hash=recomputed,
    )


def trust_ceiling_for(verdict: SignatureVerdict) -> dict:
    """§9 -- the highest trust tier a verification result allows.

    A *ceiling*, not a verdict: a passing signature only unlocks `verified`, it
    does not assert the manifest's contents are true (§7.2).
    """
    if verdict.ok:
        return {"trust_tier": "verified", "invalidates_cache": False}
    # Neither of these is evidence that anything was altered: one node has not
    # started signing, the other forgot to re-sign. Dropping their caches would
    # punish an absence of proof as though it were proof of tampering.
    if verdict.error is not None and verdict.error.code in ("unsigned", "signature_expired"):
        return {"trust_tier": "unverified", "invalidates_cache": False}
    return {"trust_tier": "unknown", "invalidates_cache": True}
