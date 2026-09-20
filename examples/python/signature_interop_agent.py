"""The Python participant in the three-language **document signature** matrix.

    python signature_interop_agent.py sign
    python signature_interop_agent.py verify <document.json>
    python signature_interop_agent.py selftest

Same three verbs as `interop_agent.py`, over a different fixture
(`packages/ocp-crypto/fixtures/signature/manifest-v1.json`) and a different
signing material. `scripts/interop/ts-signature-agent.mjs` and
`examples/go/interopsig` are the other two participants;
`scripts/interop/signature-matrix.mjs` drives all three.

Two agents rather than one because the two signatures are not interchangeable:
an attribution chain node signs the chain prefix plus the token's core claims,
a document signs its envelope minus `signature`. Teaching one agent both verbs
would invite a caller to pass a manifest to the attribution verifier and read
"invalid" as "forged" rather than "wrong verifier".

- `sign`     runs the fixture's signing recipe and prints the signed document.
- `verify`   runs §7 over a document file, prints the verdict **and the §9
             trust ceiling** as JSON, and exits non-zero on rejection.
- `negatives` prints one `{name, code, trust_tier, invalidates_cache}` per
             fixture negative, which is what the matrix compares across
             languages.
- `selftest` checks everything Python can check alone: byte-identical signing
             (both the plain and the expiring document), the positive verdict,
             and all 12 negatives with their exact §8 code, trust tier and
             cache-invalidation flag.

`signature_test.py` imports these helpers rather than restating them, so the
unittest suite and the matrix cannot drift apart.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ocp_canonical import canonical_value_hash, canonicalize_value
from ocp_signature import (
    sign_document,
    static_document_key_resolver,
    trust_ceiling_for,
    verify_document_signature,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parents[2] / "packages" / "ocp-crypto" / "fixtures" / "signature" / "manifest-v1.json"
)


def load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def sign_manifest(fixture: dict, expiring: bool = False) -> dict:
    """Execute the fixture's signing recipe. Must be byte-reproducible.

    `signed_at` comes from the recipe, never from the clock: the whole point of
    the matrix is that three languages produce the same bytes, and a timestamp
    read at runtime would make that impossible to assert.
    """
    recipe = fixture["sign"]
    key = fixture["key"]["private_jwk"]
    if expiring:
        return sign_document(
            recipe["expiring_document"],
            key,
            signed_at=_instant(recipe["signed_at"]),
            expires_at=_instant(recipe["expiring_expires_at"]),
        )
    return sign_document(recipe["document"], key, signed_at=_instant(recipe["signed_at"]))


def verify_manifest(fixture: dict, document: Any, overrides: Optional[dict] = None) -> dict:
    """Run §7 plus §9 under the fixture's verification parameters, as plain JSON.

    The ceiling travels with the verdict because a caller that reads only `ok`
    will treat `unsigned` and `payload_mismatch` identically, and §9 exists
    precisely to keep them apart.
    """
    overrides = overrides or {}
    at = _instant(overrides.get("at", fixture["verify"]["at"]))
    verdict = verify_document_signature(
        document,
        static_document_key_resolver(fixture["jwks"]),
        at=at,
        expected_issuer=overrides.get("expected_issuer"),
    )
    ceiling = trust_ceiling_for(verdict)
    common = {"trust_tier": ceiling["trust_tier"], "invalidates_cache": ceiling["invalidates_cache"]}
    if verdict.ok:
        return {
            "ok": True,
            "issuer": verdict.issuer,
            "kid": verdict.kid,
            "alg": verdict.alg,
            "signed_at": verdict.signed_at,
            "expires_at": verdict.expires_at,
            "payload_hash": verdict.payload_hash,
            **common,
        }
    assert verdict.error is not None
    return {"ok": False, "code": verdict.error.code, "message": verdict.error.message, **common}


def negative_outcomes(fixture: dict) -> list[dict]:
    """Each negative's §8 code and §9 ceiling, as the matrix compares them.

    A separate verb from `verify` because the matrix needs all three languages'
    answers side by side, and two of the negatives carry their own `at`
    override -- driving them through `verify` one file at a time would mean
    passing that override on the command line and getting it wrong somewhere.
    """
    outcomes = []
    for negative in fixture["negative"]:
        got = verify_manifest(fixture, negative["document"], negative.get("verify_overrides"))
        outcomes.append(
            {
                "name": negative["name"],
                "code": got.get("code"),
                "trust_tier": got["trust_tier"],
                "invalidates_cache": got["invalidates_cache"],
            }
        )
    return outcomes


def checks(fixture: dict) -> list[tuple[str, bool, str]]:
    """Every fixture assertion Python can make alone, as (name, ok, detail)."""
    results: list[tuple[str, bool, str]] = []

    signed = sign_manifest(fixture)
    results.append(
        (
            "signing is byte-identical to the fixture",
            canonicalize_value(signed) == canonicalize_value(fixture["expected_signed_document"]),
            "canonical form differs from expected_signed_document",
        )
    )
    results.append(
        (
            "the signed document hashes to expected_signed_document_sha256",
            canonical_value_hash(signed) == fixture["expected_signed_document_sha256"],
            f"got {canonical_value_hash(signed)}",
        )
    )
    results.append(
        (
            "the signed envelope matches expected_envelope",
            canonicalize_value(signed["signature"]) == canonicalize_value(fixture["expected_envelope"]),
            "envelope differs",
        )
    )
    results.append(
        (
            "the expiring document is byte-identical too",
            canonicalize_value(sign_manifest(fixture, expiring=True))
            == canonicalize_value(fixture["expected_expiring_signed_document"]),
            "canonical form differs from expected_expiring_signed_document",
        )
    )

    verdict = verify_manifest(fixture, fixture["expected_signed_document"])
    want = fixture["verify"]["expect"]
    results.append(
        (
            "the good document verifies with the expected verdict",
            verdict["ok"]
            and all(verdict[k] == want[k] for k in ("issuer", "kid", "alg", "signed_at", "payload_hash"))
            and verdict["trust_tier"] == want["trust_tier"]
            and verdict["invalidates_cache"] == want["invalidates_cache"],
            json.dumps(verdict, ensure_ascii=False),
        )
    )

    for negative, got in zip(fixture["negative"], negative_outcomes(fixture)):
        results.append(
            (
                f"negative: {negative['name']}",
                got["code"] == negative["expected_error"]
                and got["trust_tier"] == negative["expected_trust_tier"]
                and got["invalidates_cache"] == negative["expected_invalidates_cache"],
                json.dumps({k: got[k] for k in ("code", "trust_tier", "invalidates_cache")}),
            )
        )

    return results


def main(argv: list[str]) -> int:
    fixture = load_fixture()
    verb = argv[0] if argv else ""

    if verb == "sign":
        print(json.dumps(sign_manifest(fixture, expiring="--expiring" in argv), indent=2, ensure_ascii=False))
        return 0

    if verb == "verify" and len(argv) > 1:
        document = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        verdict = verify_manifest(fixture, document)
        print(json.dumps(verdict, ensure_ascii=False))
        return 0 if verdict["ok"] else 1

    if verb == "negatives":
        print(json.dumps(negative_outcomes(fixture), ensure_ascii=False))
        return 0

    if verb == "selftest":
        failed = 0
        for name, ok, detail in checks(fixture):
            print(f"  ok   {name}" if ok else f"  FAIL {name} — {detail}")
            failed += 0 if ok else 1
        print(f"\npython: {failed} failed" if failed else "\npython: all checks passed")
        return 1 if failed else 0

    print(
        "usage: signature_interop_agent.py sign [--expiring] | verify <document.json> | negatives | selftest",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
