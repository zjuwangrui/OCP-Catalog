"""The Python participant in the three-language interop matrix.

    python interop_agent.py sign
    python interop_agent.py verify <token.json>
    python interop_agent.py selftest

Every language exposes these same three verbs over the same fixture
(`packages/ocp-crypto/fixtures/interop/attribution-v1.json`), so the matrix
runner needs to know nothing about the language it is driving.
`scripts/interop/ts-agent.mjs` and `examples/go/interop` are the other two.

- `sign`     builds the fixture's token from the issuance recipe and prints it.
- `verify`   runs §7.1 over a token file and prints the verdict as JSON,
             exiting non-zero on rejection.
- `selftest` checks Python against every part of the fixture it can check
             alone: byte-identical issuance, the positive verdict, and all 13
             negative cases with their exact error code and hop number.

`attribution_test.py` imports the helpers here rather than restating them, so
the unittest suite and the matrix cannot drift apart.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ocp_attribution import (
    OCP_SIGNATURE_ALG,
    recompute_complete,
    sign_chain_node,
    static_key_resolver,
    verify_attribution_token,
)
from ocp_canonical import canonicalize_value

FIXTURE_PATH = (
    Path(__file__).resolve().parents[2] / "packages" / "ocp-crypto" / "fixtures" / "interop" / "attribution-v1.json"
)


def load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _private_jwk(fixture: dict, catalog_id: str) -> dict:
    return next(k for k in fixture["keys"] if k["catalog_id"] == catalog_id)["private_jwk"]


def sign_token(fixture: dict) -> dict:
    """Execute the fixture's issuance recipe. Must be byte-reproducible.

    Deliberately built from the per-hop primitive rather than
    `issue_origin_token` / `append_relay_hop`: the recipe pins `signed_at` for
    every hop, so there is no clock in the loop and nothing to be flaky about.
    The high-level API is exercised separately in `attribution_test.py`.
    """
    core = fixture["issue"]["core"]
    chain: list[dict] = []
    for hop in fixture["issue"]["hops"]:
        unsigned = {
            "catalog_id": hop["catalog_id"],
            "hop": hop["hop"],
            "role": hop["role"],
            "settles": hop["settles"],
            "chain_complete": hop["chain_complete"],
            "alg": OCP_SIGNATURE_ALG,
            "kid": hop["kid"],
            "signed_at": hop["signed_at"],
        }
        chain.append(sign_chain_node(_private_jwk(fixture, hop["catalog_id"]), core, chain, unsigned))
    return {**core, "complete": recompute_complete(chain), "chain": chain}


def verify_token(fixture: dict, token: dict, overrides: dict[str, Any] | None = None) -> dict:
    """Run §7.1 under the fixture's verification parameters, as plain JSON."""
    overrides = overrides or {}
    at = datetime.fromisoformat(overrides.get("at", fixture["verify"]["at"]).replace("Z", "+00:00"))
    provider = overrides.get("expected_provider_id", fixture["verify"]["expected_provider_id"])
    verdict = verify_attribution_token(
        token,
        static_key_resolver(fixture["jwks"]),
        at=at.astimezone(timezone.utc),
        expected_provider_id=provider,
    )
    if verdict.ok:
        return {
            "ok": True,
            "complete": verdict.complete,
            "hops": verdict.hops,
            "agent_id": verdict.agent_id,
            "settling_catalog_ids": verdict.settling_catalog_ids,
            "last_signed_at": verdict.last_signed_at,
        }
    return {"ok": False, "code": verdict.error.code, "hop": verdict.error.hop, "message": verdict.error.message}


def checks(fixture: dict) -> list[tuple[str, bool, str]]:
    """Every fixture assertion Python can make on its own, as (name, ok, detail).

    Returned rather than asserted so both the CLI selftest and the unittest
    suite can present the same list their own way.
    """
    results: list[tuple[str, bool, str]] = []

    signed = sign_token(fixture)
    results.append(
        (
            "issuance is byte-identical to the fixture",
            canonicalize_value(signed) == canonicalize_value(fixture["expected_token"]),
            "canonical form differs from expected_token",
        )
    )

    verdict = verify_token(fixture, fixture["expected_token"])
    want = fixture["verify"]["expect"]
    results.append(
        (
            "the good token verifies with the expected verdict",
            verdict["ok"]
            and verdict["complete"] == want["complete"]
            and verdict["hops"] == want["hops"]
            and verdict["agent_id"] == want["agent_id"]
            and verdict["last_signed_at"] == want["last_signed_at"]
            and verdict["settling_catalog_ids"] == want["settling_catalog_ids"],
            json.dumps(verdict, ensure_ascii=False),
        )
    )

    for negative in fixture["negative"]:
        got = verify_token(fixture, negative["token"], negative.get("verify_overrides"))
        hop_matches = "expected_hop" not in negative or got.get("hop") == negative["expected_hop"]
        results.append(
            (
                f"negative: {negative['name']}",
                not got["ok"] and got.get("code") == negative["expected_error"] and hop_matches,
                f"got {json.dumps({'code': got.get('code'), 'hop': got.get('hop')})}",
            )
        )

    return results


def main(argv: list[str]) -> int:
    fixture = load_fixture()
    verb = argv[0] if argv else ""

    if verb == "sign":
        print(json.dumps(sign_token(fixture), indent=2))
        return 0

    if verb == "verify" and len(argv) > 1:
        token = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        verdict = verify_token(fixture, token)
        print(json.dumps(verdict, ensure_ascii=False))
        return 0 if verdict["ok"] else 1

    if verb == "selftest":
        failed = 0
        for name, ok, detail in checks(fixture):
            print(f"  ok   {name}" if ok else f"  FAIL {name} — {detail}")
            failed += 0 if ok else 1
        print(f"\npython: {failed} failed" if failed else "\npython: all checks passed")
        return 1 if failed else 0

    print("usage: interop_agent.py sign | verify <token.json> | selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
