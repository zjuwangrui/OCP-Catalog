"""Attribution verification tests for the Python example.

    python attribution_test.py

Two halves, and they answer different questions:

- `InteropFixtureTest` drives the shared interop fixture, which the TypeScript
  implementation generated. It answers "does Python agree with the reference?"
  and every case in it is also run by Go. A failure here is a cross-language
  divergence.
- The rest tests the Python API on its own -- the issuance helpers, the replay
  guard, key handling. It answers "is this implementation coherent?" and a
  failure is a local bug.

Neither half needs a network or a server: offline verification from public keys
is the property attribution exists to provide, so the tests have to be able to
demonstrate it.
"""
from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

import interop_agent
from ocp_attribution import (
    CryptoError,
    JtiRegistry,
    append_relay_hop,
    assert_ed25519_public_jwk,
    check_chain_structure,
    from_base64url,
    generate_key_pair,
    issue_origin_token,
    jwk_thumbprint,
    public_jwk_of,
    recompute_complete,
    rfc3339,
    static_key_resolver,
    verify_attribution_token,
)

FIXED_NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


class InteropFixtureTest(unittest.TestCase):
    """Every assertion the shared fixture makes, one subtest each."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = interop_agent.load_fixture()

    def test_fixture_checks(self) -> None:
        results = interop_agent.checks(self.fixture)
        # 1 issuance + 1 positive + one per negative case. Asserted so a fixture
        # that lost its negatives to a bad merge fails loudly instead of quietly
        # passing a two-check suite.
        self.assertEqual(len(results), 2 + len(self.fixture["negative"]))
        for name, ok, detail in results:
            with self.subTest(check=name):
                self.assertTrue(ok, detail)

    def test_signing_input_bytes_match(self) -> None:
        """The canonical bytes each hop signs, before any signature is involved.

        This is the check that localises a cross-language failure: if the
        signatures disagree but these agree, the bug is in key handling, and if
        these disagree the bug is in canonicalization.
        """
        from ocp_attribution import attribution_signing_bytes, core_claims

        token = self.fixture["expected_token"]
        core = core_claims(token)
        for index, expected in enumerate(self.fixture["expected_signing_input"]):
            with self.subTest(hop=index + 1):
                actual = attribution_signing_bytes(token["chain"][: index + 1], core)
                self.assertEqual(actual.decode("utf-8"), expected)


class IssuanceTest(unittest.TestCase):
    """The high-level helpers, which the fixture recipe deliberately bypasses."""

    def setUp(self) -> None:
        self.origin_pub, self.origin_priv = generate_key_pair(seed=b"\x01" * 32)
        self.relay_pub, self.relay_priv = generate_key_pair(seed=b"\x02" * 32)
        self.jwks = {
            "cat_origin": {"keys": [self.origin_pub]},
            "cat_relay": {"keys": [self.relay_pub]},
        }
        self.resolve = static_key_resolver(self.jwks)

    def _origin(self, **overrides) -> dict:
        params = dict(
            private_jwk=self.origin_priv,
            kid=self.origin_priv["kid"],
            catalog_id="cat_origin",
            agent_id="agent_test",
            entry_id="entry_1",
            object_id="obj_1",
            provider_id="provider_1",
            purpose="checkout",
            now=lambda: FIXED_NOW,
        )
        params.update(overrides)
        return issue_origin_token(**params)

    def test_origin_token_verifies(self) -> None:
        token = self._origin()
        verdict = verify_attribution_token(token, self.resolve, at=FIXED_NOW + timedelta(minutes=5))
        self.assertTrue(verdict.ok, verdict.error and verdict.error.message)
        self.assertEqual(verdict.hops, 1)
        self.assertTrue(verdict.complete)
        # `issue_origin_token` defaults `settles=True`: the node that put the
        # object in front of the agent is owed by default.
        self.assertEqual(verdict.settling_catalog_ids, ["cat_origin"])

    def test_relay_preserves_upstream_settlement(self) -> None:
        token = self._origin()
        relayed = append_relay_hop(
            self.relay_priv,
            self.relay_priv["kid"],
            "cat_relay",
            token,
            chain_complete=True,
            settles=True,
            now=lambda: FIXED_NOW + timedelta(seconds=5),
        )
        verdict = verify_attribution_token(relayed, self.resolve, at=FIXED_NOW + timedelta(minutes=5))
        self.assertTrue(verdict.ok, verdict.error and verdict.error.message)
        self.assertEqual(verdict.hops, 2)
        # Both hops declared `settles`, so both are owed (§7.3) -- a relay
        # taking a cut does not displace the node that found the object.
        self.assertEqual(verdict.settling_catalog_ids, ["cat_origin", "cat_relay"])
        self.assertEqual(verdict.last_signed_at, rfc3339(FIXED_NOW + timedelta(seconds=5)))

    def test_relay_defaults_to_not_settling(self) -> None:
        """Forgetting a share you are owed is recoverable; claiming one you are
        not is a false settlement claim signed under your own key."""
        relayed = append_relay_hop(
            self.relay_priv, self.relay_priv["kid"], "cat_relay", self._origin(), chain_complete=True
        )
        self.assertFalse(relayed["chain"][1]["settles"])

    def test_relay_incomplete_chain_flips_complete(self) -> None:
        relayed = append_relay_hop(
            self.relay_priv, self.relay_priv["kid"], "cat_relay", self._origin(), chain_complete=False
        )
        self.assertFalse(relayed["complete"])
        self.assertFalse(recompute_complete(relayed["chain"]))
        verdict = verify_attribution_token(relayed, self.resolve, at=FIXED_NOW + timedelta(minutes=5))
        # An incomplete chain is still a valid one -- §5.3 records the gap, it
        # does not reject it. Whether to settle on it is a policy call.
        self.assertTrue(verdict.ok, verdict.error and verdict.error.message)
        self.assertFalse(verdict.complete)

    def test_relay_refuses_to_sign_a_loop(self) -> None:
        with self.assertRaises(Exception) as caught:
            append_relay_hop(
                self.origin_priv, self.origin_priv["kid"], "cat_origin", self._origin(), chain_complete=True
            )
        self.assertEqual(getattr(caught.exception, "code", None), "chain_broken")

    def test_purpose_view_is_signed_but_not_settleable(self) -> None:
        token = self._origin(purpose="view")
        at = FIXED_NOW + timedelta(minutes=5)
        self.assertFalse(verify_attribution_token(token, self.resolve, at=at).ok)
        # Passing `require_purpose=None` checks the cryptography of a
        # non-settleable token: it is legitimately signed, it just cannot settle.
        self.assertTrue(verify_attribution_token(token, self.resolve, at=at, require_purpose=None).ok)


class ReplayGuardTest(unittest.TestCase):
    """§7.1 row 10, which the shared fixture cannot cover -- it needs state."""

    def setUp(self) -> None:
        pub, self.priv = generate_key_pair(seed=b"\x03" * 32)
        self.resolve = static_key_resolver({"cat_origin": {"keys": [pub]}})
        self.token = issue_origin_token(
            private_jwk=self.priv,
            kid=self.priv["kid"],
            catalog_id="cat_origin",
            agent_id="agent_test",
            entry_id="entry_1",
            object_id="obj_1",
            provider_id="provider_1",
            purpose="checkout",
            jti="atr_replay_test",
            now=lambda: FIXED_NOW,
        )
        self.at = FIXED_NOW + timedelta(minutes=5)

    def _verify(self, registry: JtiRegistry, order_id: str, claim: bool = True):
        return verify_attribution_token(
            self.token, self.resolve, at=self.at, replay_guard=(registry, order_id), claim_jti=claim
        )

    def test_same_order_twice_is_a_retry(self) -> None:
        registry = JtiRegistry(now=lambda: self.at)
        self.assertTrue(self._verify(registry, "ord_1").ok)
        self.assertTrue(self._verify(registry, "ord_1").ok, "a retry against the same order is normal traffic")

    def test_second_order_is_a_replay(self) -> None:
        registry = JtiRegistry(now=lambda: self.at)
        self.assertTrue(self._verify(registry, "ord_1").ok)
        verdict = self._verify(registry, "ord_2")
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.error.code, "replayed_jti")

    def test_checking_without_claiming_leaves_the_slot_free(self) -> None:
        """A settler evaluating several candidates must not burn the losers' jti."""
        registry = JtiRegistry(now=lambda: self.at)
        self.assertTrue(self._verify(registry, "ord_1", claim=False).ok)
        self.assertEqual(registry.size, 0)
        self.assertTrue(self._verify(registry, "ord_2").ok)

    def test_expiry_prunes_the_claim(self) -> None:
        registry = JtiRegistry(now=lambda: FIXED_NOW + timedelta(hours=2))
        registry.claim("atr_replay_test", "ord_1", FIXED_NOW + timedelta(hours=1))
        self.assertEqual(registry.size, 0, "past exp, row 9 rejects the token anyway")

    def test_window_is_measured_at_the_report_time(self) -> None:
        early = verify_attribution_token(self.token, self.resolve, at=FIXED_NOW - timedelta(seconds=1))
        self.assertEqual(early.error.code, "token_not_yet_valid")
        late = verify_attribution_token(self.token, self.resolve, at=FIXED_NOW + timedelta(hours=2))
        self.assertEqual(late.error.code, "token_expired")


class KeyHandlingTest(unittest.TestCase):
    def test_thumbprint_matches_the_fixture(self) -> None:
        """RFC 7638 is OCP-JCS over `{crv, kty, x}`; the fixture's kids prove it."""
        for key in interop_agent.load_fixture()["keys"]:
            with self.subTest(catalog=key["catalog_id"]):
                self.assertEqual(jwk_thumbprint(key["public_jwk"]), key["kid"])

    def test_base64url_rejects_padding_and_standard_alphabet(self) -> None:
        for bad in ("abc=", "ab+cd", "ab/cd", ""):
            with self.subTest(value=bad), self.assertRaises(CryptoError):
                from_base64url(bad)

    def test_non_ed25519_key_is_alg_not_supported(self) -> None:
        with self.assertRaises(CryptoError) as caught:
            assert_ed25519_public_jwk({"kty": "EC", "crv": "P-256", "x": "AAAA"})
        # Not `key_not_found`: "you are looking at the wrong node" and "that node
        # published something I will not verify with" are different problems.
        self.assertEqual(caught.exception.code, "alg_not_supported")

    def test_public_jwk_of_drops_the_seed(self) -> None:
        _, private = generate_key_pair(seed=b"\x04" * 32)
        self.assertNotIn("d", public_jwk_of(private))
        self.assertIn("d", private)

    def test_unresolvable_catalog_is_key_not_found(self) -> None:
        pub, priv = generate_key_pair(seed=b"\x05" * 32)
        token = issue_origin_token(
            private_jwk=priv,
            kid=priv["kid"],
            catalog_id="cat_origin",
            agent_id="a",
            entry_id="e",
            object_id="o",
            provider_id="p",
            purpose="checkout",
            now=lambda: FIXED_NOW,
        )
        verdict = verify_attribution_token(token, static_key_resolver({}), at=FIXED_NOW + timedelta(minutes=1))
        self.assertEqual(verdict.error.code, "key_not_found")
        self.assertEqual(verdict.error.hop, 1)


class ChainStructureTest(unittest.TestCase):
    def test_reasons(self) -> None:
        node = {"catalog_id": "a", "hop": 1, "role": "origin"}
        cases = [
            ([], "chain is empty"),
            ([{**node, "hop": 2}], "expected 1"),
            ([{**node, "role": "relay"}], 'expected "origin"'),
            ([node, {"catalog_id": "a", "hop": 2, "role": "relay"}], "appears twice"),
            ([{**node, "catalog_id": f"c{i}", "hop": i + 1, "role": "origin" if i == 0 else "relay"} for i in range(9)], "over the §4.4 cap"),
        ]
        for chain, fragment in cases:
            with self.subTest(fragment=fragment):
                reason = check_chain_structure(chain)
                self.assertIsNotNone(reason)
                self.assertIn(fragment, reason)

    def test_well_formed_chain_has_no_reason(self) -> None:
        fixture = interop_agent.load_fixture()
        self.assertIsNone(check_chain_structure(fixture["expected_token"]["chain"]))


if __name__ == "__main__":
    unittest.main()
