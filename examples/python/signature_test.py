"""Document signature tests for the Python example.

    python signature_test.py

Two halves, answering different questions:

- `SignatureFixtureTest` drives the shared signature fixture, which the
  TypeScript implementation generated. It answers "does Python agree with the
  reference?" and Go runs the same cases. A failure here is a cross-language
  divergence.
- The rest tests the Python API on its own -- signing, key resolution, the §7
  step order, the §9 ceiling. A failure is a local bug.

Neither half needs a network: offline verification from public keys is the
property signing exists to provide, so the tests must be able to show it.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

import signature_interop_agent as agent
from ocp_attribution import CryptoError, generate_key_pair
from ocp_canonical import canonical_value_hash, canonicalize_value
from ocp_signature import (
    SIGNATURE_ERROR_CODES,
    SignatureError,
    document_payload,
    document_payload_hash,
    select_verification_key,
    sign_document,
    signature_signing_bytes,
    static_document_key_resolver,
    trust_ceiling_for,
    verify_document_signature,
)

FIXED_NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


def _key_pair():
    """A deterministic pair, so a failure is reproducible from the log alone."""
    return generate_key_pair(seed=bytes([0x22] * 32))


class SignatureFixtureTest(unittest.TestCase):
    """Every assertion the shared fixture makes, one subtest each."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = agent.load_fixture()

    def test_fixture_checks(self) -> None:
        results = agent.checks(self.fixture)
        # 4 signing + 1 positive + one per negative. Asserted so a fixture that
        # lost its negatives to a bad merge fails loudly instead of quietly
        # passing a five-check suite.
        self.assertEqual(len(results), 5 + len(self.fixture["negative"]))
        for name, ok, detail in results:
            with self.subTest(check=name):
                self.assertTrue(ok, detail)

    def test_signing_input_matches_the_fixture_byte_for_byte(self) -> None:
        """Pins *what gets signed*, not just the signature.

        Without this, a divergence in the canonicalizer and a divergence in the
        key handling both surface as one opaque "signature differs".
        """
        signed = agent.sign_manifest(self.fixture)
        self.assertEqual(
            signature_signing_bytes(signed["signature"]).decode("utf-8"),
            self.fixture["expected_signing_input"],
        )

    def test_payload_hash_matches_the_fixture(self) -> None:
        signed = agent.sign_manifest(self.fixture)
        self.assertEqual(document_payload_hash(signed), self.fixture["expected_payload_hash"])

    def test_every_section_8_code_is_reachable(self) -> None:
        """The fixture must exercise all eight §8 codes, not a convenient subset.

        A verifier is only as good as the failures it can tell apart, and a
        fixture that stopped covering one of them would let that code rot
        undetected in any of the three languages.
        """
        covered = {n["expected_error"] for n in self.fixture["negative"]}
        self.assertEqual(covered, set(SIGNATURE_ERROR_CODES))


class SignDocumentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.public, self.private = _key_pair()
        self.document = {"catalog_id": "cat_local", "kind": "catalog-manifest", "n": 1}
        self.resolver = static_document_key_resolver({"cat_local": {"keys": [self.public]}})

    def test_round_trip(self) -> None:
        signed = sign_document(self.document, self.private, signed_at=FIXED_NOW)
        verdict = verify_document_signature(signed, self.resolver, at=FIXED_NOW)
        self.assertTrue(verdict.ok, verdict.error and verdict.error.message)
        self.assertEqual(verdict.issuer, "cat_local")
        self.assertEqual(verdict.kid, self.private["kid"])

    def test_kid_defaults_to_the_jwk_thumbprint(self) -> None:
        anonymous = {k: v for k, v in self.private.items() if k != "kid"}
        signed = sign_document(self.document, anonymous, signed_at=FIXED_NOW)
        self.assertEqual(signed["signature"]["kid"], self.private["kid"])

    def test_refuses_to_sign_an_issuer_that_contradicts_catalog_id(self) -> None:
        """A document no verifier will ever accept should not leave the signer.

        §7 step 4 rejects this combination everywhere, so producing it only
        moves the failure from the node that can fix it to the consumer who
        cannot.
        """
        with self.assertRaises(SignatureError) as caught:
            sign_document(self.document, self.private, issuer="cat_someone_else", signed_at=FIXED_NOW)
        self.assertEqual(caught.exception.code, "issuer_mismatch")

    def test_requires_an_issuer_when_the_document_has_no_catalog_id(self) -> None:
        with self.assertRaises(SignatureError) as caught:
            sign_document({"kind": "thing"}, self.private, signed_at=FIXED_NOW)
        self.assertEqual(caught.exception.code, "issuer_mismatch")

    def test_signing_is_deterministic(self) -> None:
        a = sign_document(self.document, self.private, signed_at=FIXED_NOW)
        b = sign_document(self.document, self.private, signed_at=FIXED_NOW)
        self.assertEqual(canonicalize_value(a), canonicalize_value(b))

    def test_member_order_in_the_document_does_not_change_the_signature(self) -> None:
        """OCP-JCS sorts before hashing, so a re-serialized document still verifies.

        This is the property that makes the signature survive a proxy, a
        database round-trip, or any JSON library with its own opinion about
        member order.
        """
        shuffled = {k: self.document[k] for k in reversed(list(self.document))}
        a = sign_document(self.document, self.private, signed_at=FIXED_NOW)
        b = sign_document(shuffled, self.private, signed_at=FIXED_NOW)
        self.assertEqual(a["signature"]["signature"], b["signature"]["signature"])

    def test_re_signing_replaces_the_envelope_rather_than_nesting_it(self) -> None:
        once = sign_document(self.document, self.private, signed_at=FIXED_NOW)
        twice = sign_document(once, self.private, signed_at=FIXED_NOW)
        self.assertEqual(canonicalize_value(once), canonicalize_value(twice))
        self.assertNotIn("signature", document_payload(twice))

    def test_an_expiring_signature_verifies_before_and_fails_after(self) -> None:
        expires = FIXED_NOW + timedelta(hours=1)
        signed = sign_document(self.document, self.private, signed_at=FIXED_NOW, expires_at=expires)
        self.assertTrue(verify_document_signature(signed, self.resolver, at=expires).ok)
        late = verify_document_signature(signed, self.resolver, at=expires + timedelta(seconds=1))
        self.assertEqual(late.error.code, "signature_expired")


class VerifyOrderTest(unittest.TestCase):
    """§7's step order, which is a security property and not an implementation detail."""

    def setUp(self) -> None:
        self.public, self.private = _key_pair()
        self.document = {"catalog_id": "cat_local", "kind": "catalog-manifest", "n": 1}
        self.signed = sign_document(self.document, self.private, signed_at=FIXED_NOW)
        self.resolver = static_document_key_resolver({"cat_local": {"keys": [self.public]}})

    def _verify(self, document, **kw):
        return verify_document_signature(document, self.resolver, at=FIXED_NOW, **kw)

    def test_payload_is_checked_before_the_key_is_fetched(self) -> None:
        """A tampered document must not be able to drive a key lookup.

        Otherwise anyone can make this verifier issue a request to any issuer
        string they choose, just by handing it a document.
        """
        fetched = []

        def resolver(issuer, kid):
            fetched.append((issuer, kid))
            return self.public

        tampered = {**self.signed, "n": 2}
        verdict = verify_document_signature(tampered, resolver, at=FIXED_NOW)
        self.assertEqual(verdict.error.code, "payload_mismatch")
        self.assertEqual(fetched, [])

    def test_issuer_is_checked_before_the_payload_hash(self) -> None:
        tampered = {**self.signed, "catalog_id": "cat_other", "n": 2}
        self.assertEqual(self._verify(tampered).error.code, "issuer_mismatch")

    def test_expiry_is_checked_last_so_a_forgery_is_not_reported_as_expired(self) -> None:
        expires = FIXED_NOW + timedelta(hours=1)
        signed = sign_document(self.document, self.private, signed_at=FIXED_NOW, expires_at=expires)
        forged = {**signed, "n": 99}
        verdict = verify_document_signature(forged, self.resolver, at=expires + timedelta(days=1))
        self.assertEqual(verdict.error.code, "payload_mismatch")

    def test_unknown_envelope_field_is_rejected(self) -> None:
        tampered = {**self.signed, "signature": {**self.signed["signature"], "extra": "x"}}
        self.assertEqual(self._verify(tampered).error.code, "envelope_malformed")

    def test_a_document_without_catalog_id_needs_an_expected_issuer(self) -> None:
        """A §4.4 check that silently does not run is worse than one that fails."""
        signed = sign_document({"kind": "thing"}, self.private, issuer="cat_local", signed_at=FIXED_NOW)
        self.assertEqual(self._verify(signed).error.code, "issuer_mismatch")
        self.assertTrue(self._verify(signed, expected_issuer="cat_local").ok)
        self.assertEqual(self._verify(signed, expected_issuer="cat_x").error.code, "issuer_mismatch")

    def test_a_correctly_signed_document_from_the_wrong_node_is_still_wrong(self) -> None:
        self.assertEqual(self._verify(self.signed, expected_issuer="cat_other").error.code, "issuer_mismatch")

    def test_unsigned_document_and_non_object(self) -> None:
        self.assertEqual(self._verify(document_payload(self.signed)).error.code, "unsigned")
        self.assertEqual(self._verify("not an object").error.code, "unsigned")


class KeyResolutionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.public, self.private = _key_pair()
        self.signed = sign_document({"catalog_id": "cat_local"}, self.private, signed_at=FIXED_NOW)

    def test_missing_jwks_and_missing_kid_both_read_as_key_not_found(self) -> None:
        for jwks in ({}, {"cat_local": {"keys": []}}):
            with self.subTest(jwks=jwks):
                verdict = verify_document_signature(
                    self.signed, static_document_key_resolver(jwks), at=FIXED_NOW
                )
                self.assertEqual(verdict.error.code, "key_not_found")

    def test_a_key_of_the_wrong_kind_is_alg_not_supported_not_key_not_found(self) -> None:
        """One means "wrong node", the other means "that node published
        something I will not verify with". §8 keeps them apart."""
        rsa = {"kty": "RSA", "kid": self.private["kid"], "n": "x", "e": "AQAB"}
        verdict = verify_document_signature(
            self.signed, static_document_key_resolver({"cat_local": {"keys": [rsa]}}), at=FIXED_NOW
        )
        self.assertEqual(verdict.error.code, "alg_not_supported")

    def test_a_key_server_outage_raises_rather_than_returning_a_verdict(self) -> None:
        """§7.3 -- a node whose key server is down has not forged anything.

        Filing the outage as `key_not_found` would give it the same trust
        ceiling as a forgery, and the cache invalidation that comes with it.
        """

        def resolver(issuer, kid):
            raise CryptoError("jwks_unavailable", "key server is down")

        with self.assertRaises(CryptoError):
            verify_document_signature(self.signed, resolver, at=FIXED_NOW)

    def test_select_verification_key_finds_by_kid(self) -> None:
        other, _ = generate_key_pair(seed=bytes([0x33] * 32))
        found = select_verification_key({"keys": [other, self.public]}, self.public["kid"], "cat_local")
        self.assertEqual(found["kid"], self.public["kid"])


class TrustCeilingTest(unittest.TestCase):
    """§9 -- a ceiling, not a verdict."""

    def setUp(self) -> None:
        self.public, self.private = _key_pair()
        self.signed = sign_document({"catalog_id": "cat_local"}, self.private, signed_at=FIXED_NOW)
        self.resolver = static_document_key_resolver({"cat_local": {"keys": [self.public]}})

    def test_a_passing_signature_unlocks_verified_and_keeps_the_cache(self) -> None:
        ceiling = trust_ceiling_for(verify_document_signature(self.signed, self.resolver, at=FIXED_NOW))
        self.assertEqual(ceiling, {"trust_tier": "verified", "invalidates_cache": False})

    def test_absence_of_proof_is_not_proof_of_tampering(self) -> None:
        """`unsigned` and `signature_expired` keep the cache; everything else drops it."""
        unsigned = verify_document_signature(document_payload(self.signed), self.resolver, at=FIXED_NOW)
        self.assertEqual(trust_ceiling_for(unsigned), {"trust_tier": "unverified", "invalidates_cache": False})

        tampered = verify_document_signature({**self.signed, "x": 1}, self.resolver, at=FIXED_NOW)
        self.assertEqual(trust_ceiling_for(tampered), {"trust_tier": "unknown", "invalidates_cache": True})


class PayloadHashTest(unittest.TestCase):
    def test_hashing_strips_the_envelope(self) -> None:
        _, private = _key_pair()
        document = {"catalog_id": "cat_local", "n": 1}
        signed = sign_document(document, private, signed_at=FIXED_NOW)
        self.assertEqual(document_payload_hash(signed), canonical_value_hash(document))


if __name__ == "__main__":
    unittest.main()
