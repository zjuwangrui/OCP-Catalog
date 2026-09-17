"""Runs the shared OCP-JCS v1 conformance vectors against `ocp_canonical`.

    python canonical_test.py

The vectors live in `packages/ocp-crypto/fixtures/canonical/` and are the same
75 the TypeScript implementation runs -- that is what makes this a conformance
test rather than a unit test. A vector that passes here and fails there (or the
reverse) is exactly the cross-language divergence this file exists to catch.

`input_raw` is JSON **wire text**, not a value. It is handed to
`canonicalize()` as-is and never through `json.loads` first: half the rejection
vectors (duplicate keys, `NaN`, lone surrogates) are things `json.loads`
silently accepts or rewrites, so pre-parsing them would make those vectors pass
for the wrong reason.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from ocp_canonical import CanonicalError, canonical_hash, canonicalize

FIXTURES = Path(__file__).resolve().parents[2] / "packages" / "ocp-crypto" / "fixtures" / "canonical"


def load_vectors() -> list[tuple[str, dict]]:
    """Every vector in the fixture set, tagged with the file it came from."""
    out: list[tuple[str, dict]] = []
    for path in sorted(FIXTURES.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        vectors = doc["vectors"]
        # The files declare their own count; a vector silently lost to a bad
        # merge would otherwise just shrink the suite without failing it.
        assert len(vectors) == doc["vector_count"], f"{path.name}: vector_count disagrees with the array"
        out.extend((path.name, v) for v in vectors)
    return out


class CanonicalVectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = load_vectors()
        assert cls.vectors, f"no vectors found under {FIXTURES}"

    def test_accept_vectors(self) -> None:
        checked = 0
        for filename, v in self.vectors:
            if "expected_canonical" not in v:
                continue
            checked += 1
            with self.subTest(file=filename, vector=v["name"]):
                actual = canonicalize(v["input_raw"])
                self.assertEqual(actual, v["expected_canonical"], v.get("reason", ""))
                self.assertEqual(canonical_hash(v["input_raw"]), v["expected_sha256"])
                # Canonicalizing a canonical form must be a no-op, or signing
                # twice through different code paths would produce two hashes.
                self.assertEqual(canonicalize(actual), actual, "canonicalization is not idempotent")
        self.assertGreater(checked, 0)

    def test_reject_vectors(self) -> None:
        checked = 0
        for filename, v in self.vectors:
            if "expected_error" not in v:
                continue
            checked += 1
            with self.subTest(file=filename, vector=v["name"]):
                with self.assertRaises(CanonicalError) as caught:
                    canonicalize(v["input_raw"])
                # The code is the cross-language contract; the message is not.
                self.assertEqual(caught.exception.code, v["expected_error"], v.get("reason", ""))
        self.assertGreater(checked, 0)

    def test_utf8_bytes_and_text_agree(self) -> None:
        """Accepting `bytes` must not be a second, differently-behaved path."""
        for filename, v in self.vectors:
            if "expected_canonical" not in v:
                continue
            with self.subTest(file=filename, vector=v["name"]):
                try:
                    raw = v["input_raw"].encode("utf-8")
                except UnicodeEncodeError:
                    continue  # a vector carrying a literal surrogate has no UTF-8 form
                self.assertEqual(canonicalize(raw), v["expected_canonical"])

    def test_paired_assertions(self) -> None:
        """Two pairs the fixture README calls out, asserted across files.

        Neither is checkable from a single vector: one says two different
        inputs MUST hash the same, the other says two similar inputs MUST NOT.
        """
        by_name = {v["name"]: v for _, v in self.vectors}

        a, b = by_name["key-order-idempotent-a"], by_name["key-order-idempotent-b"]
        self.assertEqual(
            canonical_hash(a["input_raw"]),
            canonical_hash(b["input_raw"]),
            "member order must not change the hash -- this is the property signing depends on",
        )

        present, absent = by_name["null-preserved"], by_name["null-absent-counterpart"]
        self.assertNotEqual(
            canonical_hash(present["input_raw"]),
            canonical_hash(absent["input_raw"]),
            "a null member and a missing member must not hash alike (§8.2)",
        )


if __name__ == "__main__":
    unittest.main()
