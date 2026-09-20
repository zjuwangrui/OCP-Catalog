package main

import (
	"testing"

	"github.com/Open-Commerce-Protocol/OCP-Catalog/examples/go/ocpcrypto"
)

// The fixture-driven half of the Go document-signature suite. It answers "does
// Go agree with the reference?" -- every case here is also run by TypeScript
// and Python, so a failure is a cross-language divergence rather than a local
// bug. The local bugs are ocpcrypto/signature_test.go's job.
//
// Nothing here needs a network: offline verification from public keys is the
// property signing exists to provide, so the tests have to be able to show it.

func mustFixture(t *testing.T) map[string]any {
	t.Helper()
	fixture, err := loadFixture()
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return fixture
}

func TestSignatureFixtureChecks(t *testing.T) {
	fixture := mustFixture(t)
	results, err := checks(fixture)
	if err != nil {
		t.Fatalf("checks: %v", err)
	}
	// 4 signing + 1 positive + one per negative. Asserted so a fixture that
	// lost its negatives to a bad merge fails loudly instead of quietly passing
	// a five-check suite.
	if want := 5 + len(fixture["negative"].([]any)); len(results) != want {
		t.Fatalf("ran %d checks, expected %d", len(results), want)
	}
	for _, r := range results {
		if !r.ok {
			t.Errorf("%s: %s", r.name, r.detail)
		}
	}
}

// TestSigningInputMatchesTheFixture pins *what gets signed*, not just the
// signature. Without it, a divergence in the canonicalizer and a divergence in
// the key handling both surface as one opaque "signature differs".
func TestSigningInputMatchesTheFixture(t *testing.T) {
	fixture := mustFixture(t)
	signed, err := signManifest(fixture, false)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	envelope := signed[ocpcrypto.SignatureMember].(map[string]any)
	got, err := ocpcrypto.SignatureSigningBytes(envelope)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if want := fixture["expected_signing_input"].(string); string(got) != want {
		t.Errorf("signing input\n got %s\nwant %s", got, want)
	}
}

func TestPayloadHashMatchesTheFixture(t *testing.T) {
	fixture := mustFixture(t)
	signed, err := signManifest(fixture, false)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := ocpcrypto.DocumentPayloadHash(signed)
	if err != nil {
		t.Fatalf("payload hash: %v", err)
	}
	if want := fixture["expected_payload_hash"].(string); got != want {
		t.Errorf("payload hash = %s, want %s", got, want)
	}
}

// TestEverySection8CodeIsReachable asserts the fixture exercises all eight §8
// codes rather than a convenient subset. A verifier is only as good as the
// failures it can tell apart, and a fixture that stopped covering one would
// let that code rot undetected in any of the three languages.
func TestEverySection8CodeIsReachable(t *testing.T) {
	fixture := mustFixture(t)
	covered := map[string]bool{}
	for _, item := range fixture["negative"].([]any) {
		covered[item.(map[string]any)["expected_error"].(string)] = true
	}
	for _, code := range ocpcrypto.SignatureErrorCodes {
		if !covered[code] {
			t.Errorf("§8 code %q is never produced by the fixture's negatives", code)
		}
	}
}
