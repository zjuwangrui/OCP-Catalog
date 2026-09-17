package main

import (
	"encoding/json"
	"testing"

	"github.com/Open-Commerce-Protocol/OCP-Catalog/examples/go/ocpcrypto"
)

// The fixture-driven half of the Go suite. It answers "does Go agree with the
// reference?" -- every case here is also run by TypeScript and Python, so a
// failure is a cross-language divergence rather than a local bug. The local
// bugs are ocpcrypto/attribution_test.go's job.
//
// Nothing here needs a network or a server: offline verification from public
// keys is the property attribution exists to provide, so the tests have to be
// able to demonstrate it.

func mustFixture(t *testing.T) map[string]any {
	t.Helper()
	fixture, err := loadFixture()
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return fixture
}

func TestFixtureChecks(t *testing.T) {
	fixture := mustFixture(t)
	results, err := checks(fixture)
	if err != nil {
		t.Fatalf("checks: %v", err)
	}
	// 1 issuance + 1 positive + one per negative case. Asserted so a fixture
	// that lost its negatives to a bad merge fails loudly instead of quietly
	// passing a two-check suite.
	if want := 2 + len(fixture["negative"].([]any)); len(results) != want {
		t.Fatalf("ran %d checks, expected %d", len(results), want)
	}
	for _, r := range results {
		if !r.ok {
			t.Errorf("%s: %s", r.name, r.detail)
		}
	}
}

// TestSigningInputBytes compares the canonical bytes each hop signs, before any
// signature is involved.
//
// This is the check that localises a cross-language failure: if the signatures
// disagree but these agree, the bug is in key handling, and if these disagree
// the bug is in canonicalization.
func TestSigningInputBytes(t *testing.T) {
	fixture := mustFixture(t)
	token := fixture["expected_token"].(map[string]any)
	chain := ocpcrypto.ChainOf(token)
	core := ocpcrypto.CoreClaims(token)

	for index, item := range fixture["expected_signing_input"].([]any) {
		expected := item.(string)
		got, err := ocpcrypto.SigningBytes(chain[:index+1], core)
		if err != nil {
			t.Fatalf("hop %d: %v", index+1, err)
		}
		if string(got) != expected {
			t.Errorf("hop %d signing input\n got: %s\nwant: %s", index+1, got, expected)
		}
	}
}

// TestThumbprintsMatchTheFixture: RFC 7638 is OCP-JCS over {crv, kty, x}, and
// the fixture's kids are the proof.
func TestThumbprintsMatchTheFixture(t *testing.T) {
	for _, item := range mustFixture(t)["keys"].([]any) {
		key := item.(map[string]any)
		thumbprint, err := ocpcrypto.JWKThumbprint(key["public_jwk"].(map[string]any))
		if err != nil {
			t.Fatalf("%v: %v", key["catalog_id"], err)
		}
		if thumbprint != key["kid"] {
			t.Errorf("%v: thumbprint %s, kid %v", key["catalog_id"], thumbprint, key["kid"])
		}
	}
}

// TestSignedTokenSurvivesAWireRoundTrip is the property the matrix depends on
// and no single-process test would catch: the token this agent writes to a file
// still verifies after another agent has read it back.
//
// The risk is real -- encoding/json decodes hop into a float64 unless the
// reader remembers UseNumber, and 1 as a float canonicalizes through a
// different path than 1 as a literal.
func TestSignedTokenSurvivesAWireRoundTrip(t *testing.T) {
	fixture := mustFixture(t)
	token, err := signToken(fixture)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	reread, err := decodeJSON(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	verdict, err := verifyToken(fixture, reread, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict["ok"] != true {
		t.Fatalf("a token this agent signed did not survive a round trip: %v", verdict)
	}
}
