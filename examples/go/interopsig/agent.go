// Command interopsig is the Go participant in the three-language **document
// signature** matrix.
//
//	go run ./interopsig sign
//	go run ./interopsig verify <document.json>
//	go run ./interopsig selftest
//
// Same three verbs as ./interop, over a different fixture
// (packages/ocp-crypto/fixtures/signature/manifest-v1.json) and a different
// signing material. scripts/interop/ts-signature-agent.mjs and
// examples/python/signature_interop_agent.py are the other two participants;
// scripts/interop/signature-matrix.mjs drives all three.
//
// Two commands rather than one because the two signatures are not
// interchangeable: an attribution chain node signs the chain prefix plus the
// token's core claims, a document signs its envelope minus signature. Teaching
// one agent both verbs would invite a caller to hand a manifest to the
// attribution verifier and read "invalid" as "forged" rather than "wrong
// verifier".
//
//   - sign     runs the fixture's signing recipe and prints the signed document.
//   - verify   runs §7 over a document file, prints the verdict *and the §9
//     trust ceiling* as JSON, and exits non-zero on rejection.
//   - negatives prints one {name, code, trust_tier, invalidates_cache} per
//     fixture negative, which is what the matrix compares across languages.
//   - selftest checks everything Go can check alone: byte-identical signing of
//     both documents, the positive verdict, and all 12 negatives with their
//     exact §8 code, trust tier and cache-invalidation flag.
//
// agent_test.go drives the helpers here rather than restating them, so
// `go test ./...` and the matrix cannot drift apart.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Open-Commerce-Protocol/OCP-Catalog/examples/go/ocpcrypto"
)

// fixturePath resolves relative to this source file, not the working
// directory, so `go run ./interopsig` and `go test ./interopsig` from anywhere
// in the module find the same fixture. OCP_SIGNATURE_FIXTURE overrides it for a
// build that has been moved away from its source.
func fixturePath() string {
	if override := os.Getenv("OCP_SIGNATURE_FIXTURE"); override != "" {
		return override
	}
	_, self, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(self), "..", "..", "..",
		"packages", "ocp-crypto", "fixtures", "signature", "manifest-v1.json")
}

// decodeJSON decodes into map[string]any with numbers left as literals.
//
// UseNumber is not optional here. Without it every integer in the manifest
// arrives as a float64, and canonicalization has to guess at a literal that has
// already been thrown away -- see ocpcrypto's package comment, trap 2. A
// guessed literal changes the payload hash, and the symptom is a
// payload_mismatch against a document nobody touched.
func decodeJSON(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func loadFixture() (map[string]any, error) {
	data, err := os.ReadFile(fixturePath())
	if err != nil {
		return nil, err
	}
	return decodeJSON(data)
}

// signManifest executes the fixture's signing recipe. Must be byte-reproducible.
//
// signed_at comes from the recipe, never from the clock: the whole point of the
// matrix is that three languages produce the same bytes, and a timestamp read
// at runtime would make that impossible to assert.
func signManifest(fixture map[string]any, expiring bool) (ocpcrypto.Document, error) {
	recipe := fixture["sign"].(map[string]any)
	key := fixture["key"].(map[string]any)["private_jwk"].(map[string]any)

	signedAt, err := time.Parse(time.RFC3339, recipe["signed_at"].(string))
	if err != nil {
		return nil, err
	}

	params := ocpcrypto.SignDocumentParams{
		Document:   recipe["document"].(map[string]any),
		PrivateJWK: key,
		SignedAt:   signedAt,
	}
	if expiring {
		expiresAt, err := time.Parse(time.RFC3339, recipe["expiring_expires_at"].(string))
		if err != nil {
			return nil, err
		}
		params.Document = recipe["expiring_document"].(map[string]any)
		params.ExpiresAt = expiresAt
	}
	return ocpcrypto.SignDocument(params)
}

// verifyManifest runs §7 plus §9 under the fixture's verification parameters
// and returns the result as plain JSON -- the shape all three agents agree on.
//
// The ceiling travels with the verdict because a caller that reads only "ok"
// will treat unsigned and payload_mismatch identically, and §9 exists precisely
// to keep them apart.
func verifyManifest(fixture map[string]any, document any, overrides map[string]any) (map[string]any, error) {
	atText := fixture["verify"].(map[string]any)["at"].(string)
	expectedIssuer := ""
	if overrides != nil {
		if v, ok := overrides["at"].(string); ok {
			atText = v
		}
		if v, ok := overrides["expected_issuer"].(string); ok {
			expectedIssuer = v
		}
	}
	at, err := time.Parse(time.RFC3339, atText)
	if err != nil {
		return nil, err
	}

	resolver := ocpcrypto.StaticDocumentKeyResolver(fixture["jwks"].(map[string]any))
	verdict, err := ocpcrypto.VerifyDocumentSignature(document, resolver,
		ocpcrypto.VerifyDocumentOptions{At: at, ExpectedIssuer: expectedIssuer})
	if err != nil {
		return nil, err
	}
	ceiling := ocpcrypto.TrustCeilingFor(verdict)

	out := map[string]any{
		"trust_tier":        ceiling.TrustTier,
		"invalidates_cache": ceiling.InvalidatesCache,
	}
	if verdict.OK {
		out["ok"] = true
		out["issuer"] = verdict.Issuer
		out["kid"] = verdict.Kid
		out["alg"] = verdict.Alg
		out["signed_at"] = verdict.SignedAt
		out["payload_hash"] = verdict.PayloadHash
		if verdict.ExpiresAt != "" {
			out["expires_at"] = verdict.ExpiresAt
		}
		return out, nil
	}
	out["ok"] = false
	out["code"] = verdict.Err.Code
	out["message"] = verdict.Err.Message
	return out, nil
}

type check struct {
	name   string
	ok     bool
	detail string
}

// negativeOutcome is one negative's §8 code and §9 ceiling, in the shape the
// matrix compares across languages.
type negativeOutcome struct {
	Name             string `json:"name"`
	Code             any    `json:"code"`
	TrustTier        string `json:"trust_tier"`
	InvalidatesCache bool   `json:"invalidates_cache"`
}

// negativeOutcomes is a separate verb from verify because the matrix needs all
// three languages' answers side by side, and two of the negatives carry their
// own "at" override -- driving them through verify one file at a time would
// mean passing that override on the command line and getting it wrong
// somewhere.
func negativeOutcomes(fixture map[string]any) ([]negativeOutcome, error) {
	outcomes := []negativeOutcome{}
	for _, item := range fixture["negative"].([]any) {
		negative := item.(map[string]any)
		overrides, _ := negative["verify_overrides"].(map[string]any)
		got, err := verifyManifest(fixture, negative["document"], overrides)
		if err != nil {
			return nil, err
		}
		outcomes = append(outcomes, negativeOutcome{
			Name:             negative["name"].(string),
			Code:             got["code"],
			TrustTier:        got["trust_tier"].(string),
			InvalidatesCache: got["invalidates_cache"].(bool),
		})
	}
	return outcomes, nil
}

// canonicalEquals compares two values by their canonical form rather than as
// raw text: the canonical bytes are what was signed, and every language spells
// its JSON output differently. Agreement here is the real claim -- three
// independent implementations produced the same signed bytes, so an Ed25519
// signature over them is identical too.
func canonicalEquals(a, b any) (bool, error) {
	left, err := ocpcrypto.CanonicalizeValue(a)
	if err != nil {
		return false, err
	}
	right, err := ocpcrypto.CanonicalizeValue(b)
	if err != nil {
		return false, err
	}
	return left == right, nil
}

// checks is every fixture assertion Go can make on its own.
//
// Returned rather than asserted so both the CLI selftest and the test suite can
// present the same list their own way.
func checks(fixture map[string]any) ([]check, error) {
	var results []check

	signed, err := signManifest(fixture, false)
	if err != nil {
		return nil, err
	}

	same, err := canonicalEquals(map[string]any(signed), fixture["expected_signed_document"])
	if err != nil {
		return nil, err
	}
	results = append(results, check{
		"signing is byte-identical to the fixture", same,
		"canonical form differs from expected_signed_document",
	})

	gotHash, err := ocpcrypto.CanonicalValueHash(map[string]any(signed))
	if err != nil {
		return nil, err
	}
	results = append(results, check{
		"the signed document hashes to expected_signed_document_sha256",
		gotHash == fixture["expected_signed_document_sha256"],
		"got " + gotHash,
	})

	sameEnvelope, err := canonicalEquals(signed[ocpcrypto.SignatureMember], fixture["expected_envelope"])
	if err != nil {
		return nil, err
	}
	results = append(results, check{
		"the signed envelope matches expected_envelope", sameEnvelope, "envelope differs",
	})

	expiring, err := signManifest(fixture, true)
	if err != nil {
		return nil, err
	}
	sameExpiring, err := canonicalEquals(map[string]any(expiring), fixture["expected_expiring_signed_document"])
	if err != nil {
		return nil, err
	}
	results = append(results, check{
		"the expiring document is byte-identical too", sameExpiring,
		"canonical form differs from expected_expiring_signed_document",
	})

	verdict, err := verifyManifest(fixture, fixture["expected_signed_document"], nil)
	if err != nil {
		return nil, err
	}
	want := fixture["verify"].(map[string]any)["expect"].(map[string]any)
	detail, _ := json.Marshal(verdict)
	matches := verdict["ok"] == true &&
		verdict["trust_tier"] == want["trust_tier"] &&
		verdict["invalidates_cache"] == want["invalidates_cache"]
	for _, field := range []string{"issuer", "kid", "alg", "signed_at", "payload_hash"} {
		matches = matches && verdict[field] == want[field]
	}
	results = append(results, check{
		"the good document verifies with the expected verdict", matches, string(detail),
	})

	outcomes, err := negativeOutcomes(fixture)
	if err != nil {
		return nil, err
	}
	for i, item := range fixture["negative"].([]any) {
		negative := item.(map[string]any)
		got := outcomes[i]
		results = append(results, check{
			"negative: " + negative["name"].(string),
			got.Code == negative["expected_error"] &&
				got.TrustTier == negative["expected_trust_tier"] &&
				got.InvalidatesCache == negative["expected_invalidates_cache"],
			fmt.Sprintf("got code=%v trust_tier=%v invalidates_cache=%v",
				got.Code, got.TrustTier, got.InvalidatesCache),
		})
	}
	return results, nil
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fixture, err := loadFixture()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot load the signature fixture:", err)
		return 2
	}

	verb := ""
	if len(args) > 0 {
		verb = args[0]
	}
	expiring := false
	for _, arg := range args {
		if arg == "--expiring" {
			expiring = true
		}
	}

	switch {
	case verb == "sign":
		document, err := signManifest(fixture, expiring)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		out, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(string(out))
		return 0

	case verb == "verify" && len(args) > 1:
		data, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		document, err := decodeJSON(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		verdict, err := verifyManifest(fixture, document, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		out, _ := json.Marshal(verdict)
		fmt.Println(string(out))
		if verdict["ok"] == true {
			return 0
		}
		return 1

	case verb == "negatives":
		outcomes, err := negativeOutcomes(fixture)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		out, _ := json.Marshal(outcomes)
		fmt.Println(string(out))
		return 0

	case verb == "selftest":
		results, err := checks(fixture)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		failed := 0
		for _, r := range results {
			if r.ok {
				fmt.Printf("  ok   %s\n", r.name)
			} else {
				fmt.Printf("  FAIL %s — %s\n", r.name, r.detail)
				failed++
			}
		}
		if failed > 0 {
			fmt.Printf("\ngo: %d failed\n", failed)
			return 1
		}
		fmt.Println("\ngo: all checks passed")
		return 0
	}

	fmt.Fprintln(os.Stderr, "usage: interopsig sign [--expiring] | verify <document.json> | negatives | selftest")
	return 2
}
