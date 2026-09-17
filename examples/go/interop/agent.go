// Command interop is the Go participant in the three-language interop matrix.
//
//	go run ./interop sign
//	go run ./interop verify <token.json>
//	go run ./interop selftest
//
// Every language exposes these same three verbs over the same fixture
// (packages/ocp-crypto/fixtures/interop/attribution-v1.json), so the matrix
// runner needs to know nothing about the language it is driving.
// scripts/interop/ts-agent.mjs and examples/python/interop_agent.py are the
// other two.
//
//   - sign     builds the fixture's token from the issuance recipe and prints it.
//   - verify   runs §7.1 over a token file and prints the verdict as JSON,
//     exiting non-zero on rejection.
//   - selftest checks Go against every part of the fixture it can check alone:
//     byte-identical issuance, the positive verdict, and all 13 negative cases
//     with their exact error code and hop number.
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
// directory, so `go run ./interop` and `go test ./interop` from anywhere in the
// module find the same fixture. OCP_INTEROP_FIXTURE overrides it for a build
// that has been moved away from its source.
func fixturePath() string {
	if override := os.Getenv("OCP_INTEROP_FIXTURE"); override != "" {
		return override
	}
	_, self, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(self), "..", "..", "..",
		"packages", "ocp-crypto", "fixtures", "interop", "attribution-v1.json")
}

// decodeJSON decodes into map[string]any with numbers left as literals.
//
// UseNumber is not optional here. Without it every hop number arrives as a
// float64, and canonicalization has to guess at a literal that has already been
// thrown away -- see ocpcrypto's package comment, trap 2.
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

func privateJWK(fixture map[string]any, catalogID string) (ocpcrypto.JWK, error) {
	for _, item := range fixture["keys"].([]any) {
		key := item.(map[string]any)
		if key["catalog_id"] == catalogID {
			return key["private_jwk"].(map[string]any), nil
		}
	}
	return nil, fmt.Errorf("no key in the fixture for catalog %q", catalogID)
}

// signToken executes the fixture's issuance recipe. Must be byte-reproducible.
//
// Deliberately built from the per-hop primitive rather than IssueOriginToken /
// AppendRelayHop: the recipe pins signed_at for every hop, so there is no clock
// in the loop and nothing to be flaky about. The high-level API is exercised
// separately in agent_test.go.
func signToken(fixture map[string]any) (ocpcrypto.Token, error) {
	issue := fixture["issue"].(map[string]any)
	core := issue["core"].(map[string]any)

	var chain []ocpcrypto.ChainNode
	for _, item := range issue["hops"].([]any) {
		hop := item.(map[string]any)
		key, err := privateJWK(fixture, hop["catalog_id"].(string))
		if err != nil {
			return nil, err
		}
		unsigned := map[string]any{
			"catalog_id":     hop["catalog_id"],
			"hop":            hop["hop"],
			"role":           hop["role"],
			"settles":        hop["settles"],
			"chain_complete": hop["chain_complete"],
			"alg":            ocpcrypto.SignatureAlg,
			"kid":            hop["kid"],
			"signed_at":      hop["signed_at"],
		}
		node, err := ocpcrypto.SignChainNode(key, core, chain, unsigned)
		if err != nil {
			return nil, err
		}
		chain = append(chain, node)
	}

	token := ocpcrypto.Token{}
	for k, v := range core {
		token[k] = v
	}
	nodes := make([]any, 0, len(chain))
	for _, n := range chain {
		nodes = append(nodes, map[string]any(n))
	}
	token["chain"] = nodes
	token["complete"] = ocpcrypto.RecomputeComplete(chain)
	return token, nil
}

// verifyToken runs §7.1 under the fixture's verification parameters and returns
// the verdict as plain JSON -- the shape all three agents agree on.
func verifyToken(fixture map[string]any, token ocpcrypto.Token, overrides map[string]any) (map[string]any, error) {
	verify := fixture["verify"].(map[string]any)

	atText := verify["at"].(string)
	provider := verify["expected_provider_id"].(string)
	if overrides != nil {
		if v, ok := overrides["at"].(string); ok {
			atText = v
		}
		if v, ok := overrides["expected_provider_id"].(string); ok {
			provider = v
		}
	}
	at, err := time.Parse(time.RFC3339, atText)
	if err != nil {
		return nil, err
	}

	verdict, err := ocpcrypto.VerifyAttributionToken(token, ocpcrypto.StaticKeyResolver(fixture["jwks"].(map[string]any)),
		ocpcrypto.VerifyOptions{At: at, ExpectedProviderID: provider})
	if err != nil {
		return nil, err
	}
	if verdict.OK {
		return map[string]any{
			"ok":                   true,
			"complete":             verdict.Complete,
			"hops":                 verdict.Hops,
			"agent_id":             verdict.AgentID,
			"settling_catalog_ids": verdict.SettlingCatalogIDs,
			"last_signed_at":       verdict.LastSignedAt,
		}, nil
	}
	return map[string]any{
		"ok":      false,
		"code":    verdict.Err.Code,
		"hop":     verdict.Err.Hop,
		"message": verdict.Err.Message,
	}, nil
}

type check struct {
	name   string
	ok     bool
	detail string
}

// checks is every fixture assertion Go can make on its own.
//
// Returned rather than asserted so both the CLI selftest and the test suite can
// present the same list their own way.
func checks(fixture map[string]any) ([]check, error) {
	var results []check

	signed, err := signToken(fixture)
	if err != nil {
		return nil, err
	}
	expected := fixture["expected_token"].(map[string]any)
	// Compared canonically, not as raw text: the canonical bytes are what was
	// signed, and every language spells its JSON output differently. Agreement
	// here is the real claim -- three independent implementations produced the
	// same signed bytes, so an Ed25519 signature over them is identical too.
	gotCanonical, err := ocpcrypto.CanonicalizeValue(map[string]any(signed))
	if err != nil {
		return nil, err
	}
	wantCanonical, err := ocpcrypto.CanonicalizeValue(expected)
	if err != nil {
		return nil, err
	}
	results = append(results, check{
		"issuance is byte-identical to the fixture",
		gotCanonical == wantCanonical,
		"canonical form differs from expected_token",
	})

	verdict, err := verifyToken(fixture, expected, nil)
	if err != nil {
		return nil, err
	}
	want := fixture["verify"].(map[string]any)["expect"].(map[string]any)
	detail, _ := json.Marshal(verdict)
	results = append(results, check{
		"the good token verifies with the expected verdict",
		verdict["ok"] == true &&
			verdict["complete"] == want["complete"] &&
			numberEquals(want["hops"], verdict["hops"]) &&
			verdict["agent_id"] == want["agent_id"] &&
			verdict["last_signed_at"] == want["last_signed_at"] &&
			stringsEqual(verdict["settling_catalog_ids"].([]string), want["settling_catalog_ids"]),
		string(detail),
	})

	for _, item := range fixture["negative"].([]any) {
		negative := item.(map[string]any)
		overrides, _ := negative["verify_overrides"].(map[string]any)
		got, err := verifyToken(fixture, negative["token"].(map[string]any), overrides)
		if err != nil {
			return nil, err
		}
		hopMatches := true
		if expectedHop, present := negative["expected_hop"]; present {
			hopMatches = numberEquals(expectedHop, got["hop"])
		}
		results = append(results, check{
			"negative: " + negative["name"].(string),
			got["ok"] == false && got["code"] == negative["expected_error"] && hopMatches,
			fmt.Sprintf("got code=%v hop=%v", got["code"], got["hop"]),
		})
	}

	return results, nil
}

// numberEquals compares a fixture number (json.Number) against a Go int.
func numberEquals(fixtureValue any, goValue any) bool {
	n, ok := fixtureValue.(json.Number)
	if !ok {
		return false
	}
	i, err := n.Int64()
	if err != nil {
		return false
	}
	got, ok := goValue.(int)
	return ok && int64(got) == i
}

func stringsEqual(got []string, fixtureValue any) bool {
	want, ok := fixtureValue.([]any)
	if !ok || len(want) != len(got) {
		return false
	}
	for i := range got {
		if want[i] != got[i] {
			return false
		}
	}
	return true
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fixture, err := loadFixture()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot load the interop fixture:", err)
		return 2
	}

	verb := ""
	if len(args) > 0 {
		verb = args[0]
	}

	switch {
	case verb == "sign":
		token, err := signToken(fixture)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		out, err := json.MarshalIndent(token, "", "  ")
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
		token, err := decodeJSON(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		verdict, err := verifyToken(fixture, token, nil)
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

	fmt.Fprintln(os.Stderr, "usage: interop sign | verify <token.json> | selftest")
	return 2
}
