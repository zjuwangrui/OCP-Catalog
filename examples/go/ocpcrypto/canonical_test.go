package ocpcrypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shared conformance vectors -- the same 75 that canonical.ts and
// examples/python/canonical_test.py run. Same files, same assertions, so a
// divergence between the three implementations shows up as a test failure in
// the one that drifted rather than as an unverifiable signature in production.
var fixtureFiles = []string{
	"01-key-order.json",
	"02-nesting.json",
	"03-escaping.json",
	"04-numbers.json",
	"05-empty-and-null.json",
	"06-rejection.json",
}

type vector struct {
	Name string `json:"name"`
	Spec string `json:"spec"`
	// InputRaw is JSON *wire text*, not a decoded value. Handing it to
	// encoding/json first would destroy exactly the properties under test:
	// duplicate members collapse, number literals become float64.
	InputRaw          string `json:"input_raw"`
	ExpectedCanonical string `json:"expected_canonical"`
	ExpectedSHA256    string `json:"expected_sha256"`
	ExpectedError     string `json:"expected_error"`
	Reason            string `json:"reason"`
}

type fixtureFile struct {
	Category    string   `json:"category"`
	Spec        string   `json:"spec"`
	Description string   `json:"description"`
	VectorCount int      `json:"vector_count"`
	Vectors     []vector `json:"vectors"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "packages", "ocp-crypto", "fixtures", "canonical")
	var all []vector
	for _, name := range fixtureFiles {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var file fixtureFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		// The envelope states its own count; checking it means a vector lost to
		// a bad merge fails loudly instead of quietly shrinking the suite.
		if file.VectorCount != len(file.Vectors) {
			t.Fatalf("%s declares vector_count=%d but carries %d", name, file.VectorCount, len(file.Vectors))
		}
		all = append(all, file.Vectors...)
	}
	return all
}

func TestAcceptVectors(t *testing.T) {
	count := 0
	for _, v := range loadVectors(t) {
		if v.ExpectedError != "" {
			continue
		}
		count++
		t.Run(v.Name, func(t *testing.T) {
			canonical, err := Canonicalize([]byte(v.InputRaw))
			if err != nil {
				t.Fatalf("rejected an accept vector: %v (%s)", err, v.Reason)
			}
			if canonical != v.ExpectedCanonical {
				t.Errorf("canonical form\n got: %q\nwant: %q", canonical, v.ExpectedCanonical)
			}
			hash, err := CanonicalHash([]byte(v.InputRaw))
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if hash != v.ExpectedSHA256 {
				t.Errorf("hash\n got: %s\nwant: %s", hash, v.ExpectedSHA256)
			}
			// Idempotence: canonical output is valid input, and canonicalizing
			// it again must be a no-op. A canonicalizer that is not idempotent
			// cannot be used to re-verify anything it stored.
			again, err := Canonicalize([]byte(canonical))
			if err != nil {
				t.Fatalf("canonical output was rejected as input: %v", err)
			}
			if again != canonical {
				t.Errorf("not idempotent\n got: %q\nwant: %q", again, canonical)
			}
		})
	}
	if count == 0 {
		t.Fatal("no accept vectors loaded")
	}
	t.Logf("%d accept vectors", count)
}

func TestRejectVectors(t *testing.T) {
	count := 0
	for _, v := range loadVectors(t) {
		if v.ExpectedError == "" {
			continue
		}
		count++
		t.Run(v.Name, func(t *testing.T) {
			_, err := Canonicalize([]byte(v.InputRaw))
			if err == nil {
				t.Fatalf("accepted a reject vector (%s)", v.Reason)
			}
			// The code, not the message. Codes are the cross-language contract
			// (§11); messages are free to differ per implementation.
			if got := CodeOf(err); got != v.ExpectedError {
				t.Errorf("error code\n got: %q\nwant: %q\n(%v)", got, v.ExpectedError, err)
			}
		})
	}
	if count == 0 {
		t.Fatal("no reject vectors loaded")
	}
	t.Logf("%d reject vectors", count)
}

// TestPairedAssertions covers the two claims no single vector can make: one
// pair must agree and one pair must differ.
func TestPairedAssertions(t *testing.T) {
	byName := map[string]vector{}
	for _, v := range loadVectors(t) {
		byName[v.Name] = v
	}
	hash := func(name string) string {
		v, ok := byName[name]
		if !ok {
			t.Fatalf("vector %q is missing from the fixtures", name)
		}
		h, err := CanonicalHash([]byte(v.InputRaw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return h
	}

	// Member order in the input carries no meaning: two spellings of the same
	// object must hash identically, or signatures would depend on serializer
	// whim.
	if a, b := hash("key-order-idempotent-a"), hash("key-order-idempotent-b"); a != b {
		t.Errorf("reordered members hashed differently:\n a: %s\n b: %s", a, b)
	}

	// An explicit null is not the same as an absent member (§8.1). Dropping
	// nulls -- which several serializers do by default -- would make these two
	// collide, and a verifier could not tell "unset" from "set to nothing".
	if a, b := hash("null-preserved"), hash("null-absent-counterpart"); a == b {
		t.Errorf("an explicit null hashed the same as an absent member: %s", a)
	}
}

// TestBytesAndTextAgree pins that the canonical bytes are plain UTF-8 of the
// canonical text -- no BOM, no trailing newline. What gets signed is the bytes,
// so this is the property signatures actually rest on.
func TestBytesAndTextAgree(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.ExpectedError != "" {
			continue
		}
		canonical, err := Canonicalize([]byte(v.InputRaw))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if len(canonical) == 0 {
			t.Errorf("%s: empty canonical form", v.Name)
			continue
		}
		if canonical[0] == 0xEF || canonical[len(canonical)-1] == '\n' {
			t.Errorf("%s: canonical bytes carry a BOM or a trailing newline", v.Name)
		}
	}
}

// TestCanonicalizeValueMatchesWire checks the signing-side entry point against
// the parsing-side one. They are separate code paths over a shared serializer,
// and the signer uses the first while the verifier uses the second -- if they
// ever disagree, every signature this package produces is unverifiable by it.
func TestCanonicalizeValueMatchesWire(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.ExpectedError != "" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			decoder := json.NewDecoder(strings.NewReader(v.InputRaw))
			decoder.UseNumber() // trap 2: without this every number is a float64
			var value any
			if err := decoder.Decode(&value); err != nil {
				t.Skipf("encoding/json will not decode this vector: %v", err)
			}
			canonical, err := CanonicalizeValue(value)
			if err != nil {
				t.Fatalf("CanonicalizeValue: %v", err)
			}
			if canonical != v.ExpectedCanonical {
				t.Errorf("value path disagrees with the wire path\n got: %q\nwant: %q", canonical, v.ExpectedCanonical)
			}
		})
	}
}
