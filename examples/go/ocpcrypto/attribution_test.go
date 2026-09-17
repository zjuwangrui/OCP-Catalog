package ocpcrypto

import (
	"strings"
	"testing"
	"time"
)

// The local half of the Go suite: the issuance helpers, the replay guard, key
// handling, chain structure. It answers "is this implementation coherent?" and
// a failure here is a local bug. The cross-language agreement is checked by
// examples/go/interop.

var fixedNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

type harness struct {
	t          *testing.T
	originPub  JWK
	originPriv JWK
	relayPub   JWK
	relayPriv  JWK
	resolve    KeyResolver
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t}
	var err error
	h.originPub, h.originPriv, err = GenerateKeyPair(bytes32(1))
	if err != nil {
		t.Fatalf("origin key: %v", err)
	}
	h.relayPub, h.relayPriv, err = GenerateKeyPair(bytes32(2))
	if err != nil {
		t.Fatalf("relay key: %v", err)
	}
	h.resolve = StaticKeyResolver(map[string]any{
		"cat_origin": map[string]any{"keys": []any{map[string]any(h.originPub)}},
		"cat_relay":  map[string]any{"keys": []any{map[string]any(h.relayPub)}},
	})
	return h
}

func bytes32(b byte) []byte {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b
	}
	return seed
}

func (h *harness) origin(mutate func(*OriginParams)) Token {
	h.t.Helper()
	params := OriginParams{
		PrivateJWK: h.originPriv,
		Kid:        h.originPriv["kid"].(string),
		CatalogID:  "cat_origin",
		AgentID:    "agent_test",
		EntryID:    "entry_1",
		ObjectID:   "obj_1",
		ProviderID: "provider_1",
		Now:        func() time.Time { return fixedNow },
	}
	if mutate != nil {
		mutate(&params)
	}
	token, err := IssueOriginToken(params)
	if err != nil {
		h.t.Fatalf("issue: %v", err)
	}
	return token
}

func (h *harness) verify(token Token, opts VerifyOptions) Verdict {
	h.t.Helper()
	if opts.At.IsZero() {
		opts.At = fixedNow.Add(5 * time.Minute)
	}
	verdict, err := VerifyAttributionToken(token, h.resolve, opts)
	if err != nil {
		h.t.Fatalf("verify returned a non-verdict error: %v", err)
	}
	return verdict
}

func TestOriginTokenVerifies(t *testing.T) {
	h := newHarness(t)
	verdict := h.verify(h.origin(nil), VerifyOptions{})
	if !verdict.OK {
		t.Fatalf("rejected: %v", verdict.Err)
	}
	if verdict.Hops != 1 || !verdict.Complete {
		t.Errorf("hops=%d complete=%v, want 1/true", verdict.Hops, verdict.Complete)
	}
	// IssueOriginToken defaults Settles=true: the node that put the object in
	// front of the agent is owed by default.
	if len(verdict.SettlingCatalogIDs) != 1 || verdict.SettlingCatalogIDs[0] != "cat_origin" {
		t.Errorf("settling = %v, want [cat_origin]", verdict.SettlingCatalogIDs)
	}
}

func TestRelayPreservesUpstreamSettlement(t *testing.T) {
	h := newHarness(t)
	relayed, err := AppendRelayHop(h.origin(nil), RelayParams{
		PrivateJWK:    h.relayPriv,
		Kid:           h.relayPriv["kid"].(string),
		CatalogID:     "cat_relay",
		ChainComplete: true,
		Settles:       true,
		Now:           func() time.Time { return fixedNow.Add(5 * time.Second) },
	})
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	verdict := h.verify(relayed, VerifyOptions{})
	if !verdict.OK {
		t.Fatalf("rejected: %v", verdict.Err)
	}
	if verdict.Hops != 2 {
		t.Errorf("hops = %d, want 2", verdict.Hops)
	}
	// Both hops declared settles, so both are owed (§7.3) -- a relay taking a
	// cut does not displace the node that found the object.
	want := []string{"cat_origin", "cat_relay"}
	if len(verdict.SettlingCatalogIDs) != 2 || verdict.SettlingCatalogIDs[0] != want[0] || verdict.SettlingCatalogIDs[1] != want[1] {
		t.Errorf("settling = %v, want %v", verdict.SettlingCatalogIDs, want)
	}
	if verdict.LastSignedAt != RFC3339(fixedNow.Add(5*time.Second)) {
		t.Errorf("last_signed_at = %q", verdict.LastSignedAt)
	}
}

// TestRelayDefaultsToNotSettling: forgetting a share you are owed is
// recoverable by asking; claiming one you are not is a false settlement claim
// signed under your own key.
func TestRelayDefaultsToNotSettling(t *testing.T) {
	h := newHarness(t)
	relayed, err := AppendRelayHop(h.origin(nil), RelayParams{
		PrivateJWK: h.relayPriv, Kid: h.relayPriv["kid"].(string), CatalogID: "cat_relay", ChainComplete: true,
	})
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	if ChainOf(relayed)[1]["settles"] != false {
		t.Error("a relay claimed a settlement share it was not asked to claim")
	}
}

func TestRelayIncompleteChainFlipsComplete(t *testing.T) {
	h := newHarness(t)
	relayed, err := AppendRelayHop(h.origin(nil), RelayParams{
		PrivateJWK: h.relayPriv, Kid: h.relayPriv["kid"].(string), CatalogID: "cat_relay", ChainComplete: false,
	})
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	if relayed["complete"] != false || RecomputeComplete(ChainOf(relayed)) {
		t.Fatal("complete survived a hop that declared the chain incomplete")
	}
	// An incomplete chain is still a valid one -- §5.3 records the gap, it does
	// not reject it. Whether to settle on it is a policy call.
	verdict := h.verify(relayed, VerifyOptions{})
	if !verdict.OK || verdict.Complete {
		t.Errorf("ok=%v complete=%v, want true/false (%v)", verdict.OK, verdict.Complete, verdict.Err)
	}
}

func TestRelayRefusesToSignALoop(t *testing.T) {
	h := newHarness(t)
	_, err := AppendRelayHop(h.origin(nil), RelayParams{
		PrivateJWK: h.originPriv, Kid: h.originPriv["kid"].(string), CatalogID: "cat_origin", ChainComplete: true,
	})
	if CodeOf(err) != "chain_broken" {
		t.Fatalf("err = %v, want chain_broken", err)
	}
}

func TestPurposeViewIsSignedButNotSettleable(t *testing.T) {
	h := newHarness(t)
	token := h.origin(func(p *OriginParams) { p.Purpose = "view" })
	if verdict := h.verify(token, VerifyOptions{}); verdict.OK || verdict.Err.Code != "purpose_not_settleable" {
		t.Errorf("a view token settled: ok=%v err=%v", verdict.OK, verdict.Err)
	}
	// AnyPurpose checks the cryptography of a non-settleable token: it is
	// legitimately signed, it just cannot settle.
	if verdict := h.verify(token, VerifyOptions{RequirePurpose: AnyPurpose}); !verdict.OK {
		t.Errorf("a legitimately signed view token failed verification: %v", verdict.Err)
	}
}

// --- §7.1 row 10, which the shared fixture cannot cover: it needs state ------

func replayHarness(t *testing.T) (*harness, Token, time.Time) {
	h := newHarness(t)
	token := h.origin(func(p *OriginParams) { p.Jti = "atr_replay_test" })
	return h, token, fixedNow.Add(5 * time.Minute)
}

func TestSameOrderTwiceIsARetry(t *testing.T) {
	h, token, at := replayHarness(t)
	registry := NewJtiRegistry()
	registry.Now = func() time.Time { return at }
	opts := VerifyOptions{At: at, Replay: registry, OrderID: "ord_1", ClaimJti: true}
	if v := h.verify(token, opts); !v.OK {
		t.Fatalf("first claim rejected: %v", v.Err)
	}
	if v := h.verify(token, opts); !v.OK {
		t.Fatalf("a retry against the same order is normal traffic, got %v", v.Err)
	}
}

func TestSecondOrderIsAReplay(t *testing.T) {
	h, token, at := replayHarness(t)
	registry := NewJtiRegistry()
	registry.Now = func() time.Time { return at }
	if v := h.verify(token, VerifyOptions{At: at, Replay: registry, OrderID: "ord_1", ClaimJti: true}); !v.OK {
		t.Fatalf("first claim rejected: %v", v.Err)
	}
	v := h.verify(token, VerifyOptions{At: at, Replay: registry, OrderID: "ord_2", ClaimJti: true})
	if v.OK || v.Err.Code != "replayed_jti" {
		t.Fatalf("one token settled against two orders: ok=%v err=%v", v.OK, v.Err)
	}
}

// TestCheckingWithoutClaimingLeavesTheSlotFree: a settler evaluating several
// candidates for one order must not burn the losers' jti.
func TestCheckingWithoutClaimingLeavesTheSlotFree(t *testing.T) {
	h, token, at := replayHarness(t)
	registry := NewJtiRegistry()
	registry.Now = func() time.Time { return at }
	if v := h.verify(token, VerifyOptions{At: at, Replay: registry, OrderID: "ord_1"}); !v.OK {
		t.Fatalf("rejected: %v", v.Err)
	}
	if registry.Size() != 0 {
		t.Fatal("a check-only verification took the slot")
	}
	if v := h.verify(token, VerifyOptions{At: at, Replay: registry, OrderID: "ord_2", ClaimJti: true}); !v.OK {
		t.Fatalf("the slot was not free: %v", v.Err)
	}
}

func TestExpiryPrunesTheClaim(t *testing.T) {
	registry := NewJtiRegistry()
	registry.Now = func() time.Time { return fixedNow.Add(2 * time.Hour) }
	registry.Claim("atr_replay_test", "ord_1", fixedNow.Add(time.Hour))
	if registry.Size() != 0 {
		t.Error("an expired claim was retained; past exp, row 9 rejects the token anyway")
	}
}

// TestWindowIsMeasuredAtTheReportTime: rows 8 and 9 are about when the
// transaction happened, not when it is being verified.
func TestWindowIsMeasuredAtTheReportTime(t *testing.T) {
	h, token, _ := replayHarness(t)
	if v := h.verify(token, VerifyOptions{At: fixedNow.Add(-time.Second)}); v.Err == nil || v.Err.Code != "token_not_yet_valid" {
		t.Errorf("early: %v", v.Err)
	}
	if v := h.verify(token, VerifyOptions{At: fixedNow.Add(2 * time.Hour)}); v.Err == nil || v.Err.Code != "token_expired" {
		t.Errorf("late: %v", v.Err)
	}
}

// --- key handling -----------------------------------------------------------

func TestBase64URLRejectsPaddingAndStandardAlphabet(t *testing.T) {
	for _, bad := range []string{"abc=", "ab+cd", "ab/cd", ""} {
		if _, err := DecodeBase64URL(bad, "value"); err == nil {
			t.Errorf("accepted %q; two spellings of one signature is a malleability foothold", bad)
		}
	}
}

func TestNonEd25519KeyIsAlgNotSupported(t *testing.T) {
	_, err := AssertEd25519PublicJWK(JWK{"kty": "EC", "crv": "P-256", "x": "AAAA"}, "JWK")
	// Not key_not_found: "you are looking at the wrong node" and "that node
	// published something I will not verify with" are different problems.
	if CodeOf(err) != "alg_not_supported" {
		t.Fatalf("err = %v, want alg_not_supported", err)
	}
}

func TestPublicJWKOfDropsTheSeed(t *testing.T) {
	_, private, err := GenerateKeyPair(bytes32(4))
	if err != nil {
		t.Fatal(err)
	}
	if _, present := PublicJWKOf(private)["d"]; present {
		t.Error("PublicJWKOf published the private seed")
	}
	if _, present := private["d"]; !present {
		t.Error("PublicJWKOf mutated its input")
	}
}

func TestUnresolvableCatalogIsKeyNotFound(t *testing.T) {
	h := newHarness(t)
	verdict, err := VerifyAttributionToken(h.origin(nil), StaticKeyResolver(map[string]any{}),
		VerifyOptions{At: fixedNow.Add(time.Minute)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Err == nil || verdict.Err.Code != "key_not_found" || verdict.Err.Hop != 1 {
		t.Fatalf("verdict = %+v", verdict.Err)
	}
}

// --- §5.4 structure ---------------------------------------------------------

func TestChainStructureReasons(t *testing.T) {
	base := func(overrides map[string]any) ChainNode {
		node := ChainNode{"catalog_id": "a", "hop": 1, "role": "origin"}
		for k, v := range overrides {
			node[k] = v
		}
		return node
	}
	long := make([]ChainNode, 9)
	for i := range long {
		role := "relay"
		if i == 0 {
			role = "origin"
		}
		long[i] = ChainNode{"catalog_id": string(rune('a' + i)), "hop": i + 1, "role": role}
	}

	cases := []struct {
		chain    []ChainNode
		fragment string
	}{
		{nil, "chain is empty"},
		{[]ChainNode{base(map[string]any{"hop": 2})}, "expected 1"},
		{[]ChainNode{base(map[string]any{"role": "relay"})}, `expected "origin"`},
		{[]ChainNode{base(nil), {"catalog_id": "a", "hop": 2, "role": "relay"}}, "appears twice"},
		{long, "over the §4.4 cap"},
	}
	for _, c := range cases {
		reason := CheckChainStructure(c.chain)
		if !strings.Contains(reason, c.fragment) {
			t.Errorf("reason %q does not mention %q", reason, c.fragment)
		}
	}
}

func TestWellFormedChainHasNoReason(t *testing.T) {
	h := newHarness(t)
	if reason := CheckChainStructure(ChainOf(h.origin(nil))); reason != "" {
		t.Errorf("a freshly issued token was called malformed: %s", reason)
	}
}
