package ocpcrypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// SignatureAlg is the only algorithm OCP accepts.
//
// A deliberate floor, not a starting point: attribution spec §5.1 puts alg
// inside the signed material precisely so a verifier cannot be talked into a
// weaker one, and a single-algorithm implementation cannot be talked into it at
// all.
const SignatureAlg = "EdDSA"

// MaxChainLength is §4.4's cap, bounded so a verifier cannot be made to run
// unbounded signature verifications.
const MaxChainLength = 8

// Token and ChainNode are maps, not structs, and that is a correctness
// decision rather than laziness.
//
// A struct with json tags round-trips a token through a fixed field list, so
// any claim this Go build does not know about is silently dropped before
// canonicalization -- and every upstream hop signed over it. The failure
// surfaces as "signature invalid" against an honest node. Verification has to
// operate on what was actually on the wire (§9.1), so the wire shape is what it
// holds.
type (
	Token     = map[string]any
	ChainNode = map[string]any
	JWK       = map[string]any
)

// ---------------------------------------------------------------------------
// Encoding and keys
// ---------------------------------------------------------------------------

// Base64URL encodes unpadded base64url -- the encoding §5.2 mandates.
func Base64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URL decodes unpadded base64url and rejects everything else.
//
// base64.URLEncoding would accept "=" padding, and StdEncoding would accept
// "+/". Admitting those makes two distinct encodings of one signature both
// valid -- a malleability foothold -- and lets through values that
// AttributionChainNode.signature's own pattern (^[A-Za-z0-9_-]+$) rejects.
func DecodeBase64URL(value, what string) ([]byte, error) {
	if value == "" {
		return nil, errf("invalid_encoding", "%s is empty", what)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return nil, errf("invalid_encoding", "%s is not unpadded base64url", what)
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errf("invalid_encoding", "%s is not unpadded base64url", what)
	}
	return raw, nil
}

// AssertEd25519PublicJWK validates that an arbitrary JWKS entry is an Ed25519
// signing key and returns its raw 32 bytes.
//
// Returns alg_not_supported -- not key_not_found -- when the key exists but is
// the wrong kind. §8 keeps those codes separate and the distinction is
// operationally real: one means "you are looking at the wrong node", the other
// means "that node published something I will not verify with".
func AssertEd25519PublicJWK(jwk JWK, what string) (ed25519.PublicKey, error) {
	if jwk == nil {
		return nil, errf("invalid_key", "%s is not an object", what)
	}
	if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
		return nil, errf("alg_not_supported", "%s is kty=%v crv=%v; only OKP/Ed25519 is supported", what, jwk["kty"], jwk["crv"])
	}
	if alg, ok := jwk["alg"]; ok && alg != SignatureAlg {
		return nil, errf("alg_not_supported", "%s declares alg=%v; only EdDSA is supported", what, alg)
	}
	if use, ok := jwk["use"]; ok && use != "sig" {
		return nil, errf("alg_not_supported", "%s declares use=%v; a signing key is required", what, use)
	}
	x, ok := jwk["x"].(string)
	if !ok {
		return nil, errf("invalid_key", "%s has no \"x\" member", what)
	}
	raw, err := DecodeBase64URL(x, what+".x")
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errf("invalid_key", "%s.x decodes to %d bytes, expected %d", what, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// PrivateKeyFromJWK rebuilds a signing key from a JWK's "d" seed.
func PrivateKeyFromJWK(jwk JWK) (ed25519.PrivateKey, error) {
	d, ok := jwk["d"].(string)
	if !ok {
		return nil, errf("invalid_key", "private JWK has no \"d\" member")
	}
	seed, err := DecodeBase64URL(d, "JWK.d")
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errf("invalid_key", "JWK.d decodes to %d bytes, expected %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// JWKThumbprint is the RFC 7638 thumbprint.
//
// The RFC describes SHA-256 over the required members in lexicographic order
// with no whitespace, which is OCP-JCS v1 applied to {crv, kty, x} -- so it
// reuses the canonicalizer rather than hand-rolling the JSON. One fewer place
// for member order to drift.
func JWKThumbprint(jwk JWK) (string, error) {
	canonical, err := CanonicalizeValue(map[string]any{"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return Base64URL(sum[:]), nil
}

// ---------------------------------------------------------------------------
// Chain primitives (§4.3, §5.2, §5.3, §5.4)
// ---------------------------------------------------------------------------

// CoreClaims is §4.3 -- the token minus complete and chain.
//
// Built by removing the two derived members rather than copying a list of
// wanted keys. A future optional claim would silently drop out of the signed
// material under a copy-list, and a claim signed by one implementation and not
// another is a verification failure with no useful error message.
func CoreClaims(token Token) map[string]any {
	core := make(map[string]any, len(token))
	for k, v := range token {
		if k != "complete" && k != "chain" {
			core[k] = v
		}
	}
	return core
}

// UnsignedNode is §5.2's unsigned(node): every field except signature.
func UnsignedNode(n ChainNode) map[string]any {
	out := make(map[string]any, len(n))
	for k, v := range n {
		if k != "signature" {
			out[k] = v
		}
	}
	return out
}

// SigningBytes returns the exact bytes hop N signs, where chainPrefix is hops
// 1..N in order. Exposed because when a cross-language signature disagrees,
// this is the first thing worth comparing.
//
// Member order inside the object is irrelevant (OCP-JCS sorts it); array order
// is semantics and is preserved.
func SigningBytes(chainPrefix []ChainNode, core map[string]any) ([]byte, error) {
	unsigned := make([]any, 0, len(chainPrefix))
	for _, n := range chainPrefix {
		unsigned = append(unsigned, UnsignedNode(n))
	}
	canonical, err := CanonicalizeValue(map[string]any{"chain": unsigned, "core": core})
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

// SignChainNode signs hop N, where chainPrefix is hops 1..N-1.
//
// Hop N signs itself as well as its predecessors -- the prefix handed to the
// canonicalizer is append(chainPrefix, node). Omitting the node's own fields
// would leave settles and chain_complete unsigned, and those two are exactly
// the fields with money attached.
func SignChainNode(privateJWK JWK, core map[string]any, chainPrefix []ChainNode, unsigned map[string]any) (ChainNode, error) {
	key, err := PrivateKeyFromJWK(privateJWK)
	if err != nil {
		return nil, err
	}
	message, err := SigningBytes(append(append([]ChainNode{}, chainPrefix...), unsigned), core)
	if err != nil {
		return nil, err
	}
	signed := make(ChainNode, len(unsigned)+1)
	for k, v := range unsigned {
		signed[k] = v
	}
	signed["signature"] = Base64URL(ed25519.Sign(key, message))
	return signed, nil
}

// VerifyChainNodeSignature checks one hop against the chain prefix it committed
// to. It returns false for a mismatch and an error only for unusable key
// material: "this signature is wrong" is a fact a verifier must record and keep
// going from, while "I cannot evaluate this key" is a trust failure that must
// not be filed as a mismatch.
func VerifyChainNodeSignature(jwk JWK, core map[string]any, chain []ChainNode, hopIndex int) (bool, error) {
	if hopIndex >= len(chain) {
		return false, nil
	}
	node := chain[hopIndex]
	if alg, ok := node["alg"].(string); ok && alg != SignatureAlg {
		return false, errf("alg_not_supported", "alg=%s is not supported; only EdDSA is", alg)
	}
	pub, err := AssertEd25519PublicJWK(jwk, "JWK")
	if err != nil {
		return false, err
	}
	signature, ok := node["signature"].(string)
	if !ok {
		return false, nil
	}
	raw, decodeErr := DecodeBase64URL(signature, "signature")
	if decodeErr != nil || len(raw) != ed25519.SignatureSize {
		return false, nil // a malformed signature is a mismatch, not a config error
	}
	message, err := SigningBytes(chain[:hopIndex+1], core)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(pub, message, raw), nil
}

// RecomputeComplete is §5.3 -- the AND of every hop's chain_complete.
//
// A verifier must call this and compare, never read token["complete"]: that
// field sits outside all signed material, so it is the cheapest possible place
// to probe for a verifier that trusts what it is told.
func RecomputeComplete(chain []ChainNode) bool {
	for _, node := range chain {
		if flag, ok := node["chain_complete"].(bool); !ok || !flag {
			return false
		}
	}
	return true
}

// CheckChainStructure is §5.4, which §7.1 runs before any signature check.
//
// It returns the reason the chain is malformed, or "". A reason string rather
// than a bool because all four conditions collapse to one error code
// (chain_broken), so the only way a caller can tell a cycle from a renumbered
// hop is if this says which.
//
// Running it first is not a happy-path optimisation -- it is a refusal to run
// eight signature verifications on behalf of a chain already known to be junk.
func CheckChainStructure(chain []ChainNode) string {
	if len(chain) < 1 {
		return "chain is empty"
	}
	if len(chain) > MaxChainLength {
		return fmt.Sprintf("chain has %d hops, over the §4.4 cap of %d", len(chain), MaxChainLength)
	}
	seen := map[string]struct{}{}
	for index, node := range chain {
		expectedHop := index + 1
		if hop, ok := asInt(node["hop"]); !ok || hop != expectedHop {
			return fmt.Sprintf("chain[%d].hop is %v, expected %d", index, node["hop"], expectedHop)
		}
		expectedRole := "relay"
		if index == 0 {
			expectedRole = "origin"
		}
		if node["role"] != expectedRole {
			return fmt.Sprintf("hop %d has role %q, expected %q", expectedHop, node["role"], expectedRole)
		}
		// A repeat is a loop, not a topology: the same node cannot both hand
		// off and receive back without an unrecorded hop in between.
		catalogID, _ := node["catalog_id"].(string)
		if _, dup := seen[catalogID]; dup {
			return fmt.Sprintf("catalog_id %q appears twice (hop %d repeats an earlier hop)", catalogID, expectedHop)
		}
		seen[catalogID] = struct{}{}
	}
	return ""
}

func asInt(value any) (int, bool) {
	switch v := value.(type) {
	case json.Number:
		n, err := v.Int64()
		return int(n), err == nil
	case float64:
		return int(v), v == float64(int(v))
	case int:
		return v, true
	default:
		return 0, false
	}
}

// ChainOf extracts the chain as a slice, tolerating its absence.
func ChainOf(token Token) []ChainNode {
	raw, ok := token["chain"].([]any)
	if !ok {
		return nil
	}
	chain := make([]ChainNode, 0, len(raw))
	for _, item := range raw {
		node, ok := item.(map[string]any)
		if !ok {
			return nil
		}
		chain = append(chain, node)
	}
	return chain
}

// ---------------------------------------------------------------------------
// Key resolution and the replay guard
// ---------------------------------------------------------------------------

// KeyResolver returns the verification key for one hop. Injected rather than
// fetched: a verifier that reaches for the network on its own cannot be tested
// offline, and offline verification is the property this mechanism exists to
// provide.
type KeyResolver func(catalogID, kid string, hop int) (JWK, error)

// StaticKeyResolver resolves from key material already in hand -- one JWKS per
// catalog_id, exactly what a merchant has after curling each node once.
func StaticKeyResolver(jwksByCatalogID map[string]any) KeyResolver {
	return func(catalogID, kid string, hop int) (JWK, error) {
		jwks, ok := jwksByCatalogID[catalogID].(map[string]any)
		if !ok {
			return nil, errf("key_not_found", "no JWKS on hand for catalog %q", catalogID)
		}
		keys, ok := jwks["keys"].([]any)
		if !ok {
			return nil, errf("key_not_found", "no JWKS on hand for catalog %q", catalogID)
		}
		for _, item := range keys {
			key, ok := item.(map[string]any)
			if ok && key["kid"] == kid {
				if _, err := AssertEd25519PublicJWK(key, "JWK"); err != nil {
					return nil, err
				}
				return key, nil
			}
		}
		return nil, errf("key_not_found", "kid %q is not in the JWKS of %q", kid, catalogID)
	}
}

// JtiRegistry is §7.1 row 10, the jti replay guard.
//
// The rule is narrow and worth restating: the same jti against the same
// order_id is normal traffic (a retry, a status update). The same jti against a
// different order_id is one attribution token being spent twice, which is the
// whole attack.
//
// This is in-memory, and production needs persistent storage. Not a caveat, a
// correctness gap with a name: a restart empties it, so every token issued
// before the restart becomes replayable once more; and it is per-process, so
// two settlement workers behind a load balancer hold two maps and the same
// token can be claimed once in each. The replacement is a row in the same
// transactional store that records the settlement, keyed on jti with the
// order_id beside it -- the claim and the payout have to commit together or the
// guard can be lost after the money moves.
//
// Not safe for concurrent use; a caller settling from several goroutines has
// already outgrown it.
type JtiRegistry struct {
	claims map[string]jtiClaim
	Now    func() time.Time
}

type jtiClaim struct {
	orderID   string
	expiresAt time.Time
}

func NewJtiRegistry() *JtiRegistry {
	return &JtiRegistry{claims: map[string]jtiClaim{}, Now: time.Now}
}

func (r *JtiRegistry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Prune drops entries past their token's exp. Retention is derived, not
// configured: past exp, §7.1 row 9 rejects the token anyway.
func (r *JtiRegistry) Prune() {
	now := r.now()
	for jti, claim := range r.claims {
		if !claim.expiresAt.After(now) {
			delete(r.claims, jti)
		}
	}
}

// Size reports live claims, after pruning.
func (r *JtiRegistry) Size() int {
	r.Prune()
	return len(r.claims)
}

// Claim binds jti to orderID. It returns false if that jti is already bound to
// a different order -- a replay.
func (r *JtiRegistry) Claim(jti, orderID string, expiresAt time.Time) bool {
	r.Prune()
	if existing, ok := r.claims[jti]; ok {
		return existing.orderID == orderID
	}
	r.claims[jti] = jtiClaim{orderID: orderID, expiresAt: expiresAt}
	return true
}

// OrderOf reports the order a jti is bound to, if any.
func (r *JtiRegistry) OrderOf(jti string) (string, bool) {
	r.Prune()
	claim, ok := r.claims[jti]
	return claim.orderID, ok
}

// ---------------------------------------------------------------------------
// The §7.1 eligibility filter
// ---------------------------------------------------------------------------

// Verdict is the outcome of running §7.1 over one token. A rejection is data,
// not an error return: a settler holds several candidate tokens and must record
// why each one lost before adjudicating among the survivors (§7.2).
type Verdict struct {
	OK                 bool
	Err                *Error
	Complete           bool
	AgentID            string
	SettlingCatalogIDs []string
	LastSignedAt       string
	Hops               int
}

// VerifyOptions carries the §7.1 parameters that depend on the report.
type VerifyOptions struct {
	// At is the moment the token is being claimed for -- a report's
	// occurred_at, not the moment of verification. Rows 8 and 9 are about when
	// the transaction happened; checking them against "now" would reject a
	// valid sale reported an hour late. Zero means now.
	At time.Time
	// ExpectedProviderID is row 7. Empty skips the check.
	ExpectedProviderID string
	// RequirePurpose is row 6. Empty means "checkout"; AnyPurpose checks the
	// cryptography of a non-settleable token, which is legitimately signed and
	// simply cannot be settled against.
	RequirePurpose string
	// Replay, when set, is row 10. ClaimJti false checks the row without taking
	// the slot: a settler holding several candidates for one order must
	// evaluate row 10 on all of them but claim only the one that wins §7.2 --
	// claiming for a loser binds its jti to an order it never settled against.
	Replay   *JtiRegistry
	OrderID  string
	ClaimJti bool
}

// AnyPurpose disables row 6.
const AnyPurpose = "*"

func reject(code, message string, hop int) Verdict {
	return Verdict{OK: false, Err: &Error{Code: code, Message: message, Hop: hop}}
}

// VerifyAttributionToken runs the §7.1 eligibility filter over one token, in
// §8's fixed order, stopping at the first failure.
//
// §7.1 is written as a settlement filter but it is also the normative
// verification order: §8 fixes the order to that table's rows and requires
// termination at the first failure. The reason is conformance, not taste -- a
// token that violates three rules at once must produce the same one error code
// in every implementation, or the shared vectors cannot assert anything about
// it. That is why this mirrors verify.ts row for row instead of checking the
// same things in whatever order reads best in Go.
//
// Key-material failures that are not about the token are returned as an error
// rather than a verdict: if the JWKS is unreachable, stale or malformed, a node
// whose key server is down has not forged anything, and turning its outage into
// key_not_found would settle against it as though it had. Only key_not_found,
// alg_not_supported and invalid_key -- all statements about key material
// actually published under that kid -- become verdicts.
//
// One deviation from §7.1's printed row order: rows 3, 4, 5 are listed as
// signature -> key -> alg, which cannot be executed in that order, because
// verifying a signature requires the key and verifying it under an unchecked
// algorithm is the algorithm-confusion hole §5.1 exists to close. This runs
// each hop as alg -> key -> signature, hops ascending, and the spec has been
// corrected to match (§7.1, v1.0.1).
//
// Ascending hop order is itself normative: §5.2's second implied property is
// that altering hop K breaks hops K..N, so the lowest failing hop is the
// tampered one. Reporting any other failing hop would name an innocent node.
func VerifyAttributionToken(token Token, resolveKey KeyResolver, opts VerifyOptions) (Verdict, error) {
	at := opts.At
	if at.IsZero() {
		at = time.Now()
	}
	requirePurpose := opts.RequirePurpose
	if requirePurpose == "" {
		requirePurpose = "checkout"
	}

	chain := ChainOf(token)

	// Row 1 -- structure, before any signature work (§5.4).
	if broken := CheckChainStructure(chain); broken != "" {
		return reject("chain_broken", broken, 0), nil
	}

	// Row 2 -- recompute complete; never read it (§5.3).
	complete := RecomputeComplete(chain)
	if declared, ok := token["complete"].(bool); !ok || declared != complete {
		return reject("complete_mismatch", fmt.Sprintf(
			"token says complete=%v, the chain's chain_complete flags recompute to %v", token["complete"], complete), 0), nil
	}

	// Rows 3-5, per hop, ascending. See the note above on their order.
	core := CoreClaims(token)
	for index, node := range chain {
		hop := index + 1

		if node["alg"] != SignatureAlg {
			return reject("alg_not_supported", fmt.Sprintf("alg is %q, expected %q", node["alg"], SignatureAlg), hop), nil
		}

		catalogID, _ := node["catalog_id"].(string)
		kid, _ := node["kid"].(string)
		jwk, err := resolveKey(catalogID, kid, hop)
		if err != nil {
			switch CodeOf(err) {
			// "Resolvable" in row 4 covers a kid that is present but unusable:
			// a key we cannot verify with is a key we did not find.
			case "key_not_found", "invalid_key":
				return reject("key_not_found", err.(*Error).Message, hop), nil
			case "alg_not_supported":
				return reject("alg_not_supported", err.(*Error).Message, hop), nil
			}
			return Verdict{}, err // jwks_unavailable and friends -- not a verdict
		}

		ok, err := VerifyChainNodeSignature(jwk, core, chain, index)
		if err != nil {
			if code := CodeOf(err); code == "alg_not_supported" || code == "invalid_key" {
				return reject(code, err.(*Error).Message, hop), nil
			}
			return Verdict{}, err
		}
		if !ok {
			return reject("signature_invalid", fmt.Sprintf(
				"hop %d (%s) does not verify against its chain prefix", hop, catalogID), hop), nil
		}
	}

	// Row 6 -- only checkout settles.
	if requirePurpose != AnyPurpose && token["purpose"] != requirePurpose {
		return reject("purpose_not_settleable", fmt.Sprintf(
			"purpose is %q, only %q settles", token["purpose"], requirePurpose), 0), nil
	}

	// Row 7 -- the report and the token must name the same provider.
	if opts.ExpectedProviderID != "" && token["provider_id"] != opts.ExpectedProviderID {
		return reject("provider_mismatch", fmt.Sprintf(
			"report names provider %q, token names %q", opts.ExpectedProviderID, token["provider_id"]), 0), nil
	}

	// Rows 8, 9 -- the validity window, measured at `at`.
	iat, iatOK := instant(token["iat"])
	exp, expOK := instant(token["exp"])
	if !iatOK || !expOK {
		return reject("chain_broken", fmt.Sprintf(
			"iat/exp are not usable timestamps: iat=%q exp=%q", token["iat"], token["exp"]), 0), nil
	}
	if at.Before(iat) {
		return reject("token_not_yet_valid", fmt.Sprintf("%s is before iat %v", at.UTC().Format(time.RFC3339), token["iat"]), 0), nil
	}
	if at.After(exp) {
		return reject("token_expired", fmt.Sprintf("%s is after exp %v", at.UTC().Format(time.RFC3339), token["exp"]), 0), nil
	}

	// Row 10 -- last, so nothing below can reject a token whose jti we just spent.
	if opts.Replay != nil {
		jti, _ := token["jti"].(string)
		held, exists := "", false
		if opts.ClaimJti {
			if !opts.Replay.Claim(jti, opts.OrderID, exp) {
				held, exists = opts.Replay.OrderOf(jti)
			}
		} else {
			held, exists = opts.Replay.OrderOf(jti)
		}
		if exists && held != opts.OrderID {
			return reject("replayed_jti", fmt.Sprintf(
				"jti %q is already settled against order %q, not %q", jti, held, opts.OrderID), 0), nil
		}
	}

	settling := []string{}
	for _, node := range chain {
		if flag, ok := node["settles"].(bool); ok && flag {
			catalogID, _ := node["catalog_id"].(string)
			settling = append(settling, catalogID)
		}
	}
	agentID, _ := token["agent_id"].(string)
	lastSignedAt, _ := chain[len(chain)-1]["signed_at"].(string)

	return Verdict{
		OK:                 true,
		Complete:           complete,
		AgentID:            agentID,
		SettlingCatalogIDs: settling,
		LastSignedAt:       lastSignedAt,
		Hops:               len(chain),
	}, nil
}

func instant(value any) (time.Time, bool) {
	s, ok := value.(string)
	if !ok {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, s)
	return parsed, err == nil
}

// SortedCatalogIDs is a convenience for tests comparing settlement subjects
// where hop order is not the property under test.
func SortedCatalogIDs(ids []string) []string {
	out := append([]string{}, ids...)
	sort.Strings(out)
	return out
}
