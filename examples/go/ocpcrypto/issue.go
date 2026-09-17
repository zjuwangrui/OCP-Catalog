package ocpcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"
)

// Issuance: the helpers a catalog uses to mint a token and a relay uses to
// extend one. The W4 deliverable only requires Go to *verify*, but signing is
// what makes the 3x3 matrix meaningful -- a verifier that has never produced a
// signature is only being tested against one producer.

// RFC3339 formats an instant the way the rest of the protocol does:
// millisecond precision, Z, no offset.
//
// Not cosmetic. iat, exp and signed_at sit inside the signed material, so the
// exact spelling is part of the bytes every implementation has to reproduce.
// time.RFC3339Nano would drop trailing zeros (12:00:00Z instead of
// 12:00:00.000Z) and every signature would differ from the TypeScript one.
func RFC3339(moment time.Time) string {
	return moment.UTC().Format("2006-01-02T15:04:05.000") + "Z"
}

// GenerateKeyPair returns (public JWK, private JWK). A nil seed draws from
// crypto/rand; a fixed seed makes a test reproducible.
//
// kid defaults to the RFC 7638 thumbprint, so two nodes that hold the same key
// name it identically without coordinating.
func GenerateKeyPair(seed []byte) (JWK, JWK, error) {
	if seed == nil {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, nil, err
		}
	}
	if len(seed) != ed25519.SeedSize {
		return nil, nil, errf("invalid_key", "seed is %d bytes, expected %d", len(seed), ed25519.SeedSize)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)

	publicJWK := JWK{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   Base64URL(public),
		"alg": SignatureAlg,
		"use": "sig",
	}
	kid, err := JWKThumbprint(publicJWK)
	if err != nil {
		return nil, nil, err
	}
	publicJWK["kid"] = kid

	privateJWK := JWK{"d": Base64URL(seed)}
	for k, v := range publicJWK {
		privateJWK[k] = v
	}
	return publicJWK, privateJWK, nil
}

// PublicJWKOf strips the private seed. Used wherever a key is about to be
// published -- the one-line version of "never serialize the JWK you signed with".
func PublicJWKOf(jwk JWK) JWK {
	out := make(JWK, len(jwk))
	for k, v := range jwk {
		if k != "d" {
			out[k] = v
		}
	}
	return out
}

// OriginParams is what hop 1 needs. A struct rather than a dozen positional
// arguments because catalog_id, agent_id, entry_id, object_id and provider_id
// are all strings and swapping two of them silently signs the wrong thing.
type OriginParams struct {
	PrivateJWK JWK
	Kid        string
	CatalogID  string
	AgentID    string
	EntryID    string
	ObjectID   string
	ProviderID string
	// Purpose defaults to "checkout"; only that one settles (§7.1 row 6).
	Purpose string
	// AgentIdentitySource defaults to "ocp".
	AgentIdentitySource string
	// Jti defaults to a random identifier. Supply one only to make a test
	// reproducible -- a predictable jti in production is a replay handed out.
	Jti string
	// TTLSeconds defaults to 3600.
	TTLSeconds int
	// Settles defaults to true: the node that put the object in front of the
	// agent is the node that is owed.
	Settles *bool
	// Now defaults to time.Now.
	Now func() time.Time
}

// IssueOriginToken mints a single-hop token signed by the origin catalog.
func IssueOriginToken(p OriginParams) (Token, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	issuedAt := now()
	ttl := p.TTLSeconds
	if ttl == 0 {
		ttl = 3600
	}
	purpose := p.Purpose
	if purpose == "" {
		purpose = "checkout"
	}
	source := p.AgentIdentitySource
	if source == "" {
		source = "ocp"
	}
	jti := p.Jti
	if jti == "" {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, err
		}
		jti = "atr_" + fmt.Sprintf("%x", raw)
	}
	settles := true
	if p.Settles != nil {
		settles = *p.Settles
	}

	core := map[string]any{
		"ocp_version":           "1.0",
		"kind":                  "AttributionToken",
		"jti":                   jti,
		"iss":                   p.CatalogID,
		"iat":                   RFC3339(issuedAt),
		"exp":                   RFC3339(issuedAt.Add(time.Duration(ttl) * time.Second)),
		"agent_id":              p.AgentID,
		"agent_identity_source": source,
		"entry_id":              p.EntryID,
		"object_id":             p.ObjectID,
		"provider_id":           p.ProviderID,
		"purpose":               purpose,
	}

	node, err := SignChainNode(p.PrivateJWK, core, nil, map[string]any{
		"catalog_id":     p.CatalogID,
		"hop":            1,
		"role":           "origin",
		"settles":        settles,
		"chain_complete": true,
		"alg":            SignatureAlg,
		"kid":            p.Kid,
		"signed_at":      RFC3339(issuedAt),
	})
	if err != nil {
		return nil, err
	}

	token := Token{}
	for k, v := range core {
		token[k] = v
	}
	token["chain"] = []any{map[string]any(node)}
	token["complete"] = true
	return token, nil
}

// RelayParams is what hop N>1 needs.
type RelayParams struct {
	PrivateJWK JWK
	Kid        string
	CatalogID  string
	// ChainComplete is required and has no default on purpose. It is this
	// node's assertion that it knows of no hop it failed to record; a default
	// would make "I did not think about it" indistinguishable from "I checked".
	ChainComplete bool
	// Settles defaults to false. Forgetting a share you are owed is
	// recoverable by asking; claiming one you are not is a false settlement
	// claim signed under your own key.
	Settles bool
	Now     func() time.Time
}

// AppendRelayHop extends a token with one more hop, re-signing over the whole
// prefix.
//
// The upstream chain is copied, never rewritten: a relay that edits an earlier
// hop invalidates that hop's signature and names itself as the tamper site.
func AppendRelayHop(token Token, p RelayParams) (Token, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	chain := ChainOf(token)
	if len(chain) == 0 {
		return nil, errf("chain_broken", "token has no chain to extend")
	}
	if len(chain) >= MaxChainLength {
		return nil, errf("chain_broken", "chain is already at the §4.4 cap of %d hops", MaxChainLength)
	}

	core := CoreClaims(token)
	unsigned := map[string]any{
		"catalog_id":     p.CatalogID,
		"hop":            len(chain) + 1,
		"role":           "relay",
		"settles":        p.Settles,
		"chain_complete": p.ChainComplete,
		"alg":            SignatureAlg,
		"kid":            p.Kid,
		"signed_at":      RFC3339(now()),
	}

	// Refused here rather than at verification time, so a misconfigured relay
	// finds out at the moment it would have signed instead of after a merchant
	// rejects the token.
	extended := append(append([]ChainNode{}, chain...), unsigned)
	if broken := CheckChainStructure(extended); broken != "" {
		return nil, errf("chain_broken", "%s", broken)
	}

	node, err := SignChainNode(p.PrivateJWK, core, chain, unsigned)
	if err != nil {
		return nil, err
	}

	newChain := make([]any, 0, len(chain)+1)
	for _, n := range chain {
		newChain = append(newChain, map[string]any(n))
	}
	newChain = append(newChain, map[string]any(node))

	out := Token{}
	for k, v := range core {
		out[k] = v
	}
	out["chain"] = newChain
	out["complete"] = RecomputeComplete(append(append([]ChainNode{}, chain...), node))
	return out, nil
}
