package ocpcrypto

import (
	"testing"
	"time"
)

// Local tests for the document signature implementation -- the half that asks
// "is this implementation coherent?" rather than "does it agree with the other
// two languages?". The cross-language half lives in interopsig/agent_test.go.

var signatureNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// signatureKeyPair returns a deterministic pair, so a failure is reproducible
// from the log alone.
func signatureKeyPair(t *testing.T) (JWK, JWK) {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x22
	}
	public, private, err := GenerateKeyPair(seed)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return public, private
}

func signFixtureDocument(t *testing.T, private JWK, document Document) Document {
	t.Helper()
	signed, err := SignDocument(SignDocumentParams{Document: document, PrivateJWK: private, SignedAt: signatureNow})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func localDocument() Document {
	return Document{"catalog_id": "cat_local", "kind": "catalog-manifest", "n": 1}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	public, private := signatureKeyPair(t)
	signed := signFixtureDocument(t, private, localDocument())

	resolver := StaticDocumentKeyResolver(map[string]any{"cat_local": map[string]any{"keys": []any{map[string]any(public)}}})
	verdict, err := VerifyDocumentSignature(map[string]any(signed), resolver, VerifyDocumentOptions{At: signatureNow})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !verdict.OK {
		t.Fatalf("verdict rejected: %s", verdict.Err)
	}
	if verdict.Issuer != "cat_local" || verdict.Kid != private["kid"] || verdict.Alg != SignatureAlg {
		t.Errorf("unexpected verdict %+v", verdict)
	}
}

func TestKidDefaultsToTheThumbprint(t *testing.T) {
	_, private := signatureKeyPair(t)
	anonymous := JWK{}
	for k, v := range private {
		if k != "kid" {
			anonymous[k] = v
		}
	}
	signed, err := SignDocument(SignDocumentParams{Document: localDocument(), PrivateJWK: anonymous, SignedAt: signatureNow})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	envelope := signed[SignatureMember].(map[string]any)
	if envelope["kid"] != private["kid"] {
		t.Errorf("kid = %v, want the RFC 7638 thumbprint %v", envelope["kid"], private["kid"])
	}
}

// TestRefusesAnIssuerThatContradictsCatalogID -- a document no verifier will
// ever accept should not leave the signer. §7 step 4 rejects this combination
// everywhere, so producing it only moves the failure from the node that can fix
// it to the consumer who cannot.
func TestRefusesAnIssuerThatContradictsCatalogID(t *testing.T) {
	_, private := signatureKeyPair(t)
	_, err := SignDocument(SignDocumentParams{
		Document: localDocument(), PrivateJWK: private, Issuer: "cat_someone_else", SignedAt: signatureNow,
	})
	if CodeOf(err) != "issuer_mismatch" {
		t.Fatalf("err = %v, want issuer_mismatch", err)
	}
}

func TestRequiresAnIssuerWhenThereIsNoCatalogID(t *testing.T) {
	_, private := signatureKeyPair(t)
	_, err := SignDocument(SignDocumentParams{Document: Document{"kind": "thing"}, PrivateJWK: private, SignedAt: signatureNow})
	if CodeOf(err) != "issuer_mismatch" {
		t.Fatalf("err = %v, want issuer_mismatch", err)
	}
}

// TestMemberOrderDoesNotChangeTheSignature -- OCP-JCS sorts before hashing, so
// a document that went through a proxy, a database, or any JSON library with
// its own opinion about member order still verifies.
func TestMemberOrderDoesNotChangeTheSignature(t *testing.T) {
	_, private := signatureKeyPair(t)
	a := signFixtureDocument(t, private, Document{"catalog_id": "cat_local", "kind": "catalog-manifest", "n": 1})
	b := signFixtureDocument(t, private, Document{"n": 1, "kind": "catalog-manifest", "catalog_id": "cat_local"})

	left := a[SignatureMember].(map[string]any)["signature"]
	right := b[SignatureMember].(map[string]any)["signature"]
	if left != right {
		t.Errorf("signature depends on member order: %v vs %v", left, right)
	}
}

func TestReSigningReplacesTheEnvelope(t *testing.T) {
	_, private := signatureKeyPair(t)
	once := signFixtureDocument(t, private, localDocument())
	twice := signFixtureDocument(t, private, once)

	if _, nested := DocumentPayload(twice)[SignatureMember]; nested {
		t.Error("the previous envelope was carried into the new payload")
	}
	a, err := CanonicalizeValue(map[string]any(once))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	b, err := CanonicalizeValue(map[string]any(twice))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if a != b {
		t.Error("re-signing an unchanged document produced a different result")
	}
}

// TestPayloadIsCheckedBeforeTheKeyIsFetched -- a tampered document must not be
// able to drive a key lookup, or anyone can make this verifier issue a request
// to any issuer string they choose just by handing it a document.
func TestPayloadIsCheckedBeforeTheKeyIsFetched(t *testing.T) {
	public, private := signatureKeyPair(t)
	signed := signFixtureDocument(t, private, localDocument())

	fetched := 0
	resolver := func(issuer, kid string) (JWK, error) {
		fetched++
		return public, nil
	}

	tampered := map[string]any{}
	for k, v := range signed {
		tampered[k] = v
	}
	tampered["n"] = 2

	verdict, err := VerifyDocumentSignature(tampered, resolver, VerifyDocumentOptions{At: signatureNow})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict.Err.Code != "payload_mismatch" {
		t.Errorf("code = %s, want payload_mismatch", verdict.Err.Code)
	}
	if fetched != 0 {
		t.Errorf("the resolver was called %d times for a document that never verified", fetched)
	}
}

// TestExpiryIsCheckedLast -- a forged document that is also expired is a
// forgery. Checking expiry earlier would report it as the milder finding.
func TestExpiryIsCheckedLast(t *testing.T) {
	public, private := signatureKeyPair(t)
	expires := signatureNow.Add(time.Hour)
	signed, err := SignDocument(SignDocumentParams{
		Document: localDocument(), PrivateJWK: private, SignedAt: signatureNow, ExpiresAt: expires,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	forged := map[string]any{}
	for k, v := range signed {
		forged[k] = v
	}
	forged["n"] = 99

	resolver := StaticDocumentKeyResolver(map[string]any{"cat_local": map[string]any{"keys": []any{map[string]any(public)}}})
	verdict, err := VerifyDocumentSignature(forged, resolver,
		VerifyDocumentOptions{At: expires.Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict.Err.Code != "payload_mismatch" {
		t.Errorf("code = %s, want payload_mismatch", verdict.Err.Code)
	}
}

func TestUnknownEnvelopeFieldIsRejected(t *testing.T) {
	public, private := signatureKeyPair(t)
	signed := signFixtureDocument(t, private, localDocument())

	envelope := map[string]any{"extra": "x"}
	for k, v := range signed[SignatureMember].(map[string]any) {
		envelope[k] = v
	}
	tampered := map[string]any{SignatureMember: envelope}
	for k, v := range DocumentPayload(signed) {
		tampered[k] = v
	}

	resolver := StaticDocumentKeyResolver(map[string]any{"cat_local": map[string]any{"keys": []any{map[string]any(public)}}})
	verdict, err := VerifyDocumentSignature(tampered, resolver, VerifyDocumentOptions{At: signatureNow})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict.Err.Code != "envelope_malformed" {
		t.Errorf("code = %s, want envelope_malformed", verdict.Err.Code)
	}
}

// TestADocumentWithoutCatalogIDNeedsAnExpectedIssuer -- a §4.4 check that
// silently does not run is worse than one that fails loudly.
func TestADocumentWithoutCatalogIDNeedsAnExpectedIssuer(t *testing.T) {
	public, private := signatureKeyPair(t)
	signed, err := SignDocument(SignDocumentParams{
		Document: Document{"kind": "thing"}, PrivateJWK: private, Issuer: "cat_local", SignedAt: signatureNow,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	resolver := StaticDocumentKeyResolver(map[string]any{"cat_local": map[string]any{"keys": []any{map[string]any(public)}}})

	cases := []struct {
		expectedIssuer string
		wantCode       string
	}{
		{"", "issuer_mismatch"},
		{"cat_local", ""},
		{"cat_x", "issuer_mismatch"},
	}
	for _, tc := range cases {
		verdict, err := VerifyDocumentSignature(map[string]any(signed), resolver,
			VerifyDocumentOptions{At: signatureNow, ExpectedIssuer: tc.expectedIssuer})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		got := ""
		if !verdict.OK {
			got = verdict.Err.Code
		}
		if got != tc.wantCode {
			t.Errorf("ExpectedIssuer=%q gave %q, want %q", tc.expectedIssuer, got, tc.wantCode)
		}
	}
}

func TestMissingJWKSAndMissingKidBothReadAsKeyNotFound(t *testing.T) {
	_, private := signatureKeyPair(t)
	signed := signFixtureDocument(t, private, localDocument())

	for _, jwks := range []map[string]any{
		{},
		{"cat_local": map[string]any{"keys": []any{}}},
	} {
		verdict, err := VerifyDocumentSignature(map[string]any(signed),
			StaticDocumentKeyResolver(jwks), VerifyDocumentOptions{At: signatureNow})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if verdict.Err.Code != "key_not_found" {
			t.Errorf("code = %s, want key_not_found", verdict.Err.Code)
		}
	}
}

// TestWrongKindOfKeyIsAlgNotSupported -- one means "wrong node", the other
// means "that node published something I will not verify with". §8 keeps them
// apart.
func TestWrongKindOfKeyIsAlgNotSupported(t *testing.T) {
	_, private := signatureKeyPair(t)
	signed := signFixtureDocument(t, private, localDocument())

	rsa := map[string]any{"kty": "RSA", "kid": private["kid"], "n": "x", "e": "AQAB"}
	resolver := StaticDocumentKeyResolver(map[string]any{"cat_local": map[string]any{"keys": []any{rsa}}})
	verdict, err := VerifyDocumentSignature(map[string]any(signed), resolver, VerifyDocumentOptions{At: signatureNow})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verdict.Err.Code != "alg_not_supported" {
		t.Errorf("code = %s, want alg_not_supported", verdict.Err.Code)
	}
}

// TestKeyServerOutageIsAnErrorNotAVerdict -- §7.3. A node whose key server is
// down has not forged anything, and filing the outage as key_not_found would
// give it a forgery's trust ceiling and drop its cache with it.
func TestKeyServerOutageIsAnErrorNotAVerdict(t *testing.T) {
	_, private := signatureKeyPair(t)
	signed := signFixtureDocument(t, private, localDocument())

	resolver := func(issuer, kid string) (JWK, error) {
		return nil, errf("jwks_unavailable", "key server is down")
	}
	_, err := VerifyDocumentSignature(map[string]any(signed), resolver, VerifyDocumentOptions{At: signatureNow})
	if CodeOf(err) != "jwks_unavailable" {
		t.Fatalf("err = %v, want jwks_unavailable to propagate", err)
	}
}

func TestTrustCeiling(t *testing.T) {
	cases := []struct {
		verdict SignatureVerdict
		want    TrustCeiling
	}{
		{SignatureVerdict{OK: true}, TrustCeiling{"verified", false}},
		// Absence of proof is not proof of tampering: one node has not started
		// signing, the other forgot to re-sign. Neither justifies a cache drop.
		{rejectSignature("unsigned", ""), TrustCeiling{"unverified", false}},
		{rejectSignature("signature_expired", ""), TrustCeiling{"unverified", false}},
		{rejectSignature("payload_mismatch", ""), TrustCeiling{"unknown", true}},
		{rejectSignature("signature_invalid", ""), TrustCeiling{"unknown", true}},
		{rejectSignature("envelope_malformed", ""), TrustCeiling{"unknown", true}},
		{rejectSignature("key_not_found", ""), TrustCeiling{"unknown", true}},
		{rejectSignature("alg_not_supported", ""), TrustCeiling{"unknown", true}},
		{rejectSignature("issuer_mismatch", ""), TrustCeiling{"unknown", true}},
	}
	for _, tc := range cases {
		if got := TrustCeilingFor(tc.verdict); got != tc.want {
			code := "ok"
			if tc.verdict.Err != nil {
				code = tc.verdict.Err.Code
			}
			t.Errorf("%s: got %+v, want %+v", code, got, tc.want)
		}
	}
}

func TestDocumentPayloadHashStripsTheEnvelope(t *testing.T) {
	_, private := signatureKeyPair(t)
	document := localDocument()
	signed := signFixtureDocument(t, private, document)

	got, err := DocumentPayloadHash(signed)
	if err != nil {
		t.Fatalf("payload hash: %v", err)
	}
	want, err := CanonicalValueHash(map[string]any(document))
	if err != nil {
		t.Fatalf("canonical hash: %v", err)
	}
	if got != want {
		t.Errorf("payload hash = %s, want %s", got, want)
	}
}
