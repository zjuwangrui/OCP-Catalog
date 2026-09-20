package ocpcrypto

import (
	"crypto/ed25519"
	"fmt"
	"regexp"
	"time"
)

// Document signatures -- spec docs/specs/crypto/v1.md §4.1, §5.1, §7, §8, §9.
//
// A port of packages/ocp-crypto/src/signature.ts, alongside
// examples/python/ocp_signature.py. The three must produce byte-identical
// signed documents from the same recipe and the same key, and must give the
// same §8 code and the same §9 ceiling for every negative in
// packages/ocp-crypto/fixtures/signature/manifest-v1.json.
//
// Not the same mechanism as the attribution chain above, despite the shared
// keys and the shared canonicalizer. A chain node signs the chain prefix plus
// the token's core claims; a document signs an envelope carrying a hash of the
// document. Neither verifier accepts the other's signature, and that is
// deliberate: the two answer different questions, and a verifier that accepted
// both would let a token's signature stand in for a manifest's.

// SignatureMember is the member a signed document carries its envelope in (§2).
const SignatureMember = "signature"

// SignatureErrorCodes is §8, in the order §7 can produce them.
var SignatureErrorCodes = []string{
	"unsigned",
	"envelope_malformed",
	"alg_not_supported",
	"issuer_mismatch",
	"payload_mismatch",
	"key_not_found",
	"signature_invalid",
	"signature_expired",
}

// Document is the wire shape, a map for the same reason Token is: a struct
// with json tags drops any member this build does not know about, and the
// signer hashed over all of them.
type Document = map[string]any

var envelopeFields = map[string]bool{
	"alg": true, "kid": true, "issuer": true, "signed_at": true,
	"expires_at": true, "payload_hash": true, "signature": true,
}

var requiredEnvelopeFields = []string{"alg", "kid", "issuer", "signed_at", "payload_hash", "signature"}

var (
	payloadHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	base64URLPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// ---------------------------------------------------------------------------
// §3 / §4.1 -- the two layers
// ---------------------------------------------------------------------------

// DocumentPayload is §3 -- the document minus its signature member.
func DocumentPayload(document Document) map[string]any {
	payload := make(map[string]any, len(document))
	for k, v := range document {
		if k != SignatureMember {
			payload[k] = v
		}
	}
	return payload
}

// DocumentPayloadHash is §4.1 -- sha256:{hex} over the canonical payload.
//
// Takes the whole document rather than the payload so a caller cannot forget
// to strip the envelope. Hashing a document with its envelope still inside
// produces a hash nothing will ever match, and the symptom is an unexplained
// payload_mismatch.
func DocumentPayloadHash(document Document) (string, error) {
	return CanonicalValueHash(DocumentPayload(document))
}

// SignatureSigningInput is §4.1 -- the envelope minus signature, which is what
// actually gets signed.
func SignatureSigningInput(envelope map[string]any) map[string]any {
	input := make(map[string]any, len(envelope))
	for k, v := range envelope {
		if k != "signature" {
			input[k] = v
		}
	}
	return input
}

// SignatureSigningBytes is the exact byte string the signer signs. Exported
// because when three languages disagree, the first question is whether they
// disagreed about the bytes or about the key.
func SignatureSigningBytes(envelope map[string]any) ([]byte, error) {
	canonical, err := CanonicalizeValue(SignatureSigningInput(envelope))
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

// SignDocumentParams carries the signing inputs. Kid, Issuer and ExpiresAt are
// optional; SignedAt zero means now.
type SignDocumentParams struct {
	Document   Document
	PrivateJWK JWK
	// Kid defaults to the JWK's own kid, then to its RFC 7638 thumbprint.
	Kid string
	// Issuer defaults to the document's catalog_id.
	Issuer    string
	SignedAt  time.Time
	ExpiresAt time.Time
}

// SignDocument returns a copy of the document carrying its envelope (§4.1).
//
// Refuses to sign when Issuer disagrees with the document's catalog_id: every
// verifier runs §7 step 4 and rejects that combination, so emitting one would
// only move the failure from the node that can fix it to the consumer who
// cannot.
//
// Re-signing an already-signed document replaces the envelope, and the old
// envelope does not enter the new payload hash.
func SignDocument(p SignDocumentParams) (Document, error) {
	kid := p.Kid
	if kid == "" {
		if own, ok := p.PrivateJWK["kid"].(string); ok && own != "" {
			kid = own
		} else {
			thumbprint, err := JWKThumbprint(PublicJWKOf(p.PrivateJWK))
			if err != nil {
				return nil, err
			}
			kid = thumbprint
		}
	}

	catalogID, hasCatalogID := p.Document["catalog_id"].(string)
	issuer := p.Issuer
	if issuer == "" {
		if !hasCatalogID {
			return nil, errf("issuer_mismatch", "document has no \"catalog_id\" member, so Issuer must be supplied explicitly")
		}
		issuer = catalogID
	}
	if hasCatalogID && catalogID != issuer {
		return nil, errf("issuer_mismatch",
			"refusing to sign: issuer %q does not match the document's catalog_id %q", issuer, catalogID)
	}

	signedAt := p.SignedAt
	if signedAt.IsZero() {
		signedAt = time.Now()
	}

	payload := DocumentPayload(p.Document)
	payloadHash, err := CanonicalValueHash(payload)
	if err != nil {
		return nil, err
	}

	unsigned := map[string]any{
		"alg":          SignatureAlg,
		"kid":          kid,
		"issuer":       issuer,
		"signed_at":    RFC3339(signedAt),
		"payload_hash": payloadHash,
	}
	if !p.ExpiresAt.IsZero() {
		unsigned["expires_at"] = RFC3339(p.ExpiresAt)
	}

	message, err := SignatureSigningBytes(unsigned)
	if err != nil {
		return nil, err
	}
	privateKey, err := PrivateKeyFromJWK(p.PrivateJWK)
	if err != nil {
		return nil, err
	}

	envelope := make(map[string]any, len(unsigned)+1)
	for k, v := range unsigned {
		envelope[k] = v
	}
	envelope["signature"] = Base64URL(ed25519.Sign(privateKey, message))

	signed := payload
	signed[SignatureMember] = envelope
	return signed, nil
}

// ---------------------------------------------------------------------------
// Key resolution
// ---------------------------------------------------------------------------

// DocumentKeyResolver returns the public key a document was signed with.
// Injected rather than fetched, for the same reason the attribution resolver
// is: a verifier that reaches for the network on its own cannot be tested
// offline, and offline verification is the property signing exists to provide.
type DocumentKeyResolver func(issuer, kid string) (JWK, error)

// SelectVerificationKey picks the key with this kid out of a JWKS document.
//
// Reports key_not_found both when the kid is absent and when no key set is in
// hand at all. The two are not distinguished here -- a caller that needs the
// distinction must check before calling, because the fix for one is a dispute
// and the fix for the other is a configuration flag.
func SelectVerificationKey(jwks any, kid, owner string) (JWK, error) {
	set, ok := jwks.(map[string]any)
	if !ok {
		return nil, errf("key_not_found", "no JWKS on hand for catalog %q", owner)
	}
	keys, ok := set["keys"].([]any)
	if !ok {
		return nil, errf("key_not_found", "no JWKS on hand for catalog %q", owner)
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
	return nil, errf("key_not_found", "kid %q is not in the JWKS of %q", kid, owner)
}

// StaticDocumentKeyResolver resolves from key sets already in hand -- the
// offline path, one JWKS per catalog_id.
func StaticDocumentKeyResolver(jwksByCatalogID map[string]any) DocumentKeyResolver {
	return func(issuer, kid string) (JWK, error) {
		return SelectVerificationKey(jwksByCatalogID[issuer], kid, issuer)
	}
}

// ---------------------------------------------------------------------------
// §7 -- verification
// ---------------------------------------------------------------------------

// SignatureVerdict is the outcome of running §7 over one document. A rejection
// is data rather than an error return: "this is not signed" and "this was
// tampered with" are both answers a caller has to record and act on, and §9
// turns each into a different trust ceiling.
type SignatureVerdict struct {
	OK          bool
	Err         *Error
	Issuer      string
	Kid         string
	Alg         string
	SignedAt    string
	ExpiresAt   string
	PayloadHash string
}

// VerifyDocumentOptions carries the §7 parameters that depend on the caller.
type VerifyDocumentOptions struct {
	// At is the moment to judge expires_at at. Zero means now.
	At time.Time
	// ExpectedIssuer is the catalog_id the verifier expects this document to
	// belong to. Required for a document with no catalog_id member; optional
	// otherwise, where it pins the document to a node the verifier already had
	// in mind (§4.4) -- a manifest correctly signed by somebody else is still
	// the wrong manifest. Empty means not supplied.
	ExpectedIssuer string
}

func rejectSignature(code, message string) SignatureVerdict {
	return SignatureVerdict{OK: false, Err: &Error{Code: code, Message: message}}
}

// parseInstant parses an RFC 3339 timestamp, reporting whether it is usable.
func parseInstant(value any) (time.Time, bool) {
	text, ok := value.(string)
	if !ok {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// envelopeReason is §7 step 2 -- envelope shape. Returns the reason it is
// malformed, or "".
//
// Unknown fields are rejected (§5.1): the envelope *is* the signed material,
// so a field this verifier does not recognise still entered the signature and
// still went unchecked.
//
// alg's *value* is deliberately not checked here -- that is step 3 and it has
// its own code. This only asserts it is a non-empty string.
func envelopeReason(envelope map[string]any) string {
	for field := range envelope {
		if !envelopeFields[field] {
			return fmt.Sprintf("unknown field %q", field)
		}
	}
	for _, field := range requiredEnvelopeFields {
		value, ok := envelope[field].(string)
		if !ok || value == "" {
			return fmt.Sprintf("%q is missing or not a non-empty string", field)
		}
	}
	if _, ok := parseInstant(envelope["signed_at"]); !ok {
		return "\"signed_at\" is not an RFC 3339 instant"
	}
	if raw, present := envelope["expires_at"]; present {
		if _, ok := parseInstant(raw); !ok {
			return "\"expires_at\" is not an RFC 3339 instant"
		}
	}
	if !payloadHashPattern.MatchString(envelope["payload_hash"].(string)) {
		return "\"payload_hash\" is not sha256:<64 lowercase hex>"
	}
	if !base64URLPattern.MatchString(envelope["signature"].(string)) {
		return "\"signature\" is not unpadded base64url"
	}
	return ""
}

// VerifyDocumentSignature runs §7's eight steps in order, stopping at the
// first failure.
//
// The error return is reserved for failures that are *not* verdicts about the
// document: a canonicalization failure, and key-material failures where the
// key set is unreachable, stale or malformed. A node whose key server is down
// has not forged anything, and recording its outage as key_not_found would
// degrade it as though it had (§7.3).
func VerifyDocumentSignature(document any, resolveKey DocumentKeyResolver, opts VerifyDocumentOptions) (SignatureVerdict, error) {
	at := opts.At
	if at.IsZero() {
		at = time.Now()
	}

	// Step 1 -- is there an envelope at all.
	carrier, ok := document.(map[string]any)
	if !ok {
		return rejectSignature("unsigned", "document is not a JSON object, so it carries no signature"), nil
	}
	raw, present := carrier[SignatureMember]
	if !present || raw == nil {
		return rejectSignature("unsigned", "document has no \"signature\" member"), nil
	}

	// Step 2 -- envelope shape.
	envelope, ok := raw.(map[string]any)
	if !ok {
		return rejectSignature("envelope_malformed", "\"signature\" is not an object"), nil
	}
	if reason := envelopeReason(envelope); reason != "" {
		return rejectSignature("envelope_malformed", reason), nil
	}

	// Step 3 -- algorithm, read from inside the signed material, never guessed.
	alg := envelope["alg"].(string)
	if alg != SignatureAlg {
		return rejectSignature("alg_not_supported", fmt.Sprintf("alg is %q, expected %q", alg, SignatureAlg)), nil
	}

	// Step 4 -- issuer. A string comparison, run before spending a
	// whole-document canonicalization on a manifest hanging off the wrong name.
	issuer := envelope["issuer"].(string)
	catalogID, hasCatalogID := carrier["catalog_id"].(string)
	switch {
	case hasCatalogID:
		if catalogID != issuer {
			return rejectSignature("issuer_mismatch",
				fmt.Sprintf("envelope issuer is %q, document catalog_id is %q", issuer, catalogID)), nil
		}
	case opts.ExpectedIssuer == "":
		// Not skipped silently: a §4.4 check that quietly does not run is worse
		// than one that fails loudly, because the verdict still reads OK.
		return rejectSignature("issuer_mismatch",
			"document has no \"catalog_id\" member and no ExpectedIssuer was supplied, so the issuer cannot be checked"), nil
	}
	if opts.ExpectedIssuer != "" && issuer != opts.ExpectedIssuer {
		return rejectSignature("issuer_mismatch",
			fmt.Sprintf("envelope issuer is %q, expected %q", issuer, opts.ExpectedIssuer)), nil
	}

	// Step 5 -- recompute the payload hash. Before the key lookup, so no
	// arbitrary document can drive this verifier into making a network request.
	recomputed, err := DocumentPayloadHash(carrier)
	if err != nil {
		return SignatureVerdict{}, err
	}
	claimed := envelope["payload_hash"].(string)
	if recomputed != claimed {
		return rejectSignature("payload_mismatch", fmt.Sprintf(
			"payload hashes to %s, envelope claims %s -- the document was altered after signing",
			recomputed, claimed)), nil
	}

	// Step 6 -- the key.
	kid := envelope["kid"].(string)
	jwk, err := resolveKey(issuer, kid)
	if err != nil {
		switch CodeOf(err) {
		// A key we cannot verify with is a key we did not find, the same
		// reading attribution §7.1 row 4 takes.
		case "key_not_found", "invalid_key":
			return rejectSignature("key_not_found", err.Error()), nil
		case "alg_not_supported":
			return rejectSignature("alg_not_supported", err.Error()), nil
		}
		return SignatureVerdict{}, err // jwks_unavailable / _expired / _malformed -- not a verdict.
	}
	publicKey, err := AssertEd25519PublicJWK(jwk, "JWK")
	if err != nil {
		return SignatureVerdict{}, err
	}

	// Step 7 -- the signature itself.
	message, err := SignatureSigningBytes(envelope)
	if err != nil {
		return SignatureVerdict{}, err
	}
	sig, decodeErr := DecodeBase64URL(envelope["signature"].(string), "signature")
	// A malformed signature is a mismatch, not a configuration error.
	if decodeErr != nil || !ed25519.Verify(publicKey, message, sig) {
		return rejectSignature("signature_invalid", fmt.Sprintf(
			"envelope does not verify under kid %q of %q -- the envelope was altered, or this is not that node's signature",
			kid, issuer)), nil
	}

	// Step 8 -- expiry, last: an expired-but-genuine signature and a forgery
	// are different findings, and checking this earlier would report the
	// forgery as the milder one.
	expiresAt, _ := envelope["expires_at"].(string)
	if expiresAt != "" {
		deadline, _ := parseInstant(expiresAt)
		if at.After(deadline) {
			return rejectSignature("signature_expired", fmt.Sprintf(
				"signature expired at %s, checked at %s", expiresAt, RFC3339(at))), nil
		}
	}

	return SignatureVerdict{
		OK:          true,
		Issuer:      issuer,
		Kid:         kid,
		Alg:         SignatureAlg,
		SignedAt:    envelope["signed_at"].(string),
		ExpiresAt:   expiresAt,
		PayloadHash: recomputed,
	}, nil
}

// TrustCeiling is §9's answer: the highest tier a verification result allows,
// and whether anything cached under a better tier must be dropped.
type TrustCeiling struct {
	TrustTier        string
	InvalidatesCache bool
}

// TrustCeilingFor is §9 -- a ceiling, not a verdict. A passing signature only
// unlocks "verified"; it does not assert the manifest's contents are true
// (§7.2).
func TrustCeilingFor(v SignatureVerdict) TrustCeiling {
	if v.OK {
		return TrustCeiling{TrustTier: "verified", InvalidatesCache: false}
	}
	// Neither of these is evidence that anything was altered: one node has not
	// started signing, the other forgot to re-sign. Dropping their caches would
	// punish an absence of proof as though it were proof of tampering.
	if v.Err != nil && (v.Err.Code == "unsigned" || v.Err.Code == "signature_expired") {
		return TrustCeiling{TrustTier: "unverified", InvalidatesCache: false}
	}
	return TrustCeiling{TrustTier: "unknown", InvalidatesCache: true}
}
