// Package ocpcrypto implements OCP Canonical JSON v1.0 ("OCP-JCS v1") and
// attribution chain verification, using only the Go standard library.
//
// Spec: docs/specs/crypto/canonicalization.md. Conformance vectors:
// packages/ocp-crypto/fixtures/canonical/ (75 of them; canonical_test.go runs
// every one). This is a port of packages/ocp-crypto/src/canonical.ts and must
// stay byte-identical to it -- that is the whole point of having it.
//
// Four things here are load-bearing, and three are Go-specific traps the
// fixture README calls out by name:
//
//  1. It has its own JSON parser. encoding/json resolves duplicate members
//     last-one-wins (spec §5.4), so by the time you hold the decoded value
//     {"amount":1,"amount":9999} has already become {"amount":9999} and the
//     signature bypass is invisible.
//  2. Number admission is decided on the decimal literal, never on a float.
//     encoding/json decodes every number into float64 unless you remember
//     Decoder.UseNumber, and by then the literal is gone. See
//     canonicalNumberLiteral.
//  3. Member sorting uses UTF-16 code-unit order (§5.2). sort.Strings compares
//     UTF-8 bytes, which disagrees outside the BMP: U+FFFF sorts before
//     U+10000 by UTF-8 byte and after it by UTF-16 code unit. sortKey encodes
//     to UTF-16 first.
//  4. Escaping is minimal (§6.1). encoding/json escapes <, > and & by default
//     for HTML safety; this emits them raw, along with all non-ASCII.
package ocpcrypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Error is a canonicalization or verification failure carrying one of the
// spec's stable codes. The code is the cross-language contract -- the rejection
// vectors assert on it, so it is wire behaviour and not a debugging detail.
type Error struct {
	Code    string
	Message string
	// Hop is the 1-based chain position a verification failure localises to,
	// or 0 when the failure is not about one hop.
	Hop int
}

func (e *Error) Error() string {
	if e.Hop > 0 {
		return fmt.Sprintf("[%s] hop %d: %s", e.Code, e.Hop, e.Message)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// CodeOf returns the stable error code of err, or "" if it carries none.
func CodeOf(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

// ---------------------------------------------------------------------------
// Numbers (spec §7, Level 1)
// ---------------------------------------------------------------------------

// maxSafeDecimal is 2^53 - 1 as a decimal string. Range checks compare digits,
// not floats.
const maxSafeDecimal = "9007199254740991"

// exponentClamp bounds a parsed exponent so the scale arithmetic below cannot
// overflow int. Any exponent past it is already far outside 2^53, so clamping
// changes no verdict -- it only keeps 1e999999999999999999999 from being a
// parsing problem instead of a range one.
//
// Deliberately small enough to be an int on a 32-bit build: this package is
// built for GOARCH=386 too, where int is 32 bits and a 1<<40 constant does not
// compile.
const exponentClamp = 1 << 20

// canonicalNumberLiteral admits a JSON number literal under Level 1 and returns
// its canonical form.
//
// The judgement is made on the literal's exact decimal value, not on its float64
// rounding. Spec §7.2 normatively says "its mathematical value is an integer";
// a float test only agrees with that when the literal carries no more precision
// than a double. 9007199254740991.0000000000001 is the counterexample: it
// rounds to an exact integer, so the float test accepts it and emits
// 9007199254740991 -- signing a value that is not the one on the wire.
//
// Working on digits also keeps the two rejection codes distinct. 1e400 is
// number_out_of_range (magnitude), 0.5 is non_integer_number (shape); a float
// path collapses the first into +Inf and has to special-case its way back out.
func canonicalNumberLiteral(literal string) (string, error) {
	negative, intPart, fracPart, expPart, ok := splitNumber(literal)
	if !ok {
		return "", errf("malformed_json", "not a JSON number: %s", literal)
	}

	exponent := 0
	if expPart != "" {
		exponent = parseExponent(expPart)
	}

	digits := strings.TrimLeft(intPart+fracPart, "0")
	if digits == "" {
		digits = "0"
	}
	scale := len(fracPart) - exponent

	if digits == "0" {
		return "0", nil // also covers -0 and -0.0 (spec §7.2)
	}

	var integerDigits string
	switch {
	case scale <= 0:
		// Trailing zeros to append. Check the resulting magnitude before
		// building the string, or 1e999999999 becomes an allocation bomb.
		if len(digits)-scale > len(maxSafeDecimal) {
			return "", errf("number_out_of_range", "|%s| exceeds 2^53-1", literal)
		}
		integerDigits = digits + strings.Repeat("0", -scale)
	case scale >= len(digits):
		// Non-zero with magnitude < 1.
		return "", errf("non_integer_number", "%s is not an integer", literal)
	default:
		if strings.Trim(digits[len(digits)-scale:], "0") != "" {
			return "", errf("non_integer_number", "%s is not an integer", literal)
		}
		integerDigits = digits[:len(digits)-scale]
	}

	if len(integerDigits) > len(maxSafeDecimal) ||
		(len(integerDigits) == len(maxSafeDecimal) && integerDigits > maxSafeDecimal) {
		return "", errf("number_out_of_range", "|%s| exceeds 2^53-1", literal)
	}

	if negative {
		return "-" + integerDigits, nil
	}
	return integerDigits, nil
}

// splitNumber is the regexp ^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$ written
// out, so this package needs no regexp import and no per-call compilation.
func splitNumber(s string) (negative bool, intPart, fracPart, expPart string, ok bool) {
	i := 0
	if i < len(s) && s[i] == '-' {
		negative = true
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start {
		return false, "", "", "", false
	}
	intPart = s[start:i]

	if i < len(s) && s[i] == '.' {
		i++
		start = i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == start {
			return false, "", "", "", false
		}
		fracPart = s[start:i]
	}

	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		start = i
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		digitsStart := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == digitsStart {
			return false, "", "", "", false
		}
		expPart = s[start:i]
	}

	return negative, intPart, fracPart, expPart, i == len(s)
}

func parseExponent(s string) int {
	sign := 1
	if s[0] == '+' {
		s = s[1:]
	} else if s[0] == '-' {
		sign = -1
		s = s[1:]
	}
	s = strings.TrimLeft(s, "0")
	value := 0
	for _, c := range []byte(s) {
		// Checked every digit, so value stays under 10*exponentClamp and the
		// multiply cannot overflow even a 32-bit int.
		if value > exponentClamp {
			return sign * exponentClamp
		}
		value = value*10 + int(c-'0')
	}
	if value > exponentClamp {
		return sign * exponentClamp
	}
	return sign * value
}

// ---------------------------------------------------------------------------
// Parsing (spec §4.1 stage 1 + stage 2, fused only where the spec requires it)
// ---------------------------------------------------------------------------

type nodeKind int

const (
	kindObject nodeKind = iota
	kindArray
	kindString
	kindNumber
	kindBool
	kindNull
)

type member struct {
	key string
	// sortKey is the key's UTF-16 big-endian form, precomputed because sorting
	// touches it O(n log n) times. See the package comment, trap 3.
	sortKey string
	value   *node
}

type node struct {
	kind    nodeKind
	members []member
	items   []*node
	text    string // decoded string, or the canonical number literal
	boolean bool
}

type parser struct {
	s []rune
	i int
}

func parseTopLevel(text string) (*node, error) {
	p := &parser{s: []rune(text)}
	p.ws()
	// Checked before parsing so error precedence is deterministic: a non-object
	// top level reports top_level_not_object regardless of what else is wrong
	// further in. Without this, [1,NaN] would report non_finite_number here and
	// top_level_not_object in an implementation that checked shape first.
	if p.peek() != '{' {
		return nil, errf("top_level_not_object", "canonicalization input must be a JSON object")
	}
	n, err := p.value()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, errf("malformed_json", "trailing content after top-level value")
	}
	return n, nil
}

func (p *parser) peek() rune {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) bad(what string) error {
	return errf("malformed_json", "%s at offset %d", what, p.i)
}

func (p *parser) literal(word string) error {
	runes := []rune(word)
	if p.i+len(runes) > len(p.s) || string(p.s[p.i:p.i+len(runes)]) != word {
		return p.bad("expected " + word)
	}
	p.i += len(runes)
	return nil
}

func (p *parser) startsWith(word string) bool {
	runes := []rune(word)
	return p.i+len(runes) <= len(p.s) && string(p.s[p.i:p.i+len(runes)]) == word
}

func (p *parser) value() (*node, error) {
	switch c := p.peek(); {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &node{kind: kindString, text: s}, nil
	case c == 't':
		if err := p.literal("true"); err != nil {
			return nil, err
		}
		return &node{kind: kindBool, boolean: true}, nil
	case c == 'f':
		if err := p.literal("false"); err != nil {
			return nil, err
		}
		return &node{kind: kindBool}, nil
	case c == 'n':
		if err := p.literal("null"); err != nil {
			return nil, err
		}
		return &node{kind: kindNull}, nil
	// NaN / Infinity are not JSON, but several standard libraries emit or
	// accept them (§7.5), so they do show up on the wire. They get their own
	// code rather than being lumped in with syntax errors.
	case c == 'N' && p.startsWith("NaN"):
		return nil, errf("non_finite_number", "NaN is not a permitted value")
	case c == 'I' && p.startsWith("Infinity"):
		return nil, errf("non_finite_number", "Infinity is not a permitted value")
	case c == '-' && p.startsWith("-Infinity"):
		return nil, errf("non_finite_number", "-Infinity is not a permitted value")
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.bad("unexpected token")
	}
}

func (p *parser) number() (*node, error) {
	start := p.i
	if p.peek() == '-' {
		p.i++
	}
	for p.i < len(p.s) && ((p.s[p.i] >= '0' && p.s[p.i] <= '9') || p.s[p.i] == '.' ||
		p.s[p.i] == 'e' || p.s[p.i] == 'E' || p.s[p.i] == '+' || p.s[p.i] == '-') {
		p.i++
	}
	token := string(p.s[start:p.i])
	// Leading zeros are not JSON, and splitNumber accepts them, so reject here.
	if len(token) > 1 {
		unsigned := strings.TrimPrefix(token, "-")
		if len(unsigned) > 1 && unsigned[0] == '0' && unsigned[1] != '.' && unsigned[1] != 'e' && unsigned[1] != 'E' {
			return nil, p.bad("invalid number")
		}
	}
	// Admission happens here, at parse time, so the literal is still available.
	// Canonicalizing from a decoded float64 would have lost it.
	canonical, err := canonicalNumberLiteral(token)
	if err != nil {
		return nil, err
	}
	return &node{kind: kindNumber, text: canonical}, nil
}

func (p *parser) hex4() (int, error) {
	if p.i+4 > len(p.s) {
		return 0, p.bad(`invalid \u escape`)
	}
	value := 0
	for k := 0; k < 4; k++ {
		c := p.s[p.i+k]
		switch {
		case c >= '0' && c <= '9':
			value = value*16 + int(c-'0')
		case c >= 'a' && c <= 'f':
			value = value*16 + int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			value = value*16 + int(c-'A') + 10
		default:
			return 0, p.bad(`invalid \u escape`)
		}
	}
	p.i += 4
	return value, nil
}

// str returns the decoded string. Surrogate pairing is validated here (§6.4).
func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var out strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", p.bad("unterminated string")
		}
		c := p.s[p.i]

		if c == '"' {
			p.i++
			return out.String(), nil
		}

		if c == '\\' {
			p.i++
			if p.i >= len(p.s) {
				return "", p.bad(`invalid escape \<eof>`)
			}
			esc := p.s[p.i]
			switch esc {
			case '"', '\\', '/':
				out.WriteRune(esc)
				p.i++
			case 'b':
				out.WriteByte('\b')
				p.i++
			case 'f':
				out.WriteByte('\f')
				p.i++
			case 'n':
				out.WriteByte('\n')
				p.i++
			case 'r':
				out.WriteByte('\r')
				p.i++
			case 't':
				out.WriteByte('\t')
				p.i++
			case 'u':
				p.i++
				unit, err := p.hex4()
				if err != nil {
					return "", err
				}
				switch {
				case unit >= 0xD800 && unit <= 0xDBFF:
					if !p.startsWith(`\u`) {
						return "", errf("lone_surrogate", "high surrogate without a following low surrogate")
					}
					p.i += 2
					low, err := p.hex4()
					if err != nil {
						return "", err
					}
					if low < 0xDC00 || low > 0xDFFF {
						return "", errf("lone_surrogate", "high surrogate followed by a non-low-surrogate unit")
					}
					out.WriteRune(utf16.DecodeRune(rune(unit), rune(low)))
				case unit >= 0xDC00 && unit <= 0xDFFF:
					return "", errf("lone_surrogate", "low surrogate without a preceding high surrogate")
				default:
					out.WriteRune(rune(unit))
				}
			default:
				return "", p.bad(fmt.Sprintf(`invalid escape \%c`, esc))
			}
			continue
		}

		if c < 0x20 {
			return "", p.bad("unescaped control character in string")
		}
		// No raw-surrogate branch here, unlike the TypeScript and Python ports:
		// Canonicalize rejects invalid UTF-8 up front, and UTF-8 cannot encode a
		// surrogate, so by this point a literal lone surrogate is unreachable.
		// Checking for utf8.RuneError instead would reject a legitimate U+FFFD,
		// which the key-order-astral-vs-fffd vector requires be accepted.

		out.WriteRune(c)
		p.i++
	}
}

func (p *parser) object() (*node, error) {
	p.i++ // '{'
	n := &node{kind: kindObject}
	seen := map[string]struct{}{}
	p.ws()
	if p.peek() == '}' {
		p.i++
		return n, nil
	}
	for {
		p.ws()
		if p.peek() != '"' {
			return nil, p.bad("object member name must be a string")
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		// Compared after decoding, so "a" and "a" collide (§5.4).
		if _, dup := seen[key]; dup {
			return nil, errf("duplicate_key", "duplicate member name %q", key)
		}
		seen[key] = struct{}{}
		p.ws()
		if p.peek() != ':' {
			return nil, p.bad("expected ':'")
		}
		p.i++
		p.ws()
		value, err := p.value()
		if err != nil {
			return nil, err
		}
		n.members = append(n.members, member{key: key, sortKey: sortKey(key), value: value})
		p.ws()
		switch p.peek() {
		case ',':
			p.i++
		case '}':
			p.i++
			return n, nil
		default:
			return nil, p.bad("expected ',' or '}'")
		}
	}
}

func (p *parser) array() (*node, error) {
	p.i++ // '['
	n := &node{kind: kindArray}
	p.ws()
	if p.peek() == ']' {
		p.i++
		return n, nil
	}
	for {
		p.ws()
		item, err := p.value()
		if err != nil {
			return nil, err
		}
		n.items = append(n.items, item)
		p.ws()
		switch p.peek() {
		case ',':
			p.i++
		case ']':
			p.i++
			return n, nil
		default:
			return nil, p.bad("expected ',' or ']'")
		}
	}
}

// ---------------------------------------------------------------------------
// Serialization (spec §5, §6, §8)
// ---------------------------------------------------------------------------

// sortKey returns the key's UTF-16 big-endian bytes as a string.
//
// Big-endian UTF-16 bytes compare exactly as code units do, and folding an
// astral rune back into its surrogate pair is what makes this differ from
// comparing the UTF-8 string directly -- which is the bug this exists to avoid.
func sortKey(key string) string {
	units := utf16.Encode([]rune(key))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u>>8), byte(u))
	}
	return string(b)
}

// encodeString applies minimal escaping (§6.1). Everything outside the table is
// emitted as-is, including /, <, >, & and all non-ASCII -- those are the three
// language-default traps in §6.3, and encoding/json falls into two of them.
func encodeString(s string, out *strings.Builder) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r) // lowercase hex (§6.1)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

func serialize(n *node, out *strings.Builder) {
	switch n.kind {
	case kindObject:
		// Sorted per level, independently of the parent (§5.1).
		members := make([]member, len(n.members))
		copy(members, n.members)
		sort.Slice(members, func(i, j int) bool { return members[i].sortKey < members[j].sortKey })
		out.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				out.WriteByte(',')
			}
			encodeString(m.key, out)
			out.WriteByte(':')
			serialize(m.value, out)
		}
		out.WriteByte('}')
	case kindArray:
		// Order preserved, no dedupe -- array order is semantics (§8.4).
		out.WriteByte('[')
		for i, item := range n.items {
			if i > 0 {
				out.WriteByte(',')
			}
			serialize(item, out)
		}
		out.WriteByte(']')
	case kindString:
		encodeString(n.text, out)
	case kindNumber:
		out.WriteString(n.text)
	case kindBool:
		if n.boolean {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case kindNull:
		out.WriteString("null") // never dropped (§8.1)
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Canonicalize canonicalizes JSON wire bytes per OCP-JCS v1.
//
// Feed this the bytes as received. Do not decode them first: spec §9.1 -- a
// schema validator injects defaulted members, and a signer that canonicalizes
// post-decode while a verifier canonicalizes pre-decode fails every single
// time, for reasons that look like a key problem.
func Canonicalize(data []byte) (string, error) {
	if !utf8.Valid(data) {
		return "", errf("malformed_json", "input is not valid UTF-8")
	}
	n, err := parseTopLevel(string(data))
	if err != nil {
		return "", err
	}
	var out strings.Builder
	serialize(n, &out)
	return out.String(), nil
}

// CanonicalHash returns sha256:{64 lowercase hex} over the canonical bytes (§10).
func CanonicalHash(data []byte) (string, error) {
	canonical, err := Canonicalize(data)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
