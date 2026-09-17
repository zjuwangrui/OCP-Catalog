package ocpcrypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// CanonicalizeValue canonicalizes an in-memory value under the same admission
// rules as Canonicalize.
//
// Used by the signing side, which builds an object rather than receiving bytes.
// Deliberately not implemented as Canonicalize(json.Marshal(v)): encoding/json
// escapes <, > and & by default and refuses NaN outright with a message that
// has no stable code, both of which lose information §2.2 says must not be lost
// silently.
//
// Accepted: map[string]any, []any, string, bool, nil, json.Number, and the
// numeric types. Decode wire JSON with a Decoder in UseNumber mode before
// passing it here -- a float64 that has already rounded cannot be un-rounded,
// and §7.2's admission test is about the literal.
func CanonicalizeValue(value any) (string, error) {
	n, err := toNode(value, "$")
	if err != nil {
		return "", err
	}
	if n.kind != kindObject {
		return "", errf("top_level_not_object", "canonicalization input must be a JSON object")
	}
	var out strings.Builder
	serialize(n, &out)
	return out.String(), nil
}

// CanonicalValueHash returns sha256:{64 lowercase hex} over CanonicalizeValue.
func CanonicalValueHash(value any) (string, error) {
	canonical, err := CanonicalizeValue(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func toNode(value any, path string) (*node, error) {
	switch v := value.(type) {
	case nil:
		return &node{kind: kindNull}, nil
	case bool:
		return &node{kind: kindBool, boolean: v}, nil
	case string:
		return &node{kind: kindString, text: v}, nil
	case json.Number:
		literal, err := canonicalNumberLiteral(v.String())
		if err != nil {
			return nil, err
		}
		return &node{kind: kindNumber, text: literal}, nil
	case float64:
		return floatNode(v, path)
	case float32:
		return floatNode(float64(v), path)
	case int:
		return intNode(int64(v), path)
	case int64:
		return intNode(v, path)
	case []any:
		items := make([]*node, 0, len(v))
		for i, item := range v {
			child, err := toNode(item, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			items = append(items, child)
		}
		return &node{kind: kindArray, items: items}, nil
	case map[string]any:
		members := make([]member, 0, len(v))
		for key, item := range v {
			child, err := toNode(item, path+"."+key)
			if err != nil {
				return nil, err
			}
			members = append(members, member{key: key, sortKey: sortKey(key), value: child})
		}
		return &node{kind: kindObject, members: members}, nil
	default:
		// Refused rather than coerced: changing a member's type changes the
		// signed value (§8.2).
		return nil, errf("unsupported_value", "%s has non-JSON type %T", path, value)
	}
}

func floatNode(v float64, path string) (*node, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, errf("non_finite_number", "%s is %v", path, v)
	}
	if v != math.Trunc(v) {
		return nil, errf("non_integer_number", "%s = %v is not an integer", path, v)
	}
	return intNode(int64(v), path)
}

func intNode(v int64, path string) (*node, error) {
	const maxSafe = 9007199254740991
	if v > maxSafe || v < -maxSafe {
		return nil, errf("number_out_of_range", "%s = %d exceeds 2^53-1", path, v)
	}
	return &node{kind: kindNumber, text: fmt.Sprintf("%d", v)}, nil
}
