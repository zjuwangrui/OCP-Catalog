"""OCP Canonical JSON v1.0 -- "OCP-JCS v1", Python standard library only.

Spec: `docs/specs/crypto/canonicalization.md`. Conformance vectors:
`packages/ocp-crypto/fixtures/canonical/` (75 of them; `canonical_test.py` runs
every one). This is a port of `packages/ocp-crypto/src/canonical.ts` and must
stay byte-identical to it -- that is the whole point of having it.

Four things here are load-bearing, and three of them are Python-specific traps
the fixture README calls out by name:

1. **It has its own JSON parser.** `json.loads` resolves duplicate members
   last-one-wins (spec §5.4), so by the time you hold the parsed value
   `{"amount":1,"amount":9999}` has already become `{"amount":9999}` and the
   signature bypass is invisible. `object_pairs_hook` can see the duplicates,
   but `json.loads` also accepts `NaN` / `Infinity` by default (§7.5), needs
   `parse_constant` to stop, and hands back floats for every number -- so the
   literal is gone before admission can be decided on it. Parsing here costs
   less than patching four hooks onto a parser that is wrong by default.
2. **Number admission is decided on the decimal literal, never on a float.**
   See `canonical_number_literal`.
3. **Member sorting uses UTF-16 code-unit order (§5.2).** Python's `<` on `str`
   compares *code points*, which disagrees with UTF-16 outside the BMP: U+FFFF
   sorts after U+10000 by code point and before it by code unit. `sort_key`
   encodes to UTF-16 big-endian first, where a byte comparison is exactly a
   code-unit comparison.
4. **Escaping is minimal (§6.1).** No `\\uXXXX` for non-ASCII, no escaping of
   `/`, `<`, `>`, `&`. `json.dumps` defaults to `ensure_ascii=True` and would
   get every non-ASCII vector wrong.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Any, Union

__all__ = [
    "CanonicalError",
    "canonical_number_literal",
    "canonicalize",
    "canonicalize_to_bytes",
    "canonical_hash",
    "canonicalize_value",
    "canonicalize_value_to_bytes",
    "canonical_value_hash",
]


class CanonicalError(Exception):
    """A canonicalization failure carrying one of the spec's stable codes.

    The code is the cross-language contract -- the rejection vectors assert on
    it, so it is part of the wire behaviour and not a debugging detail.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Numbers (spec §7, Level 1)
# ---------------------------------------------------------------------------

#: 2^53 - 1, as a decimal string. Range checks compare digits, not floats.
MAX_SAFE_DECIMAL = "9007199254740991"

_NUMBER_PARTS = re.compile(r"^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$")


def canonical_number_literal(literal: str) -> str:
    """Admit a JSON number literal under Level 1 and return its canonical form.

    The judgement is made on the literal's exact decimal value, not on
    `float(literal)`. Spec §7.2 normatively says "its mathematical value is an
    integer"; `float.is_integer()` only agrees with that when the literal
    carries no more precision than a double. `9007199254740991.0000000000001`
    is the counterexample: it rounds to an exact integer, so the float test
    accepts it and emits `9007199254740991` -- signing a value that is not the
    one on the wire.

    Working on digits also keeps the two rejection codes distinct. `1e400` is
    `number_out_of_range` (magnitude), `0.5` is `non_integer_number` (shape); a
    float path collapses the first into `inf` and has to special-case its way
    back out.
    """
    m = _NUMBER_PARTS.match(literal)
    if not m:
        raise CanonicalError("malformed_json", f"not a JSON number: {literal}")

    negative = m.group(1) == "-"
    frac = m.group(3) or ""
    exponent = int(m.group(4)) if m.group(4) else 0

    # value = digits * 10^(-scale)
    digits = (m.group(2) + frac).lstrip("0") or "0"
    scale = len(frac) - exponent

    if digits == "0":
        return "0"  # also covers -0 and -0.0 (spec §7.2)

    if scale <= 0:
        # Trailing zeros to append. Check the resulting magnitude *before*
        # building the string, or `1e999999999` becomes an allocation bomb --
        # Python ints are unbounded, so nothing else would stop it.
        if len(digits) - scale > len(MAX_SAFE_DECIMAL):
            raise CanonicalError("number_out_of_range", f"|{literal}| exceeds 2^53-1")
        integer_digits = digits + "0" * -scale
    elif scale >= len(digits):
        # Non-zero with magnitude < 1.
        raise CanonicalError("non_integer_number", f"{literal} is not an integer")
    else:
        dropped = digits[len(digits) - scale :]
        if dropped.strip("0"):
            raise CanonicalError("non_integer_number", f"{literal} is not an integer")
        integer_digits = digits[: len(digits) - scale]

    if len(integer_digits) > len(MAX_SAFE_DECIMAL) or (
        len(integer_digits) == len(MAX_SAFE_DECIMAL) and integer_digits > MAX_SAFE_DECIMAL
    ):
        raise CanonicalError("number_out_of_range", f"|{literal}| exceeds 2^53-1")

    return ("-" if negative else "") + integer_digits


# ---------------------------------------------------------------------------
# Parsing (spec §4.1 stage 1 + stage 2, fused only where the spec requires it)
# ---------------------------------------------------------------------------

_NUMBER_TOKEN = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_HEX4 = re.compile(r"^[0-9a-fA-F]{4}$")
_WS = " \t\n\r"

# Parsed tree: ("obj", [(key, node), ...]) | ("arr", [node, ...])
#            | ("str", text) | ("num", literal) | ("bool", value) | ("null", None)
_Node = tuple


class _Parser:
    __slots__ = ("s", "i")

    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0

    @staticmethod
    def parse_top_level(text: str) -> _Node:
        p = _Parser(text)
        p._ws()
        # Checked before parsing so that error precedence is deterministic: a
        # non-object top level reports `top_level_not_object` regardless of what
        # else is wrong further in. Without this, `[1,NaN]` would report
        # `non_finite_number` here and `top_level_not_object` in an
        # implementation that validated the shape first.
        if p._peek() != "{":
            raise CanonicalError("top_level_not_object", "canonicalization input must be a JSON object")
        node = p._value()
        p._ws()
        if p.i != len(p.s):
            raise CanonicalError("malformed_json", "trailing content after top-level value")
        return node

    def _peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def _ws(self) -> None:
        s, n = self.s, len(self.s)
        while self.i < n and s[self.i] in _WS:
            self.i += 1

    def _bad(self, what: str) -> None:
        raise CanonicalError("malformed_json", f"{what} at offset {self.i}")

    def _literal(self, word: str) -> None:
        if self.s.startswith(word, self.i):
            self.i += len(word)
        else:
            self._bad(f"expected {word}")

    def _value(self) -> _Node:
        c = self._peek()
        if c == "{":
            return self._object()
        if c == "[":
            return self._array()
        if c == '"':
            return ("str", self._string())
        if c == "t":
            self._literal("true")
            return ("bool", True)
        if c == "f":
            self._literal("false")
            return ("bool", False)
        if c == "n":
            self._literal("null")
            return ("null", None)
        # NaN / Infinity are not JSON, but `json.loads` accepts them by default
        # (§7.5), so they do show up on the wire. They get their own code rather
        # than being lumped in with syntax errors.
        if c == "N":
            self._literal("NaN")
            raise CanonicalError("non_finite_number", "NaN is not a permitted value")
        if c == "I":
            self._literal("Infinity")
            raise CanonicalError("non_finite_number", "Infinity is not a permitted value")
        if c == "-" and self.s.startswith("-Infinity", self.i):
            raise CanonicalError("non_finite_number", "-Infinity is not a permitted value")
        if c == "-" or (c.isascii() and c.isdigit()):
            return self._number()
        self._bad("unexpected token")
        raise AssertionError("unreachable")

    def _number(self) -> _Node:
        m = _NUMBER_TOKEN.match(self.s, self.i)
        if not m:
            self._bad("invalid number")
        self.i = m.end()
        # Admission happens here, at parse time, so the literal is still
        # available. Canonicalizing from a parsed float would have lost it.
        return ("num", canonical_number_literal(m.group(0)))

    def _hex4(self) -> int:
        hex4 = self.s[self.i : self.i + 4]
        if not _HEX4.match(hex4):
            self._bad("invalid \\u escape")
        self.i += 4
        return int(hex4, 16)

    _SHORT_UNESCAPE = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}

    def _string(self) -> str:
        """Return the decoded string. Surrogate pairing is validated here (§6.4).

        Escaped pairs are folded into one astral code point, because that is the
        form Python holds text in -- and the form `sort_key` needs in order to
        re-derive the UTF-16 units the spec sorts by.
        """
        self.i += 1  # opening quote
        out: list[str] = []
        s = self.s
        while True:
            if self.i >= len(s):
                self._bad("unterminated string")
            ch = s[self.i]

            if ch == '"':
                self.i += 1
                return "".join(out)

            if ch == "\\":
                self.i += 1
                esc = s[self.i] if self.i < len(s) else ""
                simple = self._SHORT_UNESCAPE.get(esc)
                if simple is not None:
                    out.append(simple)
                    self.i += 1
                    continue
                if esc != "u":
                    self._bad(f"invalid escape \\{esc or '<eof>'}")
                self.i += 1
                unit = self._hex4()
                if 0xD800 <= unit <= 0xDBFF:
                    if s[self.i : self.i + 2] != "\\u":
                        raise CanonicalError("lone_surrogate", "high surrogate without a following low surrogate")
                    self.i += 2
                    low = self._hex4()
                    if not (0xDC00 <= low <= 0xDFFF):
                        raise CanonicalError("lone_surrogate", "high surrogate followed by a non-low-surrogate unit")
                    out.append(chr(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)))
                elif 0xDC00 <= unit <= 0xDFFF:
                    raise CanonicalError("lone_surrogate", "low surrogate without a preceding high surrogate")
                else:
                    out.append(chr(unit))
                continue

            cp = ord(ch)
            if cp < 0x20:
                self._bad("unescaped control character in string")

            # Literal (non-escaped) surrogates: unreachable from well-formed
            # UTF-8 bytes, reachable when a caller hands us a `str` directly --
            # which `json.loads` on a fixture file does.
            if 0xD800 <= cp <= 0xDBFF:
                nxt = ord(s[self.i + 1]) if self.i + 1 < len(s) else 0
                if not 0xDC00 <= nxt <= 0xDFFF:
                    raise CanonicalError("lone_surrogate", "unpaired high surrogate")
                out.append(chr(0x10000 + ((cp - 0xD800) << 10) + (nxt - 0xDC00)))
                self.i += 2
                continue
            if 0xDC00 <= cp <= 0xDFFF:
                raise CanonicalError("lone_surrogate", "unpaired low surrogate")

            out.append(ch)
            self.i += 1

    def _object(self) -> _Node:
        self.i += 1  # '{'
        members: list[tuple[str, _Node]] = []
        seen: set[str] = set()
        self._ws()
        if self._peek() == "}":
            self.i += 1
            return ("obj", members)
        while True:
            self._ws()
            if self._peek() != '"':
                self._bad("object member name must be a string")
            key = self._string()
            # Compared after decoding, so `"a"` and `"a"` collide (§5.4).
            if key in seen:
                raise CanonicalError("duplicate_key", f"duplicate member name {key!r}")
            seen.add(key)
            self._ws()
            if self._peek() != ":":
                self._bad("expected ':'")
            self.i += 1
            self._ws()
            members.append((key, self._value()))
            self._ws()
            c = self._peek()
            if c == ",":
                self.i += 1
                continue
            if c == "}":
                self.i += 1
                return ("obj", members)
            self._bad("expected ',' or '}'")

    def _array(self) -> _Node:
        self.i += 1  # '['
        items: list[_Node] = []
        self._ws()
        if self._peek() == "]":
            self.i += 1
            return ("arr", items)
        while True:
            self._ws()
            items.append(self._value())
            self._ws()
            c = self._peek()
            if c == ",":
                self.i += 1
                continue
            if c == "]":
                self.i += 1
                return ("arr", items)
            self._bad("expected ',' or ']'")


# ---------------------------------------------------------------------------
# Serialization (spec §5, §6, §8)
# ---------------------------------------------------------------------------

_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _encode_string(s: str) -> str:
    """Minimal escaping (§6.1).

    Everything outside the table above is emitted as-is, including `/`, `<`,
    `>`, `&` and all non-ASCII -- those are the three language-default traps in
    §6.3, and `json.dumps` falls into two of them.
    """
    out = ['"']
    for ch in s:
        cp = ord(ch)
        short = _SHORT_ESCAPES.get(cp)
        if short is not None:
            out.append(short)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")  # lowercase hex (§6.1)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _sort_key(key: str) -> bytes:
    """UTF-16 code-unit order (§5.2).

    Big-endian UTF-16 bytes compare exactly as code units do, and folding an
    astral code point back into its surrogate pair is what makes this differ
    from Python's native `str` ordering -- which is the bug this function
    exists to avoid.
    """
    return key.encode("utf-16-be", "surrogatepass")


def _serialize(node: _Node) -> str:
    kind, payload = node
    if kind == "obj":
        # Sorted per level, independently of the parent (§5.1).
        members = sorted(payload, key=lambda m: _sort_key(m[0]))
        return "{" + ",".join(f"{_encode_string(k)}:{_serialize(v)}" for k, v in members) + "}"
    if kind == "arr":
        # Order preserved, no dedupe -- array order is semantics (§8.4).
        return "[" + ",".join(_serialize(item) for item in payload) + "]"
    if kind == "str":
        return _encode_string(payload)
    if kind == "num":
        return payload
    if kind == "bool":
        return "true" if payload else "false"
    return "null"  # never dropped (§8.1)


# ---------------------------------------------------------------------------
# Value entry point
# ---------------------------------------------------------------------------


def _to_node(value: Any, path: str) -> _Node:
    """Convert an in-memory value to a node under the same admission rules.

    Used by the signing side, which builds an object rather than receiving
    bytes. Deliberately *not* `canonicalize(json.dumps(value))`: `json.dumps`
    emits `NaN` and `Infinity` as bare tokens and would re-enter through the
    parser as a different error, and `ensure_ascii` would escape every non-ASCII
    character. Both are the "silent correction" §2.2 forbids.
    """
    if value is None:
        return ("null", None)
    # bool before int: `isinstance(True, int)` is True in Python, and a `bool`
    # that fell through to the number branch would be canonicalized as `1`.
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, str):
        return ("str", _assert_no_lone_surrogate(value, path))
    if isinstance(value, int):
        if abs(value) > 9007199254740991:
            raise CanonicalError("number_out_of_range", f"{path} = {value} exceeds 2^53-1")
        return ("num", str(value))
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalError("non_finite_number", f"{path} is {value}")
        if not value.is_integer():
            raise CanonicalError("non_integer_number", f"{path} = {value} is not an integer")
        if abs(value) > 9007199254740991:
            raise CanonicalError("number_out_of_range", f"{path} = {value} exceeds 2^53-1")
        return ("num", str(int(value)))  # `int()` drops the `.0` and the `-0.0` sign
    if isinstance(value, (list, tuple)):
        return ("arr", [_to_node(item, f"{path}[{i}]") for i, item in enumerate(value)])
    if isinstance(value, dict):
        members = []
        for key, member in value.items():
            if not isinstance(key, str):
                raise CanonicalError("unsupported_value", f"{path} has a non-string member name {key!r}")
            members.append((_assert_no_lone_surrogate(key, f"{path}.{key}"), _to_node(member, f"{path}.{key}")))
        return ("obj", members)
    # bytes, Decimal, sets, objects. Refused rather than coerced: changing a
    # member's type changes the signed value (§8.2).
    raise CanonicalError("unsupported_value", f"{path} has non-JSON type {type(value).__name__}")


def _assert_no_lone_surrogate(s: str, path: str) -> str:
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise CanonicalError("lone_surrogate", f"{path} contains an unpaired surrogate")
    return s


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def canonicalize(source: Union[str, bytes, bytearray]) -> str:
    """Canonicalize JSON **wire bytes** (or their decoded text) per OCP-JCS v1.

    Feed this the bytes as received. Do not pre-parse them: spec §9.1 -- a
    schema `.parse()` injects defaulted members, and a signer that
    canonicalizes post-parse while a verifier canonicalizes pre-parse fails
    every single time, for reasons that look like a key problem.
    """
    if isinstance(source, (bytes, bytearray)):
        try:
            text = bytes(source).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CanonicalError("malformed_json", "input is not valid UTF-8") from exc
    else:
        text = source
    return _serialize(_Parser.parse_top_level(text))


def canonicalize_value(value: Any) -> str:
    """Canonicalize an in-memory object. See `_to_node` for why not `dumps`."""
    node = _to_node(value, "$")
    if node[0] != "obj":
        raise CanonicalError("top_level_not_object", "canonicalization input must be a JSON object")
    return _serialize(node)


def canonicalize_to_bytes(source: Union[str, bytes, bytearray]) -> bytes:
    """The canonical form as UTF-8 bytes: no BOM, no trailing newline (§4.2)."""
    return canonicalize(source).encode("utf-8")


def canonicalize_value_to_bytes(value: Any) -> bytes:
    return canonicalize_value(value).encode("utf-8")


def canonical_hash(source: Union[str, bytes, bytearray]) -> str:
    """`sha256:{64 lowercase hex}` over the canonical bytes (§10)."""
    return "sha256:" + hashlib.sha256(canonicalize_to_bytes(source)).hexdigest()


def canonical_value_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonicalize_value_to_bytes(value)).hexdigest()
