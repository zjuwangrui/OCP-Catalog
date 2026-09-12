/**
 * OCP Canonical JSON v1.0 — "OCP-JCS v1".
 *
 * Spec: `docs/specs/crypto/canonicalization.md`. Conformance vectors:
 * `packages/ocp-crypto/fixtures/canonical/` (75 of them; `canonical.test.ts`
 * runs every one).
 *
 * Three things about this file are load-bearing and easy to undo by accident:
 *
 * 1. **It has its own JSON parser.** `JSON.parse` cannot be used, because it
 *    silently resolves duplicate members last-one-wins (spec §5.4) — by the
 *    time you hold the parsed value, `{"amount":1,"amount":9999}` has already
 *    become `{"amount":9999}` and the signature bypass is invisible. Duplicate
 *    detection has to happen during parsing.
 * 2. **Number admission is decided on the decimal literal, never on a float.**
 *    See {@link canonicalNumberLiteral}.
 * 3. **Member sorting uses `<` on JS strings**, which compares UTF-16 code
 *    units — exactly the order spec §5.2 requires. `localeCompare` and
 *    `Intl.Collator` do NOT, and swapping one in would break cross-language
 *    byte equality for astral-plane keys while leaving every ASCII test green.
 */
import { createHash } from 'node:crypto';
import { CanonicalError } from './errors';

/** 2^53 - 1, as a decimal string. Range checks compare digits, not doubles. */
const MAX_SAFE_DECIMAL = '9007199254740991';

type JsonNode =
  | { readonly t: 'obj'; readonly members: ReadonlyArray<{ key: string; value: JsonNode }> }
  | { readonly t: 'arr'; readonly items: readonly JsonNode[] }
  | { readonly t: 'str'; readonly value: string }
  | { readonly t: 'num'; readonly literal: string }
  | { readonly t: 'bool'; readonly value: boolean }
  | { readonly t: 'null' };

// ---------------------------------------------------------------------------
// Numbers (spec §7, Level 1)
// ---------------------------------------------------------------------------

const NUMBER_PARTS = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/;

/**
 * Admits a JSON number literal under Level 1 and returns its canonical form.
 *
 * The judgement is made on the literal's exact decimal value, not on
 * `Number(literal)`. Spec §7.2 normatively says "其数学值是整数"; the
 * `Number.isInteger(v)` snippet beside it is a convenience that only agrees
 * with the normative text when the literal carries no more precision than a
 * double. `9007199254740991.0000000000001` is the counterexample: it rounds to
 * an exact integer, so the float test accepts it and emits
 * `9007199254740991` — signing a value that is not the one on the wire.
 *
 * Doing it on digits also keeps the two rejection codes distinct. `1e400` is
 * `number_out_of_range` (magnitude), `0.5` is `non_integer_number` (shape); a
 * float path collapses the first into `Infinity` and has to special-case its
 * way back out.
 */
export function canonicalNumberLiteral(literal: string): string {
  const m = NUMBER_PARTS.exec(literal);
  if (!m) throw new CanonicalError('malformed_json', `not a JSON number: ${literal}`);

  const negative = m[1] === '-';
  const frac = m[3] ?? '';
  // `parseInt` on an absurd exponent yields ±Infinity, which flows through the
  // comparisons below correctly and never reaches an allocation.
  const exponent = m[4] ? Number.parseInt(m[4], 10) : 0;

  // value = digits * 10^(-scale)
  const digits = (m[2] + frac).replace(/^0+/, '') || '0';
  const scale = frac.length - exponent;

  if (digits === '0') return '0'; // also covers -0 and -0.0 (spec §7.2)

  let integerDigits: string;
  if (scale <= 0) {
    // Trailing zeros to append. Check the resulting magnitude before building
    // the string, or `1e999999999` becomes an allocation bomb.
    if (digits.length - scale > MAX_SAFE_DECIMAL.length) {
      throw new CanonicalError('number_out_of_range', `|${literal}| exceeds 2^53-1`);
    }
    integerDigits = digits + '0'.repeat(-scale);
  } else if (scale >= digits.length) {
    // Non-zero with magnitude < 1.
    throw new CanonicalError('non_integer_number', `${literal} is not an integer`);
  } else {
    const dropped = digits.slice(digits.length - scale);
    if (!/^0+$/.test(dropped)) {
      throw new CanonicalError('non_integer_number', `${literal} is not an integer`);
    }
    integerDigits = digits.slice(0, digits.length - scale);
  }

  if (
    integerDigits.length > MAX_SAFE_DECIMAL.length ||
    (integerDigits.length === MAX_SAFE_DECIMAL.length && integerDigits > MAX_SAFE_DECIMAL)
  ) {
    throw new CanonicalError('number_out_of_range', `|${literal}| exceeds 2^53-1`);
  }

  return (negative ? '-' : '') + integerDigits;
}

// ---------------------------------------------------------------------------
// Parsing (spec §4.1 stage 1 + stage 2, fused only where the spec requires it)
// ---------------------------------------------------------------------------

const NUMBER_TOKEN = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

class Parser {
  private i = 0;
  private readonly s: string;

  constructor(text: string) {
    this.s = text;
  }

  static parseTopLevel(text: string): JsonNode {
    const p = new Parser(text);
    p.ws();
    // Checked before parsing so that error precedence is deterministic: a
    // non-object top level reports `top_level_not_object` regardless of what
    // else is wrong further in. Without this, `[1,NaN]` would report
    // `non_finite_number` here and `top_level_not_object` in an implementation
    // that validated the shape first.
    if (p.peek() !== '{') {
      throw new CanonicalError('top_level_not_object', 'canonicalization input must be a JSON object');
    }
    const node = p.value();
    p.ws();
    if (p.i !== p.s.length) throw new CanonicalError('malformed_json', 'trailing content after top-level value');
    return node;
  }

  private peek(): string | undefined {
    return this.s[this.i];
  }

  private ws(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i += 1;
      else break;
    }
  }

  private bad(what: string): never {
    throw new CanonicalError('malformed_json', `${what} at offset ${this.i}`);
  }

  private literal(word: string): void {
    if (this.s.startsWith(word, this.i)) this.i += word.length;
    else this.bad(`expected ${word}`);
  }

  private value(): JsonNode {
    const c = this.peek();
    switch (c) {
      case '{':
        return this.object();
      case '[':
        return this.array();
      case '"':
        return { t: 'str', value: this.string() };
      case 't':
        this.literal('true');
        return { t: 'bool', value: true };
      case 'f':
        this.literal('false');
        return { t: 'bool', value: false };
      case 'n':
        this.literal('null');
        return { t: 'null' };
      // NaN / Infinity are not JSON, but Python's json.loads accepts them by
      // default (§7.5), so they do show up on the wire. They get their own code
      // rather than being lumped in with syntax errors.
      case 'N':
        this.literal('NaN');
        throw new CanonicalError('non_finite_number', 'NaN is not a permitted value');
      case 'I':
        this.literal('Infinity');
        throw new CanonicalError('non_finite_number', 'Infinity is not a permitted value');
      default:
        if (c === '-' && this.s.startsWith('-Infinity', this.i)) {
          throw new CanonicalError('non_finite_number', '-Infinity is not a permitted value');
        }
        if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) return this.number();
        return this.bad('unexpected token');
    }
  }

  private number(): JsonNode {
    NUMBER_TOKEN.lastIndex = this.i;
    const m = NUMBER_TOKEN.exec(this.s);
    if (!m || m.index !== this.i) return this.bad('invalid number');
    this.i += m[0].length;
    // Admission happens here, at parse time, so the literal is still available.
    // Canonicalizing from a parsed double would have already lost it.
    return { t: 'num', literal: canonicalNumberLiteral(m[0]) };
  }

  private hex4(): number {
    const hex = this.s.slice(this.i, this.i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.bad('invalid \\u escape');
    this.i += 4;
    return Number.parseInt(hex, 16);
  }

  /** Returns the decoded string. Surrogate pairing is validated here (§6.4). */
  private string(): string {
    this.i += 1; // opening quote
    let out = '';
    for (;;) {
      if (this.i >= this.s.length) this.bad('unterminated string');
      const cc = this.s.charCodeAt(this.i);

      if (cc === 0x22) {
        this.i += 1;
        return out;
      }

      if (cc === 0x5c) {
        this.i += 1;
        const esc = this.s[this.i];
        switch (esc) {
          case '"':
          case '\\':
          case '/':
            out += esc;
            this.i += 1;
            break;
          case 'b':
            out += '\b';
            this.i += 1;
            break;
          case 'f':
            out += '\f';
            this.i += 1;
            break;
          case 'n':
            out += '\n';
            this.i += 1;
            break;
          case 'r':
            out += '\r';
            this.i += 1;
            break;
          case 't':
            out += '\t';
            this.i += 1;
            break;
          case 'u': {
            this.i += 1;
            const unit = this.hex4();
            if (unit >= 0xd800 && unit <= 0xdbff) {
              if (this.s[this.i] !== '\\' || this.s[this.i + 1] !== 'u') {
                throw new CanonicalError('lone_surrogate', 'high surrogate without a following low surrogate');
              }
              this.i += 2;
              const low = this.hex4();
              if (low < 0xdc00 || low > 0xdfff) {
                throw new CanonicalError('lone_surrogate', 'high surrogate followed by a non-low-surrogate unit');
              }
              out += String.fromCharCode(unit, low);
            } else if (unit >= 0xdc00 && unit <= 0xdfff) {
              throw new CanonicalError('lone_surrogate', 'low surrogate without a preceding high surrogate');
            } else {
              out += String.fromCharCode(unit);
            }
            break;
          }
          default:
            this.bad(`invalid escape \\${esc ?? '<eof>'}`);
        }
        continue;
      }

      if (cc < 0x20) this.bad('unescaped control character in string');

      // Literal (non-escaped) surrogates: unreachable from well-formed UTF-8
      // bytes, reachable when a caller hands us a JS string directly.
      if (cc >= 0xd800 && cc <= 0xdbff) {
        const next = this.s.charCodeAt(this.i + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) {
          throw new CanonicalError('lone_surrogate', 'unpaired high surrogate');
        }
        out += this.s.slice(this.i, this.i + 2);
        this.i += 2;
        continue;
      }
      if (cc >= 0xdc00 && cc <= 0xdfff) {
        throw new CanonicalError('lone_surrogate', 'unpaired low surrogate');
      }

      out += this.s[this.i];
      this.i += 1;
    }
  }

  private object(): JsonNode {
    this.i += 1; // '{'
    const members: Array<{ key: string; value: JsonNode }> = [];
    const seen = new Set<string>();
    this.ws();
    if (this.peek() === '}') {
      this.i += 1;
      return { t: 'obj', members };
    }
    for (;;) {
      this.ws();
      if (this.peek() !== '"') this.bad('object member name must be a string');
      const key = this.string();
      // Compared after decoding, so `"a"` and `"a"` collide (§5.4).
      if (seen.has(key)) {
        throw new CanonicalError('duplicate_key', `duplicate member name ${JSON.stringify(key)}`);
      }
      seen.add(key);
      this.ws();
      if (this.peek() !== ':') this.bad("expected ':'");
      this.i += 1;
      this.ws();
      members.push({ key, value: this.value() });
      this.ws();
      const c = this.peek();
      if (c === ',') {
        this.i += 1;
        continue;
      }
      if (c === '}') {
        this.i += 1;
        return { t: 'obj', members };
      }
      return this.bad("expected ',' or '}'");
    }
  }

  private array(): JsonNode {
    this.i += 1; // '['
    const items: JsonNode[] = [];
    this.ws();
    if (this.peek() === ']') {
      this.i += 1;
      return { t: 'arr', items };
    }
    for (;;) {
      this.ws();
      items.push(this.value());
      this.ws();
      const c = this.peek();
      if (c === ',') {
        this.i += 1;
        continue;
      }
      if (c === ']') {
        this.i += 1;
        return { t: 'arr', items };
      }
      return this.bad("expected ',' or ']'");
    }
  }
}

// ---------------------------------------------------------------------------
// Serialization (spec §5, §6, §8)
// ---------------------------------------------------------------------------

const SHORT_ESCAPES = new Map<number, string>([
  [0x08, '\\b'],
  [0x09, '\\t'],
  [0x0a, '\\n'],
  [0x0c, '\\f'],
  [0x0d, '\\r'],
  [0x22, '\\"'],
  [0x5c, '\\\\'],
]);

/**
 * Minimal escaping (§6.1). Everything not in the table above is emitted as-is,
 * including `/`, `<`, `>`, `&` and all non-ASCII — those are the three
 * language-default traps in §6.3.
 */
function encodeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i += 1) {
    const cc = s.charCodeAt(i);
    const short = SHORT_ESCAPES.get(cc);
    if (short !== undefined) {
      out += short;
      continue;
    }
    if (cc < 0x20) {
      out += `\\u00${cc.toString(16).padStart(2, '0')}`; // lowercase hex (§6.1)
      continue;
    }
    out += s[i];
  }
  return `${out}"`;
}

/** UTF-16 code-unit order (§5.2). `<` on JS strings is exactly that. */
function byCodeUnit(a: { key: string }, b: { key: string }): number {
  return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
}

function serialize(node: JsonNode): string {
  switch (node.t) {
    case 'obj': {
      // Sorted per level, independently of the parent (§5.1).
      const sorted = [...node.members].sort(byCodeUnit);
      return `{${sorted.map((m) => `${encodeString(m.key)}:${serialize(m.value)}`).join(',')}}`;
    }
    case 'arr':
      // Order preserved, no dedupe — array order is semantics (§8.4).
      return `[${node.items.map(serialize).join(',')}]`;
    case 'str':
      return encodeString(node.value);
    case 'num':
      return node.literal;
    case 'bool':
      return node.value ? 'true' : 'false';
    case 'null':
      return 'null'; // never dropped (§8.1)
  }
}

// ---------------------------------------------------------------------------
// Value entry point
// ---------------------------------------------------------------------------

/**
 * Converts an in-memory value to a node with the same admission rules.
 *
 * Used by the signing side, which builds an object rather than receiving bytes.
 * Deliberately *not* implemented as `canonicalize(JSON.stringify(value))`:
 * `JSON.stringify` turns `NaN` into `null` and drops `undefined` members, both
 * of which are the "静默修正" §2.2 forbids.
 */
function toNode(value: unknown, path: string): JsonNode {
  if (value === null) return { t: 'null' };

  switch (typeof value) {
    case 'boolean':
      return { t: 'bool', value };
    case 'string':
      return { t: 'str', value: assertNoLoneSurrogate(value, path) };
    case 'number': {
      if (!Number.isFinite(value)) {
        throw new CanonicalError('non_finite_number', `${path} is ${String(value)}`);
      }
      if (!Number.isInteger(value)) {
        throw new CanonicalError('non_integer_number', `${path} = ${value} is not an integer`);
      }
      if (Math.abs(value) > Number.MAX_SAFE_INTEGER) {
        throw new CanonicalError('number_out_of_range', `${path} = ${value} exceeds 2^53-1`);
      }
      return { t: 'num', literal: Object.is(value, -0) ? '0' : String(value) };
    }
    case 'object': {
      if (Array.isArray(value)) {
        return { t: 'arr', items: value.map((item, idx) => toNode(item, `${path}[${idx}]`)) };
      }
      const members = Object.entries(value as Record<string, unknown>).map(([key, v]) => ({
        key: assertNoLoneSurrogate(key, `${path}.${key}`),
        value: toNode(v, `${path}.${key}`),
      }));
      return { t: 'obj', members };
    }
    default:
      // undefined, bigint, symbol, function. Refused rather than skipped:
      // dropping a member changes the signed value (§8.2).
      throw new CanonicalError('unsupported_value', `${path} has non-JSON type ${typeof value}`);
  }
}

function assertNoLoneSurrogate(s: string, path: string): string {
  for (let i = 0; i < s.length; i += 1) {
    const cc = s.charCodeAt(i);
    if (cc >= 0xd800 && cc <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new CanonicalError('lone_surrogate', `${path} contains an unpaired high surrogate`);
      }
      i += 1;
    } else if (cc >= 0xdc00 && cc <= 0xdfff) {
      throw new CanonicalError('lone_surrogate', `${path} contains an unpaired low surrogate`);
    }
  }
  return s;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

const utf8 = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();

/**
 * Canonicalizes JSON **wire bytes** (or their decoded text) per OCP-JCS v1.
 *
 * Feed this the bytes as received. Do not pre-parse them: spec §9.1 — Zod
 * `.parse()` injects `.default()` members (96 of them in `ocp-schema`), and a
 * signer that canonicalizes post-parse while a verifier canonicalizes pre-parse
 * fails every single time, for reasons that look like a key problem.
 */
export function canonicalize(input: string | Uint8Array): string {
  let text: string;
  if (typeof input === 'string') {
    text = input;
  } else {
    try {
      text = utf8.decode(input);
    } catch (cause) {
      throw new CanonicalError('malformed_json', 'input is not valid UTF-8', { cause });
    }
  }
  return serialize(Parser.parseTopLevel(text));
}

/** Canonicalizes an in-memory object. See {@link toNode} for why not stringify. */
export function canonicalizeValue(value: unknown): string {
  const node = toNode(value, '$');
  if (node.t !== 'obj') {
    throw new CanonicalError('top_level_not_object', 'canonicalization input must be a JSON object');
  }
  return serialize(node);
}

/** The canonical form as UTF-8 bytes: no BOM, no trailing newline (§4.2). */
export function canonicalizeToBytes(input: string | Uint8Array): Uint8Array {
  return encoder.encode(canonicalize(input));
}

export function canonicalizeValueToBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalizeValue(value));
}

/** `sha256:{64 lowercase hex}` over the canonical bytes (§10). */
export function canonicalHash(input: string | Uint8Array): string {
  return `sha256:${createHash('sha256').update(canonicalizeToBytes(input)).digest('hex')}`;
}

export function canonicalValueHash(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalizeValueToBytes(value)).digest('hex')}`;
}
