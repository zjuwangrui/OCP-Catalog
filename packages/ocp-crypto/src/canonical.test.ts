import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, test } from 'bun:test';
import {
  CanonicalError,
  canonicalHash,
  canonicalNumberLiteral,
  canonicalize,
  canonicalizeValue,
  canonicalValueHash,
} from './index';

/**
 * Conformance run over `fixtures/canonical/` (75 vectors) plus the assertions
 * the fixtures cannot express on their own.
 *
 * Per the fixture README §2.1, `input_raw` is handed to `canonicalize` as text
 * and is deliberately NOT pre-parsed with `JSON.parse` — the rejection vectors
 * only exist because the standard parser would silently fix them.
 */

const FIXTURE_DIR = new URL('../fixtures/canonical/', import.meta.url);

interface Vector {
  name: string;
  reason: string;
  spec: string;
  input_raw: string;
  expected_canonical?: string;
  expected_sha256?: string;
  expected_error?: string;
}

interface VectorFile {
  category: string;
  vector_count: number;
  vectors: Vector[];
}

const files = readdirSync(FIXTURE_DIR)
  .filter((name) => name.endsWith('.json'))
  .sort();

const loaded = files.map((name) => {
  const file = JSON.parse(readFileSync(new URL(name, FIXTURE_DIR), 'utf8')) as VectorFile;
  return { name, file };
});

const allVectors = loaded.flatMap(({ file }) => file.vectors);
const byName = new Map(allVectors.map((v) => [v.name, v]));

/** Returns the stable error code, so a vector asserts *which* failure it is. */
function failureCodeOf(input: string): string {
  try {
    canonicalize(input);
    return '<no error>';
  } catch (err) {
    if (err instanceof CanonicalError) return err.code;
    return `<${(err as Error).name}: ${(err as Error).message}>`;
  }
}

describe('OCP-JCS v1 · 向量集完整性', () => {
  test('六个向量文件共 75 条，且每个文件的 vector_count 与实际条数一致', () => {
    expect(files.length).toBe(6);
    for (const { name, file } of loaded) {
      expect(`${name}:${file.vectors.length}`).toBe(`${name}:${file.vector_count}`);
    }
    expect(allVectors.length).toBe(75);
  });

  test('向量名唯一', () => {
    expect(byName.size).toBe(allVectors.length);
  });
});

for (const { name, file } of loaded) {
  describe(`OCP-JCS v1 · ${name}`, () => {
    for (const vector of file.vectors) {
      test(`${vector.name} (${vector.spec})`, () => {
        if (vector.expected_error !== undefined) {
          expect(failureCodeOf(vector.input_raw)).toBe(vector.expected_error);
          return;
        }
        expect(canonicalize(vector.input_raw)).toBe(vector.expected_canonical!);
        expect(canonicalHash(vector.input_raw)).toBe(vector.expected_sha256!);
      });
    }
  });
}

describe('OCP-JCS v1 · 成对断言（关系本身是断言内容）', () => {
  // Fixture README §5: these two pairs are why the spec exists. A per-vector
  // loop passes even if the implementation is order-dependent, as long as each
  // expected string was written to match the bug.
  test('同一逻辑对象的两种字段序 → 哈希必须相等', () => {
    const a = byName.get('key-order-idempotent-a')!;
    const b = byName.get('key-order-idempotent-b')!;
    expect(a.input_raw).not.toBe(b.input_raw);
    expect(canonicalHash(a.input_raw)).toBe(canonicalHash(b.input_raw));
  });

  test('成员为 null 与成员缺省 → 哈希必须不等', () => {
    const present = byName.get('null-preserved')!;
    const absent = byName.get('null-absent-counterpart')!;
    expect(canonicalHash(present.input_raw)).not.toBe(canonicalHash(absent.input_raw));
  });
});

describe('OCP-JCS v1 · 规范条款的补充断言', () => {
  test('规范化是幂等的：canonicalize(canonicalize(x)) === canonicalize(x)', () => {
    for (const vector of allVectors) {
      if (vector.expected_error !== undefined) continue;
      expect(canonicalize(vector.expected_canonical!)).toBe(vector.expected_canonical!);
    }
  });

  test('接受 UTF-8 字节与接受等价文本结果相同（§4.1 输入是字节）', () => {
    const bytes = new TextEncoder().encode('{"b":1,"a":"中文😀"}');
    expect(canonicalize(bytes)).toBe('{"a":"中文😀","b":1}');
  });

  test('输出无 BOM、无结尾换行、无非结构空白（§4.2）', () => {
    const out = canonicalize('{\n  "b" : 1,\n  "a" : [ 1, 2 ]\n}');
    expect(out).toBe('{"a":[1,2],"b":1}');
    expect(out.charCodeAt(0)).toBe(0x7b);
  });

  test('整数判定作用于十进制字面量，不经过 double（§7.2 规范文本）', () => {
    // Rounds to an exact integer as a double, so a `Number.isInteger` check
    // would accept it and sign 9007199254740991 — a value that was never on
    // the wire.
    expect(failureCodeOf('{"a":9007199254740991.0000000000001}')).toBe('non_integer_number');
    // Integral despite a fractional mantissa and a negative exponent.
    expect(canonicalize('{"a":100e-2}')).toBe('{"a":1}');
    expect(failureCodeOf('{"a":1e-400}')).toBe('non_integer_number');
  });

  test('荒谬的指数不触发大额分配，直接判超范围', () => {
    expect(failureCodeOf('{"a":1e999999999}')).toBe('number_out_of_range');
    expect(failureCodeOf(`{"a":1e${'9'.repeat(400)}}`)).toBe('number_out_of_range');
  });

  test('2^53 边界两侧', () => {
    expect(canonicalNumberLiteral('9007199254740991')).toBe('9007199254740991');
    expect(canonicalNumberLiteral('-9007199254740991')).toBe('-9007199254740991');
    expect(failureCodeOf('{"a":9007199254740992}')).toBe('number_out_of_range');
    expect(failureCodeOf('{"a":-9007199254740992}')).toBe('number_out_of_range');
  });

  test('顶层判定优先于内容判定，错误码可预期', () => {
    // Violates both §4.2 and §7.5; the reported code must not depend on the
    // order an implementation happens to check things in.
    expect(failureCodeOf('[1,NaN]')).toBe('top_level_not_object');
  });

  test('非法 JSON 与规范拒绝是两类失败', () => {
    expect(failureCodeOf('{"a":}')).toBe('malformed_json');
    expect(failureCodeOf('{"a":1}{"b":2}')).toBe('malformed_json');
    expect(failureCodeOf('{"a":01}')).toBe('malformed_json');
  });
});

describe('OCP-JCS v1 · 值入口（签名侧）', () => {
  test('字段序不影响输出，与字节入口结果一致', () => {
    expect(canonicalizeValue({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalValueHash({ b: 1, a: 2 })).toBe(canonicalHash('{"a":2,"b":1}'));
  });

  test('-0 输出 0，null 保留，空容器保留', () => {
    expect(canonicalizeValue({ a: -0, b: null, c: [], d: {} })).toBe('{"a":0,"b":null,"c":[],"d":{}}');
  });

  test('NaN / 非整数 / 超范围各自报对应码，而非 JSON.stringify 的静默改写', () => {
    // JSON.stringify({a: NaN}) === '{"a":null}' — silently signs a different
    // value. §2.2 forbids exactly that.
    expect(valueFailureCodeOf({ a: Number.NaN })).toBe('non_finite_number');
    expect(valueFailureCodeOf({ a: Number.POSITIVE_INFINITY })).toBe('non_finite_number');
    expect(valueFailureCodeOf({ a: 129.5 })).toBe('non_integer_number');
    expect(valueFailureCodeOf({ a: 2 ** 53 })).toBe('number_out_of_range');
  });

  test('undefined 成员被拒绝，而不是被丢掉（§8.2 禁止增删成员）', () => {
    expect(valueFailureCodeOf({ a: 1, b: undefined })).toBe('unsupported_value');
    expect(valueFailureCodeOf({ a: 1n })).toBe('unsupported_value');
  });

  test('顶层非 object 被拒绝', () => {
    expect(valueFailureCodeOf([1, 2])).toBe('top_level_not_object');
    expect(valueFailureCodeOf('str')).toBe('top_level_not_object');
  });

  test('金额场景：最小单位整数可签，浮点金额不可签（§7.4）', () => {
    expect(canonicalizeValue({ amount_minor: 12900, currency: 'CNY' })).toBe(
      '{"amount_minor":12900,"currency":"CNY"}',
    );
    expect(valueFailureCodeOf({ amount: 129.0 + 0.5, currency: 'CNY' })).toBe('non_integer_number');
  });
});

function valueFailureCodeOf(value: unknown): string {
  try {
    canonicalizeValue(value);
    return '<no error>';
  } catch (err) {
    if (err instanceof CanonicalError) return err.code;
    return `<${(err as Error).name}>`;
  }
}
