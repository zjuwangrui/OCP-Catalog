# OCP Canonical JSON 一致性测试向量

规范：[`docs/specs/crypto/canonicalization.md`](../../../../docs/specs/crypto/canonicalization.md)

三语言（TypeScript / Python / Go）共用。实现**必须**通过全部向量才算符合 OCP Canonical JSON v1.0。

## 1. 向量清单

| 文件 | 类别 | 规范章节 | 条数 |
|---|---|---|---|
| `01-key-order.json` | 键序 | §5 | 12 |
| `02-nesting.json` | 嵌套 | §5.1 / §8.4 | 5 |
| `03-escaping.json` | 转义与 Unicode | §6 | 13 |
| `04-numbers.json` | 数字（Level 1） | §7 | 21 |
| `05-empty-and-null.json` | 空值与空容器 | §8 | 10 |
| `06-rejection.json` | 拒绝类 | §4.2 / §5.4 / §6.4 | 14 |

合计 **75 条**：接受类 51 条，拒绝类 24 条。

## 2. 向量格式

每个文件是一个 object，`vectors` 为向量数组。单条向量：

```jsonc
{
  "name": "key-order-astral-vs-fffd",     // 唯一标识，用作测试用例名
  "reason": "规范 §5.2 原例：D83D < FFFD，码点序/UTF-8 序结论相反",
  "spec": "§5.2",                          // 该向量锚定的规范条款
  "input_raw": "{\"\\ufffd\":1,\"\\ud83d\\ude00\":2}",
  "expected_canonical": "{\"😀\":2,\"\uFFFD\":1}",
  "expected_sha256": "sha256:ee25c272...9848"
}
```

拒绝类向量用 `expected_error` 取代 `expected_canonical` 与 `expected_sha256`。

### 2.1 为什么是 `input_raw`（字符串）而不是 `input`（JSON 值）

规范 §11 最初把 `input` 写成一个 JSON 值。**实做时发现这样做不成立**：拒绝类向量的输入按定义就是解析器会拒绝或会静默改写的东西，无法以「已解析的 JSON 值」形式存在于 fixture 里。

- `{"a":1,"a":2}`——加载 fixture 的那个解析器自己就会静默去重，向量到达被测实现时重复键已经消失
- `{"a":NaN}`——不是合法 JSON，fixture 文件本身会变成非法 JSON
- `{"a":"\ud800"}`——孤立代理项在多数解析器里能过，但产出的字符串已不可靠
- `[1,2]`——顶层非 object，无法作为 object 类型的 `input` 字段承载

因此 `input_raw` 是**字符串**，内容为待规范化的 JSON **文本**（即规范 §4.1 里的 wire bytes，按 UTF-8 解释）。这同时更忠实于规范：规范化的输入是字节，不是某语言的对象图。

**读取方式**：从 fixture 取出 `input_raw` 字符串后，直接把它的 UTF-8 编码交给被测实现的入口，**不要**先用标准库 `JSON.parse` 过一遍。

### 2.2 `expected_sha256`

`expected_canonical` 的 UTF-8 字节的 SHA-256，按规范 §10 表示为 `sha256:{64 位小写十六进制}`。

任意语言一行可复算，无需专用工具：

```bash
python -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" '{"a":[1,2],"b":1}'
```

`expected_canonical` 由人按规范逐条手写，再用一份独立实现的参考规范化器交叉验证；两条独立推导一致后才写入哈希。哈希不是判断题，因此由机器算；canonical 字符串是判断题，因此由人写。

## 3. 错误码

规范只说「报错终止」，这在测试里不可判定——三个实现都抛异常但抛的不是同一件事时，测试仍会绿。因此拒绝类向量约定以下**稳定错误码**，实现必须能把失败归类到这一层：

| 错误码 | 触发条件 | 规范条款 |
|---|---|---|
| `duplicate_key` | 同一 object 内成员名重复（解码后比较） | §5.4 |
| `lone_surrogate` | 字符串或成员名含未成对的 U+D800–U+DFFF | §6.4 |
| `non_integer_number` | number 的数学值非整数 | §7.2 |
| `number_out_of_range` | \|value\| > 2⁵³−1，含解析后溢出为 Infinity 的字面量 | §7.2 / §7.3 |
| `non_finite_number` | 字面量 `NaN` / `Infinity` / `-Infinity` | §7.5 |
| `top_level_not_object` | 顶层不是 JSON object | §4.2 |

错误码不要求出现在用户可见的错误消息里，只要求实现内部可稳定映射，以便测试断言。

## 4. 各语言加载向量时的坑

| 语言 | 坑 | 做法 |
|---|---|---|
| **TypeScript** | `JSON.parse` 不暴露重复键，`duplicate_key` 无法在 parse 之后检测 | 自建扫描或流式解析；不能依赖 `JSON.parse` 的返回值 |
| **TypeScript** | `JSON.parse('{"a":NaN}')` 抛 `SyntaxError`，与规范要求的 `non_finite_number` 是两类错误 | 映射到统一错误码，不要把 `SyntaxError` 直接透出 |
| **Python** | `json.loads` 默认接受 `NaN`/`Infinity` | `parse_constant` 钩子拦截；不要用 `parse_float` 代替 |
| **Python** | `json.loads` 默认对重复键取后者 | `object_pairs_hook` 自行检测 |
| **Go** | `encoding/json` 解 number 为 `float64`，2⁵³ 以上精度已丢，`number_out_of_range` 检测不到 | `Decoder.UseNumber()`，在 `json.Number` 的字符串形态上判定 |
| **Go** | `encoding/json` 默认转义 `<` `>` `&` | 序列化侧不使用 `encoding/json`，或 `SetEscapeHTML(false)` |
| **Go** | `sort.Strings` 按 UTF-8 字节序，与规范的 UTF-16 代码单元序在 BMP 外结论相反 | 转 UTF-16 后比较（见 §5.2） |

## 5. 必须成对断言的向量

以下两组不是「各自过」就够，它们的**关系**才是断言内容：

| 组 | 断言 |
|---|---|
| `key-order-idempotent-a` / `-b` | 两条 `expected_sha256` **必须相等**——同一逻辑对象、不同字段序，规范化后逐字节相同。这是整个规范存在的理由 |
| `null-preserved` / `null-absent-counterpart` | 两条 `expected_sha256` **必须不等**——「成员不存在」与「成员为 null」是不同的值（§8.2） |

## 6. 覆盖上的已知缺口

- **浮点**：Level 2 在 v1 不实现（规范 §7.4），因此没有 `1e21`、`5e-7`、次正规数的向量。实现 Level 2 时需另起一套向量文件。
- **超大输入**：没有深度/体积压力向量。递归深度上限属于实现的抗 DoS 策略，规范未定义。
- **`packages/ocp-schema` 真实对象**：本向量集只测规范化本身。真实 `CatalogManifest` / `AttributionToken` 的端到端签名向量属 W3-T1 与 W4-T3。
