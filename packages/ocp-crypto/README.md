# @ocp-catalog/ocp-crypto

OCP Catalog 的规范化、签名与密钥发现实现。四块内容：

| 模块 | 规范 | 内容 |
|---|---|---|
| `canonical.ts` | [OCP Canonical JSON v1.0](../../docs/specs/crypto/canonicalization.md) | OCP-JCS v1 规范化、`sha256:` 哈希 |
| `keys.ts` | [归因规范 §5](../../docs/specs/attribution/v1.md) | Ed25519 生成 / 签名 / 验签、JWK 形态 |
| `jwks.ts` | [归因规范 §7.1](../../docs/specs/attribution/v1.md) 第 4 行 | JWKS 加载、`kid` 解析、TTL 缓存 |
| `attribution.ts` | [归因规范 §4.3 / §5.2 / §5.3](../../docs/specs/attribution/v1.md) | 核心声明、逐跳签名材料、`complete` 重算、origin token 签发 |

一致性向量在 [`fixtures/canonical/`](./fixtures/canonical/README.md)（75 条），`src/canonical.test.ts` 逐条跑。

## 本包没有依赖，这是规范要求

包括**没有 `zod`**。规范 §9.1 禁止对 Zod `parse()` 的输出做规范化——`ocp-schema` 里有 96 处 `.default(...)`，`parse()` 会**注入**线上不存在的成员。签名方在 parse 前规范化、验签方在 parse 后规范化（或反之），会**每一次**都验签失败，且失败与内容无关，排查方向极易跑偏到密钥或算法上。

所以本包的公开 API 不接受 schema 参数：让调用方无法表达那个错误，比在文档里劝他别犯要可靠。

```text
                ┌──▶ Zod 校验    ──▶ 业务处理
wire bytes ──解析┤
                └──▶ ocp-crypto  ──▶ 哈希/签名
```

## 入口

```ts
import { canonicalize, canonicalHash, canonicalizeValue } from '@ocp-catalog/ocp-crypto';

canonicalize('{"b":1,"a":[1,2]}');          // '{"a":[1,2],"b":1}'
canonicalHash('{"b":1,"a":[1,2]}');         // 'sha256:...'
canonicalizeValue({ b: 1, a: [1, 2] });     // 同上，用于签名侧自建对象
```

**字节入口 vs 值入口**：`canonicalize` 收 wire bytes（或其文本），`canonicalizeValue` 收内存对象。验签一律走前者——收到什么就验什么。签名侧走后者，因为此刻还没有字节。

```ts
import { generateEd25519KeyPair, signCanonical, verifyCanonical } from '@ocp-catalog/ocp-crypto';

const { kid, publicJwk, privateJwk } = generateEd25519KeyPair();
const signature = signCanonical(privateJwk, { chain: [...], core: {...} });   // 归因规范 §5.2
verifyCanonical({ jwk: publicJwk, value: { ... }, signature });              // → boolean
```

```ts
import { JwksCache, createDiscoveryJwksLoader } from '@ocp-catalog/ocp-crypto';

const cache = new JwksCache({
  load: createDiscoveryJwksLoader({
    wellKnownUrl: (catalogId) => `https://${catalogId}.example.com/.well-known/ocp-catalog`,
    fetchJson: async (url) => (await fetch(url)).json(),
  }),
  ttlMs: 300_000,
});

const jwk = await cache.getVerificationKey('cat_origin', 'kid_2026_09');
```

`fetch` 是注入的，不是 import 的。验证器必须能离线跑（第 1 周五的演示就是「断网状态下用公钥验通」），而一个自己伸手去 `fetch` 的包，没法测它真正要紧的那几条失败路径。

### 归因凭证

```ts
import { issueOriginToken, coreClaims, recomputeComplete, verifyChainNodeSignature }
  from '@ocp-catalog/ocp-crypto';

const token = issueOriginToken({
  privateJwk, kid, catalogId: 'cat_origin',
  agentId: 'agent_alpha', entryId, objectId, providerId,
  purpose: 'checkout',                       // §7.1：只有 checkout 可结算
});

// 验证一跳：core 与 chain 前缀必须与签名方构造的完全一致，所以两边调同一个函数
verifyChainNodeSignature({ jwk, core: coreClaims(token), chain: token.chain, hopIndex: 0 });
recomputeComplete(token.chain) === token.complete;   // §5.3：必须重算，不能读
```

签名材料是 `{ chain: [unsigned(1..N)], core }`（§5.2）。两个容易写错的地方：

- **第 N 跳签的是含自己在内的前缀**，不是只签前 N−1 跳。漏掉自己会让 `settles` 和 `chain_complete` 落在签名之外——而钱正好挂在这两个字段上。
- **`coreClaims` 是「删掉 `complete` 和 `chain`」，不是「挑出想要的键」**。挑键的写法会让将来新增的可选声明悄悄掉出签名材料，于是一边签了一边没签，报出来只是一句「验签失败」。

`attribution.ts` 只做**签发**和**单跳验签**——重放、过期、provider 匹配、逐跳错误定位是完整验证器的事（T4），要配着它们需要的策略状态一起写。放在这里的是签名方和验证方**必须逐字节一致**的那部分，两边调同一份代码才不会漂。多跳（relay）签发同理是 T4 的独立入口：一跳链是本节点自己起的，`chain_complete: true` 由构造保证；接在别人 token 后面的中继，靠本地信息给不出这个结论。

端到端的样子见 [`examples/typescript`](../../examples/typescript/README.md)——curl 取公钥、关掉节点、离线验通。

## 三条实现决定，改之前先读理由

### 1. 自带 JSON 解析器，不用 `JSON.parse`

不是造轮子。`JSON.parse` 对重复成员是「后者胜」且静默：

```text
{"amount":1,"amount":9999}   JSON.parse ──▶  {"amount":9999}
```

拿到解析结果时，签名旁路（规范 §5.4）已经看不见了。重复键检测**必须在解析过程中**完成。

### 2. 整数判定在十进制字面量上做，不经过 double

`9007199254740991.0000000000001` 舍入后恰为安全整数。`Number.isInteger` 路线会接受它，并签下 `9007199254740991`——一个线上从未出现过的值。见规范 §7.2 的澄清段。

### 3. 键序用 JS 的 `<`，不要换成 `localeCompare`

`<` 比较 UTF-16 代码单元，正是规范 §5.2 要求的序。`localeCompare` / `Intl.Collator` **不是**。换掉它会让 BMP 外键名的跨语言字节一致性失效，而所有 ASCII 测试照绿——这是本仓库最容易悄悄坏掉的一条。

## 错误码

失败一律带 `code`。规范只说「报错终止」在测试里不可判定：三个实现都抛异常但抛的不是同一件事时，测试仍会绿。

**规范化**（`CanonicalError`）：

| 码 | 触发 | 出处 |
|---|---|---|
| `duplicate_key` | 同一 object 内成员名重复（解码后比较） | §5.4 |
| `lone_surrogate` | 未成对代理项 | §6.4 |
| `non_integer_number` | 数学值非整数 | §7.2 |
| `number_out_of_range` | \|值\| > 2⁵³−1 | §7.2 / §7.3 |
| `non_finite_number` | `NaN` / `±Infinity` 字面量 | §7.5 |
| `top_level_not_object` | 顶层非 object | §4.2 |
| `malformed_json` | 根本不是合法 JSON | 实现补充 |
| `unsupported_value` | `undefined` / `bigint` 等非 JSON 值 | 实现补充，仅值入口可达 |

前六个是规范 §11 的**稳定集**，三语言必须一致；后两个是实现补充，故意留在稳定集之外。

**密钥与 JWKS**（`CryptoError`）：

| 码 | 触发 |
|---|---|
| `key_not_found` | `kid` 不在该 `catalog_id` 的 JWKS 中 |
| `alg_not_supported` | `kid` 命中了，但不是 Ed25519 签名密钥，或请求的 `alg` 非 `EdDSA` |
| `jwks_expired` | 缓存过期且回源失败——**拒绝用过期密钥验签** |
| `jwks_unavailable` | 无缓存且回源失败 |
| `jwks_malformed` | JWKS 文档本身不合法（无 `keys` 数组 / 密钥无 `kid` / `kid` 重复） |
| `invalid_key` | JWK 形状对但内容不可用（如 `x` 长度不是 32 字节） |
| `invalid_encoding` | 不是无填充 base64url |

`key_not_found` 与 `alg_not_supported` 与归因规范 §8 同名，T4 的验证器会给它们附上 `hop` 再抛出去。

### 几条刻意的取舍

**`key_not_found` 与 `alg_not_supported` 必须可分。** JWKS 里非 Ed25519 的密钥被**索引而不是丢弃**：丢弃的话，「该节点在这个 kid 下发的是 ES256 密钥」会退化成 `key_not_found`，把两个错误码并成一个，失败现场就读不出来了。一个说「你找错节点了」，一个说「那个节点发了我不会用的东西」。

**过期的密钥材料绝不使用。** 回源失败时不回落到过期缓存，而是删掉它并报 `jwks_expired`。回落的实现会在节点已经吊销密钥之后继续接受它的签名——而这正是吊销要关的那个窗口。

**`kid` 未命中会触发一次轮换探测，但有冷却。** 未命中是密钥轮换的正常症状，所以允许提前回源一次；没有冷却的话，携带随机 `kid` 的凭证就是一条免费的放大通道（每条凭证打一次目录节点）。冷却从**上次尝试**算起，不是上次成功，否则 JWKS 挂掉的节点会被每条凭证探一次。

**JWKS 里 `kid` 重复 → 整份文档失败。** 任选其一意味着验签结果取决于数组顺序，而能往 JWKS 追加内容的攻击者正好控制这个顺序。

**验签失败返回 `false`，算法不支持则抛异常。** 「这个签名不对」是数据事实，验证器要能记下来继续往下走；「这个算法我评估不了」是配置与信任问题，不能被静默记成一次签名不匹配。

## 状态

- ✅ TypeScript：规范化（Level 1）、Ed25519、JWKS
- ⏸ Python / Go：backlog。75 条向量语言中立，补实现不会返工（两周计划 §5 已登记这个代价：**两周内只有 TS 能验签**）
- ⛔ Level 2（完整双精度）：v1 不实现，见规范 §7.4。需要签含金额的对象时，**首选把金额改成最小单位整数**，不是实现 Level 2
