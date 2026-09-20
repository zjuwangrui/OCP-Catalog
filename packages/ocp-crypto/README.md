# @ocp-catalog/ocp-crypto

OCP Catalog 的规范化、签名与密钥发现实现。五块内容：

| 模块 | 规范 | 内容 |
|---|---|---|
| `canonical.ts` | [OCP Canonical JSON v1.0](../../docs/specs/crypto/canonicalization.md) | OCP-JCS v1 规范化、`sha256:` 哈希 |
| `keys.ts` | [归因规范 §5](../../docs/specs/attribution/v1.md) | Ed25519 生成 / 签名 / 验签、JWK 形态 |
| `jwks.ts` | [归因规范 §7.1](../../docs/specs/attribution/v1.md) 第 4 行 | JWKS 加载、`kid` 解析、TTL 缓存 |
| `attribution.ts` | [归因规范 §4.3 / §5.2 / §5.3 / §5.4](../../docs/specs/attribution/v1.md) | 核心声明、逐跳签名材料、`complete` 重算、链结构校验、origin 签发与 relay 追加 |
| `verify.ts` | [归因规范 §7.1 / §8](../../docs/specs/attribution/v1.md) | 完整验证器：逐跳验签并定位到跳、`jti` 防重放、有效期与 provider 匹配 |
| `settlement.ts` | [归因规范 §6 / §7.1 第 11 行 / §7.2 / §7.3](../../docs/specs/attribution/v1.md) | `ConversionReport` 结算：`order_id` 去重、`report_id` 幂等、last-touch 裁决、退款冲正 |

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

`attribution.ts` 只做**签发**和**单跳验签**——重放、过期、provider 匹配、逐跳错误定位在 `verify.ts`，它们要配着自己需要的策略状态一起写。放在 `attribution.ts` 的是签名方和验证方**必须逐字节一致**的那部分，两边调同一份代码才不会漂。

### 多跳：接在别人的 token 后面

```ts
import { appendRelayHop } from '@ocp-catalog/ocp-crypto';

const relayed = appendRelayHop({
  privateJwk, kid, catalogId: 'cat_relay_a',
  token: upstreamToken,        // core claims 原样带走，一个字都不能改
  chainComplete: true,         // 故意没有默认值
  settles: true,               // 默认 false
});
```

`chainComplete` 必须显式给，因为两个默认值都是错的：给 `true` 会让一次随手的接入声明出它背不起的「无未记录上游」，给 `false` 会让每条链都不完整、这个字段就作废了。而 `settles` 默认 `false`——少报一份自己应得的分成还能补，多报一份就是用自己的私钥签下一条假结算声明。

**追加之前必须先验上游链**（`verifyAttributionToken`）。§5.2 让第 N 跳的签名永久覆盖第 1..N−1 跳，所以在一条没验过的链上联署，等于把本节点的名字签在别人的伪造上。

### 完整验证器

```ts
import { verifyAttributionToken, staticKeyResolver, JtiRegistry } from '@ocp-catalog/ocp-crypto';

const verdict = await verifyAttributionToken({
  token,
  resolveKey: staticKeyResolver({ cat_origin: originJwks, cat_relay_a: relayJwks }),
  at: report.occurred_at,                       // 成交时刻，不是验证时刻
  expectedProviderId: report.provider_id,
  replayGuard: { registry, orderId: report.order_id },
});

if (!verdict.ok) console.error(verdict.error.code, verdict.error.hop);
else console.log(verdict.settlingCatalogIds, verdict.complete, verdict.lastSignedAt);
```

失败返回**结果**而不是抛异常：结算方手上有好几条候选凭证，必须先记下每条为什么出局，再在幸存者之间裁决（§7.2）。一次拒绝是数据。

`at` 是**成交时刻**。第 8、9 行问的是交易发生时凭证是否在窗口内；拿「此刻」去比，会把一笔迟报一小时的正常成交拒掉。

**取不到密钥和凭证是假的，必须分开。** `jwks_unavailable` / `jwks_expired` / `jwks_malformed` 会让 Promise **reject**，不会变成 `ok: false`——密钥服务器宕机的节点并没有伪造任何东西，把它的故障记成 `key_not_found` 等于按伪造来结算它。只有「那个 `kid` 下确实发布了的东西不可用」才是判决（规范 v1.0.1 已写进 §8）。

**第 3–5 行按 alg → key → signature 跑，跳号升序。** 规范 v1.0 把这三行印成 signature → key → alg，而那个顺序执行不了：验签得先有公钥，先验签再查 `alg` 更是把 §5.1 要堵的算法混淆重新打开了一次。升序是规范性的——§5.2 的第 2 条性质说改第 K 跳会让第 K..N 跳全失效，所以**最小的失效跳号才是篡改位置**，报别的跳就是指认无辜节点。规范已按此更正（§7.1，v1.0.1）。

### `JtiRegistry` 是内存实现，上生产前必须换掉

这不是注意事项，是一条有名字的正确性缺口：

1. **重启即清空**——重启前签发的每一条凭证都能再被重放一次。夜间重启的结算进程有一个夜间重放窗口。
2. **按进程隔离**——负载均衡后面的两个结算 worker 各持一份 map，同一条凭证在每份里都能被认领一次。

替代物是**和结算记录同一个事务性存储里的一行**，`jti` 为键、`order_id` 在旁边：认领和打款必须一起提交，否则钱动了之后守卫还可能丢。写满时它**抛异常而不是淘汰**——淘汰会在进程最忙的那一刻悄悄打开它本来要关的那个窗口。

换的接口已经在包里：`JtiRegistry` 实现的是 [`ReplayStore`](./src/stores.ts)，`settleOrder` 只认这个接口，所以换存储不用动裁决逻辑。方法允许返回 `Promise`——持久化 store 的每次认领都是一次网络调用，只能返回 `boolean` 的接口除了另一个 `Map` 谁都实现不了。事务契约见 [`docs/specs/attribution/settlement-stores.md`](../../docs/specs/attribution/settlement-stores.md)。

保留期是**推导出来的，不是配置项**：条目留到凭证自己的 `exp`。过了那一刻第 9 行本来就会拒掉它，再记住这个 `jti` 也保护不了任何东西。

### 结算：从「这张凭证是真的」到「这笔订单付给谁」

`verifyAttributionToken` 判一张凭证。`settleOrder` 判**一笔订单**——几个商户的回报各自带着凭证来争，谁拿钱、以及怎么保证没人拿两次。

```ts
import { SettlementLedger, JtiRegistry, settleOrder } from '@ocp-catalog/ocp-crypto';

const ledger = new SettlementLedger();
const jtiRegistry = new JtiRegistry();

const result = await settleOrder({
  reports,                    // 同一个 order_id 的全部回报
  resolveKey,
  ledger,
  jtiRegistry,
  rule: 'last_touch',         // 默认；§7.4 允许改成 first_touch，但**必须公示**
});

if (!result.ok) console.error(result.error.code);           // duplicate_order / replayed_jti / …
else if (result.action === 'settled') console.log(result.record.agentId, result.record.settlingCatalogIds);
```

顺序是固定的，每一步都能单独说出理由：

1. **§7.1 第 1–10 行逐条候选跑一遍**，各自按自己回报的 `occurred_at` 和 `provider_id` 判。第 10 行**只读不认领**。
2. **§7.2 在幸存者里裁决**。`confirmed` 先争；全是 `pending` 就挂起而不是付钱。
3. **先 `report_id` 幂等，再第 11 行 `duplicate_order`**。
4. **认领 `jti` 与写账一起落**。

#### `report_id` 和 `order_id` 是两把钥匙，合成一把就一定错

§6.1 给回报两个标识是有分工的：

- `report_id` 是**回报自己的**幂等键。网络会重投，同一份回报到两次必须只结一次、并返回同一个答案。
- `order_id` 是**结算的**去重键（§7.1 第 11 行）。同一笔订单上换一份新回报，那是第二次认领同一笔成交。

只按其中一把去重：按 `report_id` 就会给每一次重复认领都付钱，按 `order_id` 就会把每一次正常重投拒成 `duplicate_order`。所以顺序也是固定的——幂等在前，第 11 行在后。

#### 输家不认领 `jti`

第 10 行对每个候选都查，只对赢家写。替输家认领会把它的 `jti` 绑到一笔它根本没结算的订单上——那样第一个看到这张凭证的结算方只要让它输一次，就永久花掉了它。

#### 冲正不重开订单

`refunded` / `cancelled` 会把订单记录改成冲正状态，但**不会**让它重新可结算。否则「退款→再确认」就是绕过第 11 行的洗单路径。真的又成交一笔，那是一个新的 `order_id`。

#### `SettlementLedger` 也是内存的，而且这一个管着钱

同 `JtiRegistry` 的缺口，赌注更大：这张 map 是一笔成交和两次打款之间唯一的东西，重启就等于把所有历史订单重新放开一次。替代物是一张在 `order_id` 上**带唯一约束**的表，和打款同一个事务写入——不是在它前面加缓存：插入和打款能分开提交，就存在「钱动了、去重行没落」的窗口，而那正是它要挡的那次重复打款。

它也没有过期和上限，这是故意的：已结算的订单不允许老化淘汰，忘掉一笔就等于放它再结一次。

对应的接口是 [`LedgerStore`](./src/stores.ts)，和 `ReplayStore` 一起由 `settleOrder` 的 `transaction` 参数串起来：认领 `jti` 与写入结算记录发生在同一个回调里，回调抛错就整体回滚。默认值 `nonTransactional` 直接执行回调——内存实现下等价，生产上配错了也能在 code review 里看见，这是它没被写成匿名箭头的原因。两条规则的完整事务契约见 [`docs/specs/attribution/settlement-stores.md`](../../docs/specs/attribution/settlement-stores.md)：**先打款后认领是唯一救不回来的方向**——认领了没打款，重试会对着同一个 `order_id` 补上；打款了没认领，这张凭证还能对着另一个 `order_id` 再结一次，而事后没有任何东西能把它和一笔真的复购区分开。真实的 SQL / 事务存储实现在 `ocp-catalog-instances`：协议仓定契约，运行时选存储。

端到端的样子见 [`examples/typescript`](../../examples/typescript/README.md)——curl 取公钥、关掉节点、离线验通、离线结算。

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

`key_not_found` 与 `alg_not_supported` 与归因规范 §8 同名，`verify.ts` 的验证器直接透传这两个码并补上 `hop`，不另起一套。

**归因**（`AttributionError`，规范 §8 的 11 个码）：结构与裁决层面的失败，凡是能定位到跳的都带 `hop`。完整列表与顺序见 `ATTRIBUTION_ERROR_CODES`，以规范 §8 为准。

### 几条刻意的取舍

**`key_not_found` 与 `alg_not_supported` 必须可分。** JWKS 里非 Ed25519 的密钥被**索引而不是丢弃**：丢弃的话，「该节点在这个 kid 下发的是 ES256 密钥」会退化成 `key_not_found`，把两个错误码并成一个，失败现场就读不出来了。一个说「你找错节点了」，一个说「那个节点发了我不会用的东西」。

**过期的密钥材料绝不使用。** 回源失败时不回落到过期缓存，而是删掉它并报 `jwks_expired`。回落的实现会在节点已经吊销密钥之后继续接受它的签名——而这正是吊销要关的那个窗口。

**`kid` 未命中会触发一次轮换探测，但有冷却。** 未命中是密钥轮换的正常症状，所以允许提前回源一次；没有冷却的话，携带随机 `kid` 的凭证就是一条免费的放大通道（每条凭证打一次目录节点）。冷却从**上次尝试**算起，不是上次成功，否则 JWKS 挂掉的节点会被每条凭证探一次。

**JWKS 里 `kid` 重复 → 整份文档失败。** 任选其一意味着验签结果取决于数组顺序，而能往 JWKS 追加内容的攻击者正好控制这个顺序。

**验签失败返回 `false`，算法不支持则抛异常。** 「这个签名不对」是数据事实，验证器要能记下来继续往下走；「这个算法我评估不了」是配置与信任问题，不能被静默记成一次签名不匹配。

## 状态

- ✅ TypeScript：规范化（Level 1）、Ed25519、JWKS、归因签发（origin / relay）、完整验证器、`ConversionReport` 结算与裁决
- ✅ Python / Go：规范化与文档签名已补齐，3×3 互操作矩阵全绿（`scripts/interop/signature-matrix.mjs`）。归因签发与结算仍只有 TS
- ⚠️ `JtiRegistry` 与 `SettlementLedger` 只是**演示实现**（内存）。生产要实现 `ReplayStore` / `LedgerStore` 并接上真实事务，见 [`docs/specs/attribution/settlement-stores.md`](../../docs/specs/attribution/settlement-stores.md)
- ⛔ Level 2（完整双精度）：v1 不实现，见规范 §7.4。需要签含金额的对象时，**首选把金额改成最小单位整数**，不是实现 Level 2
