# ocp.catalog.attribution.v1

`ocp.catalog.attribution.v1` 冻结 OCP Catalog 的**商业归因**对象：一笔成交是谁带来的，如何被第三方独立验证。

规范文档：[`docs/specs/attribution/v1.md`](../docs/specs/attribution/v1.md)。本 README 只讲机读契约，语义与理由全在规范里。

## Scope

本包冻结的对象：

| Schema | 谁产生 | 何时 |
|---|---|---|
| `AttributionToken` | 目录节点 | `resolve` 响应 |
| `AttributionChainNode` | 每一跳目录节点 | 转发时追加 |
| `ConversionReport` | 商户 | 成交时 |
| `AttributionContext` | 代理 / 中继节点 | `resolve` 请求 |

它**不**冻结：签名算法的字节格式、JWKS 发现流程（属 `docs/specs/crypto/`）、分账比例与对账流程（明确非目标）。

## 文件结构

```text
ocp.catalog.attribution.v1/
├── README.md
├── package.json
├── common.schema.json                   # 共享 $defs 与错误码枚举
├── attribution-token.schema.json        # AttributionToken
├── attribution-chain-node.schema.json   # AttributionChainNode
├── conversion-report.schema.json        # ConversionReport
└── attribution-context.schema.json      # AttributionContext（请求侧输入）
```

`$id` 基址 `https://ocp.dev/schema/ocp.catalog.attribution.v1/`，与 `ocp.catalog.handshake.v1` / `ocp.catalog.registration.v1` 一致。`package.json` 采用 `ocp.catalog.registration.v1` 的形态（`name` / `type` / `files`）。

## 实现者必读的三条

这三条**无法由 JSON Schema 表达**，纯靠 schema 校验会漏掉，必须在代码里另行实现：

### 1. `hop` 必须等于数组下标 + 1

Schema 只能约束 `hop` 在 `[1, 8]`，不能约束它与位置的对应关系。链重排攻击会产生一条**schema 完全合法**的凭证。

校验：`chain[i].hop === i + 1`，以及 `chain[0].role === "origin"` 且其余为 `"relay"`，以及 `catalog_id` 在链内不重复。失败码 `chain_broken`。

### 2. `complete` 必须重算，禁止采信

顶层 `complete` 不在任何签名材料内。Schema 只校验它是 boolean。

校验：`complete === chain.every(n => n.chain_complete)`。失败码 `complete_mismatch`。

### 3. 签名输入不是「整个 token」

第 N 跳签的是：

```text
OCP-JCS-v1({ "chain": [unsigned(1..N)], "core": <core claims> })
```

`unsigned(node)` = 该节点删去 `signature` 后的其余全部字段；`core claims` = token 去掉 `complete` 与 `chain`。

直接对整个 token 签名或验签一定失败。详见规范 §5.2。

## 金额禁止浮点

`amount_minor` 是最小货币单位**整数**（`12900` + `"CNY"` = ￥129.00）。

这不是风格偏好：[OCP Canonical JSON v1.0](../docs/specs/crypto/canonicalization.md) §7 的 Level 1 只接受安全整数，浮点数的字节表示在 TypeScript / Python / Go 间无法统一，**用浮点承载金额会让凭证在跨语言验签时直接失败**。

## 错误码

11 个稳定取值集中在 `common.schema.json#/$defs/AttributionErrorCode`，语义与判定顺序见规范 §7.1 / §8。

**验证顺序是规范性的**：必须按规范 §7.1 表格行序执行，遇首个失败即终止。顺序不固定的话，一条同时违反多项的凭证在不同实现下会报出不同错误码，一致性测试形同虚设。

## 与既有 schema 的关系

Zod 侧挂载在 `packages/ocp-schema`，**全部为可选字段**：

| 位置 | 字段 |
|---|---|
| `resolveRequestSchema` | `attribution_context` |
| `actionBindingSchema` | `attribution` |

`catalogQueryRequestSchema` 是 `.strict()`，本包**不碰**。

不含上述字段的旧 payload 必须继续通过校验——回归断言见 `packages/ocp-schema/src/attribution.test.ts`。
