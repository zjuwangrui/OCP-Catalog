# OCP 加密与归因 · 需求确认与方案草案

| 项目 | 内容 |
|---|---|
| 状态 | **草案（Draft）· 待需求确认** |
| 版本 | v0.1 |
| 日期 | 2026-09-01 |
| 目标读者 | 协议负责人 / 技术主管 |
| 定位 | 本文**不是**协议规范。它盘点现状、给出范围选项与字段设计草图，用于确认需求边界后再立项写正式 spec。 |

---

## 1. 这件事在路线图上的位置

"加密"与"归因"并非新话题，[`apps/ocp-site-web/src/content/roadmap.ts`](../../apps/ocp-site-web/src/content/roadmap.ts) 里已有对应条目，均处于 `planned` 状态：

| 阶段 | 条目 | 路线图原文 |
|---|---|---|
| `commerce` 交易层 | **分佣分账机制** | "让参与路由和解析交易的各方能被**公平归因**和结算" |
| `trust` 信任与网络 | **更强的加密与安全** | "协议层面更强的加密与安全，端到端保护请求、载荷与身份" |
| `trust` 信任与网络 | 交易行为上链追溯 | "让关键交易动作拥有可验证、可审计的记录" |

即：**把 OCP 从"只能发现"推进到"可信任、可结算"**。

---

## 2. 核心判断：加密与归因是同一件事的两面

设想 Agent 代用户下单的完整链路：

```text
User Agent ──query/resolve──▶ Catalog Node ──action_binding──▶ Provider（商户）下单
```

商户凭什么相信"这笔订单是 Agent X 经由 Catalog Y 带来的"，从而支付佣金？

**如果归因信息只是明文字段，任何人都能伪造 `catalog_id` 骗取分佣。** 归因一旦不可验证，商业上即等于零。

因此本方案的核心命题是：

> **构建一套"可验证的归因凭证"（Verifiable Attribution Credential）。加密是它的地基，归因是它的用途。**

- **加密** = 让每一跳的身份与载荷**可证明未被篡改**（签名 / 验签 / 密钥分发）
- **归因** = 让"这次转化归谁"**可被第三方独立验证**（带签名的凭证沿链路传递）

两者拆开做都不成立：只做加密没有商业出口，只做归因没有防伪能力。

---

## 3. 现状盘点：两处"已占位、未实现"的空洞

这是本方案的事实基础——协议**已经预留了字段，但没有任何机制与实现**。

### 3.1 加密侧：只有声明位，没有算法

| 位置 | 现有字段 |
|---|---|
| [`catalog-manifest.schema.json:344`](../../ocp.catalog.handshake.v1/catalog-manifest.schema.json) | `trust_strategy.{manifest_signed, signature_algorithms, domain_verified, trust_tier, downgrade_invalidates_cache}` |
| [`catalog-route-hint.schema.json:38-52`](../../ocp.catalog.registration.v1/catalog-route-hint.schema.json) | `trust_profile.{manifest_signed, signature_alg, manifest_hash, issuer}` |
| [`packages/ocp-schema/src/index.ts:266`](../../packages/ocp-schema/src/index.ts) | 上述字段的 Zod 镜像 |
| [`packages/registration-schema/src/index.ts:132`](../../packages/registration-schema/src/index.ts) | `signature_alg` |

**问题**：全仓 `signature` 关键字仅 6 处命中，**全部是字段声明**。未定义：

- 签名格式（JWS？COSE？detached？）
- canonical 序列化规则（字段序、空值、浮点表示）
- 密钥发布位置与轮换方式（JWKS？DID？`.well-known`？）
- 验签失败时的降级行为（虽然 `downgrade_invalidates_cache` 已占位）

**零实现代码。** `manifest_signed: true` 目前是一句无法被检验的自我声明。

已落地的只有**身份验证**（注意：不等于报文完整性）：

- [`catalog-verification-challenge.schema.json`](../../ocp.catalog.registration.v1/catalog-verification-challenge.schema.json) 支持 `dns_txt` 与 `https_well_known` 两种域名挑战（ACME 风格）
- 认证层面仅 `api_key` / `bearer`，配 `catalog-token-rotation-result` 做 token 轮换

[`docs/specs/registration/v1.md:527`](../specs/registration/v1.md) 的"安全与治理原则"更接近一张待办清单：

> refresh/update 操作应要求 catalog-specific token、**signed manifest** 或重新验证。

"signed manifest"四字已写入规范，但从未被定义。

### 3.2 归因侧：两段链条，中间断裂

**上游已有**——对象级来源记录 `CommercialObject.provenance` → [`ProvenanceRecord`](../../ocp.catalog.handshake.v1/common.schema.json)：

```text
authority_type / provider_id / source / source_site / source_uri /
source_object_id / source_variant_id / collected_at / verified_at /
verification_status / trust_tier / evidence
```

配套 `ObjectContract.provenance_requirements` 声明 Catalog 接受哪些权威来源。
回答的是：**"这条数据从哪来"**。

**旁路已有**——调用链追踪 [`packages/ocp-activity-schema/src/index.ts`](../../packages/ocp-activity-schema/src/index.ts)：

```text
correlation_id / trace_id / span_id / parent_event_id / payload_hash
公开投影降级为 correlation_id_hash
```

回答的是：**"这次调用是谁发起的"**。

**断点在这里**——[`actionBindingSchema:626-637`](../../packages/ocp-schema/src/index.ts)：

```ts
export const actionBindingSchema = z.object({
  action_id, action_type, label, description,
  entrypoint, input_schema_url, input_schema,
  auth_requirements, requires_user_confirmation, expires_at,
});
```

**没有任何归因字段。** Agent 拿 `entrypoint` 去下单，商户侧无从证明这单归谁。

同样地，[`resolveRequestSchema:611-619`](../../packages/ocp-schema/src/index.ts) 有 `purpose: view | checkout | contact | workflow`——`checkout` 正是归因发生的时刻，但请求里**没有调用方身份**。

`payload_hash` / `audit_id` 只存在于**事后的 activity 日志**，不在协议报文中，因此它们是**可观测性**，不是**可验证性**。

> **这个断点，就是本方案要补的洞。**

---

## 4. 范围选项（需主管拍板）

三档范围的工作量差一个数量级。以下工期按 1 人投入估算，不含评审与联调等待。

### S 档 · 只做加密（2–3 周）

补齐签名机制，把已有的 `manifest_signed` / `signature_algorithms` / `manifest_hash` / `issuer` 从"声明位"变成"可验证事实"。

- 定义 `SignatureEnvelope` 与 canonical 序列化规则
- 定义密钥发布与轮换（`.well-known` + JWKS）
- 只签 `CatalogManifest` 与 discovery 文档
- 交付：spec 章节 + JSON Schema + Zod + 验签实现 + 示例节点接入

**价值**：解决"Catalog 冒名 / manifest 被篡改"，但**不产生商业出口**。

### M 档 · 加密 + 归因凭证（5–7 周）✅ 建议起点

S 档全部内容，外加：

- `AttributionContext`：请求侧声明调用方身份（Agent / Catalog）
- `AttributionToken`：Catalog 在 resolve 时签发的**签名凭证**，嵌入 `action_binding`
- Provider 侧验签流程与拒绝语义
- 与 activity 事件的 `correlation_id` 打通，形成端到端可审计链路

**价值**：商户可独立验证"这单归谁"，**为分佣结算提供协议基础**。

**明确不含**：资金流转、费率计算、对账结算——本档只产出**可信的归因事实**。

### L 档 · 完整交易层（季度级，建议单独立项）

M 档全部内容，外加分账规则引擎、结算对账、交易行为上链存证。

**建议**：上链选型（链、成本、合规）与结算涉及财务系统，应独立立项，不与协议层混做。

---

## 5. 技术方案草图

> 以下为讨论用草图，**非最终设计**。字段名待评审。

### 5.1 加密：签名信封

```jsonc
// SignatureEnvelope — 附着在被签对象上，detached 风格
{
  "alg": "EdDSA",              // MUST: Ed25519；SHOULD: ES256
  "kid": "cat_example#key-1",  // 指向 JWKS 中的密钥
  "issuer": "https://catalog.example.com",
  "signed_at": "2026-09-01T00:00:00Z",
  "expires_at": "2026-09-08T00:00:00Z",
  "payload_hash": "sha256:...",  // 对 canonical JSON 求哈希
  "signature": "base64url..."
}
```

要点：

1. **Canonical 化采用 JCS（RFC 8785）**，避免各语言 JSON 序列化差异导致验签失败——examples 有 TS/Python/Go 三实现，这点必须先钉死。
2. **密钥发现**：`/.well-known/ocp-catalog` 增加 `jwks_url`，复用已有的 discovery 端点，不新增发现机制。
3. **分层签名**，按价值排优先级：

   | 层级 | 被签对象 | 优先级 |
   |---|---|---|
   | T1 | `CatalogManifest`、discovery 文档 | 必做（S 档） |
   | T2 | `ResolvableReference` + `ActionBinding` | 归因依赖（M 档） |
   | T3 | `ObjectSyncRequest` / Provider 上行数据 | 可延后 |

4. **降级语义**：验签失败时 route hint 的 `trust_tier` 降级，并触发已有的 `downgrade_invalidates_cache`。

### 5.2 归因：可验证归因凭证

**请求侧**——`ResolveRequest` 增加可选的调用方声明：

```jsonc
{
  "entry_id": "entry_...",
  "purpose": "checkout",
  "attribution_context": {          // 新增，optional
    "agent_id": "agent_...",
    "agent_issuer": "https://agent-platform.example.com",
    "session_ref": "opaque-hash",   // 不含 PII
    "upstream_catalog_id": "cat_..." // 多跳/联邦场景
  }
}
```

**响应侧**——`ActionBinding` 携带 Catalog 签发的凭证：

```jsonc
{
  "action_id": "checkout",
  "action_type": "url",
  "entrypoint": { "url": "https://merchant.example.com/cart/...", "method": "GET" },
  "attribution": {                  // 新增，optional
    "token": "eyJ...",              // 签名后的紧凑串
    "claims": {                     // 明文镜像，便于调试
      "catalog_id": "cat_...",
      "agent_id": "agent_...",
      "entry_id": "entry_...",
      "object_id": "sku-001",
      "provider_id": "prov_...",
      "issued_at": "...",
      "expires_at": "...",
      "nonce": "..."                // 防重放
    },
    "verify_url": "https://catalog.example.com/.well-known/jwks.json"
  }
}
```

**Provider 验证流程**：收单 → 取 `token` → 拉 `verify_url` 的 JWKS → 验签 → 校验 `expires_at` 与 `nonce` 未重放 → 记账归因。

**多跳归因**：联邦场景下 token 可嵌套（类似证书链），由 `upstream_catalog_id` 串联。此处需评审——嵌套深度与信任传递规则是复杂度来源，M 档建议**先只支持单跳**。

### 5.3 向后兼容性（重要工程约束）

已核查各 schema 的 strict 性质，直接决定改动成本：

| Schema | 是否 `.strict()` | 加可选字段的影响 |
|---|---|---|
| `actionBindingSchema` | 否 | ✅ 向后兼容 |
| `resolvableReferenceSchema` | 否 | ✅ 向后兼容 |
| `resolveRequestSchema` | 否 | ✅ 向后兼容 |
| `catalogQueryRequestSchema` | **是** | ⚠️ 新字段会被现有校验拒绝，需版本协商 |

**结论**：归因凭证走 resolve 链路（M 档设计）**几乎零破坏性**；若将来要在 query 阶段带归因上下文，必须走版本升级流程。这是把归因锚定在 resolve 而非 query 的技术理由之一——另一个理由是 `purpose: "checkout"` 本就标识了转化意图。

---

## 6. 边界：本方案不做什么

- ❌ 不定义支付、清算、退款流程（归 Visa VIC / 商户支付层，参见站点 `examples/visa-vic-reference-agent`）
- ❌ 不定义费率与分账规则（L 档）
- ❌ 不替代 Provider 的权威数据源与订单系统
- ❌ 不在 route hint 中放入任何 secret（沿用 registration v1 §17 既有原则）
- ❌ 不引入中心化的归因仲裁方——保持 OCP 去中心化前提，验签由各 Provider 自行完成

---

## 7. 待确认问题清单

| # | 问题 | 备选 | 草案建议 |
|---|---|---|---|
| 1 | 交付物形态？ | 协议规范 / 参考实现 / 技术方案评审 | 先规范后实现，示例节点同步接入 |
| 2 | **"归因"归的是钱还是链路？** | ① 商业归因（分佣）② 链路归因（审计溯源）③ 结果归因（`explain` 可解释性） | ①，兼顾② |
| 3 | **"加密"的边界？** | ① 报文签名验签 ② 字段级加密 ③ 密钥凭证管理 | ①为主，③补齐轮换 |
| 4 | 是否对齐外部标准？ | Visa VIC / ACP / AP2 已有各自 trusted-agent 与归因机制 | 若需对齐，先追加 2 天调研 |
| 5 | 上链是否纳入本期？ | 是 / 否 | 否，单独立项 |
| 6 | 落在哪个仓库？ | 本仓（协议）/ ocp-catalog-instances（实现） | 协议在本仓，节点改动需跨仓协作 |
| 7 | 取哪一档范围？ | S / M / L | **M 档** |

> **关于问题 2 的说明**：中文"归因"存在歧义。仓库中 `CatalogEntryMatch.explain`、`CatalogQueryResult.explain`、`policy_summary.supports_explain` 以及 CLI 的 `--explain` 均已存在，指"为什么召回并如此排序这条结果"。若主管的本意是**查询结果可解释性**，则本方案整体不适用，需重新规划。**此项建议优先澄清。**

---

## 8. 建议的下一步

1. **确认第 7 节问题清单**（尤其 #2 与 #7），预计一次 30 分钟沟通即可闭环
2. 确认后 3 个工作日内产出正式 spec 草案：`docs/specs/attribution/v1.md`（或并入 handshake v1 增补章节）
3. 同步补 JSON Schema 与 Zod，`bun run site:check` 保证文档与规范一致
4. 在 `examples/typescript` 落一个最小验签 + 归因样例，作为可执行的一致性基线

---

## 附录 A · 现状字段索引

| 关注点 | 文件 | 位置 |
|---|---|---|
| manifest 签名声明 | `ocp.catalog.handshake.v1/catalog-manifest.schema.json` | `:344` `trust_strategy` |
| route hint 信任摘要 | `ocp.catalog.registration.v1/catalog-route-hint.schema.json` | `:38-52` `trust_profile` |
| 域名验证挑战 | `ocp.catalog.registration.v1/catalog-verification-challenge.schema.json` | 全文 |
| 对象来源记录 | `ocp.catalog.handshake.v1/common.schema.json` | `:203` `ProvenanceRecord` |
| 来源要求声明 | `packages/ocp-schema/src/index.ts` | `:113` `provenance_requirements` |
| **归因断点** | `packages/ocp-schema/src/index.ts` | `:626-637` `actionBindingSchema` |
| resolve 请求 | `packages/ocp-schema/src/index.ts` | `:611-619` `resolveRequestSchema` |
| 活动事件追踪 | `packages/ocp-activity-schema/src/index.ts` | 全文 |
| 安全治理原则 | `docs/specs/registration/v1.md` | `:527` 第 17 节 |
| 路线图条目 | `apps/ocp-site-web/src/content/roadmap.ts` | `:105-182` |
