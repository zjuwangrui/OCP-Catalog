# OCP 加密与归因 · 7 周实施计划

> ## ⚠️ 本计划已被部分取代（2026-09-11）
>
> 主管确认 **A1 = 商业归因**，并要求归因链在**两周内**完成。现行执行计划为
> [**OCP 商业归因链 · 两周实施计划**](./ocp-attribution-2w-plan.md)。
>
> | 本文档的章节 | 现状 |
> |---|---|
> | W1 Canonical 地基 | ✅ T1 / T2 已完成，T3 并入两周计划 T2 |
> | W2 密钥与 JWKS | 压缩进两周计划 T2 |
> | W3 Manifest 签名 | **移出本期**，进 backlog |
> | W4 三语言互操作 | **推迟**，进 backlog 第 1 优先级 |
> | W5 / W6 归因 | 由两周计划 T1 / T3 / T4 / T5 取代并扩展为多跳链 |
> | W7 收尾 | **推迟**，进 backlog |
>
> 本文档保留为**完整路线图**——两周计划交付后的后续工作仍按此处的拆分推进，
> 其中的 schema strict 性质实测、字段清单、跨仓协作点均未过期。

| 项目 | 内容 |
|---|---|
| 状态 | **已部分取代**（见上） |
| 版本 | v0.2（细化到 21 个 2 天小任务） |
| 日期 | 2026-09-01 |
| 上游文档 | [需求确认与方案草案](./ocp-encryption-and-attribution.md) |
| 采用范围 | **M 档**（加密 + 归因凭证，不含结算与上链） |
| 节奏 | 7 周 × 3 个小任务 = **21 个小任务**，每个约 2 天，每周五交付一个可演示产出 |

---

## 0. 前提与假设

本计划按草案第 7 节的**建议值**推进。以下假设若被推翻，需重新规划——请在 **W1-T1** 的闸门会上确认：

| # | 假设 | 若不成立的影响 |
|---|---|---|
| A1 | **"归因" = 商业归因**（谁带来这笔交易，可结算），非查询结果可解释性（`explain`） | ✅ **已确认成立**（2026-09-11，主管批注）。闸门关闭 |
| A2 | 范围取 M 档：产出"可信的归因事实"，**不含**资金流转与费率计算 | 🟡 工期翻倍，需拆独立项目 |
| A3 | 加密以**报文签名验签**为主，字段级加密不在本期 | 🟡 +2～3 周 |
| A4 | 不强制对齐 Visa VIC / ACP / AP2，先做 OCP 自有机制 | 🟡 +2 天调研，可能改 token 结构 |
| A5 | 上链存证不在本期 | 🟢 已按此排期 |
| A6 | 协议改动落本仓，节点侧改动由 `ocp-catalog-instances` 承接 | 🟡 需跨仓协作窗口 |

> **A1 的确认方式**：一句话问清"这个归因的下游是财务分账，还是搜索质量分析？"
> 完整确认单见 [A1 归因口径确认单](./a1-attribution-scope-gate.md)（W1-T1 产出）。

### 关于「3 × 2 天 = 6 天」与 5 天工作周

三个 2 天小任务合计 6 个工作日，标准工作周只有 5 天。本计划的默认落法：

| 小任务 | 工作日 | 实做时长 |
|---|---|---|
| T1 | 周一 – 周二 | 2 天 |
| T2 | 周三 – 周四 | 2 天 |
| T3 | 周五 | **1 天实做 + demo/合入**，第 6 天记为溢出缓冲 |

**T3 一律安排整周中最轻的一项**（集成、CLI 封装、演示脚本），因为它实际只有 1 天。若团队跑 6 天工作周，T3 可用满 2 天，与"两天一个小任务"1:1 对齐。

---

## 1. 里程碑总览

```text
W1  Canonical 地基     ──┐
W2  密钥与 JWKS          │  加密侧（= S 档范围）
W3  Manifest 签名闭环    │
W4  三语言互操作 ────────┘  ★ 可独立发布点
W5  归因模型定稿       ──┐
W6  归因凭证端到端       │  归因侧
W7  可观测性 + 文档 ─────┘  ★ M 档完成
```

| 周 | 主题 | T1（周一二） | T2（周三四） | T3（周五） | 周五可演示 |
|---|---|---|---|---|---|
| W1 | Canonical 地基 | 闸门 + 规范起草 | 测试向量集 | TS 实现 | 乱序后哈希不变 |
| W2 | 密钥与 JWKS | 补 discovery schema | 密钥与 JWKS 能力 | CLI + 节点暴露 | `curl` 拿到公钥 |
| W3 | Manifest 签名 | 签名格式定稿 | 节点签发 | CLI 验签 + 反例 | 篡改一字节即失败 |
| W4 | 三语言互操作 | Python 验签 | Go 验签 | 交叉矩阵 + 信任落地 | **3×3 矩阵 9 格全绿** |
| W5 | 归因模型 | 规范起草 | Schema 落地 | 零破坏回归 | 新旧 payload 并排通过 |
| W6 | 归因凭证 | 签发侧 | 验证侧 + 防重放 | CLI + 演示脚本 | 四条断言逐条通过 |
| W7 | 收尾 | activity 打通 | 站点文档四件套 | skill + 发布 | 站点读到新文档页 |

---

## 2. 逐周计划

### W1 · Canonical JSON 地基

**为什么第一周做这个**：examples 有 TS / Python / Go 三套实现，三种语言的 JSON 序列化在**键序、Unicode 转义、浮点表示、空值**上各行其是。签名验证对字节敏感，这个不先钉死，后面每一周都会踩。**它是整条链路的单点故障。**

| 小任务 | 天 | 内容 | 完成判据 |
|---|---|---|---|
| **W1-T1** | 周一二 | ① **A1 假设闸门会**（30 分钟，最优先）<br>② `docs/specs/crypto/canonicalization.md` 起草——JCS（RFC 8785）子集<br>③ 定稿四条规则：键序 / Unicode 转义 / 数字表示 / 空值处理 | 四条规则**无歧义**，可交付他人独立实现 |
| **W1-T2** | 周三四 | `packages/ocp-crypto/fixtures/canonical/*.json`——**≥20 条测试向量**，覆盖键序、深层嵌套、Unicode、转义、数字边界、空数组 / 空对象 | 每条向量含 `input_raw` + `expected_canonical` + `expected_sha256`（接受类）或 `input_raw` + `expected_error`（拒绝类）；拒绝类错误码有统一取值 |
| **W1-T3** | 周五 | `packages/ocp-crypto` 包骨架（对齐现有 8 个包形态）+ TS 版 `canonicalize()` | `bun test` 绿，20 条向量全过 |

> **向量优先写边界情形，不写 happy path。** 覆盖不足的代价是 W4 才暴露差异，届时返工三种语言。

- **涉及文件**：`docs/specs/crypto/`（新）、`packages/ocp-crypto/`（新）。根 `package.json` 的 workspaces 已含 `packages/*`，无需改
- **周五演示**：同一对象的两种字段序 → canonical 输出逐字节相同 → SHA-256 一致

---

### W2 · 密钥与 JWKS 发现

**本周附带清一笔历史欠账**：`WellKnownCatalogDiscovery`（`/.well-known/ocp-catalog` 的响应体）**在 `packages/ocp-schema` 里没有任何 Zod schema**——目前是 `examples/typescript/src/server.ts:35` 手写的字面量。要往里加 `jwks_url`，得先把 schema 补上，否则新字段没有任何校验保护。

| 小任务 | 天 | 内容 | 完成判据 |
|---|---|---|---|
| **W2-T1** | 周一二 | ① `wellKnownCatalogDiscoverySchema` 补进 `packages/ocp-schema`（还欠账）<br>② 增加可选 `jwks_url`——**复用既有发现端点，不新增发现机制**<br>③ `examples/typescript` 接入该 schema | `server.test.ts` 新增 discovery 校验断言并通过 |
| **W2-T2** | 周三四 | `ocp-crypto` 密钥能力：Ed25519 keygen / sign / verify；JWKS 加载、`kid` 解析、TTL 缓存 | 单测覆盖**三条错误路径**：`kid` 未命中、JWKS 过期、算法不支持 |
| **W2-T3** | 周五 | ① CLI 新增 `ocp keys generate` / `ocp keys show`（新 `keys` 域，与既有 `catalog`/`registration`/`provider`/`validate` 并列）<br>② `examples/typescript` 暴露 `/.well-known/jwks.json` | 端到端 `curl` 通 |

- **算法选型**：**MUST 支持 Ed25519（EdDSA）**，SHOULD 支持 ES256。理由：Ed25519 在 Go / Python 标准库与 Node WebCrypto 中均原生可用，三语言零依赖
- **周五演示**：`ocp keys generate` → 起节点 → `curl /.well-known/ocp-catalog` 看到 `jwks_url` → `curl` 该地址拿到公钥
- **风险**：私钥在示例节点的存放方式 → 示例只从环境变量读，明确标注"示例用途，生产密钥托管归实例仓"

---

### W3 · Manifest 签名闭环（T1 层）

把 `trust_strategy.manifest_signed` 从一句**无法被检验的自我声明**，变成可验证事实。

| 小任务 | 天 | 内容 | 完成判据 |
|---|---|---|---|
| **W3-T1** | 周一二 | ① `SignatureEnvelope` JSON Schema + Zod（字段见草案 5.1）<br>② `docs/specs/crypto/v1.md`：签名对象范围、验签流程、失败语义<br>③ **决策落定：签名放 body 内嵌还是 header**（倾向 body——对 CDN / 代理更鲁棒，且便于离线校验） | 规范可评审，决策有书面理由 |
| **W3-T2** | 周三四 | ① `examples/typescript` 签发 signed manifest<br>② 真实填充 `trust_strategy.{manifest_signed, signature_algorithms}`（`catalog-manifest.schema.json:344`） | manifest 含 envelope 且 schema 校验通过 |
| **W3-T3** | 周五 | CLI `ocp catalog inspect --verify` + 篡改检测 | 正例退出码 `0`；**篡改任意一字节 → 退出码非 0** |

- **周五演示**：两条命令——对正常节点验签通过 / 对篡改副本失败

---

### W4 · 三语言互操作 + Registration 侧信任落地 ★

**加密侧完成点。本周结束即达成 S 档全部范围，可作为独立发布节点。**

| 小任务 | 天 | 内容 | 完成判据 |
|---|---|---|---|
| **W4-T1** | 周一二 | `examples/python` 的 canonical + verify 实现，复用 W1 向量 | `python conformance_test.py` **原有 7 条断言不回归** + 新增验签断言 |
| **W4-T2** | 周三四 | `examples/go` 的 canonical + verify 实现 | `go test ./...` 同上标准 |
| **W4-T3** | 周五 | ① **3×3 交叉验签矩阵测试**：任一语言签发，另两种均能验通<br>② `CatalogRouteHint.trust_profile` 真实填充 `manifest_hash` / `issuer` / `signature_alg`（`catalog-route-hint.schema.json:38-52`）<br>③ 实现降级语义：验签失败 → `trust_tier` 降级 → 触发既有 `downgrade_invalidates_cache` | **矩阵 9 格全绿** |

- **签发可选，验签必做**：Python / Go 侧无 OCP 包需手写，只做 verify 不做完整 schema 绑定，靠 W1 向量保证一致性
- **周五演示**：输出一张 3×3 矩阵表
- **跨仓**：本周需知会 `ocp-catalog-instances`，route hint 字段将开始承载真实值

---

### W5 · 归因数据模型定稿（零破坏改造）

| 小任务 | 天 | 内容 | 完成判据 |
|---|---|---|---|
| **W5-T1** | 周一二 | ① `docs/specs/attribution/v1.md` 起草<br>② `AttributionToken` claims 定稿（**单跳**）<br>③ 多跳嵌套 token 记入 backlog，不进本期 | claims **逐条写明存在理由**，无"以防万一"字段 |
| **W5-T2** | 周三四 | ① `ocp.catalog.attribution.v1/` JSON Schema<br>② Zod **可选字段**挂载：`resolveRequestSchema.attribution_context`、`actionBindingSchema.attribution` | `bun run typecheck` 绿 |
| **W5-T3** | 周五 | 向后兼容回归测试；确认**未触碰** `catalogQueryRequestSchema` | **不含 attribution 字段的旧 payload 必须仍然通过校验** |

**关键约束**（已实测各 schema 的 strict 性质，决定了改哪里）：

| Schema | `.strict()` | 结论 |
|---|---|---|
| `actionBindingSchema` / `resolvableReferenceSchema` / `resolveRequestSchema` | 否 | 加可选字段**零破坏** ✅ |
| `catalogQueryRequestSchema` | **是** | 本期**明确不碰** ⛔ |

**设计决策**：归因锚定在 **resolve** 而非 query。两条理由：① 零破坏性（见上）② `purpose: "checkout"` 本就标识转化意图。

- **周五演示**：新旧两份 payload 并排跑校验，均通过

---

### W6 · 归因凭证签发与验证端到端 ★

**M 档核心价值交付点。本周结束，"这单归谁"第一次变得可被第三方独立验证。**

| 小任务 | 天 | 内容 | 完成判据 |
|---|---|---|---|
| **W6-T1** | 周一二 | `examples/typescript` 在 `purpose: "checkout"` 时签发 token，嵌入 `action_binding.attribution` | resolve 响应含 attribution 且 schema 校验通过 |
| **W6-T2** | 周三四 | ① **Provider 侧验签参考实现**（独立小脚本，模拟商户收单）<br>② nonce 防重放（内存 TTL 缓存，明确标注生产需持久化） | **三种反例各自失败**：篡改 `agent_id` / 过期 / 重放 |
| **W6-T3** | 周五 | CLI `ocp catalog resolve --verify-attribution` + 端到端演示脚本 | 四条断言逐条打印通过 |

- **周五演示**——四条断言：
  - ✅ 正常链路 query → resolve → verify 通过
  - ❌ 篡改 `agent_id` → 失败
  - ❌ 超过 `expires_at` → 失败
  - ❌ 同一 nonce 重放 → 失败
- **风险**：Provider 接入意愿 → 参考实现要短到能一眼读完。**这是采纳率的决定因素，不是技术问题**
- **跨仓**：需 `ocp-catalog-instances` 配合验证真实节点，**W5 就要知会**

---

### W7 · 可观测性、文档与技能收尾

| 小任务 | 天 | 内容 | 完成判据 |
|---|---|---|---|
| **W7-T1** | 周一二 | activity 事件补归因关联——复用既有 `correlation_id`，**公开投影只出 `correlation_id_hash`** | 公开投影测试断言**无明文归因主体** |
| **W7-T2** | 周三四 | 站点文档**四件套**：`content/docs/` 新增页 + `locales/zh/` 中文页 + `navigation.ts` + artifacts registry | `bun run site:check` 绿 |
| **W7-T3** | 周五 | ① `skills/ocp-catalog/references/` 更新 + `bun run skill:sync`<br>② `updates/` 发布说明一篇（含 zh）<br>③ README 包清单增补 `ocp-crypto` | **四条命令全绿**（见下） |

> ⚠️ **W7-T2 有坑**：`scripts/check-docs-integrity.ts` 同时校验 **navigation ↔ 内容文件 ↔ zh locale ↔ artifacts registry** 四者一致，新增一个文档页要同步改 4 处，**漏一处就红**。别留到周五。

- **W7-T3 验收**：`bun run typecheck && bun test && bun run site:check && bun run skill:check`
- **周五演示**：`bun run site:dev` → 浏览器里读到新文档页，中英切换正常

---

## 3. 工程约定

**分支与合入**
- 全模块共用一条长分支 `crypto-attribution`，从个人 fork（`origin`）推出，向 `Open-Commerce-Protocol/OCP-Catalog`（`upstream`）的 `main` 提 PR
- 小任务粒度提交：commit message 前缀用 `W3-T2:` 便于回溯
- 每周产出**可独立回滚**，不产生跨周的半成品状态；由于走单一长分支，「可回滚」由 commit 边界保证而非分支边界，因此**禁止**跨小任务的混合提交

**每周固定节奏**

| 时点 | 动作 |
|---|---|
| 周一早 15 分钟 | T1 启动，确认本周范围 + 上周遗留；**W1 周一额外做 A1 假设闸门** |
| 周二晚 | T1 收口自检 |
| 周三早 | T2 启动 |
| 周四晚 | T2 收口自检——**风险最后暴露点**，此时未收口应主动缩 T3 范围 |
| 周五 | T3 + Demo + 合入 + 一页周报（做了什么 / 下周做什么 / 卡在哪） |

**小任务 Definition of Done**
1. 完成判据（见各周表格最右列）达成
2. `bun run typecheck` 绿
3. 新增字段 / 命令**全部 additive**，无破坏性变更

**每周 Definition of Done**（在小任务 DoD 之上追加）
4. `bun test` 绿
5. 周五演示项当场可复现

---

## 4. 风险登记

| 风险 | 概率 | 影响 | 缓解 | 触发预案 |
|---|---|---|---|---|
| **A1 假设错误**（归因指 `explain`） | 低 | 🔴 致命 | **W1-T1 闸门确认** | 立即停工重新规划，沉没成本 ≤ 1 天 |
| 三语言 canonical 不一致 | 中 | 🔴 高 | W1 前置 + 向量驱动 | 收敛到 TS 单语言签发，Py/Go 仅验签 |
| Provider 侧不愿接入验签 | 中 | 🟡 中 | 参考实现极简化 | 先在自营节点闭环，拿数据说话 |
| 跨仓协作窗口错配 | 中 | 🟡 中 | W4 / W6 提前一周知会 | 本仓先合入，实例仓异步跟进 |
| 密钥托管涉及运维 | 中 | 🟡 中 | 本期只定协议契约 | 明确划归实例仓，不阻塞协议 |
| **T3 只有 1 天被高估** | 中 | 🟡 中 | T3 一律排整周最轻项 | 溢出顺延到下周 T1，不牺牲 T1/T2 |
| 工期被其他事务挤压 | 高 | 🟡 中 | W4 是天然发布点 | **降级到 S 档交付**，归因侧顺延 |

---

## 5. 压缩到 5 周的方案

若工期被压到 5 周，按此裁剪（保留全部核心价值）：

| 调整 | 做法 |
|---|---|
| W3 + W4 合并 | Python / Go 只做 verify，**放弃签发能力**；交叉矩阵降为 1×3 |
| W7 拆出 | 站点文档与 skill 同步顺延，只保留 `updates` 一篇 |
| 保留不动 | W1（地基）、W5（零破坏模型）、W6（端到端）**三周不可压缩** |

反过来，若要扩到 7 周以上，优先补：多跳嵌套 token、字段级加密、ES256 支持。

---

## 6. 明确不在本计划内

- ❌ 资金流转、费率计算、分账对账（L 档，需独立立项）
- ❌ 交易行为上链存证（选型涉及合规与成本）
- ❌ 字段级 / 端到端加密
- ❌ `catalogQueryRequestSchema` 的任何改动（`.strict()`，需版本协商流程）
- ❌ 生产密钥托管与轮换运维（归 `ocp-catalog-instances`）
- ❌ 中心化的信任仲裁机制——保持去中心化，验签由各 Provider 自行完成

---

## 附录 A · 21 个小任务一览

可直接贴进项目管理工具。

| ID | 周 | 任务 | 天 | 完成判据 |
|---|---|---|---|---|
| W1-T1 | 1 | A1 闸门 + canonical 规范起草 | 周一二 | 四条规则无歧义 |
| W1-T2 | 1 | ≥20 条测试向量 | 周三四 | 每条含三元组 |
| W1-T3 | 1 | `ocp-crypto` 骨架 + TS `canonicalize()` | 周五 | 向量全过 |
| W2-T1 | 2 | 补 discovery schema + `jwks_url` | 周一二 | 新断言通过 |
| W2-T2 | 2 | Ed25519 + JWKS 加载 | 周三四 | 三条错误路径有测试 |
| W2-T3 | 2 | `ocp keys` CLI + 节点暴露 JWKS | 周五 | `curl` 通 |
| W3-T1 | 3 | `SignatureEnvelope` + 签名规范 | 周一二 | 决策有书面理由 |
| W3-T2 | 3 | 节点签发 signed manifest | 周三四 | schema 校验通过 |
| W3-T3 | 3 | `inspect --verify` + 篡改检测 | 周五 | 篡改退出码非 0 |
| W4-T1 | 4 | Python 验签 | 周一二 | 原断言不回归 |
| W4-T2 | 4 | Go 验签 | 周三四 | 原断言不回归 |
| W4-T3 | 4 | 交叉矩阵 + `trust_profile` 落地 | 周五 | **9 格全绿** |
| W5-T1 | 5 | 归因规范 + claims 定稿 | 周一二 | 逐条有理由 |
| W5-T2 | 5 | JSON Schema + Zod 挂载 | 周三四 | typecheck 绿 |
| W5-T3 | 5 | 零破坏回归 | 周五 | 旧 payload 必过 |
| W6-T1 | 6 | 签发侧 token | 周一二 | 响应含 attribution |
| W6-T2 | 6 | 验证侧 + nonce 防重放 | 周三四 | 三种反例失败 |
| W6-T3 | 6 | CLI + 演示脚本 | 周五 | 四条断言通过 |
| W7-T1 | 7 | activity 归因关联 | 周一二 | 公开投影无明文 |
| W7-T2 | 7 | 站点文档四件套 | 周三四 | `site:check` 绿 |
| W7-T3 | 7 | skill 同步 + 发布收尾 | 周五 | 四条命令全绿 |

## 附录 B · 新增文件清单

| 小任务 | 路径 | 说明 |
|---|---|---|
| W1-T1 | `docs/specs/crypto/canonicalization.md` | canonical JSON 规范 |
| W1-T2 | `packages/ocp-crypto/fixtures/canonical/` | 三语言共用测试向量 |
| W1-T3 | `packages/ocp-crypto/` | 新包（第 9 个 workspace 包） |
| W3-T1 | `docs/specs/crypto/v1.md` | 签名协议规范 |
| W3-T1 | `ocp.catalog.handshake.v1/signature-envelope.schema.json` | 机读 schema |
| W5-T1 | `docs/specs/attribution/v1.md` | 归因协议规范 |
| W5-T2 | `ocp.catalog.attribution.v1/` | 归因 JSON Schema 目录 |
| W6-T3 | `examples/typescript/src/attribution-demo.ts` | 端到端演示 |
| W7-T2 | `apps/ocp-site-web/src/content/docs/` + `locales/zh/` | 站点文档（双语） |

## 附录 C · 新增 CLI 命令

| 小任务 | 命令 | 域 |
|---|---|---|
| W2-T3 | `ocp keys generate` / `ocp keys show` | `keys`（新） |
| W3-T3 | `ocp catalog inspect --verify` | `catalog`（既有） |
| W6-T3 | `ocp catalog resolve --verify-attribution` | `catalog`（既有） |

## 附录 D · 改动的既有字段

| 字段 | 位置 | 从 → 到 | 小任务 |
|---|---|---|---|
| `trust_strategy.manifest_signed` | `catalog-manifest.schema.json:344` | 自我声明 → 可验证事实 | W3-T2 |
| `trust_strategy.signature_algorithms` | 同上 | 空数组 → 真实算法列表 | W3-T2 |
| `trust_profile.{manifest_hash, issuer, signature_alg}` | `catalog-route-hint.schema.json:38-52` | 未填充 → 真实值 | W4-T3 |
| `downgrade_invalidates_cache` | 同上 | 已声明未实现 → 生效 | W4-T3 |
| `WellKnownCatalogDiscovery` | **`ocp-schema` 中缺失** | 无 schema → 补全 + 加 `jwks_url` | W2-T1 |
