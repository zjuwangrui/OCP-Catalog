# OCP 加密与归因 · 收口两周计划

| 项目 | 内容 |
|---|---|
| 状态 | **进行中**——T1、T2、T3、T4 已完成（2026-09-20） |
| 版本 | v1.0 |
| 日期 | 2026-09-18 |
| 起止 | **2026-09-21（周一）– 2026-10-09（周五）**，10 个工作日（跨国庆，见下） |
| 口径 | **加密 = 报文签名验签闭环**，字段级加密不在本期（沿用 7 周计划假设 A3） |
| 上游文档 | [7 周实施计划](./ocp-encryption-and-attribution-plan.md)（完整路线图）、[归因两周计划](./ocp-attribution-2w-plan.md)（已完成） |
| 目标 | 把加密侧与归因侧在**本仓内**各自收口，剩余项全部有明确去处 |

---

## 0. 日历：这两周被国庆切成两段

| 段 | 日期 | 工作日 |
|---|---|---|
| 前段 | 09-21（一）– 09-25（五） | 5 |
| 中段 | 09-28（一）– 09-30（三） | 3 |
| 国庆 | 10-01（四）– 10-07（三） | — |
| 后段 | 10-08（四）– 10-09（五） | 2 |

合计 10 个工作日。**排期刻意把「必须连着做」的任务全压在国庆之前**：跨语言签名互操作（T4）要三种语言逐字节对齐，中间断七天再捡起来，成本远高于一天。节后两天留给 activity 与文档收尾——这两项断得起。

若公司调休把 09-26（周六）或 10-10（周六）算作工作日，多出来的日子一律记为缓冲，不往前提任务。

---

## 1. 现在到底还差什么

前置已完成（截至 2026-09-18）：

| 已交付 | 内容 |
|---|---|
| Canonical 地基 | OCP-JCS v1 规范 + 75 条向量，TypeScript / Python / Go 三语言实现，3×3 矩阵全绿 |
| 密钥与 JWKS | Ed25519 签发验签、JWKS 加载、`kid` 解析、TTL 缓存、`ocp keys` CLI、节点暴露公钥 |
| 归因链 | 规范、JSON Schema、多跳逐跳签名、验证器、`jti` 防重放、商户收单、`order_id` 去重、last-touch 裁决、CLI 与六条断言演示 |
| Manifest 签名规范 | `docs/specs/crypto/v1.md`、`ocp.catalog.crypto.v1/`、`SignatureEnvelope` 的 Zod 与 TS 实现、12 条一致性向量（W3-T1，今天合入） |

还差的，按「谁在等它」分三类：

**A. 加密侧：规范写完了，但没有任何节点真的在签**
`trust_strategy.manifest_signed` 目前仍是一句自我声明，`examples/typescript` 的 manifest 不带 `signature`，CLI 的 `ocp catalog inspect` 没有 `--verify`，`CatalogRouteHint.trust_profile` 的 `manifest_hash` / `issuer` / `signature_alg` 三个字段仍然空着，`downgrade_invalidates_cache` 是「已声明未实现」。**规范到事实之间还隔着一整条链路。**

**B. 归因侧：链路成立，但有两处已知会在生产出事的地方**
① `examples/typescript` 追加中继跳时**不验上游链**——规范 §5.2 让第 N 跳的签名永久覆盖第 1..N−1 跳，所以这等于可能把本节点的名字签在别人的伪造上。
② `JtiRegistry` 与 `SettlementLedger` 都在内存里，重启即清空，按进程隔离，而后者管着钱。

**C. 对外面：协议做完了，外面看不见**
activity 事件没有归因关联，站点没有加密与归因的文档页，skill 没同步，`updates` 没有发布说明，README 的包清单没有 `ocp-crypto`。

---

## 2. 逐任务计划

### 第 1 周（09-21 ~ 09-25）· 让签名从规范变成事实

| 小任务 | 天 | 内容 | 完成判据 |
|---|---|---|---|
| **T1**（原 W3-T2） ✅ | 09-21 / 22 | ① `examples/typescript` 用已有的 `SIGNING_KEY` 签发 signed manifest<br>② `federation.trust_strategy.{manifest_signed, signature_algorithms}` 真实填充<br>③ `/.well-known/ocp-catalog` 的 discovery 文档同样签发（schema 已留好可选 `signature`） | manifest 与 discovery 同时通过 **JSON Schema 与 Zod 两侧**校验；`server.test.ts` 新增断言：取到公钥后**离线**验通 |
| **T2**（原 W3-T3） ✅ | 09-23 / 24 | CLI `ocp catalog inspect --verify` + 篡改检测 | 正例退出码 `0`；**篡改任意一字节 → 退出码非 0**；§8 八个错误码都能从 CLI 输出里读到，不是一句「验签失败」 |
| **T3**（原 W4-T3 ②③） ✅ | 09-25 | ① `CatalogRouteHint.trust_profile` 填 `manifest_hash` / `issuer` / `signature_alg`<br>② 降级语义：验签失败 → `trust_tier` 降级 → 触发既有 `downgrade_invalidates_cache` | 一份被篡改的 manifest 让路由提示从 `verified` 掉到 `unknown` **且缓存被作废**，有测试；`unsigned` / `signature_expired` 掉到 `unverified` **且缓存保留** |

> **T1 的坑**：`trust_strategy` 在 `federation` 里面，不在 manifest 顶层。写在顶层时 Zod 照收（非 `.strict()`），JSON Schema 拒收（顶层 `additionalProperties: false`）——两边口径差正好把这个错藏住。W3-T1 的向量已经踩过一次。

> **T1 交付时的一处偏离（2026-09-18）**：原计划第 ② 项含 `trust_tier`，**实际没填**。
> 这个字段是节点写给自己的信任等级，而签名存在的全部理由就是取代自述——等级由验签方按
> 规范 §9 的 `trustCeilingFor()` 算出来，写在被验的文档里既不增加信息也不会被采信。
> 另两项（`manifest_signed` / `signature_algorithms`）照填，它们描述的是节点**做了什么**，
> 旁边的签名让这两句话可被检验。T3 落 `trust_profile` 时按这个口径走：等级是验签的结论，不是声明。

> **T2 的坑**：`packages/ocp-cli` 的验签逻辑必须照 `attribution.ts` 的形态写成**纯模块**，不 import `@ocp-catalog/ocp-client` 也不 import `node:fs`，I/O 归调用方。否则它在 `--experimental-strip-types` 下跑不起来（client 用了构造函数参数属性），测试就跑不了。

> **T2 交付说明（2026-09-19）**：退出码定的是 `2` 而不是笼统的「非 0」。`1` 已经是这个 CLI 抛异常时的退出码
> ——取不到 manifest、flag 打错、密钥集没给。把「签名验不过」和「命令用错了」并到同一个码上，
> 早晚有脚本按「非 0 就重试」处理，然后把一次取不到读成节点可信。另：`ocp attribution verify`
> 目前验不过也退 0，同一个洞，按「禁止跨小任务混合提交」留到单独一个提交里补。

> **T3 的现成件**：`trustCeilingFor()` 已经在 `packages/ocp-crypto/src/signature.ts` 里，把验签结果映射成「信任上限 + 是否作废缓存」。T3 调它，不要另写一份映射——规范 §9 只有一份，实现漂了会出现「CLI 说降级、路由提示说没降」。

> **T3 交付说明（2026-09-20）**：三条口径写在 `applyManifestVerification()` 里，都是从「上限不是判决」推出来的。
> ① **验通不抬等级**：注册方说 `verified_domain` 就还是 `verified_domain`。§7.2 说得很清楚，签名验通只解锁
> `verified` 这个上限，不断言 manifest 内容为真——域名验证是另一条轴，这个函数没看到它的任何证据。
> ② **降级时清掉三个证据字段**：`manifest_hash` / `issuer` / `signature_alg` 只在验通时写。把上一次验通的哈希
> 留在一份验不过的提示旁边，正是这几个字段本来要防的那种投毒。
> ③ **节点声明 `downgrade_invalidates_cache: false` 挡不住自己伪造的 manifest 作废缓存**。和 T1 里
> `trust_tier` 同一个道理：这是验签方的结论，不是被验方的声明。
> 另外顶层 `trust_tier` 与 `trust_profile.trust_tier` 一起降，有断言钉住——只读顶层字段的消费方不能看到
> `verified` 而底下写着 `unknown`。

**周五演示**：两条命令，对正常节点验签通过 / 对篡改副本失败；再并排打印降级前后的 route hint。

---

### 第 2 周（09-28 ~ 09-30）· 跨语言与归因收口

| 小任务 | 天 | 内容 | 完成判据 |
|---|---|---|---|
| **T4** ✅ | 09-28 / 29 | `examples/python` 与 `examples/go` 的**文档签名**实现（两者目前只有归因验签），复用 `fixtures/signature/manifest-v1.json` | 三语言产出的 `expected_signed_document` **逐字节相同**；12 条反例三语言给出**同一个错误码与同一个信任上限**；3×3 签名矩阵 9 格全绿 |
| **T5** | 09-30 | 归因的两处生产缺口：<br>① example server 联署中继跳前先验上游链（按 `catalog_id` 取 JWKS 的解析器）<br>② `JtiRegistry` / `SettlementLedger` 抽成 `ReplayStore` / `LedgerStore` 接口 + 内存实现 + **事务契约文档** | 上游链被伪造时**拒绝联署**，有测试；两个接口各有一份「认领与打款必须同事务」的契约文档，内存实现标注为仅供演示 |

> **T4 为什么不是「再做一遍归因互操作」**：归因签的是「链前缀 + 核心声明」，文档签的是「信封去掉 signature」，两套签名材料不同、互不接受。Python / Go 现有的验签代码一行都复用不了签名材料构造，但 canonical 层可以全复用——这也是为什么它是 2 天而不是 4 天。

> **T4 交付说明（2026-09-20）**：9 格全绿，三语言签出的文档规范哈希同为
> `sha256:c05a532c…f85c03`，12 条反例同码同上限。四个判断记在这里：
> ① **两套矩阵不合并**。`matrix.mjs` 管归因、`signature-matrix.mjs` 管文档，各自跑。合成一句
> 「interop: green」会让其中一边退化躲在另一边的结果后面——而它们签的本来就不是同一份材料。
> ② **加了第四个动词 `negatives`**，而不是让矩阵解析 selftest 的输出、或把 `--at` 从命令行传进去。
> 12 条反例里有 2 条自带 `verify_overrides.at`，命令行传时间是最容易某一种语言悄悄传错的地方。
> 现在每种语言一次性吐一份结构化 JSON（3 次子进程调用，不是 36 次），矩阵**既比对 fixture 又两两比对**：
> 只比对彼此，三家用同一种方式错会一起通过；只比对 fixture，又说不出是哪种语言漂了。
> ③ **`invalid_key` 也映射成 `key_not_found`**。和归因 §7.1 第 4 行同一种读法：一把验不了的密钥，
> 就是一把没找到的密钥。TS 参考实现是这么写的，移植时差点漏掉，是逐行对 `signature.ts` 才发现的。
> ④ **Go 侧 `encoding/json` 必须开 `UseNumber()`**。否则整数一律变 float64，规范化时只能去猜一个
> 已经被丢掉的字面量，症状是一份没人动过的文档报 `payload_mismatch`。
> 另：三个 agent 的 `checks()` 都改成复用 `negativeOutcomes()`，单测路径和矩阵路径不会各走各的。

> **T5 的边界**：本仓只交付**接口与事务契约**，真实的 SQL / 事务存储实现归 `ocp-catalog-instances`。理由和生产密钥托管一样：协议仓定契约，运行时选存储。`SettlementLedger` 已经留好了从记录重建的构造函数，换存储不用动裁决逻辑。

---

### 节后（10-08 ~ 10-09）· 让外面看得见

| 小任务 | 天 | 内容 | 完成判据 |
|---|---|---|---|
| **T6**（原 W7-T1） | 10-08 | activity 事件补归因关联——复用既有 `correlation_id`，**公开投影只出 `correlation_id_hash`** | 公开投影测试断言**无明文归因主体**（无 `jti`、无 `agent_id`、无 `order_id`） |
| **T7**（原 W7-T2 + T3） | 10-09 | ① 站点文档四件套：`content/docs/` 新增页 + `locales/zh/` 中文页 + `navigation.ts` + artifacts registry<br>② `skills/ocp-catalog/references/` 更新 + `bun run skill:sync`<br>③ `updates/` 发布说明一篇（含 zh）<br>④ README 包清单增补 `ocp-crypto` | **四条命令全绿**：`bun run typecheck && bun test && bun run site:check && bun run skill:check` |

> ⚠️ **T7 是本计划最可能超时的一天。** `scripts/check-docs-integrity.ts` 同时校验 navigation ↔ 内容文件 ↔ zh locale ↔ artifacts registry 四者一致，**漏一处就红**，而它只有一天。
> **降级预案**：优先保 `updates` 一篇 + README + skill 同步（这三项让外部使用者知道有这个东西），站点四件套顺延到节后第二周。**不要为了赶四件套把 skill 同步挤掉**——skill 是 CLI 使用者的入口，站点是读者的入口，前者影响能不能用。

---

## 3. 两周后「彻底完成」的确切含义

这是验收口径，也是这份计划愿意承诺的全部。

**加密侧 · 完成**
真实节点签发带 `SignatureEnvelope` 的 manifest 与 discovery 文档；任何第三方用 CLI 一条命令即可验签，篡改一字节退出码非 0；三种语言签出逐字节相同的结果并对同一批反例给出同一个码；`trust_strategy` 与 `trust_profile` 从自我声明变成可验证事实，验签失败按规范降级并作废缓存。

**归因侧 · 完成**
规范、Schema、多跳签发与验证、防重放、商户收单与裁决、CLI 与端到端演示已在两周计划交付；本期补上中继跳的上游链验证与去重仓的持久化契约，**本仓内不再有已知的可伪造路径**。

**明确划走，不算本期未完成**

| 项 | 去处 |
|---|---|
| 去重仓的真实事务存储 | `ocp-catalog-instances`（本期交付接口与契约） |
| 生产密钥托管与轮换运维 | `ocp-catalog-instances` |
| 与 AP2 / Visa TAP 的代理身份对齐 | 待主管一句话（见两周计划附录），字段口子已留 |
| 字段级加密、ES256、上链存证 | 未排期。各自的代价见 §5 |
| `catalogQueryRequestSchema` 的任何改动 | 它是 `.strict()`，需版本协商流程 |
| 中心化的归因仲裁机构 | 不做。裁决规则成文公开，各方独立算得出同一结果 |

---

## 4. 节奏与 Definition of Done

沿用既有约定：单一长分支 `crypto-attribution`，commit 前缀用当前小任务号（如 `T4:`）便于回溯，**禁止跨小任务的混合提交**。

| 时点 | 动作 |
|---|---|
| 每段开头 15 分钟 | 确认本段范围 + 上段遗留 |
| 每个小任务最后一天晚 | 收口自检——**这是风险最后暴露点**，此时未收口应主动缩下一个小任务的范围，不要顺延到国庆之后 |
| 每周五 | Demo + 合入 + 两句话周报 |

**小任务 DoD**：完成判据达成 + `bun run typecheck` 绿 + 新增字段 / 命令**全部 additive**。
**每段 DoD**：追加 `bun test` 绿 + 演示项当场可复现。

---

## 5. 风险登记

| 风险 | 概率 | 影响 | 缓解 | 触发预案 |
|---|---|---|---|---|
| **T7 一天做不完四件套** | **高** | 🟡 中 | 预案已写进 T7 | 保 updates + README + skill，站点页顺延 |
| 国庆把 T4 的跨语言对齐切断 | 中 | 🟡 中 | T4 排在节前，节前一天必须 9 格全绿 | 未全绿则 T5 让路，先收 T4 |
| Python / Go 的签名材料与 TS 漂了 | 中 | 🟡 中 | 12 条向量已含 `expected_signing_input`，可定位到是规范化还是密钥处理 | 收敛到 TS 单语言签发，Py / Go 仅验签 |
| 去重仓契约与实例仓的存储选型对不上 | 中 | 🟡 中 | T5 当天知会 `ocp-catalog-instances` | 本仓先合入接口，实例仓异步跟进 |
| `trust_profile` 开始承载真实值，下游解析出错 | 中 | 🟡 中 | 全部字段可选，缺省行为不变 | 字段可随时回退为空，不改 schema |
| 工期被其他事务挤压 | 高 | 🟡 中 | **T3 结束（09-25）是天然发布点**——加密侧到此即闭环 | 降级交付「加密闭环」，归因收口与对外面顺延 |

---

## 附录 A · 7 个小任务一览

可直接贴进项目管理工具。

| ID | 日期 | 任务 | 天 | 完成判据 |
|---|---|---|---|---|
| T1 ✅ | 09-21/22 | 节点签发 signed manifest + discovery | 2 | 两侧 schema 校验通过，离线验通 |
| T2 ✅ | 09-23/24 | `ocp catalog inspect --verify` + 篡改检测 | 2 | 篡改一字节退出码非 0 |
| T3 ✅ | 09-25 | `trust_profile` 落地 + 降级语义 | 1 | 降级触发缓存作废，有测试 |
| T4 ✅ | 09-28/29 | Python + Go 文档签名 + 3×3 矩阵 | 2 | **9 格全绿**，反例同码同信任上限 |
| T5 | 09-30 | 上游链验证 + 去重仓接口与事务契约 | 1 | 伪造上游链拒绝联署 |
| T6 | 10-08 | activity 归因关联 | 1 | 公开投影无明文归因主体 |
| T7 | 10-09 | 站点四件套 + skill + updates + README | 1 | 四条命令全绿 |

## 附录 B · 新增与改动的文件

| 小任务 | 路径 | 说明 |
|---|---|---|
| T1 | `examples/typescript/src/server.ts` | 签发 signed manifest 与 discovery |
| T2 | `packages/ocp-cli/src/inspect-verify.ts`（新） | 纯模块，I/O 归调用方 |
| T3 | `packages/registration-schema/src/trust-profile.ts`（新） | `trust_profile` 真实值与降级，调 `trustCeilingFor()` |
| T4 | `examples/python/ocp_signature.py`（新）、`examples/go/ocpcrypto/signature.go`（新） | 文档签名实现 |
| T4 | `examples/python/signature_interop_agent.py`、`examples/go/interopsig/`、`scripts/interop/ts-signature-agent.mjs`（均新） | 三语言 agent，四个动词 `sign / verify / negatives / selftest` |
| T4 | `scripts/interop/signature-matrix.mjs`（新） | 3×3 文档签名矩阵，与归因矩阵分开跑 |
| T5 | `packages/ocp-crypto/src/stores.ts`（新） | `ReplayStore` / `LedgerStore` 接口与事务契约 |
| T6 | `packages/ocp-activity-schema/src/index.ts` | 归因关联字段与公开投影 |
| T7 | `apps/ocp-site-web/src/content/docs/` + `locales/zh/` | 站点文档（双语） |

## 附录 C · 新增 CLI 命令

| 小任务 | 命令 | 域 |
|---|---|---|
| T2 | `ocp catalog inspect --verify` | `catalog`（既有） |

## 附录 D · 改动的既有字段

| 字段 | 位置 | 从 → 到 | 小任务 |
|---|---|---|---|
| `federation.trust_strategy.manifest_signed` | `catalog-manifest.schema.json` | 自我声明 → 可验证事实 | T1 |
| `federation.trust_strategy.signature_algorithms` | 同上 | 空数组 → `["EdDSA"]` | T1 |
| `trust_profile.{manifest_hash, issuer, signature_alg}` | `catalog-route-hint.schema.json` | 未填充 → 真实值 | T3 |
| `trust_profile.downgrade_invalidates_cache` | 同上 | 已声明未实现 → 生效 | T3 |
