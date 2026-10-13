# OCP Catalog 开发者体验六周交付计划

| 项目 | 内容 |
|---|---|
| 状态 | **草案（Draft）· 待评审** |
| 版本 | v0.1 |
| 日期 | 2026-10-13 |
| 实施周期 | 2026-10-19（周一）– 2026-11-27（周五），共 6 周 |
| 上游计划 | [OCP Catalog 开发者体验与新业务探索计划](./ocp-developer-experience-exploration-plan.md) |
| 目标读者 | 协议负责人、产品负责人、工具链、CLI 与站点开发者 |
| 目标 | 按周交付“能力发现与匹配 → 本地协议沙盒 → 一致性验证 → 三者联动”的可演示闭环 |
| 范围 | 协议纯模块、fixture、CLI、站点交互、静态报告与 Agent skill |
| 非目标 | 生产部署、数据库、任意远程代理、用户代码执行、密钥托管、支付与结算 |

---

## 1. 排期原则

本计划把上游方案中的 4–6 周估算固定为 **6 周**，用完整周期换取清晰的模块边界、跨语言验证和每周可演示结果。每周采用 **2 + 2 + 1** 的节奏：周一至周二完成第一个窄范围任务，周三至周四完成第二个窄范围任务，周五只做集成、回归、文档和演示，不在周五引入新的核心合同。

所有任务遵循以下规则：

1. 每个两日任务独立提交，不把能力模型、站点交互和 conformance runner 混在同一个提交中；
2. 纯模块先于 UI，结构化合同先于 CLI 和站点消费；
3. 必需能力决定 `eligible`，偏好能力只影响 `score`，两者不得混用；
4. 沙盒只运行仓库内 handler 和 fixture，不连接任意远程 URL；
5. TypeScript、Python、Go 消费同一 suite manifest、case ID、输入 fixture 和报告合同；
6. 每个任务附两句话工作报告，并如实记录未执行的门禁。

---

## 2. 六周总览

| 周次 | 日期 | 周目标 | 周末可演示结果 |
|---|---|---|---|
| 第 1 周 | 10-19 – 10-23 | 冻结统一能力模型和匹配合同 | 单个 manifest 可稳定输出 profile、匹配结果和解释 |
| 第 2 周 | 10-26 – 10-30 | 交付能力目录与匹配 MVP | CLI 与站点目录可按需求排序、解释并比较 Catalog |
| 第 3 周 | 11-02 – 11-06 | 建立本地协议沙盒内核 | 本地完成 discovery → manifest → query，非法请求提前拒绝 |
| 第 4 周 | 11-09 – 11-13 | 交付沙盒 UI、resolve 与代码生成 | 站点完成 query → resolve，导出四种调用示例和 transcript |
| 第 5 周 | 11-16 – 11-20 | 交付一致性与互操作实验室 MVP | 三语言运行同一 suite，并生成可复现的结构化报告 |
| 第 6 周 | 11-23 – 11-27 | 串联目录、沙盒、conformance 与 skill | 完整演示选节点、试调用、查兼容性并导出报告 |

---

## 3. 第 1 周：统一能力模型与匹配合同

**日期：2026-10-19 – 2026-10-23**  
**周目标：** 建立目录、沙盒和 conformance 共同消费的稳定能力视图，不修改现有稳定协议字段。

| 时间 | 任务 | 具体工作 | 交付物 | 完成判据 |
|---|---|---|---|---|
| 10-19 – 10-20 | W1-T1 · 能力 profile 合同 | 盘点 manifest、route hint、provider declaration 和 object contract 的字段来源；定义 `CatalogCapabilityProfile`、来源引用和确定性排序规则；建立完全匹配、部分匹配、硬性不匹配三组 fixture | profile 类型、Zod/JSON Schema 合同、字段映射表、fixture | 同一输入重复转换得到逐字段相同的 profile；数组去重与排序稳定；每个派生字段可追溯到原字段 |
| 10-21 – 10-22 | W1-T2 · 提取与匹配纯函数 | 实现 manifest → profile；定义 required/preferred requirements；实现 eligibility、score、matched、missing、warnings 和 explanations；锁定初始评分权重 | 纯函数、单元测试、匹配结果合同 | 三组 fixture 输出稳定；缺失 required 项时 `eligible=false`；偏好缺失只降低分数；解释可定位具体能力或字段 |
| 10-23 | W1-T3 · 合同收口 | 增加 JSON Schema 与 Zod 接受/拒绝一致性检查；补术语文档、快照和工作报告；演示单个 manifest 的 profile 与匹配解释 | 合同基线、演示脚本、周报 | package 定向测试通过；合同无未解释字段；下周 CLI 与站点可直接消费，不需要复制匹配逻辑 |

**本周门禁：**

- 不拆新 workspace package，先在现有 package 中验证模型；
- 不修改站点和 CLI；
- 不把评分当作协议合规结论；
- profile 只做现有 schema 的派生视图。

---

## 4. 第 2 周：能力目录与匹配 MVP

**日期：2026-10-26 – 2026-10-30**  
**周目标：** 将共享能力模型接入 CLI 和现有目录，支持需求匹配、原因解释和 Catalog 对比。

| 时间 | 任务 | 具体工作 | 交付物 | 完成判据 |
|---|---|---|---|---|
| 10-26 – 10-27 | W2-T1 · 匹配 CLI | 增加 `catalog capabilities`、`catalog match`、`catalog compare`；支持文件输入、结构化错误和 `--json`；文本输出复用同一结果对象 | 三个 CLI 子命令、help、测试 | 相同输入在纯函数与 CLI 中得到同一排序和解释；无效 manifest 返回可定位错误；JSON 输出可被合同校验 |
| 10-28 – 10-29 | W2-T2 · 目录匹配与对比 | 在现有目录筛选上增加 query pack、mode、字段、对象类型、resolve 和 sync requirement；展示 eligible、score、matched、missing、warning；支持至少两个 Catalog 对比 | 双语目录 UI、对比视图、组件测试 | 现有浏览与筛选不回退；硬性不匹配有明确标记；CLI 与站点不各自实现评分；窄屏内容无溢出 |
| 10-30 | W2-T3 · 集成与演示 | 固化演示数据；验证 URL/状态序列化和空、加载、错误状态；更新文档与工作报告 | 静态演示 fixture、截图或演示步骤、周报 | 输入 product-search 需求后得到确定排序、理由和缺失项；刷新后需求状态可恢复；相关门禁通过或明确记录 |

**本周演示：** 输入 query pack、对象类型和字段需求，比较两个 Catalog，展示一个满足项和一个因必需字段缺失而不满足的结果。

---

## 5. 第 3 周：本地协议沙盒内核

**日期：2026-11-02 – 2026-11-06**  
**周目标：** 建立无远程依赖、可确定复现的 discovery → manifest → query 沙盒执行链。

| 时间 | 任务 | 具体工作 | 交付物 | 完成判据 |
|---|---|---|---|---|
| 11-02 – 11-03 | W3-T1 · 请求模型与校验 | 核对并修正 `buildSampleQueryBody` 与 `catalogQueryRequestSchema` 的语义；定义统一中间请求模型；实现 schema 驱动默认值、字段级错误和 canonical JSON | 请求模型、校验器、query fixture、回归测试 | 示例请求同时通过 JSON Schema 与 Zod；非法请求在 handler 前拒绝；错误包含字段路径和规则；不修改稳定协议合同 |
| 11-04 – 11-05 | W3-T2 · 本地执行适配器 | 包装 TypeScript 示例节点的 `handle(Request)`；实现 discovery、manifest、query 三步执行；定义 transcript v1，记录输入、规范化请求、响应和错误 | in-process adapter、沙盒执行 API、transcript schema | 同一 fixture 重复运行输出一致；每步可单独重放；没有网络、密钥或数据库依赖；失败步骤不会继续执行后续步骤 |
| 11-06 | W3-T3 · 内核收口 | 增加正例、反例和步骤状态测试；生成最小 CLI/脚本演示；补文档和工作报告 | 内核测试矩阵、演示 transcript、周报 | 本地完成 discovery → manifest → query；合法与非法案例均可复现；沙盒核心不依赖 React |

**本周门禁：**

- 仅运行仓库内 TypeScript handler 和固定 fixture；
- 不接受用户输入 URL；
- 不保存认证信息；
- transcript 不包含环境相关的随机值或绝对路径。

---

## 6. 第 4 周：沙盒 UI、resolve 与代码生成

**日期：2026-11-09 – 2026-11-13**  
**周目标：** 将沙盒内核接入站点，完成 query → resolve、代码生成和实验导入导出。

| 时间 | 任务 | 具体工作 | 交付物 | 完成判据 |
|---|---|---|---|---|
| 11-09 – 11-10 | W4-T1 · 请求编辑与执行界面 | 实现节点选择、步骤导航、schema 表单、原始 JSON 编辑、字段错误、请求/响应和 canonical JSON 视图；接入第 3 周内核 | 双语沙盒页面、编辑状态模型、组件测试 | 表单与 JSON 双向同步；无效输入不能执行；加载、空、成功和错误状态完整；键盘与屏幕阅读器可用 |
| 11-11 – 11-12 | W4-T2 · Resolve、代码与 transcript | 从 query 结果选择对象执行 resolve；基于同一请求模型生成 curl、TypeScript、Python、Go 示例；实现 transcript 导出与导入 | resolve 流程、四种代码生成器、导入导出 | query 结果可直接成为 resolve 输入；四种示例语义一致；导入 transcript 后可复现相同结果；生成代码有快照或执行测试 |
| 11-13 | W4-T3 · 沙盒验收 | 做桌面和移动端实机检查；补边界案例、文档和工作报告；准备完整演示 | 沙盒验收记录、演示脚本、周报 | 站点完成 discovery → manifest → query → resolve；可查看错误解释和代码；可导出并重新导入实验 |

**本周演示：** 从推荐节点进入预填充沙盒，修改过滤字段，先看到字段错误，再修正并执行 query 和 resolve，最后导出 Python 示例和 transcript。

---

## 7. 第 5 周：一致性与互操作实验室 MVP

**日期：2026-11-16 – 2026-11-20**  
**周目标：** 让 TypeScript、Python、Go 使用同一版本化 suite，并生成统一、可解释、可机器消费的报告。

| 时间 | 任务 | 具体工作 | 交付物 | 完成判据 |
|---|---|---|---|---|
| 11-16 – 11-17 | W5-T1 · Suite 与报告合同 | 定义 suite manifest、case、implementation、summary 和 report schema；首批覆盖 discovery、manifest、health、query、resolve、canonical、签名、错误码和反例 | `suite_version=v1` 合同、case registry、共享 fixture | case ID 稳定且唯一；每个 case 有输入、期望、规范引用和复现信息；报告同时通过 JSON Schema 与 Zod |
| 11-18 – 11-19 | W5-T2 · 三语言执行适配器 | 复用现有 interop agent 模式；为 TypeScript、Python、Go 实现统一动词和输出；加入 schema/Zod 接受拒绝矩阵及跨语言结果对比 | 三个 adapter、runner、正反例矩阵 | 三种语言消费同一 fixture；同一失败归到同一 case ID；语言进程失败与协议失败分开报告；输出可重复生成 |
| 11-20 | W5-T3 · CLI 与静态报告 | 增加 `conformance run`、单 case 重放和 `conformance report`；生成站点可直接读取的静态报告；补文档和工作报告 | CLI、示例报告、静态报告视图、周报 | `--all` 和 `--case` 可运行；失败项含 expected、actual、spec_ref 和 reproduce；站点不执行第三方代码即可展示报告 |

**本周演示：** 三种语言运行同一 suite，展示一个通过案例和一个有意失败案例，并从报告中的复现命令重跑单 case。

---

## 8. 第 6 周：三条方向联动与最终验收

**日期：2026-11-23 – 2026-11-27**  
**周目标：** 将目录、沙盒、conformance、CLI、站点和 Agent skill 连接为一个可复现的开发者工作流。

| 时间 | 任务 | 具体工作 | 交付物 | 完成判据 |
|---|---|---|---|---|
| 11-23 – 11-24 | W6-T1 · 目录到沙盒 | 定义带版本的 handoff payload；从匹配结果携带 profile、requirements 和选中 Catalog 打开预填充沙盒；处理合同版本不兼容 | handoff schema、深链接、集成测试 | 目录选择与沙盒初始状态一致；刷新和分享链接后可恢复；旧或未知版本给出明确错误，不静默误读 |
| 11-25 – 11-26 | W6-T2 · 沙盒到 conformance 与 skill | 将 transcript 关联或转换为 conformance case；失败项链接到规范章节、schema 字段和能力声明；同步 Agent skill 消费统一 JSON 合同 | case 导出、规范链接、skill 更新、端到端 fixture | CLI、站点和 skill 对同一结果使用相同 case ID 和术语；失败定位可往返；skill 检查通过或明确记录限制 |
| 11-27 | W6-T3 · 最终验收与发布 | 执行相关 package 测试、typecheck、site/skill 检查；完成双语文档、演示脚本、已知限制和后续清单；导出最终静态实验报告 | 最终演示、验收记录、发布说明、周报 | 完整闭环在无生产依赖下复现；所有失败门禁有原始结果和责任归属；没有把非目标内容带入本期 |

**最终演示：**

```text
输入 product-search 业务需求
→ 查看 Catalog 排序、匹配理由和缺失能力
→ 选择一个合格 Catalog 打开预填充沙盒
→ 校验并执行 query
→ 从结果执行 resolve
→ 将实验转换为 conformance case
→ 用 TypeScript、Python、Go 重放
→ 查看规范定位并导出代码、transcript 与静态报告
```

---

## 9. 依赖关系与关键路径

```text
W1 能力与匹配合同
 ├─→ W2 CLI 与目录匹配
 └─→ W3 沙盒请求模型
          └─→ W4 沙盒 UI 与代码生成

W3 transcript 合同
 └─→ W5 conformance suite 与 runner

W2 目录 + W4 沙盒 + W5 conformance
 └─→ W6 三向联动与最终验收
```

关键路径为 **W1 → W3 → W4 → W5 → W6**。如果某周未完成合同级交付，下游只允许继续做不依赖该合同的 UI 草图、fixture 整理或文档，不得复制临时结构绕过阻塞。

---

## 10. 每周固定检查清单

### 周一开工前

- 确认本周输入合同和上周遗留；
- 把两日任务缩到可独立提交的范围；
- 明确必须运行的定向测试和仓库门禁；
- 确认不涉及生产 API、数据库或任意远程执行。

### 周四结束前

- 两个核心任务均已有测试和结构化输出；
- CLI、站点或语言 adapter 没有复制核心规则；
- 新增用户可见文本已有中英文版本；
- 失败路径包含字段、case 或规范定位。

### 周五收口

- 运行相关 package 测试和 typecheck；
- 涉及站点或 skill 时运行对应检查；
- 固化演示 fixture 和复现命令；
- 写两句话工作报告并逐任务提交；
- 未通过或未执行的门禁原样记录，不以“预计通过”代替结果。

---

## 11. 周级验收与延期规则

| 情况 | 处理方式 |
|---|---|
| 两日任务按时完成 | 合入任务提交，周五进入集成和演示 |
| 两日任务只差文档或非关键测试 | 周五优先补齐，不开启额外功能 |
| 合同或核心行为未稳定 | 不向下游暴露临时 API；下一任务缩减为 fixture、测试或设计验证 |
| 站点任务延期 | 保留纯模块、CLI 和静态数据交付，UI 顺延但不复制逻辑 |
| 某语言 adapter 延期 | runner 和报告合同照常交付，明确缺失语言，不用模拟结果占位 |
| Bun 或特定环境不可用 | 使用仓库认可的替代 harness 做定向验证，并明确列出未执行的仓库门禁 |

任何延期都必须说明：未完成项、阻塞原因、影响的下游任务、临时禁止事项和新的验收日期。不得通过扩大单个提交或删除负面 fixture 来维持表面进度。

---

## 12. 六周结束后的完成定义

六周计划完成时，应同时满足：

- 有一套稳定、可追溯的 `CatalogCapabilityProfile` 和可解释匹配合同；
- CLI 与站点使用同一匹配器，能够筛选、排序和比较 Catalog；
- 本地沙盒能完成 discovery → manifest → query → resolve；
- 请求错误能定位到字段和规则，生成的四种调用示例与真实请求一致；
- transcript 可导入、重放并转换或关联到 conformance case；
- TypeScript、Python、Go 使用同一 suite 和报告格式；
- 每个 conformance 失败项包含期望、实际、规范引用和复现命令；
- 目录、沙盒、报告、CLI 和 Agent skill 消费统一的版本化 JSON 合同；
- 完整演示不依赖生产数据库、外部托管服务、用户代码执行或密钥；
- 文档明确记录已完成项、未执行门禁、已知限制和后续候选任务。
