# OCP Catalog 开发者体验与新业务探索计划

| 项目 | 内容 |
|---|---|
| 状态 | **草案（Draft）· 待评审** |
| 版本 | v0.1 |
| 日期 | 2026-10-13 |
| 目标读者 | 协议负责人、产品负责人、工具链与站点开发者 |
| 目标 | 建立“发现能力 → 在线试调 → 验证兼容性 → 生成接入方案”的开发者产品闭环 |
| 范围 | 能力目录与匹配、交互式协议沙盒、一致性与互操作实验室 |
| 非目标 | 生产部署、数据库、远程代码执行、密钥托管、支付与结算 |

---

## 1. 背景与核心判断

OCP Catalog 已经具备协议规范、JSON Schema、Zod 模型、typed client、CLI、三语言示例节点、跨语言 fixture 和网站目录等基础能力，但这些能力目前主要以规范、包和测试的形式存在。新用户仍需自行完成以下工作：

1. 从 manifest 和 registration 数据中判断某个 Catalog 是否满足业务需求；
2. 阅读规范后手工构造 query / resolve 请求；
3. 分别运行各语言测试，判断实现是否符合协议；
4. 在失败时自行定位字段、能力或语言实现之间的差异。

本计划不继续扩展加密与归因，也不建设生产运行系统，而是把现有协议资产组合成三类面向开发者的新能力：

- **能力目录与智能匹配**：回答“哪些 Catalog 适合当前需求，以及为什么”；
- **交互式协议沙盒**：回答“如何正确调用这个 Catalog”；
- **一致性与互操作实验室**：回答“这个实现是否符合 OCP，以及哪里不兼容”。

三者共同形成以下闭环：

```text
Catalog 能力目录
      ↓
按需求匹配节点
      ↓
进入协议沙盒
      ↓
构造 query / resolve 请求
      ↓
查看请求、响应和错误解释
      ↓
运行 conformance 检查
      ↓
生成兼容性报告和代码示例
```

---

## 2. 现有基础

### 2.1 能力目录与匹配

现有协议已经包含大部分能力描述和匹配字段：

- `ocp.catalog.handshake.v1/catalog-manifest.schema.json`：query pack、query mode、可搜索/过滤/排序字段、resolve、对象契约、同步能力、data profile、federation 和 trust strategy；
- `ocp.catalog.registration.v1/catalog-search.schema.json`：Catalog 搜索请求；
- `ocp.catalog.registration.v1/catalog-search-result.schema.json`：搜索结果与评分；
- `ocp.catalog.registration.v1/catalog-route-hint.schema.json`：路由提示、信任和健康状态；
- `packages/ocp-client/src/index.ts`：manifest-aware 请求校验和 query pack 选择；
- `apps/ocp-site-web/src/components/directory/`：现有目录浏览、筛选、manifest 拉取和详情展示。

当前主要缺口是：站点筛选仍以身份、标签、注册中心、信任和健康状态为主，尚未形成 query pack、query mode、字段、对象契约、resolve 和同步能力的统一索引，也没有可复用的确定性匹配器。

### 2.2 交互式协议沙盒

可复用基础包括：

- `packages/ocp-client` 已覆盖 discover、search、route resolve、inspect、provider register/sync、catalog query/resolve；
- `packages/ocp-cli` 已有请求构造、校验和结构化输出模式；
- `examples/typescript/src/server.ts` 提供不依赖监听端口的 `handle(Request)`，可用于确定性本地执行；
- `apps/ocp-site-web/src/content/artifacts/` 与 `PageArtifacts.tsx` 已能组织和展示 schema 片段及请求响应示例；
- `packages/webmcp-adapter` 已提供浏览器 Agent 工具注册能力。

当前站点没有可编辑的请求构造器、串联工作流、响应验证面板、请求历史或实验记录导出。首期应使用本地示例 handler 与 fixture，不连接任意远程 URL。

### 2.3 一致性与互操作实验室

可复用基础包括：

- TypeScript、Python、Go 三套最小示例节点；
- `packages/ocp-crypto/fixtures/` 下的 canonical、signature 和 attribution fixture；
- `scripts/interop/matrix.mjs` 与 `signature-matrix.mjs` 的统一 agent、固定动词、反例和 3×3 矩阵模式；
- CLI 中已有的结构化校验与验签错误；
- 根 JSON Schema 和 TypeScript Zod schema。

当前“conformance”口径并不统一：TypeScript 主要使用 Zod，而 Python 和 Go 的部分检查只验证必要字段；现有矩阵也尚未覆盖 registration、handshake、query/resolve、provider negotiation、分页、错误响应和版本兼容性。

---

## 3. 产品目标与成功标准

计划完成后，使用者应能回答四个问题：

1. 哪些 Catalog 支持我的 query pack、对象类型、字段和操作需求？
2. 每个推荐结果为何匹配，缺少哪些能力？
3. 如何对选中的 Catalog 发起合法的 query 和 resolve 请求？
4. 某个 OCP 实现是否符合规范，失败项应该如何复现和修复？

总体成功标准：

- 目录、沙盒和 conformance 使用同一套能力 profile；
- 所有匹配分数均有机器可读和人类可读的解释；
- 沙盒能完成 discovery → manifest → query → resolve 的本地闭环；
- TypeScript、Python、Go 使用统一测试套件和报告格式；
- CLI、站点与 Agent skill 能消费同一份结构化输出；
- 不依赖生产数据库、外部托管服务或用户上传代码执行。

---

## 4. 阶段 0：统一能力模型（2–3 天）

### 4.1 目标

定义三个方向共同使用的数据结构，避免目录、沙盒和 conformance 分别解释 manifest。

### 4.2 任务

| ID | 任务 | 内容 | 完成判据 |
|---|---|---|---|
| T1 | 能力 profile | 定义 `CatalogCapabilityProfile`，映射 manifest、route hint、provider declaration 和 object contract | 同一输入重复转换得到逐字段相同的 profile |
| T2 | 匹配合同 | 定义需求、匹配结果、matched/missing 和 explanation 结构 | 正例、部分匹配和不匹配 fixture 均有稳定输出 |
| T3 | 报告合同 | 定义 versioned conformance suite manifest 和 report schema | 报告可被 JSON Schema/Zod 校验并支持逐 case 结果 |

### 4.3 建议数据结构

```ts
type CatalogCapabilityProfile = {
  catalogId: string;
  protocolVersions: string[];
  queryPacks: Array<{
    id: string;
    modes: string[];
    searchableFields: string[];
    filterableFields: string[];
    sortableFields: string[];
  }>;
  objectTypes: string[];
  resolve: {
    supported: boolean;
    objectTypes: string[];
  };
  syncCapabilities: string[];
  trust: {
    manifestSigned: boolean;
    tier?: string;
  };
};
```

字段名称以现有 schema 的最终映射为准，不为统一模型修改稳定协议字段。

### 4.4 建议落点

首期优先在现有 package 中实现纯函数，数据模型稳定后再决定是否拆分：

```text
packages/ocp-client/src/capabilities.ts
packages/ocp-client/src/capabilities.test.ts
packages/ocp-client/fixtures/capabilities/
packages/ocp-conformance/                 # 报告合同稳定后再新增
```

---

## 5. 阶段 1：能力目录与匹配 MVP（1 周）

### 5.1 目标

把当前目录从“浏览和筛选 Catalog”扩展为“根据业务需求推荐并比较 Catalog”。

### 5.2 功能范围

- query pack 匹配；
- query mode 匹配；
- searchable/filterable/sortable 字段匹配；
- 对象类型与 resolve 能力匹配；
- provider sync capability 与 object contract 匹配；
- 协议版本、信任状态和健康状态展示；
- matched、missing、warning 和可解释评分；
- 两个或多个 Catalog 的能力对比。

### 5.3 初始评分规则

```text
协议版本匹配       +30
query pack 匹配    +25
对象类型匹配       +20
操作类型匹配       +15
信任或健康状态     +10
```

评分是排序辅助，不得替代硬性约束。必需能力缺失时，结果必须明确标记为不满足，而不能仅以较低分数表示。

### 5.4 示例输出

```json
{
  "catalog_id": "cat_demo",
  "eligible": false,
  "score": 85,
  "matched": [
    "query_pack:product-search",
    "query_mode:filtered",
    "resolve:product"
  ],
  "missing": [
    "field:brand"
  ],
  "explanations": [
    "Supports the requested product-search query pack",
    "Does not declare brand as a filterable field"
  ]
}
```

### 5.5 CLI 草案

```bash
ocp catalog capabilities --source ./manifest.json --json
ocp catalog match --source ./manifest.json --require query_pack=product-search --json
ocp catalog compare --catalog-a ./a.json --catalog-b ./b.json --json
```

### 5.6 完成判据

- 给定相同 profile 和需求，匹配顺序与 explanation 稳定；
- 必需能力和偏好能力有明确区分；
- 每个不匹配项能定位到具体字段；
- CLI 与站点使用同一匹配函数；
- 现有目录浏览行为不回退。

---

## 6. 阶段 2：交互式协议沙盒 MVP（1–2 周）

### 6.1 目标

让用户无需先阅读完整规范，即可完成一次本地 discovery、query 和 resolve 流程。

### 6.2 首期边界

仅支持：

- 仓库内 TypeScript 示例节点的 in-process handler；
- 仓库内固定 fixture；
- 明确版本的 schema；
- 无密钥、无账号、无持久化的本地实验。

首期不支持：

- 任意远程 URL；
- 远程代理；
- 用户上传代码执行；
- 保存密钥或认证信息；
- 将沙盒作为生产 API gateway。

### 6.3 工作流

```text
选择示例节点
      ↓
读取 discovery 和 manifest
      ↓
选择 query pack / query mode
      ↓
编辑并校验请求
      ↓
执行 query
      ↓
选择结果并执行 resolve
      ↓
查看响应、错误解释和代码示例
      ↓
导出实验 transcript
```

### 6.4 必须提供的视图

- schema 驱动表单；
- 原始 JSON 编辑器；
- 字段级校验错误；
- 请求与响应；
- canonical JSON；
- `curl`、TypeScript、Python、Go 调用示例；
- 可导入和导出的实验 transcript。

### 6.5 前置修正

在复用站点现有请求示例前，必须核对并测试 `apps/ocp-site-web/src/lib/useCatalogManifest.ts` 中的 `buildSampleQueryBody`。当前 helper 生成的 query 结构可能与 `catalogQueryRequestSchema` 对 `query`、`query_pack` 和 `query_mode` 的定义不一致，不应未经验证直接作为沙盒基线。

### 6.6 完成判据

- 可以完成 discovery → manifest → query → resolve；
- 非法请求在调用 handler 前被拒绝；
- 错误可以定位到字段和规则；
- query 结果可作为 resolve 输入继续使用；
- 四种调用示例与实际请求语义一致；
- transcript 可以重新导入并复现相同结果。

---

## 7. 阶段 3：一致性与互操作实验室 MVP（1 周）

### 7.1 目标

把现有跨语言 fixture 和示例节点测试统一成版本化、可解释、可机器消费的 conformance 报告。

### 7.2 首期检查范围

- discovery 文档；
- manifest；
- health 响应；
- query 请求和响应；
- resolve 请求和响应；
- canonical JSON；
- 文档签名与验签；
- 正例与反例；
- 错误码；
- TypeScript、Python、Go 输出一致性。

### 7.3 报告格式草案

```json
{
  "suite_version": "v1",
  "implementation": {
    "name": "typescript-example",
    "language": "typescript"
  },
  "summary": {
    "total": 24,
    "passed": 22,
    "failed": 2
  },
  "cases": [
    {
      "id": "manifest.query-pack.filtered",
      "status": "failed",
      "expected": {},
      "actual": {},
      "spec_ref": "handshake/v1",
      "reproduce": "ocp conformance run --case manifest.query-pack.filtered"
    }
  ]
}
```

### 7.4 CLI 草案

```bash
ocp conformance run --implementation typescript --json
ocp conformance run --all --json
ocp conformance run --case manifest.query-pack.filtered --json
ocp conformance report --input ./report.json
```

### 7.5 完成判据

- 三种语言消费同一批 suite fixture；
- 正例与反例均纳入报告；
- 失败结果包含语言、case、期望、实际、规范引用和复现命令；
- 同一版本 suite 重复执行产生稳定结果；
- JSON Schema 与 Zod 对同一协议对象的接受/拒绝结论有一致性检查；
- 站点可以直接读取并展示静态报告。

---

## 8. 阶段 4：三条方向联动（1 周）

### 8.1 目标

将三个独立工具连接成完整开发者体验。

### 8.2 任务

| ID | 任务 | 完成判据 |
|---|---|---|
| T1 | 目录 → 沙盒 | 匹配结果可携带 profile 和需求打开预填充沙盒 |
| T2 | 沙盒 → conformance | 沙盒运行结果可生成或关联 conformance case |
| T3 | conformance → 规范 | 每个失败项可回到规范章节、schema 字段和能力声明 |
| T4 | 统一输出 | CLI、站点和 skill 消费同一 JSON 合同 |
| T5 | 实验导出 | 一次完整流程可导出为可复现的静态报告 |

### 8.3 最终演示

```text
搜索支持 product-search 的 Catalog
→ 查看匹配理由和缺失能力
→ 打开该 Catalog 的沙盒
→ 构造并校验 query
→ 查看响应并执行 resolve
→ 运行兼容性检查
→ 导出 TypeScript / Python / Go 示例和实验报告
```

---

## 9. 建议模块边界

```text
packages/ocp-capability/
  能力提取、归一化、索引、过滤、匹配和解释

packages/ocp-sandbox/
  请求构造、schema 校验、响应解释和代码生成

packages/ocp-conformance/
  suite、fixture、执行适配器、报告生成和报告校验

apps/ocp-site-web/
  能力目录、Catalog 对比、协议沙盒和报告展示

packages/ocp-cli/
  catalog capabilities / match / compare
  sandbox query / resolve
  conformance run / report

skills/ocp-catalog/
  能力发现、节点选择、请求生成和结果解释
```

这些边界是目标形态，不要求阶段 0 立即新增三个 workspace package。只有在纯模块已经被两个以上调用方复用、且数据合同稳定后再拆包。

---

## 10. 实施顺序与周期

| 阶段 | 周期 | 主要产出 | 演示点 |
|---|---:|---|---|
| 阶段 0 | 2–3 天 | 能力 profile、匹配合同、报告合同 | 单个 manifest 输出稳定 profile 和匹配解释 |
| 阶段 1 | 1 周 | 能力匹配器、CLI、目录对比 | 输入需求后得到排序、理由和缺失项 |
| 阶段 2 | 1–2 周 | 本地协议沙盒 | 完成一次 query → resolve 并导出代码 |
| 阶段 3 | 1 周 | 统一 conformance runner 和报告 | 三语言同 suite 运行并定位差异 |
| 阶段 4 | 1 周 | 目录、沙盒、报告联动 | 完整闭环现场演示 |

预计总周期为 **4–6 周**。每个小任务单独提交，禁止把能力模型、站点交互和 conformance runner 混在同一个提交中。

---

## 11. Definition of Done

### 11.1 小任务 DoD

- 行为有针对性测试；
- 新增数据结构有 JSON Schema 或 Zod 校验；
- CLI 新命令支持 `--json`；
- 用户可见内容提供中英文版本；
- 不破坏现有稳定 schema；
- 对应工作报告记录实际完成项和未执行门禁。

### 11.2 阶段 DoD

- package typecheck 通过；
- 相关 package 测试通过；
- `site:check` 和 `skill:check` 在涉及站点或 skill 时通过；
- fixture 和报告可重复生成；
- 演示步骤可在无生产环境依赖的条件下复现；
- 文档、实现与 CLI help 使用同一术语。

---

## 12. 风险登记

| 风险 | 概率 | 影响 | 缓解措施 |
|---|---|---|---|
| 新能力 profile 与现有 schema 重复或漂移 | 中 | 高 | profile 只做派生视图，保留原字段来源并用 fixture 锁定映射 |
| 匹配评分被误解为协议合规结论 | 中 | 高 | 将硬性 eligibility 与偏好 score 分开，强制输出 explanation |
| 沙盒范围膨胀为远程 API 调试平台 | 高 | 高 | 首期只运行本地 handler 和 fixture，远程执行不在本仓计划内 |
| JSON Schema 与 Zod 的接受范围不一致 | 中 | 高 | conformance suite 增加双侧接受/拒绝矩阵 |
| 三语言示例使用不同测试口径 | 高 | 中 | 统一 suite manifest、case ID、输入 fixture 和报告结构 |
| 站点引入过多协议逻辑 | 中 | 中 | 匹配、校验和报告生成保持纯模块，站点仅负责交互和展示 |
| 过早拆包增加维护成本 | 中 | 中 | 达到两个以上真实调用方后再拆 package |
| 生成代码与实际请求语义漂移 | 中 | 高 | 所有语言代码生成器共享同一中间请求模型并加入快照/执行测试 |

---

## 13. 明确不纳入本期

| 项目 | 说明 |
|---|---|
| 生产 API 与数据库 | 本计划只处理协议、纯模块、fixture、CLI 和站点体验 |
| 任意 URL 代理 | 不接受用户输入 URL 后由站点服务端代发请求 |
| 用户代码执行 | 不上传、不编译、不运行第三方实现代码 |
| 密钥与凭证管理 | 沙盒不存储 API key、私钥或生产认证信息 |
| 公共提交与排行榜 | 首期只展示仓库内示例和静态报告 |
| 支付、结算和商业归因 | 已有独立路线，不与本计划混合 |
| 链上存证 | 不属于开发者体验闭环 |
| 用户账户和实验历史云同步 | transcript 仅本地导入导出 |

若未来建设远程 conformance 提交、隔离执行、结果持久化或公开 dashboard，应由 `ocp-catalog-instances` 承担运行时与托管职责；本仓只保留合同、runner、fixture、CLI 和公开站点展示。

---

## 14. 首个建议任务

优先启动阶段 0 的第一个窄范围任务：

> 输入一份合法 manifest 和一组能力需求，输出确定性的 `CatalogCapabilityProfile` 与可解释匹配结果。

首个任务只包含：

1. profile 类型；
2. manifest → profile 纯函数；
3. requirement → match result 纯函数；
4. 三组 fixture：完全匹配、部分匹配、硬性不匹配；
5. 单元测试和两句话工作报告。

首个任务不修改站点、不新增 CLI 命令、不拆 workspace package，以最小成本验证统一能力模型是否成立。
