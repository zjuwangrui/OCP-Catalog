# T6 小报告

| 项目 | 内容 |
|---|---|
| 任务 | **T6** · activity 事件归因关联与公开投影 |
| 日期 | 2026-10-08 |
| 计划 | [加密与归因 · 收口两周计划](../ocp-crypto-closeout-2w-plan.md) 节后 T6（原 W7-T1） |
| 状态 | 完成判据达成（公开投影不包含明文归因主体；activity-schema 测试 24/24 通过） |

---

activity 事件现在能带上归因关联，但公开 feed 不会把归因凭证带出去：原始事件用一个 strict 的 `attribution` 块承载 `jti`、`agent_id`、`order_id` 等主体，沿用既有 `correlation_id` 做链路关联；公开投影只留下 keyed 的 `correlation_id_hash` 和闭合的 `attribution_outcome`。下一步是 T7 的对外收口——站点文档、skill、updates 和 README，不在本任务里混入。

---

## 本次交付

- 新增五类 attribution activity 事件和 `attribution` raw 字段，所有字段可选；不带归因字段的旧事件继续通过校验。
- 新增 `toPublicActivityEvent()` 公开投影：只有 `public_visibility: "public"` 才生成一行，默认 `aggregate_only` 与 `private` 均不公开。
- `correlation_id` 使用 Web Crypto HMAC-SHA256 生成 `correlation_id_hash`；没有 secret 时直接丢弃关联，不输出无密钥摘要。
- 公开 schema 使用 strict allowlist，只保留 `attribution_outcome`；`jti`、`agent_id`、`order_id`、`report_id` 及 raw `attribution` 均不会进入公开结果。
- 增加值层泄漏保护：自定义公开摘要若夹带归因主体，投影直接拒绝，不做“修补后发布”。
- 公开消费类型补齐 `attribution_outcome`，不把 raw attribution 字段带进前端。

## 验证结果

| 检查 | 结果 |
|---|---|
| activity-schema 测试 | ✅ **24 passed, 0 failed** |
| activity-schema typecheck | ⚠️ 仓库原始 tsconfig 依赖 `bun` 类型；本机未安装 Bun，既有 Node harness 的 activity 配置路径也需要修正，未将环境错误误报为代码通过 |
| 仓库级 typecheck / 全量测试 | ⚠️ 未执行：本机无 Bun，按项目约定留待 CI 或修复 harness 配置后执行 |

测试覆盖了 raw attribution strict 校验、八跳上限、旧事件兼容、错误码同步、HMAC 稳定性与密钥隔离、无明文 `correlation_id`、公开投影无 `jti`/`agent_id`/`order_id`/`report_id`、摘要注入阻断、公开 schema strict 以及 visibility 和分桶回归。

## 边界

本任务只完成 activity schema 与公开投影，不包含字段级加密、生产 secret 管理或真实持久化；前两项不在本期范围，生产密钥和存储由运行实例负责。站点文档与 skill 同步属于 T7。

---

## 相关文档（飞书）

| 文档 | 链接 |
|---|---|
| **加密与归因 · 收口两周计划** | [docs/proposals/ocp-crypto-closeout-2w-plan.md](../ocp-crypto-closeout-2w-plan.md) |
| OCP 商业归因协议 v1.0 | https://pageflux.feishu.cn/docx/MHZbdM1o1oMNMExg9c4cu3cEnXb |
| OCP Canonical JSON v1.0 | https://pageflux.feishu.cn/docx/KHnIdfoTroTPnnxpGaocPTaInrc |
| T5 小报告 | [reports/t5.md](t5.md) |
