# T25 Activity API 恢复提示工作汇报

进度：已移除官网 Activity API 不再存在的 `bun run activity:api` 与迁移指引，改为提示部署方配置 `VITE_OCP_ACTIVITY_API_URL` 指向可用的公开投影 endpoint；中英文恢复提示保持一致且不承诺本仓库提供 API runtime。
计划：本机未安装 Bun，未执行站点 typecheck、全量测试、`site:check` 或仓库级 CI；需在具备 Bun 的环境补跑门禁并进行中英文页面检查。Activity API 的部署、数据库与持久化责任不属于本仓库。
