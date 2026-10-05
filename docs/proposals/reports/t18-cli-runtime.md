# T18 CLI 运行时兼容工作汇报

进度：已将 CLI skill installer 中的 Bun 专用 `import.meta.dir` 改为标准 Node `fileURLToPath(import.meta.url)` 目录解析，并新增 bundled skill source-discovery 回归测试；独立 Node strip-only smoke 通过，聚焦 harness 测试中 8 项通过、4 项因外部 harness 缺少 Bun matcher 未执行成功。
计划：下一步在具备 Bun 的 CI 环境运行 skill-installer 测试、typecheck 及仓库级冻结安装和全量门禁，确认目录解析改动不影响 Bun 行为；外部 harness 的 matcher 限制不在本任务范围内，生产密钥托管与持久化结算事务继续由 `ocp-catalog-instances` 落地。
