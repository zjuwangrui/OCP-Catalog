# T21 OCP client correlation 工作汇报

进度：已修复工厂形式 correlation ID 在一次协议请求内被重复求值的问题；协议 `x-ocp-trace-id`、attempted/completed activity 事件现在复用同一请求级 ID，显式 activity override 也只求值一次，并覆盖 `includeClientCorrelationId: false` 与跨请求刷新测试。Node harness 聚焦结果为 8 项通过、2 项失败，失败均为既有测试使用外部 harness 未实现的 `toMatchObject` matcher。
计划：本机未安装 Bun，未执行 Bun 测试、typecheck 或仓库级 CI；需在具备 Bun 的环境验证完整门禁。生产密钥托管与持久化结算事务继续由 `ocp-catalog-instances` 落地。
