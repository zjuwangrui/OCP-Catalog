# T19 OCP client activity 投递工作汇报

进度：已补齐 `@ocp-catalog/ocp-client` 的 HTTP activity 投递回归测试，覆盖 endpoint URL 规范化、API key、请求方法与事件体，以及 activity 投递失败不影响主协议请求；Node harness 聚焦运行结果为 5 项通过、2 项失败，失败均来自既有测试使用外部 harness 未实现的 `toMatchObject` matcher，并非 T19 新增测试。
计划：本机未安装 Bun，因此未执行 Bun client 测试、typecheck 或仓库级 CI 门禁；这些门禁需在具备 Bun 的环境运行，确认 best-effort 投递契约在 Bun 下保持稳定。生产密钥托管与持久化结算事务继续由 `ocp-catalog-instances` 落地。
