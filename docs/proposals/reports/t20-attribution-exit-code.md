# T20 归因验签退出码工作汇报

进度：已将 `ocp attribution verify` 与 `ocp catalog resolve --verify-attribution` 的负面归因 verdict 统一映射为退出码 `2`，成功仍为 `0`，命令、输入、网络与 JWKS 加载异常继续走退出码 `1`；Node harness 下 attribution 测试 20/20、document verification 回归测试 21/21 通过。
计划：本机未安装 Bun，未执行 Bun 测试、typecheck 或仓库级 CI；下一步在具备 Bun 的环境验证完整 CLI 子进程与仓库门禁，生产密钥托管与持久化结算事务继续由 `ocp-catalog-instances` 落地。
