# T23 Live Activity 轮询一致性工作汇报

进度：已为 live Activity 轮询加入请求序列保护；同一 effect 内较旧的请求不能在较新的请求之后覆盖事件、聚合或错误状态，effect 卸载后的响应也继续被丢弃。公开 recent/rollup payload 解析抽为无 React 依赖的纯函数，并新增 8 项测试，覆盖 `attribution_outcome` 保留、严格公开 schema、聚合字段校验以及当前/过期/取消请求判定；Node harness 结果为 8/8 通过，VS Code 对三个 T23 源文件均无诊断。
计划：本机未安装 Bun，未执行站点全量 test、typecheck、lint 或仓库级 CI；需在具备 Bun 的环境补跑这些门禁。未引入新依赖，生产密钥托管与持久化结算事务继续由 `ocp-catalog-instances` 落地。
