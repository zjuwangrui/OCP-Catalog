# 签名协议文档与商业归因现已形成完整文档

OCP Catalog 现在完整说明了签名 discovery/manifest、信任策略、归因链、结算防护和隐私友好的公开 activity 之间的验证路径。

新的[加密与商业归因](/docs/protocols/crypto-attribution/overview)指南介绍：

- OCP canonical JSON 与 Ed25519 文档签名
- `ocp catalog inspect --verify`
- JWKS 密钥选择与信任降级规则
- TypeScript、Python、Go 互操作
- 有界且逐跳签名的归因链
- `jti`、`order_id`、`report_id` 的防重放和幂等语义
- 持久化 `ReplayStore` 与 `LedgerStore` 契约
- 带密钥的 `correlation_id_hash` 与 Activity API 公开投影隐私边界

协议仓库负责定义 schema、签名输入、验证顺序和存储接口。生产密钥托管、持久化数据库、付款执行和部署 secret 仍由运行实例负责。

OCP Catalog skill references 和 README 包清单也已同步更新，让 CLI 使用者和 package 消费者可以从现有入口找到这些能力。
