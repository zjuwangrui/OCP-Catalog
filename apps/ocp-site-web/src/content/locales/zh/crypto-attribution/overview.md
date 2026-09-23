# 加密与商业归因

当部署需要可验证的发现、信任判断或商业归因时，OCP Catalog 使用签名协议文档和签名归因链。本页介绍本仓库中的协议包，并说明协议契约与生产运行时服务之间的边界。

## 签名发现文档与 manifest

Catalog 可以发布带签名的 discovery 文档和 manifest。签名覆盖使用 OCP canonical JSON（OCP-JCS）编码的文档 payload，并使用 Ed25519 `SignatureEnvelope`。验证方可以根据 `kid` 解析签名公钥，检查算法声明，验证 canonical bytes，并应用文档声明的 trust profile。

检查远程或本地 manifest 时使用 CLI：

```bash
ocp catalog inspect https://catalog.example.com/ocp/manifest --verify
```

签名文档的验证采用 fail-closed 语义。签名错误、未知密钥、不支持的算法或无效 canonical payload 不能被当作可信 manifest 展示。只有在协议 trust policy 明确允许时，验证方才可以保留较低的 trust tier；不能把无法验证的文档静默变成可信文档。

`@ocp-catalog/ocp-crypto` 提供 canonicalization、Ed25519 签名与验签、JWKS 密钥选择、discovery 密钥缓存和文档信任评估。TypeScript、Python 和 Go 实现使用相同的签名输入，目标是得到可复现的结果。互操作性通过共享 fixture 测试，而不是依赖某一种语言的 JSON 序列化器。

## 归因链

`AttributionToken` 携带 agent、对象、provider、purpose 和 `jti` 等核心声明，随后是由 origin 和 relay 节点组成的有界链。每一跳都对自己的 canonical signing input 签名。relay 必须先验证上游完整链，再追加自己的 hop；不能签署一条已经损坏的链并把失败传给下游。

验证遵循协议规定的顺序，并在第一个失败处停止。实现使用 `key_not_found`、`signature_invalid`、`token_expired`、`replayed_jti`、`duplicate_order` 和 `chain_broken` 等明确结果，让运维可以区分无效 token、缺少运行时密钥和结算冲突。归因链最多八跳。

结算使用 `ConversionReport`，并分别处理两个幂等问题：

- `jti` 把 token 绑定到 order，防止同一个 token 被用于另一个 order。
- `order_id` 和 `report_id` 让结算和报告投递具备幂等性。

本仓库中的 `ReplayStore` 和 `LedgerStore` 是接口与事务契约。内存实现只用于测试和演示。生产部署必须提供持久化存储，并在同一个事务资源中提交 replay claim、ledger record 和 payout。SQL schema、连接池、付款集成和密钥托管属于拥有这些系统的运行时，不属于协议包。

## 公开 activity 隐私边界

原始 activity 事件可以携带可选且 strict 的 `attribution` 块，用于内部链路关联。该块可能包含 `jti`、`agent_id`、`order_id`、`report_id`、跳数、purpose 和闭合 outcome code，但它不是公开 API 结构。

只有显式设置 `public_visibility: "public"` 的事件才会生成公开 activity 行。公开 allowlist 可以保留闭合的 `attribution_outcome`，但不会复制 raw attribution 块或其中的主体标识。需要关联时，投影使用带密钥的 HMAC-SHA-256 生成 `correlation_id_hash`。没有投影 secret 时不会输出 correlation 摘要。如果自定义摘要试图把归因主体偷偷带入公开行，值层防护会拒绝投影。

这个边界是有意设计的：公开 rollup 和最近 activity 可以解释协议结果，但不会成为 raw 商业归因、订单标识或 agent 身份数据的来源。消费者应使用 Activity API 公开投影和 `events tail`，不要读取原始审计 payload。

## 范围与部署边界

本仓库定义 schema、密码学原语、验证顺序和存储接口。不提供生产 secret 管理、数据库持久化、付款执行或托管密钥服务。部署方可以选择这些组件，但必须保持协议契约和公开投影隐私边界不变。
