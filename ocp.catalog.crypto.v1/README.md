# ocp.catalog.crypto.v1

`ocp.catalog.crypto.v1` 冻结 OCP 文档签名的机读契约：一份 OCP JSON 文档如何携带它的签名。

规范文档：[`docs/specs/crypto/v1.md`](../docs/specs/crypto/v1.md)。字节表示由 [`docs/specs/crypto/canonicalization.md`](../docs/specs/crypto/canonicalization.md)（OCP-JCS v1）定义。本 README 只讲机读契约，语义与理由全在规范里。

## Scope

| Schema | 谁产生 | 何时 |
|---|---|---|
| `SignatureEnvelope` | 被签文档的签发节点 | 发布文档时 |

它**不**冻结：被签文档本身的形状（那在各自的包里——`CatalogManifest` 在 `ocp.catalog.handshake.v1`）、JWKS 格式（RFC 7517）、归因链的逐跳签名（`ocp.catalog.attribution.v1`，签名材料不同，不可互换）。

## 文件结构

```text
ocp.catalog.crypto.v1/
├── README.md
├── package.json
├── common.schema.json               # 共享 $defs 与错误码枚举
└── signature-envelope.schema.json   # SignatureEnvelope
```

`$id` 基址 `https://ocp.dev/schema/ocp.catalog.crypto.v1/`，与其余三个包一致。

## 挂载方式

信封作为被签文档的 `signature` 成员内嵌：

```jsonc
{
  "ocp_version": "1.0",
  "kind": "CatalogManifest",
  "catalog_id": "cat_example",
  // ... 载荷其余部分
  "signature": {
    "alg": "EdDSA",
    "kid": "3q2-7w...",
    "issuer": "cat_example",
    "signed_at": "2026-09-18T00:00:00.000Z",
    "payload_hash": "sha256:9f86d0...",
    "signature": "MEUCIQ..."
  }
}
```

内嵌而非放 header 是一个有书面理由的决策，见规范 §2。

## 实现者必读的三条

这三条**无法由 JSON Schema 表达**，纯靠 schema 校验会漏掉，必须在代码里另行实现：

### 1. 签名材料不是「整份文档」

```text
payload_hash = "sha256:" + hex(SHA-256(OCP-JCS-v1(document 删去 "signature")))
签名材料      = OCP-JCS-v1(envelope 删去 "signature")
```

两层。哈希对不上是**载荷**被改（`payload_mismatch`），签名验不过是**信封**被改或用错了公钥（`signature_invalid`）。Schema 只能校验 `payload_hash` 的形状是 `sha256:` 加 64 位十六进制，不能校验它算的是这份文档。

### 2. `issuer` 必须等于文档的 `catalog_id`

Schema 只能约束 `issuer` 是非空字符串。一份把 `issuer` 与 `kid` 一起改挂到另一个节点名下的文档，schema 完全合法。失败码 `issuer_mismatch`。

### 3. 禁止对 Zod `parse()` 结果计算哈希

`catalogManifestSchema` 的 `federation` 分支带大量 `.default(...)`：一份线上没有 `federation` 的 manifest 经 `parse()` 会凭空长出几十个成员，哈希随之不同。签名方与验签方只要有一方在 parse 之后规范化，**每一次都验不过**，且失败与内容无关。

正确做法是 canonicalization.md §9.3 的并行两分支：wire bytes 解析一次，一支去 Zod 校验，一支去规范化签名。

## 错误码

`common.schema.json#/$defs/SignatureErrorCode` 冻结 8 个稳定取值。验签顺序固定为规范 §7 的表格行序，遇首个失败即终止——一份同时违反多条的文档，若顺序不定，三个实现会报三个不同的码。

`unsigned` 与 `signature_expired` 不指向伪造，其余码的运维含义见规范 §8 与 §9 的降级表。
