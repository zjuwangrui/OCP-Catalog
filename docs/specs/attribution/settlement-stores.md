# 结算存储契约 · Settlement Store Contract

> 状态：**draft**。配套 [attribution v1](./v1.md) §7.1 row 10 / row 11，
> 接口定义在 [`packages/ocp-crypto/src/stores.ts`](../../../packages/ocp-crypto/src/stores.ts)。

attribution v1 把裁决写成了纯规则，但有两行不是纯规则——它们问的是「以前发生过没有」：

| 行 | 问题 | 接口 |
|---|---|---|
| §7.1 row 10 | 这个 `jti` 之前被花掉过吗？ | `ReplayStore` |
| §7.1 row 11 | 这个 `order_id` 之前结算过吗？ | `LedgerStore` |

这两个问题的答案存在**进程外**。本仓给出接口与契约，不给实现；真实的事务存储归运行时
（`ocp-catalog-instances`）。理由和生产密钥托管一样：协议仓定契约，运行时选存储。

`JtiRegistry` 与 `SettlementLedger` 是**仅供演示**的内存实现，存在的目的是让裁决逻辑能在
没有数据库的情况下被测试，不是让谁拿去上线。两个类的文档注释里各写了它们具体怎么坏。

---

## 1. 核心要求：认领与打款必须同事务

一次结算要写**两行**：row 10 的 `jti` 认领、row 11 的结算记录。这两行，加上打款本身，
**必须一起提交**。

两个方向的失败不对称，这是整份契约的由来：

| 失败方向 | 后果 | 能不能补救 |
|---|---|---|
| **认领提交了，打款没提交** | token 被烧在一个没付过钱的订单上。商户重试，row 10 说这个 `jti` 就属于这个订单——确实属于——于是重试结算成功。 | 能。 |
| **打款提交了，认领没提交** | 钱动了，没有任何东西记得。同一个 token 可以对着**另一个** `order_id` 再结算一次。 | **不能。** 事后没有任何办法把它和一笔合法的二次销售区分开。 |

所以：

- **调换事务内的写入顺序救不了。** 不对称的是提交边界，不是语句顺序。
- **重试队列救不了。** 「打款成功、认领待重试」这个状态本身就是漏洞窗口，
  而窗口开着的时长正好等于重试延迟。
- **在打款前面加一层缓存救不了。** 缓存和打款能分别提交，就有窗口。

推论：两个 store **必须落在同一个事务性资源上**——同一个库、同一条连接、同一个 `BEGIN`。
如果部署方手上是两个库 + 两阶段提交，那是另一套设计、另一套失败模式；这种情况下打款应该
放在持有 ledger 的那一侧。

## 2. `SettlementTransaction`

部署方用它把两次写入圈成一个工作单元：

```ts
await settleOrder({
  reports,
  resolveKey,
  ledger: pgLedger,
  jtiRegistry: pgReplay,
  transaction: (work) => db.transaction(work),   // 打款也写在这个回调里
});
```

形状是**包装器**而不是「把事务句柄传进每个方法」，因为知道连接的是 store 实现，而把某个
驱动特有的事务对象穿进本包的类型里，会让下一个驱动没法实现这组接口。store 实现从
`AsyncLocalStorage` 或自己的 per-call 上下文里拿连接。

默认值是 `nonTransactional`——顺序执行，**没有任何原子性**。它对内存实现是正确的（进程崩了
两次写入一起没），对任何持久化 store 都是错的。它是个具名导出而不是内联箭头函数，就是为了
让「生产配置里没覆盖 transaction」这件事在 code review 里能被看见。

## 3. `ReplayStore`（row 10）

```ts
interface ReplayStore {
  claim(jti: string, orderId: string, expiresAt: Date): boolean | Promise<boolean>;
  orderOf(jti: string): string | undefined | Promise<string | undefined>;
}
```

- `claim` 返回 `false` 只有一种含义：这个 `jti` 已经绑在**别的** `order_id` 上了。
  同一对 `(jti, orderId)` 再次认领**必须**返回 `true`——那是重试，不是重放。
- 持久化实现：`jti` 上加唯一约束的 insert，写在结算事务里。
- **保留期是推导出来的，不是配置项。** 记到 token 自己的 `exp` 为止。过了 `exp`，
  row 9 本来就会拒掉这个 token，再记下去保护不了任何东西。
- **过期行可以随时清，活跃行在任何压力下都不许驱逐。** 驱逐一条活跃认领＝悄悄重开一个重放
  窗口，而且是在系统最忙的那一刻。内存实现在写满时选择抛错而不是驱逐，就是这个道理；
  持久化实现应该选择让写入失败。

## 4. `LedgerStore`（row 11）

```ts
interface LedgerStore {
  recordOf(orderId: string): SettlementRecord | undefined | Promise<...>;
  outcomeOf(reportId: string): SettlementRecord | undefined | Promise<...>;
  commit(record: SettlementRecord): void | Promise<void>;
}
```

**两把键，是故意的**（§6.1），合成一把就错：

- `report_id` 是**回报的**幂等键。同一份回报重投，必须只结算一次、返回同一个答案。
- `order_id` 是**结算的**去重键。已结算订单上来了一份**不同的**回报，那是对同一笔销售的
  第二次认领。

只按其中一把去重，结果要么是拒掉每一次重试，要么是付掉每一笔重复。

`commit` 遇到「已结算订单又来一次 `confirmed`」**必须拒绝**，而不是静默覆盖：走到这一步
说明 row 11 检查已经过了，冲突意味着发生了竞态、或者 store 被绕过直接驱动了，两种情况下
安全的答案都是让事务失败。持久化实现用 `order_id` 上的唯一约束兜这一条。

**已结算订单不过期。** 忘掉一个订单＝这个订单可以再被结算一次。所以这里没有 TTL，增长是
真实的——这也是持久化版本必须是一张表而不是一个 `Map` 的另一个原因。

## 5. 为什么方法可以返回 Promise

持久化 store 是一次网络调用。`claim` 如果只能返回裸 `boolean`，这组接口就只能抽象另一个
`Map`，抽象本身变成装饰。所以每个方法都是 `T | Promise<T>`，调用方一律 `await`：内存实现
保持同步，Postgres 实现成为可能。

## 6. 重建（rehydration）

`SettlementLedger` 的构造函数收的是**已提交的记录**，不是重放 `commit`。重新加载状态不是
一次结算，不该触发重复支付的守卫。持久化实现换上来时，裁决逻辑一行都不用动。

## 7. 本仓不提供什么

没有 SQL、没有迁移、没有连接池。这份文档和 `stores.ts` 就是全部交付物。
