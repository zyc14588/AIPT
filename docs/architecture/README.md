# 架构（ARCHITECTURE）

> 公开顶层架构合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)；
> 冲突处理顺序见 [../authority/README.md](../authority/README.md)。
> M0 与 `AIPT-MVP-B001` 历史实现保持不变；`AIPT-MVP-B002` Candidate 只新增 game-neutral Deterministic Run Core，不改变 Launcher、Agent 或模型边界。

## 技术栈与进程边界

- 技术栈：**Go Core + TypeScript Harness Adapter / Web UI**，单一多语言 Monorepo。
- 进程边界（`R4-F001`）：
  - 两个长期应用服务：**AIPT Core** 与 **Harness Host**；
  - **PostgreSQL** 是基础设施（持久权威账本）；
  - 适配器 Worker 是短生命周期进程。

## 进程间通信（IPC）

- 第一阶段使用 **stdio JSON-RPC**；后续增加 **Unix Domain Socket**；协议同时支持两种传输（`R4-F005`）。

## 持久化：PostgreSQL 事件账本与 B001 队列权威

- PostgreSQL 上维护**追加式哈希链事件账本**（`R4-Q008`）。
- 事件账本是权威：快照、投影与 UI 状态均可从账本重建，属于派生/次级（`R4-Q009`）。
- 冻结迁移 `000001_ledger.sql` 保持精确字节与 SHA-256；B001 仅新增 `000002_playtest_queue.sql`，定义 Campaign/Suite/Case/Run、不可变 Run Manifest、依赖、queue control、lease 与 append-only Attempt。
- 队列选择由 PostgreSQL 中的确定性 priority rank、`queued_at`、`run_id COLLATE "C"`、依赖与 capability 条件决定；正式资格槽位通过数据库部分唯一索引实施 WIP=1，而不是进程内互斥。
- Lease 的 acquisition、heartbeat、expiry 与 recovery 使用数据库时间；generation + holder + token hash 构成所有权边界。生产库不保存明文 token，调用方返回值中的 token 由可注入 `TokenSource` 生成。

## 确定性状态提交

- B002 的 [`internal/runcore`](../../internal/runcore) 实现通用版本化动作事务：caller 只提交 intent/action proposal；Core 依次执行 Schema、Run/Actor 授权、Rule/Source、当前状态前置条件、不变量、确定性 RNG、next-state 不变量，随后才把完整事件原子追加到 PostgreSQL ledger，最后生成派生 projection 与 receipt（`R5-Q008`）。任何失败都不会推进 state、RNG cursor 或 projection。
- 影响状态的裁定必须强制引用 Rule ID 或来源（`R5-Q011`）；GM 临时裁定必须形成事件并记录范围、理由、可逆性与期限（`R5-Q012`）。
- Initial Run State 绑定 B001 Manifest identity、runtime-adapter input identity 与只读 source package commit/tree/content identity；binding 被复制进每个 authoritative event，handler 只能返回新的 domain JSON，不能改写 identity、sequence、RNG cursor 或 ledger。
- PostgreSQL append-only hash chain 仍是唯一持久权威；RunState 和 projection 是可由 genesis + ordered events 重建的 derived values。B002 未新增 table、snapshot authority 或 migration。

## 席位与信息隔离

- 每个席位每局一个独立持久 Session，不跨 Run 复用（`R5-Q004`、`R2-Q016`）。
- 每次模型调用前由 Core 生成席位授权视图（`R5-Q006`）。
- ACL 与内容标签在检索之前实施；未标记数据 fail-closed（`R5-Q017`、`R13-Q015`）。
- 数据/内容分类（`R4-F002`）：`PUBLIC`、`UNRELEASED_REMOTE_ALLOWED`、`TABLE_HIDDEN_REMOTE_ALLOWED`、`LOCAL_ONLY_SECRET`、`HUMAN_PRIVATE_DATA`、`CREDENTIAL_SECRET`。

## 上下文与随机性

- AIPT 事件账本是记忆权威；Harness Compaction 只做长度优化（`R4-Q012`）。
- Deterministic Run Core 使用 `AIPT_RNG_HMAC_SHA256_V1` 与稳定 domain/stream identity；root seed 由可注入 `SeedSource` 提供，commitment `AIPT_SEED_COMMITMENT_SHA256_V1` 在首次 draw 前固定。事件记录 stream、draw index、result 与算法版本，但普通 state/projection/receipt 不包含 root seed（`R5-Q013`、`R5-Q014`）。
- replay 先验证 `AIPT_LEDGER_V1` 哈希链、不可变 binding、seed commitment、event/version/order，再重新执行每个 deterministic transition 与 RNG draw；任何缺失、重排、篡改、版本漂移或最终 hash 不符均 fail-closed。

## Launcher

- Go Launcher 按门禁顺序启动：配置、PostgreSQL、迁移、模型、Harness、Core、IPC、Web（`R7-Q009`、`R7-Q010`）。
- 本地模型端点默认仅 Loopback（`R6-Q020`）；端口动态分配（`R7-Q014`）。

## 设计状态声明

冻结历史合同继续有效；B001 的 Test Plan / Manifest / Queue-Lease-Attempt 与 B002 Deterministic Run Core 保持分层。B002 Candidate 可作为 library 被确定性测试和 replay，但 Launcher 的 MODEL/HARNESS/IPC 前序 gate 仍未实现，因此不代表产品 runtime ready。Agent orchestration、模型 gateway、真实 playtest 与 qualification 仍由后续批次建设。详见 [../authority/BATCH_DEPENDENCY_GRAPH.md](../authority/BATCH_DEPENDENCY_GRAPH.md)。

## 相邻文档

- [../authority/README.md](../authority/README.md) · [../authority/DECISION_MATRIX.md](../authority/DECISION_MATRIX.md) · [../security/README.md](../security/README.md) · [../integration/README.md](../integration/README.md) · [../milestones/M0.md](../milestones/M0.md)
- [返回仓库首页](../../README.md)
