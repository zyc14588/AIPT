# 架构（ARCHITECTURE）

> 公开顶层架构合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)；
> 冲突处理顺序见 [../authority/README.md](../authority/README.md)。
> M0 历史实现保持不变；`AIPT-MVP-B001` 只实现声明式 Test Plan、不可变 Manifest 与 PostgreSQL Queue/Lease/Attempt authority，不代表 Run Core 已实现。

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

- Agent 只提交**意图**；Core 依次执行 Schema 校验、授权、规则与不变量检查后，才提交权威事件（`R5-Q008`）。
- 影响状态的裁定必须强制引用 Rule ID 或来源（`R5-Q011`）；GM 临时裁定必须形成事件并记录范围、理由、可逆性与期限（`R5-Q012`）。

## 席位与信息隔离

- 每个席位每局一个独立持久 Session，不跨 Run 复用（`R5-Q004`、`R2-Q016`）。
- 每次模型调用前由 Core 生成席位授权视图（`R5-Q006`）。
- ACL 与内容标签在检索之前实施；未标记数据 fail-closed（`R5-Q017`、`R13-Q015`）。
- 数据/内容分类（`R4-F002`）：`PUBLIC`、`UNRELEASED_REMOTE_ALLOWED`、`TABLE_HIDDEN_REMOTE_ALLOWED`、`LOCAL_ONLY_SECRET`、`HUMAN_PRIVATE_DATA`、`CREDENTIAL_SECRET`。

## 上下文与随机性

- AIPT 事件账本是记忆权威；Harness Compaction 只做长度优化（`R4-Q012`）。
- Core 维护版本化确定性随机流及分域子流；开局前记录种子承诺哈希，运行中保密，结束后按证据策略披露（`R5-Q013`、`R5-Q014`）。

## Launcher

- Go Launcher 按门禁顺序启动：配置、PostgreSQL、迁移、模型、Harness、Core、IPC、Web（`R7-Q009`、`R7-Q010`）。
- 本地模型端点默认仅 Loopback（`R6-Q020`）；端口动态分配（`R7-Q014`）。

## 设计状态声明

冻结历史合同继续有效；B001 已交付的 Test Plan / Manifest / Queue-Lease-Attempt 只是权威调度骨架。Run Core 的动作事务、Agent orchestration、模型 gateway、真实 playtest 与 qualification 仍由后续批次建设，当前不得从“可入队/可租约”推断“可运行”。详见 [../authority/BATCH_DEPENDENCY_GRAPH.md](../authority/BATCH_DEPENDENCY_GRAPH.md)。

## 相邻文档

- [../authority/README.md](../authority/README.md) · [../authority/DECISION_MATRIX.md](../authority/DECISION_MATRIX.md) · [../security/README.md](../security/README.md) · [../integration/README.md](../integration/README.md) · [../milestones/M0.md](../milestones/M0.md)
- [返回仓库首页](../../README.md)
