# 架构（ARCHITECTURE）

> 公开顶层架构合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)；
> 冲突处理顺序见 [../authority/README.md](../authority/README.md)。
> M0、`AIPT-MVP-B001`、`AIPT-MVP-B002` 与 `AIPT-MVP-B003` 已关闭历史保持不变；`AIPT-MVP-B004` 在独立层实现版本化 Model Profile 与受治理 Harness gateway。

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

- B003 [`internal/orchestrator`](../../internal/orchestrator) 固定建立 1 个 `GM` 与 4 个 `PLAYER_n` 机器席位；Run、role contract、Session、Persona、Character（Player）与 visibility identity 均显式绑定，显示名或数组下标不是 authority。Oracle、Retriever、Rules/State Engine 与 Observer 不是伪玩家席位。
- 每个席位每局一个独立持久 Session，不跨 Run/seat 复用；Session recovery 只能生成同 Run/seat、递增 generation、显式 parent 的新 identity。Session 是可从事件重建的 operational continuity，不是第二套记忆 Authority（`R5-Q004`、`R2-Q016`）。
- 每次 provider-neutral invocation 前生成 canonical `SEAT_AUTHORIZED_VIEW`；完整 authoritative state 不进入 Agent context（`R5-Q006`）。
- 固定管线为 classification → ACL/visibility → retrieval → citation/hash verification → context assembly。未标记数据 fail-closed；secret/human-private/system-internal 分类不能进入普通 Agent context（`R5-Q017`、`R13-Q015`）。
- 数据/内容分类（`R4-F002`）：`PUBLIC`、`UNRELEASED_REMOTE_ALLOWED`、`TABLE_HIDDEN_REMOTE_ALLOWED`、`LOCAL_ONLY_SECRET`、`HUMAN_PRIVATE_DATA`、`CREDENTIAL_SECRET`。

## B003 确定性 Agent Orchestrator

- versioned `OrchestrationPolicy` 显式提供 seat/interruption order、timeout 与 transport/semantic/recovery 有界预算；缺失或负数界限拒绝。相同 Run binding、policy、scripted response/failure、event history 与 fake clock 输入产生相同 floor events、context hashes、Session transitions、repair decisions 与 accepted action order。
- floor state machine 支持 discussion、显式 interruption、private chat、group decision 与 GM clarification。并发请求不靠 goroutine/模型延迟竞争；interruption 与 group tie 使用 policy/input 中的显式顺序，非法 transition fail-closed。
- Persona 是 immutable baseline 加 event-driven、0..100 有界的 misunderstanding/forgetting/stress/suboptimal-decision state；Character 是独立 world projection。二者具有不同 identity/hash，Persona event 不写 Character，Character 状态也不反向改写 Persona baseline。
- Context 将 trusted role/policy/Persona/tool contract 与 untrusted state window/rulebook/module/log/model prose 分区；所有列表 canonical 排序并绑定 authorized projection、Session、Persona、Character、summary、event window 与 capability identity。memory summary 只能引用当前授权事实/来源，不能创造、覆盖或重新引入隐藏事实。
- Agent output 将 speech 与 structured B002 `ActionProposal` 分离。只有 structured action 可影响状态；speech/action machine claim 冲突进入有限 semantic repair，仍冲突则拒绝。Transport retry、semantic retry 与 Session recovery 分别审计，按顺序接受第一个合法结果，不做 best-of-N。
- `RunCoreSubmitter` 是唯一 mutation adapter：B003 自身没有 gameplay state writer，只调用已关闭 B002 `Run.Execute`。成功后同 invocation/action 不得再次提交，因而不会重复消费 RNG 或追加 authoritative event。

## B004 模型执行层

- [`internal/modelgateway`](../../internal/modelgateway) 实现 B003 `AgentInvoker`，但不重新拼装 full state；输入只能是 B003 已授权 Context Bundle。分类/egress 在 Core 与 gateway 两层验证，unsafe reduction 结构化失败。
- Model Profile、Sampling Profile、Harness identity、certification 与 complete execution tuple 分别版本化、哈希绑定。Run Manifest 为 GM 和四个 Player 固定独立 assignment identity；同 underlying model 也不退化为 global model。静默 fallback 被拒绝，显式 replacement 形成事件并取消 clean eligibility。
- 唯一 backend 是 `REMOTE_DEEPSEEK` 与 `LOCAL_LLAMACPP`。前者精确请求 `deepseek-v4-pro`；后者以已登记 binary/GGUF/template/hardware identity 启动动态 IPv4 loopback `llama.cpp`。AIPT 不实现模型下载或 hot-switch。
- 所有 model invocation 都经固定 DeepSeek Harness ACP 进程路由；Gateway 验证 process/package/protocol/model identity、frame、timeout/cancellation 与结构化响应。AIPT Core/Orchestrator 没有 provider HTTP 或 llama inference bypass。
- 当前冻结登记为 `HARNESS-01`、`GGUF-04` 与 `LLAMACPP-01`。受控 `REMOTE_DEEPSEEK` 与 `LOCAL_LLAMACPP` minimum certification 均已 PASS；local 路径完成批准 root containment、canonical target、完整 SHA-256、GGUF metadata、executable compatibility、受管启动、Harness role invocation 与有界关闭/失败验证，且不允许下载、猜测或替代资产。公开 registration/certification 只保留稳定身份、摘要与结果，不保留 credential 值或本机路径。

## 上下文与随机性

- AIPT 事件账本是记忆权威；Harness Compaction 只做长度优化（`R4-Q012`）。
- Deterministic Run Core 使用 `AIPT_RNG_HMAC_SHA256_V1` 与稳定 domain/stream identity；root seed 由可注入 `SeedSource` 提供，commitment `AIPT_SEED_COMMITMENT_SHA256_V1` 在首次 draw 前固定。事件记录 stream、draw index、result 与算法版本，但普通 state/projection/receipt 不包含 root seed（`R5-Q013`、`R5-Q014`）。
- replay 先验证 `AIPT_LEDGER_V1` 哈希链、不可变 binding、seed commitment、event/version/order，再重新执行每个 deterministic transition 与 RNG draw；任何缺失、重排、篡改、版本漂移或最终 hash 不符均 fail-closed。

## Launcher

- Go Launcher 按门禁顺序启动：配置、PostgreSQL、迁移、模型、Harness、Core、IPC、Web（`R7-Q009`、`R7-Q010`）。
- 本地模型端点默认仅 Loopback（`R6-Q020`）；端口动态分配（`R7-Q014`）。

## 设计状态声明

冻结历史合同继续有效；B001 Test Plan/Manifest/Queue、B002 Run Core、B003 Orchestrator 与 B004 model gateway 保持分层。MODEL/HARNESS 及双 backend controlled minimum certification 已实现，IPC 仍未实现，因此产品 runtime 不 ready。真实 playtest 与 qualification 属于后续批次。详见 [../authority/BATCH_DEPENDENCY_GRAPH.md](../authority/BATCH_DEPENDENCY_GRAPH.md)。

## 相邻文档

- [../authority/README.md](../authority/README.md) · [../authority/DECISION_MATRIX.md](../authority/DECISION_MATRIX.md) · [../security/README.md](../security/README.md) · [../integration/README.md](../integration/README.md) · [../milestones/M0.md](../milestones/M0.md)
- [返回仓库首页](../../README.md)
