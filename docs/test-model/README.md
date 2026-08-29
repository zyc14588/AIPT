# 测试模型（TEST MODEL）

> 公开测试模型设计合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)。
> `AIPT-MVP-B001` 已实现本页所述 Test Plan、Manifest 与 Queue/Lease/Attempt 合同；`AIPT-MVP-B002` Candidate 只实现 Deterministic Run Core，Agent 编排与真实桌测仍只是后续目标。

## B002 验证矩阵

`AIPT-MVP-B002` 使用 synthetic、game-neutral fixture 与固定 injected seed 覆盖 action happy path、schema/auth/Rule-source/precondition/invariant reject、ledger rollback、duplicate/stale/cross-Run conflict、RNG repeatability/domain separation/seed commitment、derived projection non-authority、strict replay tamper reject 与 malformed input no-panic。相同 initial state、actions、seed 和 versions 重复 20 次必须产生相同 ordered events、RNG evidence、state hash 与 projection hash。

PostgreSQL 18.4 集成仅使用 loopback-only 临时数据库，证明同一 expected sequence 的两个并发 action 恰好一个提交、persisted replay 等于 live state、rollback 保留旧 cursor/hash。历史 B001 Test Plan/Manifest/Queue/Lease/Attempt gate 在精确 B002 Base 上重放；B002 没有执行 Clean Run、Mutant Run、qualification Run、产品模型调用或真实桌测。

## 三条测试轨

`CONFORMANCE`、`HUMAN_SIMULATION`、`ADVERSARIAL` 三轨独立（`R1-Q001`）：

- `CONFORMANCE`：规则/协议符合性。
- `HUMAN_SIMULATION`：模拟真人桌测的完整行为验证。
- `ADVERSARIAL`：对抗性验证（含 Mutant 检出）。

## 双规则模式

同一规则版本分别运行 **PROSE_ONLY** 与 **ORACLE_ASSISTED** 并比较（`R1-Q011`）；两模式采用不同规则/GM 优先级（`R2-Q012`）。

## Persona / GM / Observer

- 固定基准 Persona + 受约束变体（`R1-Q006`）；受约束认知状态模拟误解、遗忘、压力与次优决策（`R1-Q007`）。
- 多个固定 GM Profile，基准为中立熟练规则忠实（`R1-Q008`）。
- 确定性采集器 + 隔离模型 Observer（`R14-Q012`）；Core 无进展指标结合 Observer 信号（`R5-Q021`）。
- Player Persona 与 Character 两层独立建模（`R13-Q010`）。

## 队列层级：Campaign → Suite → Case → Run

- 版本化声明式 Test Plan 的用户层级精确为 `Campaign → Suite → Case → Run`；`Attempt` 是 Run 内部 append-only 执行记录，不进入用户层级，也不得被提升为第五层（`R8-F001`）。
- Case/Run 的任务类型是闭集：`SYSTEM_QUALIFICATION`、`RULE`、`PROSE`、`ORACLE`、`HUMAN_SIMULATION`、`ADVERSARIAL`、`PACKAGE_BUILD`、`CALIBRATION`、`REGRESSION`。
- 每个 Run 在入队事务中绑定不可变 Manifest：AIPT 与游戏仓库 commit/tree、模型分配 ID、Prompt 资产 ID + SHA-256、座席阵容、预算、证据配置、VisibilityProfile、SafetyProfile 与 classification/qualification eligibility（`R8-Q003`、`R8-Q005`）。Manifest 只保存可公开身份与摘要，禁止 Prompt 正文、凭据、DSN、私有绝对路径或真人私密数据；canonical SHA-256 从移除 `canonical_sha256` 后的规范 JSON 投影计算。
- PostgreSQL 18.4 是唯一持久队列权威（`R8-Q006`）。优先级闭集与顺序为 `RELEASE → HOTFIX → MILESTONE → SYSTEM → CALIBRATION → EXPLORATORY → BACKGROUND`，同级再按 `queued_at` 与二进制稳定 `run_id` 排序；资源、模型、标签、认证、依赖完成与 `eligible_after` 等待年龄均 fail-closed 参与选择（`R8-Q007`）。
- Lease 使用数据库时间执行 acquire / heartbeat / expiry / recovery，并以 holder、generation 与 token SHA-256 证明所有权；token source 可注入以支持确定性测试。PostgreSQL 部分唯一索引保证 formal qualification 活跃槽位 `WIP = 1`，并由 16 个并发 claimer 的真实 PostgreSQL race 测试证明。
- 控制面只允许暂停**新的队列 acquisition**；当前合同没有 active formal Run 的人工 pause/resume API。取消只允许尚未开始的 queued Run；同 Run recovery 与 Attempt 历史保留，不覆盖旧记录。

## Campaign 与 Mutant

- 默认六场 Campaign（2 Oracle clean、2 Prose、1 Adversarial、1 Mutant）；MVP 资格另加两场 Mutant Run，**共八场**（`R14-F001`）。
- MVP 门禁要求三个 Mutant 均成功检出（`R15-Q019`）；首批 Mutant：隐藏信息泄漏、Prose-Machine 分歧、状态重放不一致（`R14-Q021`）。
- Mutant 存放于游戏仓库明确 `NON_CANON_TEST_FIXTURE` 目录，以固定游戏 Commit + 不可变 Patch Overlay 应用（`R13-Q018`、`R13-Q019`）。

## 覆盖率

- 规则**语义覆盖**，而非文件/行覆盖（`R3-Q008`）。
- `ORGANIC_DISCOVERY`（自然发现）与 `CONTROLLED_REACHABILITY`（受控可达）分开（`R3-Q011`）。
- 先基准测量，再冻结覆盖率阈值、运行次数与停止条件（`R3-Q013`）；发布覆盖率阈值延期（`DEFER-009`）。

## AI 主观报告的证据限制

- 主观仿真报告与客观体验代理指标分开（`R1-Q014`）。
- AI 只验证安全协议执行正确，**不能证明真人心理安全**（`R14-Q006`）。
- 当前证据等级为 `SYNTHETIC_PLAYTEST_EVIDENCE`；真人校准后才能升级（`R14-Q001`）。
- 恢复运行可发现问题，但不能单独支持发布门禁 PASS（`R2-Q019`）。

## 真人校准与发布前盲测（延期，但发布前强制）

- 发布前必须使用发行候选完成至少一场**可审计真人盲测**（`R3-Q021`）。
- 真人桌测数据作为受控私有校准数据治理；样本由开发团队与招募志愿者分层组成（`R3-Q016`、`R3-Q017`）。
- 校准样本数尚未基准化（`DEFER-008`）：当前**不声称**任何真人等价结论。

## 相邻文档

- [../authority/README.md](../authority/README.md) · [../authority/DECISION_MATRIX.md](../authority/DECISION_MATRIX.md) · [../architecture/README.md](../architecture/README.md) · [../evidence/README.md](../evidence/README.md) · [../milestones/MVP.md](../milestones/MVP.md)
- [返回仓库首页](../../README.md)
