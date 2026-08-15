# 测试模型（TEST MODEL）

> 公开测试模型设计合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)。
> **本节全部为设计目标；B000 未实现任何测试代码。**

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

- 任务层级 `Campaign → Suite → Case → Run`；`Attempt` 是 Run 内部执行记录，不进入用户层级（`R8-F001`）。
- 每个 Run 生成不可变 Manifest，固定源码、模型、Prompt、阵容、预算与证据（`R8-Q003`）；入队后冻结（`R8-Q005`）。
- PostgreSQL 持久队列，确定性优先级调度（`R8-Q007`）。

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
