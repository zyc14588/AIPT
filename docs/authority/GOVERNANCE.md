# AIPT 治理（GOVERNANCE）

> 人类可读治理合同。机器权威为 [registry/decisions.json](registry/decisions.json)；
> 冲突处理顺序见 [README.md](README.md)。

## 1. 管理员逻辑角色

`Owner`、`Operator`、`Auditor Manager`、`License Manager` 四个角色逻辑分离，首版允许由同一用户兼任（`R16-Q001`）：

- `Owner`：最终批准合并、发布与高风险决策。
- `Operator`：日常施工与运行操作。
- `Auditor Manager`：审计 Profile 批准、审计争议处理。
- `License Manager`：许可政策执行与授权事务。

## 2. 参与方职责

| 参与方 | 权威职责 |
|---|---|
| GPT | 顶层设计、私有任务规划、主要实质审计、结构化审计结论（`R9-F001`） |
| Codex CLI | 只读核验远端 Commit，整理/规范化证据并生成 `AUDIT_READY`（`R9-F001`） |
| DeepSeek Harness | 在隔离任务工作树中施工、运行本地验收、创建并推送候选 Commit |
| 用户 | 控制本地私有提示词、授权披露、接受/拒绝审计结果、批准合并（`R9-Q023`） |
| Claude Web | 未来生产/高风险独立第二审计；`AIPT-M0-B000` 批次不要求 |

约束：GPT/Codex 不直接修改用户本地仓库；DeepSeek Harness 不得直接写 `main`（`R0-Q008`）。

## 3. 全局施工纪律

- **全局 WIP=1**：首个纵向切片完成前，AIPT 与《未登记》联合施工全局 WIP=1（`R12-Q017`、`R13-Q003`）。
- **单批次单仓库**：一个实施批次只能修改一个权威仓库（`R13-Q002`）。
- **串行批次**：前一批次正式关闭后才可启动下一批次（见 [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md)）。
- **集成只读**：集成任务只读两个来源 Commit，不修改任一仓库（`INT-AIPT-UNREGISTERED-001`）。

## 4. 任务分支、候选 Commit、PR 与合并

1. 每个批次在**独立 Git worktree** 上创建任务分支（如 `task/AIPT-M0-B000`），不得在 `main` 工作树施工（`R12-Q023`、`R0-Q008`）。
2. 实施产出**候选 Commit**，推送任务分支到权威远端。
3. 开发分支 Commit 可审计；正式/生产/发行必须走 PR（`R9-Q005`）。
4. 只有**用户批准**合并；合并后必须执行身份/树/门禁核验（`R9-Q023`）。
5. 合并策略：merge-commit；不得 force push。

## 5. 不可豁免门禁（Non-waivable Gates）

以下硬门禁**不得**被管理员覆盖（`R16-Q003`）：

- Commit / Tree 身份；
- 哈希 / 签名；
- 凭据泄漏；
- 隐藏信息泄漏；
- 权威状态一致性；
- 账本完整性。

## 6. 开发 Break-glass

- 开发阶段允许 Break-glass 越过**非完整性**门禁，但相应产物**无生产/发行资格**（`R16-Q004`）。
- 诊断场景可临时放宽限制（如本地模型不可用时的 `LOCAL_ONLY_SECRET` 外发），运行即失格（`R6-F002`）。
- Claude Web 隐私状态未知时仅允许开发 Break-glass；生产/发行必须已知隐私状态或明确 Incognito 记录（`DCA-Q004`）。

## 7. 追加式管理员裁定

- 管理员决定使用**追加式裁定事件**保存，不覆盖历史（`R16-Q002`）。
- 缺陷处理使用显式状态机和追加裁定（`R8-Q023`）。
- 开发候选可风险接受；生产和发行双审计冲突不能仅靠风险接受合并（`R16-Q005`）。

## 8. 高风险双审计与 MERGE_HOLD

- GPT 为主要实质审计者（`R10-F003`）。
- 高风险/生产边界由第二厂商（Anthropic Claude Web）独立审计；第二审计 `FAIL`/`BLOCKED` 触发 `AUDIT_DISPUTE` 与 `MERGE_HOLD`（`R10-F003`、`R9-F003`）。
- 第二审计者未配置时允许开发态施工与真实桌测，生产/发行 Gate 阻塞（`R13-Q024`）。
- MVP Development Pass 以 GPT 审计为硬门禁；Claude 完成管理员批准后用于生产/高风险（`R14-Q024`）。
- 当前第二审计状态：`ADMIN_APPROVAL_AND_PRIVACY_PROFILE_PENDING`，尚不具备生产资格（见 [registry/project-status.json](registry/project-status.json)）。

## 9. 本批次的 B000 例外

`AIPT-M0-B000` 是唯一一次在公共 CI 尚不存在时关闭的 Bootstrap 批次（`BOOTSTRAP-Q001`）：

- 无 CI；以**最终本地确定性验收 + GPT 审计**关闭；
- `AIPT-M0-B001` 建立公共 CI 后，必须**追溯验证** B000 的文档、JSON、链接与 MIT License；
- 该例外不适用于 B001 之后的普通批次。

## 相邻文档

- [README.md](README.md) · [PROJECT_CHARTER.md](PROJECT_CHARTER.md) · [DECISION_MATRIX.md](DECISION_MATRIX.md) · [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md) · [../security/README.md](../security/README.md) · [../evidence/README.md](../evidence/README.md)
- [返回仓库首页](../../README.md)
