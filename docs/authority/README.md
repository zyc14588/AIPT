# AIPT 权威索引（Authority Index）

本页是 AIPT 权威文档的入口，解释权威分层、冲突处理顺序与最短阅读路径。

## 权威分层

AIPT 的权威信息分两层：

1. **机器登记（Machine Registry）**——决策 ID、选择、状态与覆盖关系的**机器权威**：
   - [registry/decisions.json](registry/decisions.json)：全部 454 条决策（`ACTIVE` / `REFINED` / `SUPERSEDED`）。
   - [registry/supersessions.json](registry/supersessions.json)：覆盖与细化关系。
   - [registry/deferred-parameters.json](registry/deferred-parameters.json)：允许延期、尚未冻结的参数。
   - [registry/project-status.json](registry/project-status.json)：工作轨、仓库与审计状态快照。
2. **人类文档**——可读解释与施工合同。若与机器登记冲突，以机器登记为准；人类文档**不是**第二份独立权威。

## 冲突处理顺序

当多份材料说法不一致时，按以下顺序裁决：

1. 当前 `ACTIVE` / 最新的细化决定（`REFINED` 链末端的 `ACTIVE` 决定）；
2. Machine Decision Registry（[registry/decisions.json](registry/decisions.json)）；
3. 人类领域文档（本目录及 [../architecture](../architecture/README.md) 等领域文档）；
4. 里程碑合同（[../milestones/M0.md](../milestones/M0.md)、[../milestones/MVP.md](../milestones/MVP.md)）；
5. 历史 / 被覆盖决定（[SUPERSEDED_DECISIONS.md](SUPERSEDED_DECISIONS.md)）仅用于追溯，不得作为当前方案引用。

## 权威文档地图

| 文档 | 内容 |
|---|---|
| [PROJECT_CHARTER.md](PROJECT_CHARTER.md) | 项目章程：目标、首发范围、非目标与边界 |
| [GOVERNANCE.md](GOVERNANCE.md) | 治理：角色、职责、门禁与合并规则 |
| [DECISION_MATRIX.md](DECISION_MATRIX.md) | 人类可读领域决策矩阵（关键决定 ID） |
| [SUPERSEDED_DECISIONS.md](SUPERSEDED_DECISIONS.md) | 被覆盖 / 被细化决定及其当前执行含义 |
| [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md) | 延期参数：状态、阻塞范围与关闭条件 |
| [PROJECT_STATUS.md](PROJECT_STATUS.md) | 当前项目状态与下一步 |
| [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md) | 全局串行批次依赖图 |

领域文档：架构 [../architecture/README.md](../architecture/README.md) · 安全 [../security/README.md](../security/README.md) · 证据 [../evidence/README.md](../evidence/README.md) · 测试模型 [../test-model/README.md](../test-model/README.md) · 集成 [../integration/README.md](../integration/README.md) · 许可 [../licensing/README.md](../licensing/README.md) · 供应链 [../supply-chain/README.md](../supply-chain/README.md)

## 工具与供应链登记（B001）

B001 建立公共 CI 与供应链基础后，以下工具登记随仓库同行（工程锁，不是决策权威）：

| 登记 | 内容 |
|---|---|
| [../../tools/toolchain.lock.json](../../tools/toolchain.lock.json) | 精确工具链资格：Go 1.26.6（B003 安全重资格，理由 reachable standard-library vulnerabilities，触发公告 GO-2026-6090 crypto/tls、GO-2026-6088 encoding/xml、GO-2026-5972 encoding/asn1，各已由 Go 1.26.6 官方修复；`selected_by_batch` 保持历史 `AIPT-M0-B001`，`provenance` 同时记录 B001 初始资格 Go 1.26.5 与 B003 安全重资格）/ Node 24.19.0 LTS / pnpm 11.4.0 / PostgreSQL 18.4，含官方来源、完整性材料与验证时间 |
| [../../tools/ci-actions.lock.json](../../tools/ci-actions.lock.json) | 公共 CI Actions 的稳定 tag → 完整 Commit SHA 映射与来源验证 |
| [../../tools/supply-chain/policy.json](../../tools/supply-chain/policy.json) | `R4-Q023` 供应链机器规则 |
| [../../tools/supply-chain/licenses.json](../../tools/supply-chain/licenses.json) | 许可证清单（AIPT MIT、CI Actions、工具链与扫描工具） |

规则：Workflow `uses:` 必须与该登记一致；任何新依赖必须先进入许可证清单并获得批准记录。

## 最短阅读路径

- **施工者**：本页 → [DECISION_MATRIX.md](DECISION_MATRIX.md) → [GOVERNANCE.md](GOVERNANCE.md) → [PROJECT_STATUS.md](PROJECT_STATUS.md) → [../milestones/M0.md](../milestones/M0.md)
- **审计者**：本页 → [SUPERSEDED_DECISIONS.md](SUPERSEDED_DECISIONS.md) → [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md) → [registry/decisions.json](registry/decisions.json) → [../evidence/README.md](../evidence/README.md)

## 私有提示词政策

本公共仓库**不包含**私有提示词正文。全部提示词资产仅保存在本地加密 Git 仓库，不配置任何远端、不公开正文（`R13-F001`）。公共文档只记录政策，不记录提示词内容或存储位置。

## 状态名约定

- 决策状态：`ACTIVE`（当前权威）、`REFINED`（已被细化，指向细化决定）、`SUPERSEDED`（已被取代，指向取代决定）。
- 延期参数状态：见 [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md)。`DEFER-016` 已由 B001 资格批次 `RESOLVED`（`resolved_by_batch = AIPT-M0-B001` 不可变历史事实）；当前 Go 身份由 B003 安全重资格更新为 **1.26.6**（理由 reachable standard-library vulnerabilities，见 [../../tools/toolchain.lock.json](../../tools/toolchain.lock.json) 的 provenance），其余 15 项为非冻结状态（如 `DEFERRED_TO_*`、`ADMIN_DECISION_PENDING`），不得写成已实现。

## 返回

- [仓库首页](../../README.md)
