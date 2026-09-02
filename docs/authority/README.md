# AIPT 权威索引（Authority Index）

本页是 AIPT 权威文档的入口，解释权威分层、冲突处理顺序与最短阅读路径。

## 权威分层

AIPT 的权威信息分两层：

1. **机器登记（Machine Registry）**——决策 ID、选择、状态与覆盖关系的**机器权威**：
   - [registry/decisions.json](registry/decisions.json)：全部 454 条决策（`ACTIVE` / `REFINED` / `SUPERSEDED`）。
   - [registry/supersessions.json](registry/supersessions.json)：覆盖与细化关系。
   - [registry/deferred-parameters.json](registry/deferred-parameters.json)：允许延期、尚未冻结的参数。
   - [registry/batch-graph.json](registry/batch-graph.json)：M0 closeout 后的 13 项 MVP 权威串行图。
   - [registry/project-status.json](registry/project-status.json)：工作轨、仓库与审计状态快照。
   - [registry/unregistered-aipt-p1-b000-authority.json](registry/unregistered-aipt-p1-b000-authority.json)：`UNREGISTERED-AIPT-P1-B000` 的版本化、机器可验证 task-scoped Authority Contract；其优先级低于当前 ACTIVE/REFINED decision chain，高于 roadmap prose。
   - [registry/unregistered-aipt-p1-b000-authority-amendment-001.json](registry/unregistered-aipt-p1-b000-authority-amendment-001.json)：R1 replacement Amendment；在不修改上述冻结 Authority 的前提下，追加授权 validator identity supersession、B001 historical CLOSED-state repair、exact-target post-merge reverification，以及一次性 direct governance closeout successor；只有按序且已接受的 Amendment/supersession record 才进入 effective Authority。
   - [registry/unregistered-aipt-p1-b000-authority-amendment-002.json](registry/unregistered-aipt-p1-b000-authority-amendment-002.json)：Amendment-002 的不可变 candidate-time semantic snapshot；其冻结字段仍为 `CANDIDATE_FROZEN` / `accepted=false`，实际治理状态已是 MERGED、POST_MERGE_VERIFIED、尚未 CLOSED。
   - [registry/unregistered-aipt-p1-b000-authority-amendment-003.json](registry/unregistered-aipt-p1-b000-authority-amendment-003.json)：lifecycle externalization Amendment candidate；把不可变 semantic snapshot 与 append-only lifecycle acceptance records 分离。
   - [registry/authority-lifecycle/registry.json](registry/authority-lifecycle/registry.json)：通用 Authority lifecycle registry、确定性顺序、历史 migration anchors 与 projection policy。
   - [registry/integration-closeouts/int-aipt-unregistered-mvp-001-closeout.json](registry/integration-closeouts/int-aipt-unregistered-mvp-001-closeout.json)：只读 fixed-pair integration 的 canonical closeout；明确 `repository_merge_performed = false`，不伪造 Candidate、merge parents 或 merge CI。
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
| [registry/batch-graph.json](registry/batch-graph.json) | 机器可读 MVP 批次图（13 项，顺序与字段冻结） |
| [UNREGISTERED_AIPT_P1_B000_AUTHORITY.md](UNREGISTERED_AIPT_P1_B000_AUTHORITY.md) | P1 B000 的目标、边界、package/adapter/source/visibility/compatibility 与验收解释 |
| [registry/unregistered-aipt-p1-b000-authority.json](registry/unregistered-aipt-p1-b000-authority.json) | P1 B000 执行机器权威、精确路径策略、N01–N39 与 lifecycle/stop contract |
| [amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_001.md](amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_001.md) | P1 B000 Authority Amendment 001 的人类可读解释；原冻结身份与缺失历史 CI 事实保持不变 |
| [registry/unregistered-aipt-p1-b000-authority-amendment-001.json](registry/unregistered-aipt-p1-b000-authority-amendment-001.json) | append-only Amendment、确定性 effective-authority resolution、supersession chain 与 recovery evidence 的机器权威 |
| [amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_002.md](amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_002.md) | 为什么历史 P0 closed set 不能直接验证 P1 candidate，以及 predecessor/preservation/delta 三层替代模型 |
| [registry/unregistered-aipt-p1-b000-authority-amendment-002.json](registry/unregistered-aipt-p1-b000-authority-amendment-002.json) | Amendment-002 immutable semantic snapshot；actual lifecycle 为 MERGED / POST_MERGE_VERIFIED / not CLOSED，因此尚不 effective |
| [amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_003.md](amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_003.md) | immutable semantics + append-only lifecycle acceptance model、自关闭 bootstrap 与 Amendment-002 recovery 边界 |
| [registry/unregistered-aipt-p1-b000-authority-amendment-003.json](registry/unregistered-aipt-p1-b000-authority-amendment-003.json) | Amendment-003 machine authority、exact path policy、A3-N01–N30 与 stop contract |
| [registry/authority-lifecycle/registry.json](registry/authority-lifecycle/registry.json) | canonical lifecycle record registry、legacy immutable anchors、ordering 与 projection rules |
| [amendments/INT_AIPT_UNREGISTERED_MVP_001_CLOSEOUT_AUTHORITY_001.md](amendments/INT_AIPT_UNREGISTERED_MVP_001_CLOSEOUT_AUTHORITY_001.md) | read-only integration closeout governance gap、固定证据边界与 B005 predecessor contract |
| [registry/integration-closeouts/int-aipt-unregistered-mvp-001-closeout.json](registry/integration-closeouts/int-aipt-unregistered-mvp-001-closeout.json) | `INT-AIPT-UNREGISTERED-MVP-001` canonical closeout record；仅含 Commit/Tree/SHA-256/stable IDs/result/counters/classification |
| [registry/authority-lifecycle/records/int-aipt-unregistered-mvp-001-closeout-authority-001/003-closed.json](registry/authority-lifecycle/records/int-aipt-unregistered-mvp-001-closeout-authority-001/003-closed.json) | `INT-AIPT-UNREGISTERED-MVP-001-CLOSEOUT-AUTHORITY-001` canonical Authority closeout；前驱记录冻结 exact merge 与 post-merge CI |

## Authority Amendment 解析规则

Authority Amendment 不采用“最新文件获胜”或“main 当前 hash 即权威”。解析顺序固定为：不可变 base Authority → 按唯一 sequence 与 accepted merge first-parent ancestry 排序的已接受 Amendment → 由这些 Amendment 授权、并通过独立验收的连续 supersession chain。原 artifact hash、授权 Amendment、变更理由、repair Candidate 与独立验收身份必须同时保留；冲突或断链一律 fail closed。

Amendment-001/R1 的 bootstrap 权限只覆盖 replacement Candidate、其 legal merge 和一个直接治理 closeout child。该 child 只能新增精确 closeout evidence 路径，不能修改 Base Authority、Amendment 语义、validator、schema 或业务代码；`CLOSED` 后权限自动失效。F1/F2 仍实际执行并保留原始失败证据，只有冻结 hash 与精确缺陷指纹同时匹配才可分类为 `KNOWN_PREEXISTING_BOOTSTRAP_DEFECT`。

Amendment-002 已按批准 candidate/tree 合法 merge，且 merge CI 已通过；它尚未 CLOSED，因此尚不 effective。其 semantic 文件中的 `CANDIDATE_FROZEN` / `accepted=false` 是冻结时快照，不得原地改写。历史 P0 gates 固定在 immutable predecessor 上执行，Amendment-002 semantic gate 固定在 exact legal merge 上重放；当前 successor lifecycle 由独立 record validator 处理。

Amendment-003 candidate 定义唯一 canonical lifecycle chain：`MERGED → POST_MERGE_VERIFIED → CLOSED`。Record 通过 sequence、explicit predecessor digest 与 accepted Git commit ordinal 排序；mtime、文件枚举、lexical latest 与 main descendant 都不构成 acceptance。`project-status.json` 只能是可重建 projection。Amendment-003 尚未获得 merge/closeout 权限，Amendment-002 closeout 与 B000 implementation 也仍未授权。

`INT-AIPT-UNREGISTERED-MVP-001-CLOSEOUT-AUTHORITY-001` 增加独立的 read-only integration lifecycle contract。它不扩展或改写 integration lifecycle；integration 的 `CLOSED` 由固定来源、冻结 evidence hashes、replay/security/model/qualification counters、Owner authorization 与 append-only record identity 共同解析。Project status 的 `MERGED_CLOSED` 仅是现有 batch-history 枚举投影，必须同时验证 `repository_merge_performed = false`。Authority Amendment 本身则复用既有通用 Git Authority lifecycle，并由唯一 append-only `MERGED → POST_MERGE_VERIFIED → CLOSED` record chain 关闭。

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

- **施工者**：本页 → [registry/batch-graph.json](registry/batch-graph.json) → [PROJECT_STATUS.md](PROJECT_STATUS.md) → [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md) → [../milestones/MVP.md](../milestones/MVP.md)
- **审计者**：本页 → [SUPERSEDED_DECISIONS.md](SUPERSEDED_DECISIONS.md) → [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md) → [registry/decisions.json](registry/decisions.json) → [../evidence/README.md](../evidence/README.md)

## 私有提示词政策

本公共仓库**不包含**私有提示词正文。全部提示词资产仅保存在本地加密 Git 仓库，不配置任何远端、不公开正文（`R13-F001`）。公共文档只记录政策，不记录提示词内容或存储位置。

## 状态名约定

- 决策状态：`ACTIVE`（当前权威）、`REFINED`（已被细化，指向细化决定）、`SUPERSEDED`（已被取代，指向取代决定）。
- 延期参数状态：见 [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md)。`DEFER-016` 已由 B001 资格批次 `RESOLVED`（`resolved_by_batch = AIPT-M0-B001` 不可变历史事实）；当前 Go 身份由 B003 安全重资格更新为 **1.26.6**（理由 reachable standard-library vulnerabilities，见 [../../tools/toolchain.lock.json](../../tools/toolchain.lock.json) 的 provenance），其余 15 项为非冻结状态（如 `DEFERRED_TO_*`、`ADMIN_DECISION_PENDING`），不得写成已实现。

## 返回

- [仓库首页](../../README.md)
