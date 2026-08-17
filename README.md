# AIPT

AIPT 是一个**完全由 AI Agent 替代真人桌面席位的 TRPG 全流程桌测系统**：AI 替代 GM、玩家、Observer 等真人席位；状态、随机数、调度、日志与规则计算由确定性基础设施承担。

## 当前状态（as of 2026-08-17）

| 工作轨 | 状态 |
|---|---|
| `AIPT-STANDALONE` | 设计已冻结（`FROZEN_R0_R16_DCA_BOOTSTRAP`），正在 M0 施工；当前批次 `AIPT-M0-B002`（`B002_IN_PROGRESS`） |
| `AIPT-PLATFORM-INTEGRATION` | `FROZEN_WAITING_M1_ENGINE`：冻结等待平台 M1 游戏引擎，解冻未获授权（`unfreeze_authorized = false`） |

批次状态：`AIPT-M0-B000` = **MERGED/CLOSED**（合并提交 `777a3f39ba78c1ef3168597890c61abf7a55d962`，树 `f5f845b860ba0944ef104b4679fa074ad6efecbb`，GPT 审计 PASS）；`AIPT-M0-B001` = **MERGED/CLOSED**（候选 `2e904ddc2d4f1313a99e19f6751a991d589f8336`，合并提交 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`，树 `fefc25f1acb523d013c2a7d8db9801ccdab37d2d`，合并后公共 CI run `31951440133` PASS）。当前批次 = `AIPT-M0-B002`：Schema、JSON-RPC、Adapter SDK 与最小协议夹具合同（协议批次）；迭代 2 已落地权威协议 Schema（`schemas/protocol/v1/`）、游戏中立最小确定性夹具（`testdata/protocol/v1/minimal-fixture/`）与协议资产验证器。已验证接受的主线基点 = `8bcadc9669e7d04f589f883daa6d4f593875fc9e`。GLOBAL_WIP = 1。

**设计基线已冻结、运行时代码尚未建设。** B001 已合并关闭（工具链骨架、公共 CI、供应链门禁）；B002 本迭代新增权威协议 Schema、最小确定性夹具与协议资产验证器（含 Schema/JSON-RPC/可见性负向探针），尚未建设 Adapter SDK、Go 契约与任何 server/socket/worker/model/数据库运行时；`AIPT-PLATFORM-INTEGRATION` 保持 `FROZEN_WAITING_M1_ENGINE`。

首个真实游戏目标为 **《未登记》UNREGISTERED**（当前就绪等级 `PLAYTESTABLE_DRAFT`）。

## 权威入口（渐进式披露）

- 施工者：从 [docs/authority/README.md](docs/authority/README.md)（Authority Index）开始，再按需进入领域文档与机器登记。
- 项目现状与下一步：[docs/authority/PROJECT_STATUS.md](docs/authority/PROJECT_STATUS.md)
- 里程碑合同：[docs/milestones/M0.md](docs/milestones/M0.md) 与 [docs/milestones/MVP.md](docs/milestones/MVP.md)
- 机器决策权威：[docs/authority/registry/decisions.json](docs/authority/registry/decisions.json)（共 454 条决策 ID）
- 协议契约（B002）：[docs/protocol/README.md](docs/protocol/README.md) → 权威根 [schemas/protocol/v1/aipt-protocol.schema.json](schemas/protocol/v1/aipt-protocol.schema.json) 与最小确定性夹具 [testdata/protocol/v1/minimal-fixture/manifest.json](testdata/protocol/v1/minimal-fixture/manifest.json)
- 工具链与供应链：[docs/supply-chain/README.md](docs/supply-chain/README.md) 与 [tools/toolchain.lock.json](tools/toolchain.lock.json)

## 面向读者

| 读者 | 最短阅读路径 |
|---|---|
| 施工者（实施批次） | [docs/authority/README.md](docs/authority/README.md) → [docs/authority/DECISION_MATRIX.md](docs/authority/DECISION_MATRIX.md) → [docs/authority/GOVERNANCE.md](docs/authority/GOVERNANCE.md) → [docs/milestones/M0.md](docs/milestones/M0.md) → [docs/supply-chain/README.md](docs/supply-chain/README.md) |
| 审计者（GPT 主审；Claude 第二审计） | [docs/authority/README.md](docs/authority/README.md) → [docs/authority/SUPERSEDED_DECISIONS.md](docs/authority/SUPERSEDED_DECISIONS.md) → [docs/evidence/README.md](docs/evidence/README.md) → [docs/security/README.md](docs/security/README.md) |
| 游戏适配器作者 | [docs/integration/README.md](docs/integration/README.md) → [docs/architecture/README.md](docs/architecture/README.md) → [docs/milestones/MVP.md](docs/milestones/MVP.md) |

## 领域文档

| 领域 | 文档 |
|---|---|
| 架构 | [docs/architecture/README.md](docs/architecture/README.md) |
| 协议 | [docs/protocol/README.md](docs/protocol/README.md) |
| 安全 | [docs/security/README.md](docs/security/README.md) |
| 证据与审计 | [docs/evidence/README.md](docs/evidence/README.md) |
| 测试模型 | [docs/test-model/README.md](docs/test-model/README.md) |
| 多仓库集成 | [docs/integration/README.md](docs/integration/README.md) |
| 许可 | [docs/licensing/README.md](docs/licensing/README.md) |
| 供应链 | [docs/supply-chain/README.md](docs/supply-chain/README.md) |

## 权威与冲突处理

决策 ID、状态与覆盖关系以机器登记（[docs/authority/registry/](docs/authority/registry/decisions.json)）为准；人类文档是可读解释，不是第二份独立权威。冲突处理顺序见 [docs/authority/README.md](docs/authority/README.md)。

本公共仓库**不含**任何私有提示词、凭据、模型端点或本机路径。提示词资产仅保存在本地加密 Git 仓库且不配置任何远端，正文永不公开。

## 许可

AIPT 代码与文档本体采用 [MIT License](LICENSE)（Copyright (c) 2026 AIPT contributors）。

MIT 只覆盖 AIPT 本体，**不自动覆盖**游戏内容：《未登记》游戏内容适用独立的非商业相同方式共享政策（政策已冻结、最终法律正文尚未起草），其适配器/执行代码预计为 MIT。详见 [docs/licensing/README.md](docs/licensing/README.md)。

## 仓库与分支

- 仓库：<https://github.com/zyc14588/AIPT>，权威分支 `main`。
- 施工使用独立任务分支（如 `task/AIPT-M0-B002`）与隔离工作树；候选 Commit 推送后，经独立本地验收与 GPT 审计核验，仅由用户批准才合并到 `main`。
- `AIPT-M0-B000` 是一次性 Bootstrap 例外：无 CI，以最终本地确定性验收 + GPT 审计关闭（已 `MERGED/CLOSED`）；`AIPT-M0-B001` 建立公共 CI 并追溯验证 B000（`b000-retro` job），已 `MERGED/CLOSED`（合并提交 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`）。
