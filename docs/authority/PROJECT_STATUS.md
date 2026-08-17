# 项目状态（PROJECT STATUS）

> 人类可读状态页。机器快照见 [registry/project-status.json](registry/project-status.json)。
> 状态日期：**2026-08-17**；权威快照 ID：`AIPT-DCA-CLOSEOUT-R0-R16-002`。

## 工作轨

| 工作轨 | 状态 |
|---|---|
| `AIPT-STANDALONE` | 设计冻结：`FROZEN_R0_R16_DCA_BOOTSTRAP`；施工：M0；当前批次 `AIPT-M0-B002`（`B002_IN_PROGRESS`）；`AIPT-M0-B000` 与 `AIPT-M0-B001` 均已 `MERGED/CLOSED` |
| `AIPT-PLATFORM-INTEGRATION` | `FROZEN_WAITING_M1_ENGINE`；解冻未获授权（`unfreeze_authorized = false`；`DEFER-001`、`R0-Q011`） |

## 当前里程碑

- 当前里程碑：**M0**（建立可构建可验证工程基础，不实现真实桌测）。
- `AIPT-M0-B000` = **MERGED/CLOSED**（合并提交 `777a3f39ba78c1ef3168597890c61abf7a55d962`，树 `f5f845b860ba0944ef104b4679fa074ad6efecbb`，GPT 审计 PASS）。
- `AIPT-M0-B001` = **MERGED/CLOSED**：候选 `2e904ddc2d4f1313a99e19f6751a991d589f8336`，合并提交 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`（树 `fefc25f1acb523d013c2a7d8db9801ccdab37d2d`），合并后公共 CI run `31951440133` PASS；Go/pnpm 工具链骨架、无秘密公共 CI（`b000-retro` / `toolchain` / `supply-chain`）、供应链基础（`R4-Q023`：锁文件、SBOM、许可证、漏洞、来源），`DEFER-016` 已 `RESOLVED`（Go 1.26.5 / Node 24.19.0 / pnpm 11.4.0 / PostgreSQL 18.4，见 [../../tools/toolchain.lock.json](../../tools/toolchain.lock.json)）。
- 当前批次：`AIPT-M0-B002`——Schema、JSON-RPC、Adapter SDK 与最小协议夹具合同（协议批次，`B002_IN_PROGRESS`）；迭代 1 完成公开状态迁移（B001 关闭、B002 开启）与验证器基线升级；迭代 2 新增权威协议 Schema（`schemas/protocol/v1/aipt-protocol.schema.json`）、游戏中立最小确定性夹具（`testdata/protocol/v1/minimal-fixture/`）与依赖自由的协议资产验证器（`scripts/ci/validate/protocol-assets.mjs`）；迭代 3 修复加固：Schema 根可执行（`oneOf` 只接受三种注册 wire 信封）、持久化 wire 夹具（`requests/`、`responses/`、`notifications/`，含确定性 `-32000` + `AIPT_*` 错误示例）、全量状态投影语义（重复 field_id、值漂移、未知席位/授权、遗漏授权字段）、manifest 路径加固与 `kind→schema_ref` 精确映射、schema helper fail-closed 探针；未建设 Adapter SDK、Go 契约，本迭代未创建任何协议包/工作区（`packages/adapter-sdk` 与 `internal/protocol` 由 B002 主合同要求后续迭代建设，本迭代仅机械禁止）。
- 施工纪律：`GLOBAL_WIP = 1`（同时只有一个活跃批次）；单批次单仓库；前一批次正式关闭后才可启动下一批次。
- 详见 [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md) 与 [../milestones/M0.md](../milestones/M0.md)。

## 仓库

| 仓库 | 说明 |
|---|---|
| AIPT | <https://github.com/zyc14588/AIPT>，默认分支 `main`；已验证接受的主线基点 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`（B001 合并提交，`MERGED/CLOSED`）；`AIPT-M0-B002` 在 `task/AIPT-M0-B002` 施工 |
| 《未登记》UNREGISTERED | <https://github.com/zyc14588/UNREGISTERED>，默认分支 `main`；规划快照 `3e4a28bba1caf44828412f90bb6715b6955e3604`；就绪等级 `PLAYTESTABLE_DRAFT` |

## 运行环境与模型（设计基线）

- 参考环境：Ubuntu 26.04 LTS（`ENV-F001`）；Bash 启动 + 本地 Web（`ENV-F002`）。
- 主远端模型：`deepseek-v4-pro`（`ENV-F003`），完整 Campaign 使用该模型（`R14-Q023`）。
- 本地模型：`UNASSIGNED`；GGUF 选型与性能阈值延期（`DEFER-002`、`DEFER-003`）。
- 以上是**设计基线**：运行时代码尚未建设（B001 仅安装工程骨架与 CI；B002 迭代 2 落地协议 Schema、最小确定性夹具与验证器，迭代 3 修复加固并新增持久化 wire 夹具与语义/加固探针；仍无 server/socket/worker/model/数据库运行时，无 Adapter SDK，无 Go 契约）。

## 审计状态

| 项 | 状态 |
|---|---|
| 主审计 | GPT（`R10-F003`） |
| 包准备 | 本地 Codex CLI，产出 `AUDIT_READY`（`R9-F001`） |
| 第二审计 | Anthropic Claude Web；本批次不要求 |
| 第二审计 Profile | `Fable 5`、`Opus 5`、`Opus 4.8`（`DCA-Q003`） |
| 第二审计生产资格 | `ADMIN_APPROVAL_AND_PRIVACY_PROFILE_PENDING`：**尚不具备生产资格**；Model Improvement 状态 `UNKNOWN`（`DEFER-011`） |

## 提示词资产政策

- 全部提示词仅保存在**本地加密 Git 仓库**；不配置远端、不公开正文（`R13-F001`）。
- 本公共仓库不含任何提示词正文、凭据或本机路径。

## 下一步

当前**只允许**执行 `AIPT-M0-B002`：

1. 公开状态迁移：B001 关闭（候选 `2e904ddc2d4f1313a99e19f6751a991d589f8336`、合并提交 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`、合并后公共 CI run `31951440133`），B002 开启（`IN_PROGRESS`、`current_batch = AIPT-M0-B002`），`verified_head = 8bcadc9669e7d04f589f883daa6d4f593875fc9e`，状态日期 `2026-08-17`；
2. 验证器从 B001 候选基线升级到 B002 基线（`constants.mjs`、`status-transition`、`defer-016`、`tree-integrity`），保留全部 B000/B001 历史门禁；
3. 迭代 3 协议资产修复：权威协议 Schema 根可执行（`schemas/protocol/v1/`，`oneOf` 只接受三种注册 wire 信封）、游戏中立最小确定性夹具（`testdata/protocol/v1/minimal-fixture/`，新增 `requests/`、`responses/`、`notifications/` 持久化 wire 信封与 `mutants/` 隐藏泄露突变）、依赖自由子集验证器（`scripts/ci/lib/json-schema.mjs`）与协议资产门禁（`scripts/ci/validate/protocol-assets.mjs`，含 23 个负向探针：9 个冻结迭代 2 探针 + 根/投影/manifest/schema-helper 探针），`pnpm run check:protocol-assets` 并纳入 `scripts/ci/run-checks.mjs`；
4. 本地确定性验证 + 推送候选 Commit + 公共 CI 全绿；
5. 独立本地验收与 GPT 审计 PASS；
6. 用户批准后合并；`AIPT-PLATFORM-INTEGRATION` 保持冻结；后续批次在 B002 正式关闭前不启动。

## 相邻文档

- [README.md](README.md)（Authority Index） · [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md) · [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md) · [../protocol/README.md](../protocol/README.md) · [../milestones/M0.md](../milestones/M0.md) · [../milestones/MVP.md](../milestones/MVP.md) · [../supply-chain/README.md](../supply-chain/README.md)
- [返回仓库首页](../../README.md)
