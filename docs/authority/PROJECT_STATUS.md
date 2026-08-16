# 项目状态（PROJECT STATUS）

> 人类可读状态页。机器快照见 [registry/project-status.json](registry/project-status.json)。
> 状态日期：**2026-08-16**；权威快照 ID：`AIPT-DCA-CLOSEOUT-R0-R16-002`。

## 工作轨

| 工作轨 | 状态 |
|---|---|
| `AIPT-STANDALONE` | 设计冻结：`FROZEN_R0_R16_DCA_BOOTSTRAP`；施工：M0；当前批次 `AIPT-M0-B001`（`B001_IN_PROGRESS`）；`AIPT-M0-B000` 已 `MERGED/CLOSED` |
| `AIPT-PLATFORM-INTEGRATION` | `FROZEN_WAITING_M1_ENGINE`；解冻未获授权（`DEFER-001`、`R0-Q011`） |

## 当前里程碑

- 当前里程碑：**M0**（建立可构建可验证工程基础，不实现真实桌测）。
- `AIPT-M0-B000`（权威文档、MIT 许可与机器决策登记）已合并关闭：合并提交 `777a3f39ba78c1ef3168597890c61abf7a55d962`（树 `f5f845b860ba0944ef104b4679fa074ad6efecbb`），GPT 审计 PASS。
- 当前批次：`AIPT-M0-B001`——Go/pnpm 工具链骨架、无秘密公共 CI（`b000-retro` / `toolchain` / `supply-chain`）、供应链基础（`R4-Q023`：锁文件、SBOM、许可证、漏洞、来源），并首次用 CI 追溯验证 B000。`DEFER-016` 已 `RESOLVED`（Go 1.26.5 / Node 24.19.0 / pnpm 11.4.0 / PostgreSQL 18.4，见 [../../tools/toolchain.lock.json](../../tools/toolchain.lock.json)）。
- `AIPT-M0-B002` 尚未授权；B001 不实现任何运行时代码。
- 详见 [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md) 与 [../milestones/M0.md](../milestones/M0.md)。

## 仓库

| 仓库 | 说明 |
|---|---|
| AIPT | <https://github.com/zyc14588/AIPT>，默认分支 `main`；已验证接受的主线基点 `777a3f39ba78c1ef3168597890c61abf7a55d962`（B000 合并提交，`MERGED/CLOSED`）；B001 在 `task/AIPT-M0-B001` 施工 |
| 《未登记》UNREGISTERED | <https://github.com/zyc14588/UNREGISTERED>，默认分支 `main`；规划快照 `3e4a28bba1caf44828412f90bb6715b6955e3604`；就绪等级 `PLAYTESTABLE_DRAFT` |

## 运行环境与模型（设计基线）

- 参考环境：Ubuntu 26.04 LTS（`ENV-F001`）；Bash 启动 + 本地 Web（`ENV-F002`）。
- 主远端模型：`deepseek-v4-pro`（`ENV-F003`），完整 Campaign 使用该模型（`R14-Q023`）。
- 本地模型：`UNASSIGNED`；GGUF 选型与性能阈值延期（`DEFER-002`、`DEFER-003`）。
- 以上是**设计基线**：运行时代码尚未建设（B001 仅安装工程骨架与 CI，不建设运行时）。

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

当前**只允许**执行 `AIPT-M0-B001`：

1. 工具链资格（`DEFER-016` → `RESOLVED`）与 Go/pnpm Monorepo 骨架；
2. 公共无秘密 CI（`b000-retro` / `toolchain` / `supply-chain`）与供应链基础；
3. 本地确定性验证 + 推送候选 Commit + 公共 CI 全绿；
4. 独立本地验收与 GPT 审计 PASS；
5. 用户批准后合并；`AIPT-M0-B002` 在此之前不启动，`AIPT-PLATFORM-INTEGRATION` 保持冻结。

## 相邻文档

- [README.md](README.md)（Authority Index） · [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md) · [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md) · [../milestones/M0.md](../milestones/M0.md) · [../milestones/MVP.md](../milestones/MVP.md) · [../supply-chain/README.md](../supply-chain/README.md)
- [返回仓库首页](../../README.md)
