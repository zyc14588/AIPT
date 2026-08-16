# 项目状态（PROJECT STATUS）

> 人类可读状态页。机器快照见 [registry/project-status.json](registry/project-status.json)。
> 状态日期：**2026-08-16**；权威快照 ID：`AIPT-DCA-CLOSEOUT-R0-R16-002`。

## 工作轨

| 工作轨 | 状态 |
|---|---|
| `AIPT-STANDALONE` | 设计冻结：`FROZEN_R0_R16_DCA_BOOTSTRAP`；施工：M0；当前批次 `AIPT-M0-B000`（READY） |
| `AIPT-PLATFORM-INTEGRATION` | `FROZEN_WAITING_M1_ENGINE`；解冻未获授权（`DEFER-001`、`R0-Q011`） |

## 当前里程碑

- 当前里程碑：**M0**（建立可构建可验证工程基础，不实现真实桌测）。
- 当前批次：`AIPT-M0-B000`——安装公共权威文档、MIT 许可与机器决策登记。
- B000 无 CI（`BOOTSTRAP-Q001` 一次性例外）；`AIPT-M0-B001` 建立公共 CI 并追溯验证 B000。
- 详见 [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md) 与 [../milestones/M0.md](../milestones/M0.md)。

## 仓库

| 仓库 | 说明 |
|---|---|
| AIPT | <https://github.com/zyc14588/AIPT>，默认分支 `main`；B000 基线 `8b1c6b322c0a1a14df33b0e29e8324d4f1dd1f61`；施工前基线为单条 README 占位提交 |
| 《未登记》UNREGISTERED | <https://github.com/zyc14588/UNREGISTERED>，默认分支 `main`；规划快照 `3e4a28bba1caf44828412f90bb6715b6955e3604`；就绪等级 `PLAYTESTABLE_DRAFT` |

## 运行环境与模型（设计基线）

- 参考环境：Ubuntu 26.04 LTS（`ENV-F001`）；Bash 启动 + 本地 Web（`ENV-F002`）。
- 主远端模型：`deepseek-v4-pro`（`ENV-F003`），完整 Campaign 使用该模型（`R14-Q023`）。
- 本地模型：`UNASSIGNED`；GGUF 选型与性能阈值延期（`DEFER-002`、`DEFER-003`）。
- 以上是**设计基线**：运行时代码尚未建设（B000 仅安装文档）。

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

当前**只允许**执行 `AIPT-M0-B000`：

1. 完成公共权威文档安装；
2. 最终本地确定性验收 PASS；
3. 推送候选 Commit；
4. GPT 治理与文档审计 PASS；
5. 用户批准后合并，随后才可启动 `AIPT-M0-B001`。

## 相邻文档

- [README.md](README.md)（Authority Index） · [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md) · [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md) · [../milestones/M0.md](../milestones/M0.md) · [../milestones/MVP.md](../milestones/MVP.md)
- [返回仓库首页](../../README.md)
