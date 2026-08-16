# 批次依赖图（BATCH DEPENDENCY GRAPH）

> 由机器种子 `BATCH_GRAPH.json` 生成的可读视图。全局串行批次依赖；
> 规则：`GLOBAL_WIP = 1`、一个批次只修改一个权威仓库、前一批次正式关闭后才可启动下一批次、
> 集成任务只读两个来源 Commit。

## 串行批次表

| 顺序 | 批次 | 仓库 | 目的 | 风险 |
|---|---|---|---|---|
| 1 | `AIPT-M0-B000` | AIPT | 权威入口、MIT、决策登记、设计文档安装 | governance |
| 2 | `AIPT-M0-B001` | AIPT | Go/pnpm 工具链、公共 CI、供应链基础；追溯验证 B000 | supply-chain |
| 3 | `AIPT-M0-B002` | AIPT | Schema、JSON-RPC、Adapter SDK、最小协议夹具合同 | protocol |
| 4 | `UNREGISTERED-AIPT-P0-B000` | UNREGISTERED | 正式名称、内容许可、预制角色 v2 | licensing |
| 5 | `UNREGISTERED-AIPT-P0-B001` | UNREGISTERED | AIPT 输入清单、稳定 ID、可见性与 SafetyProfile | visibility |
| 6 | `AIPT-M0-B003` | AIPT | PostgreSQL、迁移与事件账本骨架 | authoritative-state |
| 7 | `AIPT-M0-B004` | AIPT | Launcher 与 Core 空壳 | runtime |
| 8 | `AIPT-M0-B005` | AIPT | Harness Adapter、stdio Smoke、最小协议夹具运行 | harness-integration |
| 9 | `AIPT-M0-B006` | AIPT | Evidence/Audit Schema 与最小证据导出 | evidence-integrity |
| 10 | `UNREGISTERED-AIPT-P0-B002` | UNREGISTERED | 机器规则、Rule ID 映射、关键语义图 | rules-canon |
| 11 | `UNREGISTERED-AIPT-P0-B003` | UNREGISTERED | 游戏适配器、三个 Mutant、真人指南协议映射 | game-adapter |
| 12 | `AIPT-M0-B007` | AIPT | 最小 Web UI、队列视图、报告入口 | ui |
| 13 | `INT-AIPT-UNREGISTERED-001` | INTEGRATION_READ_ONLY | 固定候选 Commit 对的只读 Schema/Adapter Smoke | cross-repository |
| 14 | `AIPT-M0-B008` | AIPT | M0 综合验收、GPT 开发态审计、M0 Development Pass | milestone-gate |

## 纯文本串行链

```text
AIPT-M0-B000
  → AIPT-M0-B001
  → AIPT-M0-B002
  → UNREGISTERED-AIPT-P0-B000
  → UNREGISTERED-AIPT-P0-B001
  → AIPT-M0-B003
  → AIPT-M0-B004
  → AIPT-M0-B005
  → AIPT-M0-B006
  → UNREGISTERED-AIPT-P0-B002
  → UNREGISTERED-AIPT-P0-B003
  → AIPT-M0-B007
  → INT-AIPT-UNREGISTERED-001（只读）
  → AIPT-M0-B008
```

## Mermaid 视图（可选渲染）

```mermaid
flowchart LR
    B000["AIPT-M0-B000<br/>AIPT"] --> B001["AIPT-M0-B001<br/>AIPT"] --> B002["AIPT-M0-B002<br/>AIPT"]
    B002 --> P0A["UNREGISTERED-AIPT-P0-B000<br/>UNREGISTERED"] --> P0B["UNREGISTERED-AIPT-P0-B001<br/>UNREGISTERED"]
    P0B --> B003["AIPT-M0-B003<br/>AIPT"] --> B004["AIPT-M0-B004<br/>AIPT"] --> B005["AIPT-M0-B005<br/>AIPT"] --> B006["AIPT-M0-B006<br/>AIPT"]
    B006 --> P0C["UNREGISTERED-AIPT-P0-B002<br/>UNREGISTERED"] --> P0D["UNREGISTERED-AIPT-P0-B003<br/>UNREGISTERED"]
    P0D --> B007["AIPT-M0-B007<br/>AIPT"] --> INT["INT-AIPT-UNREGISTERED-001<br/>只读"] --> B008["AIPT-M0-B008<br/>AIPT"]
```

## 施工纪律

- `GLOBAL_WIP = 1`（`R12-Q017`、`R13-Q003`）：首个纵向切片完成前，任何时刻只有一个活跃批次。
- **单批次单仓库**（`R13-Q002`）：一个实施批次只能修改一个权威仓库。
- **前一批次正式关闭后才可启动下一批次**。
- **集成任务只读**（`INT-AIPT-UNREGISTERED-001`）：只读两个来源 Commit，不修改任一仓库。

## B000 Bootstrap CI 例外与 B001 追溯义务

- `AIPT-M0-B000` 是唯一一次在公共 CI 尚不存在时关闭的 Bootstrap 批次（`BOOTSTRAP-Q001`）：
  以最终本地确定性验收 + GPT 审计关闭，**不创建 CI**。
- `AIPT-M0-B001` 建立无秘密公共 CI（`R12-Q019`）后，第一次 CI 必须**追溯验证** B000 的
  文档、JSON、链接与 MIT License。

## 相邻文档

- [README.md](README.md)（Authority Index） · [PROJECT_STATUS.md](PROJECT_STATUS.md) · [registry/decisions.json](registry/decisions.json) · [../milestones/M0.md](../milestones/M0.md) · [../milestones/MVP.md](../milestones/MVP.md)
- [返回仓库首页](../../README.md)
