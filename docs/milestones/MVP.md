# 里程碑 MVP（MILESTONE MVP）

> 开发 MVP 资格合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)；
> 延期参数见 [../authority/registry/deferred-parameters.json](../authority/registry/deferred-parameters.json)。

## 冻结实施序列与当前状态

MVP 的机器权威是 [batch-graph.json](../authority/registry/batch-graph.json)，固定串行顺序为：

```text
AIPT-MVP-B000 → AIPT-MVP-B001 → UNREGISTERED-AIPT-P1-B000
→ AIPT-MVP-B002 → AIPT-MVP-B003 → AIPT-MVP-B004
→ INT-AIPT-UNREGISTERED-MVP-001（只读）
→ AIPT-MVP-B005 → AIPT-MVP-B006 → AIPT-MVP-B007
→ AIPT-MVP-B008 → AIPT-MVP-B009 → AIPT-MVP-B010
```

`AIPT-MVP-B000 = MERGED_CLOSED`：final Candidate `9a4d5e0ad09fbc9c3e13536d02cd131f992836f2`（tree `895ccfc569435c390a1aaeea566167a2d61a4de6`，CI `32869412683` success）由 implementation merge `1a26e023af1b56c057590a46de2f63c3b4220923` 精确集成，post-merge CI `32907168240` success；finding `AIPT-MVP-B000-POSTMERGE-LIFECYCLE-001` = `CLOSED`。

当前唯一活动批次 `AIPT-MVP-B001 = IN_PROGRESS`，Authority `AIPT-MVP-B001-START-001` 仅为 `IMPLEMENT_AND_FREEZE_CANDIDATE_ONLY`。精确 Base 为 `64b5692971bbe687884ec34bd6417fe803987ae9`（tree `1a6feabb1796af9f66fd78fc842f249ec03a5251`），当前 `construction = IN_PROGRESS`、`current_batch = AIPT-MVP-B001`、`GLOBAL_WIP = 1`。本批次只实现版本化 `Campaign → Suite → Case → Run` Test Plan、不可变 canonical-SHA-256 Run Manifest、PostgreSQL 18.4 权威 Queue/Lease/Attempt 与 formal WIP=1；没有 Run Core、Agent 编排、产品模型调用、真实桌测或 qualification Run，merge/closeout 均未授权。下一项 `UNREGISTERED-AIPT-P1-B000` 与所有更晚批次仍为 `NOT_STARTED` / `NOT_AUTHORIZED`。`M0 Development Pass = GRANTED` 继续有效，MVP Development Pass 仍为 `NOT_GRANTED`；生产/发行资格仍为 `NOT_GRANTED`，真人等价仍为 `NOT_CLAIMED`，平台集成仍为 `FROZEN_WAITING_M1_ENGINE`。

## 真实 MVP：使用《未登记》任务 0

- 真实 MVP 直接与已进入原型桌测阶段的**《未登记》**共同建设，使用其当前游戏仓库（`R12-Q001`、`R12-Q003`）。
- 直接使用《未登记》的世界观与叙事（`R12-Q013`）；具体内容为任务 0 的短篇完整单次游戏（`R12-Q009`）。
- AIPT 自带内容只保留**最小非叙事协议夹具**，不另造完整合成游戏（`DCA-Q001`）。

## 阵容

- 基准桌：**1 GM + 4 玩家**（`R12-Q008`），固定四名 Sentinel 角色，另两名用于后续变体（`R13-Q009`）。

## 运行场次：五场 Clean + 三 Mutant 检出

- 默认六场 Campaign；MVP 资格**另加两场 Mutant Run**，总计八场（`R14-F001`）。
- MVP 门禁（`R12-Q006`、`R15-Q019`、`R14-Q021`、`R14-Q024`、`R15-Q020`、`R15-Q022`、`R15-Q024`）：

```text
五场 Clean Run 完成
三个 Mutant 成功检出（隐藏信息泄漏 / Prose-Machine 分歧 / 状态重放不一致）
无隐藏信息泄漏
状态可重放
关键路径 / 结局 / 恢复可达
GPT 审计 PASS
```

## 模型分配

- **deepseek-v4-pro** 完成完整 Campaign（GM、玩家与 Observer）（`R14-Q023`、`R12-Q004`）。
- **llama.cpp** 只做启动、认证与最小角色调用（`R12-Q004`）；本地 GGUF 选型与性能阈值延期（`DEFER-002`、`DEFER-003`）。

## 开发/生产限制

- 叙事降级 Run 失去 Game Gate 资格但保留诊断证据（`R14-Q018`）。
- 第二审计者（Claude）未配置时允许开发态真实桌测；**生产/发行 Gate 阻塞**（`R13-Q024`）。
- MVP Development Pass 以 GPT 审计为硬门禁；Claude 经管理员批准后用于生产/高风险（`R14-Q024`）。
- 证据等级：`SYNTHETIC_PLAYTEST_EVIDENCE`（`R14-Q001`）。

## 当前不声称真人等价

- 发布前必须完成至少一场可审计**真人盲测**，并经过真人校准（`R3-Q021`、`R1-Q013`）。
- 校准样本数尚未基准化（`DEFER-008`）：在完成前，MVP 结果**不得**表述为真人等价证明。
- AI 只验证安全协议执行正确，不能证明真人心理安全（`R14-Q006`）。

## 相邻文档

- [../authority/README.md](../authority/README.md) · [../authority/BATCH_DEPENDENCY_GRAPH.md](../authority/BATCH_DEPENDENCY_GRAPH.md) · [../test-model/README.md](../test-model/README.md) · [../evidence/README.md](../evidence/README.md) · [../integration/README.md](../integration/README.md) · [M0.md](M0.md)
- [返回仓库首页](../../README.md)
