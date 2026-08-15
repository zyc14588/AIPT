# 里程碑 MVP（MILESTONE MVP）

> 开发 MVP 资格合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)；
> 延期参数见 [../authority/registry/deferred-parameters.json](../authority/registry/deferred-parameters.json)。

## 真实 MVP：使用《未登记》任务 0

- 真实 MVP 直接与已进入原型桌测阶段的**《未登记》**共同建设，使用其当前游戏仓库（`R12-Q001`、`R12-Q003`）。
- 直接使用《未登记》的世界观与叙事（`R13-Q012`）；具体内容为任务 0 的短篇完整单次游戏（`R12-Q009`）。
- AIPT 自带内容只保留**最小非叙事协议夹具**，不另造完整合成游戏（`DCA-Q001`）。

## 阵容

- 基准桌：**1 GM + 4 玩家**（`R12-Q008`），固定四名 Sentinel 角色，另两名用于后续变体（`R13-Q009`）。

## 运行场次：五场 Clean + 三 Mutant 检出

- 默认六场 Campaign；MVP 资格**另加两场 Mutant Run**，总计八场（`R14-F001`）。
- MVP 门禁（`R12-Q006`、`R15-Q019`、`R14-Q021`）：

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
