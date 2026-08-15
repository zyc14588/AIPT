# AIPT 项目章程（PROJECT CHARTER）

> 人类可读章程。机器权威为 [registry/decisions.json](registry/decisions.json)；
> 冲突处理顺序见 [README.md](README.md)。

## 1. 项目目标

AIPT 是一个完全由 AI Agent 替代真人桌面席位的 TRPG 全流程桌测系统（`R1-Q002`）：

- AI 替代 GM、玩家、Observer 等**真人席位**；
- 状态、随机数、调度、日志与规则计算由**确定性基础设施**承担（`R5-Q002`）；
- 目标产出是可信的自动化桌测证据，而不是单纯的主观 AI 报告。

## 2. 首发范围

- 技术栈：Go Core + TypeScript Harness Adapter / Web UI，单一多语言 Monorepo（`R0-Q005`、`R2-Q008`）。
- 首个真实 MVP：**《未登记》UNREGISTERED** 任务 0（`R12-Q001`、`R12-Q013`），当前就绪等级 `PLAYTESTABLE_DRAFT`（`R13-Q007`）。
- 基准桌：1 GM + 4 玩家（`R12-Q008`）。
- AIPT 自带内容收敛为**最小非叙事协议夹具**，仅测试 Schema / JSON-RPC / 账本 / 投影 / 回放 / 证据，不维护第二套完整 TRPG（`DCA-Q001`）。
- 参考环境：Ubuntu 26.04 LTS（`ENV-F001`）；主远端模型 `deepseek-v4-pro`（`ENV-F003`）。

## 3. 非目标（Non-Goals）

- AIPT **永久不提供**模型下载能力，只扫描、登记、验证现有文件（`R7-F003`）。
- 不复制任何游戏正文到 AIPT 仓库，只保存身份、哈希、稳定 ID、脱敏摘要与测试结果（`R13-Q006`）。
- 不公开私有提示词：提示词资产仅保存在本地加密 Git 仓库且无远端（`R13-F001`、`R0-Q009`）。
- B000 不实现运行时代码、不建立 CI（`BOOTSTRAP-Q001`）。
- 平台集成轨保持冻结，见第 6 节。

## 4. AIPT 与 TRPG_PLATFORM 的关系

- AIPT 是**独立项目**；`AIPT-STANDALONE` 是当前施工轨。
- `AIPT-PLATFORM-INTEGRATION` 是平台集成轨，状态 `FROZEN_WAITING_M1_ENGINE`：等待 TRPG_PLATFORM 中负责稳定游戏引擎接口的具体 M1 批次（`DEFER-001`）。
- 解冻必须**同时满足**四项条件（`R0-Q011`）：指定 M1 游戏引擎批次通过、接口稳定、兼容探测通过、用户明确批准。当前解冻未获授权。

## 5. 《未登记》与《规则残差》的定位

- **《未登记》UNREGISTERED**：首个真实 MVP 目标游戏，正式中文名由 `R12-F001` 固定；就绪等级 `PLAYTESTABLE_DRAFT`。
- **《规则残差》**：后续第二个第一方适配对象，不在首纵向切片范围内。
- 两者均为各自仓库的权威内容；AIPT 不自行创造 Canon（`R2-Q006`）。

## 6. AI 替代真人席位的边界

- AI 只替代**真人桌面席位**（GM、玩家、Observer 等）。
- 确定性职责（Oracle、状态、完整性、调度、随机数、规则计算）由确定性服务承担，不交给模型（`R5-Q002`）。
- 每个席位每局一个独立持久 Session，不跨 Run 复用（`R5-Q004`）。
- 主观仿真报告与客观体验代理指标分开记录（`R1-Q014`）；AI 不能证明真人心理安全（`R14-Q006`）。

## 7. 远端 Git / Commit 权威

- 代码、游戏与模组以各自**远端 Git 仓库及不可变 Commit** 为权威；分支仅用于导航（`R0-Q004`）。
- 组件权威仓库：<https://github.com/zyc14588/AIPT>（`R0-Q003`）；权威分支 `main`。
- 只有已推送权威远端的不可变 Commit 可正式审计（`R9-Q004`）。

## 8. 平台集成解冻条件

`AIPT-PLATFORM-INTEGRATION` 解冻必须同时满足（`R0-Q011`、`DEFER-001`）：

1. TRPG_PLATFORM 指定的 M1 游戏引擎批次通过；
2. 稳定接口达成；
3. 兼容探测通过；
4. 用户明确批准。

在满足前，任何批次不得解冻该轨，也不得把平台集成能力写成已实现。

## 9. 许可边界

- AIPT 核心与文档：MIT（见仓库根 [LICENSE](../../LICENSE)）。
- 《未登记》游戏内容：自定义非商业允许改编相同方式共享政策（`R13-F004`、`R16-Q006`），最终法律正文尚未起草（`DEFER-014`）。
- 《未登记》适配器 / 执行代码：预计 MIT（`R13-Q021`）。
- 商业行为判定以实际行为为准：存在广告 / 订阅 / 付费权益 / 获客用途即需授权（`DCA-Q006`）。
- 详见 [../licensing/README.md](../licensing/README.md)。

## 相邻文档

- [README.md](README.md)（Authority Index） · [GOVERNANCE.md](GOVERNANCE.md) · [DECISION_MATRIX.md](DECISION_MATRIX.md) · [PROJECT_STATUS.md](PROJECT_STATUS.md) · [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md)
- [返回仓库首页](../../README.md)
