# 多仓库集成（INTEGRATION）

> 公开集成合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)。

## 多仓库分别权威

- 代码、游戏和模组以**各自远端 Git 仓库及不可变 Commit** 为权威；分支仅用于导航（`R0-Q004`）。
- AIPT 组件权威仓库：<https://github.com/zyc14588/AIPT>；《未登记》：<https://github.com/zyc14588/UNREGISTERED>。

## 任务 ID 与 Integration ID

- AIPT 与《未登记》使用**独立任务 ID**（如 `AIPT-M0-B00x`、`UNREGISTERED-AIPT-P0-B00x`），由 **Integration ID**（如 `INT-AIPT-UNREGISTERED-001`）关联固定 Commit 对（`R13-Q001`）。
- Integration 任务**只读**两个来源 Commit，不修改任一仓库（见 [../authority/BATCH_DEPENDENCY_GRAPH.md](../authority/BATCH_DEPENDENCY_GRAPH.md)）。

## 单批次单仓库与固定 Commit 对

- 一个实施批次只能修改一个权威仓库（`R13-Q002`）。
- 双层合同：**AIPT Schema + 游戏兼容声明**；Run Manifest 绑定实际 Commit 对（`R13-Q004`）。
- 流程：先形成两个远端候选并配对验证，再按依赖顺序分别合并并复核（`R13-Q005`）。
- 固定 Commit 独立只读检出，运行目录分离（`R2-Q004`）。

## 游戏内容不得复制到 AIPT

- AIPT **禁止复制游戏正文**：只保存身份、哈希、稳定 ID、脱敏摘要与测试结果（`R13-Q006`）。
- 游戏仓库提供统一 AIPT 输入清单（位于游戏测试目录或等效明确路径）（`R2-Q002`、`R13-Q008`）。
- AIPT 提供 Schema/SDK/兼容测试；**游戏仓库拥有本游戏适配器**（`R2-Q003`）。

## 游戏适配与《规则残差》

- 首个真实 MVP 使用《未登记》任务 0（`R12-Q001`）；适配器属于《未登记》仓库。
- 《规则残差》为后续第二个第一方适配对象，不在首纵向切片内。

## 平台集成冻结

- `AIPT-PLATFORM-INTEGRATION` 状态 `FROZEN_WAITING_M1_ENGINE`（见 [../authority/PROJECT_STATUS.md](../authority/PROJECT_STATUS.md)）。
- 解冻必须同时满足：指定 M1 游戏引擎批次通过、稳定接口、兼容探测、用户明确批准（`R0-Q011`）；具体 M1 批次未定（`DEFER-001`）。
- 解冻前不得把平台集成能力写成已实现。

## 相邻文档

- [../authority/README.md](../authority/README.md) · [../authority/PROJECT_STATUS.md](../authority/PROJECT_STATUS.md) · [../authority/BATCH_DEPENDENCY_GRAPH.md](../authority/BATCH_DEPENDENCY_GRAPH.md) · [../architecture/README.md](../architecture/README.md) · [../licensing/README.md](../licensing/README.md) · [../milestones/M0.md](../milestones/M0.md)
- [返回仓库首页](../../README.md)
