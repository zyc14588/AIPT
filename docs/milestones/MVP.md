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

`AIPT-MVP-B001 = MERGED_CLOSED`：Candidate `85ef3489405694cf0764867a97fb21b09fda5894`（tree `44a885569c59c428fb173e0847dc49a8111b526c`，CI `32932281680` success）由 implementation merge `ad8e39b23f5888cfb9a7f8f15f9dd996964d8f16` 精确集成，post-merge CI `32939064547` success，并由 `AIPT-MVP-B001-CLOSEOUT-001` 关闭。其历史交付精确为版本化 `Campaign → Suite → Case → Run` Test Plan、不可变 canonical-SHA-256 Run Manifest、PostgreSQL 18.4 权威 Queue/Lease/Attempt 与 formal WIP=1。

`UNREGISTERED-AIPT-P1-B000 = MERGED_CLOSED`：accepted merge `fe0965977447caf8cd7b6e58252bc1b991b7cc6f`，post-merge CI `33186880614` success，AIPT canonical lifecycle closeout `411bf2997cd0f10ba1a022ac687d27a1bd19eb36`。

`AIPT-MVP-B002 = MERGED_CLOSED`：Owner 批准的 R1 Candidate `dd634f575cdec5ec572696409ac574102442af3e`（tree `2b7240f11b1bcf934d34d95a286bdd49dbf021b5`，CI `33241732672` success）由第二次合法 merge `a5d9e9b0aeea5f2a9990d976258ddd34b9b8375e` 精确集成，post-merge CI `33243508362` success，并由 canonical append-only lifecycle chain 关闭；首次失败 merge `f4ceabe3e3a3e7bea31481bd91681a1b87f27d56` 仍是不可变 failure 且没有生命周期记录。关闭交付实现 game-neutral Deterministic Run Core 的 action transaction、authoritative state、versioned/domain-separated RNG、seed commitment、invariants、derived projection、PostgreSQL ledger atomicity 与 fail-closed replay。

`AIPT-MVP-B003 = MERGED_CLOSED`：唯一授权 Candidate `4f2979f4495e3d78393e9f9ec1978308a7fb10b9`（tree `bbdb35861bb6cf47a9e6ec4e943720c0126cbc50`，CI `33247140362` success）由合法 no-ff merge `beb7c70738b1f876845d68bec8e20166ab3eac10` 精确集成，post-merge CI `33264083089` success，并由 canonical append-only lifecycle chain 关闭。交付范围只包含 provider-neutral Deterministic Agent Orchestrator，B002/B003 business semantics、迁移和关闭生命周期继续冻结。

`AIPT-MVP-B004 = IN_PROGRESS`：Owner 授权 Base 为 B003 closeout `98591311c4872cdc5f091e23fba1acb500ad4599`（tree `a02ffea60c59d7187975f175875fa108c78d3cac`）。施工已实现版本化 Model/Sampling Profiles、per-role immutable binding、完整 execution tuple、`REMOTE_DEEPSEEK` / `LOCAL_LLAMACPP` 闭集、固定 DeepSeek Harness ACP 单文件运行时闭包、held-file verified assets、credential/egress/context、私有 local user/network namespace，以及 MODEL/HARNESS launcher gates；IPC 仍是首个阻塞 gate。当前 `GLOBAL_WIP = 1`，下一项 `INT-AIPT-UNREGISTERED-MVP-001` 未授权且未启动。安全修复后的受控 `REMOTE_DEEPSEEK` 与 `LOCAL_LLAMACPP` minimum re-certification 均已 PASS，[remote 最终公开证据](../model-certification/remote-deepseek-controlled-real-02.json)与 [local 最终公开证据](../model-certification/local-llamacpp-controlled-real-02.json)均不含 credential 值或私有路径；旧 `-01` 证据仅为 `SUPERSEDED_NON_FINAL`。受控流程累计 5 次真实模型调用：remote/network 3 次、local 2 次，本次修复后各新增最小 1 次成功调用。`GGUF-04` locator 已按批准 root、canonical target、完整 SHA-256 与 metadata 验证但未导出；隔离后的 `LLAMACPP-01` 仍为 loopback/no API key，宿主不可直连。上一 Candidate `abd684a4d858376866766d67653f212c26ca4215` / `0141bb24f7c46cfcc3d0ce0a50b17a0adf631d93` 已拒绝且从未公开推送；替代 Candidate 需要新的 commit/tree 和新的公开披露授权。公共 CI 真实模型/网络调用和 secret requirement 均为 0，真实 playtest 与 qualification Run 均未执行；B004 未 merge 或 closeout。`M0 Development Pass = GRANTED` 继续有效，MVP Development Pass、生产/发行资格仍为 `NOT_GRANTED`，真人等价仍为 `NOT_CLAIMED`。

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
