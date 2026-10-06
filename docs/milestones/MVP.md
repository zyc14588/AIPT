# 里程碑 MVP（MILESTONE MVP）

2026-10-06 最新状态：Owner 另行批准 `B006-PREDECESSOR-GATES-SUCCESSOR-Q001=A`，将 B005/INT001 门禁按固定已验收版本完整重放，并严格核验当前工作树、main 及每个历史状态投影；原验证代码、历史测试及关闭依据不改写。已登记独立授权 `registry/b006-predecessor-gates-successor.json`。B006 本地审查发现的配置、自停止完成、例外历史、CI 字节绑定和前序状态历史缺口均已修复，仍待同一只读代理对最终精确候选复审、公开 PR 与精确 CI 验收。M0=100%，MVP=8/13（61.5%），总体=17/22（77.3%）；真实模型和 qualification=0，runtime_ready=false。


2026-10-06 当前状态：B002 空 RNG 数组的最小后继修复已获 Owner 批准并应用；B006 是唯一 GLOBAL_WIP=1 批次，正在完成后继规则、当前测试、公开 PR 与同一独立只读复审。原 B002 关闭快照及失败证据保留。M0 100%，MVP 8/13（61.5%），总体 17/22（77.3%）；真实资格 Run 0/8，runtime_ready=false。


2026-10-06 B006 验收阻塞：共用控制/Web/stdio 的 87 项 Go unit/race 与 TypeScript 契约测试通过；真实 PostgreSQL 18.4 集成确认前序 B002 在 rng_requests=[] 时提交成功但回放失败。最小修复仅在隔离副本中通过 Run Core 全套 race 与 2 项 PostgreSQL race 集成，活动 B002 字节未改动；需 Owner 批准明确的 post-closeout 后继修复例外后继续。MVP 仍为 8/13，真实 qualification 为 0/8。
2026-10-06 最新状态：B005 已正式 MERGED_CLOSED；B006 共用权威运行控制/Web/stdio IPC 已启动，GLOBAL_WIP=1。M0=100%，MVP=8/13（61.5%），总体=17/22（77.3%）；0/8 真实 qualification Runs，MVP Development Pass=NOT_GRANTED。以下前序状态记录按历史快照保留。

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

`AIPT-MVP-B004 = MERGED_CLOSED`；MODEL/HARNESS minimum certification 的历史受控真实调用累计为 remote 3 次、local 2 次。`INT-AIPT-UNREGISTERED-MVP-001` 已按 read-only closeout 正式关闭，不声称 Git merge、不会重跑旧集成。

2026-10-06 当前唯一施工批次是 `AIPT-MVP-B005 R1`，GLOBAL_WIP=1。远端证明治理已在接受的 main closeout `fdbf9637b38a773fbc7ea57a21e6f75dd89b235f` 关闭；R1 固定匿名 GitHub Commit/Tree 核验及安全修复正在等待独立实现验收。原 `c07e1aae94f681733ad73c1800423248bcc72376` merge 的 post-merge security FAIL 保留，不能作为合格 B005 关闭依据。B006 尚未启动。

按权威串行批次等权计算，M0=9/9（100%）、MVP=7/13（53.8%）、总体=16/22（72.7%）。这表示工程批次进度；真实桌测和 qualification Run 均为 0/8。M0 Development Pass=GRANTED，MVP Development Pass、production/release qualification 仍为 NOT_GRANTED；runtime_ready=false，首个阻塞 gate=IPC。后续依次为 B006 运行控制/IPC、B007 real pilot、B008 five Clean、B009 three Mutant 与 B010 GPT audit。

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

2026-10-06 R6 repair：PR #23 已由 Owner 合并，但本地独立 Codex 审查发现 LOCAL-B005-R1-001 收据字段缺口，总体 FAIL；CI 成功不覆盖此结论。Owner 授权在 exact failed merge 08f8b2ecf721759940f4e4fef862b1a4da9c1834 上追加公开 R6 PR，保留失败历史并复审。R6 enforce 完整 canonical receipt bytes；最终独立审查、精确 final merge 5/5 CI、online source verification 与 immutable catalogue 全部通过才关闭 B005。当前进度仍为 M0 9/9、MVP 7/13、总体 16/22；B006 未启动。

R6 第一个候选与 PR #24 未合并，保留 independent review FAIL（LOCAL-B005-R6-001）及 successful 5/5 CI。后续候选继续同一 R6 授权和 exact 08f8 repair base，补全 accepted main/checkout 两侧的 frozen artifact 与 rewrite/restore history 校验，并禁止已接受记录的失败被降级为 proposal。B005 仍 IN_PROGRESS，B006 未启动，工程进度保持 7/13 MVP。

B006 后继修复授权已接受（2026-10-06）：Owner 批准 `B006-B002-ZERO-RNG-REPAIR-Q001=A`，仅修复 `cloneProposal` 将合法 `rng_requests=[]` 复制为 `null` 的问题，增加 nil/empty 回放回归与明确的后继验收规则。原 B002 关闭快照及失败证据保留；公开 PR、同一独立只读 Codex 子代理复审、精确合并 SHA 的 5/5 CI 与不可变证据目录通过前不关闭 B006。当前补丁已应用；M0 100%，MVP 8/13（61.5%），总体 17/22（77.3%），真实模型和资格 Run 仍为 0。
