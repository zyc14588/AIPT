# 决策矩阵（DECISION MATRIX）

> 人类可读领域矩阵。机器权威为 [registry/decisions.json](registry/decisions.json)（全部 454 条决策 ID，
> 含 `choice`、`qualifier`、`domain`、`status`、`superseded_by`）。
> 本页按领域给出**当前唯一权威**与关键决定 ID，不逐字复制全部记录；
> `REFINED`/`SUPERSEDED` 记录只被引用、不作为当前方案。

## 项目与游戏

| 领域 | 当前唯一权威 | 关键决定 ID |
|---|---|---|
| 项目身份 | AIPT 是独立项目；`AIPT-STANDALONE` 为当前施工轨 | `R0-Q001`、`R0-Q003`、`R0-Q004` |
| 第一方游戏 | 首个真实 MVP 用《未登记》UNREGISTERED；《规则残差》为后续第二适配对象 | `R12-F001`、`R12-Q001`、`R13-Q007`、`DCA-Q001` |
| 游戏就绪 | `PLAYTESTABLE_DRAFT` 与 `REGRESSION_READY` 两级；《未登记》当前 `PLAYTESTABLE_DRAFT` | `R2-Q001`、`R13-Q007` |
| Canon 权威 | 游戏仓库定义 Canon、模组真相、不变量与测试向量；AIPT 不自行创造 Canon | `R2-Q006`、`R3-Q006` |

## 仿真与测试模型

| 领域 | 当前唯一权威 | 关键决定 ID |
|---|---|---|
| 桌面替代范围 | AI 替代 GM、玩家、Observer 等真人席位；状态、随机数、调度、日志和规则计算由确定性基础设施承担 | `R1-Q002`、`R5-Q002` |
| 测试轨 | CONFORMANCE、HUMAN_SIMULATION、ADVERSARIAL 三轨独立 | `R1-Q001` |
| 运行模式 | FORMAL_AUTONOMOUS 禁止人工介入；COMPONENT_DIAGNOSTIC 可介入但失去游戏/发布证据资格 | `R1-Q003` |
| 规则模式 | PROSE_ONLY 与 ORACLE_ASSISTED 分开运行并比较 | `R1-Q011`、`R2-Q012` |
| 席位建模 | Persona 不可变基线 + 事件驱动可变状态；基准模式单一 GM Agent；每席位独立 Session | `R5-Q003`、`R5-Q004`、`R5-Q005`、`R13-Q010` |

## 架构与持久化

| 领域 | 当前唯一权威 | 关键决定 ID |
|---|---|---|
| 技术栈 | Go Core + TypeScript Harness Adapter/Web UI；单一多语言 Monorepo | `R4-Q001`、`R4-Q002`、`R2-Q008` |
| 进程边界 | 长期应用服务为 AIPT Core 与 Harness Host；PostgreSQL 是基础设施；适配器 Worker 短生命周期 | `R4-F001` |
| IPC | 第一阶段 stdio JSON-RPC；后续增加 Unix Domain Socket | `R4-F005` |
| 持久化 | PostgreSQL 追加式哈希链事件账本为权威；快照、UI 和 Harness Session 均为派生/次级 | `R4-Q008`、`R4-Q009` |
| 状态提交 | Agent 只提交意图；Core 通过 Schema、授权、规则和不变量后提交权威事件 | `R5-Q008` |
| 信息隔离 | 每席位独立 Session；ACL 与内容标签在检索之前实施；未标记数据 fail-closed | `R2-Q016`、`R5-Q006`、`R5-Q017`、`R13-Q015` |
| 上下文 | AIPT 事件账本是记忆权威；Harness Compaction 只做长度优化 | `R4-Q012`、`R5-Q016` |
| 随机性 | Core 使用版本化分域随机流；种子开局承诺，结束后按证据策略披露 | `R5-Q013`、`R5-Q014` |

## 模型与配置

| 领域 | 当前唯一权威 | 关键决定 ID |
|---|---|---|
| 模型后端 | 首版支持 REMOTE_DEEPSEEK 与 LOCAL_LLAMACPP；所有模型调用经 Harness | `R6-Q001`、`R6-Q002`、`ENV-F003` |
| 模型治理 | 模型 Profile、能力认证和完整执行元组版本化；远端能力指纹仅为观察性漂移信号 | `R6-Q003`、`R6-Q005`、`R6-Q006`、`R6-F001` |
| 本地模型 | Launcher 可启动已登记 GGUF；AIPT 永久不提供模型下载能力 | `R7-F003`、`R6-Q018`、`R6-Q019`、`R6-Q020` |
| 配置 | Web UI 与 CLI 共用配置服务；开发/生产 Profile、数据库和证据命名空间隔离 | `R7-Q001`、`R7-Q007` |
| Launcher | Go Launcher 按门禁顺序启动 PostgreSQL、llama.cpp、Harness、Core 与 Web UI | `R7-Q009`、`R7-Q010` |

## 队列、Campaign 与 MVP

| 领域 | 当前唯一权威 | 关键决定 ID |
|---|---|---|
| 队列 | Campaign→Suite→Case→Run；Attempt 是 Run 内部记录；PostgreSQL 持久队列 | `R8-F001`、`R8-Q003`、`R8-Q005`、`R8-Q006` |
| Campaign | 默认六场；MVP 资格另加两场 Mutant，共八场 | `R14-F001` |
| MVP 阵容 | 1 GM + 4 玩家（固定四名 Sentinel 角色） | `R12-Q008`、`R13-Q009` |
| MVP 门禁 | 五场 Clean Run 完成；三个 Mutant 检出；无隐藏信息泄漏；状态可重放；关键路径/结局/恢复可达；GPT 审计 PASS | `R12-Q006`、`R15-Q019`、`R14-Q021`、`R14-Q024` |
| 模型分配 | 完整 Campaign 用 deepseek-v4-pro；本地 llama.cpp 只做启动、认证与最小角色调用 | `R14-Q023`、`R12-Q004` |

## 覆盖率与缺陷

| 领域 | 当前唯一权威 | 关键决定 ID |
|---|---|---|
| 覆盖率 | 规则语义覆盖；作者语义图优先；自然发现与受控可达分开 | `R3-Q008`、`R3-Q011`、`R3-Q012` |
| 缺陷 | 根因域、严重度、可信度、可复现性、范围和优先级分别记录；缺陷家族与 occurrence 分离 | `R3-Q001`、`R3-Q002`、`R3-Q003` |

## 证据与审计

| 领域 | 当前唯一权威 | 关键决定 ID |
|---|---|---|
| 证据流水线 | RAW_CAPTURE→AUDIT_READY→AUDIT_RESULT；Canonical JSON 为机器权威 | `R10-Q001`、`R9-F001` |
| 证据披露 | PUBLIC、EXTERNAL_AUDITOR、PRIVATE_FULL 三种 Profile；大型证据内容寻址分块 | `R10-Q012`、`R10-Q009` |
| 审计安全 | 所有环境执行包安全验证；生产/发行追加证据资格、签名和核心环境完整性验证 | `R10-Q013`、`R10-Q014`、`R10-F002` |
| Codex 权限 | 只读 source-mirror、可销毁 verification-worktree、持久可写 audit-output；无原始 Docker Socket | `R10-Q005`、`R11-Q002`、`R11-Q003`、`R11-Q004` |
| 双审计 | GPT 主审；Claude Web 为独立第二审计通道；第二审计 FAIL/BLOCKED 触发 MERGE_HOLD | `R10-F003`、`R13-Q024`、`R14-Q024` |
| Claude 路由 | Fable 5、Opus 5、Opus 4.8 是管理员独立重试 Profile；自动切换只记录为 FALLBACK_ATTEMPT | `DCA-Q003`、`DCA-Q004`、`R15-F001`、`R15-F002` |

## 许可、管理员与集成

| 领域 | 当前唯一权威 | 关键决定 ID |
|---|---|---|
| 许可 | AIPT Core 为 MIT；《未登记》内容采用自定义非商业相同方式共享许可；适配器/执行代码为 MIT | `R2-Q009`、`R13-Q021`、`R13-F004`、`R16-Q006` |
| 许可商业边界 | 广告/赞助实况在条件下允许；收费 GM 需授权；带广告、订阅、付费权益或获客用途的平台需授权 | `R16-Q008`、`R16-Q009`、`DCA-Q006` |
| 法律结构 | 《未登记》内容许可主准据法为昆士兰州及适用澳大利亚联邦法律，并保留中国大陆不可排除强制法 | `DCA-Q005` |
| 管理员 | Owner、Operator、Auditor Manager、License Manager 逻辑分离，首版由同一用户兼任 | `R16-Q001`、`R16-Q002` |
| 不可豁免门禁 | Commit/Tree、哈希/签名、凭据、隐藏信息、权威状态和账本完整性故障不得被管理员覆盖 | `R16-Q003`、`R16-Q004` |
| 平台集成 | 解冻必须同时满足指定 M1 游戏引擎批次通过、稳定接口、兼容探测和用户明确批准 | `R0-Q011`、`DEFER-001` |
| B000 Bootstrap | 无 CI；以最终本地确定性验收 + GPT 审计关闭；B001 首次 CI 追溯验证 | `BOOTSTRAP-Q001` |
| 参考环境 | Ubuntu 26.04 LTS；Bash 启动 + 本地 Web 可视化 | `ENV-F001`、`ENV-F002` |

## 使用说明

- 需要某条决定的原文语义时，在 [registry/decisions.json](registry/decisions.json) 中按 `decision_id` 查找。
- `REFINED`/`SUPERSEDED` 决定的当前含义见 [SUPERSEDED_DECISIONS.md](SUPERSEDED_DECISIONS.md) 与 [registry/supersessions.json](registry/supersessions.json)。
- 延期参数（如 `DEFER-001`）尚未冻结，见 [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md)。

## 相邻文档

- [README.md](README.md)（Authority Index） · [PROJECT_CHARTER.md](PROJECT_CHARTER.md) · [GOVERNANCE.md](GOVERNANCE.md) · [SUPERSEDED_DECISIONS.md](SUPERSEDED_DECISIONS.md) · [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md)
- [返回仓库首页](../../README.md)
