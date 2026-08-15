# 被覆盖与细化决定（SUPERSEDED / REFINED）

> 本页由机器种子 `SUPERSESSIONS.json` 生成。机器权威为
> [registry/supersessions.json](registry/supersessions.json)；本页提供可读解释。
> `SUPERSEDED`/`REFINED` 记录中的旧结论**不是**当前权威：当前方案只能引用
> 覆盖链中 `ACTIVE` 的新决定（见 [DECISION_MATRIX.md](DECISION_MATRIX.md) 与
> [registry/decisions.json](registry/decisions.json)）。

覆盖类型：

- `FULL`：旧决定被完全取代，不得再作为当前方案引用。
- `REFINEMENT`：旧决定被细化/修正，执行以新决定为准。
- `BOOTSTRAP_EXCEPTION`：一次性 Bootstrap 例外（仅 `BOOTSTRAP-Q001`）。

## 完整覆盖关系表（共 35 条）

| 旧决定 | 新决定（当前权威） | 类型 | 原因 | 当前执行含义（新决定 qualifier） |
|---|---|---|---|---|
| `R6-F004`（SUPERSEDED） | `R7-F003`（ACTIVE） | `FULL` | AIPT 模型下载能力由未来可选改为永久不提供；仅登记和验证外部已下载模型。 | AIPT 永久不负责下载模型，只扫描、登记和验证现有文件 |
| `R12-F003`（SUPERSEDED） | `R13-F001`（ACTIVE） | `FULL` | 提示词资产仓库最终确定为单一本地 Git 权威且不配置远端，上传隔离不再依赖 .gitignore。 | 提示词资产使用本地唯一加密 Git 权威仓库，不配置任何远端 |
| `R15-Q012`（SUPERSEDED） | `DCA-Q006`（ACTIVE） | `FULL` | 商业平台免费托管豁免被收紧：仅在无广告、订阅、付费权益和获客用途时可按非商业处理。 | 平台是否商业按实际行为：无广告/订阅/付费权益/获客用途时可按非商业，否则需授权 |
| `R15-F007`（SUPERSEDED） | `DCA-Q006`（ACTIVE） | `FULL` | 一般商业平台托管豁免被最终商业行为测试取代。 | 平台是否商业按实际行为：无广告/订阅/付费权益/获客用途时可按非商业，否则需授权 |
| `R15-F003`（REFINED） | `DCA-Q003`（ACTIVE） | `REFINEMENT` | Fable→Opus5→Opus4.8 明确为管理员独立重试阶梯；平台自动切换只记录为 FALLBACK_ATTEMPT。 | Claude 自动切换响应仅作 FALLBACK_ATTEMPT；管理员按 Fable 5、Opus 5、Opus 4.8 建立独立审计 |
| `R15-F005`（REFINED） | `DCA-Q004`（ACTIVE） | `REFINEMENT` | Claude 隐私状态未知时最终限定为开发 Break-glass，生产/发行必须已知状态或 Incognito 证据。 | Model Improvement 未知时允许开发 Break-glass；生产/发行须已知隐私状态或明确 Incognito 记录 |
| `R16-Q015`（REFINED） | `DCA-Q005`（ACTIVE） | `REFINEMENT` | 准据法最终确定为昆士兰州及适用澳大利亚联邦法律，中国大陆不可排除强制法保留。 | 主准据法为昆士兰州及适用澳大利亚联邦法律；中国大陆不可排除强制法保留；昆州法院非专属管辖 |
| `R0-Q002`（REFINED） | `R12-F001`（ACTIVE） | `REFINEMENT` | UNREGISTERED 的正式中文名称由早期《未注册》统一为《未登记》。 | 正式中文名称为《未登记》UNREGISTERED |
| `R0-Q014`（REFINED） | `R13-F001`（ACTIVE） | `REFINEMENT` | 私有 Git 提示词资产最终固定为本地唯一加密 Git 权威、无远端。 | 提示词资产使用本地唯一加密 Git 权威仓库，不配置任何远端 |
| `R5-F002`（REFINED） | `R13-F001`（ACTIVE） | `REFINEMENT` | 当前不保留已配置远端；未来远端同步必须形成新治理决定。 | 提示词资产使用本地唯一加密 Git 权威仓库，不配置任何远端 |
| `R0-Q017`（REFINED） | `DCA-Q001`（ACTIVE） | `REFINEMENT` | 真实 MVP 使用《未登记》；AIPT 自带内容收敛为非叙事最小协议夹具。 | 保留最小非叙事协议夹具，仅测试 Schema/JSON-RPC/账本/投影/回放/证据；真实 MVP 用《未登记》 |
| `R2-Q007`（REFINED） | `DCA-Q001`（ACTIVE） | `REFINEMENT` | 参考游戏包收敛为最小协议夹具，不维护完整第二套 TRPG。 | 保留最小非叙事协议夹具，仅测试 Schema/JSON-RPC/账本/投影/回放/证据；真实 MVP 用《未登记》 |
| `R9-Q017`（REFINED） | `R9-F001`（ACTIVE） | `REFINEMENT` | Codex 角色最终为 AUDIT_READY 包准备，GPT 为主要实质审计者。 | AIPT/Harness 产 RAW_CAPTURE；Codex 核验规范化为 AUDIT_READY；GPT 产 AUDIT_RESULT |
| `R9-Q019`（REFINED） | `R10-F003`（ACTIVE） | `REFINEMENT` | GPT 保持主审，但第二厂商 FAIL/BLOCKED 会触发 MERGE_HOLD 与争议流程。 | GPT 主审；第二厂商 FAIL/BLOCKED 触发 AUDIT_DISPUTE 与 MERGE_HOLD |
| `R10-Q006`（REFINED） | `R10-F002`（ACTIVE） | `REFINEMENT` | 所有环境运行包安全验证；生产/发行追加完整证据资格验证。 | 所有环境强制 Package Safety Validator；生产/发行另强制 Evidence Eligibility Verifier |
| `R11-Q008`（REFINED） | `R11-F001`（ACTIVE） | `REFINEMENT` | 开发最低命令证据较轻；生产/发行命令保存完整执行身份。 | 开发命令最低记录命令/退出码；生产/发行测试、构建、迁移和资格命令保存完整身份 |
| `R9-Q009`（REFINED） | `R9-F002`（ACTIVE） | `REFINEMENT` | 环境字段分核心与辅助，生产/发行缺失核心字段即阻塞。 | 环境字段分核心和辅助；生产缺核心字段即 BLOCKED |
| `R6-Q007`（REFINED） | `R6-F001`（ACTIVE） | `REFINEMENT` | 远端模型 ID 为主要身份，能力指纹作为观察性漂移信号而非自动门禁。 | 能力指纹仅作观察信息；变化警告但不自动使生产认证失效 |
| `R6-Q010`（REFINED） | `R6-F002`（ACTIVE） | `REFINEMENT` | LOCAL_ONLY_SECRET 默认阻塞；仅诊断 break-glass 可外发且运行失格。 | 诊断模式可管理员一次性外发 LOCAL_ONLY_SECRET 且运行失格；正式模式必须改分类 Commit 后重启 |
| `R6-Q024`（REFINED） | `R6-F003`（ACTIVE） | `REFINEMENT` | 开发更新为自动检查、管理员确认、安装到候选区；不自动覆盖生产基线。 | 自动检查更新并展示候选，管理员确认后安装到 development candidate，不覆盖生产基线 |
| `R7-Q002`（REFINED） | `R7-F001`（ACTIVE） | `REFINEMENT` | 开发 PostgreSQL 配置权威增加最小外部 Bootstrap 以解决自举。 | 开发配置使用最小外部 Bootstrap，其余配置以 PostgreSQL 为权威 |
| `R7-Q015`（REFINED） | `R7-F002`（ACTIVE） | `REFINEMENT` | 开发可复用不完全匹配服务，但须最低能力探测并标记无正式证据资格。 | 开发复用已有 llama.cpp 时检查 API 和最低能力；身份不符标记未验证且无正式资格 |
| `R8-Q001`（REFINED） | `R8-F001`（ACTIVE） | `REFINEMENT` | Attempt 保留为 Run 内部执行记录，不进入用户任务层级。 | Attempt 作为 Run 内部执行记录保留，不进入用户层级 |
| `R10-Q019`（REFINED） | `R10-F004`（ACTIVE） | `REFINEMENT` | 关闭生产/发行备份必须登记风险接受。 | 关闭生产/发行备份必须记录风险接受 |
| `R12-Q024`（REFINED） | `R12-F004`（ACTIVE） | `REFINEMENT` | 批次关闭保存最终必需验收、CI 和审计，不要求全部探索过程。 | 保存最终必需验收命令、退出码、CI 和审计，不保存探索过程 |
| `R12-Q024`（REFINED） | `BOOTSTRAP-Q001`（ACTIVE） | `BOOTSTRAP_EXCEPTION` | B000 在 CI 尚不存在时以本地确定性验收 + GPT 审计关闭；B001 追溯 CI 验证。 | B000 以本地确定性验收 + GPT 审计关闭；B001 建 CI 后追溯验证 B000 |
| `R15-Q001`（REFINED） | `R15-F001`（ACTIVE） | `REFINEMENT` | 保留已知真值测试，但最终启用由管理员签署批准。 | 保留已知真值审计测试，由管理员查看指标并签署 ADMIN_APPROVED_AUDITOR_PROFILE |
| `R15-Q004`（REFINED） | `R15-F002`（ACTIVE） | `REFINEMENT` | 系统自动发出漂移 REVIEW_REQUIRED，管理员决定继续、暂停或重测。 | 系统检测审计 Profile 漂移并进入 REVIEW_REQUIRED，管理员决定继续/暂停/重测 |
| `R3-Q009`（REFINED） | `R3-F001`（ACTIVE） | `REFINEMENT` | 无作者语义图时 AIPT 推断图只能支持探索，作者确认前不能支持正式 Gate。 | AIPT 推断语义图仅为未验证探索图；作者审核前不能支持 MODULE/Release PASS |
| `R4-Q004`（REFINED） | `R4-F005`（ACTIVE） | `REFINEMENT` | 第一阶段 stdio JSON-RPC，后续增加 UDS，协议支持两种传输。 | 协议支持 stdio 与 UDS；施工顺序 stdio 后 UDS |
| `R4-Q003`（REFINED） | `R4-F001`（ACTIVE） | `REFINEMENT` | 双进程指两个长期应用服务，不排除 PostgreSQL 和短生命周期 Worker。 | 两个长期应用服务；PostgreSQL 为基础设施，Worker 为短生命周期进程 |
| `R4-Q016`（REFINED） | `R4-F002`（ACTIVE） | `REFINEMENT` | 远端处理边界通过字段级数据分类与 fail-closed 默认实施。 | 内容按 PUBLIC/UNRELEASED_REMOTE_ALLOWED/TABLE_HIDDEN_REMOTE_ALLOWED/LOCAL_ONLY_SECRET/HUMAN_PRIVATE/CREDENTIAL 分类 |
| `R14-Q022`（REFINED） | `R14-F001`（ACTIVE） | `REFINEMENT` | 默认六场 Campaign 保持，MVP 资格额外增加两场 Mutant Run，总计八场。 | 保留六场基础 Campaign，追加两场 Mutant Qualification，总计 8 场 |
| `R14-F004`（REFINED） | `DCA-Q003`（ACTIVE） | `REFINEMENT` | 备用模型使用必须是独立管理员批准 Profile，自动切换不直接作为正式结果。 | Claude 自动切换响应仅作 FALLBACK_ATTEMPT；管理员按 Fable 5、Opus 5、Opus 4.8 建立独立审计 |
| `R15-F004`（REFINED） | `DCA-Q003`（ACTIVE） | `REFINEMENT` | 管理员声明仍是最低身份凭证，但必须记录自动切换并按独立重试阶梯处理。 | Claude 自动切换响应仅作 FALLBACK_ATTEMPT；管理员按 Fable 5、Opus 5、Opus 4.8 建立独立审计 |

## 关键覆盖链说明

以下覆盖链对外部读者影响最大，完整关系仍以机器登记为准：

1. **模型下载能力**：`R6-F004`（未来可选）→ `R7-F003`（AIPT 永久不提供下载，只扫描、登记、验证现有文件）。
2. **提示词远端**：`R0-Q014`/`R5-F002`/`R12-F003`（私有远端候选/路径隔离）→ `R13-F001`（单一本地加密 Git、无任何远端）。
3. **合成游戏**：`R0-Q017`/`R2-Q007`（完整参考游戏）→ `DCA-Q001`（最小非叙事协议夹具；真实 MVP 用《未登记》）。
4. **审计角色**：`R9-Q017`（Codex 审计）→ `R9-F001`（Codex 准备 AUDIT_READY 包，GPT 主审）；`R9-Q019` → `R10-F003`（Claude 第二审计与 MERGE_HOLD）。
5. **商业平台**：`R15-Q012`/`R15-F007`（一般免费托管豁免）→ `DCA-Q006`（存在广告/订阅/付费权益/获客用途即需授权）。
6. **Claude 自动切换**：`R15-F003`/`R14-F004`/`R15-F004` → `DCA-Q003`（只记 FALLBACK_ATTEMPT，管理员建立独立 Profile 审计）。
7. **批次命令证据**：`R12-Q024`（全部探索过程）→ `R12-F004`（开发/M0 仅保存最终必需验收、CI 与适用审计）。
8. **B000 CI**：`R12-Q024` → `BOOTSTRAP-Q001`（B000 无 CI 一次性例外；B001 建 CI 后追溯验证 B000）。
9. **Claude 隐私状态**：`R15-F005` → `DCA-Q004`（未知时仅开发 Break-glass；生产/发行须已知状态或 Incognito 证据）。
10. **准据法**：`R16-Q015` → `DCA-Q005`（昆士兰州及适用澳大利亚联邦法律；保留中国大陆不可排除强制法）。

## 相邻文档

- [Authority Index](README.md) · [DECISION_MATRIX.md](DECISION_MATRIX.md) · [registry/decisions.json](registry/decisions.json) · [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md)
- [返回仓库首页](../../README.md)
