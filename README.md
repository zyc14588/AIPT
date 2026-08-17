# AIPT

AIPT 是一个**完全由 AI Agent 替代真人桌面席位的 TRPG 全流程桌测系统**：AI 替代 GM、玩家、Observer 等真人席位；状态、随机数、调度、日志与规则计算由确定性基础设施承担。

## 当前状态（as of 2026-08-17）

| 工作轨 | 状态 |
|---|---|
| `AIPT-STANDALONE` | 设计已冻结（`FROZEN_R0_R16_DCA_BOOTSTRAP`），正在 M0 施工；当前批次 `AIPT-M0-B002`（`B002_IN_PROGRESS`） |
| `AIPT-PLATFORM-INTEGRATION` | `FROZEN_WAITING_M1_ENGINE`：冻结等待平台 M1 游戏引擎，解冻未获授权（`unfreeze_authorized = false`） |

批次状态：`AIPT-M0-B000` = **MERGED/CLOSED**（合并提交 `777a3f39ba78c1ef3168597890c61abf7a55d962`，树 `f5f845b860ba0944ef104b4679fa074ad6efecbb`，GPT 审计 PASS）；`AIPT-M0-B001` = **MERGED/CLOSED**（候选 `2e904ddc2d4f1313a99e19f6751a991d589f8336`，合并提交 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`，树 `fefc25f1acb523d013c2a7d8db9801ccdab37d2d`，合并后公共 CI run `31951440133` PASS）。当前批次 = `AIPT-M0-B002`：Schema、JSON-RPC、Adapter SDK 与最小协议夹具合同（协议批次）；迭代 2 落地权威协议 Schema（`schemas/protocol/v1/`）、游戏中立最小确定性夹具（`testdata/protocol/v1/minimal-fixture/`）与协议资产验证器；迭代 3 修复加固：可执行根（oneOf 只接受三种注册 wire 信封）、持久化 wire 夹具（`requests/`、`responses/`、`notifications/`，含确定性 `-32000` 错误示例）、全量状态投影语义（重复 field_id / 值漂移 / 未知席位 / 遗漏授权字段）、manifest 路径加固与 `kind→schema_ref` 精确映射、依赖自由 schema helper 的 fail-closed 探针；迭代 3B 修复 Codex 审查发现：跨语言安全整数 id（±(2^53-1)）、夹具身份显式失败门（`AIPT_FIXTURE_IDENTITY_MISMATCH`）、预检中止 + lstat/realpath 符号链接遏制、持久化协议错误与所引用请求一致（`AIPT_ACTION_REJECTED`）、消息身份措辞更正（`message_id` 仅属动作意图文档）；迭代 4 落地**依赖自由的一方 TypeScript 契约 SDK**（`packages/adapter-sdk`，`@aipt/adapter-sdk@1.0.0`，Node 24 原生可擦除 TypeScript + `node:test`，零第三方依赖，契约漂移清单由 `check:adapter-sdk` 机器门禁绑定到权威 Schema），并演进一方 pnpm 工作区（lockfile 恰为 `.` 与 `packages/adapter-sdk` 两个 importer、零依赖说明符、零第三方包）与供应链/SBOM 记录（licenses.json 增加 SDK 记录；SBOM 增加 SDK 包与 `PACKAGE_OF` 一方关系，命名空间演进至 `aipt-m0-b002`，11 个 B001 包身份全部保留）；**迭代 4B 修复 Codex 对抗探针确认的 fail-open 验证缺口**（无损 JSON 值门禁覆盖全部信任边界、夹具 manifest 预检 + 逐文档 schema 校验 + 突变语义证明、投影身份与已知席位加固、wire 错误码类型修复、权威 Schema 全量指纹 + 公开类型形状审计，`node:test` 测试 90 项全绿、机器门禁负向探针 53 个）；**迭代 4C 修复 Codex 独立探针确认的更深 fail-open 缺口**（纯描述符零 getter/setter 调用的无损门禁、全值门禁覆盖每个实际 SDK 信任边界、canonical schema SHA-256 指纹绑定 + 确定性 schema 语法预检、普通投影语义门禁 + 突变包装元数据绑定 + 精确清单、描述符派生字面量类型 + 91 项成员类型表达式审计，`node:test` 测试 107 项全绿、机器门禁负向探针 81 个）；**迭代 4D 修复 Codex 独立源码评审与原始实现探针确认的求值器缺口**（同对象跨调用陈旧预检接受、未引用定义中的本地 `$ref` 环、声明语法内部精确化（空 `required` 合法、type/enum 唯一、注解形状、结构关键字仅限根且 `$schema` 恰为 2020-12 URI）、十进制 `multipleOf` 1e-9 容差；`node:test` 测试 122 项全绿、机器门禁探针 103 个）；**迭代 5 落地依赖自由的 Go 协议契约消费者**（`internal/protocol`，仅 Go 标准库，`go.mod`/`go.sum` 不变）：严格 fail-closed JSON-RPC 2.0 信封解码（重复键任意深度拒绝、尾随数据拒绝、未知/缺失成员与显式 null 拒绝、安全整数 id ±(2^53-1) 按值**与 JSON 类型**往返）、确定性 canonical JSON/SHA-256（与 Node 协议资产预言机逐字节一致）、纯投影/可见性语义（六冻结标签、全量状态投影合同、hidden-leak 突变以 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD` 语义拒绝）、共享夹具端到端兼容测试（manifest 精确清单/摘要重算/身份三元组/重放哈希）与权威 Schema `$defs` 常量漂移测试；**迭代 5B 修复 Codex 独立对抗评审复现的六个 fail-open 缺口**：整数值不安全的小数/指数拼写（`9007199254740993.0`/`9007199254740992e0`/`1e20` 等，任何整数值数字必须落在 ±(2^53-1) 安全区间，`AIPT_JSON_UNSAFE_INTEGER`）；Node 逐字节兼容的孤立 UTF-16 代理（孤立高/低代理保留为独立码元并以小写 `\uXXXX` 序列化、合法代理对重组为 Unicode 标量、键按 JavaScript UTF-16 码元序排序、重复键检测与 `JSONEqual` 绝不把孤立代理与 U+FFFD 混同）；确定性 wire 错误一致性门禁校验数值 `error.code = -32000`（方法/消息/数据/码逐字段漂移均拒绝）；突变内嵌投影身份必须等于供应源 state 身份（漂移 `AIPT_FIXTURE_IDENTITY_MISMATCH`）且 nil 语义输入一律类型化失败、绝不 panic（`CheckProjection`/`KnownSeats`/`MutantSemanticRejection`/`ValidateProjection`）；`DecodeManifest` 解码期语义预检（路径安全/资产+突变路径唯一/突变路径必须位于 `mutants/`/每个 kind 的 `schema_ref` 必须等于可信精确映射，无文件 I/O）且 kind→schema_ref 登记表改为不可变非导出权威（快照 API 返回副本，快照突变绝不影响解码）；`go test` 测试 183 项全绿、负向用例 101 项；**迭代 5C 修复 Codex 独立探针复现的四个 Go 契约缺口**：字符串 `RequestID` 保存精确 JavaScript 字符串值（孤立 UTF-16 代理码元以 Node 兼容小写 `\uXXXX` 序列化、绝不与 U+FFFD 混同，`Equal` 按精确值比较（转义合法对 == 字面标量、同值异拼写相等、字符串 vs 数字恒不相等），1..128 字符按 JavaScript 码点语义含 128/129 边界，`String()` 诚实声明为有损 Go Unicode 视图且数字 id 返回十进制，不可变规范引用文本表示、无可变底层切片）；`NewStringID` 对非法 UTF-8 以类型化 `AIPT_ID_INVALID` 确定性拒绝（绝不静默重写字节，真实 U+FFFD 保持有效）；`CheckStateMetadata` 将 present-but-empty fields 视为 `AIPT_STATE_MISSING_FIELDS`（schema `fields.minItems = 1`）；`CheckProjection` 在投影专属原因之前确定性地先门禁源 state 元数据（缺失字段/重复 field_id/未知授权席位），`ValidateProjection` 因而以首个稳定相关原因失败，从同一缺陷 state 复制的投影无法掩盖源缺陷，干净夹具/数学集合授权比较/nil 行为/hidden-leak 突变唯一原因全部保留；`go test` 测试 205 项全绿、负向用例 116 项；B002 聚焦工作流演进（Go 测试接入公共 CI workflow）仍待后续迭代。已验证接受的主线基点 = `8bcadc9669e7d04f589f883daa6d4f593875fc9e`。GLOBAL_WIP = 1。

**设计基线已冻结、运行时代码尚未建设。** B001 已合并关闭（工具链骨架、公共 CI、供应链门禁）；B002 迭代 3/3B 已产出修复加固后的权威协议 Schema、确定性夹具（含持久化 wire 信封）与协议资产验证器（含 33 个负向探针；3B 关闭跨语言验证缺口：安全整数 id 边界、身份失配显式失败、lstat/realpath 遏制、错误响应与引用请求一致、消息身份措辞）；迭代 4 已产出依赖自由的一方 TypeScript Adapter SDK（契约常量/类型、确定性 canonical JSON 与 SHA-256、严格 JSON-RPC 2.0 四类信封的 parse/decode/encode 与类型化 builder、语义投影验证、夹具兼容验证、无导入副作用探针）及其机器门禁与供应链/SBOM 表示；迭代 4B 已关闭 Codex 对抗探针确认的验证缺口（无损 JSON 值门禁、manifest 预检 + 逐文档 schema 校验 + 突变语义证明、投影身份加固、wire 错误码类型修复、Schema 全量指纹与类型形状审计；测试 90 项、门禁负向探针 53 个）；迭代 4C 已关闭 Codex 独立探针确认的更深验证缺口（零调用描述符无损门禁、全值信任边界门禁、schema 指纹绑定 + 语法预检、普通投影语义门禁、突变元数据绑定、精确清单、成员类型表达式审计；测试 107 项、门禁负向探针 81 个）；迭代 4D 已关闭 Codex 独立源码评审与原始实现探针确认的求值器缺口（同对象跨调用陈旧预检接受、未引用定义本地 `$ref` 环、空 `required` 拒绝/type·enum 重复接受/注解与结构关键字语法不精确、十进制 `multipleOf` 误拒；测试 122 项、门禁探针 103 个）；迭代 5 已落地依赖自由的 Go 协议契约消费者（`internal/protocol`：严格信封解码、canonical JSON/SHA-256、投影/可见性语义、共享夹具与 schema 漂移测试），迭代 5B 已关闭 Codex 独立对抗评审复现的六个 Go 消费者 fail-open 缺口（整数值不安全小数/指数拼写、Node 逐字节兼容的孤立 UTF-16 代理、数值 wire 错误码一致性、突变内嵌投影身份绑定与 nil 语义输入、manifest 解码期语义预检与不可变 kind→schema_ref 权威，测试 183 项、负向用例 101 项），尚未建设任何 server/socket/worker/model/数据库运行时；`AIPT-PLATFORM-INTEGRATION` 保持 `FROZEN_WAITING_M1_ENGINE`。

首个真实游戏目标为 **《未登记》UNREGISTERED**（当前就绪等级 `PLAYTESTABLE_DRAFT`）。

## 权威入口（渐进式披露）

- 施工者：从 [docs/authority/README.md](docs/authority/README.md)（Authority Index）开始，再按需进入领域文档与机器登记。
- 项目现状与下一步：[docs/authority/PROJECT_STATUS.md](docs/authority/PROJECT_STATUS.md)
- 里程碑合同：[docs/milestones/M0.md](docs/milestones/M0.md) 与 [docs/milestones/MVP.md](docs/milestones/MVP.md)
- 机器决策权威：[docs/authority/registry/decisions.json](docs/authority/registry/decisions.json)（共 454 条决策 ID）
- 协议契约（B002）：[docs/protocol/README.md](docs/protocol/README.md) → 权威根 [schemas/protocol/v1/aipt-protocol.schema.json](schemas/protocol/v1/aipt-protocol.schema.json) 与最小确定性夹具 [testdata/protocol/v1/minimal-fixture/manifest.json](testdata/protocol/v1/minimal-fixture/manifest.json)
- Adapter SDK（B002 迭代 4）：一方 TypeScript 契约 SDK [packages/adapter-sdk/README.md](packages/adapter-sdk/README.md)（`@aipt/adapter-sdk@1.0.0`，零依赖，Node 24 原生 TS；机器门禁 `pnpm run check:adapter-sdk`，测试 `pnpm --filter @aipt/adapter-sdk test`）
- Go 协议契约消费者（B002 迭代 5/5B）：[internal/protocol](internal/protocol)（仅 Go 标准库，零依赖；严格 JSON-RPC 2.0 信封解码、确定性 canonical JSON/SHA-256 与 Node 预言机逐字节一致（含孤立 UTF-16 代理）、投影/可见性语义、共享夹具兼容与 schema 漂移测试；运行 `pnpm run test:protocol-go`，即 `go test ./internal/protocol -count=1`）
- 工具链与供应链：[docs/supply-chain/README.md](docs/supply-chain/README.md) 与 [tools/toolchain.lock.json](tools/toolchain.lock.json)

## 面向读者

| 读者 | 最短阅读路径 |
|---|---|
| 施工者（实施批次） | [docs/authority/README.md](docs/authority/README.md) → [docs/authority/DECISION_MATRIX.md](docs/authority/DECISION_MATRIX.md) → [docs/authority/GOVERNANCE.md](docs/authority/GOVERNANCE.md) → [docs/milestones/M0.md](docs/milestones/M0.md) → [docs/supply-chain/README.md](docs/supply-chain/README.md) |
| 审计者（GPT 主审；Claude 第二审计） | [docs/authority/README.md](docs/authority/README.md) → [docs/authority/SUPERSEDED_DECISIONS.md](docs/authority/SUPERSEDED_DECISIONS.md) → [docs/evidence/README.md](docs/evidence/README.md) → [docs/security/README.md](docs/security/README.md) |
| 游戏适配器作者 | [docs/integration/README.md](docs/integration/README.md) → [docs/architecture/README.md](docs/architecture/README.md) → [docs/milestones/MVP.md](docs/milestones/MVP.md) |

## 领域文档

| 领域 | 文档 |
|---|---|
| 架构 | [docs/architecture/README.md](docs/architecture/README.md) |
| 协议 | [docs/protocol/README.md](docs/protocol/README.md) |
| 安全 | [docs/security/README.md](docs/security/README.md) |
| 证据与审计 | [docs/evidence/README.md](docs/evidence/README.md) |
| 测试模型 | [docs/test-model/README.md](docs/test-model/README.md) |
| 多仓库集成 | [docs/integration/README.md](docs/integration/README.md) |
| 许可 | [docs/licensing/README.md](docs/licensing/README.md) |
| 供应链 | [docs/supply-chain/README.md](docs/supply-chain/README.md) |

## 权威与冲突处理

决策 ID、状态与覆盖关系以机器登记（[docs/authority/registry/](docs/authority/registry/decisions.json)）为准；人类文档是可读解释，不是第二份独立权威。冲突处理顺序见 [docs/authority/README.md](docs/authority/README.md)。

本公共仓库**不含**任何私有提示词、凭据、模型端点或本机路径。提示词资产仅保存在本地加密 Git 仓库且不配置任何远端，正文永不公开。

## 许可

AIPT 代码与文档本体采用 [MIT License](LICENSE)（Copyright (c) 2026 AIPT contributors）。

MIT 只覆盖 AIPT 本体，**不自动覆盖**游戏内容：《未登记》游戏内容适用独立的非商业相同方式共享政策（政策已冻结、最终法律正文尚未起草），其适配器/执行代码预计为 MIT。详见 [docs/licensing/README.md](docs/licensing/README.md)。

## 仓库与分支

- 仓库：<https://github.com/zyc14588/AIPT>，权威分支 `main`。
- 施工使用独立任务分支（如 `task/AIPT-M0-B002`）与隔离工作树；候选 Commit 推送后，经独立本地验收与 GPT 审计核验，仅由用户批准才合并到 `main`。
- `AIPT-M0-B000` 是一次性 Bootstrap 例外：无 CI，以最终本地确定性验收 + GPT 审计关闭（已 `MERGED/CLOSED`）；`AIPT-M0-B001` 建立公共 CI 并追溯验证 B000（`b000-retro` job），已 `MERGED/CLOSED`（合并提交 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`）。
