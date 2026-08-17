# 项目状态（PROJECT STATUS）

> 人类可读状态页。机器快照见 [registry/project-status.json](registry/project-status.json)。
> 状态日期：**2026-08-17**；权威快照 ID：`AIPT-DCA-CLOSEOUT-R0-R16-002`。

## 工作轨

| 工作轨 | 状态 |
|---|---|
| `AIPT-STANDALONE` | 设计冻结：`FROZEN_R0_R16_DCA_BOOTSTRAP`；施工：M0；当前批次 `AIPT-M0-B002`（`B002_IN_PROGRESS`）；`AIPT-M0-B000` 与 `AIPT-M0-B001` 均已 `MERGED/CLOSED` |
| `AIPT-PLATFORM-INTEGRATION` | `FROZEN_WAITING_M1_ENGINE`；解冻未获授权（`unfreeze_authorized = false`；`DEFER-001`、`R0-Q011`） |

## 当前里程碑

- 当前里程碑：**M0**（建立可构建可验证工程基础，不实现真实桌测）。
- `AIPT-M0-B000` = **MERGED/CLOSED**（合并提交 `777a3f39ba78c1ef3168597890c61abf7a55d962`，树 `f5f845b860ba0944ef104b4679fa074ad6efecbb`，GPT 审计 PASS）。
- `AIPT-M0-B001` = **MERGED/CLOSED**：候选 `2e904ddc2d4f1313a99e19f6751a991d589f8336`，合并提交 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`（树 `fefc25f1acb523d013c2a7d8db9801ccdab37d2d`），合并后公共 CI run `31951440133` PASS；Go/pnpm 工具链骨架、无秘密公共 CI（`b000-retro` / `toolchain` / `supply-chain`）、供应链基础（`R4-Q023`：锁文件、SBOM、许可证、漏洞、来源），`DEFER-016` 已 `RESOLVED`（Go 1.26.5 / Node 24.19.0 / pnpm 11.4.0 / PostgreSQL 18.4，见 [../../tools/toolchain.lock.json](../../tools/toolchain.lock.json)）。
- 当前批次：`AIPT-M0-B002`——Schema、JSON-RPC、Adapter SDK 与最小协议夹具合同（协议批次，`B002_IN_PROGRESS`）；迭代 1 完成公开状态迁移（B001 关闭、B002 开启）与验证器基线升级；迭代 2 新增权威协议 Schema（`schemas/protocol/v1/aipt-protocol.schema.json`）、游戏中立最小确定性夹具（`testdata/protocol/v1/minimal-fixture/`）与依赖自由的协议资产验证器（`scripts/ci/validate/protocol-assets.mjs`）；迭代 3 修复加固：Schema 根可执行（`oneOf` 只接受三种注册 wire 信封）、持久化 wire 夹具（`requests/`、`responses/`、`notifications/`，含确定性 `-32000` + `AIPT_*` 错误示例）、全量状态投影语义（重复 field_id、值漂移、未知席位/授权、遗漏授权字段）、manifest 路径加固与 `kind→schema_ref` 精确映射、schema helper fail-closed 探针；迭代 3B 修复 Codex 审查发现：跨语言安全整数 id（`minimum`/`maximum` = ±(2^53-1)）、夹具身份显式失败门（`AIPT_FIXTURE_IDENTITY_MISMATCH`，含突变内嵌投影）、manifest 预检中止 + lstat/realpath 符号链接遏制、持久化协议错误与所引用请求一致（`AIPT_ACTION_REJECTED`）、消息身份措辞更正（`message_id` 仅属动作意图文档）；迭代 4 落地**依赖自由的一方 TypeScript Adapter SDK**（`packages/adapter-sdk`，`@aipt/adapter-sdk@1.0.0`，Node 24 原生可擦除 TypeScript，零第三方依赖，`node:test` 测试 53 项全绿）与独立机器门禁（`scripts/ci/validate/adapter-sdk.mjs`：契约漂移清单与权威 Schema 逐字节比对、四类持久化 wire 信封行为、夹具摘要/投影/突变负向探针、源码卫生与无副作用导入探针；已并入 `pnpm run check`）；**迭代 4B 修复 Codex 对抗探针确认的 fail-open 验证缺口**：无损 JSON 值门禁覆盖全部信任边界（`state_field.value`/`proposal`/嵌套 JSON/通用解析输出，拒绝循环、undefined/function/symbol/bigint、非有限数、非安全整数、-0、访问器/不可枚举/符号键、非普通对象，`AIPT_LOSSY_JSON_VALUE`）；夹具 manifest 预检强制冻结常量、相对规范化 POSIX 路径、资产+突变路径唯一与精确 `kind→schema_ref` 映射表（含 `mutant_specimen`），预检失败即停止资产处理；`validateFixtureBundle` 增加包内依赖自由的 canonical JSON Schema 2020-12 子集求值器（调用方显式传入仓库唯一 Schema，包不复制 Schema、不读文件系统）逐文档校验 + 突变语义证明（对 bundle 供应的游戏中立席位/状态必须精确产生声明的 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD`）；投影身份绑定源 state（`AIPT_FIXTURE_IDENTITY_MISMATCH`）与已知席位确定性校验；wire 错误码类型修复（`ErrorObject.data.error_code` 为开放 canonical 命名空间 `AiptWireErrorCode`，`ValidationIssue.code` 保持有限稳定联合）；契约清单扩展为完整功能投影 + 权威 Schema 全量内容指纹 + 25 个公开接口形状的 schema 派生审计与 8 个内存漂移探针（任何 Schema/类型编辑都必须显式复审）；`node:test` 测试扩展至 **90 项全绿**（53 项迭代 4 测试全部保留），机器门禁负向探针扩展至 **53 个**（43 fail-closed 行为 + 8 漂移 + 突变 + 未来 wire 错误码），并演进一方 pnpm 工作区与供应链/SBOM 表示（lockfile 恰为 `.` + `packages/adapter-sdk` 两个零依赖 importer；licenses.json 新增 SDK 记录（B002 元数据，绝不冒充 B001 验证）；SBOM 新增 SDK 包（`PACKAGE_OF` 一方关系，绝非 `DEV_TOOL_OF`）与五个 SDK 负向探针，命名空间演进至 `aipt-m0-b002`，11 个 B001 包身份、工具链/action pin 与三层 PostgreSQL 模型全部保留）；未建设 Go 协议消费者与任何 server/socket/worker/model/数据库运行时，B002 聚焦工作流演进仍待后续迭代（`internal/protocol` 由 B002 主合同要求后续迭代建设，本迭代仅机械禁止）；**迭代 4C 修复 Codex 独立探针确认的更深 fail-open 缺口**：无损 JSON 值门禁改为纯描述符检查（零 getter/setter 调用，数组符号键/不可枚举/访问器索引/稀疏洞/非法索引描述符全部拒绝，保持迭代式、纯函数、路径寻址与非变异）；全值门禁覆盖每个实际 SDK 信任边界（wire/state/projection/request-id/manifest 校验器与 `validateSchemaInstance` 的 schema/document 输入；`toJsonRpcRequest` 顶层符号键/不可枚举成员与 `id=-0`、`toJsonRpcErrorResponse` 非安全整数 `error.code`、显式 `undefined`/访问器成员绕过必填分支全部拒绝）；`validateFixtureBundle` 在 manifest 预检之后、任何资产处理之前绑定调用方提供的 schema 的 canonical SHA-256 全量指纹（缺失/畸形/有损/指纹漂移一律 `AIPT_FIXTURE_INVALID_SCHEMA`），包内求值器新增确定性递归 schema 语法预检（关键字值形状/范围、类型名、schema 子节点、组合数组、本地引用与注释；隐藏于 anyOf/oneOf 通过分支或 `not` 内的非法关键字、字符串 `minLength`、数组 `properties`、字符串 `additionalProperties` 全部拒绝，const 按自有成员存在判定）；普通投影语义门禁（每个干净普通投影必须以供应 known seats 对至少一个兼容供应 state 通过 `validateProjectionSemantics`，隐藏泄露投影绝不可能作为普通投影通过，传播稳定语义码含 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD`）；突变包装元数据绑定（`seat_id` 必须等于 `projection.seat_id`、`leaked_field_id` 必须等于唯一产生声明拒绝的字段，漂移以 `AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT` 失败）；精确清单移除 `manifest.json` 豁免；`ManifestMutant.expected_semantic_rejection` 收紧为描述符派生的精确字面量类型，机器门禁新增 91 个成员类型表达式审计（嵌套形状与描述符派生 const/判别类型，`StateField.value: JsonValue → string`、嵌套成员类型漂移、突变字面量扩宽全部可检出）；`node:test` 测试扩展至 **107 项全绿**（90 项迭代 4B 测试全部保留），机器门禁负向探针扩展至 **81 个**（62 fail-closed 行为 + 11 漂移 + 6 零调用/无文档触碰 + 突变 + 未来 wire 错误码），并验证原始 `9325cce` 实现对全部新探针 fail-open。
- 施工纪律：`GLOBAL_WIP = 1`（同时只有一个活跃批次）；单批次单仓库；前一批次正式关闭后才可启动下一批次。
- 详见 [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md) 与 [../milestones/M0.md](../milestones/M0.md)。

## 仓库

| 仓库 | 说明 |
|---|---|
| AIPT | <https://github.com/zyc14588/AIPT>，默认分支 `main`；已验证接受的主线基点 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`（B001 合并提交，`MERGED/CLOSED`）；`AIPT-M0-B002` 在 `task/AIPT-M0-B002` 施工 |
| 《未登记》UNREGISTERED | <https://github.com/zyc14588/UNREGISTERED>，默认分支 `main`；规划快照 `3e4a28bba1caf44828412f90bb6715b6955e3604`；就绪等级 `PLAYTESTABLE_DRAFT` |

## 运行环境与模型（设计基线）

- 参考环境：Ubuntu 26.04 LTS（`ENV-F001`）；Bash 启动 + 本地 Web（`ENV-F002`）。
- 主远端模型：`deepseek-v4-pro`（`ENV-F003`），完整 Campaign 使用该模型（`R14-Q023`）。
- 本地模型：`UNASSIGNED`；GGUF 选型与性能阈值延期（`DEFER-002`、`DEFER-003`）。
- 以上是**设计基线**：运行时代码尚未建设（B001 仅安装工程骨架与 CI；B002 迭代 2 落地协议 Schema、最小确定性夹具与验证器，迭代 3 修复加固并新增持久化 wire 夹具与语义/加固探针，迭代 3B 关闭 Codex 审查的跨语言验证缺口——安全整数 id 边界、身份失配显式失败、lstat/realpath 遏制、错误响应一致性、消息身份措辞；迭代 4 落地依赖自由的一方 TypeScript Adapter SDK 及其机器门禁/供应链表示；迭代 4B 关闭 Codex 对抗探针确认的验证缺口（无损门禁/预检/schema 求值/突变证明/类型审计）；迭代 4C 关闭 Codex 独立探针确认的更深 fail-open 缺口（零调用描述符门禁、schema 指纹绑定与语法预检、普通投影语义门禁、突变包装元数据绑定、成员类型表达式审计），不新增任何运行时代码）；仍无 server/socket/worker/model/数据库运行时，无 Go 协议消费者。

## 审计状态

| 项 | 状态 |
|---|---|
| 主审计 | GPT（`R10-F003`） |
| 包准备 | 本地 Codex CLI，产出 `AUDIT_READY`（`R9-F001`） |
| 第二审计 | Anthropic Claude Web；本批次不要求 |
| 第二审计 Profile | `Fable 5`、`Opus 5`、`Opus 4.8`（`DCA-Q003`） |
| 第二审计生产资格 | `ADMIN_APPROVAL_AND_PRIVACY_PROFILE_PENDING`：**尚不具备生产资格**；Model Improvement 状态 `UNKNOWN`（`DEFER-011`） |

## 提示词资产政策

- 全部提示词仅保存在**本地加密 Git 仓库**；不配置远端、不公开正文（`R13-F001`）。
- 本公共仓库不含任何提示词正文、凭据或本机路径。

## 下一步

当前**只允许**执行 `AIPT-M0-B002`：

1. 公开状态迁移：B001 关闭（候选 `2e904ddc2d4f1313a99e19f6751a991d589f8336`、合并提交 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`、合并后公共 CI run `31951440133`），B002 开启（`IN_PROGRESS`、`current_batch = AIPT-M0-B002`），`verified_head = 8bcadc9669e7d04f589f883daa6d4f593875fc9e`，状态日期 `2026-08-17`；
2. 验证器从 B001 候选基线升级到 B002 基线（`constants.mjs`、`status-transition`、`defer-016`、`tree-integrity`），保留全部 B000/B001 历史门禁；
3. 迭代 3 协议资产修复：权威协议 Schema 根可执行（`schemas/protocol/v1/`，`oneOf` 只接受三种注册 wire 信封）、游戏中立最小确定性夹具（`testdata/protocol/v1/minimal-fixture/`，新增 `requests/`、`responses/`、`notifications/` 持久化 wire 信封与 `mutants/` 隐藏泄露突变）、依赖自由子集验证器（`scripts/ci/lib/json-schema.mjs`）与协议资产门禁（`scripts/ci/validate/protocol-assets.mjs`）；迭代 3B 修复 Codex 审查发现并扩展至 33 个负向探针（9 个冻结迭代 2 探针 + 迭代 3 根/投影/manifest/schema-helper 探针 + 迭代 3B 安全整数 id 边界/身份失配/符号链接遏制/wire 错误一致性探针）；`pnpm run check:protocol-assets` 并纳入 `scripts/ci/run-checks.mjs`；
4. 迭代 4 Adapter SDK 与一方工作区/供应链演进：依赖自由的一方 TypeScript 契约 SDK（`packages/adapter-sdk`，`@aipt/adapter-sdk@1.0.0`，契约漂移清单 + 独立机器门禁 `scripts/ci/validate/adapter-sdk.mjs`，`node:test` 测试，无导入副作用）；迭代 4B 修复 Codex 对抗探针确认的验证缺口（无损 JSON 值门禁覆盖全部信任边界、manifest 预检 + 逐文档 schema 校验 + 突变语义证明、投影身份与已知席位加固、wire 错误码类型修复、Schema 全量指纹 + 公开类型形状审计 + 漂移负向探针，测试 90 项、门禁负向探针 53 个）；迭代 4C 修复 Codex 独立探针确认的更深 fail-open 缺口（纯描述符零调用无损门禁、全值门禁覆盖全部信任边界、canonical schema 指纹绑定 + schema 语法预检、普通投影语义门禁 + 突变包装元数据绑定 + 精确清单、描述符派生字面量类型 + 91 项成员类型表达式审计，测试 107 项、门禁负向探针 81 个）；pnpm 工作区与 lockfile 演进（恰为 `.` + `packages/adapter-sdk` 两个零依赖 importer、零第三方包）；licenses.json 新增 B002 SDK 记录；SBOM 演进至 B002 身份（新增 SDK 包与 `PACKAGE_OF` 一方关系，五个 SDK 负向探针，命名空间 `aipt-m0-b002`，11 个 B001 包身份与三层 PostgreSQL 模型保留）；`pnpm run check:adapter-sdk`、`pnpm --filter @aipt/adapter-sdk test` 并纳入 `pnpm run check`；Go 协议消费者与 B002 聚焦工作流演进留待后续迭代；
5. 本地确定性验证 + 推送候选 Commit + 公共 CI 全绿；
6. 独立本地验收与 GPT 审计 PASS；
7. 用户批准后合并；`AIPT-PLATFORM-INTEGRATION` 保持冻结；后续批次在 B002 正式关闭前不启动。

## 相邻文档

- [README.md](README.md)（Authority Index） · [BATCH_DEPENDENCY_GRAPH.md](BATCH_DEPENDENCY_GRAPH.md) · [DEFERRED_PARAMETERS.md](DEFERRED_PARAMETERS.md) · [../protocol/README.md](../protocol/README.md) · [../milestones/M0.md](../milestones/M0.md) · [../milestones/MVP.md](../milestones/MVP.md) · [../supply-chain/README.md](../supply-chain/README.md)
- [返回仓库首页](../../README.md)
