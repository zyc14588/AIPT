# AIPT

AIPT 是一个**完全由 AI Agent 替代真人桌面席位的 TRPG 全流程桌测系统**：AI 替代 GM、玩家、Observer 等真人席位；状态、随机数、调度、日志与规则计算由确定性基础设施承担。

## 当前状态（as of 2026-08-23）

| 工作轨 | 状态 |
|---|---|
| `AIPT-STANDALONE` | 设计已冻结（`FROZEN_R0_R16_DCA_BOOTSTRAP`）；`construction = IN_PROGRESS`，`current_batch = AIPT-M0-B007`，`GLOBAL_WIP = 1`；权威快照 `AIPT-M0-B007-CONSTRUCTION-001` |
| `AIPT-PLATFORM-INTEGRATION` | `FROZEN_WAITING_M1_ENGINE`：冻结等待平台 M1 游戏引擎，解冻未获授权（`unfreeze_authorized = false`） |

批次状态：`AIPT-M0-B000` = **MERGED/CLOSED**（合并提交 `777a3f39ba78c1ef3168597890c61abf7a55d962`，树 `f5f845b860ba0944ef104b4679fa074ad6efecbb`，GPT 审计 PASS）；`AIPT-M0-B001` = **MERGED/CLOSED**（候选 `2e904ddc2d4f1313a99e19f6751a991d589f8336`，合并提交 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`，树 `fefc25f1acb523d013c2a7d8db9801ccdab37d2d`，合并后公共 CI run `31951440133` PASS）；`AIPT-M0-B002` = **MERGED/CLOSED**（候选 `9968cbc89c09640e3fc2feb8d851220eae98b9b9`，implementation merge commit `fccfb595c23feab38397506505a3e996fe7b9e9c`，implementation tree `f99570bc3c4307244ca926cec62e82a07ef5aee8`，post-merge CI run `31985644832` success）；`AIPT-M0-B003` = **MERGED/CLOSED**（Candidate `fbe1363acd977759c4effa2687483c0b78b63ab6`，Candidate tree `60bcdd0df2c29391c2564bfeae17013c07723cd3`，Candidate CI run `32334341279` success；implementation merge `725fc005185412d115307b594aa64e84acfabf67`，implementation tree `60bcdd0df2c29391c2564bfeae17013c07723cd3`，post-merge CI run `32336615560` success，Go 1.26.6 security requalification `AIPT-M0-B003-SECURITY-TOOLCHAIN-QUAL-001` PASS）；`AIPT-M0-B004` = **MERGED/CLOSED**（Candidate `4810d2cfec6146db7c161506ba7f37ab0a4ce69c`，Candidate tree `f35365d0ad47fdd513fbecb84a03b1559026637e`，Candidate CI run `32392886647` success；implementation merge `d07c0c3817620ada47b3ae7344d8ee423ace3b12`，implementation tree `f35365d0ad47fdd513fbecb84a03b1559026637e`；初始 post-merge CI run `32557930038` 保持 immutable failure，原因 `AIPT-B004-TREE-INTEGRITY-LIFECYCLE-001`；repair 指令 `AIPT-M0-B004-POSTMERGE-TREE-INTEGRITY-REPAIR-001`，repair commit `bd0c06867da58f89e82a35d82ce1d798c1ec9cae`，repair CI run `32558813381` success，accepted post-merge gate PASS；依赖安全再资格化 `AIPT-M0-B004-DEPENDENCY-SECURITY-REQUAL-001` PASS，`GO-2026-5970` = `RESOLVED_BY_X_TEXT_V0_39_0`）。`AIPT-M0-B000`/`AIPT-M0-B001`/`AIPT-M0-B002`/`AIPT-M0-B003`/`AIPT-M0-B004` 为不可变已关闭历史。外部串行前序 `UNREGISTERED-AIPT-P0-B001` = **MERGED/CLOSED**（closeout 提交 `a37b284bf5ec35895f436abe71d22599edb6da53`，公共 CI run `32194224161` success）。

`AIPT-M0-B005` = **MERGED_CLOSED**：基线 `8005dd3bec8b367a6d97dcd9397158f1d8618f3e`（tree `d0f32b7ac1c3f6e5ddb258aaa2ee030844b1eb2b`）；Approved Candidate `d9e24cbac30a1472c41cc8719848acbbc2426fa5`（tree `c1b0b3e3c5218a46c4f3d9501b52a2618cfe20f5`，Candidate CI `32565305803` success）；implementation merge `8652a92c51b86a3bf66aee725c0f1b7be4c60654`（相同 tree，精确父提交为基线与 Candidate），post-merge CI `32569995492` success；closeout `10d0232bd2e3e42601bbb00cedc753f842e219db`（tree `922115b9a75a7eca8dd97475f3f228bc7d3d2c10`），closeout CI `32571092786` success。`@aipt/harness-adapter` `0.1.0` 的真实子进程 stdio smoke 为 `23/23` PASS，第三方 pnpm 包为 0，未调用远端模型。Harness 升级指令 `AIPT-M0-B005-EXTERNAL-HARNESS-UPGRADE-001` 的 disposition 为 `OWNER_GATE_RATIFIED`：previous `47f943859bef60e4160492346772ded9b24f765a`，current `141eb6fef83422698aef7a981029e843e8161534`，release `dsh-v0.1.0-rc.8`，`prior_authorization_timing_independently_verified = false`。

`AIPT-M0-B006` = **MERGED_CLOSED**：Base `10d0232bd2e3e42601bbb00cedc753f842e219db`（tree `922115b9a75a7eca8dd97475f3f228bc7d3d2c10`）；Approved Candidate `3987b8d4c26ac079d01c214ba90e113eeffd5713`（tree `4271a3fb71236a8b003b4d9ddc84727c6fec8d46`，Candidate CI `32577246851` success）；implementation merge `35acba9fb629f50087def3b720df304fadfd2158`（相同 tree，精确父提交为 Base 与 Candidate，subject `merge: integrate AIPT-M0-B006`），post-merge CI `32578143923` success。已交付 Evidence/Audit Draft 2020-12 Schema、最小原生 `RAW_CAPTURE` exporter/verifier、只读 PostgreSQL 18.4 ledger source、合成 golden 与确定性/篡改门禁；`AUDIT_READY`/`AUDIT_RESULT` generator、签名、加密、分块仍为 `NOT_IMPLEMENTED`。施工 Harness 因输入 `190183 > 180000` 命中 `HARNESS_INPUT_TOKEN_BUDGET`，未产生 patch，最终路由 `CODEX_ONLY`；这是施工遥测，不是 product runtime failure，split-memory 未手工编辑。

`AIPT-M0-B007` = **IN_PROGRESS**：从固定 Base `e1e1a6315ef2308922105dd30fd4bbcf4e3f91c8`（tree `326def92334a43f6d63cd77b40f0eae9af31b375`）建设仅绑定 `127.0.0.1` 动态端口的本地 Web Dashboard。六个只读面板固定为 Config、Health、Queue、Run、Status/Table、Reports；Queue/Run/Status backend 与 Report UI export/generator 均明确 `NOT_IMPLEMENTED`，不得产生假数据。外部串行前序 `UNREGISTERED-AIPT-P0-B003` 已 `MERGED_CLOSED`（closeout `358d6d9d08a86818e34fd0c0d9a62bfe66e73abe`，CI `32621464543` success）；下一串行项 `INT-AIPT-UNREGISTERED-001` 为 `NOT_AUTHORIZED`（`next_batch_authorized = false`，`next_batch_started = false`），未开始。`AIPT-PLATFORM-INTEGRATION` 保持 `FROZEN_WAITING_M1_ENGINE`。

**B005 Harness Adapter（已关闭）** 是一方薄适配层：复用 `@aipt/adapter-sdk` 的既有 wire truth，以每行一个 UTF-8 JSON-RPC 信封的 stdio 边界连接可注入的 `HarnessBackend`；stdout 只承载协议帧，stderr 只承载脱敏诊断。测试专用 fixture backend 从 B002 权威夹具读取 ACCEPT/REJECT 输出，不在生产源码硬编码游戏字段，也不发起网络或模型调用。详见 [docs/harness/README.md](docs/harness/README.md)。

**B004 Runtime Shell** 已作为关闭交付保存在 accepted implementation merge `d07c0c3817620ada47b3ae7344d8ee423ace3b12`（tree `f35365d0ad47fdd513fbecb84a03b1559026637e`）：Go Launcher 固定执行 `CONFIG → POSTGRESQL → MIGRATIONS → MODEL → HARNESS → CORE → IPC → WEB`，真实路径完成严格配置加载、PostgreSQL Ping 与 B003 `MigrateUp` 后，在未实现的 `MODEL` 门禁以 `AIPT_LAUNCH_GATE_NOT_IMPLEMENTED` 失败关闭，绝不把 launch plan 冒充 runtime ready。新增 [`internal/config`](internal/config) / [`schemas/config/v1`](schemas/config/v1) 共享配置基础、[`internal/core`](internal/core) lifecycle shell、[`internal/launcher`](internal/launcher) 门禁机与 [`cmd/aipt`](cmd/aipt) 最小 CLI；SIGINT/SIGTERM 传播取消，启动失败与取消均执行独立有界的逆序清理并保留根错误。B004 没有新增业务依赖；在 `AIPT-M0-B004-DEPENDENCY-SECURITY-REQUAL-001` 下，reachable `GO-2026-5970` 使 B003 原始 x/text v0.29.0 安全再资格化为精确 v0.39.0，pgx 仍冻结为 v5.10.0，MVS 精确提升 x/sync v0.17.0→v0.21.0、x/mod v0.27.0→v0.37.0、x/tools v0.36.0→v0.47.0。运行边界与配置示例见 [`docs/runtime/README.md`](docs/runtime/README.md)。本段是 B004 `MERGED_CLOSED` closeout 说明，不改变 fail-closed runtime 边界。

**B003 迭代 6a（storage supply docs）**已落地：失败关闭的存储机器门禁 [scripts/ci/validate/storage.mjs](scripts/ci/validate/storage.mjs)（`pnpm run check:storage`，Node 标准库；校验 pgx v5.10.0 闭包、迁移/账本/VerifyStream/集成测试契约，并**动态枚举** `internal/storage/postgres` 下全部非测试 `.go` 源码做大小写/空白容忍的零运行时完整性绕过扫描——非固定白名单；临时夹具经由同一共享源码树检查证明缺失 verify.go 与新增绕过文件均失败）、**pgx v5.10.0 Go 运行时闭包资格**（`go.mod` 直接 `github.com/jackc/pgx/v5 v5.10.0` + 五个间接模块；jackc 四模块 MIT、golang.org/x 两模块 BSD-3-Clause，精确版本/角色/直接性记录于 [tools/supply-chain/licenses.json](tools/supply-chain/licenses.json)，go=6/pnpm=0；冻结的 [tools/supply-chain/policy.json](tools/supply-chain/policy.json) 保持不可变 B001 基线）、B003 供应链门禁与确定性 SPDX 2.3 SBOM 演进（`aipt-m0-b003` 内容寻址 namespace、18 个包身份、Go h1/SHA-256 校验和语义、`AIPT DEPENDS_ON pgx` / `pgx DEPENDS_ON` 五个间接模块的运行时依赖关系——绝不 DEV_TOOL_OF、30 个语义负向探针 + 7 个 go.mod/go.sum 清单负向探针）、在 Owner 指令 `AIPT-M0-B003-SCOPE-EXPANSION-001` 授权下把 [scripts/ci/validate/toolchain-lock.mjs](scripts/ci/validate/toolchain-lock.mjs) 从 B001 时代"go.mod 零第三方 require"引导规则演进为**精确批准闭包的 fail-closed 校验**（六模块精确版本/直接性、replace/exclude/retract 图覆盖拒绝、zip 与 `/go.mod` h1 精确 pin；全部 B001 工具链 pin 与 `selected_by_batch = AIPT-M0-B001` 历史事实原样保留、pnpm 零第三方依赖策略不变）以及存储与供应链文档（[docs/storage/README.md](docs/storage/README.md)、[docs/supply-chain/README.md](docs/supply-chain/README.md)）。该实施已随 `AIPT-M0-B003` 合并并关闭；严格存储、供应链与 scope 门禁继续保留。

**B003 security toolchain requalification**已落地：当前 Go 身份从 B001 初始资格化的 **1.26.5** 重资格为官方稳定版 **1.26.6**（release date 2026-08-13；理由 `reachable standard-library vulnerabilities`；精确触发公告集 **GO-2026-6090**（crypto/tls）、**GO-2026-6088**（encoding/xml）、**GO-2026-5972**（encoding/asn1），每条均已由 1.26.6 官方修复；官方 release index / linux/amd64 归档 `go1.26.6.linux-amd64.tar.gz` 及独立重算的 SHA-256 / upstream tag go1.26.6 提交 / release history / 安全公告全部记录于 [tools/toolchain.lock.json](tools/toolchain.lock.json) 的 provenance，显式区分 **B001 初始资格（Go 1.26.5）** 与 **B003 安全重资格（Go 1.26.6）**，`selected_by_batch` 保持 `AIPT-M0-B001`）。`go` 语言指令仍为 `go 1.26.x`，`toolchain go1.26.6`；pgx v5.10.0 六模块闭包与全部 go.sum pin、Node 24.19.0、pnpm 11.4.0、PostgreSQL 18.4、govulncheck v1.7.0 与全部 action pin 不变；`DEFER-016` 保持 `RESOLVED`（`resolved_by_batch = AIPT-M0-B001`），其记录以受控方式携带当前 Go 1.26.6 与精确安全 provenance，`DEFER-001..015` 与 `decisions.json`/`supersessions.json` 逐字节不变；CI 在 `ubuntu-24.04` 与 `ubuntu-26.04` 上精确校验 `go version go1.26.6 linux/amd64`。该重资格已由 B003 Candidate、implementation merge 与 post-merge CI 接受，且不会改写 B001 历史。

**设计基线已冻结。** B001 已合并关闭（工具链骨架、公共 CI、供应链门禁）；B002 迭代 3/3B 已产出修复加固后的权威协议 Schema、确定性夹具（含持久化 wire 信封）与协议资产验证器（含 33 个负向探针；3B 关闭跨语言验证缺口：安全整数 id 边界、身份失配显式失败、lstat/realpath 遏制、错误响应与引用请求一致、消息身份措辞）；迭代 4 已产出依赖自由的一方 TypeScript Adapter SDK（契约常量/类型、确定性 canonical JSON 与 SHA-256、严格 JSON-RPC 2.0 四类信封的 parse/decode/encode 与类型化 builder、语义投影验证、夹具兼容验证、无导入副作用探针）及其机器门禁与供应链/SBOM 表示；迭代 4B 已关闭 Codex 对抗探针确认的验证缺口（无损 JSON 值门禁、manifest 预检 + 逐文档 schema 校验 + 突变语义证明、投影身份加固、wire 错误码类型修复、Schema 全量指纹与类型形状审计；测试 90 项、门禁负向探针 53 个）；迭代 4C 已关闭 Codex 独立探针确认的更深验证缺口（零调用描述符无损门禁、全值信任边界门禁、schema 指纹绑定 + 语法预检、普通投影语义门禁、突变元数据绑定、精确清单、成员类型表达式审计；测试 107 项、门禁负向探针 81 个）；迭代 4D 已关闭 Codex 独立源码评审与原始实现探针确认的求值器缺口（同对象跨调用陈旧预检接受、未引用定义本地 `$ref` 环、空 `required` 拒绝/type·enum 重复接受/注解与结构关键字语法不精确、十进制 `multipleOf` 误拒；测试 122 项、门禁探针 103 个）；迭代 5 已落地依赖自由的 Go 协议契约消费者（`internal/protocol`：严格信封解码、canonical JSON/SHA-256、投影/可见性语义、共享夹具与 schema 漂移测试），迭代 5B 已关闭 Codex 独立对抗评审复现的六个 Go 消费者 fail-open 缺口（整数值不安全小数/指数拼写、Node 逐字节兼容的孤立 UTF-16 代理、数值 wire 错误码一致性、突变内嵌投影身份绑定与 nil 语义输入、manifest 解码期语义预检与不可变 kind→schema_ref 权威，测试 183 项、负向用例 101 项），迭代 6 已落地聚焦 B002 CI 工作流演进（耐久名称 `AIPT M0 CI` 的公共 workflow 在两个合格 Ubuntu runner 上显式执行 `pnpm run check:protocol-assets` / `pnpm run test:adapter-sdk` / `pnpm run test:protocol-go`，`pnpm run check` 保留为 B001+B002 聚合门禁；workflow 验证器升级为 fail-closed B002 契约；B002 全程不新增任何运行时代码）。B003 迭代 6a 首次落地运行时代码——PostgreSQL 存储层（只前向嵌入式迁移、追加式哈希链账本 Append/VerifyStream、集成测试契约）与其机器门禁 `pnpm run check:storage`，并资格化 pgx v5.10.0 Go 运行时闭包（go=6/pnpm=0）。B005 已交付受控 stdio worker 与 Harness Adapter；B006 已交付 Evidence/Audit Schema 与最小原生 `RAW_CAPTURE` exporter/verifier；均不建设 server/socket/model runtime 或 Web UI，且 `AIPT-PLATFORM-INTEGRATION` 保持 `FROZEN_WAITING_M1_ENGINE`。

首个真实游戏目标为 **《未登记》UNREGISTERED**（当前就绪等级 `PLAYTESTABLE_DRAFT`）。

## 权威入口（渐进式披露）

- 施工者：从 [docs/authority/README.md](docs/authority/README.md)（Authority Index）开始，再按需进入领域文档与机器登记。
- 项目现状与下一步：[docs/authority/PROJECT_STATUS.md](docs/authority/PROJECT_STATUS.md)
- 里程碑合同：[docs/milestones/M0.md](docs/milestones/M0.md) 与 [docs/milestones/MVP.md](docs/milestones/MVP.md)
- 机器决策权威：[docs/authority/registry/decisions.json](docs/authority/registry/decisions.json)（共 454 条决策 ID）
- 协议契约（B002）：[docs/protocol/README.md](docs/protocol/README.md) → 权威根 [schemas/protocol/v1/aipt-protocol.schema.json](schemas/protocol/v1/aipt-protocol.schema.json) 与最小确定性夹具 [testdata/protocol/v1/minimal-fixture/manifest.json](testdata/protocol/v1/minimal-fixture/manifest.json)
- Adapter SDK（B002 迭代 4）：一方 TypeScript 契约 SDK [packages/adapter-sdk/README.md](packages/adapter-sdk/README.md)（`@aipt/adapter-sdk@1.0.0`，零依赖，Node 24 原生 TS；机器门禁 `pnpm run check:adapter-sdk`，测试 `pnpm --filter @aipt/adapter-sdk test`）
- Go 协议契约消费者（B002 迭代 5/5B）：[internal/protocol](internal/protocol)（仅 Go 标准库，零依赖；严格 JSON-RPC 2.0 信封解码、确定性 canonical JSON/SHA-256 与 Node 预言机逐字节一致（含孤立 UTF-16 代理）、投影/可见性语义、共享夹具兼容与 schema 漂移测试；运行 `pnpm run test:protocol-go`，即 `go test ./internal/protocol -count=1`）
- Harness Adapter（B005，已关闭）：[packages/harness-adapter/README.md](packages/harness-adapter/README.md)（`@aipt/harness-adapter@0.1.0`，仅依赖一方 `@aipt/adapter-sdk`；受控 stdio、可注入 backend、真实子进程 smoke；机器门禁 `pnpm run check:harness-adapter`，测试 `pnpm run test:harness-adapter`）
- 公共 CI：[.github/workflows/ci.yml](.github/workflows/ci.yml) 以耐久名称 `AIPT M0 CI` 在 `ubuntu-24.04` 与 `ubuntu-26.04` 两个合格 runner 上保留全部既有聚焦命令，并显式运行 B006 `pnpm run check:evidence` 与 `pnpm run test:evidence-go`；独立 storage job 在 digest-pinned、loopback-only PostgreSQL 18.4 上运行 Evidence 集成与 race。`pnpm run check` 是 B001–B006 聚合门禁（报告 schema `aipt.public.b006-validator-run/v1`）。
- 存储（B003 迭代 6a）：[docs/storage/README.md](docs/storage/README.md)（只前向嵌入式迁移、追加式哈希链账本 Append/VerifyStream、类型化失败、仅测试用 PostgreSQL 18.4 镜像与 DSN fail-closed、并发/篡改覆盖、生产数据禁止；机器门禁 `pnpm run check:storage`）
- Evidence/Audit（B006，已关闭）：[docs/evidence/README.md](docs/evidence/README.md) → 公开三阶段 Schema [aipt-evidence.schema.json](schemas/evidence/v1/aipt-evidence.schema.json) 与最小原生 Go [`RAW_CAPTURE` exporter/verifier](internal/evidence)；只读复用 B003 `VerifyStream`，canonical JSON 复用 B002 `internal/protocol.CanonicalJSON`，合成 golden 位于 [testdata/evidence/v1](testdata/evidence/v1)。`AUDIT_READY`/`AUDIT_RESULT` generator、签名、加密与分块均未实现。
- 工具链与供应链：[docs/supply-chain/README.md](docs/supply-chain/README.md) 与 [tools/toolchain.lock.json](tools/toolchain.lock.json)（B003 原始 pgx v5.10.0 运行时闭包 go=6/pnpm=0 与 18 身份清单保留为历史；B004 因 GO-2026-5970 将 x/text 精确再资格化到 v0.39.0；B005 加入一方 Harness Adapter 后当前许可证/SBOM 为 21 身份，其中 x/mod 与 x/tools 仅为 selected-module-graph tooling；第三方闭包、Go 1.26.6 与冻结 `policy.json` 均不变）

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
| 存储 | [docs/storage/README.md](docs/storage/README.md) |

## 权威与冲突处理

决策 ID、状态与覆盖关系以机器登记（[docs/authority/registry/](docs/authority/registry/decisions.json)）为准；人类文档是可读解释，不是第二份独立权威。冲突处理顺序见 [docs/authority/README.md](docs/authority/README.md)。

本公共仓库**不含**任何私有提示词、凭据、模型端点或本机路径。提示词资产仅保存在本地加密 Git 仓库且不配置任何远端，正文永不公开。

## 许可

AIPT 代码与文档本体采用 [MIT License](LICENSE)（Copyright (c) 2026 AIPT contributors）。

MIT 只覆盖 AIPT 本体，**不自动覆盖**游戏内容：《未登记》游戏内容适用独立的非商业相同方式共享政策（政策已冻结、最终法律正文尚未起草），其适配器/执行代码预计为 MIT。详见 [docs/licensing/README.md](docs/licensing/README.md)。

## 仓库与分支

- 仓库：<https://github.com/zyc14588/AIPT>，权威分支 `main`。
- 施工使用独立任务分支（如 `task/<batch-id>`）与隔离工作树；候选 Commit 推送后，经独立本地验收与 GPT 审计核验，仅由用户批准才合并到 `main`。
- `AIPT-M0-B000` 是一次性 Bootstrap 例外：无 CI，以最终本地确定性验收 + GPT 审计关闭（已 `MERGED/CLOSED`）；`AIPT-M0-B001` 建立公共 CI 并追溯验证 B000（`b000-retro` job），已 `MERGED/CLOSED`（合并提交 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`）。
