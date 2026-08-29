# AIPT

AIPT 是一个**完全由 AI Agent 替代真人桌面席位的 TRPG 全流程桌测系统**：AI 替代 GM、玩家、Observer 等真人席位；状态、随机数、调度、日志与规则计算由确定性基础设施承担。

## 当前状态（as of 2026-08-29）

| 工作轨 | 状态 |
|---|---|
| `AIPT-STANDALONE` | 设计已冻结（`FROZEN_R0_R16_DCA_BOOTSTRAP`）；`construction = IDLE_WAITING_NEXT_BATCH`，`current_batch = NO_ACTIVE_BATCH`，`GLOBAL_WIP = 0`；closeout 状态快照 `AIPT-MVP-B002-CLOSEOUT-001` |
| `AIPT-PLATFORM-INTEGRATION` | `FROZEN_WAITING_M1_ENGINE`：冻结等待平台 M1 游戏引擎，解冻未获授权（`unfreeze_authorized = false`） |

批次状态：`AIPT-M0-B000` = **MERGED/CLOSED**（合并提交 `777a3f39ba78c1ef3168597890c61abf7a55d962`，树 `f5f845b860ba0944ef104b4679fa074ad6efecbb`，GPT 审计 PASS）；`AIPT-M0-B001` = **MERGED/CLOSED**（候选 `2e904ddc2d4f1313a99e19f6751a991d589f8336`，合并提交 `8bcadc9669e7d04f589f883daa6d4f593875fc9e`，树 `fefc25f1acb523d013c2a7d8db9801ccdab37d2d`，合并后公共 CI run `31951440133` PASS）；`AIPT-M0-B002` = **MERGED/CLOSED**（候选 `9968cbc89c09640e3fc2feb8d851220eae98b9b9`，implementation merge commit `fccfb595c23feab38397506505a3e996fe7b9e9c`，implementation tree `f99570bc3c4307244ca926cec62e82a07ef5aee8`，post-merge CI run `31985644832` success）；`AIPT-M0-B003` = **MERGED/CLOSED**（Candidate `fbe1363acd977759c4effa2687483c0b78b63ab6`，Candidate tree `60bcdd0df2c29391c2564bfeae17013c07723cd3`，Candidate CI run `32334341279` success；implementation merge `725fc005185412d115307b594aa64e84acfabf67`，implementation tree `60bcdd0df2c29391c2564bfeae17013c07723cd3`，post-merge CI run `32336615560` success，Go 1.26.6 security requalification `AIPT-M0-B003-SECURITY-TOOLCHAIN-QUAL-001` PASS）；`AIPT-M0-B004` = **MERGED/CLOSED**（Candidate `4810d2cfec6146db7c161506ba7f37ab0a4ce69c`，Candidate tree `f35365d0ad47fdd513fbecb84a03b1559026637e`，Candidate CI run `32392886647` success；implementation merge `d07c0c3817620ada47b3ae7344d8ee423ace3b12`，implementation tree `f35365d0ad47fdd513fbecb84a03b1559026637e`；初始 post-merge CI run `32557930038` 保持 immutable failure，原因 `AIPT-B004-TREE-INTEGRITY-LIFECYCLE-001`；repair 指令 `AIPT-M0-B004-POSTMERGE-TREE-INTEGRITY-REPAIR-001`，repair commit `bd0c06867da58f89e82a35d82ce1d798c1ec9cae`，repair CI run `32558813381` success，accepted post-merge gate PASS；依赖安全再资格化 `AIPT-M0-B004-DEPENDENCY-SECURITY-REQUAL-001` PASS，`GO-2026-5970` = `RESOLVED_BY_X_TEXT_V0_39_0`）。`AIPT-M0-B000`/`AIPT-M0-B001`/`AIPT-M0-B002`/`AIPT-M0-B003`/`AIPT-M0-B004` 为不可变已关闭历史。外部串行前序 `UNREGISTERED-AIPT-P0-B001` = **MERGED/CLOSED**（closeout 提交 `a37b284bf5ec35895f436abe71d22599edb6da53`，公共 CI run `32194224161` success）。

`AIPT-M0-B005` = **MERGED_CLOSED**：基线 `8005dd3bec8b367a6d97dcd9397158f1d8618f3e`（tree `d0f32b7ac1c3f6e5ddb258aaa2ee030844b1eb2b`）；Approved Candidate `d9e24cbac30a1472c41cc8719848acbbc2426fa5`（tree `c1b0b3e3c5218a46c4f3d9501b52a2618cfe20f5`，Candidate CI `32565305803` success）；implementation merge `8652a92c51b86a3bf66aee725c0f1b7be4c60654`（相同 tree，精确父提交为基线与 Candidate），post-merge CI `32569995492` success；closeout `10d0232bd2e3e42601bbb00cedc753f842e219db`（tree `922115b9a75a7eca8dd97475f3f228bc7d3d2c10`），closeout CI `32571092786` success。`@aipt/harness-adapter` `0.1.0` 的真实子进程 stdio smoke 为 `23/23` PASS，第三方 pnpm 包为 0，未调用远端模型。Harness 升级指令 `AIPT-M0-B005-EXTERNAL-HARNESS-UPGRADE-001` 的 disposition 为 `OWNER_GATE_RATIFIED`：previous `47f943859bef60e4160492346772ded9b24f765a`，current `141eb6fef83422698aef7a981029e843e8161534`，release `dsh-v0.1.0-rc.8`，`prior_authorization_timing_independently_verified = false`。

`AIPT-M0-B006` = **MERGED_CLOSED**：Base `10d0232bd2e3e42601bbb00cedc753f842e219db`（tree `922115b9a75a7eca8dd97475f3f228bc7d3d2c10`）；Approved Candidate `3987b8d4c26ac079d01c214ba90e113eeffd5713`（tree `4271a3fb71236a8b003b4d9ddc84727c6fec8d46`，Candidate CI `32577246851` success）；implementation merge `35acba9fb629f50087def3b720df304fadfd2158`（相同 tree，精确父提交为 Base 与 Candidate，subject `merge: integrate AIPT-M0-B006`），post-merge CI `32578143923` success。已交付 Evidence/Audit Draft 2020-12 Schema、最小原生 `RAW_CAPTURE` exporter/verifier、只读 PostgreSQL 18.4 ledger source、合成 golden 与确定性/篡改门禁；`AUDIT_READY`/`AUDIT_RESULT` generator、签名、加密、分块仍为 `NOT_IMPLEMENTED`。施工 Harness 因输入 `190183 > 180000` 命中 `HARNESS_INPUT_TOKEN_BUDGET`，未产生 patch，最终路由 `CODEX_ONLY`；这是施工遥测，不是 product runtime failure，split-memory 未手工编辑。

`AIPT-M0-B007` = **MERGED_CLOSED**：Base `e1e1a6315ef2308922105dd30fd4bbcf4e3f91c8`（tree `326def92334a43f6d63cd77b40f0eae9af31b375`）；Original Candidate `5f78ca91170521ac2acc6ec6eeef4a20e1fdbf92`（tree `d4cc34e8fcbec8ea4f864f22aa7503cc1dcdffcd`）；repair/final Candidate `561e43f9bc646c43da0b48c8485f820f73941df9`（tree `35a5cc261fef75df8d25102015670bcb1d6fbd92`，Candidate CI `32634972911` success）；implementation merge `e05179a223f9dd0ff1b317e78c0e466e1146f6bb`（相同 tree，父提交为 Base 与 final Candidate，subject `merge: integrate AIPT-M0-B007`），post-merge CI `32636449574` success；closeout `656154ff37f8cff0daff46d6f4b7dfe68254853c`（tree `4781236e62a112132e00c21bd5f5b407d73178ab`）。交付仅绑定 `tcp4 127.0.0.1:0` 动态端口的本地 Web Dashboard：精确 Host、同源 Origin、mutation CSRF 与严格 CSP/安全头均 PASS；Config DTO 不含 DSN/credential，新增第三方 pnpm 依赖为 0。六个只读面板固定为 Config、Health、Queue、Run、Status/Table、Reports；Queue/Run/Status backend、Report UI export 与 `AUDIT_READY`/`AUDIT_RESULT` generator 均明确 `NOT_IMPLEMENTED`，`RAW_CAPTURE` 仅为 `IMPLEMENTED_LIBRARY_ONLY`，且没有新增 queue migration/backend。finding `AIPT-B007-SUPPLY-CHAIN-DOC-CONSISTENCY-001` 已由 repair commit 关闭且无语义代码变更。

`AIPT-M0-B008` = **MERGED_CLOSED**：GPT Hard Gate = `PASS` 且 open findings 为空；final Candidate `e5659082f9a0ec657d5c33cc8063d8a410c335aa`（tree `9ad4341317e977d455e98ced20f3880d9e50c691`，CI `32808838664` success）已由 implementation merge `8927a2779f3f123dabd472623d76d8e910152133`（相同 tree，post-merge CI `32819203218` success）精确集成，并由 `AIPT-M0-B008-CLOSEOUT-001` 完成 closeout。`M0 Development Pass = GRANTED`，其交付是可构建、可验证的工程基础；verified implementation identity 固定为该 B008 implementation merge，而不是 closeout commit。该 closeout 当时留下 `next_serial_batch = NONE` 且不自动授权后续批次；本页下述 MVP B000 状态由新的 Owner Authority 启动。详见 [M0 Development Pass](docs/milestones/M0_DEVELOPMENT_PASS.md)。

`AIPT-MVP-B000` = **MERGED_CLOSED**：Owner Authority `AIPT-MVP-B000-START-001`；精确 Base 为 M0 closeout `c617f3c6ab3e56ac88f228ed4825e751537fc1f0`（tree `95a8d2980c5a6aa44f3db67c66f07ff008ff3491`）。final Candidate `9a4d5e0ad09fbc9c3e13536d02cd131f992836f2`（tree `895ccfc569435c390a1aaeea566167a2d61a4de6`，Candidate CI `32869412683` success）由 implementation merge `1a26e023af1b56c057590a46de2f63c3b4220923` 精确集成，post-merge CI `32907168240` success；finding `AIPT-MVP-B000-POSTMERGE-LIFECYCLE-001` = `CLOSED`。本批次只完成 13 项 MVP 权威串行图、治理/bootstrap 生命周期与 fail-closed CI validator，没有 Run engine、真实模型 runtime 调用、真实桌测或 qualification Run。

`AIPT-MVP-B001` = **MERGED_CLOSED**：Owner-approved Candidate `85ef3489405694cf0764867a97fb21b09fda5894`（tree `44a885569c59c428fb173e0847dc49a8111b526c`，Candidate CI `32932281680` success）已由 implementation merge `ad8e39b23f5888cfb9a7f8f15f9dd996964d8f16`（同一 tree；parents 为精确 Base 与 Candidate）集成，post-merge CI `32939064547` 的 5 个 jobs 全部 success，并由 `AIPT-MVP-B001-CLOSEOUT-001` 关闭。该历史交付仅为版本化声明式 Test Plan、不可变且内容寻址的 Run Manifest，以及 PostgreSQL 18.4 权威串行 Queue/Lease/Attempt 持久层。

外部串行前序 `UNREGISTERED-AIPT-P1-B000` 继续由 accepted merge `fe0965977447caf8cd7b6e58252bc1b991b7cc6f`、post-merge CI `33186880614` success 和 AIPT canonical lifecycle closeout `411bf2997cd0f10ba1a022ac687d27a1bd19eb36` 解析为 **MERGED_CLOSED**。`AIPT-MVP-B002` 现为 **MERGED_CLOSED**：原始 Candidate `d81f201d57e62c9983bac67509513367ef369b64` 的首次 merge `f4ceabe3e3a3e7bea31481bd91681a1b87f27d56` 及 CI `33237860359` 永久保留为失败历史且没有生命周期记录；批准的 R1 Candidate `dd634f575cdec5ec572696409ac574102442af3e`（tree `2b7240f11b1bcf934d34d95a286bdd49dbf021b5`，Candidate CI `33241732672` success）由第二次合法 merge `a5d9e9b0aeea5f2a9990d976258ddd34b9b8375e` 精确集成，post-merge CI `33243508362` 的 5 个 jobs 全部 success，并由 accepted append-only `MERGED → POST_MERGE_VERIFIED → CLOSED` lifecycle chain 关闭。

`AIPT-MVP-B003` 现为 **IN_PROGRESS**：精确 Base `862bd6f0e93f6676355db57388dd3280b006804d`（tree `bdee02d25a89f782ae970ab6ce792d877fa81953`），`GLOBAL_WIP = 1`。本批只施工 provider-neutral Deterministic Agent Orchestrator，包括固定 `1 GM + 4 Player`、Run-bound Sessions、Persona/Character/GM Profile、Visibility/ACL-before-retrieval、Context Bundle/hash、确定性 floor、结构化 action 与有限 retry/recovery；状态变更只经冻结的 B002 Run Core。真实 model gateway、真实/网络模型调用、真实桌测和 qualification Run 均未实现或执行。`AIPT-MVP-B004` 为 `NOT_STARTED / NOT_AUTHORIZED`。

M0 未执行真实 TRPG 桌测，也不是 MVP Development Pass。`production_qualification = NOT_GRANTED`、`release_qualification = NOT_GRANTED`、`mvp_development_pass = NOT_GRANTED`、`human_equivalence = NOT_CLAIMED`、`real_playtest_completion = NOT_CLAIMED`；第二审计者生产门仍未完成，MODEL/HARNESS/IPC 生产 gate 仍未实现。`AIPT-PLATFORM-INTEGRATION` 保持 `FROZEN_WAITING_M1_ENGINE`，后续工作只能由新的 Owner Authority 另行启动。

**B005 Harness Adapter（已关闭）** 是一方薄适配层：复用 `@aipt/adapter-sdk` 的既有 wire truth，以每行一个 UTF-8 JSON-RPC 信封的 stdio 边界连接可注入的 `HarnessBackend`；stdout 只承载协议帧，stderr 只承载脱敏诊断。测试专用 fixture backend 从 B002 权威夹具读取 ACCEPT/REJECT 输出，不在生产源码硬编码游戏字段，也不发起网络或模型调用。详见 [docs/harness/README.md](docs/harness/README.md)。

**B004 Runtime Shell** 已作为关闭交付保存在 accepted implementation merge `d07c0c3817620ada47b3ae7344d8ee423ace3b12`（tree `f35365d0ad47fdd513fbecb84a03b1559026637e`）：Go Launcher 固定执行 `CONFIG → POSTGRESQL → MIGRATIONS → MODEL → HARNESS → CORE → IPC → WEB`，真实路径完成严格配置加载、PostgreSQL Ping 与 B003 `MigrateUp` 后，在未实现的 `MODEL` 门禁以 `AIPT_LAUNCH_GATE_NOT_IMPLEMENTED` 失败关闭，绝不把 launch plan 冒充 runtime ready。B007 已将最终 `WEB` 标为已实现并接入真实安全 Host，但不能绕过更早的 MODEL/HARNESS/IPC 门禁。共享配置、Core lifecycle、逆序有界清理及 B004 依赖安全再资格历史均保持不变。运行与 Web 边界见 [`docs/runtime/README.md`](docs/runtime/README.md)。

**B003 迭代 6a（storage supply docs）**已落地：失败关闭的存储机器门禁 [scripts/ci/validate/storage.mjs](scripts/ci/validate/storage.mjs)（`pnpm run check:storage`，Node 标准库；校验 pgx v5.10.0 闭包、迁移/账本/VerifyStream/集成测试契约，并**动态枚举** `internal/storage/postgres` 下全部非测试 `.go` 源码做大小写/空白容忍的零运行时完整性绕过扫描——非固定白名单；临时夹具经由同一共享源码树检查证明缺失 verify.go 与新增绕过文件均失败）、**pgx v5.10.0 Go 运行时闭包资格**（`go.mod` 直接 `github.com/jackc/pgx/v5 v5.10.0` + 五个间接模块；jackc 四模块 MIT、golang.org/x 两模块 BSD-3-Clause，精确版本/角色/直接性记录于 [tools/supply-chain/licenses.json](tools/supply-chain/licenses.json)，go=6/pnpm=0；冻结的 [tools/supply-chain/policy.json](tools/supply-chain/policy.json) 保持不可变 B001 基线）、B003 供应链门禁与确定性 SPDX 2.3 SBOM 演进（`aipt-m0-b003` 内容寻址 namespace、18 个包身份、Go h1/SHA-256 校验和语义、`AIPT DEPENDS_ON pgx` / `pgx DEPENDS_ON` 五个间接模块的运行时依赖关系——绝不 DEV_TOOL_OF、30 个语义负向探针 + 7 个 go.mod/go.sum 清单负向探针）、在 Owner 指令 `AIPT-M0-B003-SCOPE-EXPANSION-001` 授权下把 [scripts/ci/validate/toolchain-lock.mjs](scripts/ci/validate/toolchain-lock.mjs) 从 B001 时代"go.mod 零第三方 require"引导规则演进为**精确批准闭包的 fail-closed 校验**（六模块精确版本/直接性、replace/exclude/retract 图覆盖拒绝、zip 与 `/go.mod` h1 精确 pin；全部 B001 工具链 pin 与 `selected_by_batch = AIPT-M0-B001` 历史事实原样保留、pnpm 零第三方依赖策略不变）以及存储与供应链文档（[docs/storage/README.md](docs/storage/README.md)、[docs/supply-chain/README.md](docs/supply-chain/README.md)）。该实施已随 `AIPT-M0-B003` 合并并关闭；严格存储、供应链与 scope 门禁继续保留。

**B003 security toolchain requalification**已落地：当前 Go 身份从 B001 初始资格化的 **1.26.5** 重资格为官方稳定版 **1.26.6**（release date 2026-08-13；理由 `reachable standard-library vulnerabilities`；精确触发公告集 **GO-2026-6090**（crypto/tls）、**GO-2026-6088**（encoding/xml）、**GO-2026-5972**（encoding/asn1），每条均已由 1.26.6 官方修复；官方 release index / linux/amd64 归档 `go1.26.6.linux-amd64.tar.gz` 及独立重算的 SHA-256 / upstream tag go1.26.6 提交 / release history / 安全公告全部记录于 [tools/toolchain.lock.json](tools/toolchain.lock.json) 的 provenance，显式区分 **B001 初始资格（Go 1.26.5）** 与 **B003 安全重资格（Go 1.26.6）**，`selected_by_batch` 保持 `AIPT-M0-B001`）。`go` 语言指令仍为 `go 1.26.x`，`toolchain go1.26.6`；pgx v5.10.0 六模块闭包与全部 go.sum pin、Node 24.19.0、pnpm 11.4.0、PostgreSQL 18.4、govulncheck v1.7.0 与全部 action pin 不变；`DEFER-016` 保持 `RESOLVED`（`resolved_by_batch = AIPT-M0-B001`），其记录以受控方式携带当前 Go 1.26.6 与精确安全 provenance，`DEFER-001..015` 与 `decisions.json`/`supersessions.json` 逐字节不变；CI 在 `ubuntu-24.04` 与 `ubuntu-26.04` 上精确校验 `go version go1.26.6 linux/amd64`。该重资格已由 B003 Candidate、implementation merge 与 post-merge CI 接受，且不会改写 B001 历史。

**设计基线保持冻结，B003 只施工 Agent Orchestrator。** M0 B001–B008、AIPT-MVP-B000、AIPT-MVP-B001、AIPT-MVP-B002 与外部 P1 前序均为不可变关闭历史。B003 不实现真实模型 gateway、产品模型调用、真实桌测、qualification Run、运行控制 UI 或审计生成器；`real_model_calls = 0`、`network_model_calls = 0`、`real_playtest_executed = false`。`AIPT-PLATFORM-INTEGRATION` 保持 `FROZEN_WAITING_M1_ENGINE`。

首个真实游戏目标为 **《未登记》UNREGISTERED**（当前就绪等级 `PLAYTESTABLE_DRAFT`）。

## 权威入口（渐进式披露）

- 施工者：从 [docs/authority/README.md](docs/authority/README.md)（Authority Index）开始，再按需进入领域文档与机器登记。
- 项目现状与下一步：[docs/authority/PROJECT_STATUS.md](docs/authority/PROJECT_STATUS.md)
- MVP 机器批次权威：[docs/authority/registry/batch-graph.json](docs/authority/registry/batch-graph.json)（13 项固定串行图）
- 里程碑合同：[docs/milestones/M0.md](docs/milestones/M0.md)、[M0 Development Pass](docs/milestones/M0_DEVELOPMENT_PASS.md) 与 [docs/milestones/MVP.md](docs/milestones/MVP.md)
- 机器决策权威：[docs/authority/registry/decisions.json](docs/authority/registry/decisions.json)（共 454 条决策 ID）
- 协议契约（B002）：[docs/protocol/README.md](docs/protocol/README.md) → 权威根 [schemas/protocol/v1/aipt-protocol.schema.json](schemas/protocol/v1/aipt-protocol.schema.json) 与最小确定性夹具 [testdata/protocol/v1/minimal-fixture/manifest.json](testdata/protocol/v1/minimal-fixture/manifest.json)
- Adapter SDK（B002 迭代 4）：一方 TypeScript 契约 SDK [packages/adapter-sdk/README.md](packages/adapter-sdk/README.md)（`@aipt/adapter-sdk@1.0.0`，零依赖，Node 24 原生 TS；机器门禁 `pnpm run check:adapter-sdk`，测试 `pnpm --filter @aipt/adapter-sdk test`）
- Go 协议契约消费者（B002 迭代 5/5B）：[internal/protocol](internal/protocol)（仅 Go 标准库，零依赖；严格 JSON-RPC 2.0 信封解码、确定性 canonical JSON/SHA-256 与 Node 预言机逐字节一致（含孤立 UTF-16 代理）、投影/可见性语义、共享夹具兼容与 schema 漂移测试；运行 `pnpm run test:protocol-go`，即 `go test ./internal/protocol -count=1`）
- Harness Adapter（B005，已关闭）：[packages/harness-adapter/README.md](packages/harness-adapter/README.md)（`@aipt/harness-adapter@0.1.0`，仅依赖一方 `@aipt/adapter-sdk`；受控 stdio、可注入 backend、真实子进程 smoke；机器门禁 `pnpm run check:harness-adapter`，测试 `pnpm run test:harness-adapter`）
- Agent Orchestrator（MVP-B003）：[internal/orchestrator](internal/orchestrator) 与 [schemas/orchestration/v1](schemas/orchestration/v1)；运行 `pnpm run check:mvp-b003`、`pnpm run test:orchestrator`、`go test -race ./internal/orchestrator -count=1`。仅使用可注入 synthetic Agent/Retriever/Clock，不含 provider 或网络实现。
- 公共 CI：[.github/workflows/ci.yml](.github/workflows/ci.yml) 保持耐久名称 `AIPT M0 CI`，在 `ubuntu-24.04` 与 `ubuntu-26.04` 两个 toolchain matrix 实例运行 B002 冻结回归和 B003 Agent Orchestrator validator/unit/race 门禁；独立 PostgreSQL job继续使用 loopback-only 18.4 临时容器执行 Run Core 全量与 race 集成。`pnpm run check` 报告 schema 为 `aipt.public.mvp-b003-validator-run/v1`。
- 存储（B003 + MVP-B001 + MVP-B002）：[docs/storage/README.md](docs/storage/README.md)（历史 `000001_ledger.sql` / `000002_playtest_queue.sql` 字节冻结；B002 复用 ledger 并在同一行锁事务中加入 `ExpectedSequence` 前置条件，不新增迁移；PostgreSQL 18.4 全量与 race 集成门禁）
- Evidence/Audit（B006，已关闭）：[docs/evidence/README.md](docs/evidence/README.md) → 公开三阶段 Schema [aipt-evidence.schema.json](schemas/evidence/v1/aipt-evidence.schema.json) 与最小原生 Go [`RAW_CAPTURE` exporter/verifier](internal/evidence)；只读复用 B003 `VerifyStream`，canonical JSON 复用 B002 `internal/protocol.CanonicalJSON`，合成 golden 位于 [testdata/evidence/v1](testdata/evidence/v1)。`AUDIT_READY`/`AUDIT_RESULT` generator、签名、加密与分块均未实现。
- Web（B007，已关闭）：[docs/runtime/README.md](docs/runtime/README.md) → Go Host [`internal/web`](internal/web)、公开 DTO Schema [aipt-web.schema.json](schemas/web/v1/aipt-web.schema.json) 与零依赖 TypeScript [`@aipt/web-ui`](packages/web-ui)。机器门禁 `pnpm run check:web-ui`，UI/Go/smoke 分别运行 `pnpm run test:web-ui`、`pnpm run test:web-go`、`pnpm run smoke:web-ui`。
- 工具链与供应链：[docs/supply-chain/README.md](docs/supply-chain/README.md) 与 [tools/toolchain.lock.json](tools/toolchain.lock.json)（冻结许可证清单仍为 21 个历史/当前记录；B007 Web UI 由不可变 AIPT/root MIT 记录覆盖，确定性 B007 SBOM 明确加入后共 22 个 package identity；第三方闭包仍为 go=6/pnpm=0，Go 1.26.6 与冻结 `policy.json` 均不变）

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
