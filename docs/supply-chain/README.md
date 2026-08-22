# 供应链基础（SUPPLY CHAIN FOUNDATION）

> B001 依据 `R4-Q023`（固定版本、锁文件、SBOM、许可证、漏洞、来源、升级资格的完整供应链门禁）建立的公共工程基础。
> 机器规则为 [../../tools/supply-chain/policy.json](../../tools/supply-chain/policy.json)；本页是可读解释。
> **AIPT-M0-B004 安全再资格化已随批次 `MERGED_CLOSED`**：B003 原始选择（pgx v5.10.0、x/sync v0.17.0、x/text v0.29.0）和 Go 1.26.6 security requalification 是不可变历史。`AIPT-M0-B004-DEPENDENCY-SECURITY-REQUAL-001` 因可达漏洞 GO-2026-5970 将当前 x/text 精确提升到 v0.39.0，结论 `RESOLVED_BY_X_TEXT_V0_39_0`；MVS 当前选择 x/sync v0.21.0、x/mod v0.37.0、x/tools v0.47.0，pgx 仍冻结为 v5.10.0。B004 runtime shell 没有新增业务依赖，当前运行时清单仍为 go=6/pnpm=0，并另记录两个只参与 selected module graph 的 tooling identity。repair CI run `32558813381` 的 fresh govulncheck 为 PASS、reachable vulnerabilities = 0；冻结的 `policy.json` 仍是不可变 B001 基线。

> **AIPT-M0-B005 已 `MERGED_CLOSED`**：Approved Candidate `d9e24cbac30a1472c41cc8719848acbbc2426fa5`（tree `c1b0b3e3c5218a46c4f3d9501b52a2618cfe20f5`，CI `32565305803` success）经 implementation merge `8652a92c51b86a3bf66aee725c0f1b7be4c60654` 合入，post-merge CI `32569995492` success。交付的 MIT 一方包 `@aipt/harness-adapter@0.1.0` 只有一个 `@aipt/adapter-sdk: workspace:*` 依赖，锁文件精确解析为 `link:../adapter-sdk`；没有 npm registry package，pnpm 第三方运行时计数仍为 0。许可证清单与 SBOM 各增加一个一方身份；SBOM 必须同时表示 `SPDXRef-harness-adapter PACKAGE_OF SPDXRef-AIPT` 与 `SPDXRef-harness-adapter DEPENDS_ON SPDXRef-adapter-sdk`，绝不表示为 `DEV_TOOL_OF`。

## 冻结工具链（`DEFER-016` 已 RESOLVED）

| 工具 | 精确版本 | 频道 | 官方来源 |
|---|---|---|---|
| Go | **1.26.6**（B003 安全重资格；历史 B001 初始资格为 1.26.5） | stable | go.dev |
| Node.js | **24.19.0** | LTS（Krypton） | nodejs.org |
| pnpm | **11.4.0** | stable | pnpm/pnpm release + npm registry |
| PostgreSQL | **18.4** | stable | postgresql.org + Docker Official Image |

完整资格（来源身份、发行/完整性材料、验证时间、linux/amd64 校验和、PostgreSQL 多架构与 linux/amd64 平台 digest、CI 期望版本输出）见 [../../tools/toolchain.lock.json](../../tools/toolchain.lock.json)。Go 的 `provenance` 显式区分 **B001 初始资格（Go 1.26.5）** 与 **B003 安全重资格（Go 1.26.6）**：官方稳定版 go1.26.6（2026-08-13）、官方 release index、linux/amd64 归档 `go1.26.6.linux-amd64.tar.gz` 及其 SHA-256、官方 upstream tag go1.26.6 提交、官方 release history 与安全公告；触发公告集 GO-2026-6090（crypto/tls）、GO-2026-6088（encoding/xml）、GO-2026-5972（encoding/asn1）每条均已由 1.26.6 官方修复；`selected_by_batch` 保持不可变历史 `AIPT-M0-B001`。

规则：**禁止静默升级/降级**。任何版本变更必须重新资格化并进入新的变更批次。

## 公共 CI（`.github/workflows/ci.yml`）

- `permissions: contents: read`，**零** `secrets.*` 引用，**零** API Key，**零**远端模型调用。
- 所有第三方 Action `uses:` 必须是**完整 40 hex Commit SHA**（tag 只作为行尾可读注释）；映射登记在 [../../tools/ci-actions.lock.json](../../tools/ci-actions.lock.json)。
- 容器镜像必须 **digest pin**（PostgreSQL 以多架构 digest 拉取）。
- runner：`ubuntu-26.04`（参考环境）与 `ubuntu-24.04`（GA）；runner 镜像版本/OS 信息写入 CI 日志。
- 五个实际 required jobs（以下四类，其中 `toolchain` matrix 展开为两个 job）：
  - `b000-retro`：用 B001 验证器对固定历史提交 `777a3f39ba78c1ef3168597890c61abf7a55d962` 做只读展开并追溯验证 B000（MIT 许可、454 条决策、35 条 supersession、16 项延期参数以 B000 自身状态为准、17 篇 Markdown 相对链接、JSON 解析、无凭据/私有路径/Prompt 正文、merge tree == `f5f845b860ba0944ef104b4679fa074ad6efecbb`）。
  - `toolchain`：在 `ubuntu-24.04` 与 `ubuntu-26.04` 上验证精确 Go/Node/pnpm、`gofmt`、`go vet`、`go test`、`pnpm install --frozen-lockfile`、B001–B005 聚合验证器、focused `check:runtime-shell`、`check:harness-adapter` 与 `test:harness-adapter`，并执行 PostgreSQL Official Image digest pull/run（`postgres --version` 精确 18.4）。
  - `supply-chain`：锁文件存在性与完整性、Action SHA pin、容器 digest pin、依赖清单/许可证覆盖（三层 PostgreSQL 许可模型机器校验 + 负向回归）、确定性 + SPDX 2.3/组件语义 SBOM 校验（生成两次 byte-identical 并输出 SHA-256；三层许可模型、组合关系（镜像 `CONTAINS` 主软件 / `GENERATED_FROM` 打包源）、精确 digest 语义校验与全部负向探针必须通过）、Go 漏洞扫描、`pnpm audit`、来源溯源元数据、无秘密/无真实模型网络配置扫描。
  - `storage-postgres`：使用 digest-pinned、loopback-only PostgreSQL 18.4 临时容器，硬启用 B003 storage 与 B004 Launcher 的完整集成和适用 race 测试；不触碰生产数据库。
- 全部 required jobs PASS 是 Candidate、implementation merge 与 closeout 的硬门禁；不自动 deploy/publish。

## 许可证清单

[../../tools/supply-chain/licenses.json](../../tools/supply-chain/licenses.json) 覆盖：AIPT 本体（MIT）、**B002 一方工作区包 `@aipt/adapter-sdk`**（MIT，1.0.0，真实 B002 元数据）、**B005 一方工作区包 `@aipt/harness-adapter`**（MIT，0.1.0，真实 B005 元数据与唯一 SDK workspace edge）、CI Actions、工具链、供应链工具，以及 **三层 PostgreSQL 许可模型**（R6）：

| 身份 | 层 | 机器 `license` 值 |
|---|---|---|
| `postgresql` | PostgreSQL 18.4 主软件（postgresql.org） | SPDX 短标识符 **`PostgreSQL`**（人类可读全名 PostgreSQL License 只允许出现在 evidence 文本） |
| `docker-library/postgres` | Docker Official Image 的打包源 | **`MIT`** |
| `postgresql-docker-official-image` | 复合容器镜像（多来源/多组件） | **`NOASSERTION`**——整个镜像不得再断言 PostgreSQL 或 MIT；该记录同时精确固定 `image_multi_arch_digest` 与 `linux_amd64_platform_digest` |

验证器对当前 **21 条**清单记录逐一校验期望的 SPDX 许可值与精确 kind：一方集合恰为 {`AIPT`, `@aipt/adapter-sdk`, `@aipt/harness-adapter`}（均为 `first_party`/MIT），B001 批准的精确工具/CI/基础设施集合原样保留，六个第三方 Go 运行时模块保持 kind `third_party_go_runtime`、role `runtime_dependency`；其中 `selected_by_batch = AIPT-M0-B003` 保留最初引入历史，B004 的版本/漏洞再资格化由独立的封闭 provenance 对象记录：

| 模块 | 版本 | 直接性 | 机器 `license` |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | v5.10.0 | **direct**（go.mod 直接 require） | **`MIT`** |
| `github.com/jackc/pgpassfile` | v1.0.0 | indirect | **`MIT`** |
| `github.com/jackc/pgservicefile` | v0.0.0-20240606120523-5a60cdf6a761 | indirect | **`MIT`** |
| `github.com/jackc/puddle/v2` | v2.2.2 | indirect | **`MIT`** |
| `golang.org/x/sync` | v0.21.0（B003 原始 v0.17.0） | indirect | **`BSD-3-Clause`** |
| `golang.org/x/text` | v0.39.0（B003 原始 v0.29.0） | indirect | **`BSD-3-Clause`** |

Go 1.26.6 的实际 selected module graph 还包含以下两个非运行时 tooling identity；它们由 x/text v0.39.0 的模块图确定性带入，不写入 AIPT 的六模块 runtime require 闭包：

| 模块 | 当前版本 | 先前选择 | 角色 | 机器 `license` |
|---|---|---|---|---|
| `golang.org/x/mod` | v0.37.0 | v0.27.0 | `module_graph_tooling` | **`BSD-3-Clause`** |
| `golang.org/x/tools` | v0.47.0 | v0.36.0 | `module_graph_tooling` | **`BSD-3-Clause`** |

### B004 dependency security requalification

- 指令：`AIPT-M0-B004-DEPENDENCY-SECURITY-REQUAL-001`；公告：`GO-2026-5970` / `CVE-2026-56852`；官方 fixed event：`0.39.0`。
- `golang.org/x/text` 精确选择 v0.39.0：官方 tag commit `b326f3d3c814ab79b3c516f4ac03c2314d8df65f`，其 release history 包含 fix commit `5ae8e578e495731553eddba11b2d0e86c91a00ce`；module / go.mod sumdb h1 分别为 `h1:UbZz4pLOvn600D6Oh6GGEI6VAmndrEBLv8/6BEXzyus=` 与 `h1:3UwRclnC2g0TU9x8PZiyfOajCd1zaUNHF9cvqcQZ+ZM=`。
- x/text v0.39.0 的 raw module zip / go.mod SHA-256 分别为 `cbfa33111dfa6cbafef63103b82c544d35df425824ac94ea19629a12bdbf0523` 与 `40e9425e17dcc56faf496619fde6908631d57b2cce0f766c4dca6bea8fc93838`；LICENSE SHA-256 为 `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad`，SPDX 为 `BSD-3-Clause`。
- MVS 的精确变化为 x/sync v0.17.0→v0.21.0、x/mod v0.27.0→v0.37.0、x/tools v0.36.0→v0.47.0；没有新 module identity。每项的 official tag/commit、sumdb h1、raw SHA-256 与许可证哈希均锁定在 `licenses.json`。
- 2026-08-20T16:16:58Z 的 fresh `vuln.go.dev/index/modules.json`（snapshot SHA-256 `8b4159bf3e73d78c9246c49a6ccf576a27bb2f3871a4cf0046d94d128e068dca`）对 x/sync 与 x/tools 无 module advisory；x/text 的四条历史公告均在 v0.39.0 或更早修复。索引对 x/mod v0.37.0 列出 GO-2026-6179/6180（module 首修 v0.40.0），但 `go list -deps -test ./...` 零 x/mod/x/tools package，`go mod why -m` 也确认主模块不需要它们；实际执行 sumdb 的冻结 Go 1.26.6 `cmd/go` 已由两条公告修复。因此 x/mod 保持 x/text v0.39.0 的确定性 graph-only MVS 结果，不被伪报为无公告，也不构成可达漏洞 waiver。任何未来 package-graph 导入都会由机器门禁拒绝并重新触发资格化。
- x/text v0.39.0 声明 `go 1.25.0`，与冻结的 Go 1.26.6 兼容；`github.com/jackc/pgx/v5` 保持 v5.10.0，不使用 pgx 升级规避漏洞。

**精确集合模型**：当前记录集合必须恰为 21 个 identity（B004 的 20 个身份 + B005 Harness Adapter 一方身份）；任何未登记第三方身份一律拒绝。SDK 记录携带真实 B002 元数据，Harness Adapter 记录携带真实 B005 元数据，六个运行时记录保留真实 B003 选择历史，B004 requalification 保留精确 provenance；licenses.json 文件顶层 `selected_by_batch` 继续锁定不可变历史 `AIPT-M0-B001`。

**一方 pnpm 工作区模型（B005）**：`pnpm-workspace.yaml` 声明 `packages/*`，`pnpm-lock.yaml` 的 importer 集合**恰为** `.`、`packages/adapter-sdk` 与 `packages/harness-adapter`；根与 SDK importer 为 `{}`，Harness Adapter importer 恰含 `@aipt/adapter-sdk` 的 `workspace:* → link:../adapter-sdk`，`packages:` 区不存在（零第三方包）。负向探针独立拒绝 SDK edge 删除、registry 版本替换、未登记 importer 和第三方 `packages:` 注入。

**Go 运行时闭包交叉校验（B003 迭代 6a）**：`go.mod` 的 require 集合必须**恰为**上述六个模块（精确版本、精确直接/间接标记——pgx 直接、其余五个 indirect；任何未知依赖/版本漂移/直接性翻转一律 FAIL；解析是**失败关闭的行状态扫描器**——绝非对块体的正则抽取：解析覆盖**每一个**合法 `require (...)` 块并接受 Go 允许的可选行首水平空白，但只有代码部分（`//` 注释之前、trim 之后）**恰为 `)`** 的行才能关闭块，`//` 注释里的括号永远不能关闭块（`// )` 之后夹带的第七个依赖同样被计数并拒绝）；任何带任意尾随 `//` 注释的合法 require 项都被解析（先剥离注释再解析模块/版本，间接性由 Go `// indirect` 标记判定，单行 require 不重复计数）；任何无法解析的顶层 require 指令或块内非注释行都是**解析错误并使门禁 FAIL**（绝不静默丢行）），且**绝不允许任何 `replace`/`exclude`/`retract` 依赖图覆盖指令**（图覆盖会把批准闭包重路由/隐藏，一律 FAIL；单行与块两种形式、含可选行首空白均被检出）；`go.sum` 必须为每个模块同时携带 **zip `h1:` 与 `/go.mod h1:`**，且**两个** base64 载荷都必须解码为 32 字节、其小写 hex **等于冻结的 h1 SHA-256 值**（被篡改但仍是合法 base64 的 h1 也会被拒）。**13 个 go.mod/go.sum 内存变异负向探针**（注入未知依赖、pgx 版本漂移、删除 pgx 直接 require、直接性翻转、删除 pgx zip h1、删除 pgx /go.mod h1、篡改 pgx h1、注入 replace 图覆盖、**第二个 require 块夹带第七个依赖**、**`// )` 注释括号行之后的第二个 require 块夹带第七个依赖**、**带普通尾随注释的 rogue 单行 require**、**带行首空白的 replace 图覆盖**、篡改 pgx /go.mod h1）全部必须按自身原因被拒。`tools/toolchain.lock.json` 的基线/digest 另有 **3 个负向探针**（顶层 `selected_by_batch` 漂移到 B003、multi-arch digest 漂移、**linux/amd64 platform digest 漂移——精确等值校验，绝非仅格式校验**），且锁检查失败后**绝不输出无条件成功**。**`policy.json` 保持不可变 B001 基线**：`selected_by_batch = AIPT-M0-B001`、规则集冻结、`current_third_party_application_runtime_dependencies = 0` 是 B001 时代的历史事实，**从不被改写**；当前运行时依赖数只记录在 `licenses.json` 的 `application_dependencies`（go=6/pnpm=0）。

B001/B002 的第三方应用运行时依赖为 0；B003 引入 go=**6** 的 pgx v5.10.0 闭包且 pnpm=**0**；B004 不增加该集合。**B005 只增加一方 workspace 包与一方 link，第三方计数仍为 go=6/pnpm=0**。任何未来第三方依赖必须先进入清单并获得显式批准，否则 CI 门禁 FAIL。

## 确定性 SBOM

**B005 当前身份**：生成器输出 `AIPT-M0-B005-supply-chain-sbom`，AIPT 根版本为 `M0-B005`，确定性 `created` 为 `2026-08-22T00:00:00Z`，内容寻址 namespace 为 `https://github.com/zyc14588/AIPT/spdx/aipt-m0-b005/<hash>`。包集合精确为 21 个：B004 的 20 个身份全部保留，再加入 `@aipt/harness-adapter@0.1.0`；新增关系仅为其 `PACKAGE_OF AIPT` 与 `DEPENDS_ON adapter-sdk`，绝不 `DEV_TOOL_OF`。

仓库自带无第三方依赖的 Node 标准库脚本 [../../scripts/ci/sbom/generate-sbom.mjs](../../scripts/ci/sbom/generate-sbom.mjs) 生成**确定性 SPDX 2.3 JSON**，覆盖：AIPT 根包、**一方工作区包 `@aipt/adapter-sdk`**（自有 SPDX 2.3 包：MIT declared/concluded、versionInfo `1.0.0`、npm purl `pkg:npm/%40aipt/adapter-sdk@1.0.0`、`PACKAGE_OF AIPT` 一方关系——**绝不**建模为 `DEV_TOOL_OF`）、**B003 迭代 6a 的六个第三方 Go 运行时模块**（精确已知 SPDX 许可——jackc 四模块 `MIT`、golang.org/x 两模块 `BSD-3-Clause`，**绝不 NOASSERTION**；golang purl；SHA-256 `checksumValue` 为 go.sum zip `h1:` base64 载荷解码出的 64 位小写 hex——Go dirhash H1 本身是 32 字节 SHA-256 摘要，SPDX 2.3 要求解码后的小写 hex 而非 base64 字符串）、CI Actions 固定 Commit、供应链临时扫描器/工具身份、工具链版本，以及 **PostgreSQL 三层许可模型与镜像 digest**：`PostgreSQL`（18.4 主软件，`PostgreSQL`）、`docker-library/postgres`（打包源，`MIT`）、`PostgreSQL Docker Official Image`（复合镜像，两个许可字段均为 `NOASSERTION`），组合关系为**精确三层来源模型**：镜像 `CONTAINS` 主软件（容器内真实组件）、镜像 `GENERATED_FROM` 打包源（打包源代码是镜像的构建输入而非镜像内容——镜像从不 CONTAINS 打包源）。**运行时依赖关系模型（B003 迭代 6a）**：`SPDXRef-AIPT DEPENDS_ON` pgx（唯一直接模块），pgx `DEPENDS_ON` 其余五个间接模块——六个运行时模块**绝不**建模为 `DEV_TOOL_OF`；其余工具/CI/基础设施包仍是 `DEV_TOOL_OF AIPT`。所有校验和按 SPDX 2.3 规范输出：算法大写标识 + **小写十六进制** `checksumValue`（SHA256=64 位、SHA512=128 位）；pnpm 的 SHA512 由锁定 SRI base64 载荷解码为 128 位小写 hex，**不带** `sha512-` 前缀。生成器在构建时对 go.mod/go.sum 做 fail-closed 交叉校验：require 集合必须恰为六个批准模块、h1 必须存在且可解码，任何漂移直接中止生成。

**以下为 B003 的不可变历史基线，不描述当前 B004 包集合或 namespace。** 当时同一输入生成两次必须 **byte-identical**（确定性，CI 强制验证并输出 SHA-256），CI 对 SBOM 执行 **SPDX 2.3 语义/组件校验**（[../../scripts/ci/validate/sbom.mjs](../../scripts/ci/validate/sbom.mjs)）：`spdxVersion == SPDX-2.3`、`dataLicense == CC0-1.0`、**版本唯一的内容寻址 documentNamespace**（对去除 `documentNamespace` 后的版本定义载荷做规范序列化——递归键排序——并取 SHA-256 64 位小写 hex 作为 `https://github.com/zyc14588/AIPT/spdx/aipt-m0-b003/<hash>` 的后缀；验证器独立重算并要求完全相等；R3/R4 复用过的旧静态 B001 namespace `https://github.com/zyc14588/AIPT/spdx/aipt-m0-b001` 被显式拒绝）、包 SPDXID 唯一且格式合法、必需包集合齐全（**11 个 B001 包身份全部保留**：AIPT、Go toolchain、Node.js、pnpm、PostgreSQL、docker-library/postgres、PostgreSQL Docker Official Image、govulncheck、actions/checkout、actions/setup-go、actions/setup-node；迭代 4 新增一方 `@aipt/adapter-sdk`；**B003 迭代 6a 新增六个批准 Go 运行时模块**：github.com/jackc/pgx/v5、github.com/jackc/pgpassfile、github.com/jackc/pgservicefile、github.com/jackc/puddle/v2、golang.org/x/sync、golang.org/x/text——共 **18 个包**，无包可超出该批准集合）、**每个 B003 当时包的 `licenseConcluded`/`licenseDeclared` 与期望 SPDX 许可值精确一致（三层模型：主软件必须为 `PostgreSQL`，全名 PostgreSQL License 会被拒绝；打包源必须为 `MIT`；复合镜像两者必须都是 `NOASSERTION`，断言 PostgreSQL 或 MIT 都会被拒绝；`@aipt/adapter-sdk` 必须为 `MIT`；六个 Go 运行时模块必须为精确已知许可 `MIT`/`BSD-3-Clause`，**绝不 NOASSERTION**）**、**复合镜像 `CONTAINS` 主软件与 `GENERATED_FROM` 打包源两条组合关系必须精确存在（打包源代码是构建输入而非镜像内容，把打包源建模为镜像内容的 CONTAINS 会被拒绝）**、**SDK 包版本 1.0.0、npm purl 精确一致、`SPDXRef-adapter-sdk PACKAGE_OF SPDXRef-AIPT` 一方关系必须存在且绝不出现 `DEV_TOOL_OF`**、**六个 Go 运行时模块包各自必须携带精确版本、golang purl `pkg:golang/<module>@<version>`、SHA-256 `checksumValue` 等于 go.sum zip h1 解码出的冻结小写 hex、以及 comment 中真实 direct/transitive 角色（绝不 DEV_TOOL_OF）**、**依赖关系图：`SPDXRef-AIPT DEPENDS_ON` pgx 且 pgx `DEPENDS_ON` 其余五个间接模块必须全部精确存在；运行时模块绝不出现 `DEV_TOOL_OF` 关系**、工具链/Action 版本与锁文件一致、关系源/目标 SPDXID 可解析且关系类型合法于 SPDX 2.3、校验和为算法长度匹配的小写 hex、pnpm SHA512 hex 从精确锁定的 SRI 载荷解码、**镜像 `versionInfo`、`purl`、`comment` 三处必须完整携带精确 multi-arch digest `sha256:a02db8cac496f15b094798a38254f14d6e00741f709360e5e00bb6668ea31636`，`comment` 还必须携带精确 linux/amd64 platform digest**、go.mod/go.sum 闭包（require 恰为六个批准模块、版本/直接性精确、replace/exclude/retract 图覆盖拒绝、zip 与 `/go.mod` h1 精确 pin）、B003 第三方应用依赖数 go=6/pnpm=0；另含**三十个负向探针**，语义校验器必须全部 FAIL：(1) pnpm SHA512 校验和替换为 SRI/base64 形式；(2) 主软件许可字段替换为全名 `PostgreSQL License`；(3) 修改版本定义字段（如包 comment）但保留原 namespace——namespace 不再匹配文档版本；(4) 显式复用旧静态 namespace；(5) 复合镜像错标 `PostgreSQL`；(6) 复合镜像错标 `MIT`；(7) 主软件改离 `PostgreSQL`；(8) 打包源改离 `MIT`；(9) 从 versionInfo/purl/comment 删除 multi-arch digest；(10) 修改 versionInfo/purl/comment 中的 multi-arch digest；(11) 删除镜像 `CONTAINS` 主软件组合关系；(12) 改错镜像 `CONTAINS` 主软件组合关系；(13) 删除镜像 `GENERATED_FROM` 打包源组合关系；(14) 改错镜像 `GENERATED_FROM` 打包源组合关系——关系探针（11–14）的拒绝必须来自 **composition relationship** 校验本身，而非仅 namespace 失配；迭代 4 新增：(15) 删除 SDK 包；(16) SDK 包错许可；(17) SDK npm purl 删除/漂移；(18) 删除 SDK `PACKAGE_OF` 关系；(19) SDK `PACKAGE_OF` 改错为 `DEV_TOOL_OF`——SDK 探针（15–19）的拒绝必须来自**一方包模型校验**本身，而非仅 namespace 失配；**B003 迭代 6a 新增十一个 Go 依赖探针**：(20) 删除 pgx Go 运行时模块包；(21) pgx 版本漂移；(22) pgx 许可漂移；(23) pgx 校验和漂移；(24) pgx purl 漂移；(25) 删除 `AIPT DEPENDS_ON pgx` 关系；(26) 把 `AIPT DEPENDS_ON pgx` 改错为 `DEV_TOOL_OF`；(27) 删除 `pgx DEPENDS_ON` 某个间接模块关系；(28) pgx comment 直接/传递角色改错；(29) 传递模块被错标为直接；(30) **pgx comment 直接角色改错为 `indirect`（结构化角色 token 回归）**——Go 探针（20–30）的拒绝必须来自**运行时模块包/依赖关系图校验**本身，而非仅 namespace 失配；SBOM 校验器另对 go.mod/go.sum 闭包清单运行 **7 个内存变异负向探针**（注入 `replace` 图覆盖、**第二个 require 块夹带第七个依赖**、**`// )` 注释括号行之后的第二个 require 块夹带第七个依赖**、**带普通尾随注释的 rogue 单行 require**、**带行首空白的 replace 图覆盖**、删除 pgx `/go.mod` h1、篡改 pgx `/go.mod` h1），全部必须被独立清单检查（replace/exclude/retract 拒绝 + 失败关闭的逐行解析 + zip 与 `/go.mod` h1 精确 pin）拒绝，磁盘 go.mod/go.sum 从不被改写。B003 不把 SBOM 产物 commit 进仓库；动态来源溯源由 [../../scripts/ci/provenance.mjs](../../scripts/ci/provenance.mjs) 在 CI 中生成（仓库、commit、workflow run、runner 环境、SBOM SHA-256、工具链版本）。

## 漏洞扫描

- Go：官方漏洞工具 `govulncheck`，**精确版本固定在** [../../tools/toolchain.lock.json](../../tools/toolchain.lock.json) 的 tooling 区（`golang.org/x/vuln v1.7.0`）。门禁 = 代码实际导入/调用的包零可达漏洞。
- Node：`pnpm audit`（pnpm 11.4.0）。
- **advisory 数据库数据不 pin**：扫描器/公告数据随时间更新，未来公告使 CI 失败是**安全门禁**，不得通过固定旧数据库绕过。

## 无秘密与无真实模型网络配置

- CI workflow 不引用 `secrets.*`、不请求 OIDC token、不携带任何 API Key。
- 仓库公共文件不含凭据、本机私有绝对路径、模型端点或 Prompt 正文。B001 验证器实际扫描的文本/脚本后缀为 `.md` `.json` `.yaml` `.yml` `.txt` `.go` `.mjs` `.js` `.ts` `.sh`（跳过 `.git`、`node_modules`、`.b001-toolcache` 目录）；`scripts/ci/` 可执行脚本**不做整目录豁免**——扫描器自身的危险字面量全部由片段拼装，因此可以安全自扫描。机器回归含临时目录负向探针：在临时 `scripts/ci/probe.mjs` 中运行时拼装禁用模型端点，必须被检出，否则门禁 FAIL（防止 `.mjs` 支持或脚本树覆盖被移除）。

## 相邻文档

- [../authority/README.md](../authority/README.md)（Authority Index） · [../authority/DECISION_MATRIX.md](../authority/DECISION_MATRIX.md) · [../authority/DEFERRED_PARAMETERS.md](../authority/DEFERRED_PARAMETERS.md) · [../authority/PROJECT_STATUS.md](../authority/PROJECT_STATUS.md)
- [返回仓库首页](../../README.md)
