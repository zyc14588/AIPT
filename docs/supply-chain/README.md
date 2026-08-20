# 供应链基础（SUPPLY CHAIN FOUNDATION）

> B001 依据 `R4-Q023`（固定版本、锁文件、SBOM、许可证、漏洞、来源、升级资格的完整供应链门禁）建立的公共工程基础。
> 机器规则为 [../../tools/supply-chain/policy.json](../../tools/supply-chain/policy.json)；本页是可读解释。
> **AIPT-M0-B003 施工中（迭代 6a + security requalification）**：本页同时如实记录 B003 对 pgx v5.10.0 Go 运行时闭包的资格、许可证记录、SBOM 依赖关系建模，以及 B003 将当前 Go 身份从 B001 资格化的 **1.26.5** 安全重资格为 **1.26.6**（reason: reachable standard-library vulnerabilities，触发公告 GO-2026-6090 / GO-2026-6088 / GO-2026-5972）；**B003 尚未合并/关闭**——本页不是关闭声明。冻结的 `policy.json` 仍是不可变 B001 基线，从不被 B003 改写。

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
- 三个 required jobs：
  - `b000-retro`：用 B001 验证器对固定历史提交 `777a3f39ba78c1ef3168597890c61abf7a55d962` 做只读展开并追溯验证 B000（MIT 许可、454 条决策、35 条 supersession、16 项延期参数以 B000 自身状态为准、17 篇 Markdown 相对链接、JSON 解析、无凭据/私有路径/Prompt 正文、merge tree == `f5f845b860ba0944ef104b4679fa074ad6efecbb`）。
  - `toolchain`：在 `ubuntu-24.04` 与 `ubuntu-26.04` 上验证精确 Go/Node/pnpm、`gofmt`、`go vet`、`go test`、`pnpm install --frozen-lockfile`、B001 Node 验证器、PostgreSQL Official Image digest pull/run（`postgres --version` 精确 18.4）。
  - `supply-chain`：锁文件存在性与完整性、Action SHA pin、容器 digest pin、依赖清单/许可证覆盖（三层 PostgreSQL 许可模型机器校验 + 负向回归）、确定性 + SPDX 2.3/组件语义 SBOM 校验（生成两次 byte-identical 并输出 SHA-256；三层许可模型、组合关系（镜像 `CONTAINS` 主软件 / `GENERATED_FROM` 打包源）、精确 digest 语义校验与全部负向探针必须通过）、Go 漏洞扫描、`pnpm audit`、来源溯源元数据、无秘密/无真实模型网络配置扫描。
- 全部 required jobs PASS 是 B001 候选进入验收的前提；不自动 deploy/publish。

## 许可证清单

[../../tools/supply-chain/licenses.json](../../tools/supply-chain/licenses.json) 覆盖：AIPT 本体（MIT）、**B002 迭代 4 的一方工作区包 `@aipt/adapter-sdk`**（MIT，1.0.0，独立 B002 记录——`selected_by_batch = AIPT-M0-B002` 与 B002 `verified_at`，证据指向 `packages/adapter-sdk` 与根 LICENSE，**绝不冒充 B001 验证**）、CI Actions（MIT，在 pin commit 处验证）、工具链（Go BSD-3-Clause、Node MIT、pnpm MIT）、供应链工具（govulncheck BSD-3-Clause），以及 **三层 PostgreSQL 许可模型**（R6）：

| 身份 | 层 | 机器 `license` 值 |
|---|---|---|
| `postgresql` | PostgreSQL 18.4 主软件（postgresql.org） | SPDX 短标识符 **`PostgreSQL`**（人类可读全名 PostgreSQL License 只允许出现在 evidence 文本） |
| `docker-library/postgres` | Docker Official Image 的打包源 | **`MIT`** |
| `postgresql-docker-official-image` | 复合容器镜像（多来源/多组件） | **`NOASSERTION`**——整个镜像不得再断言 PostgreSQL 或 MIT；该记录同时精确固定 `image_multi_arch_digest` 与 `linux_amd64_platform_digest` |

验证器对当前 **18 条**清单记录逐一校验期望的 SPDX 许可值与精确 kind：一方集合恰为 {`AIPT`, `@aipt/adapter-sdk`}（均为 `first_party`/MIT），B001 批准的精确工具/CI/基础设施集合原样保留（actions/checkout、actions/setup-go、actions/setup-node → `ci_action`/MIT；go、node、pnpm → `toolchain`；postgresql、docker-library/postgres → `infrastructure_image_component`；postgresql-docker-official-image → `infrastructure_image`/NOASSERTION；golang.org/x/vuln → `supply_chain_tooling`/BSD-3-Clause），**B003 迭代 6a 新增六个第三方 Go 运行时模块记录**（kind `third_party_go_runtime`、role `runtime_dependency`、精确版本、`direct` 与 go.mod 一致、`selected_by_batch = AIPT-M0-B003` 与 B003 `verified_at` 及证据——绝不冒充 B001/B002 验证）：

| 模块 | 版本 | 直接性 | 机器 `license` |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | v5.10.0 | **direct**（go.mod 直接 require） | **`MIT`** |
| `github.com/jackc/pgpassfile` | v1.0.0 | indirect | **`MIT`** |
| `github.com/jackc/pgservicefile` | v0.0.0-20240606120523-5a60cdf6a761 | indirect | **`MIT`** |
| `github.com/jackc/puddle/v2` | v2.2.2 | indirect | **`MIT`** |
| `golang.org/x/sync` | v0.17.0 | indirect | **`BSD-3-Clause`** |
| `golang.org/x/text` | v0.29.0 | indirect | **`BSD-3-Clause`** |

**精确集合模型**（B003 迭代 6a）：记录集合必须恰为这 18 个 identity——任何未登记的第三方身份（`unrecorded license record ids`）一律拒绝；SDK 记录必须携带真实 B002 元数据（版本 1.0.0、`selected_by_batch = AIPT-M0-B002`、B002 `verified_at`、LICENSE 证据），六个 Go 运行时记录必须携带真实 B003 元数据（版本/直接性/角色/B003 选择证据），伪装成 B001/B002 验证即失败；licenses.json **文件顶层** `selected_by_batch` 必须**精确锁定为 `AIPT-M0-B001`**（不可变 B001 基线选择器，绝不改写为 B003——B003 只存在于各 Go 运行时记录内部的 `selected_by_batch`）。基线健壮性：`records` 必须是**非空数组**、记录 **id 唯一**（重复 id 必须 FAIL）、18 个期望 identity 必须全部存在。验证器并对内存中的变异副本运行 **29 个许可证清单负向回归**（原 13 个全部保留：复合镜像错标 PostgreSQL/MIT、主软件改离 PostgreSQL、打包源改离 MIT、镜像记录 digest 删除/修改、记录 id 重复、关键 identity 记录删除、SDK 记录删除/错许可/错 kind/冒充 B001 验证、注入未登记第三方身份；B003 新增 7 个：pgx 记录删除/错许可/版本漂移/直接性翻转/冒充 B001 验证、x/text 错标 MIT、**licenses.json 顶层 selected_by_batch 漂移到 B003**；B003 security requalification 再增 9 个：**go 工具链记录版本漂回历史 1.26.5**、**go 记录安全重资格 provenance 被删除**、**go 记录公告集错误**、**go 记录安全重资格 previous_go_version 错误**、**go 记录安全重资格 current_go_version 错误**、**go 记录安全重资格 verified_at 错误**、**go 记录保留歧义 go_version 键**、**go 记录顶层 verified_at 不是 B003 时间（2026-08-20T04:16:01Z）**、**go 记录安全重资格对象多出额外键（闭合键集）**）——全部必须被拒绝；当关键 identity 缺失时，无法执行的探针会**记录明确 FAIL 并安全跳过**（绝不因 `find` 返回 undefined 而抛异常），磁盘文件从不被探针改写。

**一方 pnpm 工作区模型（迭代 4）**：`pnpm-workspace.yaml` 声明 `packages/*`，`pnpm-lock.yaml` 的 importer 集合**恰为** `.` 与 `packages/adapter-sdk`，每个 importer 零依赖说明符（`<key>: {}`），`packages:` 区不存在（零第三方包）；工作区包必须与 licenses.json 的一方记录一一对应（id = 包名、version = package.json 版本、MIT）。内存变异负向探针证明：注入未登记 importer/包、删除已登记 SDK importer、向 importer 夹带依赖说明符、向 `packages:` 区夹带第三方包，全部按**其自身的正确原因**被拒绝。

**Go 运行时闭包交叉校验（B003 迭代 6a）**：`go.mod` 的 require 集合必须**恰为**上述六个模块（精确版本、精确直接/间接标记——pgx 直接、其余五个 indirect；任何未知依赖/版本漂移/直接性翻转一律 FAIL；解析是**失败关闭的行状态扫描器**——绝非对块体的正则抽取：解析覆盖**每一个**合法 `require (...)` 块并接受 Go 允许的可选行首水平空白，但只有代码部分（`//` 注释之前、trim 之后）**恰为 `)`** 的行才能关闭块，`//` 注释里的括号永远不能关闭块（`// )` 之后夹带的第七个依赖同样被计数并拒绝）；任何带任意尾随 `//` 注释的合法 require 项都被解析（先剥离注释再解析模块/版本，间接性由 Go `// indirect` 标记判定，单行 require 不重复计数）；任何无法解析的顶层 require 指令或块内非注释行都是**解析错误并使门禁 FAIL**（绝不静默丢行）），且**绝不允许任何 `replace`/`exclude`/`retract` 依赖图覆盖指令**（图覆盖会把批准闭包重路由/隐藏，一律 FAIL；单行与块两种形式、含可选行首空白均被检出）；`go.sum` 必须为每个模块同时携带 **zip `h1:` 与 `/go.mod h1:`**，且**两个** base64 载荷都必须解码为 32 字节、其小写 hex **等于冻结的 h1 SHA-256 值**（被篡改但仍是合法 base64 的 h1 也会被拒）。**13 个 go.mod/go.sum 内存变异负向探针**（注入未知依赖、pgx 版本漂移、删除 pgx 直接 require、直接性翻转、删除 pgx zip h1、删除 pgx /go.mod h1、篡改 pgx h1、注入 replace 图覆盖、**第二个 require 块夹带第七个依赖**、**`// )` 注释括号行之后的第二个 require 块夹带第七个依赖**、**带普通尾随注释的 rogue 单行 require**、**带行首空白的 replace 图覆盖**、篡改 pgx /go.mod h1）全部必须按自身原因被拒。`tools/toolchain.lock.json` 的基线/digest 另有 **3 个负向探针**（顶层 `selected_by_batch` 漂移到 B003、multi-arch digest 漂移、**linux/amd64 platform digest 漂移——精确等值校验，绝非仅格式校验**），且锁检查失败后**绝不输出无条件成功**。**`policy.json` 保持不可变 B001 基线**：`selected_by_batch = AIPT-M0-B001`、规则集冻结、`current_third_party_application_runtime_dependencies = 0` 是 B001 时代的历史事实，**从不被改写**；当前运行时依赖数只记录在 `licenses.json` 的 `application_dependencies`（go=6/pnpm=0）。

B001 的第三方应用运行时依赖为 **0**；B002 迭代 4 保持第三方依赖数 **0**（go.mod 无 require、pnpm-lock.yaml 恰为 `.` + `packages/adapter-sdk` 两个零依赖一方 importer、零第三方包区）；**B003 迭代 6a 首次引入第三方应用运行时依赖**：go=**6**（上述 pgx v5.10.0 闭包，1 直接 + 5 传递）、pnpm=**0**。**任何未来第三方依赖必须先进入该清单并获得显式批准记录**，否则 CI 门禁 FAIL（`unknown_license_blocks = true`）。当前不引入超出冻结设计的复杂许可证白名单。

## 确定性 SBOM

仓库自带无第三方依赖的 Node 标准库脚本 [../../scripts/ci/sbom/generate-sbom.mjs](../../scripts/ci/sbom/generate-sbom.mjs) 生成**确定性 SPDX 2.3 JSON**，覆盖：AIPT 根包、**一方工作区包 `@aipt/adapter-sdk`**（自有 SPDX 2.3 包：MIT declared/concluded、versionInfo `1.0.0`、npm purl `pkg:npm/%40aipt/adapter-sdk@1.0.0`、`PACKAGE_OF AIPT` 一方关系——**绝不**建模为 `DEV_TOOL_OF`）、**B003 迭代 6a 的六个第三方 Go 运行时模块**（精确已知 SPDX 许可——jackc 四模块 `MIT`、golang.org/x 两模块 `BSD-3-Clause`，**绝不 NOASSERTION**；golang purl；SHA-256 `checksumValue` 为 go.sum zip `h1:` base64 载荷解码出的 64 位小写 hex——Go dirhash H1 本身是 32 字节 SHA-256 摘要，SPDX 2.3 要求解码后的小写 hex 而非 base64 字符串）、CI Actions 固定 Commit、供应链临时扫描器/工具身份、工具链版本，以及 **PostgreSQL 三层许可模型与镜像 digest**：`PostgreSQL`（18.4 主软件，`PostgreSQL`）、`docker-library/postgres`（打包源，`MIT`）、`PostgreSQL Docker Official Image`（复合镜像，两个许可字段均为 `NOASSERTION`），组合关系为**精确三层来源模型**：镜像 `CONTAINS` 主软件（容器内真实组件）、镜像 `GENERATED_FROM` 打包源（打包源代码是镜像的构建输入而非镜像内容——镜像从不 CONTAINS 打包源）。**运行时依赖关系模型（B003 迭代 6a）**：`SPDXRef-AIPT DEPENDS_ON` pgx（唯一直接模块），pgx `DEPENDS_ON` 其余五个间接模块——六个运行时模块**绝不**建模为 `DEV_TOOL_OF`；其余工具/CI/基础设施包仍是 `DEV_TOOL_OF AIPT`。所有校验和按 SPDX 2.3 规范输出：算法大写标识 + **小写十六进制** `checksumValue`（SHA256=64 位、SHA512=128 位）；pnpm 的 SHA512 由锁定 SRI base64 载荷解码为 128 位小写 hex，**不带** `sha512-` 前缀。生成器在构建时对 go.mod/go.sum 做 fail-closed 交叉校验：require 集合必须恰为六个批准模块、h1 必须存在且可解码，任何漂移直接中止生成。

同一输入生成两次必须 **byte-identical**（确定性，CI 强制验证并输出 SHA-256）。此外 CI 对 SBOM 执行 **SPDX 2.3 语义/组件校验**（[../../scripts/ci/validate/sbom.mjs](../../scripts/ci/validate/sbom.mjs)）：`spdxVersion == SPDX-2.3`、`dataLicense == CC0-1.0`、**版本唯一的内容寻址 documentNamespace**（对去除 `documentNamespace` 后的版本定义载荷做规范序列化——递归键排序——并取 SHA-256 64 位小写 hex 作为 `https://github.com/zyc14588/AIPT/spdx/aipt-m0-b003/<hash>` 的后缀；验证器独立重算并要求完全相等；R3/R4 复用过的旧静态 B001 namespace `https://github.com/zyc14588/AIPT/spdx/aipt-m0-b001` 被显式拒绝）、包 SPDXID 唯一且格式合法、必需包集合齐全（**11 个 B001 包身份全部保留**：AIPT、Go toolchain、Node.js、pnpm、PostgreSQL、docker-library/postgres、PostgreSQL Docker Official Image、govulncheck、actions/checkout、actions/setup-go、actions/setup-node；迭代 4 新增一方 `@aipt/adapter-sdk`；**B003 迭代 6a 新增六个批准 Go 运行时模块**：github.com/jackc/pgx/v5、github.com/jackc/pgpassfile、github.com/jackc/pgservicefile、github.com/jackc/puddle/v2、golang.org/x/sync、golang.org/x/text——共 **18 个包**，无包可超出该批准集合）、**每个当前包的 `licenseConcluded`/`licenseDeclared` 与期望 SPDX 许可值精确一致（三层模型：主软件必须为 `PostgreSQL`，全名 PostgreSQL License 会被拒绝；打包源必须为 `MIT`；复合镜像两者必须都是 `NOASSERTION`，断言 PostgreSQL 或 MIT 都会被拒绝；`@aipt/adapter-sdk` 必须为 `MIT`；六个 Go 运行时模块必须为精确已知许可 `MIT`/`BSD-3-Clause`，**绝不 NOASSERTION**）**、**复合镜像 `CONTAINS` 主软件与 `GENERATED_FROM` 打包源两条组合关系必须精确存在（打包源代码是构建输入而非镜像内容，把打包源建模为镜像内容的 CONTAINS 会被拒绝）**、**SDK 包版本 1.0.0、npm purl 精确一致、`SPDXRef-adapter-sdk PACKAGE_OF SPDXRef-AIPT` 一方关系必须存在且绝不出现 `DEV_TOOL_OF`**、**六个 Go 运行时模块包各自必须携带精确版本、golang purl `pkg:golang/<module>@<version>`、SHA-256 `checksumValue` 等于 go.sum zip h1 解码出的冻结小写 hex、以及 comment 中真实 direct/transitive 角色（绝不 DEV_TOOL_OF）**、**依赖关系图：`SPDXRef-AIPT DEPENDS_ON` pgx 且 pgx `DEPENDS_ON` 其余五个间接模块必须全部精确存在；运行时模块绝不出现 `DEV_TOOL_OF` 关系**、工具链/Action 版本与锁文件一致、关系源/目标 SPDXID 可解析且关系类型合法于 SPDX 2.3、校验和为算法长度匹配的小写 hex、pnpm SHA512 hex 从精确锁定的 SRI 载荷解码、**镜像 `versionInfo`、`purl`、`comment` 三处必须完整携带精确 multi-arch digest `sha256:a02db8cac496f15b094798a38254f14d6e00741f709360e5e00bb6668ea31636`，`comment` 还必须携带精确 linux/amd64 platform digest**、go.mod/go.sum 闭包（require 恰为六个批准模块、版本/直接性精确、replace/exclude/retract 图覆盖拒绝、zip 与 `/go.mod` h1 精确 pin）、B003 第三方应用依赖数 go=6/pnpm=0；另含**三十个负向探针**，语义校验器必须全部 FAIL：(1) pnpm SHA512 校验和替换为 SRI/base64 形式；(2) 主软件许可字段替换为全名 `PostgreSQL License`；(3) 修改版本定义字段（如包 comment）但保留原 namespace——namespace 不再匹配文档版本；(4) 显式复用旧静态 namespace；(5) 复合镜像错标 `PostgreSQL`；(6) 复合镜像错标 `MIT`；(7) 主软件改离 `PostgreSQL`；(8) 打包源改离 `MIT`；(9) 从 versionInfo/purl/comment 删除 multi-arch digest；(10) 修改 versionInfo/purl/comment 中的 multi-arch digest；(11) 删除镜像 `CONTAINS` 主软件组合关系；(12) 改错镜像 `CONTAINS` 主软件组合关系；(13) 删除镜像 `GENERATED_FROM` 打包源组合关系；(14) 改错镜像 `GENERATED_FROM` 打包源组合关系——关系探针（11–14）的拒绝必须来自 **composition relationship** 校验本身，而非仅 namespace 失配；迭代 4 新增：(15) 删除 SDK 包；(16) SDK 包错许可；(17) SDK npm purl 删除/漂移；(18) 删除 SDK `PACKAGE_OF` 关系；(19) SDK `PACKAGE_OF` 改错为 `DEV_TOOL_OF`——SDK 探针（15–19）的拒绝必须来自**一方包模型校验**本身，而非仅 namespace 失配；**B003 迭代 6a 新增十一个 Go 依赖探针**：(20) 删除 pgx Go 运行时模块包；(21) pgx 版本漂移；(22) pgx 许可漂移；(23) pgx 校验和漂移；(24) pgx purl 漂移；(25) 删除 `AIPT DEPENDS_ON pgx` 关系；(26) 把 `AIPT DEPENDS_ON pgx` 改错为 `DEV_TOOL_OF`；(27) 删除 `pgx DEPENDS_ON` 某个间接模块关系；(28) pgx comment 直接/传递角色改错；(29) 传递模块被错标为直接；(30) **pgx comment 直接角色改错为 `indirect`（结构化角色 token 回归）**——Go 探针（20–30）的拒绝必须来自**运行时模块包/依赖关系图校验**本身，而非仅 namespace 失配；SBOM 校验器另对 go.mod/go.sum 闭包清单运行 **7 个内存变异负向探针**（注入 `replace` 图覆盖、**第二个 require 块夹带第七个依赖**、**`// )` 注释括号行之后的第二个 require 块夹带第七个依赖**、**带普通尾随注释的 rogue 单行 require**、**带行首空白的 replace 图覆盖**、删除 pgx `/go.mod` h1、篡改 pgx `/go.mod` h1），全部必须被独立清单检查（replace/exclude/retract 拒绝 + 失败关闭的逐行解析 + zip 与 `/go.mod` h1 精确 pin）拒绝，磁盘 go.mod/go.sum 从不被改写。B003 不把 SBOM 产物 commit 进仓库；动态来源溯源由 [../../scripts/ci/provenance.mjs](../../scripts/ci/provenance.mjs) 在 CI 中生成（仓库、commit、workflow run、runner 环境、SBOM SHA-256、工具链版本）。

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
