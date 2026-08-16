# 供应链基础（SUPPLY CHAIN FOUNDATION）

> B001 依据 `R4-Q023`（固定版本、锁文件、SBOM、许可证、漏洞、来源、升级资格的完整供应链门禁）建立的公共工程基础。
> 机器规则为 [../../tools/supply-chain/policy.json](../../tools/supply-chain/policy.json)；本页是可读解释。

## 冻结工具链（`DEFER-016` 已 RESOLVED）

| 工具 | 精确版本 | 频道 | 官方来源 |
|---|---|---|---|
| Go | **1.26.5** | stable | go.dev |
| Node.js | **24.19.0** | LTS（Krypton） | nodejs.org |
| pnpm | **11.4.0** | stable | pnpm/pnpm release + npm registry |
| PostgreSQL | **18.4** | stable | postgresql.org + Docker Official Image |

完整资格（来源身份、发行/完整性材料、验证时间、linux/amd64 校验和、PostgreSQL 多架构与 linux/amd64 平台 digest、CI 期望版本输出）见 [../../tools/toolchain.lock.json](../../tools/toolchain.lock.json)。

规则：**禁止静默升级/降级**。任何版本变更必须重新资格化并进入新的变更批次。

## 公共 CI（`.github/workflows/ci.yml`）

- `permissions: contents: read`，**零** `secrets.*` 引用，**零** API Key，**零**远端模型调用。
- 所有第三方 Action `uses:` 必须是**完整 40 hex Commit SHA**（tag 只作为行尾可读注释）；映射登记在 [../../tools/ci-actions.lock.json](../../tools/ci-actions.lock.json)。
- 容器镜像必须 **digest pin**（PostgreSQL 以多架构 digest 拉取）。
- runner：`ubuntu-26.04`（参考环境）与 `ubuntu-24.04`（GA）；runner 镜像版本/OS 信息写入 CI 日志。
- 三个 required jobs：
  - `b000-retro`：用 B001 验证器对固定历史提交 `777a3f39ba78c1ef3168597890c61abf7a55d962` 做只读展开并追溯验证 B000（MIT 许可、454 条决策、35 条 supersession、16 项延期参数以 B000 自身状态为准、17 篇 Markdown 相对链接、JSON 解析、无凭据/私有路径/Prompt 正文、merge tree == `f5f845b860ba0944ef104b4679fa074ad6efecbb`）。
  - `toolchain`：在 `ubuntu-24.04` 与 `ubuntu-26.04` 上验证精确 Go/Node/pnpm、`gofmt`、`go vet`、`go test`、`pnpm install --frozen-lockfile`、B001 Node 验证器、PostgreSQL Official Image digest pull/run（`postgres --version` 精确 18.4）。
  - `supply-chain`：锁文件存在性与完整性、Action SHA pin、容器 digest pin、依赖清单/许可证覆盖、确定性 + SPDX 2.3/组件语义 SBOM 校验（生成两次 byte-identical 并输出 SHA-256；语义校验与负向无效校验和探针必须通过）、Go 漏洞扫描、`pnpm audit`、来源溯源元数据、无秘密/无真实模型网络配置扫描。
- 全部 required jobs PASS 是 B001 候选进入验收的前提；不自动 deploy/publish。

## 许可证清单

[../../tools/supply-chain/licenses.json](../../tools/supply-chain/licenses.json) 覆盖：AIPT 本体（MIT）、CI Actions（MIT，在 pin commit 处验证）、工具链（Go BSD-3-Clause、Node MIT、pnpm MIT、PostgreSQL 使用 SPDX 短标识符 **`PostgreSQL`**；人类可读 evidence 保留全名 PostgreSQL License）与供应链工具（govulncheck BSD-3-Clause）。验证器对当前 9 条清单记录的机器 `license` 值逐一校验期望的 SPDX 短标识符：AIPT/actions/checkout/actions/setup-go/actions/setup-node/node/pnpm → MIT、go/golang.org/x/vuln → BSD-3-Clause、postgresql → PostgreSQL。

B001 的第三方应用运行时依赖为 **0**（`go.mod` 无 require、`pnpm-lock.yaml` 仅根 importer）。**任何未来依赖必须先进入该清单并获得显式批准记录**，否则 CI 门禁 FAIL（`unknown_license_blocks = true`）。当前不引入超出冻结设计的复杂许可证白名单。

## 确定性 SBOM

仓库自带无第三方依赖的 Node 标准库脚本 [../../scripts/ci/sbom/generate-sbom.mjs](../../scripts/ci/sbom/generate-sbom.mjs) 生成**确定性 SPDX 2.3 JSON**，覆盖：AIPT 根包、Go module 直接/传递依赖、pnpm 直接/传递依赖、CI Actions 固定 Commit、供应链临时扫描器/工具身份、PostgreSQL 镜像 digest、工具链版本。所有校验和按 SPDX 2.3 规范输出：算法大写标识 + **小写十六进制** `checksumValue`（SHA256=64 位、SHA512=128 位）；pnpm 的 SHA512 由锁定 SRI base64 载荷解码为 128 位小写 hex，**不带** `sha512-` 前缀。

同一输入生成两次必须 **byte-identical**（确定性，CI 强制验证并输出 SHA-256）。此外 CI 对 SBOM 执行 **SPDX 2.3 语义/组件校验**（[../../scripts/ci/validate/sbom.mjs](../../scripts/ci/validate/sbom.mjs)）：`spdxVersion == SPDX-2.3`、`dataLicense == CC0-1.0`、**版本唯一的内容寻址 documentNamespace**（对去除 `documentNamespace` 后的版本定义载荷做规范序列化——递归键排序——并取 SHA-256 64 位小写 hex 作为 `https://github.com/zyc14588/AIPT/spdx/aipt-m0-b001/<hash>` 的后缀；验证器独立重算并要求完全相等；R3/R4 复用过的旧静态 namespace `https://github.com/zyc14588/AIPT/spdx/aipt-m0-b001` 被显式拒绝）、包 SPDXID 唯一且格式合法、必需包集合齐全（AIPT、Go toolchain、Node.js、pnpm、PostgreSQL Docker Official Image、govulncheck、actions/checkout、actions/setup-go、actions/setup-node）、**每个当前包的 `licenseConcluded`/`licenseDeclared` 与期望 B001 SPDX 短标识符精确一致（PostgreSQL 必须为 `PostgreSQL`，全名 PostgreSQL License 会被拒绝）**、工具链/Action 版本与锁文件一致、关系源/目标 SPDXID 可解析且关系类型合法于 SPDX 2.3、校验和为算法长度匹配的小写 hex、pnpm SHA512 hex 从精确锁定的 SRI 载荷解码、PostgreSQL digest 身份保留、B001 第三方应用依赖数保持 0；另含**四个负向探针**，语义校验器必须全部 FAIL：(1) pnpm SHA512 校验和替换为 SRI/base64 形式；(2) PostgreSQL 许可字段替换为全名 `PostgreSQL License`；(3) 修改版本定义字段（如包 comment）但保留原 namespace——namespace 不再匹配文档版本；(4) 显式复用旧静态 namespace。B001 不把 SBOM 产物 commit 进仓库；动态来源溯源由 [../../scripts/ci/provenance.mjs](../../scripts/ci/provenance.mjs) 在 CI 中生成（仓库、commit、workflow run、runner 环境、SBOM SHA-256、工具链版本）。

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
