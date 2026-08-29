# 安全（SECURITY）

> 公开安全设计合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)。
> 除下列明确标注的 B007 Web 控制与 B002 Run Core 完整性边界外，本节仍是冻结设计合同；不得把设计目标误报为已实现能力。

## 信任边界

- **来源只读**：游戏与代码来源以固定 Commit 独立只读检出，运行目录分离（`R2-Q004`）；Codex 对远端仓库只读（`R10-Q005`）。
- **Agent 不可直接写状态**：Agent 只提交意图；Core 经 Schema、授权、规则、不变量校验后提交权威事件（`R5-Q008`）。
- 外层容器/OS 沙箱 + Harness 沙箱 + 只读来源 + 最小权限，纵深防御（`R4-Q014`）。

## B002 Run Core 完整性边界

- action proposal 是唯一 caller-controlled mutation input；返回的 state/projection 都是深复制派生值，没有直接写 ledger、sequence、RNG cursor 或 immutable binding 的 API。所有 gate 与 transition 均 fail-closed，错误只暴露稳定类别与有界 identity，不渲染 cause、payload、DSN、credential、seed 或私有路径。
- PostgreSQL append-only hash chain 是唯一持久状态 Authority。`ExpectedSequence` 在 ledger stream 行锁内比较，duplicate/stale/concurrent conflict 在 insert 前拒绝；state、RNG cursor 与 projection 只在 successful commit 后推进。
- root seed 由可注入 `SeedSource` 提供；seed commitment 在任何 draw 前固定。普通 event/state/projection/receipt 只携带 commitment 与版本化 RNG evidence，不携带 root seed；evidence-authorized verification 通过 constant-time digest comparison 验证 commitment。
- replay 在应用 transition 前验证完整 ledger chain、Run/Manifest/adapter/source binding、RNG/commitment version、draw evidence、state invariant 与 final state hash；缺失、重排、替换或篡改不会触发 silent repair。
- B002 未实现 Agent orchestration、model gateway 或网络 client；`real model calls = 0`，真实 playtest 为 false，测试只使用 synthetic public fixture 与 loopback-only PostgreSQL 18.4。

## 信息隔离与 ACL

- 每席位独立 Session 与显式信息投影（`R2-Q016`）；每次模型调用前由 Core 生成席位授权视图（`R5-Q006`）。
- **ACL 先于检索**：先过滤语料，再精确/混合检索与引用验证（`R5-Q017`）。
- 内容使用显式可见性标签，未标记 fail-closed（`R13-Q015`）。

## 数据/内容分类

六类字段级分类（`R4-F002`），远端发送按分类实施：

- `PUBLIC`：可公开。
- `UNRELEASED_REMOTE_ALLOWED`：未发布但允许按策略发送远端模型。
- `TABLE_HIDDEN_REMOTE_ALLOWED`：桌面隐藏信息，按策略允许远端。
- `LOCAL_ONLY_SECRET`：**默认阻塞**远端发送；仅诊断 break-glass 可外发且运行失格（`R6-F002`）。
- `HUMAN_PRIVATE_DATA`：真人隐私数据。
- `CREDENTIAL_SECRET`：凭据。

## 提示注入防护

规则书、模组和日志内容一律作为**不可信数据**处理，防提示注入（`R5-Q018`）。

## 凭据与密钥

- 凭据字段只写不读，保存后只返回引用与验证状态（`R7-Q005`）。
- 可替换凭据提供器；首版加密本地文件与环境变量引用（`R7-Q006`）。
- Codex 的 GitHub 只读凭据通过受控 Credential Helper/代理注入，Codex 不读取令牌（`R11-F002`）。

## 本地端点与界面

- B007 AIPT Web Host 已实现且绑定策略不可配置：只使用 `tcp4` `127.0.0.1:0`，OS 选择动态端口，并验证实际 listener 仍是 IPv4 loopback；没有非 loopback fallback。
- 所有请求都要求 `Host` 精确等于实际选择的 `127.0.0.1:<port>`。携带 `Origin` 时必须精确同源；`POST`/`PUT`/`PATCH`/`DELETE` 必须同时携带精确同源 `Origin` 与进程内通过 `crypto/rand` 生成的临时 CSRF token。token 不导出、不写盘、不进入 URL 或响应 DTO。合法安全前置条件通过后，当前只读路由仍以 `405 Method Not Allowed` 拒绝 mutation。
- 全部响应设置严格 CSP（仅 `self`，禁止 object/base/frame/form，connect 仅同源）、`nosniff`、`DENY`、`no-referrer`、same-origin CORP 与 `no-store`。不启用 CORS wildcard，不加载外部资产，不提供 WebSocket/SSE/telemetry。
- Dashboard Config 投影绝不包含 DSN/credential；错误与 HTTP server log 不回显底层敏感原因。Queue/Run/Status backend 与 Report UI export/generator 明确 `NOT_IMPLEMENTED`，没有伪造状态或 mutation endpoint。（`R4-Q019`）
- llama.cpp 本地模型端点默认仅 **Loopback**（`R6-Q020`）；Launcher 为其分配动态 Loopback 端口（`R7-Q014`）。
- loopback llama.cpp 首版不设置 API Key（`R7-Q017`）。

## 不可豁免门禁

Commit/Tree、哈希/签名、凭据、隐藏信息、权威状态、账本完整性等硬门禁**不得**被管理员覆盖（`R16-Q003`）。开发 Break-glass 仅可越过非完整性门禁且产物无生产/发行资格（`R16-Q004`）。

## 私有提示词政策

本公共仓库不含私有提示词正文。全部提示词资产仅保存在本地加密 Git 仓库、无远端、不公开（`R13-F001`、`R0-Q009`）。

## 设计状态声明

“本地端点与界面”中的 B007 Web 控制与“B002 Run Core 完整性边界”已由对应历史/当前 Candidate 实现；Agent/session、模型调用、完整产品 runtime 与资格运行仍只是**冻结设计合同**，由后续获授权批次实现。

## 相邻文档

- [../authority/README.md](../authority/README.md) · [../authority/DECISION_MATRIX.md](../authority/DECISION_MATRIX.md) · [../architecture/README.md](../architecture/README.md) · [../evidence/README.md](../evidence/README.md)
- [返回仓库首页](../../README.md)
