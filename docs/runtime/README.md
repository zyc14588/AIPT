# Runtime Shell 与 B007 本地 Web

`AIPT-M0-B004` 已 `MERGED_CLOSED`，交付 Go Launcher、严格共享配置基础与 Core lifecycle shell。`AIPT-M0-B007` 也已 `MERGED_CLOSED`，在不改变固定门禁顺序的前提下实现最终 `WEB` 组件；verified implementation identity 为 merge `e05179a223f9dd0ff1b317e78c0e466e1146f6bb`（tree `35a5cc261fef75df8d25102015670bcb1d6fbd92`）。`AIPT-MVP-B004` 当前为该固定计划接入受治理的 MODEL/HARNESS runtime。整个 runtime 仍然**失败关闭且尚未 ready**：具备合法私有 runtime config 与已认证资产时可越过 MODEL/HARNESS；首个固定未实现 gate 是 `IPC`，后续 WEB 不能绕过它。

## AIPT-MVP-B002 Deterministic Run Core

`AIPT-MVP-B002` Candidate 在 [`internal/runcore`](../../internal/runcore) 提供独立、game-neutral 的 Run Core library。它接受严格的 versioned action proposal，绑定不可变 Manifest/runtime-adapter/source-package identity，执行 authorization、Rule/source、precondition、invariant、versioned RNG 与 PostgreSQL ledger commit，并从 committed state 产生 deterministic derived projection。RNG 身份固定为 `AIPT_RNG_HMAC_SHA256_V1`，seed commitment 固定为 `AIPT_SEED_COMMITMENT_SHA256_V1`；root seed 不进入普通 projection、event 或 receipt。

Replay 会重新验证 ledger hash chain、binding、commitment、RNG evidence 和每次 state transition，live/replayed final canonical state hash 必须相同。B002 本身没有接入真实模型；其 business semantics 在 B004 继续 byte-identical，模型输出仍只能通过 B003 protocol 与 B002 action transaction 改变状态。

## AIPT-MVP-B003 Provider-neutral Agent Orchestrator

`AIPT-MVP-B003` 在 [`internal/orchestrator`](../../internal/orchestrator) 提供独立 Go library，并保持 [`internal/runcore`](../../internal/runcore) byte-identical。`Engine` 接受显式 Run/policy、1 GM + 4 Player seat plan、Run-bound Sessions、fake/scripted `AgentInvoker`、可注入 Clock/Retriever 与唯一 `ActionSubmitter`。公共测试不会启动 Harness 子进程、HTTP model client 或真实 provider。

调用流程固定为：验证 floor owner → 生成 seat-authorized projection → ACL-before-retrieval → citation 与 memory-summary invariant → canonical context hash → scripted Agent invocation → strict structured response → 有界 retry/recovery → B002 Action Proposal。Timeout 由可注入 clock 与显式 policy deadline 判定，测试不 sleep；任何 timeout 都形成事件，不能静默跳过或复用旧回答。

`AgentInvoker` 是 B004 实现的 provider-neutral boundary。B003 中仍只有冻结的接口与测试 fake；B004 在独立 model/gateway 层实现该接口，不把 provider 逻辑引入 floor、Persona 或 state code。`RunCoreSubmitter` 只把一个通过 B003 protocol gate 的 action 交给 B002 `Run.Execute`，没有独立 state writer、RNG 或 ledger path。Orchestration events 与 gameplay authoritative events 分层，speech/private chat/clarification prose 都不会自动成为 gameplay fact。

## AIPT-MVP-B004 Governed Model/Harness Gateway

[`internal/modelgateway`](../../internal/modelgateway) 实现严格版本化 Model/Sampling Profile、complete execution tuple、独立 capability certification、每席位不可变 Manifest binding、显式 replacement disqualification、write-only credential broker、remote egress 双层 enforcement、确定性 context reduction 与 B003 `AgentInvoker`。[`packages/model-harness-gateway`](../../packages/model-harness-gateway) 以 additive AIPT JSON-RPC 控制外部进程，并继续通过 `@aipt/harness-adapter`/ACP 对接固定 DeepSeek Harness；AIPT 没有直连 provider inference endpoint。

`REMOTE_DEEPSEEK` 只允许 `deepseek-v4-pro`。`LOCAL_LLAMACPP` 的正式主路径由 AIPT 以 argv 启动登记 binary/GGUF/template，并在私有 Linux user/network namespace 内动态绑定 `127.0.0.1`。llama executable、GGUF、isolation helper、Node executable、route config 与静态单文件 Harness closure 都通过一次 `O_NOFOLLOW` 打开，对同一 held file object 完成 hash/fstat，再仅以 inherited descriptor 执行或加载；pathname replacement 不会改变实际对象。Linux pidfd 固定不可复用的 process generation，统一 lifecycle mutex 线性化 Start/Stop/recovery/retirement，失败 cleanup 仅触达 PID > 1 的已绑定 generation 且全部有界。只有 namespace 内由 supervisor 启动的 governed adapter 能访问仍无 API key 的 llama loopback；宿主与无关本地进程无法直连，也没有 non-loopback fallback。bounded shutdown/recovery 后 clean baseline 永久失格。私有 endpoint、runtime config、credential 值和本机绝对路径都不是可导出的 Manifest/evidence。

ACP child route 还必须携带 versioned `aipt.acp-output-budget/v1`：total stdout raw bytes、notification raw bytes、response+notification raw bytes与 stderr 分别计费。BOM、未完成 frame 与大量合法小 frame 都在解析/累计语义之前消耗预算；每个 probe/invocation 的 child lifetime 在 outer result 前被强制封口，process group 终止并排空 stdout/stderr 至 EOF 后才作最终预算判断。overflow 会终止 child、删除 partial buffer，且 terminal response 后到达的超限字节也不能产生部分成功。诊断 break-glass 同样只走 B004 Gateway：签名 grant 精确绑定最终 request digest，既有 append-only ledger 的独立 Run-audit stream 在 transport 前完成全局一次性消费和 Run-level disqualification。该 authoritative sink 对正式与诊断 Gateway 均为必需；正式 invocation append 使用现有 ledger `ExpectedSequence` 与消费线性化，任何失格并发都会使正式结果失败关闭而不是产生失格后的 clean evidence。不新增 migration，也不改变 B002 Run stream 语义。

受控产品 route 已冻结为 `HARNESS-01`（`dsh-v0.1.0-rc.8` / `141eb6fef83422698aef7a981029e843e8161534`）及其静态单文件运行时闭包与 Owner 批准的 credential reference；安全修复后的受控 `REMOTE_DEEPSEEK` 和 `LOCAL_LLAMACPP` minimum re-certification 均已 PASS，[remote 最终公开证据](../model-certification/remote-deepseek-controlled-real-02.json)与 [local 最终公开证据](../model-certification/local-llamacpp-controlled-real-02.json)均不含 credential 值或私有路径，旧 `-01` 证据仅保留为 `SUPERSEDED_NON_FINAL`。受控流程累计 5 次真实模型调用：remote/network 3 次、local 2 次；本次修复后各新增最小 1 次成功调用。`GGUF-04` locator 已完成批准 root containment、canonical target、完整 SHA-256 与 metadata 验证但未导出；实际 executable/GGUF/route 消费绑定同一 held file object，`LLAMACPP-01` 与 governed adapter 位于私有 user/network namespace，宿主无法直连无 API key 的隔离 loopback endpoint。公共 CI 只运行 fake Harness/provider/llama fixtures，`public_ci_real_model_calls = 0`、`public_ci_network_model_calls = 0`、secret requirement 为 0。`real_playtest_executed = false`、`qualification_runs_executed = 0`，`DEFER-003` 未关闭。

## 固定启动计划

门禁顺序由 `internal/launcher` 固定，调用者和配置都不能重排：

1. `CONFIG` — 严格加载 `aipt.config/v1`；
2. `POSTGRESQL` — 使用配置的 URI DSN 建池，并在配置的超时内 `Ping`；
3. `MIGRATIONS` — 直接调用 B003 `internal/storage/postgres.MigrateUp`；
4. `MODEL` — B004 实现；严格验证 formal registry、credential reference、local binary/GGUF/template identity，并启动受管 local backend；
5. `HARNESS` — B004 实现；只启动并 probe 与 Profile 精确绑定的 Harness adapter route；
6. `CORE` — lifecycle shell 已实现；
7. `IPC` — 未实现；
8. `WEB` — B007 已实现安全的本地只读 Host；只有全部前序门禁成功后才可启动。

`aipt plan` 输出确定性 JSON，并明确给出 `runtime_ready: false` 与 `first_blocking_gate: "IPC"`。计划只是声明，不是启动成功证据；MODEL/HARNESS 的 implementation 标记也不等于受控认证或完整 runtime 已启动。

## 共享配置

权威 Schema 是 [`schemas/config/v1/aipt-config.schema.json`](../../schemas/config/v1/aipt-config.schema.json)，Go 消费者是 [`internal/config`](../../internal/config)。CLI 与未来 Web UI 复用这套语义。所有对象都拒绝未知字段；所有字段均为必填；不存在隐式默认值或环境变量回退。

最小 development 示例：

```json
{
  "schema": "aipt.config/v1",
  "profile": "development",
  "database": {
    "dsn": "postgres://127.0.0.1:5432/aipt_dev?sslmode=disable",
    "identity": "aipt_dev",
    "namespace": "aipt_dev",
    "ping_timeout_ms": 5000
  },
  "evidence": {
    "namespace": "aipt.dev"
  }
}
```

Production 必须提供独立文件，使用 `profile: "production"`，并显式指定不同的数据库 identity、数据库 namespace 和 evidence namespace。`config.ValidateIsolation` 对一对 development/production 配置检查三类碰撞。DSN 必须是 `postgres`/`postgresql` URI，包含 host 与数据库名，且数据库名必须等于 `identity`。

DSN 是敏感值。配置错误、`String`、格式化和 JSON 输出都不会回显 DSN；只有 Launcher 专用的 `Database.DSN()` 访问器可以取得原值。不要把带凭据的配置提交到仓库。

## B007 Web Host 与只读路由

Web 绑定策略不可配置：只允许 `tcp4` 的 `127.0.0.1:0`，由 OS 选择动态端口，并在开始服务前再次验证 listener 确实是 IPv4 loopback。`Host.URL()` 只返回形如 `http://127.0.0.1:<dynamic-port>` 的诊断 URL，不包含 CSRF token、DSN 或 credential。

固定路由只有：

- `GET|HEAD /`；
- `GET|HEAD /assets/app.js` 与 `/assets/styles.css`；
- `GET|HEAD /healthz`；
- `GET|HEAD /api/v1/dashboard`。

Dashboard 是非权威派生读模型，严格只有 Config、Health、Queue、Run、Status/Table、Reports 六个面板。Config 只投影 profile、database identity/namespace 与 evidence namespace，绝不投影 DSN。Queue、Run、Status/Table 后端均为 `NOT_IMPLEMENTED`，数组必须为空且 active run 必须为 `null`；不得伪造 live 状态。Reports 只如实声明既有 `RAW_CAPTURE` 为 `IMPLEMENTED_LIBRARY_ONLY`，UI export、`AUDIT_READY`/`AUDIT_RESULT` generator、签名、加密、分块均为 `NOT_IMPLEMENTED`。B007 没有新增 queue migration、queue backend 或 mutation API。

所有未知路由返回 404；只读路由上的非 GET/HEAD 方法在通过安全前置门禁后返回 405。没有 CORS wildcard、外部静态资源、遥测、浏览器持久化、WebSocket、SSE 或远端模型调用。

### B003 迁移命名空间边界

B003 已冻结的迁移在每个目标数据库内使用 `aipt` SQL schema。B004 不复制、不重写也不参数化该迁移层。B004 配置中的 `database.namespace` 是共享配置和跨 profile 隔离的显式基础字段；当前迁移调用仍以**独立数据库 identity**提供实际开发/生产隔离，不能把该字段理解为已重映射 B003 的 `aipt` schema。

## CLI 与关闭语义

```text
aipt plan
aipt run --config <path>
```

`run` 捕获 `SIGINT`/`SIGTERM` 并传播取消。启动失败或进程取消时，已启动组件按逆序、使用独立有界 context 清理；清理错误通过 error chain 保留，但不会掩盖最初的启动错误。CLI 只输出稳定的机器 JSON 错误码和 gate，不输出底层 DSN 或原始错误内容。

Core 状态为 `NEW → STARTING → RUNNING → STOPPING → STOPPED`，启动或 readiness 失败进入 `FAILED`。readiness 只有在全部 Core-owned checks 成功后成立；依赖显式注入、同步且 context-aware，关闭有界，不启动 goroutine、网络 listener 或模型调用。

## 验证

本地无 PostgreSQL 时，普通单元测试会安全跳过集成用例；权威 CI 使用 digest-pinned PostgreSQL 18.4 临时容器并设置测试专用 DSN：

```text
go test ./...
go test -race ./internal/runcore ./internal/storage/postgres
pnpm run check:mvp-b002
pnpm run test:run-core
pnpm run check:mvp-b003
pnpm run test:orchestrator
go test -race ./internal/orchestrator -count=1
go test -race ./internal/config/... ./internal/core/... ./internal/launcher/... ./cmd/aipt/...
pnpm run check:runtime-shell
pnpm run check:web-ui
pnpm run test:web-ui
pnpm run test:web-go
pnpm run smoke:web-ui
```

设置 `AIPT_REQUIRE_POSTGRES_INTEGRATION=1` 后，缺少或错误的 `AIPT_POSTGRES_DSN` 会硬失败，不能降级为 skip。CI 验证连接、迁移、二次迁移 no-op、checksum drift、数据库不可用、Launcher 的 later-gate stop，以及 B003/B004 适用的 race 覆盖。

## B007 明确边界

B007 的历史交付不实现 Model、Harness runtime、IPC、queue/run/status backend、queue migration、报告导出或报告 generator，也不实现 Unix socket、campaign engine 或 game adapter。当前唯一活跃状态为 `construction = IN_PROGRESS`、`current_batch = AIPT-MVP-B004`、`GLOBAL_WIP = 1`；这不会追溯改写 B007/B003/B002 closeout，也不会启动 integration batch。
