# Runtime Shell 与 B007 本地 Web

`AIPT-M0-B004` 已 `MERGED_CLOSED`，交付 Go Launcher、严格共享配置基础与 Core lifecycle shell。`AIPT-M0-B007` 也已 `MERGED_CLOSED`，在不改变固定门禁顺序的前提下实现最终 `WEB` 组件；verified implementation identity 为 merge `e05179a223f9dd0ff1b317e78c0e466e1146f6bb`（tree `35a5cc261fef75df8d25102015670bcb1d6fbd92`）。整个 runtime 仍然**失败关闭且尚未 ready**：真实启动会完成配置、PostgreSQL 连接和 B003 迁移，然后在首个尚未实现的强制 `MODEL` 门禁返回稳定错误 `AIPT_LAUNCH_GATE_NOT_IMPLEMENTED`。更晚的已实现 Web 不能绕过这个前序门禁。

## 固定启动计划

门禁顺序由 `internal/launcher` 固定，调用者和配置都不能重排：

1. `CONFIG` — 严格加载 `aipt.config/v1`；
2. `POSTGRESQL` — 使用配置的 URI DSN 建池，并在配置的超时内 `Ping`；
3. `MIGRATIONS` — 直接调用 B003 `internal/storage/postgres.MigrateUp`；
4. `MODEL` — B004 未实现，真实启动在此失败关闭；
5. `HARNESS` — 未实现；
6. `CORE` — lifecycle shell 已实现，但真实路径不能绕过更早的 `MODEL`；通过依赖注入测试验证；
7. `IPC` — 未实现；
8. `WEB` — B007 已实现安全的本地只读 Host；只有全部前序门禁成功后才可启动。

`aipt plan` 输出确定性 JSON，并明确给出 `runtime_ready: false` 与 `first_blocking_gate: "MODEL"`。计划只是声明，不是启动成功证据。

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
go test -race ./internal/config/... ./internal/core/... ./internal/launcher/... ./cmd/aipt/...
pnpm run check:runtime-shell
pnpm run check:web-ui
pnpm run test:web-ui
pnpm run test:web-go
pnpm run smoke:web-ui
```

设置 `AIPT_REQUIRE_POSTGRES_INTEGRATION=1` 后，缺少或错误的 `AIPT_POSTGRES_DSN` 会硬失败，不能降级为 skip。CI 验证连接、迁移、二次迁移 no-op、checksum drift、数据库不可用、Launcher 的 later-gate stop，以及 B003/B004 适用的 race 覆盖。

## B007 明确边界

B007 不实现 Model、Harness runtime、IPC、queue/run/status backend、queue migration、报告导出或报告 generator，也不实现 Unix socket、campaign engine、game adapter 或完整动作管线。closeout 后 `construction = IDLE_WAITING_NEXT_BATCH`、`current_batch = NO_ACTIVE_BATCH`、`GLOBAL_WIP = 0`；下一串行项 `INT-AIPT-UNREGISTERED-001` 仅为 `AUTHORIZED_TO_PREPARE`（`next_batch_authorized = true`，`next_batch_started = false`），尚未执行 Integration；B008 同样未开始。
