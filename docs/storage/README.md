# 存储（STORAGE）

> AIPT-M0-B003 施工中的 PostgreSQL 存储层：**只前向的嵌入式迁移** 与 **追加式哈希链账本**。
> 机器门禁为 [../../scripts/ci/validate/storage.mjs](../../scripts/ci/validate/storage.mjs)（`pnpm run check:storage`，Node 标准库、fail-closed）：**动态枚举** `internal/storage/postgres` 下全部文件并经由共享的完整必需文件/源码树检查校验迁移契约、账本契约表面与集成测试契约；运行时完整性绕过扫描覆盖**每一个非测试 `*.go` 源文件**（非固定白名单），匹配**大小写不敏感且空白容忍**（`disable trigger`、换行间隔的 `ALTER TABLE`、`time . Now ( )` 均被拒绝）；临时夹具通过同一共享检查证明缺失 `verify.go` 与新增绕过文件均失败。

## 范围与禁止

- 本层只实现**确定性基础设施**：迁移运行器、追加式哈希链账本（Append/VerifyStream）。Core、Launcher、Harness Host、Web UI 与 `AIPT-M0-B004` 均不在范围。
- **禁止生产数据库与真实凭据**：所有集成测试只在临时、随机命名的 `aipt_it_*` 数据库上运行；任何代码路径都不得接触生产 PostgreSQL 或真实 DSN 凭据。
- 运行时依赖为已资格化的 **pgx v5.10.0 闭包**（`go.mod` 直接 `github.com/jackc/pgx/v5 v5.10.0` + 五个间接模块；MIT / BSD-3-Clause，见 [../../tools/supply-chain/licenses.json](../../tools/supply-chain/licenses.json)），版本精确锁定，禁止静默升级/降级。

## 只前向嵌入式迁移（FORWARD-ONLY EMBEDDED MIGRATIONS）

- `migrations/*.sql` 通过 `go:embed` 嵌入二进制（[schema.go](../../internal/storage/postgres/schema.go)），运行时应用的就是测试所固定的同一批字节，永不漂移。
- `MigrateUp` 委托给包内运行器 `migrateUpFS`：**先完整加载并校验全部迁移定义，才触碰数据库**（nil pool、空目录、目录项、非法文件名、重复/零版本、空白 SQL 一律 fail-closed）。
- 单次运行持有固定 session 级咨询锁（`pg_advisory_lock`，键 `0x41495054` = ASCII "AIPT"），并发运行在同一数据库上串行化；锁仅在获取成功后注册延迟释放，释放走独立有界后台 context，并校验 `pg_advisory_unlock` 返回 true。
- 引导创建 `aipt` schema 与 `aipt.schema_migrations`（版本主键 > 0、非空 name、恰好 32 字节 checksum、数据库生成 applied_at）；表与全部语句幂等，二次运行是 no-op。
- 已应用行必须是本地迁移的**精确有序前缀**（版本/名称/32 字节 SHA-256 逐项一致，版本严格递增）；任何未知/缺口/顺序/名称/校验和漂移都在应用任何待办迁移**之前**被拒绝。校验和漂移返回 `*MigrationChecksumDriftError`（`AIPT_MIGRATION_CHECKSUM_DRIFT`，`errors.Is` 兼容，携带 Expected/Actual）。
- **只前向**：不存在 down/force/repair/ignore API；每个待办迁移在独立事务内应用并写入元数据，失败整体回滚、不留痕迹。

## 追加式哈希链权威（APPEND-ONLY HASH-CHAIN AUTHORITY）

- 版本化编码域字面量 **`AIPT_LEDGER_V1`**：preimage 布局由 [hash.go](../../internal/storage/postgres/hash.go) 的 `encodeLedgerPreimage` 精确定义（uint32 长度前缀 + UTF-8 字段、uint64 大端 sequence、payload SHA-256、0x00 或 0x01||prev hash），数据库端 `aipt.ledger_event_hash_v1` 用同一布局逐字节复现；`committed_at` 故意不在 preimage 中。
- `aipt.ledger_streams`：每流一行游标（`last_sequence`、`last_event_hash`）；空流 = `(0, NULL)`，非空流 = 正 BIGINT + 非 NULL 32 字节哈希，由 `ledger_streams_cursor_invariant` 在数据库层强制。
- `aipt.ledger_events`：追加式事件链；`ledger_events_chain_invariant`（genesis 的 `prev_event_hash` 为 NULL，其后每行非 NULL）、`payload_sha256 = sha256(convert_to(payload_canonical, 'UTF8'))` 与 `event_hash = aipt.ledger_event_hash_v1(...)` 两条 CHECK 由数据库强制；`event_id` 唯一；外键 `ON DELETE RESTRICT`。
- 语句级 `BEFORE UPDATE OR DELETE OR TRUNCATE` 触发器 `ledger_events_append_only`（`FOR EACH STATEMENT`，永不逐行）以稳定码 `AIPT_LEDGER_APPEND_ONLY` + SQLSTATE `55000` 拒绝**一切** UPDATE/DELETE/TRUNCATE——包括零行语句。

## Append 与 VerifyStream

- `Append`：先以既有 `internal/protocol.CanonicalJSON` 严格规范化原始 JSON（**任何数据库访问之前**；非法载荷即使 nil pool 也被拒绝并返回协议类型化原因），再在**单事务**内：确保流行 → 锁游标并核对真实 `ledger_events` 尾部（绝不只信游标）→ 拒绝 `math.MaxInt64` 序列耗尽 → 计算版本化事件哈希 → 插入事件（`committed_at` 由数据库 `RETURNING` 返回，**绝不使用 `time.Now()`**）→ 守卫式更新游标（必须恰好影响 1 行）。提交是最后一步：任何失败整体回滚，游标不可能脱离成功插入而推进。
- `VerifyStream`：同一 fail-closed 标识符校验后在**单个 RepeatableRead + ReadOnly 快照**内读取游标与全部事件；校验序列恰为 1..N、genesis 前哈希为 SQL NULL、其后每行前哈希等于前一行已验证哈希、记录 payload SHA-256 等于精确存储的 canonical TEXT 的 SHA-256（绝不重新规范化）、记录事件哈希等于 `hashLedgerBlock` 重算摘要、存储游标等于实际已验证尾部（空流 `(0, NULL)` 语义）。验证只读、绝不改动数据。

## 类型化失败（TYPED FAILURES）

| 稳定码 | 错误类型 | 场景 |
|---|---|---|
| `AIPT_MIGRATION_CHECKSUM_DRIFT` | `*MigrationChecksumDriftError` | 已应用迁移的磁盘字节与记录校验和漂移 |
| `AIPT_LEDGER_CURSOR_MISMATCH` | `*LedgerCursorMismatchError` | 锁定的游标与实际账本尾部不一致 |
| `AIPT_LEDGER_SEQUENCE_EXHAUSTED` | `*LedgerSequenceExhaustedError` | 游标已达最大正 BIGINT 序列 |
| `AIPT_LEDGER_STREAM_NOT_FOUND` | `*LedgerStreamNotFoundError` | 验证不存在的流 |
| `AIPT_LEDGER_SEQUENCE_GAP` | `*LedgerSequenceGapError` | 事件序列不连续（非 1..N） |
| `AIPT_LEDGER_PREV_HASH_MISMATCH` | `*LedgerPrevHashMismatchError` | 记录的前事件哈希与预期不符 |
| `AIPT_LEDGER_PAYLOAD_HASH_MISMATCH` | `*LedgerPayloadHashMismatchError` | 记录 payload 哈希与存储文本不符 |
| `AIPT_LEDGER_EVENT_HASH_MISMATCH` | `*LedgerEventHashMismatchError` | 记录事件哈希与重算摘要不符 |
| `AIPT_LEDGER_MALFORMED_HASH` | `*LedgerMalformedHashError` | 哈希列既非 NULL 也非 32 字节 |
| `AIPT_INVALID_LEDGER_HASH_INPUT` | `*LedgerHashInputError` | 版本化 preimage 输入非法（空/非 UTF-8/超长/非正序列） |

## 测试契约（仅测试用 PostgreSQL 18.4）

- 集成测试（`migration_integration_test.go`、`ledger_integration_test.go`）需要环境变量 **`AIPT_POSTGRES_DSN`**；缺失时**正常 skip**，但 **`AIPT_REQUIRE_POSTGRES_INTEGRATION=1` 会把 skip 变成硬失败**（fail-closed：不得假装通过）；DSN 必须命名 dbname，否则拒绝。
- 只使用**临时、随机、防碰撞**的 `aipt_it_*` 数据库；夹具 cleanup 终止该库全部连接、**精确 DROP 该库**（`pgx.Identifier` 消毒，绝无通配符）、并验证服务器上**无任何 `aipt_*` 数据库残留**（`left(datname, 5) = 'aipt_'` 字面前缀，无 LIKE 通配歧义）。
- PostgreSQL 镜像**仅用于测试**：Docker Official Image `library/postgres:18.4`，multi-arch digest `sha256:a02db8cac496f15b094798a38254f14d6e00741f709360e5e00bb6668ea31636`、linux/amd64 platform digest `sha256:4cc13dede823cab4e05290c7fb3350fb4e599ecabd9b07e6706b5d5e8f5bc929`（冻结于 [../../tools/toolchain.lock.json](../../tools/toolchain.lock.json)），CI 以 digest 拉取并校验 `postgres --version` 精确 18.4 前缀。

## 并发与篡改覆盖

- 迁移并发：两个并发运行器以 `pg_locks` **确定性证明**（非计时）串行化在 session 咨询锁上（bigint 形式 classid/objid/objsubid=1 编码被钉死），门锁释放后汇成一个连贯应用集合、无残留咨询锁。
- 账本并发：≥16 个 Append goroutine 在同一流上并发，只断言确定性最终态（序列恰 1..N、事件 ID 唯一、prev-hash 连贯、游标在 N、VerifyStream 精确计数/尾部）。
- 五个篡改用例（临时库内禁用触发器/只删单条约束，生产迁移 SQL 永不修改）：payload 篡改、prev-hash 篡改、event-hash 篡改、游标回卷、序列缺口删除——每个都命中对应类型化失败并返回零值结果。

## 相邻文档

- [../supply-chain/README.md](../supply-chain/README.md)（pgx 闭包资格、许可证、SBOM 依赖关系建模）· [../authority/PROJECT_STATUS.md](../authority/PROJECT_STATUS.md) · [../milestones/M0.md](../milestones/M0.md)
- [返回仓库首页](../../README.md)
