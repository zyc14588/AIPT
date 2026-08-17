# AIPT 协议契约（Protocol Contract, B002）

> 批次：`AIPT-M0-B002`（`B002_IN_PROGRESS`）· 迭代 3 · 状态日期 **2026-08-17**。
> 本页解释权威协议 Schema、最小确定性夹具（含持久化 wire 信封）与协议资产验证器。机器可读权威是
> [schemas/protocol/v1/aipt-protocol.schema.json](../../schemas/protocol/v1/aipt-protocol.schema.json)
> 与 [testdata/protocol/v1/minimal-fixture/manifest.json](../../testdata/protocol/v1/minimal-fixture/manifest.json)；
> 本文档是可读解释，不是第二份独立权威。

## 1. 权威来源（canonical authority）

- **唯一权威根**：`schemas/protocol/v1/aipt-protocol.schema.json`。全部线上协议（wire）真相以该文档的本地 `$defs` 表达；任何其它 schema 不得复制线协议定义（禁止跨 schema 重复 wire truth）。
- **根是可执行的，不是空壳**：根上有一个 `oneOf`，只接受三种已注册 wire 信封——`jsonrpc_request`、`jsonrpc_response`、`jsonrpc_notification`（全部本地 `#/$defs/...` 引用）。任意/畸形 JSON 对根 `#` 校验必然失败（验证器含显式负向探针）。
- 方言：**JSON Schema 2020-12**（根 `$schema` 精确等于 `https://json-schema.org/draft/2020-12/schema`）；根 `$id` = `https://github.com/zyc14588/AIPT/schemas/protocol/v1/aipt-protocol.schema.json`。
- 本迭代的工程选择记录为 `B002_IMPLEMENTATION_CHOICE`（实现选择，见第 9 节）——**不是** Authority Decision：不写入 decisions/supersessions/deferred 登记。

## 2. 版本与显式常量

| 字段 | 值 | 规则 |
|---|---|---|
| `protocol_version` | `"1.0.0"`（const） | 每个夹具资产与每个线信封携带；未知版本 fail closed |
| `schema_version` | `"1.0.0"`（const） | 同上，任何资产版本漂移即失败 |
| `fixture_id` | `"minimal-v1-arithmetic"` | 每个持久化信封与资产携带，必须等于 manifest 的 fixture_id |
| `jsonrpc` | `"2.0"`（const） | 严格 JSON-RPC 2.0，绝不允许 `1.0`/`2.1` |
| `message_id` | 字符串（1–128 字符） | 意图/信封文档的消息身份 |
| `id`（request/response） | 字符串或整数（oneOf） | 必须原样往返：响应 `id` 与请求 `id` 值、类型一致 |

## 3. 严格 JSON-RPC 2.0 与 fail-closed 规则

- `request`：`required = [jsonrpc, id, method, params, protocol_version, schema_version, fixture_id]`，`additionalProperties = false`。
- `response`：`required = [jsonrpc, id, protocol_version, schema_version, fixture_id]`；**`result` 与 `error` 互斥**（`oneOf` + `not`），两者同时出现或同时缺失都失败。
- `notification`：`required = [jsonrpc, method, params, protocol_version, schema_version, fixture_id]`。
- 错误对象：`code` 是**不受限的 JSON-RPC 整数**——Schema 本身**不**强制保留区间，只要求整数；`message` 必填；可选 `data.error_code` 携带 `AIPT_*` 语义错误码（第 6 节）。持久化确定性示例使用实现选择码 `-32000`（第 6 节，`B002_IMPLEMENTATION_CHOICE-009`）。
- 畸形信封、未知 `protocol_version`、未知 `schema_version`、未知方法、缺失必填参数一律 **fail closed**（const/enum/oneOf 直接拒绝；不降级、不猜测、不回退默认值）。

## 4. 最小通用方法注册表

- request 方法（仅此一个）：`aipt.protocol.applyAction`
- notification 方法（仅此一个）：`aipt.protocol.event`

本批次**不设计任何 worker 生命周期方法**（不定义 start/stop/health/status 等）。JSON-RPC 请求 `id` 就是请求身份；本迭代不发明任何 worker 生命周期。

## 5. 可见性模型（冻结的 R4-F002 六标签）

可见性是**强制元数据**，不是可选普通字段。每个 state/projected 字段必须携带：

```json
"visibility": {
  "label": "PUBLIC",
  "authorized_seat_ids": ["seat-a", "seat-b"]
}
```

`label` 只允许以下**恰好六个**冻结标签（其余任何标签 fail closed）：

1. `PUBLIC`
2. `UNRELEASED_REMOTE_ALLOWED`
3. `TABLE_HIDDEN_REMOTE_ALLOWED`
4. `LOCAL_ONLY_SECRET`
5. `HUMAN_PRIVATE_DATA`
6. `CREDENTIAL_SECRET`

`authorized_seat_ids` 非空（`minItems: 1`、`uniqueItems`）。

**全量状态投影合同**（schema 合法只是必要条件，语义门禁再判）：投影席位必须是已知席位（`AIPT_PROJECTION_UNKNOWN_SEAT`）；state 与投影中都不得出现重复 `field_id`（`AIPT_STATE_DUPLICATE_FIELD_ID` / `AIPT_PROJECTION_DUPLICATE_FIELD_ID`）；每个投影字段值必须与源 state 值深度相等（`AIPT_PROJECTION_VALUE_DRIFT`）；标签不得重分类（`AIPT_VISIBILITY_RECLASSIFIED`）；`authorized_seat_ids` 按**数学集合**比较——仅顺序不同不算授权漂移（`AIPT_VISIBILITY_AUTHORIZATION_DRIFT`）；state 可见性不得授权未知席位（`AIPT_VISIBILITY_UNKNOWN_SEAT`）；投影不得包含未授权席位字段（`AIPT_VISIBILITY_UNAUTHORIZED_FIELD`）；投影不得遗漏任何授权给该投影席位的字段（`AIPT_PROJECTION_MISSING_AUTHORIZED_FIELD`）。缺失可见性（schema 拒绝）与未知标签（enum 拒绝）同样 fail closed。

## 6. 错误命名空间

- 传输/框架层错误沿用 JSON-RPC 约定码（如 `-32602` invalid params）；协议语义错误置于 `error.data.error_code`，命名空间 `AIPT_[A-Z0-9_]+`，例如 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD`。
- **唯一文档化、确定性的 AIPT 协议错误示例**（`B002_IMPLEMENTATION_CHOICE-009`）：持久化文件 `responses/apply-action-protocol-error-response.json` 使用**实现选择**的服务器/应用码 `code = -32000`，`data.error_code = "AIPT_VISIBILITY_UNAUTHORIZED_FIELD"`，`message = "table-note is not authorized for seat-b (AIPT_VISIBILITY_UNAUTHORIZED_FIELD)"`。Schema 的 `code` 仍是普通整数，不声称强制保留区间。

## 7. 最小确定性夹具语义（testdata/protocol/v1/minimal-fixture/）

- `fixture_id = minimal-v1-arithmetic`；游戏中立、无叙事、无 Canon/Rule/Scene/NPC/Item 内容。
- **canonical JSON 规则**：对象键递归排序、数组保序、无多余空白；所有摘要/重放哈希均为该规则的 SHA-256（64 位小写十六进制）。
- `manifest.json` 记录**每个资产**的路径、类型、schema `$ref` 目标与 SHA-256 摘要；任何未登记文件、缺失文件或摘要漂移一律 fail closed。
- **manifest 加固（先于任何资产读取）**：路径必须是相对、规范化、无绝对形式/`.`/`..` 段/反斜杠/NUL 的形式（任何条目都不得引发夹具目录之外的读取）；资产与突变路径不得重复；`kind -> schema_ref` 使用验证器内置的**精确映射表**校验，绝不信任 manifest 自己声明的任意 `$ref`。

| 资产 | 类型 / schema_ref | 语义 |
|---|---|---|
| `seats.json` | `seat_set` / `#/$defs/seat_set` | 恰好两个席位：`seat-a`、`seat-b` |
| `state.json` | `state` / `#/$defs/state` | 初始状态：`turn-count`（`PUBLIC`，双方可见）+ `table-note`（`TABLE_HIDDEN_REMOTE_ALLOWED`，仅 `seat-a`）；field_id 唯一、只授权已知席位 |
| `projection-seat-a.json` | `projection` / `#/$defs/projection` | `seat-a` 投影：两个字段都在（值、标签、授权集合与源 state 深度一致） |
| `projection-seat-b.json` | `projection` / `#/$defs/projection` | `seat-b` 投影：仅 `turn-count`（隐藏字段不外泄） |
| `action-intent.json` | `action_intent` / `#/$defs/action_intent` | 一个通用动作意图：`advance-turn`（`aipt.protocol.applyAction`，含提案负载） |
| `requests/apply-action-request.json` | `jsonrpc_request` / `#/$defs/jsonrpc_request` | 一个有效 `applyAction` 请求（`id = "minimal-v1-arithmetic-request-1"`，字符串）；`params` 与 `action-intent.json` 的 params 深度相等（交叉链接） |
| `check-turn-increment.json` | `deterministic_check` / `#/$defs/deterministic_check` | 版本化算术检查（`check_version = 1.0.0`，`add`）：固定输入 `[0, 1]` → 固定输出 `1` |
| `transition.json` | `state_transition` / `#/$defs/state_transition` | 一个状态迁移：`initial → final`，结果仅更新 `turn-count` 为 `1` |
| `responses/apply-action-result-response.json` | `jsonrpc_response` / `#/$defs/jsonrpc_response` | 有效结果响应：`id` 与请求 `id` **值、类型**一致；`result.transition_id` 链接 `transition.json`，`result.applied_fields` 与 `transition.json` 的 result 深度相等、并与 `final-state.json` 的值/可见性一致（交叉链接） |
| `responses/apply-action-protocol-error-response.json` | `jsonrpc_response` / `#/$defs/jsonrpc_response` | 有效协议错误响应（已知请求 id）：`code = -32000` + `data.error_code = AIPT_VISIBILITY_UNAUTHORIZED_FIELD`（CHOICE-009 确定性示例） |
| `event.json` | `state_event` / `#/$defs/state_event` | 一个事件：`state_transition_applied`，记录 `initial → final` |
| `notifications/state-event-notification.json` | `jsonrpc_notification` / `#/$defs/jsonrpc_notification` | 有效 `aipt.protocol.event` 通知：`params.event` 与 `event.json` **精确深度相等** |
| `final-state.json` | `state` / `#/$defs/state` | 期望最终状态 |
| `replay-assertion.json` | `replay_assertion` / `#/$defs/replay_assertion` | 重放断言：canonical JSON 的 SHA-256 与两条 replay 记录同哈希，证明两次重放得到同一最终状态/哈希 |
| `mutants/hidden-leak.json` | `mutant_specimen` / `#/$defs/mutant_specimen` | 隐藏泄露突变（见下） |

**Mutant 政策**：突变只存在于 `mutants/` 目录；必须携带精确标记 `["NON_CANON", "MUTANT"]` 与 `kind = "hidden-leak"`；该突变把 `seat-a` 的隐藏字段 `table-note` 放进 `seat-b` 的投影，**先通过 schema 校验**（证明它是语义缺陷而非语法错误），再被语义门禁以**唯一且稳定**的原因 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD` 拒绝——绝不因无关的 JSON/schema 语法问题被拒绝。

## 8. 验证器与运行方式

- 依赖自由子集验证器：[scripts/ci/lib/json-schema.mjs](../../scripts/ci/lib/json-schema.mjs)。**明确支持的关键字**：`$ref`、`type`、`const`、`enum`、`properties`、`required`、`additionalProperties`、`items`、`minItems`、`maxItems`、`uniqueItems`、`minLength`、`maxLength`、`pattern`、`minimum`、`maximum`、`exclusiveMinimum`、`exclusiveMaximum`、`multipleOf`、`minProperties`、`maxProperties`、`oneOf`、`anyOf`、`allOf`、`not`；允许的注释关键字：`title`/`description`/`examples`/`default`/`deprecated`/`$comment`。**任何其它功能关键字（如 `format`、`if`/`then`/`else`、`unevaluatedProperties`、`contains`、`$dynamicRef`）一律报错拒绝，绝不静默忽略**。`$ref` 仅解析本地 `#/...` 引用；无效引用与引用环被检测并拒绝。验证器自身用内存探针证明：不支持的功能关键字被拒（`unsupported functional schema keyword`）、外部/未解析 `$ref` 被拒（`external`）、本地 `$ref` 环被拒（`cycle`）——每个原因都稳定可断言。
- 协议资产门禁：[scripts/ci/validate/protocol-assets.mjs](../../scripts/ci/validate/protocol-assets.mjs)。覆盖：schema 文档子集合规与冻结常量、可执行根（`oneOf`）、manifest 加固（路径安全/重复路径/kind→ref 精确映射，先于任何读取）、精确清单与摘要、每个正例资产对声明 `$ref` 的校验、身份/版本一致性、持久化 wire 信封（request 与 action-intent 交叉链接；result 响应与 transition/final-state 交叉链接；错误响应 `-32000` + `AIPT_*`；通知精确包裹 `event.json`）、request/response id 值与类型往返、方法注册表、全量状态投影合同（重复 field_id、值漂移、未知席位/授权、遗漏授权字段）、检查输出、迁移结果、事件、重放哈希/确定性，以及隐藏泄露突变（先 schema 后语义）。
- 负向探针（每个必须按**正确契约原因**被拒绝，共 23 个）：九个冻结的迭代 2 探针——`jsonrpc != 2.0`；未知 `protocol_version`；未知 `schema_version`；请求缺 `params`；响应同时携带 `result` 与 `error`；未知方法；缺失可见性；未知可见性标签；隐藏泄露突变（`AIPT_VISIBILITY_UNAUTHORIZED_FIELD`）。迭代 3 新增——任意/畸形根信封对 `#` 被拒（`oneOf`）；state 重复 `field_id`（`AIPT_STATE_DUPLICATE_FIELD_ID`）；投影重复 `field_id`（`AIPT_PROJECTION_DUPLICATE_FIELD_ID`）；投影值漂移（`AIPT_PROJECTION_VALUE_DRIFT`）；未知投影席位（`AIPT_PROJECTION_UNKNOWN_SEAT`）；state 可见性授权未知席位（`AIPT_VISIBILITY_UNKNOWN_SEAT`）；投影遗漏授权字段（`AIPT_PROJECTION_MISSING_AUTHORIZED_FIELD`）；manifest 不安全路径（dot 段 / 绝对路径）；manifest 重复路径；manifest kind/schema_ref 不匹配；helper 拒绝不支持关键字 / 外部 `$ref` / `$ref` 环。
- 运行：`pnpm run check:protocol-assets`（[package.json](../../package.json) 持久脚本），并已并入 [scripts/ci/run-checks.mjs](../../scripts/ci/run-checks.mjs)（`pnpm run check` 与公共 CI 均执行）。要求 Node.js 恰为 `v24.19.0`。

## 9. B002_IMPLEMENTATION_CHOICE 清单

- **CHOICE-001**：单一权威 Schema 根 + 本地 `$defs`；不在多个 schema 间复制 wire truth。
- **CHOICE-002**：JSON Schema 2020-12 + 明确声明的依赖自由子集（`lib/json-schema.mjs`）；未支持的功能关键字被拒绝而非忽略。
- **CHOICE-003**：`protocol_version = "1.0.0"`、`schema_version = "1.0.0"` 为 const，全部资产/信封携带并一致性校验；`fixture_id = "minimal-v1-arithmetic"` 同规则。
- **CHOICE-004**：最小通用方法注册表 = `aipt.protocol.applyAction`（request）+ `aipt.protocol.event`（notification）；不设计 worker 生命周期方法。
- **CHOICE-005**：可见性为强制元数据（六冻结标签 + 非空 `authorized_seat_ids`）；全量状态投影合同（重复 id、值漂移、集合比较授权、已知席位、无遗漏）使用稳定 `AIPT_*` 原因拒绝。
- **CHOICE-006**：夹具 manifest 记录每个资产的 schema `$ref` 与 canonical-JSON SHA-256；意外资产漂移 fail closed。
- **CHOICE-007**：协议语义错误命名空间 `AIPT_*`（置于 `error.data.error_code`）；传输层错误沿用 JSON-RPC 约定码。
- **CHOICE-008**：mutant 政策——仅 `mutants/`、精确 `NON_CANON`/`MUTANT` 标记、先 schema 校验后语义拒绝、固定拒绝原因。
- **CHOICE-009**：唯一确定性 AIPT 协议错误示例——`code = -32000`（服务器/应用实现选择码）+ `data.error_code = AIPT_VISIBILITY_UNAUTHORIZED_FIELD`；Schema 的 `code` 保持普通整数，不强制保留区间。
- **CHOICE-010**：持久化 wire 信封夹具（`requests/`、`responses/`、`notifications/`）各携带 `protocol_version`/`schema_version`/`fixture_id`，验证器从磁盘加载并交叉链接到 action-intent / transition / final-state / event，绝不只在内存重造等价信封。
- **CHOICE-011**：manifest 加固——路径安全（相对/规范化/无 dot 段/无绝对路径）、重复路径拒绝、`kind -> schema_ref` 精确映射表（不信任 manifest 自声明的 `$ref`），全部先于任何资产读取执行。

## 10. 本批次明确不建设

B002（含本迭代）**不新增任何 server/socket/worker/model/database 运行时**；本迭代不建设 Adapter SDK；本迭代不建设 Go 契约（`go.mod`/`go.sum` 不变）；本迭代不创建 `packages/` 与 `internal/protocol/`；`.github/`、`tools/`、`LICENSE` 与历史权威登记（decisions/supersessions/deferred）均保持不变。运行时状态保持 `not built yet`。

**路径准入是逐迭代的，不是永久禁令**：`packages/` 与 `internal/protocol/` 在本迭代被机械禁止，但 B002 主合同**明确要求**后续 B002 迭代建设 `packages/adapter-sdk`（TypeScript Adapter SDK）与 `internal/protocol`（Go 契约实现）；届时由该迭代自己的准入清单登记，本轮不预批准。

## 相邻文档

- [../authority/README.md](../authority/README.md)（Authority Index）· [../authority/PROJECT_STATUS.md](../authority/PROJECT_STATUS.md) · [../authority/BATCH_DEPENDENCY_GRAPH.md](../authority/BATCH_DEPENDENCY_GRAPH.md)
- [返回仓库首页](../../README.md)
