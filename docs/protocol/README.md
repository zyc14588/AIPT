# AIPT 协议契约（Protocol Contract, B002）

> 批次：`AIPT-M0-B002`（`B002_IN_PROGRESS`）· 迭代 5B（Go 协议契约消费者修复）· 状态日期 **2026-08-17**。
> 本页解释权威协议 Schema、最小确定性夹具（含持久化 wire 信封）、协议资产验证器、一方 TypeScript Adapter SDK 与 Go 协议契约消费者。机器可读权威是
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
| `message_id` | 字符串（1–128 字符） | **仅动作意图文档**（action_intent）的消息身份；JSON-RPC 信封不携带 `message_id`——信封的请求/响应身份是 `id`（见下） |
| `id`（request/response） | 字符串或整数（oneOf） | 必须原样往返：响应 `id` 与请求 `id` **值、类型**一致；整数由 `#/$defs/request_id_integer` 以 `minimum`/`maximum` 限定在 JavaScript 安全整数闭区间 `[-9007199254740991, 9007199254740991]`（±(2^53-1)），跨语言值恒等 |

## 3. 严格 JSON-RPC 2.0 与 fail-closed 规则

- `request`：`required = [jsonrpc, id, method, params, protocol_version, schema_version, fixture_id]`，`additionalProperties = false`。
- `response`：`required = [jsonrpc, id, protocol_version, schema_version, fixture_id]`；**`result` 与 `error` 互斥**（`oneOf` + `not`），两者同时出现或同时缺失都失败。
- `notification`：`required = [jsonrpc, method, params, protocol_version, schema_version, fixture_id]`。
- **跨语言安全整数 id**：整数 `id` 由 `#/$defs/request_id_integer` 用 `minimum = -9007199254740991`、`maximum = 9007199254740991`（±(2^53-1)，JavaScript 安全整数闭区间）限定。Node `JSON.parse` 把每个 JSON 数字读成 IEEE-754 double，区间外的整数 id 可能被静默舍入成与 Go（int64）消费者不同的值——Schema 在边界直接拒绝，保证同一 id 跨语言恒等；`jsonrpc_request` 与 `jsonrpc_response` 引用同一个 `request_id`，因此请求与响应应用完全相同的边界（整数 id 不被移除）。
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

- 传输/框架层错误沿用 JSON-RPC 约定码（如 `-32602` invalid params）；协议语义错误置于 `error.data.error_code`，命名空间 `AIPT_[A-Z0-9_]+`，例如 `AIPT_ACTION_REJECTED`（动作拒绝）或 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD`（可见性越权）。
- **唯一文档化、确定性的 AIPT 协议错误示例**（`B002_IMPLEMENTATION_CHOICE-009`）：持久化文件 `responses/apply-action-protocol-error-response.json` 引用持久化 `requests/apply-action-request.json`（advance-turn）的 id，使用**实现选择**的服务器/应用码 `code = -32000`、通用稳定的 `data.error_code = "AIPT_ACTION_REJECTED"`，以及确定性消息 `message = "advance-turn action request from seat-a was rejected (AIPT_ACTION_REJECTED)"`——错误描述的是它所引用的请求，而不是无关的席位/字段语义。Schema 的 `code` 仍是普通整数，不声称强制保留区间。`AIPT_VISIBILITY_UNAUTHORIZED_FIELD` **只属于** hidden-leak 突变（`mutants/hidden-leak.json` 的语义拒绝原因），任何 wire 错误都不得复用该码。

## 7. 最小确定性夹具语义（testdata/protocol/v1/minimal-fixture/）

- `fixture_id = minimal-v1-arithmetic`；游戏中立、无叙事、无 Canon/Rule/Scene/NPC/Item 内容。
- **canonical JSON 规则**：对象键递归排序、数组保序、无多余空白；所有摘要/重放哈希均为该规则的 SHA-256（64 位小写十六进制）。
- `manifest.json` 记录**每个资产**的路径、类型、schema `$ref` 目标与 SHA-256 摘要；任何未登记文件、缺失文件或摘要漂移一律 fail closed。
- **manifest 加固（先于任何资产读取，任一预检问题即整轮失败）**：路径必须是相对、规范化、无绝对形式/`.`/`..` 段/反斜杠/NUL 的形式（任何条目都不得引发夹具目录之外的读取）；资产与突变路径不得重复；`kind -> schema_ref` 使用验证器内置的**精确映射表**校验，绝不信任 manifest 自己声明的任意 `$ref`。**路径/重复路径/kind→ref 预检一旦有任何问题，门禁立即失败返回，任何 manifest 列出的资产都不会被解析或读取（绝不带着失败预检进入读取循环）**。对预检干净的条目，读取前依次执行：词法包含检查（解析路径必须仍在夹具目录内）→ `lstat` 只接受**常规文件**（符号链接、目录、设备及其它非常规条目一律先于读取拒绝）→ `realpath` 证明解析全部链接后的真实目标**严格位于夹具目录内**（纵深防御），然后才读取该真实路径。

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
| `responses/apply-action-protocol-error-response.json` | `jsonrpc_response` / `#/$defs/jsonrpc_response` | 有效协议错误响应（引用 advance-turn 请求的 id）：`code = -32000` + `data.error_code = AIPT_ACTION_REJECTED` + 确定性拒绝消息（CHOICE-009 确定性示例；与所引用的请求一致，不复用突变可见性码） |
| `event.json` | `state_event` / `#/$defs/state_event` | 一个事件：`state_transition_applied`，记录 `initial → final` |
| `notifications/state-event-notification.json` | `jsonrpc_notification` / `#/$defs/jsonrpc_notification` | 有效 `aipt.protocol.event` 通知：`params.event` 与 `event.json` **精确深度相等** |
| `final-state.json` | `state` / `#/$defs/state` | 期望最终状态 |
| `replay-assertion.json` | `replay_assertion` / `#/$defs/replay_assertion` | 重放断言：canonical JSON 的 SHA-256 与两条 replay 记录同哈希，证明两次重放得到同一最终状态/哈希 |
| `mutants/hidden-leak.json` | `mutant_specimen` / `#/$defs/mutant_specimen` | 隐藏泄露突变（见下） |

**Mutant 政策**：突变只存在于 `mutants/` 目录；必须携带精确标记 `["NON_CANON", "MUTANT"]` 与 `kind = "hidden-leak"`；该突变把 `seat-a` 的隐藏字段 `table-note` 放进 `seat-b` 的投影，**先通过 schema 校验**（证明它是语义缺陷而非语法错误），再被语义门禁以**唯一且稳定**的原因 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD` 拒绝——绝不因无关的 JSON/schema 语法问题被拒绝。

## 8. 验证器与运行方式

- 依赖自由子集验证器：[scripts/ci/lib/json-schema.mjs](../../scripts/ci/lib/json-schema.mjs)。**明确支持的关键字**：`$ref`、`type`、`const`、`enum`、`properties`、`required`、`additionalProperties`、`items`、`minItems`、`maxItems`、`uniqueItems`、`minLength`、`maxLength`、`pattern`、`minimum`、`maximum`、`exclusiveMinimum`、`exclusiveMaximum`、`multipleOf`、`minProperties`、`maxProperties`、`oneOf`、`anyOf`、`allOf`、`not`；允许的注释关键字：`title`/`description`/`examples`/`default`/`deprecated`/`$comment`。**任何其它功能关键字（如 `format`、`if`/`then`/`else`、`unevaluatedProperties`、`contains`、`$dynamicRef`）一律报错拒绝，绝不静默忽略**。`$ref` 仅解析本地 `#/...` 引用；无效引用与引用环被检测并拒绝。验证器自身用内存探针证明：不支持的功能关键字被拒（`unsupported functional schema keyword`）、外部/未解析 `$ref` 被拒（`external`）、本地 `$ref` 环被拒（`cycle`）——每个原因都稳定可断言。
- 协议资产门禁：[scripts/ci/validate/protocol-assets.mjs](../../scripts/ci/validate/protocol-assets.mjs)。覆盖：schema 文档子集合规与冻结常量、可执行根（`oneOf`）、跨语言安全整数 id 边界（`minimum`/`maximum` = ±(2^53-1)，请求与响应共用同一 `request_id`）、manifest 加固（路径安全/重复路径/kind→ref 精确映射预检，**任一预检问题即在解析或读取任何列出资产之前失败返回**；预检干净条目再经词法包含 → `lstat` 仅常规文件 → `realpath` 严格包含后才读取）、精确清单与摘要、每个正例资产对声明 `$ref` 的校验、身份/版本一致性（普通资产与突变内嵌投影任一漂移即显式 FAIL，稳定原因 `AIPT_FIXTURE_IDENTITY_MISMATCH`）、持久化 wire 信封（request 与 action-intent 交叉链接；result 响应与 transition/final-state 交叉链接；错误响应 `-32000` + `AIPT_ACTION_REJECTED` + 确定性 advance-turn 拒绝消息，与所引用请求一致；通知精确包裹 `event.json`）、request/response id 值与类型往返（含安全整数边界值）、方法注册表、全量状态投影合同（重复 field_id、值漂移、未知席位/授权、遗漏授权字段）、检查输出、迁移结果、事件、重放哈希/确定性，以及隐藏泄露突变（先 schema 后语义，且是 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD` 的唯一夹具）。
- 负向探针（每个必须按**正确契约原因**被拒绝，共 33 个）：九个冻结的迭代 2 探针——`jsonrpc != 2.0`；未知 `protocol_version`；未知 `schema_version`；请求缺 `params`；响应同时携带 `result` 与 `error`；未知方法；缺失可见性；未知可见性标签；隐藏泄露突变（`AIPT_VISIBILITY_UNAUTHORIZED_FIELD`）。迭代 3 新增——任意/畸形根信封对 `#` 被拒（`oneOf`）；state 重复 `field_id`（`AIPT_STATE_DUPLICATE_FIELD_ID`）；投影重复 `field_id`（`AIPT_PROJECTION_DUPLICATE_FIELD_ID`）；投影值漂移（`AIPT_PROJECTION_VALUE_DRIFT`）；未知投影席位（`AIPT_PROJECTION_UNKNOWN_SEAT`）；state 可见性授权未知席位（`AIPT_VISIBILITY_UNKNOWN_SEAT`）；投影遗漏授权字段（`AIPT_PROJECTION_MISSING_AUTHORIZED_FIELD`）；manifest 不安全路径（dot 段 / 绝对路径）；manifest 重复路径；manifest kind/schema_ref 不匹配；helper 拒绝不支持关键字 / 外部 `$ref` / `$ref` 环。迭代 3B 新增（10 个）——整数 id 超出安全整数上界 / 下界（`maximum` / `minimum`）；request 信封 id 超出上界 / 下界（同一边界作用于请求与响应，`oneOf` 拒绝）；response 信封 id 超出上界 / 下界；突变内嵌投影 `fixture_id` 漂移（保持 schema 合法，`AIPT_FIXTURE_IDENTITY_MISMATCH`）；普通资产 `fixture_id` 漂移（保持 schema 合法，`AIPT_FIXTURE_IDENTITY_MISMATCH`）；根内符号链接指向夹具根之外的目标（临时目录确定性探针，`lstat` 以符号链接/非常规文件原因先于读取拒绝）；wire 错误响应复用突变可见性码（`AIPT_PROTOCOL_ERROR_MISMATCHED_ERROR_CODE`）。
- 运行：`pnpm run check:protocol-assets`（[package.json](../../package.json) 持久脚本），并已并入 [scripts/ci/run-checks.mjs](../../scripts/ci/run-checks.mjs)（`pnpm run check` 与公共 CI 均执行）。要求 Node.js 恰为 `v24.19.0`。
- Adapter SDK 机器门禁（迭代 4/4B/4C/4D）：`pnpm run check:adapter-sdk`（[scripts/ci/validate/adapter-sdk.mjs](../../scripts/ci/validate/adapter-sdk.mjs)），同样并入 `pnpm run check`；独立依赖自由的协议资产验证器保持为**独立预言机**，SDK 门禁绝不削弱、删除或别名其检查。迭代 4B 门禁新增：契约漂移清单扩展为完整功能投影 + 权威 Schema **全量内容指纹**（任何 Schema 编辑都必须显式复审）、对 `src/types.ts` **实际声明的公开接口形状**（全部 25 个公开 wire/夹具类型的必填/可选/判别成员）的 schema 派生审计、53 个负向探针（43 个 fail-closed 行为探针 + 8 个内存漂移探针 + hidden-leak 突变探针 + 未来 wire 错误码探针）。迭代 4C 门禁新增：**91 项成员类型表达式审计**（每个公开接口成员的声明类型表达式与 schema 派生期望逐一比对，含嵌套对象形状与描述符派生 const/判别类型；`StateField.value: JsonValue → string`、嵌套成员类型漂移、`ManifestMutant.expected_semantic_rejection` 扩宽为 `AiptErrorCode` 均以内存漂移探针证明可检出）、canonical schema 指纹绑定探针（描述漂移/有损 schema → `AIPT_FIXTURE_INVALID_SCHEMA`）、schema 语法预检探针（隐藏于 anyOf 通过分支或 `not` 的 `format`、字符串 `minLength`、数组 `properties`、字符串 `additionalProperties`、未引用 `$defs` 子节点畸形 → `AIPT_FIXTURE_INVALID_SCHEMA`）、普通投影泄露探针（schema 合法的 hidden-leak 投影替换普通投影 + 摘要更新 → `AIPT_VISIBILITY_UNAUTHORIZED_FIELD`）、突变包装 `seat_id`/`leaked_field_id` 漂移探针（→ `AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT`）、精确清单探针（供应 `manifest.json` 文档条目 → `AIPT_FIXTURE_UNLISTED_ASSET`）、6 个零 getter/setter 调用与 manifest 预检无文档触碰探针，以及 wire 信任边界探针（顶层符号键/不可枚举成员、`id = -0`、非安全整数 `error.code`、显式 `undefined` 必填绕过）；探针篡改值与摘要一律由门禁自有 canonical JSON/SHA-256（`selfSha256`）独立构造，绝不把生产验证器/哈希器当作自身预言机。迭代 4D 门禁新增：同对象跨调用突变探针（首次接受后把 `minLength` 改为 `'not-a-number'`、向未引用 `spare` 定义新增 `format` → 下次调用必须 `AIPT_FIXTURE_INVALID_SCHEMA`）、未引用定义中的本地 `$ref` 环与自引用探针（→ `AIPT_FIXTURE_INVALID_SCHEMA`）、重复 `required` 成员 / 重复 `type` / JSON 相等重复 `enum` 探针、注解形状探针（`examples` 非数组、`deprecated` 非布尔、`title` 非字符串）、嵌套结构关键字探针（嵌套 `$schema`/`$id`/`$defs`）、根 `$schema` 非 2020-12 URI 与根 `$id` 非字符串探针、外部/不可解析 `$ref` 保持拒绝探针、十进制 `multipleOf` 非倍数探针（0.35 vs 0.1 → `AIPT_FIXTURE_SCHEMA_VIOLATION`）共 **18 个新 fail-closed 探针**，另有 **4 个正向语法探针**（空 `required` 接受、0.3 对 `multipleOf: 0.1` 接受、无环共享目标引用 + 重复非祖先 JS 别名接受、无 `$schema` 合成 schema 接受）；探针总数 **103 个**（80 fail-closed 行为 + 11 内存漂移 + 6 零调用/无文档触碰 + hidden-leak 突变 + 未来 wire 错误码 + 4 正向语法）。

## 9. B002_IMPLEMENTATION_CHOICE 清单

- **CHOICE-001**：单一权威 Schema 根 + 本地 `$defs`；不在多个 schema 间复制 wire truth。
- **CHOICE-002**：JSON Schema 2020-12 + 明确声明的依赖自由子集（`lib/json-schema.mjs`）；未支持的功能关键字被拒绝而非忽略。
- **CHOICE-003**：`protocol_version = "1.0.0"`、`schema_version = "1.0.0"` 为 const，全部资产/信封携带并一致性校验；`fixture_id = "minimal-v1-arithmetic"` 同规则。
- **CHOICE-004**：最小通用方法注册表 = `aipt.protocol.applyAction`（request）+ `aipt.protocol.event`（notification）；不设计 worker 生命周期方法。
- **CHOICE-005**：可见性为强制元数据（六冻结标签 + 非空 `authorized_seat_ids`）；全量状态投影合同（重复 id、值漂移、集合比较授权、已知席位、无遗漏）使用稳定 `AIPT_*` 原因拒绝。
- **CHOICE-006**：夹具 manifest 记录每个资产的 schema `$ref` 与 canonical-JSON SHA-256；意外资产漂移 fail closed。
- **CHOICE-007**：协议语义错误命名空间 `AIPT_*`（置于 `error.data.error_code`）；传输层错误沿用 JSON-RPC 约定码。
- **CHOICE-008**：mutant 政策——仅 `mutants/`、精确 `NON_CANON`/`MUTANT` 标记、先 schema 校验后语义拒绝、固定拒绝原因。
- **CHOICE-009**：唯一确定性 AIPT 协议错误示例——`code = -32000`（服务器/应用实现选择码）+ 通用稳定的 `data.error_code = AIPT_ACTION_REJECTED` + 确定性消息 `"advance-turn action request from seat-a was rejected (AIPT_ACTION_REJECTED)"`（描述其引用的 advance-turn 请求）；Schema 的 `code` 保持普通整数，不强制保留区间；`AIPT_VISIBILITY_UNAUTHORIZED_FIELD` 只属于 hidden-leak 突变，wire 错误不得复用。
- **CHOICE-010**：持久化 wire 信封夹具（`requests/`、`responses/`、`notifications/`）各携带 `protocol_version`/`schema_version`/`fixture_id`，验证器从磁盘加载并交叉链接到 action-intent / transition / final-state / event，绝不只在内存重造等价信封。
- **CHOICE-011**：manifest 加固——路径安全（相对/规范化/无 dot 段/无绝对路径）、重复路径拒绝、`kind -> schema_ref` 精确映射表（不信任 manifest 自声明的 `$ref`），全部先于任何资产读取执行。
- **CHOICE-012**（迭代 3B）：跨语言安全 JSON-RPC 整数 id——`#/$defs/request_id_integer` 以 `minimum`/`maximum` 限定 `[-9007199254740991, 9007199254740991]`（±(2^53-1)）；Node `JSON.parse` 的 IEEE-754 double 无法无损表示区间外整数，可能改变 Go 消费者看到的同一 id，因此在 Schema 边界拒绝；请求与响应共用同一 `request_id`，整数 id 保留不清除。
- **CHOICE-013**（迭代 3B）：夹具身份显式失败门——纯函数 `checkFixtureIdentity` 对普通资产与突变包装的内嵌投影统一返回稳定原因 `AIPT_FIXTURE_IDENTITY_MISMATCH`；任何 false 聚合都是显式 FAIL，绝不静默通过。
- **CHOICE-014**（迭代 3B）：预检失败即中止 + lstat/realpath 包含——路径/重复路径/kind→ref 预检任一问题立即失败返回，任何列出资产都不会被解析或读取；预检干净条目读取前依次 lstat（仅常规文件，符号链接/目录/设备先于读取拒绝）与 realpath（真实目标严格位于夹具目录内）。
- **CHOICE-015**（迭代 3B）：wire 错误与所引用请求一致——持久化协议错误对 advance-turn 请求使用 `AIPT_ACTION_REJECTED` 与确定性消息；`checkWireErrorCoherence` 拒绝复用突变可见性码的 wire 错误（`AIPT_PROTOCOL_ERROR_MISMATCHED_ERROR_CODE`）。

## 10. Adapter SDK（B002 迭代 4/4B/4C/4D）

- 一方 TypeScript 契约 SDK：[packages/adapter-sdk](../../packages/adapter-sdk/)（`@aipt/adapter-sdk@1.0.0`，MIT）。**零第三方依赖**：仅 Node.js 24 标准库（`node:crypto`、`node:test`），原生可擦除 TypeScript 语法（无编译器/框架/代码生成器/网络产物）。
- **权威单一来源**：权威 wire 真相仍是 `schemas/protocol/v1/aipt-protocol.schema.json`，Schema **不被复制进包内**。SDK 内嵌 fail-closed 契约漂移清单 `src/contract/descriptor.ts`（协议/模式/JSON-RPC 版本、方法注册表、信封变体与必填字段、安全整数 id 边界、六个可见性标签、错误码模式、manifest 冻结常量与精确 `kind→schema_ref` 映射表、确定性检查/重放断言/突变标本常量等的**完整确定性投影**，外加权威 Schema 文档的 **SHA-256 全量内容指纹**）；机器门禁在 CI 时刻从权威 Schema **独立重推导**同一清单并要求 canonical JSON 逐字节相等、全量指纹一致——Schema 或 SDK 常量/类型的任何漂移（包括投影字段之外的 Schema 编辑）都无法静默通过；门禁还以确定性源形状审计**实际解析 `src/types.ts` 声明的全部公开接口**（25 个 wire/夹具类型的必填/可选/判别成员）与 schema 派生期望逐一比对，并含 8 个内存漂移负向探针（嵌套必填成员、manifest const、kind→ref 映射、全量指纹、可选→必填、成员改名、未审查新增成员、错误码类型表面）。生产包代码不深导入 `scripts/ci` 内部实现。
- **无损 JSON 值门禁（迭代 4B）**：纯函数、路径寻址的 `validateJsonValue`（返回无效 `ValidationResult`）与 `requireJsonValue`（抛出 `ProtocolValidationError`）在**每个信任边界**运行——schema 有意接受任意 JSON 值的位置（`state_field.value`、`action_intent_params.proposal` 与任意嵌套 JSON 值）与通用解析输出在作为 `JsonValue` 返回之前都必须过门禁。循环引用、undefined/function/symbol/bigint、非有限数、非安全整数（`parseJson('9007199254740993')` 直接拒绝，绝不静默舍入）、-0、访问器/不可枚举/符号键属性、非普通对象、稀疏数组洞与数组非索引属性一律 `AIPT_LOSSY_JSON_VALUE`；有效普通 JSON、共享夹具与 request-id 行为保持不变；校验绝不改写调用方输入。
- **夹具 manifest 预检 + 全文档验证（迭代 4B）**：`validateFixtureManifest` 强制冻结常量 `expected_final_state = final-state.json`、`replay_assertion = replay-assertion.json`，全部必填/多余成员约束、恰好一个突变及其精确常量，路径必须为相对规范化 POSIX 形式（无绝对路径/`.`/`..` 段/反斜杠/空段/规范化漂移），资产+突变路径唯一，且 `kind → schema_ref` 走清单内**精确映射表**（含 `mutant_specimen`，绝不信任 manifest 自声明的 `$ref`，失配以稳定路径寻址码 `AIPT_FIXTURE_SCHEMA_REF_MISMATCH` 拒绝）；预检失败即整轮停止——任何资产文档都不会被哈希或解读。`validateFixtureBundle` 对每个供应文档依次执行：无损 JSON 门禁 → canonical SHA-256 摘要 → 包内依赖自由的 canonical JSON Schema 2020-12 子集求值器（`validateSchemaInstance`，按 kind 派生的目标 `$defs` 校验，含完整突变包装；未支持功能关键字/外部或不可解析 `$ref`/引用环一律 fail closed）→ 身份三元组（突变经内嵌投影）→ 精确清单；此外证明 manifest 突变对同一 bundle 供应的游戏中立席位/状态文档**实际产生且仅产生**其声明的 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD` 语义拒绝（摘要正确的中性/不拒绝突变以 `AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT` 失败）。schema 文档由调用方显式传入（第二参数或 `bundle.schema`），测试与门禁加载仓库唯一 Schema 传入，包内不复制 Schema、不读取仓库文件系统。
- **迭代 4C 加固（Codex 独立探针确认的更深 fail-open 缺口）**：
  1. **零调用无损门禁**：`validateJsonValue` 只检查自有属性描述符、绝不读取被拒绝属性、绝不调用任何 getter/setter（含数组索引访问器与访问器 `length` 描述符的防御检查）；数组符号键、不可枚举额外属性、访问器索引、稀疏洞与非法索引描述符全部 `AIPT_LOSSY_JSON_VALUE`，普通 JSON 与重复非祖先共享引用不变；测试与门禁均以 getter 计数器证明零调用。
  2. **全值信任边界门禁**：每个公开 wire/state/projection/request-id/manifest 校验器与 `validateSchemaInstance` 的 schema/document 输入在结构访问前先过全值无损门禁——`toJsonRpcRequest` 顶层符号键/不可枚举成员与 `id = -0`、`toJsonRpcErrorResponse` 非安全整数 `error.code`、显式 `undefined`/访问器成员绕过必填分支一律拒绝；`validate*` 返回带 `AIPT_LOSSY_JSON_VALUE` 的无效结果，`to/parse/decode/build/encode` 抛 `ProtocolValidationError`，绝不返回部分受信值；安全整数 id 边界与合法 wire 行为保持不变。
  3. **canonical schema 指纹绑定**：manifest 预检之后、任何资产文档处理之前，`validateFixtureBundle` 要求供应 schema 是有损无（lossless）JSON 文档且其 canonical SHA-256 恰等于 `CONTRACT_DESCRIPTOR.canonical_schema_sha256`；缺失/畸形/有损/指纹漂移一律 `AIPT_FIXTURE_INVALID_SCHEMA`；`validateSchemaInstance` 仍是通用包内受支持子集求值器（仅 bundle 兼容性要求精确指纹）。
  4. **schema 语法预检**：求值器在任何实例求值前对整个 schema 文档做确定性递归语法预检（关键字值形状/范围、非负整数边界关键字、布尔标志、字符串 pattern、受支持类型名、`properties`/`items`/`additionalProperties`/组合分支/`not`/`$defs` 子节点、本地引用与注释形状）；隐藏于 anyOf/oneOf 通过分支或 `not` 内的非法关键字、字符串 `minLength`、数组 `properties`、字符串 `additionalProperties` 全部 `AIPT_FIXTURE_INVALID_SCHEMA`，非法 schema 问题沿组合器传播、绝不折算为普通分支失配；`const` 按自有成员存在判定（null/false/0 均生效）；外部/未解析引用与引用环仍被拒绝；包不复制 canonical schema、不深导入 scripts/ci 内部。
  5. **普通投影语义门禁**：schema 合法不等于语义合法——所有干净 seat/state/projection 资产收集后，每个普通投影资产必须以供应 known seats 对至少一个兼容供应 state 通过 `validateProjectionSemantics`；失败时传播稳定语义问题（含 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD`），隐藏数据绝不可能作为普通投影通过；不硬编码任何夹具路径/席位/字段/游戏内容。
  6. **突变包装元数据绑定**：包装 `seat_id` 必须等于 `projection.seat_id`，`leaked_field_id` 必须等于唯一产生声明拒绝（`AIPT_VISIBILITY_UNAUTHORIZED_FIELD`）的字段；元数据漂移以 `AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT` 失败；**精确清单即精确**——供应文档中的 `manifest.json` 条目按未登记文档拒绝（无豁免）。
  7. **公开类型漂移合同完成**：`ManifestMutant.expected_semantic_rejection` 收紧为 `(typeof CONTRACT_DESCRIPTOR)['mutant_expected_semantic_rejection']` 精确字面量；`ValidationIssue.code` 仍为有限 `AiptErrorCode` 联合，`ErrorObject.data.error_code` 仍为开放正则门禁 `AiptWireErrorCode`；机器门禁对每个公开 wire/夹具接口的**声明成员类型表达式与嵌套形状**做 schema 派生审计（91 项），并以内存负向探针证明（a）`StateField.value: JsonValue → string`、（b）嵌套成员类型漂移、（c）突变字面量扩宽均被检出；TypeScript 无法表达的正则/数值边界（`Identifier`/`FixtureId`/安全整数/`AIPT_*` 模式）由运行时校验承担，文档相应收敛表述。
- **迭代 4D 加固（Codex 独立源码评审与原始实现探针确认的求值器缺口）**：
  1. **同对象跨调用观察**：调用方传入的可变 schema 对象是信任边界——schema 语法预检**每次公开校验调用全新执行**，绝不按对象身份跨调用复用 PASS（无预检缓存），不复制/冻结/变异调用方数据、不触发访问器；同一对象先通过再被突变（`minLength: 'not-a-number'`、未引用 `spare` 定义新增 `format`）后，下一次调用必须观察当前内容并以 `AIPT_FIXTURE_INVALID_SCHEMA` 拒绝。
  2. **全文档本地 `$ref` 环检测**：预检以显式访问中/已完成状态遍历完整本地引用图——未引用 `$defs` 子节点中的 `a→b→a` 环与自引用在任何实例求值之前以 `AIPT_FIXTURE_INVALID_SCHEMA` 拒绝；无环 DAG/共享目标引用与重复非祖先 JS 对象别名保持有效，普通包含遍历绝不误判为引用环（循环容器结构已先被无损 JSON 门禁拒绝）。
  3. **声明语法内部精确化**：`required: []` 为合法 JSON Schema 2020-12 予以接受，成员仍须为唯一字符串；`type` 数组必须非空、仅含支持类型名且无重复（`['string','string']` 畸形）；`enum` 必须非空且 JSON 语义唯一（重复成员确定性拒绝）；`title`/`description`/`$comment` 必须字符串、`examples` 必须数组、`deprecated` 必须布尔、`default` 可为任意无损 JSON 值；`$schema`/`$id`/`$defs` 为**仅限根**的结构关键字（`$schema` 存在时必须恰为 `https://json-schema.org/draft/2020-12/schema`、`$id` 必须字符串、`$defs` 必须为受支持 schema 节点的根对象），嵌套结构关键字拒绝而非静默忽略；无 `$schema` 的合成包内 schema 文档仍合法；包内 `items`/`properties`/组合器分支的对象唯一 schema 节点选择保持不变，本轮不拓宽方言。
  4. **十进制 `multipleOf` 修复**：与仓库独立标准库预言机一致，`q = 实例 / multipleOf`，`abs(q - round(q)) <= 1e-9` 判定为倍数——0.3 对 `multipleOf: 0.1` 通过，邻近非倍数（0.35、0.30000001）仍以 `AIPT_FIXTURE_SCHEMA_VIOLATION` 拒绝，容差不把任意值放行。
- 公开契约：规范常量与派生字面量联合类型（无 `any` 导出，`unknown` 仅限验证边界）；确定性 canonical JSON（递归键排序）与 SHA-256；可执行根的确定性 parse/decode/encode 与四类信封的类型化 builder（request id 按值**与 JSON 类型**往返，整数限定 ±(2^53-1) 闭区间）；语义投影验证（缺失/未知可见性与未授权隐藏字段 fail closed，隐藏数据绝不当作普通可选字段；迭代 4B 追加投影 `fixture_id` 必须等于源 state 的 `fixture_id`（`AIPT_FIXTURE_IDENTITY_MISMATCH`）、已知席位列表按标识符校验并确定性拒绝重复/非法条目、state/投影值先过无损门禁）；**wire 错误码类型修复**：`ErrorObject.data.error_code` 现为开放 canonical wire 命名空间类型 `AiptWireErrorCode`（branded，运行时正则强制，未来合法值如 `AIPT_FUTURE_EXTENSION` 被接受），`ValidationIssue.code` 仍是有限稳定 SDK 码联合 `AiptErrorCode`，绝不扩宽为任意字符串；迭代 4C 起 `ManifestMutant.expected_semantic_rejection` 为描述符派生的精确字面量（`(typeof CONTRACT_DESCRIPTOR)['mutant_expected_semantic_rejection']`），不再是宽泛 `AiptErrorCode`；新增公开夹具协议类型 `Seat`/`SeatSet`/`DeterministicCheck`/`StateTransition`/`ReplayAssertion`/`ReplayRecord`/`MutantSpecimen`。SDK 不硬编码任何夹具专属 seat id / field id / 动作名 / 迁移 id / 游戏内容；测试消费仓库公共的权威 Schema 与共享最小夹具。
- 无导入副作用：SDK 不连接模型、不 spawn 进程、不打开 socket、不访问数据库、不启动服务/worker、不读环境凭据、导入时零环境工作（测试与门禁均含干净子进程导入探针与环境访问陷阱探针）。
- 运行：`pnpm --filter @aipt/adapter-sdk test`（`node:test`/`assert`，确定性、密封、无外部网络；**122 项测试**——迭代 4 的 53 项与迭代 4B 的 90 项全部保留并新增 17 项迭代 4C 聚焦测试与 15 项迭代 4D 求值器聚焦测试）；`pnpm run check:adapter-sdk`（机器门禁，**103 个探针**：80 个 fail-closed 行为探针（含全部已确认误接受修复探针与 18 个迭代 4D 求值器探针）+ 11 个内存漂移探针 + 6 个零调用/无文档触碰探针 + hidden-leak 突变探针 + 未来 wire 错误码探针 + 4 个正向语法探针；已并入 `pnpm run check`）。

## 11. Go 协议契约消费者（B002 迭代 5/5B）

- **依赖自由、纯协议 Go 包**：[internal/protocol](../../internal/protocol/)（模块 `github.com/zyc14588/AIPT`，`go 1.26.x` / `toolchain go1.26.5`）。仅用 Go 标准库；**`go.mod`/`go.sum` 不变、零第三方依赖**。生产 API 纯函数化：无文件 I/O、无环境访问、无进程/网络/socket/数据库、无服务循环/goroutine worker/模型调用——不是 Core 运行时、规则引擎、服务、启动器或 Adapter。
- **schema 派生的精确常量**：`protocol_version`/`schema_version` = `1.0.0`、`jsonrpc` = `2.0`、方法注册表恰为 `aipt.protocol.applyAction`（request）+ `aipt.protocol.event`（notification）、安全整数 id 闭区间 ±(2^53-1)、恰好六个冻结 R4-F002 可见性标签。测试从权威 Schema 的本地 `$defs` **独立重推导**全部常量/注册表/边界/标签并与 Go 常量逐项比对（不实现通用 JSON Schema 求值器），任何手写常量漂移都让测试失败。
- **严格 fail-closed JSON 与信封解码**：自有严格解析器（标准库之上）拒绝空/畸形输入、尾随 JSON 值、**任意深度**的重复对象成员名（含转义键）、未知成员、缺失必填成员（含显式 null / 零值绕过）、非有限/溢出数字、跨语言安全区间外的整数（绝不静默舍入）、负零（`-0`/`-0.0`/`-0e0`）；`json.RawMessage` 承载任意 JSON 字段（`state_field.value`/`proposal`），绝不 `interface{}` + 未检查断言。`RequestID` 保留字符串 vs 数字的 **JSON 类型**与精确值并原样往返（字符串 1..128 字符、数字为闭区间内整数；拒绝空/超长字符串、null/布尔/数组/对象、非整数、负零、越界整数）；请求/响应 id 相等性按**值与类型**比较。响应解码要求 `result`/`error` 恰好其一；错误 `code` 必须是安全整数；可选 `error.data` 只允许 `^AIPT_[A-Z0-9_]{1,63}$` 的 `error_code` 且无未知成员。所有失败返回带稳定 AIPT 原因码与路径的类型化契约错误（`AIPT_JSON_MALFORMED`/`AIPT_JSON_DUPLICATE_KEY`/`AIPT_JSON_TRAILING`/`AIPT_JSON_UNSAFE_INTEGER`/`AIPT_JSON_NEGATIVE_ZERO`/`AIPT_ENVELOPE_UNKNOWN_ROOT`/`AIPT_METHOD_INVALID`/`AIPT_ID_INVALID`/…，可在测试中区分）。
- **纯语义助手（共享契约所需的最小集合）**：身份三元组、标识符（1..64 小写机器模式）、六个可见性标签、非空/唯一授权席位、已知席位引用、state/projection 重复 `field_id`、无损字段值；`CheckProjection` 按 Node 预言机语义实现全量状态投影合同（未知席位/重复 field/未知字段/值漂移/重分类/授权集合漂移/越权 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD`/遗漏授权字段，授权集合按数学集合比较——仅顺序不同不算漂移；缺失/未知可见性绝不默认 PUBLIC）；`ValidateProjection` 额外要求投影身份与源 state 一致；hidden-leak 突变**先结构解码后语义拒绝**（`MutantSemanticRejection` 返回恰为 `AIPT_VISIBILITY_UNAUTHORIZED_FIELD`，且包装 `seat_id` 必须等于 `projection.seat_id`、`leaked_field_id` 必须等于唯一越权字段——元数据漂移以 `AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT` 失败，漂移元数据无法冒充夹具）；`ApplyTransition` 是把声明迁移应用为纯数据变换的确定性助手（非规则引擎），`CheckArithmetic` 校验声明算术输出，`CheckWireErrorCoherence` 校验确定性 `-32000` 错误示例。
- **确定性 canonical JSON / SHA-256**：`CanonicalJSON`/`CanonicalSHA256` 对供应字节做严格预检（重复键、尾随、不安全整数、负零、非有限数**先于哈希拒绝**）后输出递归排序键（JavaScript UTF-16 码元序）、数组保序、无多余空白、ES6 `JSON.stringify` 数字格式的紧凑表示——与 Node 协议资产预言机**逐字节一致**。
- **跨语言共享夹具测试**：测试直接按路径消费仓库同一份权威 Schema 与共享夹具（不复制、不新建第二份 Go 真相），验证 manifest 身份/安全路径/唯一精确清单/`kind→schema_ref` 精确映射/小写 SHA-256；对**同一批共享文件**重算每个资产与突变摘要并比对 Node 预言机写入的 manifest 摘要；重算 `final-state.json` 的 canonical 哈希并要求 `replay_assertion.final_state_hash` 与两条 replay 记录都等于它；两席投影（`seat-a`/`seat-b`）、request 参数与 action-intent 参数深度相等、id 值+类型往返、错误响应一致、通知精确包裹 `event.json`、算术输出、`initial → final` 迁移与两次重放确定。突变被验证为恰 `["NON_CANON","MUTANT"]`、`kind = hidden-leak`、可结构解码，并被投影语义以**唯一** `AIPT_VISIBILITY_UNAUTHORIZED_FIELD` 拒绝。
- **运行**：`pnpm run test:protocol-go`（`package.json` 持久脚本，恰为 `go test ./internal/protocol -count=1`）；共 **183 项测试**全绿，其中 **101 项负向用例**（畸形 jsonrpc、未知协议/模式版本、缺 params、result+error 同时/皆无、未知请求/通知方法、任意根对象、未知字段、顶层与嵌套重复键、尾随 JSON、缺失/未知/空可见性、重复字段/席位、未知席位、投影值/元数据漂移与遗漏授权字段、id 字符串/数字往返与闭区间边界、不安全/小数/null/负零 id 拒绝、错误 code/data 无效、夹具身份失配、突变元数据漂移、canonicalization 拒绝重复/尾随/不安全/负零输入，以及迭代 5B 新增的整数值不安全拼写/孤立代理混同/数值 wire 错误码/突变身份漂移/语义 nil 输入/manifest 预检与登记表快照 18 项聚焦负向用例）。测试密封、无副作用、不改动任何受跟踪的 schema/夹具文件。
- **迭代 5B 修复（Codex 独立对抗评审复现的六个 fail-open 缺口，全部以聚焦回归测试关闭）**：
  1. **整数值不安全的小数/指数拼写**：`ValidateJSON`/`CanonicalJSON`/`CanonicalSHA256` 对 `9007199254740993.0`、`9007199254740992e0`、`-9007199254740993.0`、`1e20`、`-1e20`、`1e308` 等以 `AIPT_JSON_UNSAFE_INTEGER` fail closed（顶层与嵌套路径、任何 RawMessage 信任与 canonical 哈希之前）；有限解析后每个整数值数字必须满足 ±(2^53-1) 安全区间，与已接受 TS 无损门禁一致；边界正例 `±9007199254740991.0`/`±9007199254740991e0` 与有限非整数（`1.5e0`/`5e-324`/`1e-999`）继续接受，负零含 `-1e-999` 继续以 `AIPT_JSON_NEGATIVE_ZERO` 拒绝。
  2. **Node 24 逐字节兼容的孤立 UTF-16 代理**：解析器把 JSON 字符串保存为 UTF-16 码元序列（真实的 JavaScript 字符串值）——孤立高/低代理保持为独立码元并序列化为 Node 的小写 `\uXXXX` 转义（绝不输出 U+FFFD 替换符），合法代理对继续重组为对应 Unicode 标量，对象键按 JavaScript UTF-16 码元序排序（`D800 < D83D < DC00 < E000` 等，与 Node 实测一致），重复键检测与 `JSONEqual` 按码元序列比较——`"\ud800"` 与 `"\ufffd"` 绝不混同，而 `"\ud83d\ude00"` 与字面标量仍互为重复键/相等值；Node 预言机接受的字符串一律不拒绝。
  3. **确定性 wire 错误数值码门禁**：`CheckWireErrorCoherence` 现在除方法/消息/数据外还要求 `errObj.Code == WireErrorExampleCode(-32000)`；方法、数值码、消息、数据任一字段独立漂移都返回稳定原因 `AIPT_PROTOCOL_ERROR_MISMATCHED_ERROR_CODE`，nil 错误对象同样 fail closed。
  4. **突变身份漂移不可冒充**：`MutantSemanticRejection` 在接受语义拒绝前要求内嵌投影身份等于供应源 state 身份（漂移以 `AIPT_FIXTURE_IDENTITY_MISMATCH` 失败）；nil/missing specimen、state 或投影输入一律返回类型化 fail-closed 错误、绝不 panic；包装 `seat_id` 与 `leaked_field_id` 绑定检查保留。
  5. **语义助手 nil 安全**：`CheckProjection(nil, …)`/`CheckProjection(…, nil, …)` 确定性返回 `[AIPT_PROJECTION_INVALID]`；`KnownSeats(nil)` 返回空已知席位集（不 panic，授权查找全部 fail closed）；`ValidateProjection`/`MutantSemanticRejection` 对调用方可控 nil 输入全部类型化失败，行为保持窄且纯。
  6. **manifest 解码期语义预检 + 不可变登记表**：`DecodeManifest` 在解码期（零文件 I/O）对每个资产/突变路径运行 `ManifestPathProblem`、要求资产+突变路径唯一、要求突变路径位于 `mutants/`、要求每个 kind 的 `schema_ref` 等于可信精确映射，违规在冒犯路径返回类型化 manifest/路径契约错误（`AIPT_MANIFEST_PATH_UNSAFE`/`AIPT_MANIFEST_INVALID`）。kind→schema_ref 登记表改为**非导出权威**（解码器决策只读非导出映射），导出视图只有 `ManifestKindSchemaRefFor`（查询）与 `ManifestKindSchemaRefSnapshot`（返回副本）；测试证明突变返回的快照绝不改变后续解码或登记表查询。

## 12. 本批次明确不建设

B002（含本迭代）**不新增任何 server/socket/worker/model/database 运行时**；`.github/`、冻结工具链/action 锁、`tools/supply-chain/policy.json`、`LICENSE` 与历史权威登记（decisions/supersessions/deferred）均保持不变。运行时状态保持 `not built yet`。B002 聚焦工作流演进（如 Go 协议测试接入公共 CI workflow）留待后续迭代。

**路径准入是逐迭代的，不是永久禁令**：`packages/adapter-sdk`、`pnpm-workspace.yaml`/`pnpm-lock.yaml` 与 `tools/supply-chain/licenses.json` 已由迭代 4 的准入清单登记；`internal/protocol/**` 与 `internal/toolchainsmoke/doc.go` 已由迭代 5 的准入清单登记（`internal/protocol/` 同时移出禁止前缀列表），后续 B002 迭代的路径仍需各自的准入登记，绝不预批准。

## 相邻文档

- [../authority/README.md](../authority/README.md)（Authority Index）· [../authority/PROJECT_STATUS.md](../authority/PROJECT_STATUS.md) · [../authority/BATCH_DEPENDENCY_GRAPH.md](../authority/BATCH_DEPENDENCY_GRAPH.md)
- [返回仓库首页](../../README.md)
